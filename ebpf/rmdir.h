/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _RMDIR_H_
#define _RMDIR_H_

#include "syscalls.h"

long __attribute__((always_inline)) trace__sys_rmdir(const char __user *pathname) {
    struct syscall_cache_t syscall = {
        .type = EVENT_RMDIR,
    };

    bpf_probe_read_str(&syscall.mkdir.pathname, MAX_PATH_LEN, (void*)pathname);
    cache_syscall(&syscall);
    return 0;
}

int __attribute__((always_inline)) rmdir_predicate(u64 type) {
    return type == EVENT_RMDIR || type == EVENT_UNLINK;
}

long __attribute__((always_inline)) trace__sys_rmdir_ret(struct pt_regs *ctx)
{
    // Remove syscall metadata in any case
    struct syscall_cache_t *syscall = pop_syscall_with(rmdir_predicate);
    if (!syscall)
        return 0;

    int ret = PT_REGS_RC(ctx);
    //bpf_printk("rmdir_x: found syscall value stack: ret=%ld.", ret);
    if (ret == 0)
    {
        // Do not handle success
        return 0;
    }

    struct dentry_cache_t value = {};
    value.fs_event.retval = ret;
    value.fs_event.event = EVENT_RMDIR;
    value.fs_event.src_mount_id = syscall->rmdir.file.path_key.mount_id;
    value.fs_event.src_inode = syscall->rmdir.file.path_key.ino;
    resolve_paths(ctx, &value, RESOLVE_SRC | EMIT_EVENT);

    return 0;
}

// trace_rmdir - Traces a file system rmdir event.
// @ctx: registers context
// @dir: pointer to the directory that contains the directory to delete
// @dentry: pointer to the dentry of the directory to delete
__attribute__((always_inline)) static int trace_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct syscall_cache_t *syscall = peek_syscall_with(rmdir_predicate);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_RMDIR;
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    data_cache->fs_event.src_mount_id = syscall->rmdir.file.path_key.mount_id;
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_rmdir_ret - Traces the return of a file system rmdir event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_rmdir_ret(struct pt_regs *ctx)
{
    struct syscall_cache_t *syscall = pop_syscall_with(rmdir_predicate);
    if (!syscall)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    data_cache->fs_event.retval = PT_REGS_RC(ctx);

    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/do_rmdir")
int kprobe_do_rmdir(struct pt_regs *ctx)
{
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    return trace__sys_rmdir(pathname);
}

SEC("kretprobe/do_rmdir")
int kprobe_do_rmdir_ret(struct pt_regs *ctx)
{
    return trace__sys_rmdir_ret(ctx);
}

SEC("kprobe/vfs_rmdir")
int kprobe_vfs_rmdir(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    return trace_rmdir(ctx, dir, dentry);
}

SEC("kretprobe/vfs_rmdir")
int kretprobe_vfs_rmdir(struct pt_regs *ctx)
{
    return trace_rmdir_ret(ctx);
}

#endif
