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
#ifndef _MKDIR_H_
#define _MKDIR_H_

#include "syscalls.h"

long __attribute__((always_inline)) trace__sys_mkdir(const char __user *pathname, umode_t mode)
{
    struct syscall_cache_t syscall = {
        .type = EVENT_MKDIR,
        .mkdir = {
            .mode = mode
        }
    };

    bpf_probe_read_str(&syscall.mkdir.pathname, MAX_PATH_LEN, (void*)pathname);
    cache_syscall(&syscall);
    return 0;
}

long __attribute__((always_inline)) trace__sys_mkdir_ret(struct pt_regs *ctx)
{
    // Remove syscall metadata in any case
    struct syscall_cache_t *syscall = pop_syscall(EVENT_MKDIR);
    if (!syscall)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret == 0)
    {
        // Do not handle success
        return 0;
    }

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;

    fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.retval = ret;
    data_cache->fs_event.event = EVENT_MKDIR;
    data_cache->fs_event.mode = syscall->mkdir.mode;
    data_cache->fs_event.src_mount_id = syscall->mkdir.file.path_key.mount_id;
    data_cache->fs_event.src_inode = syscall->mkdir.file.path_key.ino;

    if (!match(data_cache, FILTER_SRC))
        return 0;

    data_cache->pathname = syscall->mkdir.pathname;
    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);

    return 0;
}

// trace_mkdir - Traces a file system mkdir event.
// @ctx: registers context
// @dir: pointer to the inode of the containing directory
// @dentry: pointer to the dentry structure of the new directory
// @mode: mode of the mkdir call
__attribute__((always_inline)) static int trace_mkdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MKDIR);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;

    syscall->mkdir.dentry = dentry;
    reset_cache_entry(data_cache);
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_MKDIR;
    data_cache->fs_event.mode = (int)mode;
    data_cache->fs_event.src_mount_id = get_path_mount_id(syscall->mkdir.path);
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_mkdir_ret - Traces the return of a file system mkdir event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_mkdir_ret(struct pt_regs *ctx)
{
    struct syscall_cache_t *syscall = peek_syscall(EVENT_MKDIR);
    if (!syscall)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;

    data_cache->fs_event.retval = PT_REGS_RC(ctx);
    data_cache->fs_event.src_inode = get_dentry_ino(data_cache->src_dentry);

#ifdef DEBUG
    struct basename path = {};
    get_dentry_name(data_cache->src_dentry, &path, sizeof(path));
    bpf_printk("mkdir_x: resolve paths, ino=%ld, mnt_id=%d, name=%s.",
              data_cache->fs_event.src_inode,
              data_cache->fs_event.src_mount_id,
              path.name);
#endif
    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);

    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/do_mkdirat")
int kprobe_do_mkdirat(struct pt_regs *ctx)
{
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    umode_t mode = (umode_t)PT_REGS_PARM3(ctx);
    return trace__sys_mkdir(pathname, mode);
}

SEC("kretprobe/do_mkdirat")
int kprobe_do_mkdirat_ret(struct pt_regs *ctx)
{
    return trace__sys_mkdir_ret(ctx);
}

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    umode_t mode = (umode_t)PT_REGS_PARM3(ctx);
    return trace_mkdir(ctx, dir, dentry, mode);
}

SEC("kretprobe/vfs_mkdir")
int kretprobe_vfs_mkdir(struct pt_regs *ctx)
{
    return trace_mkdir_ret(ctx);
}

#endif
