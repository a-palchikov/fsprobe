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
#ifndef _LINK_H_
#define _LINK_H_

#include "syscalls.h"

int __attribute__((always_inline)) trace__sys_link(const char __user *old_name, const char __user *new_name) {
    struct syscall_cache_t syscall = {
        .type = EVENT_LINK,
    };

    bpf_probe_read_str(&syscall.link.src_pathname, MAX_PATH_LEN, (void*)old_name);
    bpf_probe_read_str(&syscall.link.target_pathname, MAX_PATH_LEN, (void*)new_name);
    cache_syscall(&syscall);
    return 0;
}

// Trace the return from do_linkat.
// This is used to trace the unsuccessful return from linkat in which case
// we synthesize path fragments for source/target pathnames and resolve
// dentry from the base directory (set in link_path_walk).
int __attribute__((always_inline)) trace__sys_link_ret(struct pt_regs *ctx) {
    // Remove syscall metadata in any case
    struct syscall_cache_t *syscall = pop_syscall(EVENT_LINK);
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
    data_cache->fs_event.event = EVENT_LINK;
    // Store the inode/mount ID tuples for the base path
    data_cache->fs_event.src_inode = syscall->link.src_file.path_key.ino;
    data_cache->fs_event.src_mount_id = syscall->link.src_file.path_key.mount_id;
    data_cache->fs_event.target_mount_id = syscall->link.target_file.path_key.mount_id;
    data_cache->fs_event.target_inode = syscall->link.target_file.path_key.ino;

    struct dentry *src_dentry;
    bpf_probe_read(&src_dentry, sizeof(struct dentry *), &syscall->link.src_dentry);
    data_cache->src_dentry = src_dentry;

    struct dentry *target_dentry;
    bpf_probe_read(&target_dentry, sizeof(struct dentry *), &syscall->link.target_dentry);
    data_cache->target_dentry = target_dentry;

    if (!match(data_cache, FILTER_SRC) && !match(data_cache, FILTER_TARGET))
        return 0;

#ifdef DEBUG
    bpf_printk("do_linkat_x: ret=%d.", data_cache->fs_event.retval);
    bpf_printk("do_linkat_x: src(ino=%ld/mnt_id=%d).",
               data_cache->fs_event.src_inode,
               data_cache->fs_event.src_mount_id);
    bpf_printk("do_linkat_x: tgt(ino=%ld/mnt_id=%d).",
               data_cache->fs_event.target_inode,
               data_cache->fs_event.target_mount_id);
#endif

    data_cache->pathname = syscall->link.src_pathname;
    data_cache->target_pathname = syscall->link.target_pathname;
    resolve_paths(ctx, data_cache, RESOLVE_ALL | EMIT_EVENT);

    return 0;
}

// trace_link - Traces a file system link event.
// @ctx: registers context
// @old_dentry: pointer to the dentry structure of the source file
// @new_dir: pointer to the inode structure of the destination directory
// @new_dentry: pointer to the dentry structure of the destination file
__attribute__((always_inline)) static int trace_link(struct pt_regs *ctx, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    struct syscall_cache_t *syscall = peek_syscall(EVENT_LINK);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_LINK;
    data_cache->fs_event.src_inode = get_dentry_ino(old_dentry);

    // this is a hard link, source and target dentries are on the same filesystem & mount point
    // target_path was set by kprobe/filename_create before we reach this point.
    syscall->link.src_file.path_key.mount_id = get_path_mount_id(syscall->link.target_path);
    // TODO(dima): fix the overlayfs support
    //set_file_inode(src_dentry, &syscall->link.src_file, 0);

    // generate a fake target key as the inode is the same
    data_cache->fs_event.src_path_key = new_fake_inode();
    syscall->link.target_file.path_key.mount_id = syscall->link.src_file.path_key.mount_id;
    //if (is_overlayfs(src_dentry))
    //    syscall->link.target_file.flags |= UPPER_LAYER;

    data_cache->src_dentry = old_dentry;
    data_cache->target_dir = new_dir;
    data_cache->target_dentry = new_dentry;

    if (!match(data_cache, FILTER_SRC) && !match(data_cache, FILTER_TARGET))
        return 0;

    resolve_paths(ctx, data_cache, RESOLVE_SRC);
    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_link_ret - Traces the return of a file system link event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_link_ret(struct pt_regs *ctx)
{
    struct syscall_cache_t *syscall = pop_syscall(EVENT_LINK);
    if (!syscall)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;

    data_cache->fs_event.retval = PT_REGS_RC(ctx);
    data_cache->fs_event.target_inode = get_dentry_ino(data_cache->target_dentry);
    data_cache->fs_event.target_mount_id = get_path_mount_id(syscall->link.target_path);

    resolve_paths(ctx, data_cache, RESOLVE_TARGET | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/do_linkat")
int kprobe_do_linkat(struct pt_regs *ctx)
{
    const char __user *old_name = (const char __user *)PT_REGS_PARM2(ctx);
    const char __user *new_name = (const char __user *)PT_REGS_PARM4(ctx);
    return trace__sys_link(old_name, new_name);
}

SEC("kretprobe/do_linkat")
int kretprobe_do_linkat(struct pt_regs *ctx)
{
    return trace__sys_link_ret(ctx);
}

SEC("kprobe/vfs_link")
int kprobe_vfs_link(struct pt_regs *ctx)
{
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct inode *new_dir = (struct inode *)PT_REGS_PARM2(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    return trace_link(ctx, old_dentry, new_dir, new_dentry);
}

SEC("kretprobe/vfs_link")
int kretprobe_vfs_link(struct pt_regs *ctx)
{
    return trace_link_ret(ctx);
}

#endif
