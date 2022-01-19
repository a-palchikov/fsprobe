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
#ifndef _RENAME_H_
#define _RENAME_H_

int __attribute__((always_inline)) trace__sys_rename(const char __user *old_name, const char __user *new_name) {
    struct syscall_cache_t syscall = {
        .type = EVENT_RENAME,
    };

    bpf_probe_read_str(&syscall.rename.src_pathname, MAX_PATH_LEN, (void*)old_name);
    bpf_probe_read_str(&syscall.rename.target_pathname, MAX_PATH_LEN, (void*)new_name);
    cache_syscall(&syscall);
    return 0;
}

// Trace the return from do_renameat2.
// This is used to trace the unsuccessful return from renameat2 in which case
// we synthesize path fragments for source/target pathnames and resolve
// dentry from the base directory (set in link_path_walk).
int __attribute__((always_inline)) trace__sys_rename_ret(struct pt_regs *ctx) {
    // Remove syscall metadata in any case
    struct syscall_cache_t *syscall = pop_syscall(EVENT_RENAME);
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
    reset_cache_entry(data_cache);

    fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.retval = ret;
    data_cache->fs_event.event = EVENT_RENAME;
    // Store the inode/mount ID tuples for the base path
    data_cache->fs_event.src_key = syscall->rename.src_file.path_key;
    data_cache->fs_event.target_key = syscall->rename.target_file.path_key;

    struct dentry *src_dentry;
    bpf_probe_read(&src_dentry, sizeof(struct dentry *), &syscall->rename.src_dentry);
    data_cache->src_dentry = src_dentry;

    struct dentry *target_dentry;
    bpf_probe_read(&target_dentry, sizeof(struct dentry *), &syscall->rename.target_dentry);
    data_cache->target_dentry = target_dentry;

    if (!match(data_cache, FILTER_SRC) && !match(data_cache, FILTER_TARGET))
        return 0;

#ifdef DEBUG
    bpf_printk("do_renameat2_x: ret=%d.", data_cache->fs_event.retval);
    bpf_printk("do_renameat2_x: src(ino=%ld/mnt_id=%d).",
               data_cache->fs_event.src_key.ino,
               data_cache->fs_event.src_key.mount_id);
    bpf_printk("do_renameat2_x: tgt(ino=%ld/mnt_id=%d).",
               data_cache->fs_event.target_key.ino,
               data_cache->fs_event.target_key.mount_id);
#endif

    data_cache->pathname = syscall->rename.src_pathname;
    data_cache->target_pathname = syscall->rename.target_pathname;
    resolve_paths(ctx, data_cache, RESOLVE_ALL | EMIT_EVENT);

    return 0;
}

// trace_rename - Traces a file system rename event.
// @ctx: registers context
// @old_dentry: pointer to the dentry structure of the source file
// @new_dir: pointer to the inode structure of the destination directory
// @new_dentry: pointer to the dentry structure of the destination file
__attribute__((always_inline)) static int trace_rename(struct pt_regs *ctx, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    struct syscall_cache_t *syscall = peek_syscall(EVENT_RENAME);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);

    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_RENAME;
    data_cache->fs_event.src_key.ino = get_dentry_ino(old_dentry);
    // Add old mount ID
    data_cache->fs_event.src_key.mount_id = syscall->rename.src_file.path_key.mount_id;
    // Generate a fake key for the old inode as the inode will be reused
    data_cache->fs_event.src_path_key = new_fake_inode();

    syscall->rename.src_dentry = old_dentry;
    syscall->rename.target_dentry = new_dentry;
    data_cache->src_dentry = old_dentry;
    data_cache->target_dir = new_dir;
    data_cache->target_dentry = new_dentry;

    if (!match(data_cache, FILTER_SRC) && !match(data_cache, FILTER_TARGET)) {
        return 0;
    }

    resolve_paths(ctx, data_cache, RESOLVE_SRC);
    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_rename_ret - Traces the return of a file system rename event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_rename_ret(struct pt_regs *ctx)
{
    struct syscall_cache_t *syscall = pop_syscall(EVENT_RENAME);
    if (!syscall)
        return 0;

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;

    data_cache->fs_event.retval = PT_REGS_RC(ctx);
    data_cache->fs_event.target_key.ino = get_dentry_ino(syscall->rename.src_dentry);
    data_cache->fs_event.target_key.mount_id = syscall->rename.target_file.path_key.mount_id;

#ifdef DEBUG
    bpf_printk("vfs_rename_x: ret=%d", data_cache->fs_event.retval);
    bpf_printk("vfs_rename_x: src(key=%ld/ino=%ld/mnt_id=%d)",
               data_cache->fs_event.src_path_key,
               data_cache->fs_event.src_key.ino,
               data_cache->fs_event.src_key.mount_id);
    bpf_printk("vfs_rename_x: tgt(ino=%ld/mnt_id=%d)",
               data_cache->fs_event.target_key.ino,
               data_cache->fs_event.target_key.mount_id);
#endif

    resolve_paths(ctx, data_cache, RESOLVE_TARGET | EMIT_EVENT);

    // Check follow mode and insert inode if necessary
    u64 follow_mode = load_follow_mode();
    if (follow_mode) {
        u8 value = 0;
        bpf_map_update_elem(&inodes_filter, &data_cache->fs_event.target_key, &value, BPF_ANY);
    }

    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/do_renameat2")
int kprobe_do_renameat2(struct pt_regs *ctx)
{
    const char __user *old_name = (const char __user *)PT_REGS_PARM2(ctx);
    const char __user *new_name = (const char __user *)PT_REGS_PARM4(ctx);
    return trace__sys_rename(old_name, new_name);
}

SEC("kretprobe/do_renameat2")
int kretprobe_do_renameat2(struct pt_regs *ctx)
{
    return trace__sys_rename_ret(ctx);
}

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx)
{
    struct dentry *old_dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    struct inode *new_dir = (struct inode *)PT_REGS_PARM3(ctx);
    struct dentry *new_dentry = (struct dentry *)PT_REGS_PARM4(ctx);
    return trace_rename(ctx, old_dentry, new_dir, new_dentry);
}

SEC("kretprobe/vfs_rename")
int kretprobe_vfs_rename(struct pt_regs *ctx)
{
    return trace_rename_ret(ctx);
}

#endif
