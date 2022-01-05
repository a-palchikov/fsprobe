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
#ifndef _UNLINK_H_
#define _UNLINK_H_

// mount_id is set by the mnt_want_write prior
// to entry into vfs_unlink

int __attribute__((always_inline)) trace__sys_unlink(int flags) {
    struct syscall_cache_t syscall = {
        .type = EVENT_UNLINK,
        .unlink = {
            .flags = flags,
        }
    };

    cache_syscall(&syscall);
    return 0;
}

// trace_unlink - Traces a file system unlink event.
// @ctx: registers context
// @dir: pointer to the inode structure of the directory containing the file to delete
// @dentry: pointer to the dentry structure of the file to delete
__attribute__((always_inline)) static int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct syscall_cache_t *syscall = peek_syscall(EVENT_UNLINK);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_UNLINK;
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    data_cache->fs_event.src_mount_id = syscall->unlink.file.path_key.mount_id;
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_unlink_ret - Traces the return of a file system unlink event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_unlink_ret(struct pt_regs *ctx)
{
    struct syscall_cache_t *syscall = pop_syscall(EVENT_UNLINK);
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

SEC("kprobe/do_unlinkat")
int kprobe_do_unlinkat(struct pt_regs *ctx)
{
    // The only possible flag is AT_REMOVEDIR
    // which is already handled by the do_rmdir probe
    return trace__sys_unlink(0);
}

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    return trace_unlink(ctx, dir, dentry);
}

SEC("kretprobe/vfs_unlink")
int kretprobe_vfs_unlink(struct pt_regs *ctx)
{
    return trace_unlink_ret(ctx);
}

#endif
