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

struct unlinkat_args {
    u64 __unused__;
	int id;
	int dfd;
	const char * pathname;
	int flag;
};

struct unlinkat_ret_args {
    u64 __unused__;
	int id;
	int ret;
};

int __attribute__((always_inline)) trace__sys_unlink(int flags, const char __user *pathname) {
    struct syscall_cache_t syscall = {
        .type = EVENT_UNLINK,
        .unlink = {
            .flags = flags,
        }
    };

    bpf_probe_read_str(&syscall.unlink.pathname, MAX_PATH_LEN, (void*)pathname);
    cache_syscall(&syscall);
    return 0;
}

long __attribute__((always_inline)) trace__sys_unlink_ret(struct unlinkat_ret_args *args)
{
    // Remove syscall metadata in any case
    struct syscall_cache_t *syscall = pop_syscall(EVENT_UNLINK);
    if (!syscall)
        return 0;

    int ret;
    bpf_probe_read(&ret, sizeof(ret), &args->ret);
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
    data_cache->fs_event.event = EVENT_UNLINK;
    // Store the base directory path key
    data_cache->fs_event.src_key = syscall->unlink.file.path_key;

    if (!match(data_cache, FILTER_SRC))
        return 0;

#ifdef DEBUG
    bpf_printk("sys_unlink_x: name=%s",
               syscall->unlink.pathname);
    bpf_printk("sys_unlink_x: ino=%ld/mnt_id=%d",
               data_cache->fs_event.src_key.ino,
               data_cache->fs_event.src_key.mount_id);
#endif

    data_cache->pathname = syscall->unlink.pathname;
    resolve_paths(args, data_cache, RESOLVE_SRC | EMIT_EVENT);

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
    data_cache->fs_event.src_key.ino = get_dentry_ino(dentry);
    data_cache->fs_event.src_key.mount_id = syscall->unlink.file.path_key.mount_id;
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

#ifdef DEBUG
    bpf_printk("unlink_e: ino=%ld/mnt_id=%d",
               data_cache->fs_event.src_key.ino,
               data_cache->fs_event.src_key.mount_id);
#endif

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

#ifdef DEBUG
    bpf_printk("unlink_x: ret=%d",
               data_cache->fs_event.retval);
#endif

    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_do_unlinkat(struct unlinkat_args *args)
{
    const char __user *pathname = NULL;
    int flag = 0;
    bpf_probe_read(&pathname, sizeof(pathname), &args->pathname);
    bpf_probe_read(&flag, sizeof(flag), &args->flag);
    return trace__sys_unlink(flag, pathname);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint_do_unlinkat_ret(struct unlinkat_ret_args *args)
{
    return trace__sys_unlink_ret(args);
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
