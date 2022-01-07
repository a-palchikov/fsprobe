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
#ifndef _OPEN_H_
#define _OPEN_H_

long __attribute__((always_inline)) trace__sys_open(const char __user *pathname) {
    struct syscall_cache_t syscall = {
        .type = EVENT_OPEN,
    };

    bpf_probe_read_str(&syscall.open.pathname, MAX_PATH_LEN, (void*)pathname);
    cache_syscall(&syscall);
    return 0;
}

void get_dentry_name(struct dentry *dentry, void *buffer, size_t n);

// trace_path_openat - Traces a file system open event.
// @ctx: registers context
// @path: pointer to the path value describing the event. Note, that this is 
// uninitialized upon entry and can only be access in the return probe
__attribute__((always_inline)) static int trace_path_openat(struct pt_regs *ctx, struct path *path)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_open_cache_builder, &cpu);
    if (!data_cache)
        return 0;

    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_OPEN;
    data_cache->path = path;

    // Fall-through to kretprobe as we can only filter
    // upon return
    
    bpf_map_update_elem(&dentry_open_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_path_openat_ret - Traces the return of the open event (path_openat).
// This event traces the failure of the open syscall - success will be traced
// by the corresponding vfs_open trace.
// @ctx: registers context
__attribute__((always_inline)) static int trace_path_openat_ret(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_RC(ctx);
    if (!IS_ERR(file))
    {
        // Do not trace success since it will be available
        // as part of the vfs_open trace outcome.
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_open_cache, &key);
    if (!data_cache)
    {
        //bpf_printk("path_openat_x: no cached value on stack.");
        return 0;
    }

    data_cache->fs_event.retval = PTR_ERR(file);
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &data_cache->path->dentry);
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    data_cache->fs_event.src_mount_id = get_path_mount_id(data_cache->path);

    if (!match(data_cache, FILTER_SRC))
        return 0;

#ifdef DEBUG
    bpf_printk("path_openat_x: match, resolve paths, ino=%ld, mnt_id=%d, ret=%d.",
               data_cache->fs_event.src_inode,
               data_cache->fs_event.src_mount_id,
               PTR_ERR(file));
#endif

    struct syscall_cache_t *syscall = pop_syscall(EVENT_OPEN);
    if (!syscall)
    {
        //bpf_printk("path_openat_x: no syscall on stack.");
        return 0;
    }

    // Resolve paths
    data_cache->pathname = syscall->open.pathname;
    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_open_cache, &key);
    return 0;
}

// trace_open - Traces a file system open event.
// @ctx: registers context
// @path: pointer to the file path structure
__attribute__((always_inline)) static int trace_open(struct pt_regs *ctx, struct path *path)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;

    reset_cache_entry(data_cache);
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    data_cache->fs_event.event = EVENT_OPEN;
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &path->dentry);
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    data_cache->fs_event.src_mount_id = get_path_mount_id(path);
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_open_ret - Traces the return of a file system open event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_open_ret(struct pt_regs *ctx)
{
    // Remove syscall from the stack
    struct syscall_cache_t *syscall = pop_syscall(EVENT_OPEN);
    if (!syscall)
        return 0;
    //bpf_printk("open_x: remove syscall from stack.");

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;

    data_cache->fs_event.retval = PT_REGS_RC(ctx);
#ifdef DEBUG
    bpf_printk("vfs_open_x: resolve paths, ino=%ld, mnt_id=%d, ret=%d.",
               data_cache->fs_event.src_inode,
               data_cache->fs_event.src_mount_id,
               data_cache->fs_event.retval);
#endif

    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/do_sys_open")
int kprobe_do_sys_open(struct pt_regs *ctx)
{
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    return trace__sys_open(pathname);
}

//SEC("kretprobe/do_sys_open")
//int kprobe_do_sys_open_ret(struct pt_regs *ctx)
//{
//    return trace__sys_open_ret(ctx);
//}

SEC("kprobe/path_openat")
int kprobe_path_openat(struct pt_regs *ctx)
{
    // nameidata.path
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);

    return trace_path_openat(ctx, path);
}

SEC("kretprobe/path_openat")
int kretprobe_path_openat(struct pt_regs *ctx)
{
    return trace_path_openat_ret(ctx);
}

SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return trace_open(ctx, path);
}

SEC("kretprobe/vfs_open")
int kretprobe_vfs_open(struct pt_regs *ctx)
{
    return trace_open_ret(ctx);
}

#endif
