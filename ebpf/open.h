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

long __attribute__((always_inline)) trace__sys_open(const char __user *pathname, int flags) {
    struct syscall_cache_t syscall = {
        .type = EVENT_OPEN,
        .open = {
            .flags = flags,
        }
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
    struct syscall_cache_t *syscall = peek_syscall(EVENT_OPEN);
    if (!syscall)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_open_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);

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
    struct syscall_cache_t *syscall = pop_syscall(EVENT_OPEN);
    if (!syscall)
        return 0;

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
        return 0;

    data_cache->fs_event.flags = syscall->open.flags;
    data_cache->fs_event.retval = PTR_ERR(file);
    //data_cache->fs_event.src_inode = syscall->open.file.path_key.ino;
    //data_cache->fs_event.src_mount_id = syscall->open.file.path_key.mount_id;
    data_cache->fs_event.src_inode = get_path_dentry_ino(data_cache->path);
    data_cache->fs_event.src_mount_id = get_path_mount_id(data_cache->path);

    // It seems that at least with EACCES, the path cached
    // upon entry into path_openat is not initialized enough
    // to read anything beyond inode (e.g. no dentry name and
    // no backward links have been set up) so path resolution
    // is incomplete
    data_cache->pathname = syscall->open.pathname;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &data_cache->path->dentry);
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC)) {
        bpf_map_delete_elem(&dentry_open_cache, &key);
        return 0;
    }

#ifdef DEBUG
    bpf_printk("path_openat_x: match, resolve paths, ino=%ld, mnt_id=%d, ret=%d.",
               data_cache->fs_event.src_inode,
               data_cache->fs_event.src_mount_id,
               PTR_ERR(file));
#endif

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
    data_cache->path = path;

#ifdef DEBUG
    struct nameidata *nd = (struct nameidata *)path;
    int type;
    bpf_probe_read(&type, sizeof(int), &nd->last_type);
    if ((type == LAST_DOTDOT || type == LAST_DOT) && data_cache->fs_event.src_mount_id == 253) {
        struct basename name = {};
        get_dentry_name(dentry, &name, sizeof(name));
        bpf_printk("vfs_open_e: .. or . (%d), name='%s'", type, name.name);
    }
#endif

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

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;

    data_cache->fs_event.retval = PT_REGS_RC(ctx);
    data_cache->fs_event.flags = syscall->open.flags;
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &data_cache->path->dentry);
    data_cache->src_dentry = dentry;
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    data_cache->fs_event.src_mount_id = get_path_mount_id(data_cache->path);

    if (!match(data_cache, FILTER_SRC)) {
        // Clean up the dentry cache since the matching is in
        // the exit probe
        bpf_map_delete_elem(&dentry_cache, &key);
        return 0;
    }

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
    int flags = (int)PT_REGS_PARM3(ctx);
    return trace__sys_open(pathname, flags);
}

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
