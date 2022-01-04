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

#define BASENAME_FILTER_SIZE 128

struct basename_t {
    char value[BASENAME_FILTER_SIZE];
};

void get_dentry_name(struct dentry *dentry, void *buffer, size_t n);

// trace_path_openat - Traces a file system open event.
// @ctx: registers context
// @path: pointer to the path value describing the event. Note, that this is 
// uninitialized upon entry and can only be access in the return probe
__attribute__((always_inline)) static int trace_path_openat(struct pt_regs *ctx, struct path *path)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_open_cache_t *data_cache = bpf_map_lookup_elem(&dentry_open_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    // Add process data
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    // Probe type
    data_cache->fs_event.event = EVENT_OPEN;

    // Add inode data
    //struct dentry *dentry;
    //bpf_probe_read(&dentry, sizeof(struct dentry *), &path->dentry);
    //data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    //// Mount ID
    //data_cache->fs_event.src_mount_id = get_path_mount_id(path);

    // Dentry data
    data_cache->path = path;

    // Fall-through to kretprobe as we can only filter
    // upon return
    
    // Send to cache
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
    if (file != NULL && !IS_ERR(file))
    {
        // Do not trace success since it will be available
        // as part of the vfs_open trace outcome.
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct dentry_open_cache_t *data_cache = bpf_map_lookup_elem(&dentry_open_cache, &key);
    if (!data_cache)
        return 0;
    data_cache->fs_event.retval = PTR_ERR(file);
    
    struct dentry_cache_t value = {};
    value.fs_event = data_cache->fs_event;
    // Add inode data
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &data_cache->path->dentry);
    value.fs_event.src_inode = get_dentry_ino(dentry);
    //bpf_printk("path_openat_x: failure, will record: ino=%ld.", value.fs_event.src_inode);
    // Mount ID
    value.fs_event.src_mount_id = get_path_mount_id(data_cache->path);

    // Filter
    if (!match(&value, FILTER_SRC))
    {
        //bpf_printk("path_openat_x: no match, bail.");
        return 0;
    }

    bpf_printk("path_openat_x: match, resolve paths, ino=%ld, mnt_id=%ld.",
               value.fs_event.src_inode,
               value.fs_event.src_mount_id);

    // Resolve paths
    // TODO(dima): add input filename from the corresponding syscall
    resolve_paths(ctx, &value, RESOLVE_SRC | EMIT_EVENT);
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
    // Reset pathname keys (could mess up resolution if there was some leftover data)
    reset_cache_entry(data_cache);
    // Add process data
    u64 key = fill_process_data(&data_cache->fs_event.process_data);
    // Probe type
    data_cache->fs_event.event = EVENT_OPEN;

    // Add inode data
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(struct dentry *), &path->dentry);
    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    // Mount ID
    data_cache->fs_event.src_mount_id = get_path_mount_id(path);

    // Dentry data
    data_cache->src_dentry = dentry;

    // Filter
    if (!match(data_cache, FILTER_SRC))
    {
        //bpf_printk("open_e: no match, bail.");
        return 0;
    }

    // Send to cache
    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_open_ret - Traces the return of a file system open event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_open_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
    {
        //bpf_printk("open_x: no map entry for key, bail.");
        return 0;
    }
    data_cache->fs_event.retval = PT_REGS_RC(ctx);

    // Resolve paths
    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

#endif
