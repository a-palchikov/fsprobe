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
#ifndef _SETATTR_H_
#define _SETATTR_H_

// trace_security_inode_setattr - Traces a file system setattr event.
// @ctx: registers context
// @dentry: pointer to the dentry of the file
// @attr: pointer to the iattr structure explaining what happened to the file
__attribute__((always_inline)) static int trace_setattr(struct pt_regs *ctx, struct dentry *dentry, struct iattr *attr)
{
    u32 cpu = bpf_get_smp_processor_id();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache_builder, &cpu);
    if (!data_cache)
        return 0;
    reset_cache_entry(data_cache);

    data_cache->fs_event.event = EVENT_SETXATTR;
    u64 key = fill_process_data(&data_cache->fs_event.process_data);

    // SetAttr data
    bpf_probe_read(&data_cache->fs_event.flags, sizeof(attr->ia_valid), &attr->ia_valid);
    bpf_probe_read(&data_cache->fs_event.mode, sizeof(attr->ia_mode), &attr->ia_mode);

    data_cache->fs_event.src_inode = get_dentry_ino(dentry);
    struct inode *inode = get_dentry_inode(dentry);
    data_cache->fs_event.src_mount_id = get_inode_mount_id(inode);
    data_cache->src_dentry = dentry;

    if (!match(data_cache, FILTER_SRC))
        return 0;

#ifdef DEBUG
    bpf_printk("setattr: matched for event=%d, mnt_id=%d.",
               data_cache->fs_event.event,
               data_cache->fs_event.src_mount_id);
#endif

    // Send to cache
    bpf_map_update_elem(&dentry_cache, &key, data_cache, BPF_ANY);
    return 0;
}

// trace_setattr_ret - Traces the return of a file system setattr event.
// @ctx: registers context
__attribute__((always_inline)) static int trace_setattr_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = bpf_map_lookup_elem(&dentry_cache, &key);
    if (!data_cache)
        return 0;
    data_cache->fs_event.retval = PT_REGS_RC(ctx);

    resolve_paths(ctx, data_cache, RESOLVE_SRC | EMIT_EVENT);
    bpf_map_delete_elem(&dentry_cache, &key);
    return 0;
}

SEC("kprobe/security_inode_setattr")
int kprobe_security_inode_setattr(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct iattr *attr = (struct iattr *)PT_REGS_PARM2(ctx);
    return trace_setattr(ctx, dentry, attr);
}

SEC("kretprobe/security_inode_setattr")
int kretprobe_security_inode_setattr(struct pt_regs *ctx)
{
    return trace_setattr_ret(ctx);
}

#endif
