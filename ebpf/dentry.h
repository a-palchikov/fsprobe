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
#ifndef _DENTRY_H_
#define _DENTRY_H_

#include "defs.h"

#define DENTRY_RESOLUTION_FRAGMENTS         0
#define DENTRY_RESOLUTION_SINGLE_FRAGMENT   1
#define DENTRY_RESOLUTION_PERF_BUFFER       2

#define RESOLVE_SRC    1 << 0
#define RESOLVE_TARGET 1 << 1
#define RESOLVE_ALL    (RESOLVE_SRC | RESOLVE_TARGET)
#define EMIT_EVENT     1 << 2

#define MNT_OFFSETOF_MNT 32 // offsetof(struct mount, mnt)
#define DENTRY_OFFSETOF_INODE 48 // offsetof(struct dentry, d_inode)

// Marker for synthetic inodes generated for source
// inode in a rename/link syscall and ENOENT errors during path resolution
#define FAKE_INODE_MSW 0xdeadc001UL

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

//#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags;
	unsigned	seq, m_seq;
	int		last_type;
    // Other fields stripped
};

u64 __attribute__((always_inline)) new_fake_inode() {
    return FAKE_INODE_MSW<<32 | bpf_get_prandom_u32();
}

dev_t __attribute__((always_inline)) get_sb_dev(struct super_block *sb) {
    dev_t dev;
    bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

u32 __attribute__((always_inline)) get_mount_offset_of_mount_id(void) {
    return 284;
}

int __attribute__((always_inline)) get_vfsmount_mount_id(struct vfsmount *mnt) {
    int mount_id;
    // bpf_probe_read(&mount_id, sizeof(mount_id), (char *)mnt + offsetof(struct mount, mnt_id) - offsetof(struct mount, mnt));
    bpf_probe_read(&mount_id, sizeof(mount_id), (char *)mnt + get_mount_offset_of_mount_id() - MNT_OFFSETOF_MNT);
    return mount_id;
}

struct vfsmount * __attribute__((always_inline)) get_mount_vfsmount(void *mnt) {
    return (struct vfsmount *)(mnt + 32);
}

//dev_t __attribute__((always_inline)) get_vfsmount_dev(struct vfsmount *mnt) {
//    return get_sb_dev(get_vfsmount_sb(mnt));
//}
//
//dev_t __attribute__((always_inline)) get_mount_dev(void *mnt) {
//    return get_vfsmount_dev(get_mount_vfsmount(mnt));
//}

struct dentry* __attribute__((always_inline)) get_path_dentry(struct path *path) {
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);
    return dentry;
}

unsigned long get_dentry_ino(struct dentry *dentry);

unsigned long __attribute__((always_inline)) get_path_dentry_ino(struct path *path) {
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);
    return get_dentry_ino(dentry);
}

int __attribute__((always_inline)) get_path_mount_id(struct path *path) {
    struct vfsmount *mnt;
    bpf_probe_read(&mnt, sizeof(mnt), &path->mnt);
    return get_vfsmount_mount_id(mnt);
}

void __attribute__((always_inline)) get_dentry_name(struct dentry *dentry, void *buffer, size_t n) {
    struct qstr qstr;
    bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
    bpf_probe_read_str(buffer, n, (void *)qstr.name);
}

// get_inode_ino - Returns the inode number of an inode structure
__attribute__((always_inline)) unsigned long get_inode_ino(struct inode *inode)
{
    unsigned long ino;
    bpf_probe_read(&ino, sizeof(inode), &inode->i_ino);
    return ino;
}

// write_inode_ino - Writes the inode number of an inode structure
__attribute__((always_inline)) void write_inode_ino(struct inode *inode, u64 *ino)
{
    bpf_probe_read(ino, sizeof(inode), &inode->i_ino);
}

// write_inode_short_ino - Writes the inode number of an inode structure
__attribute__((always_inline)) void write_inode_short_ino(struct inode *inode, u32 *ino)
{
    bpf_probe_read(ino, sizeof(u32), &inode->i_ino);
}

// get_inode_mount_id - Returns the mount id of an inode structure
__attribute__((always_inline)) int get_inode_mount_id(struct inode *dir)
{
    // Mount ID
    int mount_id;
    struct super_block *spb;
    bpf_probe_read(&spb, sizeof(spb), &dir->i_sb);

    struct list_head s_mounts;
    bpf_probe_read(&s_mounts, sizeof(s_mounts), &spb->s_mounts);

    // bpf_probe_read(&mount_id, sizeof(int), &((struct mount *) s_mounts.next)->mnt_id);
    bpf_probe_read(&mount_id, sizeof(int), (char *)s_mounts.next + get_mount_offset_of_mount_id());

    return mount_id;
}

// get_dentry_inode - Returns the inode structure designated by the provided dentry
__attribute__((always_inline)) struct inode *get_dentry_inode(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);
    return d_inode;
}

// write_dentry_inode - Writes the inode structure designated by the provided dentry
__attribute__((always_inline)) void write_dentry_inode(struct dentry *dentry, struct inode **d_inode)
{
    bpf_probe_read(d_inode, sizeof(d_inode), &dentry->d_inode);
}

// get_inode_dev - Returns the device number to which the provided inode belongs
__attribute__((always_inline)) dev_t get_inode_dev(struct inode *inode) {
    dev_t dev;
    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

// get_dentry_dev - Returns the device number to which the provided dentry belongs
__attribute__((always_inline)) dev_t get_dentry_dev(struct dentry *dentry) {
    dev_t dev;
    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &dentry->d_sb);
    bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);
    return dev;
}

// get_inode_mountpoint - Returns a pointer to the dentry of the mountpoint to which the provided inode belongs
__attribute__((always_inline)) struct dentry *get_inode_mountpoint(struct inode *dir) {
    // Mount ID
    struct dentry *mountpoint = NULL;
    struct super_block *spb;
    bpf_probe_read(&spb, sizeof(spb), &dir->i_sb);

    struct list_head s_mounts;
    bpf_probe_read(&s_mounts, sizeof(s_mounts), &spb->s_mounts);

    bpf_probe_read(&mountpoint, sizeof(mountpoint), (void *) s_mounts.next - 88);
    // bpf_probe_read(&mountpoint, sizeof(mountpoint), (void *) s_mounts.next - offsetof(struct mount, mnt_instance) + offsetof(struct mount, mnt_mountpoint));

    return mountpoint;
}

// get_dentry_ino - Returns the inode number of the inode designated by the provided dentry
__attribute__((always_inline)) unsigned long get_dentry_ino(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);
    return get_inode_ino(d_inode);
}

// get_file_inode - Returns the inode of the provided file
__attribute__((always_inline)) struct inode *get_file_inode(struct file *file)
{
    struct inode *f_inode;
    bpf_probe_read(&f_inode, sizeof(f_inode), &file->f_inode);
    return f_inode;
}

// get_file_dentry - Returns the dentry of the provided file
__attribute__((always_inline)) struct dentry *get_file_dentry(struct file *file)
{
    struct dentry *f_dentry;
    bpf_probe_read(&f_dentry, sizeof(f_dentry), &file->f_path.dentry);
    return f_dentry;
}

// get_inode_dentry - Returns the dentry relative to the provided inode
__attribute__((always_inline)) struct dentry *get_inode_dentry(struct inode *inode)
{
    struct dentry *dentry;
    // bpf_probe_read(&dentry, sizeof(struct dentry*), (char *)inode - offsetof(struct dentry, d_inode));
    // bpf_probe_read(&dentry, sizeof(struct dentry*), (char *)inode - DENTRY_OFFSETOF_INODE);
    bpf_probe_read(&dentry, sizeof(struct dentry*), (char *)inode - offsetof(struct dentry, d_inode));
    return dentry;
}

#define DENTRY_MAX_DEPTH 70

// resolve_dentry_fragments - Resolves a dentry into multiple fragments, one per parent of the initial dentry.
// Each fragment is saved in a linked list inside the path_fragments hashmap.
// @dentry: pointer to the initial dentry to resolve
// @key: first key of the fragments linked list in the path_fragment hashmap
__attribute__((always_inline)) static int resolve_dentry_fragments(struct dentry *dentry, struct path_key_t *key)
{
    struct path_fragment_t map_value = {};
    struct path_key_t next_key = {};
    next_key = *key;
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *inode_tmp;

    #pragma unroll
    for (int i = 0; i < DENTRY_MAX_DEPTH; i++)
    {
        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&map_value.name, sizeof(map_value.name), (void*) qstr.name);
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
        *key = next_key;
        if (dentry == d_parent) {
            next_key.ino = 0;
        } else {
            write_dentry_inode(d_parent, &inode_tmp);
            write_inode_ino(inode_tmp, &next_key.ino);
        }
        if (map_value.name[0] == '/' || map_value.name[0] == 0) {
            next_key.ino = 0;
        }

        map_value.parent = next_key;

        if (bpf_map_lookup_elem(&path_fragments, key) == NULL) {
            bpf_map_update_elem(&path_fragments, key, &map_value, BPF_ANY);
        } else {
            return i + 1;
        }

        dentry = d_parent;
        if (next_key.ino == 0)
            return i + 1;
    }

    if (next_key.ino != 0) {
        map_value.name[0] = map_value.name[0];
        map_value.parent.mount_id = 0;
        map_value.parent.ino = 0;
        bpf_map_update_elem(&path_fragments, &next_key, &map_value, BPF_ANY);
    }

    return DENTRY_MAX_DEPTH;
}

__attribute__((always_inline)) static void embed_pathname(struct path_key_t *base_key,
                                                          struct dentry_cache_t *cache,
                                                          int flag) {
    struct path_key_t key = {};
    key.ino = new_fake_inode();
    key.mount_id = base_key->mount_id;

    u32 cpu = bpf_get_smp_processor_id();
    struct path_fragment_t *value = bpf_map_lookup_elem(&path_fragment_builder, &cpu);
    if (!value)
        return;

    value->parent = *base_key;
    // Invalidate the fragment for the pathname as it is supposed to be unique
    bpf_map_delete_elem(&path_fragments, &key);
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        bpf_probe_read_str(&value->name, sizeof(value->name), (void *)cache->pathname);
    } else {
        bpf_probe_read_str(&value->name, sizeof(value->name), (void *)cache->target_pathname);
    }
#ifdef DEBUG
    bpf_printk("embed_path: name=%s, ino=%ld/mnt_id=%d.",
               value->name, key.ino, key.mount_id);
    bpf_printk("embed_path: parent=ino:%ld/mnt_id=%d (%ld/%d).",
               value->parent.ino, value->parent.mount_id,
               key.ino, key.mount_id);
#endif
    bpf_map_update_elem(&path_fragments, &key, value, BPF_ANY);
    // Override the path key for pathname
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        cache->fs_event.src_inode=key.ino;
        cache->fs_event.src_mount_id=key.mount_id;
    } else {
        cache->fs_event.target_inode=key.ino;
        cache->fs_event.target_mount_id=key.mount_id;
    }
}

// resolve_paths - Resolves the paths of an event using the multiple fragments method. This method creates an entry in a hashmap for each
// parent of the paths that need to be resolved.
// @ctx: pointer to the registers context structure used to send the perf event.
// @cache: pointer to the dentry_cache_t structure that contains the source and target dentry to resolve
// @fs_event: pointer to an fs_event structure on the stack of the eBPF program that will be used to send the perf event
// flag: defines what dentry should be resolved.
__attribute__((always_inline)) static int resolve_paths(void *ctx, struct dentry_cache_t *cache, u8 flag) {
    struct path_key_t key = {};
    if ((flag & RESOLVE_SRC) == RESOLVE_SRC) {
        if (cache->fs_event.event == EVENT_RENAME || cache->fs_event.event == EVENT_LINK) {
            key.ino = cache->fs_event.src_path_key;
        } else {
            key.ino = cache->fs_event.src_inode;
        }
        key.mount_id = cache->fs_event.src_mount_id;
        if (cache->pathname) {
            embed_pathname(&key, cache, flag&RESOLVE_SRC);
        }
        resolve_dentry_fragments(cache->src_dentry, &key);
    }
    if ((flag & RESOLVE_TARGET) == RESOLVE_TARGET) {
        key.ino = cache->fs_event.target_inode;
        key.mount_id = cache->fs_event.target_mount_id;
        if (cache->fs_event.event == EVENT_RENAME || cache->fs_event.event == EVENT_LINK) {
            // Make sure to resolve the new inode regardless of the cache
            bpf_map_delete_elem(&path_fragments, &key);
            bpf_printk("resolve_paths: remove entry for ino=%ld/mnt_id=%d",
                       key.ino, key.mount_id);
        }
        if (cache->target_pathname) {
            embed_pathname(&key, cache, flag&RESOLVE_TARGET);
        }
        resolve_dentry_fragments(cache->target_dentry, &key);
    }

    if ((flag & EMIT_EVENT) == EMIT_EVENT) {
        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &fs_events, cpu, &cache->fs_event, sizeof(cache->fs_event));
    }
    return 0;
}

__attribute__((always_inline)) static void reset_cache_entry(struct dentry_cache_t *data_cache) {
    data_cache->fs_event.src_path_key = 0;
    data_cache->fs_event.target_path_key = 0;
    data_cache->fs_event.mode = 0;
    data_cache->fs_event.flags = 0;
    data_cache->cursor = 0;
    data_cache->pathname = 0;
    data_cache->target_pathname = 0;
}

//__attribute__((always_inline)) static int is_null_path_key(struct path_key_t *key) {
//    if (key->inode == 0 && key->mount_id == 0)
//        return 1;
//    return 0;
//}

#endif
