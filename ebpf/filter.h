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
#ifndef _FILTER_H_
#define _FILTER_H_

#define FILTER_SRC     1 << 1
#define FILTER_TARGET  1 << 2

// Returns 1 if there is a match for the given source (or its parent) inode.
// Returns 0 if no match found
__attribute__((always_inline)) static int match_src(struct dentry_cache_t *data_cache)
{
    // Look for the inode in the cached_inodes map
    if (bpf_map_lookup_elem(&inodes_filter, &data_cache->fs_event.src_key) == NULL) {
        // Look for the parent inode
        struct dentry *d_parent;
        bpf_probe_read(&d_parent, sizeof(d_parent), &data_cache->src_dentry->d_parent);
        u32 ino = get_dentry_ino(d_parent);
        struct path_key_t key = data_cache->fs_event.src_key;
        key.ino = ino;
        if (bpf_map_lookup_elem(&inodes_filter, &key) == NULL) {
            return 0;
        } else {
#ifdef DEBUG_FILTER
            bpf_printk("filter(src): matched on par.ino=%ld.", ino);
#endif
        }
    }
#ifdef DEBUG_FILTER
    bpf_printk("filter(src): matched on ino=%ld.", data_cache->fs_event.src_key.ino);
#endif
    return 1;
}

// Returns 1 if there is a match for the given target (or its parent) inode.
// Returns 0 if no match found
__attribute__((always_inline)) static int match_target(struct dentry_cache_t *data_cache)
{
    // Look for the inode in the cached_inodes map
    if (bpf_map_lookup_elem(&inodes_filter, &data_cache->fs_event.target_key) == NULL) {
        // Look for the parent inode
        struct dentry *d_parent;
        bpf_probe_read(&d_parent, sizeof(d_parent), &data_cache->target_dentry->d_parent);
        u32 ino = get_dentry_ino(d_parent);
        struct path_key_t key = data_cache->fs_event.target_key;
        key.ino = ino;
        if (bpf_map_lookup_elem(&inodes_filter, &key) == NULL) {
            return 0;
        } else {
#ifdef DEBUG_FILTER
            bpf_printk("filter(tgt): matched on par.ino=%ld.", ino);
#endif
        }
    }
#ifdef DEBUG_FILTER
    bpf_printk("filter(tgt): matched on ino=%ld.", data_cache->fs_event.target_key.ino);
#endif
    return 1;
}

// Returns 1 if there's a match for the inode given with data_cache.
// flag defines which side (source or target) to test.
// If the filtering mode is off or there is a match, returns 1.
// Returns 0 if no match found
__attribute__((always_inline)) static int match(struct dentry_cache_t *data_cache, u8 flag)
{
    u64 inode_filtering_mode = load_inode_filtering_mode();
    if (inode_filtering_mode == 0) {
        // Always matches
        return 1;
    }
    if ((flag & FILTER_SRC) == FILTER_SRC) {
        if (!match_src(data_cache)) {
            return 0;
        }
    }
    if ((flag & FILTER_TARGET) == FILTER_TARGET) {
        if (!match_target(data_cache)) {
            return 0;
        }
    }
    return 1;
}

#endif
