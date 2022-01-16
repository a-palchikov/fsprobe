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
#ifndef _MAPS_H_
#define _MAPS_H_

#include "defs.h"

// fs_event_t - File system event structure
struct fs_event_t
{
    struct process_ctx_t process_data;
    int flags;
    int mode;
    u32 src_path_key;
    u32 target_path_key;
    struct path_key_t src_key;
    struct path_key_t target_key;
    u32 src_path_length;
    u32 target_path_length;
    int retval;
    u32 event;
};

// fs_events - Perf buffer used to send file system events back to user space
struct bpf_map_def SEC("maps/fs_events") fs_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_cache_t - Dentry cache structure used to cache context between kprobes entry and return
struct dentry_cache_t
{
    struct fs_event_t fs_event;
    struct path *path;
    struct inode *src_dir;
    struct dentry *src_dentry;
    struct inode *target_dir;
    struct dentry *target_dentry;
    // pathname optionally specifies the pathname
    // in case of failure
    const char *pathname;
    const char *target_pathname;
    u32 cursor;
};

// dentry_cache - Dentry cache map used to store dentry cache structures between 2 eBPF programs
struct bpf_map_def SEC("maps/dentry_cache") dentry_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 1000,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_cache_builder - Dentry cache builder map used to reduce the amount of data on the stack
struct bpf_map_def SEC("maps/dentry_cache_builder") dentry_cache_builder = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 32,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_open_cache - Auxiliary map used to share dentry cache values between probes
struct bpf_map_def SEC("maps/dentry_open_cache") dentry_open_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 1000,
    .pinning = PIN_NONE,
    .namespace = "",
};

// dentry_open_cache_builder - Auxiliary map used to reduce the amount of data on the stack
// between path_openat probes
struct bpf_map_def SEC("maps/dentry_open_cache_builder") dentry_open_cache_builder = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct dentry_cache_t),
    .max_entries = 32,
    .pinning = PIN_NONE,
    .namespace = "",
};

// path_fragment_t - Structure used to store path leaf during the path resolution process
struct path_fragment_t
{
    struct path_key_t parent;
    char name[NAME_MAX];
};

// path_fragments - Map used to store path fragments. The user space program will recover the fragments from this map.
struct bpf_map_def SEC("maps/path_fragments") path_fragments = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct path_key_t),
    .value_size = sizeof(struct path_fragment_t),
    .max_entries = 10000,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/path_fragment_builder") path_fragment_builder = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct path_fragment_t),
    .max_entries = 32,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct bpf_map_def SEC("maps/inodes_filter") inodes_filter = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct path_key_t),
    .value_size = sizeof(u8),
    .max_entries = 120000,
    .pinning = PIN_NONE,
    .namespace = "",
};

#define MAX_PATH_LEN 128

struct basename {
    char name[MAX_PATH_LEN];
};

#endif
