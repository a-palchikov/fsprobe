


struct syscall_cache_t {
    //struct policy_t policy;
    u64 type;

    //struct dentry_resolver_input_t resolver;

    union {
        struct {
            int flags;
            umode_t mode;
            struct dentry *dentry;
            struct file_t file;
        } open;

        struct {
            umode_t mode;
            struct dentry *dentry;
            struct path *path;
            struct file_t file;
        } mkdir;

        struct {
            struct dentry *dentry;
            struct file_t file;
            int flags;
        } unlink;

        struct {
            struct dentry *dentry;
            struct file_t file;
        } rmdir;

        struct {
            struct file_t src_file;
            unsigned long src_inode;
            struct dentry *src_dentry;
            struct dentry *target_dentry;
            struct file_t target_file;
        } rename;

        struct {
            struct file_t src_file;
            struct path *target_path;
            struct dentry *src_dentry;
            struct dentry *target_dentry;
            struct file_t target_file;
        } link;

        struct {
            struct dentry *dentry;
            struct file_t file;
            const char *name;
        } xattr;
    };
};

struct bpf_map_def SEC("maps/syscalls") syscalls = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct syscall_cache_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct policy_t __attribute__((always_inline)) fetch_policy(u64 event_type) {
    struct policy_t *policy = bpf_map_lookup_elem(&filter_policy, &event_type);
    if (policy) {
        return *policy;
    }
    struct policy_t empty_policy = { };
    return empty_policy;
}

// cache_syscall checks the event policy in order to see if the syscall struct can be cached
void __attribute__((always_inline)) cache_syscall(struct syscall_cache_t *syscall) {
    u64 key = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&syscalls, &key, syscall, BPF_ANY);
}

struct syscall_cache_t * __attribute__((always_inline)) peek_syscall(u64 type) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *) bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (!type || syscall->type == type) {
        return syscall;
    }
    return NULL;
}

struct syscall_cache_t * __attribute__((always_inline)) peek_syscall_with(int (*predicate)(u64 type)) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *) bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (predicate(syscall->type)) {
        return syscall;
    }
    return NULL;
}

struct syscall_cache_t * __attribute__((always_inline)) pop_syscall_with(int (*predicate)(u64 type)) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *) bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (predicate(syscall->type)) {
        bpf_map_delete_elem(&syscalls, &key);
        return syscall;
    }
    return NULL;
}

struct syscall_cache_t * __attribute__((always_inline)) pop_syscall(u64 type) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *) bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (!type || syscall->type == type) {
        bpf_map_delete_elem(&syscalls, &key);
        return syscall;
    }
    return NULL;
}

//int __attribute__((always_inline)) discard_syscall(struct syscall_cache_t *syscall) {
//    u64 key = bpf_get_current_pid_tgid();
//    bpf_map_delete_elem(&syscalls, &key);
//    return 0;
//}
//
//int __attribute__((always_inline)) mark_as_discarded(struct syscall_cache_t *syscall) {
//    syscall->discarded = 1;
//    return 0;
//}
