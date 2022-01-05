#ifndef _FILENAME_H_
#define _FILENAME_H_

#include "syscalls.h"

SEC("kprobe/filename_create")
int kprobe_filename_create(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall)
        return 0;

    switch (syscall->type) {
        case EVENT_MKDIR:
            bpf_printk("filename_create_e: mkdir.");
            syscall->mkdir.path = (struct path *)PT_REGS_PARM3(ctx);
            break;
       case EVENT_LINK:
            bpf_printk("filename_create_e: link.");
            syscall->link.target_path = (struct path *)PT_REGS_PARM3(ctx);
            break;
    }
    return 0;
}

// TODO(dima): remove me, this is for debugging
SEC("kretprobe/filename_create")
int kprobe_filename_create_ret(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall)
        return 0;

    int ret = PT_REGS_RC(ctx);
    switch (syscall->type) {
        case EVENT_MKDIR:
            bpf_printk("filename_create_x: mkdir, ret=%ld.", ret);
            syscall->mkdir.path = (struct path *)PT_REGS_PARM3(ctx);
            break;
       case EVENT_LINK:
            bpf_printk("filename_create_x: link.");
            syscall->link.target_path = (struct path *)PT_REGS_PARM3(ctx);
            break;
    }
    return 0;
}

// Capture the base directory metadata for the lookup failure
// cases - e.g. ENOENT
SEC("kprobe/link_path_walk")
int kprobe_link_path_walk(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall)
        return 0;

    switch (syscall->type) {
        case EVENT_MKDIR:
            {
                // nameidata.path
                struct path *base_path = (struct path *)PT_REGS_PARM2(ctx);
                syscall->mkdir.file.path_key.mount_id = get_path_mount_id(base_path);
                syscall->mkdir.file.path_key.ino = get_path_dentry_ino(base_path);
#ifdef DEBUG
                bpf_printk("link_path_walk_e: mkdir, mnt_id=%ld, ino=%ld.",
                           syscall->mkdir.file.path_key.mount_id,
                           syscall->mkdir.file.path_key.ino);
#endif
            }
            break;
    }
    return 0;
}

#endif
