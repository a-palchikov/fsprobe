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
            syscall->mkdir.path = (struct path *)PT_REGS_PARM3(ctx);
            break;

       case EVENT_LINK:
            syscall->link.target_path = (struct path *)PT_REGS_PARM3(ctx);
            break;
    }
    return 0;
}

//SEC("kretprobe/filename_create")
//int kprobe_filename_create_ret(struct pt_regs *ctx) {
//    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
//    if (!syscall)
//        return 0;
//
//    //int ret = PT_REGS_RC(ctx);
//    switch (syscall->type) {
//        case EVENT_MKDIR:
//            //bpf_printk("filename_create_x: mkdir, ret=%d.", ret);
//            break;
//
//       case EVENT_LINK:
//            //bpf_printk("filename_create_x: link, ret=%d.", ret);
//            break;
//    }
//    return 0;
//}

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
        case EVENT_RMDIR:
            {
                // nameidata.path
                struct path *base_path = (struct path *)PT_REGS_PARM2(ctx);
                syscall->rmdir.file.path_key.mount_id = get_path_mount_id(base_path);
                syscall->rmdir.file.path_key.ino = get_path_dentry_ino(base_path);
#ifdef DEBUG
                bpf_printk("link_path_walk_e: rmdir, mnt_id=%ld, ino=%ld.",
                           syscall->rmdir.file.path_key.mount_id,
                           syscall->rmdir.file.path_key.ino);
#endif
            }
            break;
        case EVENT_UNLINK:
            {
                // nameidata.path
                struct path *base_path = (struct path *)PT_REGS_PARM2(ctx);
                syscall->unlink.file.path_key.mount_id = get_path_mount_id(base_path);
                syscall->unlink.file.path_key.ino = get_path_dentry_ino(base_path);
#ifdef DEBUG
                bpf_printk("link_path_walk_e: unlink, base dir mnt_id=%ld/ino=%ld.",
                           syscall->unlink.file.path_key.mount_id,
                           syscall->unlink.file.path_key.ino);
#endif
            }
            break;
        case EVENT_OPEN:
            {
                // nameidata.path
                struct path *base_path = (struct path *)PT_REGS_PARM2(ctx);
                syscall->open.file.path_key.mount_id = get_path_mount_id(base_path);
                syscall->open.file.path_key.ino = get_path_dentry_ino(base_path);
#ifdef DEBUG
                bpf_printk("link_path_walk_e: open, base dir mnt_id=%ld/ino=%ld.",
                           syscall->open.file.path_key.mount_id,
                           syscall->open.file.path_key.ino);
#endif
            }
            break;
        case EVENT_RENAME:
            {
                // nameidata.path
#ifdef DEBUG
                u64 ino = 0;
                u32 mnt_id = 0;
#endif
                struct path *base_path = (struct path *)PT_REGS_PARM2(ctx);
                if (!syscall->rename.src_file.path_key.mount_id) {
                    syscall->rename.src_file.path_key.mount_id = get_path_mount_id(base_path);
                    syscall->rename.src_file.path_key.ino = get_path_dentry_ino(base_path);
                    syscall->rename.src_dentry = get_path_dentry(base_path);
#ifdef DEBUG
                    ino = syscall->rename.src_file.path_key.ino;
                    mnt_id = syscall->rename.src_file.path_key.mount_id;
#endif
                } else if (!syscall->rename.target_file.path_key.mount_id) {
                    syscall->rename.target_file.path_key.mount_id = get_path_mount_id(base_path);
                    syscall->rename.target_file.path_key.ino = get_path_dentry_ino(base_path);
                    syscall->rename.target_dentry = get_path_dentry(base_path);
#ifdef DEBUG
                    ino = syscall->rename.target_file.path_key.ino;
                    mnt_id = syscall->rename.target_file.path_key.mount_id;
#endif
                }
#ifdef DEBUG
                const char *name = (const char *)PT_REGS_PARM1(ctx);
                bpf_printk("link_path_walk_e: rename, name=%s.", name);
                bpf_printk("link_path_walk_e: rename, base dir ino=%ld/mnt_id=%d.",
                           ino, mnt_id);
#endif
            }
            break;
    }
    return 0;
}

#endif
