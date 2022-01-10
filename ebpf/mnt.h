#ifndef _MNT_H_
#define _MNT_H_

#include "syscalls.h"

int __attribute__((always_inline)) mnt_want_write_predicate(u64 type) {
    return type == EVENT_RENAME || type == EVENT_RMDIR || type == EVENT_UNLINK;
}

SEC("kprobe/mnt_want_write")
int kprobe_mnt_want_write(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall_with(mnt_want_write_predicate);
    if (!syscall)
        return 0;

    struct vfsmount *mnt = (struct vfsmount *)PT_REGS_PARM1(ctx);

    switch (syscall->type) {
    case EVENT_MKDIR:
        break;
    case EVENT_RENAME:
        if (syscall->rename.src_file.path_key.mount_id > 0)
            return 0;
        syscall->rename.src_file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        syscall->rename.target_file.path_key.mount_id = syscall->rename.src_file.path_key.mount_id;
        break;
    case EVENT_RMDIR:
        if (syscall->rmdir.file.path_key.mount_id > 0)
            return 0;
        syscall->rmdir.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    case EVENT_UNLINK:
        if (syscall->unlink.file.path_key.mount_id > 0)
            return 0;
        syscall->unlink.file.path_key.mount_id = get_vfsmount_mount_id(mnt);
        break;
    }
    return 0;
}

#endif
