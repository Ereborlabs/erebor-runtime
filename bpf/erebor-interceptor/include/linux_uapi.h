/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef EREBOR_LINUX_UAPI_H
#define EREBOR_LINUX_UAPI_H

/*
 * Minimal Linux UAPI subset used by the CO-RE program. These standard macros
 * are absent from BTF/vmlinux.h; including the full host UAPI headers would
 * make a target-specific build depend on the build host's asm headers.
 */
#define EACCES 13
#define MAX_ERRNO 4095
#define CLONE_PARENT 0x00008000
#define CLONE_THREAD 0x00010000
#define AT_EXECVE_CHECK 0x10000
#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define FMODE_READ 0x00000001
#define FMODE_WRITE 0x00000002
#define FMODE_EXEC 0x00000020
#define __FMODE_EXEC FMODE_EXEC
#define PROT_READ 0x00000001
#define PROT_WRITE 0x00000002
#define PROT_EXEC 0x00000004
#define MAP_ANONYMOUS 0x00000020
#define MAP_SHARED 0x00000001
#define MAP_TYPE 0x0000000f
#define IO_URING_MAPPING_NOT_APPLICABLE_V1 1
#define VM_WRITE 0x00000002
#define VM_EXEC 0x00000004
#define AF_UNIX 1
#define SOCK_STREAM 1
#define S_IFMT 00170000
#define S_IFIFO 0010000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFSOCK 0140000
#define PIPEFS_MAGIC 0x50495045
#define TMPFS_MAGIC 0x01021994
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#define RUNTIME_BOOTSTRAP_REQUIRED_SEALS_V1                                \
    (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)
#define IOSQE_ASYNC (1U << 4)
#define IORING_SETUP_R_DISABLED (1U << 6)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_MITHRIL_V1                                           \
    (IORING_SETUP_R_DISABLED | IORING_SETUP_SINGLE_ISSUER)
#define IORING_REGISTER_RESTRICTIONS 11
#define IORING_REGISTER_ENABLE_RINGS 12
#define IORING_OP_READ 22
#define IORING_OP_WRITE 23
#define IORING_RESTRICTION_REGISTER_OP 0
#define IORING_RESTRICTION_SQE_OP 1

#endif /* EREBOR_LINUX_UAPI_H */
