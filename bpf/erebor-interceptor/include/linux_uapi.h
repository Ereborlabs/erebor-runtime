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
#define VM_WRITE 0x00000002
#define VM_EXEC 0x00000004
#define AF_UNIX 1
#define SOCK_STREAM 1
#define S_IFMT 00170000
#define S_IFIFO 0010000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFSOCK 0140000

#endif /* EREBOR_LINUX_UAPI_H */
