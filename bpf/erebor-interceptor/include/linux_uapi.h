/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef EREBOR_LINUX_UAPI_H
#define EREBOR_LINUX_UAPI_H

/*
 * Minimal Linux UAPI subset used by the CO-RE program. These standard macros
 * are absent from BTF/vmlinux.h; including the full host UAPI headers would
 * make a target-specific build depend on the build host's asm headers.
 */
#define EACCES 13
#define CLONE_PARENT 0x00008000
#define CLONE_THREAD 0x00010000
#define AT_EXECVE_CHECK 0x10000

#endif /* EREBOR_LINUX_UAPI_H */
