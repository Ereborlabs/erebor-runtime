/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Derived from Cilium Tetragon's bpf/include/vmlinux.h at
 * dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c. Copyright Authors of Cilium.
 */
#ifndef EREBOR_VMLINUX_H
#define EREBOR_VMLINUX_H

#define BPF_NO_PRESERVE_ACCESS_INDEX

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_generated_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_generated_arm64.h"
#elif defined(__TARGET_ARCH_arm)
#include "vmlinux_generated_arm.h"
#elif defined(__TARGET_ARCH_riscv)
#include "vmlinux_generated_riscv.h"
#else
#error "unsupported BPF target architecture"
#endif

#endif /* EREBOR_VMLINUX_H */
