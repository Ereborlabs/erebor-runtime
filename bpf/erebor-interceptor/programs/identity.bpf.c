// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright Erebor Labs and contributors */
#include "vmlinux.h"
#include "erebor_interceptor_abi.h"
#include "linux_uapi.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "identity_maps.h"

_Static_assert(sizeof(task_label_v1) == 328, "task label ABI size");
_Static_assert(sizeof(task_coordinate_v1) == 96, "task coordinate ABI size");
_Static_assert(sizeof(identity_runtime_config_v1) == 40,
               "identity runtime config ABI size");
_Static_assert(__builtin_offsetof(task_label_v1, process_state_id) == 64,
               "task process-state offset");

#include "identity_task_helpers.h"
#include "identity_root_helpers.h"

#include "identity_lifecycle.bpf.h"
#include "identity_exec.bpf.h"
#include "identity_effects.bpf.h"
#include "identity_exit.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
