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
_Static_assert(sizeof(effect_decision_key_v1) == 48,
               "effect decision key ABI size");
_Static_assert(sizeof(effect_default_key_v1) == 40,
               "effect default key ABI size");
_Static_assert(sizeof(physical_decision_v1) == 16,
               "physical decision ABI size");
_Static_assert(sizeof(profile_generation_descriptor_v1) == 112,
               "profile generation descriptor ABI size");
_Static_assert(sizeof(exact_file_object_key_v1) == 48,
               "exact file object ABI size");
_Static_assert(sizeof(exact_object_binding_v1) == 32,
               "exact object binding ABI size");
_Static_assert(sizeof(effect_observation_v1) == 208,
               "effect observation ABI size");
_Static_assert(sizeof(effect_observation_health_v1) == 32,
               "effect observation health ABI size");
_Static_assert(sizeof(canonical_path_component_v1) == 258,
               "canonical component ABI size");
_Static_assert(sizeof(path_graph_transition_key_v1) == 272,
               "path transition key ABI size");
_Static_assert(sizeof(mount_security_view_state_v1) == 40,
               "mount view ABI size");

#include "identity_task_helpers.h"
#include "identity_root_helpers.h"
#include "identity_path.bpf.h"

#include "identity_lifecycle.bpf.h"
static __noinline int identity_effect_gate(struct file *file,
                                           __u16 effect_family,
                                           __u16 operation, int ret);
#include "identity_exec.bpf.h"
#include "identity_effects.bpf.h"
#include "identity_exit.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
