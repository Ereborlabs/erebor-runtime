// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright Erebor Labs and contributors */
#include "vmlinux.h"
#include "erebor_interceptor_abi.h"
#include "linux_uapi.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "identity_maps.h"

_Static_assert(sizeof(task_label_v1) == 328, "task label ABI size");
_Static_assert(sizeof(task_coordinate_v1) == 88, "task coordinate ABI size");
_Static_assert(sizeof(identity_runtime_config_v1) == 48,
               "identity runtime config ABI size");
_Static_assert(__builtin_offsetof(task_label_v1, process_state_id) == 64,
               "task process-state offset");
_Static_assert(sizeof(effect_decision_key_v1) == 40,
               "effect decision key ABI size");
_Static_assert(sizeof(effect_default_key_v1) == 32,
               "effect default key ABI size");
_Static_assert(sizeof(ipc_relationship_decision_key_v1) == 24,
               "IPC relationship key ABI size");
_Static_assert(sizeof(ipc_socket_state_v1) == 216,
               "IPC socket state ABI size");
_Static_assert(sizeof(network_ipv4_lpm_key_v1) == 32,
               "network IPv4 LPM key ABI size");
_Static_assert(sizeof(network_ipv6_lpm_key_v1) == 40,
               "network IPv6 LPM key ABI size");
_Static_assert(sizeof(network_destination_class_v1) == 48,
               "network destination class ABI size");
_Static_assert(sizeof(network_destination_decision_key_v1) == 32,
               "network destination decision key ABI size");
_Static_assert(sizeof(network_socket_state_v1) == 144,
               "network socket state ABI size");
_Static_assert(sizeof(network_response_floor_key_v1) == 24,
               "network response key ABI size");
_Static_assert(sizeof(network_response_floor_v1) == 8,
               "network response floor ABI size");
_Static_assert(sizeof(device_effect_key_v1) == 80,
               "device effect key ABI size");
_Static_assert(sizeof(process_control_rule_key_v1) == 32,
               "process-control rule key ABI size");
_Static_assert(sizeof(physical_decision_v1) == 16,
               "physical decision ABI size");
_Static_assert(sizeof(policy_activation_probe_v1) == 112,
               "policy activation probe ABI size");
_Static_assert(sizeof(profile_generation_descriptor_v1) == 112,
               "profile generation descriptor ABI size");
_Static_assert(sizeof(exception_runtime_state_key_v1) == 32,
               "exception runtime key ABI size");
_Static_assert(sizeof(exception_handle_binding_key_v1) == 16,
               "exception handle binding key ABI size");
_Static_assert(sizeof(exception_handle_binding_v1) == 40,
               "exception handle binding ABI size");
_Static_assert(sizeof(exception_runtime_state_v1) == 72,
               "exception runtime state ABI size");
_Static_assert(sizeof(exception_use_receipt_key_v1) == 104,
               "exception receipt key ABI size");
_Static_assert(sizeof(exception_use_receipt_v1) == 24,
               "exception receipt ABI size");
_Static_assert(sizeof(task_effect_attempt_frame_v1) == 24,
               "effect attempt frame ABI size");
_Static_assert(sizeof(task_effect_attempt_state_v1) == 128,
               "effect attempt state ABI size");
_Static_assert(sizeof(io_uring_setup_state_v1) == 32,
               "io_uring setup state ABI size");
_Static_assert(sizeof(io_uring_actor_snapshot_v1) == 232,
               "io_uring actor snapshot ABI size");
_Static_assert(sizeof(execution_set_binding_state_v1) == 224,
               "execution-set binding ABI size");
_Static_assert(sizeof(entry_admission_rule_key_v1) == 40,
               "entry admission key ABI size");
_Static_assert(sizeof(entry_admission_rule_v1) == 64,
               "entry admission rule ABI size");
_Static_assert(sizeof(declared_entry_request_v1) == 4104,
               "declared entry request ABI size");
_Static_assert(sizeof(io_uring_ring_state_v1) == 528,
               "io_uring ring state ABI size");
_Static_assert(sizeof(io_uring_request_state_v1) == 344,
               "io_uring request state ABI size");
_Static_assert(sizeof(io_uring_execution_state_v1) == 64,
               "io_uring execution state ABI size");
_Static_assert(sizeof(struct exception_runtime_state_bpf_v1) ==
                   sizeof(exception_runtime_state_v1),
               "exception runtime BPF state ABI size");
#define ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(field)                         \
    _Static_assert(                                                          \
        __builtin_offsetof(struct exception_runtime_state_bpf_v1, field) ==  \
            __builtin_offsetof(exception_runtime_state_v1, field),           \
        "exception runtime " #field " ABI offset")
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(lock);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(maximum_uses);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(consumed_uses);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(bound_profile_generation_refs);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(deadline_boottime_ns);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(transition_version);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(exception_definition_sha256);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(state);
ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET(reserved);
#undef ASSERT_EXCEPTION_RUNTIME_FIELD_OFFSET
_Static_assert(sizeof(exact_file_object_key_v1) == 40,
               "exact file object ABI size");
_Static_assert(sizeof(exact_file_measurement_v1) == 48,
               "exact file measurement ABI size");
_Static_assert(sizeof(exact_object_binding_v1) == 32,
               "exact object binding ABI size");
_Static_assert(sizeof(effect_observation_v1) == 536,
               "effect observation ABI size");
_Static_assert(sizeof(effect_observation_health_v1) == 64,
               "effect observation health ABI size");
_Static_assert(sizeof(canonical_path_component_v1) == 258,
               "canonical component ABI size");
_Static_assert(sizeof(path_graph_transition_key_v1) == 272,
               "path transition key ABI size");
_Static_assert(sizeof(path_graph_terminal_v1) == 16,
               "path terminal ABI size");
_Static_assert(sizeof(path_tree_deny_key_v1) == 16,
               "path-tree denial key ABI size");
_Static_assert(sizeof(canonical_mount_root_v1) == 88,
               "canonical mount root ABI size");
_Static_assert(sizeof(mount_security_view_state_v1) == 40,
               "mount view ABI size");
_Static_assert(sizeof(mount_mutation_attempt_v1) == 8,
               "mount mutation attempt ABI size");

#include "identity_task_helpers.h"
#include "identity_prepared_container.h"
#include "identity_root_helpers.h"
#include "identity_path.bpf.h"

SEC("classifier")
int erebor_policy_activation_probe(struct __sk_buff *context)
{
    __u32 request_key = 0;
    policy_activation_probe_v1 *request;
    struct identity_scratch_v1 *scratch;
    physical_decision_v1 *decision = NULL;
    approved_exec_slot_v1 *administrative_slot;

    (void)context;
    request = bpf_map_lookup_elem(&policy_activation_probe_requests,
                                  &request_key);
    if (!request || request->reserved_alignment)
        return 2;
    scratch = identity_scratch_record();
    if (!scratch)
        return 3;
    switch (request->map_kind) {
    case policy_activation_probe_map_kind_v1_effect_decision:
        if (request->key_size != sizeof(scratch->effect_key))
            return 4;
        __builtin_memcpy(&scratch->effect_key, request->key,
                         sizeof(scratch->effect_key));
        decision = bpf_map_lookup_elem(&effect_decisions,
                                       &scratch->effect_key);
        break;
    case policy_activation_probe_map_kind_v1_effect_default:
        if (request->key_size != sizeof(scratch->effect_default))
            return 4;
        __builtin_memcpy(&scratch->effect_default, request->key,
                         sizeof(scratch->effect_default));
        decision = bpf_map_lookup_elem(&effect_defaults,
                                       &scratch->effect_default);
        break;
    case policy_activation_probe_map_kind_v1_ipc_relationship:
        if (request->key_size != sizeof(scratch->ipc_relationship_key))
            return 4;
        __builtin_memcpy(&scratch->ipc_relationship_key, request->key,
                         sizeof(scratch->ipc_relationship_key));
        decision = bpf_map_lookup_elem(&ipc_relationship_decisions,
                                       &scratch->ipc_relationship_key);
        break;
    case policy_activation_probe_map_kind_v1_device_effect:
        if (request->key_size != sizeof(scratch->device_effect_key))
            return 4;
        __builtin_memcpy(&scratch->device_effect_key, request->key,
                         sizeof(scratch->device_effect_key));
        decision = bpf_map_lookup_elem(&device_effect_decisions,
                                       &scratch->device_effect_key);
        break;
    case policy_activation_probe_map_kind_v1_process_control:
        if (request->key_size != sizeof(scratch->process_control_rule_key))
            return 4;
        __builtin_memcpy(&scratch->process_control_rule_key, request->key,
                         sizeof(scratch->process_control_rule_key));
        decision = bpf_map_lookup_elem(&process_control_rules,
                                       &scratch->process_control_rule_key);
        break;
    case policy_activation_probe_map_kind_v1_network_destination:
        if (request->key_size != sizeof(scratch->network_destination_key))
            return 4;
        __builtin_memcpy(&scratch->network_destination_key, request->key,
                         sizeof(scratch->network_destination_key));
        decision = bpf_map_lookup_elem(&network_destination_decisions,
                                       &scratch->network_destination_key);
        break;
    case policy_activation_probe_map_kind_v1_administrative_slot_cancel:
        if (request->key_size != sizeof(scratch->administrative_slot_key) +
                                     sizeof(scratch->administrative_match.proof_id) +
                                     sizeof(scratch->administrative_match.claim_slot_id))
            return 4;
        __builtin_memcpy(&scratch->administrative_slot_key, request->key,
                         sizeof(scratch->administrative_slot_key));
        __builtin_memcpy(&scratch->administrative_match.proof_id,
                         request->key + sizeof(scratch->administrative_slot_key),
                         sizeof(scratch->administrative_match.proof_id));
        __builtin_memcpy(
            &scratch->administrative_match.claim_slot_id,
            request->key + sizeof(scratch->administrative_slot_key) +
                sizeof(scratch->administrative_match.proof_id),
            sizeof(scratch->administrative_match.claim_slot_id));
        administrative_slot = bpf_map_lookup_elem(
            &approved_exec_slots, &scratch->administrative_slot_key);
        if (!administrative_slot)
            return 7;
        if (!id128_equal(&administrative_slot->proof_id,
                         &scratch->administrative_match.proof_id) ||
            !id128_equal(&administrative_slot->claim_slot_id,
                         &scratch->administrative_match.claim_slot_id))
            return 8;
        if (administrative_slot->state == approved_exec_slot_state_v1_consumed)
            return 9;
        if (administrative_slot->state == approved_exec_slot_state_v1_cancelled ||
            administrative_slot->state == approved_exec_slot_state_v1_expired ||
            administrative_slot->state == approved_exec_slot_state_v1_corrupt)
            return 10;
        if (administrative_slot->state != approved_exec_slot_state_v1_armed)
            return 8;
        if (__sync_val_compare_and_swap(
                &administrative_slot->state,
                approved_exec_slot_state_v1_armed,
                approved_exec_slot_state_v1_cancelled) !=
            approved_exec_slot_state_v1_armed)
            return 11;
        __sync_fetch_and_add(&administrative_slot->transition_version, 1);
        return 1;
    case policy_activation_probe_map_kind_v1_mount_reconciliation:
        if (request->key_size !=
            sizeof(scratch->file_object.mount_namespace_inode))
            return 4;
        if (request->expected.decision != physical_decision_kind_v1_allow ||
            request->expected.reserved || request->expected.errno ||
            request->expected.evidence_class_id ||
            request->expected.transition_id ||
            request->expected.exception_numeric_handle)
            return 4;
        __builtin_memcpy(&scratch->file_object.mount_namespace_inode,
                         request->key,
                         sizeof(scratch->file_object.mount_namespace_inode));
        if (!scratch->file_object.mount_namespace_inode)
            return 4;
        if (commit_mount_reconciliation_proposal(
                scratch->file_object.mount_namespace_inode))
            return 12;
        return 1;
    default:
        return 4;
    }
    if (!decision)
        return 5;
    if (decision->decision != request->expected.decision ||
        decision->reserved != request->expected.reserved ||
        decision->errno != request->expected.errno ||
        decision->evidence_class_id != request->expected.evidence_class_id ||
        decision->transition_id != request->expected.transition_id ||
        decision->exception_numeric_handle !=
            request->expected.exception_numeric_handle)
        return 6;
    return 1;
}

#include "identity_lifecycle.bpf.h"
static __noinline int identity_effect_gate(struct file *file,
                                           __u16 effect_family,
                                           __u16 operation, int ret);
static __noinline int identity_path_effect_gate(const struct path *path,
                                                __u16 effect_family,
                                                __u16 operation, int ret);
static __noinline int identity_effect_actor_gate(
    struct file *file, __u16 effect_family, __u16 operation, int ret);
static __always_inline int prepared_runtime_effect_result(
    struct identity_scratch_v1 *scratch);
static __always_inline int runtime_entry_infrastructure_effect_result(
    struct identity_scratch_v1 *scratch);
static __always_inline int hard_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    __u8 reason);
static __noinline int prepared_exec_policy_gate(struct file *file);
static __noinline int resolved_io_uring_effect_gate(
    struct file *file, __u16 effect_family, __u16 operation, int ret,
    struct identity_scratch_v1 *scratch);
static __noinline int io_uring_file_mapping_gate(
    struct file *file, unsigned long reqprot, unsigned long prot,
    unsigned long flags, int ret);
#include "identity_exec.bpf.h"
#include "identity_effects.bpf.h"
#include "identity_io_uring.bpf.h"
#include "identity_exit.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
