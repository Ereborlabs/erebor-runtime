// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright Erebor Labs and Authors of Cilium */
#ifndef EREBOR_IDENTITY_MAPS_H
#define EREBOR_IDENTITY_MAPS_H

#define EREBOR_CORE_OFFSETOF(type, member)                                  \
    ((__u64)((char *)__builtin_preserve_access_index(&((type *)0)->member) - \
             (char *)0))
#define EREBOR_CORE_CONTAINER_OF(pointer, type, member)                  \
    ((type *)((char *)(pointer) - EREBOR_CORE_OFFSETOF(type, member)))

union kernfs_node_id___old {
    struct {
        __u32 ino;
        __u32 generation;
    } id;
    __u64 ino64;
} __attribute__((preserve_access_index));

struct kernfs_node___old {
    union kernfs_node_id___old id;
} __attribute__((preserve_access_index));

struct cgroup___new {
    int level;
    struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

struct mount_security_view_lock_v1 {
    struct bpf_spin_lock lock;
};

struct exception_runtime_state_bpf_v1 {
    struct bpf_spin_lock lock;
    __u32 maximum_uses;
    __u32 consumed_uses;
    __u32 bound_profile_generation_refs;
    __u64 deadline_boottime_ns;
    __u64 transition_version;
    __u8 exception_definition_sha256[32];
    exception_runtime_state_kind_v1 state;
    __u8 reserved[7];
};

#define MAX_CGROUP_ANCESTOR_STEPS_V1 64
#define EXCEPTION_USE_RECEIPT_CAPACITY_V1 65536
#define EFFECT_GATE_DEFER_DECISION_V1 1
#define EFFECT_GATE_DENY_EXCEPTION_V1 2
#define EFFECT_GATE_FILE_OPEN_ATTEMPT_V1 4
#define EFFECT_GATE_PATH_SUPPLIED_V1 8
#define MAX_CANONICAL_MOUNTS_V1 4096
#define CANONICAL_MOUNT_CACHE_READY_V1 1
#define CANONICAL_MOUNT_CACHE_MISS_V1 1

struct canonical_mount_cache_key_v1 {
    __u64 mount_namespace_address;
    __u64 namespace_root_mount_id_unique;
    __u64 namespace_event;
    __u64 root_dentry_address;
};

struct canonical_mount_cache_value_v1 {
    struct bpf_spin_lock lock;
    __u32 reserved;
    __u64 selected_mount_address;
    __u64 selected_mount_id_unique;
};

struct canonical_mount_cache_state_key_v1 {
    __u64 mount_namespace_address;
    __u64 namespace_root_mount_id_unique;
    __u64 namespace_event;
};

struct canonical_mount_cache_state_v1 {
    __u32 mount_count;
    __u32 state;
};

struct exact_mount_event_key_v1 {
    __u64 mount_namespace_address;
    __u64 namespace_root_mount_id_unique;
    __u32 mount_namespace_inode;
    __u32 reserved;
};

struct exact_mount_event_v1 {
    struct bpf_spin_lock lock;
    __u32 reserved;
    __u64 transition_version;
    __u64 namespace_event;
    __u64 ambiguous_mount_epoch;
};

struct canonical_mount_cache_build_state_v1 {
    __u64 mount_namespace_address;
    __u64 namespace_root_mount_id_unique;
    __u64 namespace_event;
    __u64 candidate_mount_address;
    __u64 candidate_namespace_address;
    __u64 candidate_root_address;
    __u64 candidate_mount_id_unique;
    __u64 left_node_address;
    __u64 right_node_address;
    __u32 expected_mounts;
    __u32 stack_depth;
    __u32 failed;
    __u32 reserved;
};

struct canonical_mount_path_walk_state_v1 {
    __u64 mount_namespace_address;
    __u64 namespace_root_address;
    __u64 current_mount_address;
    __u64 current_dentry_address;
    __u64 next_mount_address;
    __u64 next_dentry_address;
    __u64 component_name_address;
    __u64 selected_mount_address;
    __u64 selected_mount_id_unique;
    __u64 selected_mount_namespace_address;
    __u64 selected_mount_root_address;
    __u64 live_selected_mount_id_unique;
    __u64 namespace_event;
    __u64 namespace_root_mount_id_unique;
    __u64 first_selected_mount_id_unique;
    __u32 component_count;
    __u32 component_length;
    __u32 reached_namespace_root;
    __u32 failed;
};

struct canonical_path_view_v1 {
    __u64 name_address;
    __u32 length;
    __u32 reserved;
};

struct canonical_path_match_state_v1 {
    __u64 profile_generation_ref_id;
    __u32 component_count;
    __u32 state_id;
    __u32 unresolved;
    __u32 reserved;
};

struct identity_scratch_v1 {
    task_label_v1 label;
    task_coordinate_v1 coordinate;
    kernel_real_parent_interval_v1 real_parent;
    created_by_edge_v1 created_by;
    process_security_state_v1 process;
    process_state_vector_v1 process_vector;
    entry_security_state_v1 entry;
    authority_domain_state_v1 domain;
    task_reference_tombstone_v1 tombstone;
    external_root_classification_v1 classification;
    pending_exec_v1 pending_exec;
    image_provenance_v1 image;
    process_execution_instance_v1 execution;
    pending_administrative_match_v1 administrative_match;
    approved_exec_slot_key_v1 administrative_slot_key;
    effect_decision_key_v1 effect_key;
    effect_default_key_v1 effect_default;
    ipc_relationship_decision_key_v1 ipc_relationship_key;
    ipc_socket_state_v1 ipc_socket_state;
    network_ipv4_lpm_key_v1 network_ipv4_key;
    network_ipv6_lpm_key_v1 network_ipv6_key;
    network_destination_decision_key_v1 network_destination_key;
    network_response_floor_key_v1 network_response_key;
    network_socket_state_v1 network_socket_state;
    device_effect_key_v1 device_effect_key;
    process_control_rule_key_v1 process_control_rule_key;
    exception_use_receipt_key_v1 exception_receipt_key;
    exception_use_receipt_v1 exception_receipt_draft;
    io_uring_actor_snapshot_v1 io_uring_actor;
    io_uring_ring_state_v1 io_uring_ring_draft;
    io_uring_request_state_v1 io_uring_request_draft;
    __u8 effect_gate_flags;
    __u8 effect_gate_reserved[3];
    __u32 effect_gate_operation_argument;
    __u32 path_mount_namespace_inode;
    struct path effect_path;
    exact_file_object_key_v1 file_object;
    task_label_v1 target_label;
    task_coordinate_v1 target_coordinate;
    process_security_state_v1 target_process;
    process_state_vector_v1 target_process_vector;
    path_graph_transition_key_v1 path_transition_key;
    path_graph_state_key_v1 path_state_key;
    path_graph_terminal_v1 path_terminal;
    __u64 mount_topology_generation;
    __u64 mount_transition_version;
    struct canonical_mount_cache_key_v1 mount_cache_key;
    struct canonical_mount_cache_value_v1 mount_cache_value;
    struct canonical_mount_cache_state_key_v1 mount_cache_state_key;
    struct canonical_mount_cache_state_v1 mount_cache_state;
    struct exact_mount_event_key_v1 exact_mount_event_key;
    struct exact_mount_event_v1 exact_mount_event;
    struct canonical_mount_cache_build_state_v1 mount_cache_build;
    __u64 mount_scan_stack[MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1 + 1];
    struct canonical_mount_path_walk_state_v1 mount_path_walk;
    struct canonical_path_match_state_v1 path_match;
    struct canonical_path_view_v1
        path_component_views[MAX_CANONICAL_PATH_COMPONENTS_V1 + 1];
    effect_observation_v1 observation;
    __u8 administrative_argument[MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 + 1];
    approved_exec_argument_key_v1 administrative_argument_key;
    __u8 zero_bytes[MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, identity_runtime_config_v1);
} identity_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, identity_health_v1);
} identity_health SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct identity_scratch_v1);
} identity_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, policy_activation_probe_v1);
} policy_activation_probe_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, task_label_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} task_labels SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, task_coordinate_v1);
} task_coordinates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, kernel_real_parent_interval_key_v1);
    __type(value, kernel_real_parent_interval_v1);
} kernel_real_parent_intervals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, created_by_edge_v1);
} created_by_edges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, id128_v1);
    __type(value, process_security_state_v1);
} process_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, id128_v1);
    __type(value, process_state_vector_v1);
} process_state_vectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} profile_generation_task_refs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, id128_v1);
    __type(value, entry_security_state_v1);
} entry_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, id128_v1);
    __type(value, authority_domain_state_v1);
} authority_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, execution_set_binding_state_v1);
} execution_set_bindings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, external_root_classification_v1);
} external_root_classifications SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, pending_exec_v1);
} pending_execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, id128_v1);
    __type(value, image_provenance_v1);
} image_provenance SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, id128_v1);
    __type(value, process_execution_instance_v1);
} process_execution_instances SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, approved_exec_slot_key_v1);
    __type(value, approved_exec_slot_v1);
} approved_exec_slots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, approved_exec_argument_key_v1);
    __type(value, __u8);
} approved_exec_arguments SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, pending_administrative_match_v1);
} pending_administrative_matches SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, task_reference_tombstone_v1);
} task_reference_tombstones SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, profile_generation_descriptor_v1);
} profile_generation_descriptors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, id128_v1);
    __type(value, __u64);
} active_profile_generations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, binding_activation_target_key_v1);
    __type(value, execution_set_binding_state_v1);
} binding_activation_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, effect_decision_key_v1);
    __type(value, physical_decision_v1);
} effect_decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, effect_default_key_v1);
    __type(value, physical_decision_v1);
} effect_defaults SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, ipc_relationship_decision_key_v1);
    __type(value, physical_decision_v1);
} ipc_relationship_decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(key, int);
    __type(value, ipc_socket_state_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipc_socket_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, network_ipv4_lpm_key_v1);
    __type(value, network_destination_class_v1);
} network_ipv4_destination_classes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, network_ipv6_lpm_key_v1);
    __type(value, network_destination_class_v1);
} network_ipv6_destination_classes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, network_destination_decision_key_v1);
    __type(value, physical_decision_v1);
} network_destination_decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(key, int);
    __type(value, network_socket_state_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
} network_socket_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, network_response_floor_key_v1);
    __type(value, network_response_floor_v1);
} network_response_floors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, device_effect_key_v1);
    __type(value, physical_decision_v1);
} device_effect_decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, process_control_rule_key_v1);
    __type(value, physical_decision_v1);
} process_control_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, exception_handle_binding_key_v1);
    __type(value, exception_handle_binding_v1);
} exception_handle_bindings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, exception_runtime_state_key_v1);
    __type(value, struct exception_runtime_state_bpf_v1);
} exception_runtime_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, EXCEPTION_USE_RECEIPT_CAPACITY_V1);
    __type(key, exception_use_receipt_key_v1);
    __type(value, exception_use_receipt_v1);
} exception_use_receipts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, task_effect_attempt_state_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} task_effect_attempt_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, io_uring_setup_state_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} io_uring_setup_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);
    __type(value, io_uring_ring_state_v1);
} io_uring_ring_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);
    __type(value, io_uring_request_state_v1);
} io_uring_request_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, io_uring_execution_state_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} io_uring_execution_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} profile_generation_async_refs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} profile_generation_socket_refs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, exact_file_object_key_v1);
    __type(value, exact_object_binding_v1);
} exact_file_objects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, mount_security_view_state_v1);
} mount_security_views SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mount_global_mutation_epoch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mount_global_clean_epoch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mount_global_pending_mutations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mount_global_ambiguous_epoch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct mount_security_view_lock_v1);
} mount_security_view_locks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, mount_reconciliation_proposal_v1);
} mount_reconciliation_proposals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} mount_mutation_epochs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, canonical_mount_root_key_v1);
    __type(value, canonical_mount_root_v1);
} canonical_mount_roots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct canonical_mount_cache_key_v1);
    __type(value, struct canonical_mount_cache_value_v1);
} canonical_mount_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct canonical_mount_cache_state_key_v1);
    __type(value, struct canonical_mount_cache_state_v1);
} canonical_mount_cache_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct exact_mount_event_key_v1);
    __type(value, struct exact_mount_event_v1);
} exact_mount_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, path_graph_transition_key_v1);
    __type(value, path_graph_transition_v1);
} path_graph_exact_transitions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, path_graph_state_key_v1);
    __type(value, path_graph_transition_v1);
} path_graph_wildcard_transitions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, path_graph_state_key_v1);
    __type(value, path_graph_terminal_v1);
} path_graph_terminals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, mount_mutation_attempt_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mount_mutation_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} effect_observations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, effect_observation_health_v1);
} effect_observation_health SEC(".maps");

static __always_inline identity_runtime_config_v1 *identity_runtime_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&identity_config, &zero);
}

static __always_inline identity_health_v1 *identity_health_record(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&identity_health, &zero);
}

static __always_inline struct identity_scratch_v1 *identity_scratch_record(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&identity_scratch, &zero);
}

static __always_inline bool id128_equal(const id128_v1 *left,
                                         const id128_v1 *right)
{
    return left->high == right->high && left->low == right->low;
}

static __always_inline bool id128_is_zero(const id128_v1 *id)
{
    return id->high == 0 && id->low == 0;
}

static __always_inline int allocate_id(identity_runtime_config_v1 *config,
                                       id128_v1 *target)
{
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 value = config->next_id;

        if (value == 0 || value == ~0ULL)
            return -EACCES;
        if (__sync_val_compare_and_swap(&config->next_id, value, value + 1) ==
            value) {
            target->high = config->label_epoch;
            target->low = value;
            return 0;
        }
    }
    return -EACCES;
}

/* Return the value before decrement, or zero without changing the counter. */
static __always_inline __u64 decrement_nonzero_counter(__u64 *counter)
{
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 value = __sync_fetch_and_add(counter, 0);

        if (!value)
            break;
        if (__sync_val_compare_and_swap(counter, value, value - 1) == value)
            return value;
    }
    {
        identity_health_v1 *health = identity_health_record();

        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

static __always_inline bool increment_bounded_counter(__u64 *counter)
{
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 value = __sync_fetch_and_add(counter, 0);

        if (value == ~0ULL)
            break;
        if (__sync_val_compare_and_swap(counter, value, value + 1) == value)
            return true;
    }
    {
        identity_health_v1 *health = identity_health_record();

        if (health)
            health->reconciliation_required++;
    }
    return false;
}

static __always_inline bool increment_counter_below(__u64 *counter,
                                                     __u64 maximum)
{
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 value = __sync_fetch_and_add(counter, 0);

        if (!maximum || value >= maximum)
            break;
        if (__sync_val_compare_and_swap(counter, value, value + 1) == value)
            return true;
    }
    {
        identity_health_v1 *health = identity_health_record();

        if (health)
            health->reconciliation_required++;
    }
    return false;
}

static __always_inline int task_cgroup(struct task_struct *task,
                                       struct cgroup **result)
{
    struct css_set *cgroups = NULL;

    *result = NULL;
    if (!task)
        return -EACCES;
    if (BPF_CORE_READ_INTO(&cgroups, task, cgroups) || !cgroups)
        return -EACCES;
    if (BPF_CORE_READ_INTO(result, cgroups, dfl_cgrp) || !*result)
        return -EACCES;
    return 0;
}

static __always_inline __u64 cgroup_id(struct cgroup *cgroup)
{
    struct kernfs_node *kn = NULL;
    __u64 id = 0;

    if (!cgroup || BPF_CORE_READ_INTO(&kn, cgroup, kn) || !kn)
        return 0;
    if (bpf_core_field_exists(((struct kernfs_node___old *)0)->id.id)) {
        struct kernfs_node___old *old_kn = (void *)kn;
        if (BPF_CORE_READ_INTO(&id, old_kn, id.id))
            return 0;
    } else if (BPF_CORE_READ_INTO(&id, kn, id)) {
        return 0;
    }
    return id;
}

static __always_inline int cgroup_parent(struct cgroup *cgroup,
                                         struct cgroup **result)
{
    struct cgroup___new *new_cgroup = (void *)cgroup;
    struct cgroup_subsys_state *parent_css = NULL;
    int level = 0;

    *result = NULL;
    if (!cgroup)
        return -EACCES;
    if (bpf_core_field_exists(new_cgroup->ancestors)) {
        if (BPF_CORE_READ_INTO(&level, new_cgroup, level) || level < 0 ||
            level > MAX_CGROUP_ANCESTOR_STEPS_V1)
            return -EACCES;
        if (level == 0)
            return 0;
        if (BPF_CORE_READ_INTO(result, new_cgroup, ancestors[level - 1]) ||
            !*result)
            return -EACCES;
        return 0;
    }
    if (BPF_CORE_READ_INTO(&parent_css, cgroup, self.parent))
        return -EACCES;
    if (!parent_css)
        return 0;
    *result = EREBOR_CORE_CONTAINER_OF(parent_css, struct cgroup, self);
    return 0;
}

static __always_inline execution_set_binding_state_v1 *binding_for_cgroup(
    struct cgroup *cgroup, int *lookup_result)
{
    execution_set_binding_state_v1 *binding;
    struct cgroup *parent;
    __u64 id;

    *lookup_result = -EACCES;
#pragma clang loop unroll(disable)
    for (int depth = 0; depth < MAX_CGROUP_ANCESTOR_STEPS_V1; depth++) {
        id = cgroup_id(cgroup);
        if (!id)
            return NULL;
        binding = bpf_map_lookup_elem(&execution_set_bindings, &id);
        if (binding) {
            *lookup_result = 0;
            return binding;
        }
        if (cgroup_parent(cgroup, &parent))
            return NULL;
        if (!parent) {
            *lookup_result = 0;
            return NULL;
        }
        cgroup = parent;
    }
    return NULL;
}

static __always_inline int identity_errno(__s64 error)
{
    /* Bound the LSM result for the verifier and preserve the configured s32. */
    asm volatile("%0 <<= 32\n"
                 "%0 s>>= 32\n"
                 "if %0 s< %1 goto +1\n"
                 "if %0 s< 0 goto +1\n"
                 "%0 = %2\n"
                 : "+r"(error)
                 : "i"(-MAX_ERRNO), "i"(-EACCES));
    return error;
}

static __always_inline int identity_deny(identity_runtime_config_v1 *config)
{
    return identity_errno(config ? config->first_effect_errno : -EACCES);
}

static __always_inline void close_task_effect_attempt_frames(
    task_effect_attempt_state_v1 *attempt,
    task_effect_attempt_state_kind_v1 terminal_state)
{
#pragma unroll
    for (int index = 0; index < MAX_NESTED_EFFECT_ATTEMPTS_V1; index++) {
        task_effect_attempt_frame_v1 *frame = &attempt->frames[index];

        if (index < attempt->depth &&
            (frame->state == task_effect_attempt_frame_state_v1_preparing ||
             frame->state == task_effect_attempt_frame_state_v1_decided))
            frame->state = task_effect_attempt_frame_state_v1_cancelled;
    }
    attempt->depth = 0;
    attempt->state = terminal_state;
}

static __always_inline void begin_task_effect_syscall(struct task_struct *task)
{
    task_effect_attempt_state_v1 *attempt = bpf_task_storage_get(
        &task_effect_attempt_states, task, 0,
        BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (!attempt ||
        attempt->state ==
            task_effect_attempt_state_kind_v1_overflow_fail_closed ||
        attempt->state == task_effect_attempt_state_kind_v1_task_exited)
        return;
    if (attempt->state == task_effect_attempt_state_kind_v1_active) {
        close_task_effect_attempt_frames(
            attempt,
            task_effect_attempt_state_kind_v1_overflow_fail_closed);
        return;
    }
    if (attempt->syscall_entry_sequence == ~0ULL) {
        attempt->state =
            task_effect_attempt_state_kind_v1_overflow_fail_closed;
        return;
    }
    attempt->syscall_entry_sequence++;
    attempt->next_effect_attempt_sequence = 1;
    attempt->task_cookie = 0;
    attempt->depth = 0;
    __builtin_memset(attempt->frames, 0, sizeof(attempt->frames));
    attempt->state = task_effect_attempt_state_kind_v1_active;
}

static __always_inline void finish_task_effect_syscall(struct task_struct *task)
{
    task_effect_attempt_state_v1 *attempt = bpf_task_storage_get(
        &task_effect_attempt_states, task, 0, 0);

    if (attempt &&
        attempt->state == task_effect_attempt_state_kind_v1_active)
        close_task_effect_attempt_frames(
            attempt,
            attempt->depth
                ? task_effect_attempt_state_kind_v1_overflow_fail_closed
                : task_effect_attempt_state_kind_v1_inactive);
}

static __always_inline void exit_task_effect_attempts(struct task_struct *task)
{
    task_effect_attempt_state_v1 *attempt = bpf_task_storage_get(
        &task_effect_attempt_states, task, 0, 0);

    if (attempt)
        close_task_effect_attempt_frames(
            attempt, task_effect_attempt_state_kind_v1_task_exited);
}

static __always_inline int begin_file_open_effect_attempt(
    __u64 task_cookie, __u16 effect_family, __u16 operation,
    __u64 *effect_attempt_sequence)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_effect_attempt_state_v1 *attempt = bpf_task_storage_get(
        &task_effect_attempt_states, task, 0, 0);
    task_effect_attempt_frame_v1 *frame;
    __u16 depth;

    if (!attempt || !task_cookie || !effect_attempt_sequence ||
        attempt->state != task_effect_attempt_state_kind_v1_active ||
        !attempt->syscall_entry_sequence ||
        effect_family != kernel_effect_family_v1_file ||
        (operation != kernel_effect_operation_v1_open_read &&
         operation != kernel_effect_operation_v1_open_write))
        return -EACCES;
    if ((attempt->task_cookie && attempt->task_cookie != task_cookie) ||
        !attempt->next_effect_attempt_sequence ||
        attempt->next_effect_attempt_sequence == ~0ULL ||
        attempt->depth >= MAX_NESTED_EFFECT_ATTEMPTS_V1) {
        close_task_effect_attempt_frames(
            attempt,
            task_effect_attempt_state_kind_v1_overflow_fail_closed);
        return -EACCES;
    }
    attempt->task_cookie = task_cookie;
    depth = attempt->depth;
    frame = &attempt->frames[depth];
    __builtin_memset(frame, 0, sizeof(*frame));
    frame->effect_attempt_sequence = attempt->next_effect_attempt_sequence++;
    frame->effect_family = effect_family;
    frame->operation = operation;
    frame->hook_discriminator = effect_attempt_hook_v1_file_open;
    frame->repeated_lsm_pass_count = 1;
    frame->state = task_effect_attempt_frame_state_v1_preparing;
    attempt->depth = depth + 1;
    frame->state = task_effect_attempt_frame_state_v1_decided;
    *effect_attempt_sequence = frame->effect_attempt_sequence;
    return 0;
}

static __always_inline int finish_file_open_effect_attempt(
    __u64 effect_attempt_sequence)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_effect_attempt_state_v1 *attempt = bpf_task_storage_get(
        &task_effect_attempt_states, task, 0, 0);
    task_effect_attempt_frame_v1 *frame;
    __u16 depth;

    if (!attempt ||
        attempt->state != task_effect_attempt_state_kind_v1_active ||
        !attempt->depth || attempt->depth > MAX_NESTED_EFFECT_ATTEMPTS_V1)
        return -EACCES;
    depth = attempt->depth - 1;
    frame = &attempt->frames[depth];
    if (!effect_attempt_sequence ||
        frame->effect_attempt_sequence != effect_attempt_sequence ||
        frame->hook_discriminator != effect_attempt_hook_v1_file_open ||
        frame->state != task_effect_attempt_frame_state_v1_decided) {
        close_task_effect_attempt_frames(
            attempt,
            task_effect_attempt_state_kind_v1_overflow_fail_closed);
        return -EACCES;
    }
    frame->state = task_effect_attempt_frame_state_v1_returned;
    attempt->depth = depth;
    return 0;
}

static __always_inline int consume_bounded_exception(
    __u64 profile_generation_ref_id, __u32 exception_numeric_handle,
    const id128_v1 *claim_slot_id, __u64 effect_attempt_sequence,
    __u16 effect_family, __u16 operation)
{
    exception_handle_binding_key_v1 binding_key = {
        .profile_generation_ref_id = profile_generation_ref_id,
        .exception_numeric_handle = exception_numeric_handle,
    };
    exception_handle_binding_v1 *binding;
    struct identity_scratch_v1 *scratch;
    exception_use_receipt_key_v1 *receipt_key;
    exception_use_receipt_v1 *claiming;
    exception_use_receipt_v1 *receipt;
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    task_effect_attempt_state_v1 *attempt;
    task_effect_attempt_frame_v1 *frame;
    struct exception_runtime_state_bpf_v1 *exception;
    __u64 now;
    bool keep_receipt = false;
    int result = -EACCES;

    if (!exception_numeric_handle)
        return 0;
    scratch = identity_scratch_record();
    if (!scratch)
        return -EACCES;
    receipt_key = &scratch->exception_receipt_key;
    claiming = &scratch->exception_receipt_draft;
    __builtin_memset(receipt_key, 0, sizeof(*receipt_key));
    __builtin_memset(claiming, 0, sizeof(*claiming));
    binding = bpf_map_lookup_elem(&exception_handle_bindings, &binding_key);
    if (!binding || binding->state != exception_binding_state_v1_active)
        return -EACCES;
    exception = bpf_map_lookup_elem(&exception_runtime_states,
                                    &binding->runtime_state_key);
    if (!exception)
        return -EACCES;
    receipt_key->runtime_state_key = binding->runtime_state_key;
    if (claim_slot_id && (claim_slot_id->high || claim_slot_id->low)) {
        receipt_key->use_identity.kind =
            exception_use_identity_kind_v1_claim_slot;
        receipt_key->use_identity.claim_slot_id = *claim_slot_id;
    } else {
        task = bpf_get_current_task_btf();
        label = bpf_task_storage_get(&task_labels, task, 0, 0);
        if (!label)
            return -EACCES;
        process = bpf_map_lookup_elem(&process_states,
                                      &label->process_state_id);
        if (!process)
            return -EACCES;
        attempt = bpf_task_storage_get(&task_effect_attempt_states, task, 0,
                                       0);
        if (!attempt ||
            attempt->state != task_effect_attempt_state_kind_v1_active ||
            attempt->task_cookie != label->task_cookie ||
            !attempt->syscall_entry_sequence || !effect_attempt_sequence ||
            !attempt->depth ||
            attempt->depth > MAX_NESTED_EFFECT_ATTEMPTS_V1)
            return -EACCES;
        frame = &attempt->frames[attempt->depth - 1];
        if (frame->effect_attempt_sequence != effect_attempt_sequence ||
            frame->effect_family != effect_family ||
            frame->operation != operation ||
            frame->hook_discriminator != effect_attempt_hook_v1_file_open ||
            frame->repeated_lsm_pass_count != 1 ||
            frame->state != task_effect_attempt_frame_state_v1_decided)
            return -EACCES;
        receipt_key->use_identity.kind =
            exception_use_identity_kind_v1_kernel_effect_attempt;
        receipt_key->use_identity.task_cookie = label->task_cookie;
        receipt_key->use_identity.process_state_id = process->process_state_id;
        receipt_key->use_identity.syscall_entry_sequence =
            attempt->syscall_entry_sequence;
        receipt_key->use_identity.effect_attempt_sequence =
            frame->effect_attempt_sequence;
        receipt_key->use_identity.effect_family = effect_family;
        receipt_key->use_identity.operation = operation;
    }
    receipt = bpf_map_lookup_elem(&exception_use_receipts, receipt_key);
    if (receipt)
        return receipt->state == exception_receipt_state_v1_consumed
                   ? 0
                   : -EACCES;
    if (!exception->maximum_uses ||
        !exception->bound_profile_generation_refs ||
        exception->consumed_uses >= exception->maximum_uses ||
        exception->state != exception_runtime_state_kind_v1_active)
        return -EACCES;
    now = bpf_ktime_get_ns();
    claiming->claimed_boottime_ns = now;
    claiming->transition_version = 1;
    claiming->state = exception_receipt_state_v1_claiming;
    if (bpf_map_update_elem(&exception_use_receipts, receipt_key, claiming,
                            BPF_NOEXIST)) {
        receipt = bpf_map_lookup_elem(&exception_use_receipts, receipt_key);
        return receipt && receipt->state == exception_receipt_state_v1_consumed
                   ? 0
                   : -EACCES;
    }
    receipt = bpf_map_lookup_elem(&exception_use_receipts, receipt_key);
    if (!receipt) {
        bpf_map_delete_elem(&exception_use_receipts, receipt_key);
        return -EACCES;
    }
    bpf_spin_lock(&exception->lock);
    if (binding->state != exception_binding_state_v1_active ||
        !id128_equal(&binding->runtime_state_key.node_id,
                     &receipt_key->runtime_state_key.node_id) ||
        !id128_equal(&binding->runtime_state_key.exception_instance_id,
                     &receipt_key->runtime_state_key.exception_instance_id)) {
        exception->state =
            exception_runtime_state_kind_v1_reconciliation_required;
        exception->transition_version++;
        receipt->state =
            exception_receipt_state_v1_reconciliation_required;
        receipt->transition_version++;
        goto unlock;
    }
    if (exception->state == exception_runtime_state_kind_v1_expired ||
        now >= exception->deadline_boottime_ns) {
        if (exception->state == exception_runtime_state_kind_v1_active) {
            exception->state = exception_runtime_state_kind_v1_expired;
            exception->transition_version++;
        }
        receipt->state = exception_receipt_state_v1_denied_expired;
        receipt->transition_version++;
        goto unlock;
    }
    if (!exception->maximum_uses || !exception->bound_profile_generation_refs ||
        exception->consumed_uses > exception->maximum_uses ||
        (exception->state != exception_runtime_state_kind_v1_active &&
         exception->state != exception_runtime_state_kind_v1_exhausted)) {
        exception->state =
            exception_runtime_state_kind_v1_reconciliation_required;
        exception->transition_version++;
        receipt->state = exception_receipt_state_v1_denied_corrupt;
        receipt->transition_version++;
        goto unlock;
    }
    if (exception->state == exception_runtime_state_kind_v1_exhausted ||
        exception->consumed_uses == exception->maximum_uses) {
        if (exception->state == exception_runtime_state_kind_v1_active) {
            exception->state = exception_runtime_state_kind_v1_exhausted;
            exception->transition_version++;
        }
        receipt->state = exception_receipt_state_v1_denied_exhausted;
        receipt->transition_version++;
        goto unlock;
    }
    exception->consumed_uses++;
    exception->transition_version++;
    if (exception->consumed_uses == exception->maximum_uses)
        exception->state = exception_runtime_state_kind_v1_exhausted;
    receipt->consumed_ordinal = exception->consumed_uses;
    receipt->state = exception_receipt_state_v1_consumed;
    receipt->transition_version++;
    keep_receipt = true;
    result = 0;
unlock:
    bpf_spin_unlock(&exception->lock);
    if (!keep_receipt)
        bpf_map_delete_elem(&exception_use_receipts, receipt_key);
    return result;
}

static __always_inline bool label_matches_runtime(const task_label_v1 *label,
                                                   const identity_runtime_config_v1 *config)
{
    return label && config && label->label_epoch == config->label_epoch &&
           id128_equal(&label->node_boot_id, &config->node_boot_id);
}

static __always_inline bool task_label_is_uninitialized(
    const task_label_v1 *label)
{
    if (!label || label->label_epoch || label->task_cookie ||
        label->birth_profile_generation_ref_id || label->lineage_depth ||
        !id128_is_zero(&label->node_boot_id) ||
        !id128_is_zero(&label->process_lineage_id) ||
        !id128_is_zero(&label->process_instance_id) ||
        !id128_is_zero(&label->process_state_id) ||
        !id128_is_zero(&label->entry_instance_id) ||
        !id128_is_zero(&label->execution_set_id) ||
        !id128_is_zero(&label->birth_execution_id) ||
        !id128_is_zero(&label->birth_authority_domain_id) ||
        !id128_is_zero(&label->placement.protected_root_binding_id) ||
        !id128_is_zero(&label->placement.protected_root_binding_nonce) ||
        label->placement.allowed_descendant_policy_id ||
        label->placement.reserved)
        return false;
#pragma unroll
    for (int index = 0; index < 6; index++) {
        if (label->reserved[index])
            return false;
    }
#pragma unroll
    for (int index = 0; index < MAX_ANCESTOR_PROCESS_LINEAGES_V1; index++) {
        if (!id128_is_zero(&label->ancestor_process_lineage_ids[index]))
            return false;
    }
    return true;
}

static __always_inline bool binding_matches_label(
    const execution_set_binding_state_v1 *binding, const task_label_v1 *label)
{
    return binding && label &&
           id128_equal(&binding->binding_id,
                       &label->placement.protected_root_binding_id) &&
           id128_equal(&binding->binding_nonce,
                       &label->placement.protected_root_binding_nonce) &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active;
}

static __always_inline bool generation_allows_existing_holder(
    const profile_generation_descriptor_v1 *generation)
{
    return generation &&
           (generation->state == policy_generation_state_v1_active ||
            generation->state == policy_generation_state_v1_retiring);
}

static __always_inline execution_set_binding_state_v1 *
binding_activation_for_new_root(
    const execution_set_binding_state_v1 *binding,
    const identity_runtime_config_v1 *config)
{
    __u64 *active_generation;
    __u64 generation_id;
    binding_activation_target_key_v1 key;
    execution_set_binding_state_v1 *target;
    profile_generation_descriptor_v1 *descriptor;

    if (!binding || !config)
        return NULL;
    if (!config->effect_policy_enabled)
        return (execution_set_binding_state_v1 *)binding;
    active_generation = bpf_map_lookup_elem(&active_profile_generations,
                                            &binding->profile_id);
    if (!active_generation)
        return NULL;
    generation_id = *active_generation;
    key.binding_id = binding->binding_id;
    key.profile_generation_ref_id = generation_id;
    target = bpf_map_lookup_elem(&binding_activation_targets, &key);
    if (!target ||
        !id128_equal(&target->binding_id, &binding->binding_id) ||
        !id128_equal(&target->binding_nonce, &binding->binding_nonce) ||
        !id128_equal(&target->node_boot_id, &binding->node_boot_id) ||
        !id128_equal(&target->execution_set_id, &binding->execution_set_id) ||
        !id128_equal(&target->protected_scope_id,
                     &binding->protected_scope_id) ||
        !id128_equal(&target->profile_id, &binding->profile_id) ||
        target->label_epoch != binding->label_epoch ||
        target->root_cgroup_id != binding->root_cgroup_id ||
        !id128_equal(&target->root_cgroup_live_interval_id,
                     &binding->root_cgroup_live_interval_id) ||
        target->container_generation != binding->container_generation ||
        target->lifecycle_generation != binding->lifecycle_generation ||
        target->lifecycle_state != binding_lifecycle_state_v1_active ||
        !target->initial_role_id || !target->external_role_id ||
        binding->lifecycle_state != binding_lifecycle_state_v1_active)
        return NULL;
    if (generation_id != target->active_profile_generation_ref_id)
        return NULL;
    descriptor = bpf_map_lookup_elem(&profile_generation_descriptors,
                                     &generation_id);
    if (!descriptor ||
        descriptor->state != policy_generation_state_v1_active ||
        descriptor->profile_generation_ref_id != generation_id ||
        descriptor->label_epoch != config->label_epoch ||
        !id128_equal(&descriptor->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&descriptor->profile_id, &binding->profile_id))
        return NULL;
    return target;
}

static __always_inline bool consume_initial_root(
    execution_set_binding_state_v1 *binding)
{
    __u64 previous = __sync_val_compare_and_swap(
        &binding->initial_root_state, initial_root_state_v1_available,
        initial_root_state_v1_consumed);

    if (previous != initial_root_state_v1_available)
        return false;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return true;
}

static __always_inline int snapshot_process_state(
    const process_security_state_v1 *source,
    process_security_state_v1 *snapshot)
{
    __u64 version;

    if (!source || !snapshot ||
        __sync_fetch_and_add((__u64 *)&source->transition_guard, 0))
        return -EACCES;
    version = __sync_fetch_and_add((__u64 *)&source->transition_version, 0);
    __asm__ volatile("" ::: "memory");
    *snapshot = *source;
    __asm__ volatile("" ::: "memory");
    if (__sync_fetch_and_add((__u64 *)&source->transition_guard, 0) ||
        version !=
            __sync_fetch_and_add((__u64 *)&source->transition_version, 0))
        return -EACCES;
    return 0;
}

static __always_inline void release_transition_guard(__u64 *guard)
{
    __sync_val_compare_and_swap(guard, 1, 0);
}

static __always_inline void zero_id(id128_v1 *id)
{
    id->high = 0;
    id->low = 0;
}

static __always_inline void copy_ancestors(task_label_v1 *target,
                                           const task_label_v1 *parent,
                                           bool new_process)
{
#pragma unroll
    for (int index = 0; index < MAX_ANCESTOR_PROCESS_LINEAGES_V1; index++)
        target->ancestor_process_lineage_ids[index] =
            parent->ancestor_process_lineage_ids[index];
    target->lineage_depth = parent->lineage_depth;
    if (new_process && target->lineage_depth < MAX_ANCESTOR_PROCESS_LINEAGES_V1) {
        target->ancestor_process_lineage_ids[target->lineage_depth] =
            parent->process_lineage_id;
        target->lineage_depth++;
    }
}

static __always_inline void prepare_coordinate(
    task_coordinate_v1 *coordinate, __u64 task_cookie,
    const id128_v1 *process_instance_id, const id128_v1 *process_state_id)
{
    coordinate->task_cookie = task_cookie;
    coordinate->process_instance_id = *process_instance_id;
    coordinate->process_state_id = *process_state_id;
    coordinate->host_tid = 0;
    coordinate->host_tgid = 0;
    coordinate->pid_namespace_inode = 0;
    coordinate->task_start_boottime_ns = 0;
    coordinate->finalized_boottime_ns = 0;
    coordinate->real_parent_interval_sequence = 1;
    coordinate->transition_version = 1;
    coordinate->state = task_coordinate_state_v1_allocating;
#pragma unroll
    for (int index = 0; index < 3; index++)
        coordinate->reserved[index] = 0;
}

static __always_inline void prepare_tombstone(
    task_reference_tombstone_v1 *tombstone, const task_label_v1 *label)
{
    tombstone->task_cookie = label->task_cookie;
    tombstone->birth_transaction_id.high = label->label_epoch;
    tombstone->birth_transaction_id.low = label->task_cookie;
    tombstone->birth_transition_version = 1;
    tombstone->entry_instance_id = label->entry_instance_id;
    tombstone->process_state_id = label->process_state_id;
    tombstone->authority_domain_id_at_birth = label->birth_authority_domain_id;
    tombstone->profile_generation_ref_id =
        label->birth_profile_generation_ref_id;
    tombstone->acquired_bits = TASK_REFERENCE_ALL_V1;
    tombstone->released_bits = 0;
    tombstone->transition_version = 1;
    tombstone->task_free_observed = 0;
    tombstone->wal_acknowledged = 0;
    tombstone->state = reference_tombstone_state_v1_owned;
#pragma unroll
    for (int index = 0; index < 5; index++)
        tombstone->reserved[index] = 0;
}

#endif
