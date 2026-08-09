// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright Erebor Labs and Authors of Cilium */
#ifndef EREBOR_IDENTITY_MAPS_H
#define EREBOR_IDENTITY_MAPS_H

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

struct identity_scratch_v1 {
    task_label_v1 label;
    task_coordinate_v1 coordinate;
    created_by_edge_v1 created_by;
    process_security_state_v1 process;
    entry_security_state_v1 entry;
    authority_domain_state_v1 domain;
    task_reference_tombstone_v1 tombstone;
    external_root_classification_v1 classification;
    pending_exec_v1 pending_exec;
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
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_binding_roots SEC(".maps");

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
    __type(key, __u64);
    __type(value, task_reference_tombstone_v1);
} task_reference_tombstones SEC(".maps");

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

static __always_inline __u64 task_cgroup_id(struct task_struct *task)
{
    struct css_set *cgroups = NULL;
    struct cgroup *cgroup = NULL;
    struct kernfs_node *kn = NULL;
    __u64 id = 0;

    if (!task)
        return 0;
    if (BPF_CORE_READ_INTO(&cgroups, task, cgroups) || !cgroups)
        return 0;
    if (BPF_CORE_READ_INTO(&cgroup, cgroups, dfl_cgrp) || !cgroup)
        return 0;
    if (BPF_CORE_READ_INTO(&kn, cgroup, kn) || !kn)
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

static __always_inline __u64 cgroup_parent_id(struct cgroup *cgroup)
{
    struct cgroup___new *new_cgroup = (void *)cgroup;
    struct cgroup_subsys_state *parent_css = NULL;
    struct cgroup *parent = NULL;
    int level = 0;

    if (bpf_core_field_exists(new_cgroup->ancestors)) {
        BPF_CORE_READ_INTO(&level, new_cgroup, level);
        if (level <= 0)
            return 0;
        BPF_CORE_READ_INTO(&parent, new_cgroup, ancestors[level - 1]);
        return cgroup_id(parent);
    }
    BPF_CORE_READ_INTO(&parent_css, cgroup, self.parent);
    if (!parent_css)
        return 0;
    parent = container_of(parent_css, struct cgroup, self);
    return cgroup_id(parent);
}

static __always_inline execution_set_binding_state_v1 *binding_for_cgroup(
    __u64 cgroup_id_value)
{
    execution_set_binding_state_v1 *binding;
    __u64 *root;

    binding = bpf_map_lookup_elem(&execution_set_bindings, &cgroup_id_value);
    if (binding)
        return binding;
    root = bpf_map_lookup_elem(&cgroup_binding_roots, &cgroup_id_value);
    if (!root)
        return NULL;
    return bpf_map_lookup_elem(&execution_set_bindings, root);
}

static __always_inline int identity_deny(identity_runtime_config_v1 *config)
{
    if (config && config->first_effect_errno < 0)
        return config->first_effect_errno;
    return -EACCES;
}

static __always_inline bool label_matches_runtime(const task_label_v1 *label,
                                                   const identity_runtime_config_v1 *config)
{
    return label && config && label->label_epoch == config->label_epoch &&
           id128_equal(&label->node_boot_id, &config->node_boot_id);
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
    coordinate->transition_version = 1;
    coordinate->state = task_coordinate_state_v1_allocating;
#pragma unroll
    for (int index = 0; index < 7; index++)
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
