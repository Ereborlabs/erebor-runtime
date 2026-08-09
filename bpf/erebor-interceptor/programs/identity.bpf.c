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
_Static_assert(sizeof(task_coordinate_v1) == 88, "task coordinate ABI size");
_Static_assert(sizeof(identity_runtime_config_v1) == 40,
               "identity runtime config ABI size");
_Static_assert(__builtin_offsetof(task_label_v1, process_state_id) == 64,
               "task process-state offset");

static __always_inline int publish_task(struct task_struct *task,
                                        struct identity_scratch_v1 *scratch)
{
    task_label_v1 *installed;

    if (bpf_map_update_elem(&task_coordinates, &scratch->label.task_cookie,
                            &scratch->coordinate, BPF_NOEXIST))
        return -EACCES;
    if (bpf_map_update_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie, &scratch->tombstone,
                            BPF_NOEXIST)) {
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        return -EACCES;
    }
    installed = bpf_task_storage_get(&task_labels, task, 0,
                                     BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!installed) {
        bpf_map_delete_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie);
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        return -EACCES;
    }
    *installed = scratch->label;
    return 0;
}

static __always_inline void prepare_child_process(
    process_security_state_v1 *target, const process_security_state_v1 *parent,
    const task_label_v1 *child)
{
    target->process_state_id = child->process_state_id;
    target->node_boot_id = child->node_boot_id;
    target->label_epoch = child->label_epoch;
    target->process_lineage_id = child->process_lineage_id;
    target->process_instance_id = child->process_instance_id;
    target->entry_instance_id = child->entry_instance_id;
    target->entry_root_process_state_id = parent->entry_root_process_state_id;
    target->active_execution_id = child->birth_execution_id;
    target->active_role_id = parent->active_role_id;
    target->process_state_vector_id = parent->process_state_vector_id;
    target->active_profile_generation_ref_id =
        parent->active_profile_generation_ref_id;
    target->authority_domain_id = parent->authority_domain_id;
    target->effective_response_set_ref_id =
        parent->effective_response_set_ref_id;
    zero_id(&target->pending_exec_id);
    zero_id(&target->pending_target_execution_id);
    target->pending_target_role_id = 0;
    target->reserved_pending_role = 0;
    target->transition_guard = 0;
    target->pending_exec_response_set_ref_id = 0;
    target->transition_version = 1;
    target->live_thread_refs = 1;
    target->exec_guard_state = exec_guard_state_v1_none;
    target->state = process_security_state_kind_v1_active;
#pragma unroll
    for (int index = 0; index < 6; index++)
        target->reserved[index] = 0;
}

static __always_inline int create_native_child(
    struct task_struct *task, unsigned long clone_flags,
    identity_runtime_config_v1 *config, const task_label_v1 *parent_label,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch)
{
    bool thread = (clone_flags & CLONE_THREAD) != 0;
    id128_v1 task_identity;
    process_security_state_v1 *parent_process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    __u64 *profile_task_refs;

    parent_process = bpf_map_lookup_elem(&process_states,
                                         &parent_label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states,
                                &parent_label->entry_instance_id);
    if (!parent_process || !entry)
        return identity_deny(config);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &parent_process->authority_domain_id);
    if (!domain ||
        parent_process->state != process_security_state_kind_v1_active ||
        !binding_matches_label(binding, parent_label))
        return identity_deny(config);
    if (!thread && parent_label->lineage_depth >=
                       MAX_ANCESTOR_PROCESS_LINEAGES_V1)
        return identity_deny(config);
    if (__sync_val_compare_and_swap(&parent_process->transition_guard, 0, 1))
        return identity_deny(config);
    if (parent_process->exec_guard_state != exec_guard_state_v1_none ||
        parent_process->state != process_security_state_kind_v1_active)
        goto fail_locked;

    scratch->label = *parent_label;
    scratch->label.birth_profile_generation_ref_id =
        parent_process->active_profile_generation_ref_id;
    scratch->label.birth_authority_domain_id = parent_process->authority_domain_id;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &scratch->label.birth_profile_generation_ref_id);
    if (!profile_task_refs)
        goto fail_locked;
    if (allocate_id(config, &task_identity))
        goto fail_locked;
    scratch->label.task_cookie = task_identity.low;
    if (thread) {
        scratch->label.birth_execution_id = parent_process->active_execution_id;
    } else {
        if (allocate_id(config, &scratch->label.birth_execution_id) ||
            allocate_id(config, &scratch->label.process_lineage_id) ||
            allocate_id(config, &scratch->label.process_instance_id) ||
            allocate_id(config, &scratch->label.process_state_id))
            goto fail_locked;
    }
    copy_ancestors(&scratch->label, parent_label, !thread);
    prepare_coordinate(&scratch->coordinate, scratch->label.task_cookie,
                       &scratch->label.process_instance_id,
                       &scratch->label.process_state_id);
    if (allocate_id(config, &scratch->created_by.clone_attempt_id))
        goto fail_locked;
    scratch->created_by.child_task_cookie = scratch->label.task_cookie;
    scratch->created_by.creator_task_cookie = parent_label->task_cookie;
    scratch->created_by.child_process_lineage_id =
        scratch->label.process_lineage_id;
    scratch->created_by.creator_process_lineage_id =
        parent_label->process_lineage_id;
    scratch->created_by.clone_flags = clone_flags;
    scratch->created_by.task_alloc_hook_id = TASK_ALLOC_HOOK_LSM_V1;
    scratch->created_by.reserved = 0;
    prepare_tombstone(&scratch->tombstone, &scratch->label);

    if (!thread) {
        prepare_child_process(&scratch->process, parent_process,
                              &scratch->label);
        if (bpf_map_update_elem(&process_states,
                                &scratch->label.process_state_id,
                                &scratch->process, BPF_NOEXIST))
            goto fail_locked;
    }
    __sync_fetch_and_add(&entry->live_task_refs, 1);
    __sync_fetch_and_add(profile_task_refs, 1);
    if (thread) {
        __sync_fetch_and_add(&parent_process->live_thread_refs, 1);
    } else {
        __sync_fetch_and_add(&domain->live_process_refs, 1);
    }
    if (bpf_map_update_elem(&created_by_edges, &scratch->label.task_cookie,
                            &scratch->created_by, BPF_NOEXIST))
        goto rollback_references;
    if (publish_task(task, scratch)) {
        bpf_map_delete_elem(&created_by_edges, &scratch->label.task_cookie);
        goto rollback_references;
    }
    parent_process->transition_guard = 0;
    return 0;

rollback_references:
    __sync_fetch_and_sub(&entry->live_task_refs, 1);
    __sync_fetch_and_sub(profile_task_refs, 1);
    if (thread) {
        __sync_fetch_and_sub(&parent_process->live_thread_refs, 1);
    } else {
        __sync_fetch_and_sub(&domain->live_process_refs, 1);
        bpf_map_delete_elem(&process_states, &scratch->label.process_state_id);
    }
fail_locked:
    parent_process->transition_guard = 0;
    return identity_deny(config);
}

static __always_inline int prepare_root_state(
    struct identity_scratch_v1 *scratch, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding, __u8 root_class, __u8 role_class,
    __u32 role_id)
{
    task_label_v1 *label = &scratch->label;

    label->node_boot_id = config->node_boot_id;
    label->label_epoch = config->label_epoch;
    if (allocate_id(config, &label->process_lineage_id) ||
        allocate_id(config, &label->process_instance_id) ||
        allocate_id(config, &label->process_state_id) ||
        allocate_id(config, &label->entry_instance_id))
        return -EACCES;
    label->execution_set_id = binding->execution_set_id;
    label->birth_profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    if (allocate_id(config, &label->birth_execution_id) ||
        allocate_id(config, &label->birth_authority_domain_id))
        return -EACCES;
    label->task_cookie = label->birth_execution_id.low;
    label->lineage_depth = 0;
#pragma unroll
    for (int index = 0; index < 6; index++)
        label->reserved[index] = 0;
#pragma unroll
    for (int index = 0; index < MAX_ANCESTOR_PROCESS_LINEAGES_V1; index++)
        zero_id(&label->ancestor_process_lineage_ids[index]);
    label->placement.protected_root_binding_id = binding->binding_id;
    label->placement.protected_root_binding_nonce = binding->binding_nonce;
    label->placement.allowed_descendant_policy_id = 0;
    label->placement.reserved = 0;

    prepare_coordinate(&scratch->coordinate, label->task_cookie,
                       &label->process_instance_id, &label->process_state_id);
    prepare_tombstone(&scratch->tombstone, label);

    scratch->process.process_state_id = label->process_state_id;
    scratch->process.node_boot_id = label->node_boot_id;
    scratch->process.label_epoch = label->label_epoch;
    scratch->process.process_lineage_id = label->process_lineage_id;
    scratch->process.process_instance_id = label->process_instance_id;
    scratch->process.entry_instance_id = label->entry_instance_id;
    scratch->process.entry_root_process_state_id = label->process_state_id;
    scratch->process.active_execution_id = label->birth_execution_id;
    scratch->process.active_role_id = role_id;
    scratch->process.process_state_vector_id =
        CONSERVATIVE_PROCESS_STATE_VECTOR_V1;
    scratch->process.active_profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->process.authority_domain_id = label->birth_authority_domain_id;
    scratch->process.effective_response_set_ref_id = 0;
    zero_id(&scratch->process.pending_exec_id);
    zero_id(&scratch->process.pending_target_execution_id);
    scratch->process.pending_target_role_id = 0;
    scratch->process.reserved_pending_role = 0;
    scratch->process.transition_guard = 0;
    scratch->process.pending_exec_response_set_ref_id = 0;
    scratch->process.transition_version = 1;
    scratch->process.live_thread_refs = 1;
    scratch->process.exec_guard_state = exec_guard_state_v1_none;
    scratch->process.state = process_security_state_kind_v1_active;
#pragma unroll
    for (int index = 0; index < 6; index++)
        scratch->process.reserved[index] = 0;

    scratch->entry.entry_instance_id = label->entry_instance_id;
    scratch->entry.node_boot_id = label->node_boot_id;
    scratch->entry.label_epoch = label->label_epoch;
    scratch->entry.execution_set_id = label->execution_set_id;
    zero_id(&scratch->entry.claim_slot_id);
    scratch->entry.root_task_cookie = label->task_cookie;
    scratch->entry.root_process_state_id = label->process_state_id;
    scratch->entry.committed_execution_id = label->birth_execution_id;
    scratch->entry.live_task_refs = 1;
    scratch->entry.transition_version = 1;
    scratch->entry.entry_kind =
        root_class == external_root_class_v1_initial_container_root
            ? entry_kind_v1_container_start
            : entry_kind_v1_unknown_external;
    scratch->entry.admission_state = entry_admission_state_v1_committed;
    scratch->entry.lifetime_state = entry_lifetime_state_v1_active;
    scratch->entry.terminal_reason = 0;
#pragma unroll
    for (int index = 0; index < 4; index++)
        scratch->entry.reserved_state[index] = 0;
    scratch->entry.transition_guard = 0;

    scratch->domain.authority_domain_id = label->birth_authority_domain_id;
    scratch->domain.node_boot_id = label->node_boot_id;
    scratch->domain.label_epoch = label->label_epoch;
    scratch->domain.domain_epoch = 1;
    scratch->domain.live_process_refs = 1;
    scratch->domain.response_plan_refs = 0;
    scratch->domain.reconciliation_hold_refs = 0;
    scratch->domain.potential_sensitive_bits = 0;
    scratch->domain.observed_sensitive_bits = 0;
    scratch->domain.effective_restriction_set_ref_id = 0;
    scratch->domain.effective_response_set_ref_id = 0;
    scratch->domain.retained_generation_set_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->domain.transition_version = 1;
    scratch->domain.transition_guard = 0;
    scratch->domain.state = authority_domain_state_kind_v1_active;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->domain.reserved[index] = 0;

    scratch->classification.node_boot_id = label->node_boot_id;
    scratch->classification.label_epoch = label->label_epoch;
    scratch->classification.task_cookie = label->task_cookie;
    scratch->classification.process_state_id = label->process_state_id;
    scratch->classification.entry_instance_id = label->entry_instance_id;
    scratch->classification.execution_set_id = label->execution_set_id;
    scratch->classification.cgroup_binding_id = binding->binding_id;
    scratch->classification.cgroup_lifetime_id =
        binding->root_cgroup_live_interval_id;
    scratch->classification.creator_task_cookie = 0;
    scratch->classification.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->classification.installed_role_numeric_id = role_id;
    scratch->classification.root_class = root_class;
    scratch->classification.purpose = entry_purpose_v1_unknown;
    scratch->classification.installed_role_class = role_class;
    scratch->classification.reserved = 0;
    scratch->classification.classified_boottime_ns = bpf_ktime_get_ns();
    return 0;
}

static __always_inline int create_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch,
    __u8 root_class, __u8 role_class, __u32 role_id)
{
    __u64 *profile_task_refs;

    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &binding->active_profile_generation_ref_id);
    if (!profile_task_refs)
        return identity_deny(config);
    if (prepare_root_state(scratch, config, binding, root_class, role_class,
                           role_id))
        return identity_deny(config);
    if (bpf_map_update_elem(&authority_domains,
                            &scratch->domain.authority_domain_id,
                            &scratch->domain, BPF_NOEXIST))
        return identity_deny(config);
    if (bpf_map_update_elem(&entry_states, &scratch->entry.entry_instance_id,
                            &scratch->entry, BPF_NOEXIST))
        goto rollback_domain;
    if (bpf_map_update_elem(&process_states,
                            &scratch->process.process_state_id,
                            &scratch->process, BPF_NOEXIST))
        goto rollback_entry;
    if (bpf_map_update_elem(&external_root_classifications,
                            &scratch->classification.task_cookie,
                            &scratch->classification, BPF_NOEXIST))
        goto rollback_process;
    __sync_fetch_and_add(profile_task_refs, 1);
    if (publish_task(task, scratch)) {
        __sync_fetch_and_sub(profile_task_refs, 1);
        bpf_map_delete_elem(&external_root_classifications,
                            &scratch->classification.task_cookie);
        goto rollback_process;
    }
    return 0;

rollback_process:
    bpf_map_delete_elem(&process_states, &scratch->process.process_state_id);
rollback_entry:
    bpf_map_delete_elem(&entry_states, &scratch->entry.entry_instance_id);
rollback_domain:
    bpf_map_delete_elem(&authority_domains,
                        &scratch->domain.authority_domain_id);
    return identity_deny(config);
}

static __always_inline int create_external_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch)
{
    __u8 root_class = external_root_class_v1_external_runtime_root;
    __u8 role_class = installed_role_class_v1_runtime_external_restricted;
    __u32 role_id = binding->external_role_id;

    if (binding->lifecycle_state != binding_lifecycle_state_v1_active) {
        root_class = external_root_class_v1_unresolved_protected;
        role_class = installed_role_class_v1_fail_closed_unknown;
    } else {
        __u64 previous = __sync_val_compare_and_swap(
            &binding->initial_root_state, initial_root_state_v1_available,
            initial_root_state_v1_consumed);
        if (previous == initial_root_state_v1_available) {
            __sync_fetch_and_add(&binding->transition_version, 1);
            root_class = external_root_class_v1_initial_container_root;
            role_class = installed_role_class_v1_initial_role;
            role_id = binding->initial_role_id;
        }
    }
    return create_root(task, config, binding, scratch, root_class, role_class,
                       role_id);
}

static __always_inline int finalize_task_coordinate(struct task_struct *task,
                                                     task_label_v1 *label)
{
    task_coordinate_v1 *coordinate;
    struct pid *thread_pid = NULL;
    struct pid_namespace *pid_namespace = NULL;
    __u32 tid = 0;
    __u32 tgid = 0;
    __u32 pid_namespace_inode = 0;
    __u32 level = 0;
    __u64 start = 0;

    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    BPF_CORE_READ_INTO(&tid, task, pid);
    BPF_CORE_READ_INTO(&tgid, task, tgid);
    BPF_CORE_READ_INTO(&thread_pid, task, thread_pid);
    if (thread_pid)
        BPF_CORE_READ_INTO(&level, thread_pid, level);
    if (thread_pid && level < 32)
        BPF_CORE_READ_INTO(&pid_namespace, thread_pid, numbers[level].ns);
    if (pid_namespace)
        BPF_CORE_READ_INTO(&pid_namespace_inode, pid_namespace, ns.inum);
    if (bpf_core_field_exists(task->start_boottime))
        BPF_CORE_READ_INTO(&start, task, start_boottime);
    else
        BPF_CORE_READ_INTO(&start, task, start_time);
    if (!coordinate || !tid || !tgid || !pid_namespace_inode || !start)
        return -EACCES;
    coordinate->host_tid = tid;
    coordinate->host_tgid = tgid;
    coordinate->pid_namespace_inode = pid_namespace_inode;
    coordinate->task_start_boottime_ns = start;
    coordinate->finalized_boottime_ns = bpf_ktime_get_ns();
    coordinate->transition_version++;
    coordinate->state = task_coordinate_state_v1_runnable;
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(erebor_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct identity_scratch_v1 *scratch;
    struct task_struct *creator;
    task_label_v1 *parent_label;
    execution_set_binding_state_v1 *binding;
    execution_set_binding_state_v1 *creator_binding;
    __u64 cgroup_id;
    int result;

    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    health = identity_health_record();
    scratch = identity_scratch_record();
    if (!scratch)
        return identity_deny(config);
    creator = bpf_get_current_task_btf();
    parent_label = bpf_task_storage_get(&task_labels, creator, 0, 0);
    cgroup_id = task_cgroup_id(task);
    binding = binding_for_cgroup(cgroup_id);
    if (parent_label) {
        if (!label_matches_runtime(parent_label, config) || !binding) {
            if (health)
                health->placement_mismatches++;
            return identity_deny(config);
        }
        result = create_native_child(task, clone_flags, config, parent_label,
                                     binding, scratch);
    } else if ((creator_binding = binding_for_cgroup(task_cgroup_id(creator)))) {
        if (health)
            health->missing_identity_denials++;
        return identity_deny(config);
    } else if (binding) {
        result = create_external_root(task, config, binding, scratch);
    } else {
        return 0;
    }
    if (result && health)
        health->allocation_failures++;
    return result;
}

SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(erebor_cgroup_attach_task, struct cgroup *cgroup,
             const char *path, struct task_struct *task, bool threadgroup)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding;
    __u64 target_cgroup_id;

    config = identity_runtime_config();
    if (!config || !config->enabled || !task)
        return 0;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    target_cgroup_id = cgroup_id(cgroup);
    binding = binding_for_cgroup(target_cgroup_id);
    if (label) {
        if (!binding_matches_label(binding, label)) {
            task_coordinate_v1 *coordinate =
                bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
            if (coordinate) {
                coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
                coordinate->transition_version++;
            }
            health = identity_health_record();
            if (health)
                health->placement_mismatches++;
        }
        return 0;
    }
    if (!binding)
        return 0;
    if (__sync_val_compare_and_swap(&binding->initial_root_state,
                                    initial_root_state_v1_available,
                                    initial_root_state_v1_consumed) ==
        initial_root_state_v1_available)
        __sync_fetch_and_add(&binding->transition_version, 1);
    scratch = identity_scratch_record();
    health = identity_health_record();
    if (!scratch || create_external_root(task, config, binding, scratch)) {
        if (health)
            health->allocation_failures++;
    } else if (finalize_task_coordinate(task, &scratch->label)) {
        task_coordinate_v1 *coordinate =
            bpf_map_lookup_elem(&task_coordinates, &scratch->label.task_cookie);
        if (coordinate) {
            coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
            coordinate->transition_version++;
        }
        if (health)
            health->coordinate_failures++;
    }
    return 0;
}

SEC("raw_tracepoint/cgroup_mkdir")
int erebor_cgroup_mkdir(struct bpf_raw_tracepoint_args *context)
{
    struct cgroup *cgroup = (void *)context->args[0];
    __u64 id = cgroup_id(cgroup);
    __u64 parent_id = cgroup_parent_id(cgroup);
    __u64 *tracked_root;
    __u64 root;

    if (!id || !parent_id)
        return 0;
    tracked_root = bpf_map_lookup_elem(&cgroup_binding_roots, &parent_id);
    root = tracked_root ? *tracked_root : parent_id;
    if (bpf_map_lookup_elem(&execution_set_bindings, &root))
        bpf_map_update_elem(&cgroup_binding_roots, &id, &root, BPF_NOEXIST);
    return 0;
}

SEC("raw_tracepoint/cgroup_release")
int erebor_cgroup_release(struct bpf_raw_tracepoint_args *context)
{
    struct cgroup *cgroup = (void *)context->args[0];
    execution_set_binding_state_v1 *binding;
    __u64 id = cgroup_id(cgroup);

    if (!id)
        return 0;
    bpf_map_delete_elem(&cgroup_binding_roots, &id);
    binding = bpf_map_lookup_elem(&execution_set_bindings, &id);
    if (binding) {
        binding->lifecycle_state = binding_lifecycle_state_v1_tombstoned;
        binding->initial_root_state = initial_root_state_v1_consumed;
        binding->transition_version++;
    }
    return 0;
}

SEC("fentry/wake_up_new_task")
int BPF_PROG(erebor_wake_up_new_task, struct task_struct *task)
{
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    identity_health_v1 *health;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    health = identity_health_record();
    if (finalize_task_coordinate(task, label)) {
        coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
        if (coordinate) {
            coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
            coordinate->transition_version++;
        }
        if (health)
            health->coordinate_failures++;
    }
    return 0;
}

SEC("iter/task")
int erebor_reconcile_tasks(struct bpf_iter__task *context)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    execution_set_binding_state_v1 *binding;
    struct task_struct *task = context->task;
    __u64 cgroup_id;

    if (!task)
        return 0;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    cgroup_id = task_cgroup_id(task);
    binding = binding_for_cgroup(cgroup_id);
    if (label) {
        coordinate = bpf_map_lookup_elem(&task_coordinates,
                                         &label->task_cookie);
        process = bpf_map_lookup_elem(&process_states,
                                      &label->process_state_id);
        entry = bpf_map_lookup_elem(&entry_states,
                                    &label->entry_instance_id);
        domain = process ? bpf_map_lookup_elem(&authority_domains,
                                               &process->authority_domain_id)
                         : NULL;
        if (!label_matches_runtime(label, config) ||
            !binding_matches_label(binding, label) || !coordinate ||
            coordinate->state != task_coordinate_state_v1_runnable ||
            !process || process->state != process_security_state_kind_v1_active ||
            process->transition_guard ||
            process->exec_guard_state != exec_guard_state_v1_none || !entry ||
            entry->admission_state != entry_admission_state_v1_committed ||
            entry->lifetime_state != entry_lifetime_state_v1_active || !domain ||
            domain->state != authority_domain_state_kind_v1_active) {
            if (coordinate) {
                coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
                coordinate->transition_version++;
            }
            health = identity_health_record();
            if (health)
                health->reconciliation_required++;
        }
        return 0;
    }
    if (!binding)
        return 0;
    scratch = identity_scratch_record();
    health = identity_health_record();
    if (!scratch || create_root(
                        task, config, binding, scratch,
                        external_root_class_v1_restored_or_unknown_root,
                        installed_role_class_v1_fail_closed_unknown,
                        binding->external_role_id) ||
        finalize_task_coordinate(task, &scratch->label)) {
        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

static __always_inline void candidate_from_bprm(
    exact_executable_candidate_v1 *candidate, struct linux_binprm *bprm)
{
    struct file *file = NULL;
    struct inode *inode = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *mount = NULL;
    int mount_id = 0;

    candidate->mount_id = 0;
    candidate->inode = 0;
    candidate->inode_generation = 0;
    if (BPF_CORE_READ_INTO(&file, bprm, file) || !file ||
        BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode ||
        BPF_CORE_READ_INTO(&vfsmount, file, f_path.mnt) || !vfsmount)
        return;
    mount = container_of(vfsmount, struct mount, mnt);
    if (BPF_CORE_READ_INTO(&mount_id, mount, mnt_id) || mount_id <= 0 ||
        BPF_CORE_READ_INTO(&candidate->inode, inode, i_ino) ||
        !candidate->inode ||
        BPF_CORE_READ_INTO(&candidate->inode_generation, inode, i_generation))
        return;
    candidate->mount_id = mount_id;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(erebor_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct identity_scratch_v1 *scratch;
    struct task_struct *task;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    execution_set_binding_state_v1 *binding;
    pending_exec_v1 *pending;
    __u64 cgroup_id;
    __u16 index;

    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    cgroup_id = bpf_get_current_cgroup_id();
    binding = binding_for_cgroup(cgroup_id);
    health = identity_health_record();
    if (!label) {
        if (binding) {
            if (health)
                health->missing_identity_denials++;
            return identity_deny(config);
        }
        return 0;
    }
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label) || !coordinate ||
        coordinate->state != task_coordinate_state_v1_runnable) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!process || process->state != process_security_state_kind_v1_active ||
        !entry || entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active)
        return identity_deny(config);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &process->authority_domain_id);
    if (!domain || domain->state != authority_domain_state_kind_v1_active ||
        domain->label_epoch != config->label_epoch ||
        !id128_equal(&domain->node_boot_id, &config->node_boot_id))
        return identity_deny(config);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!pending) {
        if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
            if (health)
                health->exec_guard_denials++;
            return identity_deny(config);
        }
        if (process->exec_guard_state != exec_guard_state_v1_none) {
            process->transition_guard = 0;
            if (health)
                health->exec_guard_denials++;
            return identity_deny(config);
        }
        scratch = identity_scratch_record();
        if (!scratch || allocate_id(config, &scratch->pending_exec.pending_exec_id) ||
            allocate_id(config, &scratch->pending_exec.target_execution_id)) {
            process->transition_guard = 0;
            return identity_deny(config);
        }
        scratch->pending_exec.task_cookie = label->task_cookie;
        scratch->pending_exec.process_state_id = label->process_state_id;
        scratch->pending_exec.exec_attempt_sequence = process->transition_version + 1;
        scratch->pending_exec.source_execution_id = process->active_execution_id;
        scratch->pending_exec.source_role_id = process->active_role_id;
        scratch->pending_exec.candidate_count = 1;
        scratch->pending_exec.reserved_0 = 0;
        scratch->pending_exec.source_profile_generation_ref_id =
            process->active_profile_generation_ref_id;
        scratch->pending_exec.pending_exec_response_set_ref_id =
            process->effective_response_set_ref_id;
        candidate_from_bprm(&scratch->pending_exec.ordered_candidates[0], bprm);
        if (!scratch->pending_exec.ordered_candidates[0].mount_id) {
            process->transition_guard = 0;
            return identity_deny(config);
        }
#pragma unroll
        for (int candidate = 1; candidate < MAX_EXEC_CANDIDATES_V1; candidate++) {
            scratch->pending_exec.ordered_candidates[candidate].mount_id = 0;
            scratch->pending_exec.ordered_candidates[candidate].inode = 0;
            scratch->pending_exec.ordered_candidates[candidate].inode_generation = 0;
        }
        scratch->pending_exec.transition_version = 1;
        scratch->pending_exec.state = pending_exec_state_v1_preparing;
#pragma unroll
        for (int reserved = 0; reserved < 7; reserved++)
            scratch->pending_exec.reserved_1[reserved] = 0;
        if (bpf_map_update_elem(&pending_execs, &label->task_cookie,
                                &scratch->pending_exec, BPF_NOEXIST)) {
            process->transition_guard = 0;
            return identity_deny(config);
        }
        process->pending_exec_id = scratch->pending_exec.pending_exec_id;
        process->pending_target_execution_id =
            scratch->pending_exec.target_execution_id;
        process->pending_target_role_id = process->active_role_id;
        process->pending_exec_response_set_ref_id =
            process->effective_response_set_ref_id;
        process->exec_guard_state = exec_guard_state_v1_preparing;
        process->transition_version++;
        process->transition_guard = 0;
        return 0;
    }
    if (!id128_equal(&pending->process_state_id, &label->process_state_id) ||
        pending->state != pending_exec_state_v1_preparing ||
        process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->candidate_count >= MAX_EXEC_CANDIDATES_V1)
        return identity_deny(config);
    index = pending->candidate_count;
    candidate_from_bprm(&pending->ordered_candidates[index], bprm);
    if (!pending->ordered_candidates[index].mount_id)
        return identity_deny(config);
    pending->candidate_count++;
    pending->transition_version++;
    return 0;
}

SEC("fentry/security_bprm_committing_creds")
int BPF_PROG(erebor_bprm_committing_creds, struct linux_binprm *bprm)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process || !pending ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
        if (process)
            process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        if (pending)
            pending->state = pending_exec_state_v1_outcome_unknown;
        return 0;
    }
    if (process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->state != pending_exec_state_v1_preparing ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        process->transition_guard = 0;
        return 0;
    }
    process->exec_guard_state = exec_guard_state_v1_commit_pending;
    process->transition_version++;
    pending->state = pending_exec_state_v1_commit_pending;
    pending->transition_version++;
    process->transition_guard = 0;
    return 0;
}

static __always_inline int complete_failed_exec(long result)
{
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;

    if (result >= 0)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process || !pending ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return 0;
    if (process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->state != pending_exec_state_v1_preparing) {
        pending->state = pending_exec_state_v1_post_ponr_fatal;
        pending->transition_version++;
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        process->transition_guard = 0;
        return 0;
    }
    pending->state = pending_exec_state_v1_pre_ponr_failed;
    pending->transition_version++;
    zero_id(&process->pending_exec_id);
    zero_id(&process->pending_target_execution_id);
    process->pending_target_role_id = 0;
    process->pending_exec_response_set_ref_id = 0;
    process->exec_guard_state = exec_guard_state_v1_none;
    process->transition_version++;
    process->transition_guard = 0;
    bpf_map_delete_elem(&pending_execs, &label->task_cookie);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int erebor_sys_exit_execve(struct trace_event_raw_sys_exit *context)
{
    return complete_failed_exec(context->ret);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int erebor_sys_exit_execveat(struct trace_event_raw_sys_exit *context)
{
    return complete_failed_exec(context->ret);
}

SEC("tracepoint/sched/sched_process_exec")
int erebor_sched_process_exec(struct trace_event_raw_sched_process_exec *context)
{
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;
    task_coordinate_v1 *coordinate;
    __u64 pid_tgid;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process || !pending ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
        if (process)
            process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        if (pending)
            pending->state = pending_exec_state_v1_outcome_unknown;
        return 0;
    }
    if (process->exec_guard_state != exec_guard_state_v1_commit_pending ||
        pending->state != pending_exec_state_v1_commit_pending ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        process->transition_guard = 0;
        return 0;
    }
    process->active_execution_id = pending->target_execution_id;
    process->active_role_id = process->pending_target_role_id;
    process->effective_response_set_ref_id =
        process->pending_exec_response_set_ref_id;
    zero_id(&process->pending_exec_id);
    zero_id(&process->pending_target_execution_id);
    process->pending_target_role_id = 0;
    process->pending_exec_response_set_ref_id = 0;
    process->exec_guard_state = exec_guard_state_v1_none;
    process->transition_version++;
    pending->state = pending_exec_state_v1_success;
    pending->transition_version++;
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (coordinate) {
        pid_tgid = bpf_get_current_pid_tgid();
        coordinate->host_tid = (__u32)pid_tgid;
        coordinate->host_tgid = pid_tgid >> 32;
        coordinate->transition_version++;
        coordinate->state = task_coordinate_state_v1_runnable;
    }
    process->transition_guard = 0;
    bpf_map_delete_elem(&pending_execs, &label->task_cookie);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(erebor_identity_file_open, struct file *file, int ret)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct task_struct *task;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    execution_set_binding_state_v1 *binding;
    __u64 cgroup_id;
    __u64 version;

    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    health = identity_health_record();
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    cgroup_id = bpf_get_current_cgroup_id();
    binding = binding_for_cgroup(cgroup_id);
    if (!label) {
        if (binding) {
            if (health)
                health->missing_identity_denials++;
            return identity_deny(config);
        }
        return 0;
    }
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label)) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!coordinate || coordinate->state != task_coordinate_state_v1_runnable ||
        !process || process->state != process_security_state_kind_v1_active ||
        !entry || entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        process->transition_guard ||
        process->exec_guard_state != exec_guard_state_v1_none)
        return identity_deny(config);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &process->authority_domain_id);
    version = process->transition_version;
    if (!id128_equal(&process->entry_instance_id, &label->entry_instance_id) ||
        !domain || domain->state != authority_domain_state_kind_v1_active ||
        domain->label_epoch != config->label_epoch ||
        !id128_equal(&domain->node_boot_id, &config->node_boot_id) ||
        process->transition_guard || version != process->transition_version)
        return identity_deny(config);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int erebor_sched_process_exit(struct trace_event_raw_sched_process_template *context)
{
    struct task_struct *task;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    task_reference_tombstone_v1 *tombstone;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    __u64 *profile_task_refs;
    identity_health_v1 *health;
    __u64 previous;
    bool released = true;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (coordinate) {
        coordinate->state = task_coordinate_state_v1_exited;
        coordinate->transition_version++;
    }
    tombstone = bpf_map_lookup_elem(&task_reference_tombstones,
                                    &label->task_cookie);
    if (!tombstone)
        return 0;
    tombstone->task_free_observed = 1;

    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_ENTRY_V1);
    if (!(previous & TASK_REFERENCE_ENTRY_V1)) {
        if (entry) {
            if (__sync_fetch_and_sub(&entry->live_task_refs, 1) == 0)
                released = false;
        } else {
            released = false;
        }
    }

    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_PROCESS_V1);
    if (!(previous & TASK_REFERENCE_PROCESS_V1)) {
        if (process) {
            previous = __sync_fetch_and_sub(&process->live_thread_refs, 1);
            if (previous == 0) {
                released = false;
            } else if (previous == 1) {
                process->state = process_security_state_kind_v1_reclaimable;
                process->transition_version++;
                domain = bpf_map_lookup_elem(&authority_domains,
                                             &process->authority_domain_id);
                if (!domain ||
                    __sync_fetch_and_sub(&domain->live_process_refs, 1) == 0)
                    released = false;
            }
        } else {
            released = false;
        }
    }

    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs, &tombstone->profile_generation_ref_id);
    previous = __sync_fetch_and_or(
        &tombstone->released_bits, TASK_REFERENCE_PROFILE_GENERATION_V1);
    if (!(previous & TASK_REFERENCE_PROFILE_GENERATION_V1)) {
        if (!profile_task_refs ||
            __sync_fetch_and_sub(profile_task_refs, 1) == 0)
            released = false;
    }

    tombstone->state = released ? reference_tombstone_state_v1_released
                                : reference_tombstone_state_v1_owned;
    tombstone->transition_version++;
    if (!released) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
