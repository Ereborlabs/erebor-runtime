/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_LIFECYCLE_BPF_H
#define EREBOR_IDENTITY_LIFECYCLE_BPF_H

static __always_inline int label_external_root(
    struct task_struct *task, execution_set_binding_state_v1 *binding,
    identity_runtime_config_v1 *config)
{
    identity_health_v1 *health = identity_health_record();
    struct identity_scratch_v1 *scratch;
    int claim;

    scratch = identity_scratch_record();
    if (!scratch) {
        if (health)
            health->allocation_failures++;
        return -EACCES;
    }
    claim = claim_task_label(task);
    if (claim > 0)
        return 0;
    if (claim < 0) {
        if (health)
            health->allocation_failures++;
        return -EACCES;
    }
    if (create_external_root(task, config, binding, scratch)) {
        bpf_task_storage_delete(&task_labels, task);
        if (health)
            health->allocation_failures++;
        return -EACCES;
    }
    if (finalize_task_coordinate(task, &scratch->label)) {
        task_coordinate_v1 *coordinate =
            bpf_map_lookup_elem(&task_coordinates,
                                &scratch->label.task_cookie);

        if (coordinate) {
            coordinate->state =
                task_coordinate_state_v1_fail_closed_unknown;
            coordinate->transition_version++;
        }
        if (health)
            health->coordinate_failures++;
        return -EACCES;
    }
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
    struct cgroup *creator_cgroup = NULL;
    task_label_v1 *parent_label;
    execution_set_binding_state_v1 *creator_binding;
    io_uring_execution_state_v1 *io_uring_execution;
    int creator_binding_lookup;
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
    io_uring_execution = bpf_task_storage_get(
        &io_uring_execution_states, task, 0,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!io_uring_execution)
        return identity_deny(config);
    __builtin_memset(io_uring_execution, 0, sizeof(*io_uring_execution));
    creator = bpf_get_current_task_btf();
    parent_label = bpf_task_storage_get(&task_labels, creator, 0, 0);
    if (task_cgroup(creator, &creator_cgroup)) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    creator_binding = binding_for_cgroup(creator_cgroup,
                                         &creator_binding_lookup);
    if (creator_binding_lookup) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    if (parent_label) {
        if (!label_matches_runtime(parent_label, config) ||
            !binding_matches_label(creator_binding, parent_label)) {
            if (health)
                health->placement_mismatches++;
            return identity_deny(config);
        }
        result = create_native_child(task, creator, clone_flags, config,
                                     parent_label, creator_binding, scratch);
    } else {
        if (creator_binding) {
            if (label_external_root(creator, creator_binding, config)) {
                if (health)
                    health->missing_identity_denials++;
                return identity_deny(config);
            }
            parent_label =
                bpf_task_storage_get(&task_labels, creator, 0, 0);
            if (!parent_label) {
                if (health)
                    health->missing_identity_denials++;
                return identity_deny(config);
            }
            result = create_native_child(task, creator, clone_flags, config,
                                         parent_label, creator_binding,
                                         scratch);
        } else {
            return 0;
        }
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
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding;
    int binding_lookup;

    config = identity_runtime_config();
    if (!config || !config->enabled || !task)
        return 0;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup) {
        health = identity_health_record();
        if (health)
            health->placement_mismatches++;
        if (label) {
            task_coordinate_v1 *coordinate =
                bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
            if (coordinate) {
                coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
                coordinate->transition_version++;
            }
        }
        return 0;
    }
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
    label_external_root(task, binding, config);
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
    identity_runtime_config_v1 *config;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    identity_health_v1 *health;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label) {
        if (task_cgroup(task, &cgroup))
            return 0;
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        if (!binding_lookup && binding)
            label_external_root(task, binding, config);
        return 0;
    }
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
    process_state_vector_v1 *process_vector;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    execution_set_binding_state_v1 *binding;
    __u64 *profile_task_refs;
    int claim;
    kernel_real_parent_interval_key_v1 parent_key;
    kernel_real_parent_interval_v1 *parent_interval;
    struct task_struct *task = context->task;
    struct cgroup *cgroup = NULL;
    int binding_lookup = -EACCES;

    if (!task)
        return 0;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!task_cgroup(task, &cgroup))
        binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (task_label_is_uninitialized(label))
        label = NULL;
    if (label) {
        coordinate = bpf_map_lookup_elem(&task_coordinates,
                                         &label->task_cookie);
        parent_interval = NULL;
        if (coordinate) {
            parent_key.child_task_cookie = label->task_cookie;
            parent_key.interval_sequence =
                coordinate->real_parent_interval_sequence;
            parent_interval = bpf_map_lookup_elem(
                &kernel_real_parent_intervals, &parent_key);
        }
        process = bpf_map_lookup_elem(&process_states,
                                      &label->process_state_id);
        process_vector = bpf_map_lookup_elem(&process_state_vectors,
                                             &label->process_state_id);
        entry = bpf_map_lookup_elem(&entry_states,
                                    &label->entry_instance_id);
        domain = process ? bpf_map_lookup_elem(&authority_domains,
                                               &process->authority_domain_id)
                         : NULL;
        profile_task_refs = process ? bpf_map_lookup_elem(
                                          &profile_generation_task_refs,
                                          &process->active_profile_generation_ref_id)
                                    : NULL;
        if (binding_lookup || !label_matches_runtime(label, config) ||
            !binding_matches_label(binding, label) || !coordinate ||
            coordinate->state != task_coordinate_state_v1_runnable ||
            !parent_interval ||
            parent_interval->child_task_cookie != label->task_cookie ||
            parent_interval->interval_end_boottime_ns ||
            !process || process->state != process_security_state_kind_v1_active ||
            !process->live_thread_refs ||
            !process_vector ||
            process_vector->state != process_state_vector_state_v1_active ||
            process_vector->process_state_vector_id !=
                process->process_state_vector_id ||
            process_vector->profile_generation_ref_id !=
                process->active_profile_generation_ref_id ||
            process->transition_guard ||
            process->exec_guard_state != exec_guard_state_v1_none || !entry ||
            entry->admission_state != entry_admission_state_v1_committed ||
            entry->lifetime_state != entry_lifetime_state_v1_active ||
            !entry->live_task_refs || !domain ||
            domain->state != authority_domain_state_kind_v1_active ||
            !domain->live_process_refs || !profile_task_refs ||
            __sync_fetch_and_add(profile_task_refs, 0) == 0) {
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
    if (binding_lookup) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
        return 0;
    }
    if (!binding)
        return 0;
    scratch = identity_scratch_record();
    health = identity_health_record();
    claim = scratch ? claim_task_label(task) : -EACCES;
    if (claim > 0)
        return 0;
    if (claim < 0) {
        if (health)
            health->reconciliation_required++;
        return 0;
    }
    consume_initial_root(binding);
    if (create_root(task, config, binding, scratch,
                    external_root_class_v1_restored_or_unknown_root,
                    installed_role_class_v1_fail_closed_unknown,
                    binding->external_role_id) ||
        finalize_task_coordinate(task, &scratch->label)) {
        bpf_task_storage_delete(&task_labels, task);
        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

#endif /* EREBOR_IDENTITY_LIFECYCLE_BPF_H */
