/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_ROOT_HELPERS_H
#define EREBOR_IDENTITY_ROOT_HELPERS_H

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
        allocate_id(config, &label->birth_authority_domain_id) ||
        allocate_id(config, &scratch->image.image_provenance_id))
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
    scratch->process.exec_check_task_cookie = 0;
    scratch->process.transition_version = 1;
    scratch->process.live_thread_refs = 1;
    scratch->process.exec_guard_state = exec_guard_state_v1_none;
    scratch->process.state = process_security_state_kind_v1_allocating;
#pragma unroll
    for (int index = 0; index < 6; index++)
        scratch->process.reserved[index] = 0;
    prepare_process_vector(
        &scratch->process_vector, label,
        binding->active_profile_generation_ref_id, 0);

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
    zero_id(&scratch->classification.administrative_approval_proof_id);
    zero_id(&scratch->classification.administrative_claim_slot_id);
    scratch->classification.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->classification.installed_role_numeric_id = role_id;
    scratch->classification.root_class = root_class;
    scratch->classification.purpose = entry_purpose_v1_unknown;
    scratch->classification.installed_role_class = role_class;
    scratch->classification.reserved = 0;
    scratch->classification.classified_boottime_ns = bpf_ktime_get_ns();
    prepare_execution(
        &scratch->execution, &label->birth_execution_id,
        &label->process_lineage_id, &scratch->image.image_provenance_id,
        process_execution_started_by_v1_process_birth,
        process_execution_state_v1_active);
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
    if (read_real_parent_interval(
            task, scratch->label.task_cookie, 0,
            kernel_real_parent_change_reason_v1_birth,
            &scratch->real_parent))
        return identity_deny(config);
    prepare_task_image(task, scratch, &scratch->image.image_provenance_id);
    if (bpf_map_update_elem(&image_provenance,
                            &scratch->image.image_provenance_id,
                            &scratch->image, BPF_NOEXIST))
        return identity_deny(config);
    if (bpf_map_update_elem(&process_execution_instances,
                            &scratch->execution.process_execution_instance_id,
                            &scratch->execution, BPF_NOEXIST))
        goto rollback_image;
    if (bpf_map_update_elem(&authority_domains,
                            &scratch->domain.authority_domain_id,
                            &scratch->domain, BPF_NOEXIST))
        goto rollback_execution;
    if (bpf_map_update_elem(&entry_states, &scratch->entry.entry_instance_id,
                            &scratch->entry, BPF_NOEXIST))
        goto rollback_domain;
    if (bpf_map_update_elem(&process_state_vectors,
                            &scratch->process.process_state_id,
                            &scratch->process_vector, BPF_NOEXIST))
        goto rollback_entry;
    if (bpf_map_update_elem(&process_states,
                            &scratch->process.process_state_id,
                            &scratch->process, BPF_NOEXIST))
        goto rollback_vector;
    if (bpf_map_update_elem(&external_root_classifications,
                            &scratch->classification.task_cookie,
                            &scratch->classification, BPF_NOEXIST))
        goto rollback_process;
    __sync_fetch_and_add(profile_task_refs, 1);
    if (publish_task(task, scratch)) {
        decrement_nonzero_counter(profile_task_refs);
        bpf_map_delete_elem(&external_root_classifications,
                            &scratch->classification.task_cookie);
        goto rollback_process;
    }
    {
        process_security_state_v1 *installed = bpf_map_lookup_elem(
            &process_states, &scratch->process.process_state_id);

        if (!installed ||
            !id128_equal(&installed->process_instance_id,
                         &scratch->label.process_instance_id)) {
            bpf_task_storage_delete(&task_labels, task);
            bpf_map_delete_elem(&task_reference_tombstones,
                                &scratch->label.task_cookie);
            bpf_map_delete_elem(&task_coordinates,
                                &scratch->label.task_cookie);
            delete_initial_real_parent(scratch->label.task_cookie);
            decrement_nonzero_counter(profile_task_refs);
            bpf_map_delete_elem(&external_root_classifications,
                                &scratch->classification.task_cookie);
            goto rollback_process;
        }
        installed->state = process_security_state_kind_v1_active;
        installed->transition_version++;
        {
            process_state_vector_v1 *installed_vector =
                bpf_map_lookup_elem(&process_state_vectors,
                                    &scratch->process.process_state_id);

            if (!installed_vector) {
                bpf_task_storage_delete(&task_labels, task);
                bpf_map_delete_elem(&task_reference_tombstones,
                                    &scratch->label.task_cookie);
                bpf_map_delete_elem(&task_coordinates,
                                    &scratch->label.task_cookie);
                delete_initial_real_parent(scratch->label.task_cookie);
                decrement_nonzero_counter(profile_task_refs);
                bpf_map_delete_elem(&external_root_classifications,
                                    &scratch->classification.task_cookie);
                goto rollback_process;
            }
            installed_vector->state = process_state_vector_state_v1_active;
            installed_vector->transition_version++;
        }
    }
    return 0;

rollback_process:
    bpf_map_delete_elem(&process_states, &scratch->process.process_state_id);
rollback_vector:
    bpf_map_delete_elem(&process_state_vectors,
                        &scratch->process.process_state_id);
rollback_entry:
    bpf_map_delete_elem(&entry_states, &scratch->entry.entry_instance_id);
rollback_domain:
    bpf_map_delete_elem(&authority_domains,
                        &scratch->domain.authority_domain_id);
rollback_execution:
    bpf_map_delete_elem(&process_execution_instances,
                        &scratch->execution.process_execution_instance_id);
rollback_image:
    bpf_map_delete_elem(&image_provenance,
                        &scratch->image.image_provenance_id);
    return identity_deny(config);
}

static __always_inline int create_external_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch)
{
    execution_set_binding_state_v1 *activation;
    __u8 root_class = external_root_class_v1_external_runtime_root;
    __u8 role_class = installed_role_class_v1_runtime_external_restricted;
    __u32 role_id;
    __u32 host_tid = 0;
    bool initial_root;

    activation = binding_activation_for_new_root(binding, config);
    if (!activation)
        return identity_deny(config);
    role_id = activation->external_role_id;
    if (binding->prepared_container_state ==
        prepared_container_state_v1_prepared) {
        /* Iterator reconciliation runs in the reader's context. Read the
         * target task so the held-process proof does not depend on the caller. */
        BPF_CORE_READ_INTO(&host_tid, task, pid);
        if (!prepared_container_binding_is_prepared(binding) ||
            !binding->prepared_container_initial_host_tgid)
            return identity_deny(config);
        /* Keep the canonical root on the held task. After that claim, any
         * task in the exact prepared binding can receive runtime identity. */
        if (binding->initial_root_state == initial_root_state_v1_available &&
            host_tid != binding->prepared_container_initial_host_tgid)
            return PREPARED_CONTAINER_IDENTITY_DEFER_V1;
    }
    initial_root = consume_initial_root(binding);

    if (binding->lifecycle_state != binding_lifecycle_state_v1_active)
        return identity_deny(config);
    if (initial_root) {
        root_class = external_root_class_v1_initial_container_root;
        role_class = installed_role_class_v1_initial_role;
        role_id = activation->initial_role_id;
    }
    int result = create_root(task, config, activation, scratch, root_class,
                             role_class, role_id);

    if (result && initial_root &&
        binding->prepared_container_state ==
            prepared_container_state_v1_prepared)
        prepared_container_mark_corrupt(binding);
    if (result || !initial_root)
        return result;
    if (binding->prepared_container_state ==
            prepared_container_state_v1_prepared &&
        prepared_container_set_initial_entry(
            binding, &scratch->label.entry_instance_id)) {
        prepared_container_mark_corrupt(binding);
        return identity_deny(config);
    }
    return 0;
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

#endif /* EREBOR_IDENTITY_ROOT_HELPERS_H */
