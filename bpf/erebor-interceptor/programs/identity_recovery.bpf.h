/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_RECOVERY_BPF_H
#define EREBOR_IDENTITY_RECOVERY_BPF_H

#define RECOVERY_RELATION_EXTERNAL_V1 0
#define RECOVERY_RELATION_APPLICATION_V1 1
#define RECOVERY_RELATION_UNRESOLVED_V1 -1

static __always_inline bool recovery_record_matches_binding(
    const recovered_container_activation_v1 *recovery,
    const execution_set_binding_state_v1 *binding,
    const identity_runtime_config_v1 *config)
{
    return recovery && binding && config &&
           recovery->phase != recovered_container_activation_phase_v1_unknown &&
           recovery->phase != recovered_container_activation_phase_v1_corrupt &&
           id128_equal(&recovery->node_boot_id, &config->node_boot_id) &&
           recovery->label_epoch == config->label_epoch &&
           id128_equal(&recovery->binding_id, &binding->binding_id) &&
           id128_equal(&recovery->binding_nonce, &binding->binding_nonce) &&
           id128_equal(&recovery->root_cgroup_live_interval_id,
                       &binding->root_cgroup_live_interval_id) &&
           recovery->profile_generation_ref_id ==
               binding->active_profile_generation_ref_id &&
           recovery->root_cgroup_id == binding->root_cgroup_id &&
           recovery->expected_binding_transition_version ==
               binding->transition_version &&
           recovery->init_host_tgid ==
               binding->prepared_container_initial_host_tgid &&
           recovery->task_set_generation &&
           !id128_is_zero(&recovery->recovery_attempt_id) &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active &&
           binding->prepared_container_state ==
               prepared_container_state_v1_recovering;
}

static __always_inline recovered_container_activation_v1 *
recovery_for_binding(const execution_set_binding_state_v1 *binding,
                     const identity_runtime_config_v1 *config)
{
    recovered_container_activation_v1 *recovery;

    if (!binding)
        return NULL;
    recovery = bpf_map_lookup_elem(&recovered_container_activations,
                                   &binding->root_cgroup_id);
    return recovery_record_matches_binding(recovery, binding, config)
               ? recovery
               : NULL;
}

static __always_inline bool recovery_init_request_matches(
    const recovered_container_init_task_v1 *request,
    const recovered_container_activation_v1 *recovery)
{
    return request && recovery && !request->reserved &&
           id128_equal(&request->node_boot_id, &recovery->node_boot_id) &&
           id128_equal(&request->binding_id, &recovery->binding_id) &&
           id128_equal(&request->recovery_attempt_id,
                       &recovery->recovery_attempt_id) &&
           request->label_epoch == recovery->label_epoch &&
           request->root_cgroup_id == recovery->root_cgroup_id &&
           request->expected_binding_transition_version ==
               recovery->expected_binding_transition_version &&
           request->init_host_tgid == recovery->init_host_tgid;
}

static __always_inline bool recovery_task_is_exact_init(
    struct task_struct *task,
    const recovered_container_activation_v1 *recovery)
{
    recovered_container_init_task_v1 *request;
    __u32 host_tgid = 0;

    if (!task || !recovery)
        return false;
    request = bpf_task_storage_get(&recovered_container_init_tasks,
                                   task, 0, 0);
    BPF_CORE_READ_INTO(&host_tgid, task, tgid);
    return host_tgid == recovery->init_host_tgid &&
           recovery_init_request_matches(request, recovery);
}

static __always_inline task_coordinate_v1 *recovery_init_coordinate(
    const recovered_container_activation_v1 *recovery)
{
    entry_security_state_v1 *entry;

    if (!recovery ||
        id128_is_zero(&recovery->application_entry_instance_id))
        return NULL;
    entry = bpf_map_lookup_elem(
        &entry_states, &recovery->application_entry_instance_id);
    if (!entry || !entry->root_task_cookie)
        return NULL;
    return bpf_map_lookup_elem(&task_coordinates,
                               &entry->root_task_cookie);
}

static __noinline int recovery_task_relation(
    struct task_struct *task,
    const recovered_container_activation_v1 *recovery,
    const execution_set_binding_state_v1 *binding)
{
    struct task_struct *cursor = task;
    task_coordinate_v1 *init_coordinate;

    if (!task || !recovery || !binding)
        return RECOVERY_RELATION_UNRESOLVED_V1;
    init_coordinate = recovery_init_coordinate(recovery);
    if (!init_coordinate || !init_coordinate->task_start_boottime_ns)
        return RECOVERY_RELATION_UNRESOLVED_V1;
#pragma unroll
    for (int index = 0; index <= MAX_ANCESTOR_PROCESS_LINEAGES_V1; index++) {
        struct cgroup *cgroup = NULL;
        execution_set_binding_state_v1 *owner;
        struct task_struct *parent = NULL;
        __u64 start = 0;
        __u32 host_tgid = 0;
        int lookup = -EACCES;

        BPF_CORE_READ_INTO(&host_tgid, cursor, tgid);
        if (bpf_core_field_exists(cursor->start_boottime))
            BPF_CORE_READ_INTO(&start, cursor, start_boottime);
        else
            BPF_CORE_READ_INTO(&start, cursor, start_time);
        if (host_tgid == recovery->init_host_tgid &&
            start == init_coordinate->task_start_boottime_ns)
            return RECOVERY_RELATION_APPLICATION_V1;
        if (task_cgroup(cursor, &cgroup))
            return RECOVERY_RELATION_UNRESOLVED_V1;
        owner = binding_for_cgroup(cgroup, &lookup);
        if (lookup)
            return RECOVERY_RELATION_UNRESOLVED_V1;
        if (!owner || !id128_equal(&owner->binding_id, &binding->binding_id) ||
            !id128_equal(&owner->binding_nonce, &binding->binding_nonce))
            return RECOVERY_RELATION_EXTERNAL_V1;
        if (BPF_CORE_READ_INTO(&parent, cursor, real_parent) || !parent ||
            parent == cursor)
            return RECOVERY_RELATION_EXTERNAL_V1;
        cursor = parent;
    }
    return RECOVERY_RELATION_UNRESOLVED_V1;
}

static __always_inline entry_admission_rule_v1 *recovery_application_rule(
    const execution_set_binding_state_v1 *binding,
    const identity_runtime_config_v1 *config)
{
    binding_activation_target_key_v1 key;
    execution_set_binding_state_v1 *activation;
    entry_admission_rule_v1 *rule;

    activation = binding_activation_for_new_root(binding, config);
    if (!activation)
        return NULL;
    key.binding_id = binding->binding_id;
    key.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    rule = bpf_map_lookup_elem(&recovered_container_entry_rules, &key);
    if (!rule || rule->target_role_id != activation->initial_role_id ||
        rule->target_process_state_vector_id !=
            CONSERVATIVE_PROCESS_STATE_VECTOR_V1 ||
        !rule->admitted_entry_rule_id || !rule->exact_object_key_id ||
        rule->reserved ||
        rule->executable_object.profile_generation_ref_id !=
            binding->active_profile_generation_ref_id ||
        !rule->executable_object.mount_namespace_inode ||
        !rule->executable_object.mount_id_unique ||
        !rule->executable_object.filesystem_device ||
        !rule->executable_object.inode ||
        !rule->executable_object.inode_generation)
        return NULL;
    return rule;
}

static __always_inline bool recovery_task_executable_matches(
    struct task_struct *task, const entry_admission_rule_v1 *rule,
    struct identity_scratch_v1 *scratch)
{
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;

    if (!task || !rule || !scratch ||
        BPF_CORE_READ_INTO(&mm, task, mm) || !mm ||
        BPF_CORE_READ_INTO(&executable, mm, exe_file) || !executable)
        return false;
    exact_file_object_from_file(&scratch->file_object, executable);
    scratch->file_object.profile_generation_ref_id =
        rule->executable_object.profile_generation_ref_id;
    return exact_file_keys_equal(&scratch->file_object,
                                 &rule->executable_object);
}

static __always_inline int publish_recovery_provenance(
    const task_label_v1 *label,
    const recovered_container_activation_v1 *recovery, __u8 task_class,
    struct identity_scratch_v1 *scratch)
{
    recovered_task_provenance_v1 *provenance;

    if (!label || !recovery || !scratch || !label->task_cookie)
        return -EACCES;
    provenance = &scratch->recovery_provenance;
    __builtin_memset(provenance, 0, sizeof(*provenance));
    provenance->node_boot_id = recovery->node_boot_id;
    provenance->binding_id = recovery->binding_id;
    provenance->recovery_attempt_id = recovery->recovery_attempt_id;
    provenance->task_cookie = label->task_cookie;
    provenance->class_ = task_class;
    return bpf_map_update_elem(&recovered_task_provenance,
                               &label->task_cookie, provenance,
                               BPF_NOEXIST);
}

static __always_inline void mark_recovery_identity_origin(
    const task_label_v1 *label, __u8 root_class)
{
    process_execution_instance_v1 *execution;
    external_root_classification_v1 *classification;

    if (!label)
        return;
    execution = bpf_map_lookup_elem(&process_execution_instances,
                                    &label->birth_execution_id);
    if (execution) {
        execution->started_by =
            process_execution_started_by_v1_recovery_snapshot;
        execution->transition_version++;
    }
    classification = bpf_map_lookup_elem(&external_root_classifications,
                                         &label->task_cookie);
    if (classification) {
        classification->root_class = root_class;
    }
}

static __always_inline int create_recovered_application_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding,
    recovered_container_activation_v1 *recovery,
    struct identity_scratch_v1 *scratch)
{
    entry_admission_rule_v1 *rule;
    entry_security_state_v1 *entry;
    int result;

    rule = recovery_application_rule(binding, config);
    if (!rule || !recovery_task_executable_matches(task, rule, scratch))
        return -EACCES;
    result = create_root(
        task, config, binding, scratch,
        external_root_class_v1_recovered_application_root,
        installed_role_class_v1_initial_role, rule->target_role_id);
    if (result)
        return result;
    entry = bpf_map_lookup_elem(&entry_states,
                                &scratch->label.entry_instance_id);
    if (!entry || entry->admitted_entry_rule_id ||
        publish_recovery_provenance(
            &scratch->label, recovery,
            recovered_task_class_v1_application, scratch))
        return -EACCES;
    entry->admitted_entry_rule_id = rule->admitted_entry_rule_id;
    entry->transition_version++;
    mark_recovery_identity_origin(
        &scratch->label,
        external_root_class_v1_recovered_application_root);
    recovery->application_entry_instance_id =
        scratch->label.entry_instance_id;
    recovery->transition_version++;
    return finalize_task_coordinate(task, &scratch->label);
}

static __always_inline int create_recovered_external_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding,
    recovered_container_activation_v1 *recovery,
    struct identity_scratch_v1 *scratch)
{
    int result = create_root(
        task, config, binding, scratch,
        external_root_class_v1_restored_or_unknown_root,
        installed_role_class_v1_fail_closed_unknown,
        binding->external_role_id);

    if (result)
        return result;
    if (publish_recovery_provenance(
            &scratch->label, recovery,
            recovered_task_class_v1_external, scratch))
        return -EACCES;
    mark_recovery_identity_origin(
        &scratch->label,
        external_root_class_v1_restored_or_unknown_root);
    return finalize_task_coordinate(task, &scratch->label);
}

static __always_inline int create_recovered_application_process(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding,
    recovered_container_activation_v1 *recovery,
    struct identity_scratch_v1 *scratch)
{
    entry_admission_rule_v1 *rule;
    entry_security_state_v1 *entry;
    process_security_state_v1 *root_process;
    authority_domain_state_v1 *domain;
    __u64 *profile_task_refs;

    rule = recovery_application_rule(binding, config);
    entry = bpf_map_lookup_elem(&entry_states,
                                &recovery->application_entry_instance_id);
    root_process = entry ? bpf_map_lookup_elem(
                               &process_states,
                               &entry->root_process_state_id)
                         : NULL;
    domain = root_process ? bpf_map_lookup_elem(
                                &authority_domains,
                                &root_process->authority_domain_id)
                          : NULL;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &binding->active_profile_generation_ref_id);
    if (!rule || !entry || !root_process || !domain || !profile_task_refs ||
        entry->admitted_entry_rule_id != rule->admitted_entry_rule_id ||
        root_process->active_role_id != rule->target_role_id ||
        root_process->state != process_security_state_kind_v1_active ||
        domain->state != authority_domain_state_kind_v1_active)
        return -EACCES;

    __builtin_memset(&scratch->label, 0, sizeof(scratch->label));
    scratch->label.node_boot_id = config->node_boot_id;
    scratch->label.label_epoch = config->label_epoch;
    if (allocate_id(config, &scratch->label.process_lineage_id) ||
        allocate_id(config, &scratch->label.process_instance_id) ||
        allocate_id(config, &scratch->label.process_state_id) ||
        allocate_id(config, &scratch->label.birth_execution_id) ||
        allocate_id(config, &scratch->image.image_provenance_id))
        return -EACCES;
    scratch->label.task_cookie = scratch->label.birth_execution_id.low;
    scratch->label.entry_instance_id = entry->entry_instance_id;
    scratch->label.execution_set_id = binding->execution_set_id;
    scratch->label.birth_profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->label.birth_authority_domain_id =
        root_process->authority_domain_id;
    scratch->label.lineage_depth = 1;
    scratch->label.ancestor_process_lineage_ids[0] =
        root_process->process_lineage_id;
    scratch->label.placement.protected_root_binding_id =
        binding->binding_id;
    scratch->label.placement.protected_root_binding_nonce =
        binding->binding_nonce;
    prepare_coordinate(&scratch->coordinate, scratch->label.task_cookie,
                       &scratch->label.process_instance_id,
                       &scratch->label.process_state_id);
    prepare_tombstone(&scratch->tombstone, &scratch->label);
    if (read_real_parent_interval(
            task, scratch->label.task_cookie, 0,
            kernel_real_parent_change_reason_v1_recovery_snapshot,
            &scratch->real_parent))
        return -EACCES;
    prepare_task_image(task, scratch, &scratch->image.image_provenance_id);
    prepare_child_process(&scratch->process, root_process,
                          &scratch->label);
    prepare_process_vector(&scratch->process_vector, &scratch->label,
                           binding->active_profile_generation_ref_id, 0);
    prepare_execution(
        &scratch->execution, &scratch->label.birth_execution_id,
        &scratch->label.process_lineage_id,
        &scratch->image.image_provenance_id,
        process_execution_started_by_v1_recovery_snapshot,
        process_execution_state_v1_active);
    if (bpf_map_update_elem(&image_provenance,
                            &scratch->image.image_provenance_id,
                            &scratch->image, BPF_NOEXIST) ||
        bpf_map_update_elem(&process_execution_instances,
                            &scratch->label.birth_execution_id,
                            &scratch->execution, BPF_NOEXIST) ||
        bpf_map_update_elem(&process_state_vectors,
                            &scratch->label.process_state_id,
                            &scratch->process_vector, BPF_NOEXIST) ||
        bpf_map_update_elem(&process_states,
                            &scratch->label.process_state_id,
                            &scratch->process, BPF_NOEXIST) ||
        publish_recovery_provenance(
            &scratch->label, recovery,
            recovered_task_class_v1_application, scratch))
        return -EACCES;
    __sync_fetch_and_add(&entry->live_task_refs, 1);
    __sync_fetch_and_add(&domain->live_process_refs, 1);
    __sync_fetch_and_add(profile_task_refs, 1);
    if (publish_task(task, scratch))
        return -EACCES;
    {
        process_security_state_v1 *installed = bpf_map_lookup_elem(
            &process_states, &scratch->label.process_state_id);
        process_state_vector_v1 *vector = bpf_map_lookup_elem(
            &process_state_vectors, &scratch->label.process_state_id);

        if (!installed || !vector)
            return -EACCES;
        installed->state = process_security_state_kind_v1_active;
        installed->transition_version++;
        vector->state = process_state_vector_state_v1_active;
        vector->transition_version++;
    }
    return finalize_task_coordinate(task, &scratch->label);
}

static __always_inline int create_recovered_thread(
    struct task_struct *task, struct task_struct *leader,
    identity_runtime_config_v1 *config,
    recovered_container_activation_v1 *recovery,
    struct identity_scratch_v1 *scratch)
{
    task_label_v1 *leader_label;
    recovered_task_provenance_v1 *leader_provenance;
    entry_security_state_v1 *entry;
    process_security_state_v1 *process;
    __u64 *profile_task_refs;
    id128_v1 task_id;

    leader_label = bpf_task_storage_get(&task_labels, leader, 0, 0);
    leader_provenance = leader_label ? bpf_map_lookup_elem(
        &recovered_task_provenance, &leader_label->task_cookie) : NULL;
    entry = leader_label ? bpf_map_lookup_elem(
        &entry_states, &leader_label->entry_instance_id) : NULL;
    process = leader_label ? bpf_map_lookup_elem(
        &process_states, &leader_label->process_state_id) : NULL;
    profile_task_refs = leader_label ? bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &leader_label->birth_profile_generation_ref_id) : NULL;
    if (!leader_label || !leader_provenance || !entry || !process ||
        !profile_task_refs ||
        !id128_equal(&leader_provenance->recovery_attempt_id,
                     &recovery->recovery_attempt_id) ||
        allocate_id(config, &task_id))
        return PREPARED_CONTAINER_IDENTITY_DEFER_V1;
    scratch->label = *leader_label;
    scratch->label.task_cookie = task_id.low;
    prepare_coordinate(&scratch->coordinate, scratch->label.task_cookie,
                       &scratch->label.process_instance_id,
                       &scratch->label.process_state_id);
    prepare_tombstone(&scratch->tombstone, &scratch->label);
    if (read_real_parent_interval(
            task, scratch->label.task_cookie, 0,
            kernel_real_parent_change_reason_v1_recovery_snapshot,
            &scratch->real_parent) ||
        publish_recovery_provenance(
            &scratch->label, recovery, leader_provenance->class_, scratch))
        return -EACCES;
    __sync_fetch_and_add(&entry->live_task_refs, 1);
    __sync_fetch_and_add(&process->live_thread_refs, 1);
    __sync_fetch_and_add(profile_task_refs, 1);
    if (publish_task(task, scratch))
        return -EACCES;
    return finalize_task_coordinate(task, &scratch->label);
}

static __always_inline bool recovered_candidate_is_valid(
    const task_label_v1 *label,
    const recovered_container_activation_v1 *recovery,
    const execution_set_binding_state_v1 *binding, __u8 expected_class)
{
    recovered_task_provenance_v1 *provenance;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    external_root_classification_v1 *classification;

    if (!label || !recovery || !binding ||
        !binding_identity_matches_label(binding, label))
        return false;
    provenance = bpf_map_lookup_elem(&recovered_task_provenance,
                                     &label->task_cookie);
    coordinate = bpf_map_lookup_elem(&task_coordinates,
                                     &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states,
                                  &label->process_state_id);
    vector = bpf_map_lookup_elem(&process_state_vectors,
                                 &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states,
                                &label->entry_instance_id);
    domain = process ? bpf_map_lookup_elem(
                           &authority_domains,
                           &process->authority_domain_id)
                     : NULL;
    classification = entry_root_classification(label, entry);
    if (!provenance || !coordinate || !process || !vector || !entry ||
        !domain || !classification ||
        provenance->task_cookie != label->task_cookie ||
        provenance->class_ != expected_class ||
        !id128_equal(&provenance->node_boot_id, &recovery->node_boot_id) ||
        !id128_equal(&provenance->binding_id, &recovery->binding_id) ||
        !id128_equal(&provenance->recovery_attempt_id,
                     &recovery->recovery_attempt_id) ||
        coordinate->state != task_coordinate_state_v1_runnable ||
        process->state != process_security_state_kind_v1_active ||
        process->active_profile_generation_ref_id !=
            recovery->profile_generation_ref_id ||
        vector->state != process_state_vector_state_v1_active ||
        vector->profile_generation_ref_id !=
            recovery->profile_generation_ref_id ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        domain->state != authority_domain_state_kind_v1_active)
        return false;
    if (expected_class == recovered_task_class_v1_application)
        return id128_equal(&label->entry_instance_id,
                           &recovery->application_entry_instance_id) &&
               process->active_role_id == binding->initial_role_id &&
               entry->admitted_entry_rule_id &&
               classification->root_class ==
                   external_root_class_v1_recovered_application_root;
    return process->active_role_id == binding->external_role_id &&
           !entry->admitted_entry_rule_id &&
           classification->root_class ==
               external_root_class_v1_restored_or_unknown_root;
}

static __always_inline int reconcile_recovered_task(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding)
{
    recovered_container_activation_v1 *recovery;
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    struct task_struct *leader = NULL;
    __u32 host_tid = 0;
    __u32 host_tgid = 0;
    __u8 expected_class;
    bool exact_init;
    int relation;
    int claim;
    int result = 0;

    recovery = recovery_for_binding(binding, config);
    if (!recovery)
        return -EACCES;
    BPF_CORE_READ_INTO(&host_tid, task, pid);
    BPF_CORE_READ_INTO(&host_tgid, task, tgid);
    if (!host_tid || !host_tgid)
        return -EACCES;
    exact_init = recovery_task_is_exact_init(task, recovery);
    if (!exact_init &&
        id128_is_zero(&recovery->application_entry_instance_id))
        return PREPARED_CONTAINER_IDENTITY_DEFER_V1;
    leader = runtime_entry_bootstrap_owner(task);
    relation = exact_init
                   ? RECOVERY_RELATION_APPLICATION_V1
                   : recovery_task_relation(
                         host_tid == host_tgid ? task : leader,
                         recovery, binding);
    if (relation == RECOVERY_RELATION_UNRESOLVED_V1) {
        __sync_fetch_and_add(&recovery->invalid_task_count, 1);
        return -EACCES;
    }
    expected_class = relation == RECOVERY_RELATION_APPLICATION_V1
                         ? recovered_task_class_v1_application
                         : recovered_task_class_v1_external;
    if (recovery->phase ==
        recovered_container_activation_phase_v1_scanning)
        __sync_fetch_and_add(&recovery->scan_task_count, 1);
    else if (recovery->phase ==
             recovered_container_activation_phase_v1_validating)
        __sync_fetch_and_add(&recovery->validation_task_count, 1);
    else
        return -EACCES;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (task_label_is_uninitialized(label))
        label = NULL;
    if (!label && recovery->phase ==
                      recovered_container_activation_phase_v1_scanning) {
        scratch = identity_scratch_record();
        if (!scratch)
            return -EACCES;
        claim = claim_task_label(task);
        if (claim < 0)
            return -EACCES;
        if (!claim) {
            if (host_tid != host_tgid) {
                result = create_recovered_thread(
                    task, leader, config, recovery, scratch);
            } else if (exact_init) {
                if (!id128_is_zero(
                        &recovery->application_entry_instance_id))
                    result = -EACCES;
                else
                    result = create_recovered_application_root(
                        task, config, binding, recovery, scratch);
            } else if (expected_class ==
                       recovered_task_class_v1_application) {
                if (id128_is_zero(
                        &recovery->application_entry_instance_id))
                    result = PREPARED_CONTAINER_IDENTITY_DEFER_V1;
                else
                    result = create_recovered_application_process(
                        task, config, binding, recovery, scratch);
            } else {
                result = create_recovered_external_root(
                    task, config, binding, recovery, scratch);
            }
            if (result) {
                bpf_task_storage_delete(&task_labels, task);
                if (result != PREPARED_CONTAINER_IDENTITY_DEFER_V1)
                    __sync_fetch_and_add(
                        &recovery->invalid_task_count, 1);
                return result;
            }
        }
        label = bpf_task_storage_get(&task_labels, task, 0, 0);
    }
    if (!recovered_candidate_is_valid(label, recovery, binding,
                                      expected_class)) {
        __sync_fetch_and_add(&recovery->invalid_task_count, 1);
        return -EACCES;
    }
    if (recovery->phase ==
        recovered_container_activation_phase_v1_scanning) {
        __sync_fetch_and_add(&recovery->scan_candidate_count, 1);
        if (expected_class == recovered_task_class_v1_application)
            __sync_fetch_and_add(
                &recovery->scan_application_task_count, 1);
        else
            __sync_fetch_and_add(
                &recovery->scan_external_task_count, 1);
    } else {
        if (expected_class == recovered_task_class_v1_application)
            __sync_fetch_and_add(
                &recovery->validation_application_task_count, 1);
        else
            __sync_fetch_and_add(
                &recovery->validation_external_task_count, 1);
    }
    return 0;
}

static __always_inline void reset_recovery_scan(
    recovered_container_activation_v1 *recovery)
{
    recovery->scan_generation = recovery->task_set_generation;
    recovery->scan_task_count = 0;
    recovery->scan_candidate_count = 0;
    recovery->scan_application_task_count = 0;
    recovery->scan_external_task_count = 0;
    recovery->validation_task_count = 0;
    recovery->validation_application_task_count = 0;
    recovery->validation_external_task_count = 0;
    recovery->invalid_task_count = 0;
    recovery->phase = recovered_container_activation_phase_v1_scanning;
    recovery->transition_version++;
}

static __noinline int advance_recovered_container_activation(
    const policy_activation_probe_v1 *request,
    const identity_runtime_config_v1 *config)
{
    recovered_container_activation_v1 *recovery;
    execution_set_binding_state_v1 *binding;
    id128_v1 attempt_id;
    __u64 root_cgroup_id = 0;

    if (!request || !config || request->key_size != 24)
        return 4;
    __builtin_memcpy(&root_cgroup_id, request->key,
                     sizeof(root_cgroup_id));
    __builtin_memcpy(&attempt_id,
                     request->key + sizeof(root_cgroup_id),
                     sizeof(attempt_id));
    if (!root_cgroup_id || id128_is_zero(&attempt_id))
        return 4;
    binding = bpf_map_lookup_elem(&execution_set_bindings,
                                  &root_cgroup_id);
    recovery = bpf_map_lookup_elem(&recovered_container_activations,
                                   &root_cgroup_id);
    if (!recovery || !binding ||
        !id128_equal(&recovery->recovery_attempt_id, &attempt_id) ||
        !recovery_record_matches_binding(recovery, binding, config))
        return 12;
    if (recovery->invalid_task_count) {
        reset_recovery_scan(recovery);
        return 13;
    }
    if (recovery->phase ==
        recovered_container_activation_phase_v1_scanning) {
        if (recovery->scan_generation != recovery->task_set_generation ||
            !recovery->scan_task_count ||
            recovery->scan_task_count != recovery->scan_candidate_count ||
            recovery->scan_candidate_count !=
                recovery->scan_application_task_count +
                    recovery->scan_external_task_count ||
            !recovery->scan_application_task_count ||
            id128_is_zero(&recovery->application_entry_instance_id)) {
            reset_recovery_scan(recovery);
            return 13;
        }
        recovery->expected_task_count = recovery->scan_task_count;
        recovery->validation_task_count = 0;
        recovery->validation_application_task_count = 0;
        recovery->validation_external_task_count = 0;
        recovery->invalid_task_count = 0;
        recovery->phase =
            recovered_container_activation_phase_v1_validating;
        recovery->transition_version++;
        return 14;
    }
    if (recovery->phase !=
        recovered_container_activation_phase_v1_validating)
        return 12;
    if (recovery->scan_generation != recovery->task_set_generation ||
        recovery->validation_task_count != recovery->expected_task_count ||
        recovery->validation_task_count !=
            recovery->validation_application_task_count +
                recovery->validation_external_task_count ||
        recovery->validation_application_task_count !=
            recovery->scan_application_task_count ||
        recovery->validation_external_task_count !=
            recovery->scan_external_task_count) {
        reset_recovery_scan(recovery);
        return 13;
    }
    if (__sync_val_compare_and_swap(&recovery->transition_guard, 0, 1))
        return 13;
    if (!recovery_record_matches_binding(recovery, binding, config) ||
        recovery->scan_generation != recovery->task_set_generation ||
        binding->prepared_container_state !=
            prepared_container_state_v1_recovering ||
        !id128_is_zero(&binding->prepared_container_entry_instance_id)) {
        release_transition_guard(&recovery->transition_guard);
        reset_recovery_scan(recovery);
        return 13;
    }
    binding->prepared_container_entry_instance_id =
        recovery->application_entry_instance_id;
    binding->prepared_container_state =
        prepared_container_state_v1_active_recovered;
    binding->transition_version++;
    recovery->expected_binding_transition_version =
        binding->transition_version;
    recovery->phase = recovered_container_activation_phase_v1_complete;
    recovery->transition_version++;
    release_transition_guard(&recovery->transition_guard);
    return 1;
}

static __always_inline void recovered_container_task_set_changed(
    execution_set_binding_state_v1 *binding,
    const identity_runtime_config_v1 *config)
{
    recovered_container_activation_v1 *recovery;

    recovery = recovery_for_binding(binding, config);
    if (!recovery)
        return;
    __sync_fetch_and_add(&recovery->task_set_generation, 1);
    recovery->transition_version++;
}

#endif /* EREBOR_IDENTITY_RECOVERY_BPF_H */
