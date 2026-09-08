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
           binding->lifecycle_state == binding_lifecycle_state_v1_recovering;
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

static __always_inline __u32 recovery_application_rule_id(
    struct task_struct *task,
    const execution_set_binding_state_v1 *binding,
    const identity_runtime_config_v1 *config,
    struct identity_scratch_v1 *scratch)
{
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;
    struct provisional_exec_request_v1 *request;
    execution_argv_chunk_v1 *first;
    entry_admission_rule_v1 *rule;
    unsigned long start = 0;
    unsigned long end = 0;
    __u64 atom;
    long length;
    int authority;

    if (!task || !scratch ||
        BPF_CORE_READ_INTO(&mm, task, mm) || !mm ||
        BPF_CORE_READ_INTO(&executable, mm, exe_file) || !executable ||
        BPF_CORE_READ_INTO(&start, mm, arg_start) ||
        BPF_CORE_READ_INTO(&end, mm, arg_end))
        return 0;
    request = bpf_task_storage_get(
        &provisional_exec_requests, bpf_get_current_task_btf(), 0,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!request || capture_execution_argv_packed_user(
                        start, end, 0, task, &request->argv_snapshot)) {
        clear_provisional_exec_request(bpf_get_current_task_btf());
        return 0;
    }
    scratch = identity_scratch_record();
    if (!scratch) {
        clear_provisional_exec_request(bpf_get_current_task_btf());
        return 0;
    }
    scratch->exec_argv_chunk_key.snapshot_id = request->argv_snapshot.snapshot_id;
    scratch->exec_argv_chunk_key.chunk_index = 0;
    scratch->exec_argv_chunk_key.reserved = 0;
    first = bpf_map_lookup_elem(&execution_argv_provisional_chunks,
                                &scratch->exec_argv_chunk_key);
    if (!first) {
        clear_provisional_exec_request(bpf_get_current_task_btf());
        return 0;
    }
    length = bpf_probe_read_kernel_str(
        scratch->exec_argument, sizeof(scratch->exec_argument), first->bytes);
    if (length <= 1 || length > EXECUTION_ARGV_CHUNK_BYTES_V1 ||
        first->bytes[((__u32)length - 1) &
                     (EXECUTION_ARGV_CHUNK_BYTES_V1 - 1)]) {
        clear_provisional_exec_request(bpf_get_current_task_btf());
        return 0;
    }
    request->declared_entry.path_length = 0;
    record_declared_exec_request(request, scratch, length);
    atom = logical_exec_request_atom(&request->declared_entry,
                                     binding->active_profile_generation_ref_id,
                                     scratch);
    clear_provisional_exec_request(bpf_get_current_task_btf());
    if (!atom || !recovery_for_binding(binding, config))
        return 0;
    exact_file_object_from_file(&scratch->file_object, executable);
    scratch->file_object.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->entry_admission_key.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    scratch->entry_admission_key.binding_id = binding->binding_id;
    scratch->entry_admission_key.composite_atom_id =
        atom;
    scratch->entry_admission_key.reserved = 0;
    scratch->entry_admission_key.source_role_id =
        binding->initial_role_id;
    authority = normal_entry_authority(binding, config, scratch);
    if (authority != 1)
        return 0;
    rule = bpf_map_lookup_elem(
        &entry_admission_rules, &scratch->entry_admission_key);
    if (!rule || rule->target_role_id != binding->initial_role_id ||
        rule->target_process_state_vector_id !=
            CONSERVATIVE_PROCESS_STATE_VECTOR_V1)
        return 0;
    return rule->admitted_entry_rule_id;
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

static __always_inline bool recovery_preliminary_identity_is_restricted(
    const task_label_v1 *label,
    execution_set_binding_state_v1 *binding,
    const recovered_container_activation_v1 *recovery)
{
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;

    if (!label || !binding || !recovery ||
        !binding_matches_label(binding, label) ||
        bpf_map_lookup_elem(&pending_execs, &label->task_cookie) ||
        bpf_map_lookup_elem(&pending_execution_approvals,
                            &label->task_cookie))
        return false;
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
    return coordinate && process && vector && entry && domain &&
           coordinate->state == task_coordinate_state_v1_runnable &&
           process->state == process_security_state_kind_v1_active &&
           process->exec_guard_state == exec_guard_state_v1_none &&
           (process->active_role_id == binding->external_role_id ||
            (process->active_role_id == binding->initial_role_id &&
             id128_equal(&process->entry_instance_id,
                         &recovery->application_entry_instance_id))) &&
           vector->state == process_state_vector_state_v1_active &&
           vector->profile_generation_ref_id ==
               recovery->profile_generation_ref_id &&
           entry->admission_state == entry_admission_state_v1_committed &&
           entry->lifetime_state == entry_lifetime_state_v1_active &&
           !entry->admitted_entry_rule_id &&
           domain->state == authority_domain_state_kind_v1_active;
}

static __always_inline int adopt_recovered_application_identity(
    task_label_v1 *label, execution_set_binding_state_v1 *binding,
    recovered_container_activation_v1 *recovery,
    entry_security_state_v1 *application_entry,
    struct identity_scratch_v1 *scratch, bool exact_init)
{
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    entry_security_state_v1 *old_entry;
    external_root_classification_v1 *classification = NULL;

    if (!recovery_preliminary_identity_is_restricted(
            label, binding, recovery))
        return -EACCES;
    process = bpf_map_lookup_elem(&process_states,
                                  &label->process_state_id);
    vector = bpf_map_lookup_elem(&process_state_vectors,
                                 &label->process_state_id);
    old_entry = bpf_map_lookup_elem(&entry_states,
                                    &label->entry_instance_id);
    if (!process || !vector || !old_entry ||
        (exact_init &&
         !(classification = bpf_map_lookup_elem(
               &external_root_classifications,
               &label->task_cookie))) ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return -EACCES;
    if (publish_recovery_provenance(
            label, recovery, recovered_task_class_v1_application,
            scratch)) {
        release_transition_guard(&process->transition_guard);
        return -EACCES;
    }
    __sync_fetch_and_add(&application_entry->live_task_refs, 1);
    if (!decrement_nonzero_counter(&old_entry->live_task_refs)) {
        release_transition_guard(&process->transition_guard);
        return -EACCES;
    }
    if (!old_entry->live_task_refs &&
        old_entry->lifetime_state == entry_lifetime_state_v1_active) {
        old_entry->lifetime_state = entry_lifetime_state_v1_draining;
        old_entry->transition_version++;
    }
    label->entry_instance_id = application_entry->entry_instance_id;
    process->entry_instance_id = application_entry->entry_instance_id;
    process->entry_root_process_state_id =
        application_entry->root_process_state_id;
    process->active_role_id = binding->initial_role_id;
    process->process_state_vector_id =
        CONSERVATIVE_PROCESS_STATE_VECTOR_V1;
    process->transition_version++;
    vector->process_state_vector_id = process->process_state_vector_id;
    vector->transition_version++;
    if (exact_init) {
        classification->entry_instance_id =
            application_entry->entry_instance_id;
        classification->installed_role_numeric_id =
            binding->initial_role_id;
        classification->installed_role_class =
            installed_role_class_v1_initial_role;
        classification->root_class =
            external_root_class_v1_recovered_application_root;
    }
    release_transition_guard(&process->transition_guard);
    return 0;
}

static __always_inline int adopt_recovered_application_root(
    struct task_struct *task, identity_runtime_config_v1 *config,
    execution_set_binding_state_v1 *binding,
    recovered_container_activation_v1 *recovery,
    task_label_v1 *label, struct identity_scratch_v1 *scratch)
{
    entry_security_state_v1 *old_entry;
    id128_v1 entry_instance_id;
    __u32 admitted_entry_rule_id;

    if (!id128_is_zero(&recovery->application_entry_instance_id))
        return -EACCES;
    admitted_entry_rule_id = recovery_application_rule_id(
        task, binding, config, scratch);
    scratch = identity_scratch_record();
    old_entry = label ? bpf_map_lookup_elem(
                            &entry_states, &label->entry_instance_id)
                      : NULL;
    if (!admitted_entry_rule_id || !scratch || !old_entry ||
        !recovery_preliminary_identity_is_restricted(
            label, binding, recovery) ||
        allocate_id(config, &entry_instance_id))
        return -EACCES;
    scratch->entry = *old_entry;
    scratch->entry.entry_instance_id = entry_instance_id;
    scratch->entry.live_task_refs = 0;
    scratch->entry.transition_version++;
    scratch->entry.admitted_entry_rule_id = admitted_entry_rule_id;
    if (bpf_map_update_elem(&entry_states,
                            &scratch->entry.entry_instance_id,
                            &scratch->entry, BPF_NOEXIST))
        return -EACCES;
    entry_security_state_v1 *entry = bpf_map_lookup_elem(
        &entry_states, &scratch->entry.entry_instance_id);

    if (!entry || adopt_recovered_application_identity(
                      label, binding, recovery, entry, scratch, true))
        return -EACCES;
    recovery->application_entry_instance_id = entry->entry_instance_id;
    recovery->transition_version++;
    return 0;
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
        !binding_matches_label(binding, label))
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
        if (label_restored_root(task, binding, config)) {
            __sync_fetch_and_add(&recovery->invalid_task_count, 1);
            return -EACCES;
        }
        label = bpf_task_storage_get(&task_labels, task, 0, 0);
    }
    if (label && recovery->phase ==
                     recovered_container_activation_phase_v1_scanning &&
        !recovered_candidate_is_valid(label, recovery, binding,
                                      expected_class)) {
        scratch = identity_scratch_record();
        if (!scratch)
            return -EACCES;
        if (expected_class == recovered_task_class_v1_application) {
            entry_security_state_v1 *application_entry =
                bpf_map_lookup_elem(
                    &entry_states,
                    &recovery->application_entry_instance_id);

            result = exact_init
                         ? adopt_recovered_application_root(
                               task, config, binding, recovery, label,
                               scratch)
                         : (application_entry
                                ? adopt_recovered_application_identity(
                                      label, binding, recovery,
                                      application_entry, scratch, false)
                                : PREPARED_CONTAINER_IDENTITY_DEFER_V1);
        } else if (recovery_preliminary_identity_is_restricted(
                       label, binding, recovery)) {
            result = publish_recovery_provenance(
                label, recovery, recovered_task_class_v1_external,
                scratch);
        } else {
            result = -EACCES;
        }
        if (result) {
            if (result != PREPARED_CONTAINER_IDENTITY_DEFER_V1)
                __sync_fetch_and_add(&recovery->invalid_task_count, 1);
            return result;
        }
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

SEC("iter.s/task")
int erebor_reconcile_recovering_tasks(struct bpf_iter__task *context)
{
    struct task_struct *task = context->task;
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct cgroup *cgroup = NULL;
    execution_set_binding_state_v1 *binding;
    identity_health_v1 *health;
    int lookup;
    int result;

    if (!task || !config || !config->enabled || task_cgroup(task, &cgroup))
        return 0;
    binding = binding_for_cgroup(cgroup, &lookup);
    if (lookup || !binding || binding->lifecycle_state !=
                                binding_lifecycle_state_v1_recovering)
        return 0;
    result = reconcile_recovered_task(task, config, binding);
    if (result && result != PREPARED_CONTAINER_IDENTITY_DEFER_V1) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
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
    if (__sync_val_compare_and_swap(&binding->transition_guard, 0, 1))
        return 13;
    if (recovery->scan_generation != recovery->task_set_generation ||
        recovery->validation_task_count != recovery->expected_task_count ||
        recovery->validation_task_count !=
            recovery->validation_application_task_count +
                recovery->validation_external_task_count ||
        recovery->validation_application_task_count !=
            recovery->scan_application_task_count ||
        recovery->validation_external_task_count !=
            recovery->scan_external_task_count) {
        goto retry;
    }
    if (!recovery_record_matches_binding(recovery, binding, config) ||
        recovery->scan_generation != recovery->task_set_generation ||
        binding->lifecycle_state != binding_lifecycle_state_v1_recovering ||
        !id128_is_zero(&binding->prepared_container_entry_instance_id)) {
        goto retry;
    }
    binding->prepared_container_entry_instance_id =
        recovery->application_entry_instance_id;
    binding->lifecycle_state = binding_lifecycle_state_v1_active_recovered;
    binding->transition_version++;
    recovery->expected_binding_transition_version =
        binding->transition_version;
    recovery->phase = recovered_container_activation_phase_v1_complete;
    recovery->transition_version++;
    release_transition_guard(&binding->transition_guard);
    return 1;

retry:
    reset_recovery_scan(recovery);
    release_transition_guard(&binding->transition_guard);
    return 13;
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
