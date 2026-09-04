/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_EFFECTS_BPF_H
#define EREBOR_IDENTITY_EFFECTS_BPF_H

#define LINUX_CAP_SYS_ADMIN_V1 21

SEC("raw_tracepoint/sys_enter")
int erebor_exception_sys_enter(struct bpf_raw_tracepoint_args *context)
{
    identity_runtime_config_v1 *config = identity_runtime_config();

    (void)context;
    if (!config || !config->enabled)
        return 0;
    activate_prepared_container_for_application(bpf_get_current_task_btf());
    begin_task_effect_syscall(bpf_get_current_task_btf());
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int erebor_exception_sys_exit(struct bpf_raw_tracepoint_args *context)
{
    (void)context;
    finish_task_effect_syscall(bpf_get_current_task_btf());
    return 0;
}

static __always_inline bool pending_contains_candidate(
    const pending_exec_v1 *pending,
    const exact_executable_candidate_v1 *candidate)
{
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++) {
        if (index < pending->candidate_count &&
            candidate_equal(&pending->ordered_candidates[index], candidate))
            return true;
    }
    return false;
}

static __always_inline effect_observation_health_v1 *effect_health_record(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&effect_observation_health, &zero);
}

static __always_inline void begin_effect_observation(
    struct identity_scratch_v1 *scratch, __u16 effect_family, __u16 operation)
{
    __builtin_memset(&scratch->observation, 0, sizeof(scratch->observation));
    scratch->observation.observed_boottime_ns = bpf_ktime_get_ns();
    scratch->observation.effect_family = effect_family;
    scratch->observation.operation = operation;
}

/* The physical result is fixed by the caller before this best-effort copy. */
static __always_inline int emit_effect_observation(
    struct identity_scratch_v1 *scratch, int result, __u8 reason,
    __u8 physical_result)
{
    effect_observation_health_v1 *health = effect_health_record();
    effect_observation_v1 *event;

    if (!health)
        return result;
    health->attempted++;
    health->requested++;
    if (health->next_sequence == ~0ULL) {
        health->lost++;
        return result;
    }
    health->next_sequence++;
    if (!scratch) {
        health->lost++;
        return result;
    }
    scratch->observation.source_sequence = health->next_sequence;
    scratch->observation.source_cpu_id = bpf_get_smp_processor_id();
    scratch->observation.kernel_result = result;
    scratch->observation.reason = reason;
    scratch->observation.physical_result = physical_result;
    event = bpf_ringbuf_reserve(&effect_observations, sizeof(*event), 0);
    if (!event) {
        health->lost++;
        return result;
    }
    __builtin_memcpy(event, &scratch->observation, sizeof(*event));
    bpf_ringbuf_submit(event, 0);
    health->emitted++;
    return result;
}

/* Keep the internal miss in scratch so each LSM result stays valid. */
static __always_inline int prepared_exec_policy_miss(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch)
{
    if (!scratch)
        return identity_deny(config);
    scratch->effect_gate_flags |= EFFECT_GATE_PREPARED_EXEC_POLICY_MISS_V1;
    return 0;
}

static __always_inline int hard_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    __u8 reason)
{
    int result = identity_deny(config);

    if (scratch &&
        scratch->effect_gate_flags &
            EFFECT_GATE_PREPARED_EXEC_EVALUATION_V1 &&
        (reason == effect_observation_reason_v1_unresolved_object ||
         reason == effect_observation_reason_v1_unsupported_object ||
         reason == effect_observation_reason_v1_exception_unavailable))
        return prepared_exec_policy_miss(config, scratch);
    if (reason == effect_observation_reason_v1_unresolved_object ||
        reason == effect_observation_reason_v1_unsupported_object) {
        effect_observation_health_v1 *health = effect_health_record();
        if (health) {
            health->unresolved++;
            health->classifier_miss_count++;
        }
    }
    return emit_effect_observation(
        scratch, result, reason,
        effect_physical_result_v1_denied_before_effect);
}

static __always_inline int prepared_runtime_effect_result(
    struct identity_scratch_v1 *scratch)
{
    return emit_effect_observation(
        scratch, 0,
        effect_observation_reason_v1_prepared_runtime_infrastructure,
        effect_physical_result_v1_unknown_after_pre_effect);
}

static __always_inline int runtime_entry_infrastructure_effect_result(
    struct identity_scratch_v1 *scratch)
{
    return emit_effect_observation(
        scratch, 0,
        effect_observation_reason_v1_runtime_entry_infrastructure,
        effect_physical_result_v1_unknown_after_pre_effect);
}

static __always_inline bool runtime_infrastructure_effect_was_allowed(
    const struct identity_scratch_v1 *scratch)
{
    return scratch &&
           (scratch->observation.reason ==
                effect_observation_reason_v1_prepared_runtime_infrastructure ||
            scratch->observation.reason ==
                effect_observation_reason_v1_runtime_entry_infrastructure);
}

static __always_inline int application_default_effect_result(
    struct identity_scratch_v1 *scratch)
{
    return emit_effect_observation(
        scratch, 0,
        effect_observation_reason_v1_application_default_allow,
        effect_physical_result_v1_unknown_after_pre_effect);
}

static __always_inline bool current_admitted_actor_is_exact(
    execution_set_binding_state_v1 *binding)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_label_v1 *label = task
                               ? bpf_task_storage_get(&task_labels, task, 0, 0)
                               : NULL;
    entry_security_state_v1 *entry = label
                                         ? bpf_map_lookup_elem(
                                               &entry_states,
                                               &label->entry_instance_id)
                                         : NULL;

    return prepared_container_admitted_actor_is_exact(binding, label, entry);
}

static __always_inline int admitted_default_or_hard_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry, __u8 reason)
{
    if (prepared_container_admitted_actor_is_exact(binding, label, entry))
        return application_default_effect_result(scratch);
    return hard_effect_result(config, scratch, reason);
}

static __always_inline bool path_tree_denies(
    const struct identity_scratch_v1 *scratch, __u16 operation)
{
    if (!scratch || operation >= 64)
        return false;
    return scratch->path_tree_deny_operation_mask &
           (1ULL << operation);
}

static __always_inline int path_tree_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch)
{
    int result = identity_deny(config);

    scratch->observation.configured_errno = result;
    return emit_effect_observation(
        scratch, result, effect_observation_reason_v1_path_tree_policy_deny,
        effect_physical_result_v1_denied_before_effect);
}

static __always_inline int identity_or_prior_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    int prior_result, __u8 identity_reason)
{
    if (prior_result)
        return emit_effect_observation(
            scratch, prior_result,
            effect_observation_reason_v1_prior_lsm_denial,
            effect_physical_result_v1_denied_before_effect);
    return hard_effect_result(config, scratch, identity_reason);
}

static __always_inline void populate_effect_actor(
    struct identity_scratch_v1 *scratch, const task_label_v1 *label,
    const process_security_state_v1 *process,
    const entry_security_state_v1 *entry,
    const authority_domain_state_v1 *domain)
{
    scratch->observation.task_cookie = label->task_cookie;
    scratch->observation.profile_generation_ref_id =
        process->active_profile_generation_ref_id;
    scratch->observation.process_lineage_id = process->process_lineage_id;
    scratch->observation.process_instance_id = process->process_instance_id;
    scratch->observation.entry_instance_id = process->entry_instance_id;
    scratch->observation.authority_domain_id = process->authority_domain_id;
    scratch->observation.active_role_id = process->active_role_id;
    scratch->observation.process_state_vector_id =
        process->process_state_vector_id;
    scratch->observation.admitted_entry_rule_id =
        entry->admitted_entry_rule_id;
    if (domain)
        scratch->observation.authority_domain_id = domain->authority_domain_id;
}

static __always_inline physical_decision_v1 *effect_base_decision(
    struct identity_scratch_v1 *scratch,
    const process_security_state_v1 *process,
    const process_state_vector_v1 *process_vector,
    const entry_security_state_v1 *entry,
    const execution_set_binding_state_v1 *binding)
{
    physical_decision_v1 *decision;

    __builtin_memset(&scratch->effect_key, 0, sizeof(scratch->effect_key));
    scratch->effect_key.profile_generation_ref_id =
        process->active_profile_generation_ref_id;
    scratch->effect_key.active_role_id = process->active_role_id;
    scratch->effect_key.effect_family = scratch->observation.effect_family;
    scratch->effect_key.operation = scratch->observation.operation;
    scratch->effect_key.composite_atom_id =
        scratch->observation.composite_atom_id;
    if (scratch->effect_key.effect_family ==
            kernel_effect_family_v1_privilege &&
        scratch->effect_key.operation ==
            kernel_effect_operation_v1_capability)
        scratch->effect_key.composite_atom_id =
            (__u64)scratch->observation.operation_argument + 1;
    scratch->effect_key.exact_object_key_id =
        scratch->observation.exact_object_key_id;
    scratch->effect_key.process_state_vector_id =
        process_vector->process_state_vector_id;
    scratch->effect_key.binding_lifecycle_state = binding->lifecycle_state;
    if (scratch->effect_key.exact_object_key_id) {
        decision = bpf_map_lookup_elem(&effect_decisions,
                                       &scratch->effect_key);
        if (decision)
            return decision;
    }
    __builtin_memset(&scratch->effect_default, 0,
                     sizeof(scratch->effect_default));
    scratch->effect_default.profile_generation_ref_id =
        scratch->effect_key.profile_generation_ref_id;
    scratch->effect_default.active_role_id =
        scratch->effect_key.active_role_id;
    scratch->effect_default.effect_family = scratch->effect_key.effect_family;
    scratch->effect_default.operation = scratch->effect_key.operation;
    scratch->effect_default.composite_atom_id =
        scratch->effect_key.composite_atom_id;
    scratch->effect_default.process_state_vector_id =
        scratch->effect_key.process_state_vector_id;
    scratch->effect_default.binding_lifecycle_state =
        scratch->effect_key.binding_lifecycle_state;
    decision = bpf_map_lookup_elem(&effect_defaults,
                                   &scratch->effect_default);
    if (decision)
        return decision;
    if (scratch->effect_key.effect_family ==
            kernel_effect_family_v1_privilege &&
        scratch->effect_key.operation ==
            kernel_effect_operation_v1_capability) {
        scratch->effect_default.composite_atom_id = 0;
        return bpf_map_lookup_elem(&effect_defaults,
                                   &scratch->effect_default);
    }
    if (scratch->effect_key.effect_family == kernel_effect_family_v1_mount) {
        scratch->effect_default.effect_family =
            kernel_effect_family_v1_privilege;
        scratch->effect_default.operation =
            kernel_effect_operation_v1_capability;
        scratch->effect_default.composite_atom_id =
            LINUX_CAP_SYS_ADMIN_V1 + 1;
        decision = bpf_map_lookup_elem(&effect_defaults,
                                       &scratch->effect_default);
        if (decision)
            return decision;
        scratch->effect_default.composite_atom_id = 0;
        return bpf_map_lookup_elem(&effect_defaults,
                                   &scratch->effect_default);
    }
    return NULL;
}

static __always_inline exact_object_binding_v1 *configured_file_object_binding(
    struct identity_scratch_v1 *scratch)
{
    return bpf_map_lookup_elem(&exact_file_objects, &scratch->file_object);
}

static __noinline void prepare_effect_identity(void)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !config->enabled)
        return;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (label || task_cgroup(task, &cgroup))
        return;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (!binding_lookup && binding)
        label_external_root(task, binding, config);
}

static __always_inline int apply_effect_decision(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const profile_generation_descriptor_v1 *generation,
    const physical_decision_v1 *decision, bool application_default_allow,
    bool allow_exception, bool file_open_attempt)
{
    if (!decision &&
        scratch->effect_gate_flags &
            EFFECT_GATE_PREPARED_EXEC_EVALUATION_V1)
        return prepared_exec_policy_miss(config, scratch);
    if (!decision && application_default_allow)
        return application_default_effect_result(scratch);
    if (!decision)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    scratch->observation.configured_errno = decision->errno;
    if (decision->decision == physical_decision_kind_v1_deny &&
        generation->mode == policy_generation_mode_v1_protect) {
        return emit_effect_observation(
            scratch, identity_errno(decision->errno),
            effect_observation_reason_v1_exact_policy_deny,
            effect_physical_result_v1_denied_before_effect);
    }
    if (decision->decision == physical_decision_kind_v1_deny &&
        generation->mode == policy_generation_mode_v1_observe)
        return emit_effect_observation(
            scratch, 0, effect_observation_reason_v1_would_deny,
            effect_physical_result_v1_unknown_after_pre_effect);
    if (decision->decision == physical_decision_kind_v1_audit_allow &&
        !decision->exception_numeric_handle)
        return emit_effect_observation(
            scratch, 0,
            effect_observation_reason_v1_exact_policy_audit_allow,
            effect_physical_result_v1_unknown_after_pre_effect);
    if (decision->decision == physical_decision_kind_v1_allow) {
        if (decision->exception_numeric_handle) {
            __u64 effect_attempt_sequence = 0;
            int consume_result;
            int finish_result;

            if (!allow_exception || !file_open_attempt ||
                begin_file_open_effect_attempt(
                    scratch->observation.task_cookie,
                    scratch->observation.effect_family,
                    scratch->observation.operation,
                    &effect_attempt_sequence))
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_exception_unavailable);
            consume_result = consume_bounded_exception(
                scratch->observation.profile_generation_ref_id,
                decision->exception_numeric_handle, NULL,
                effect_attempt_sequence, scratch->observation.effect_family,
                scratch->observation.operation);
            finish_result =
                finish_file_open_effect_attempt(effect_attempt_sequence);
            if (consume_result || finish_result)
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_exception_unavailable);
        }
        return emit_effect_observation(
            scratch, 0, effect_observation_reason_v1_exact_policy_allow,
            effect_physical_result_v1_unknown_after_pre_effect);
    }
    return hard_effect_result(
        config, scratch,
        effect_observation_reason_v1_corrupt_identity_or_generation);
}

static __noinline int resolved_identity_effect_gate(struct file *file,
                                                    int ret)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct task_struct *task;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    process_state_vector_v1 *process_vector;
    process_execution_instance_v1 *execution;
    image_provenance_v1 *image;
    execution_set_binding_state_v1 *binding;
    profile_generation_descriptor_v1 *generation;
    exact_object_binding_v1 *object_binding;
    physical_decision_v1 *decision;
    struct identity_scratch_v1 *scratch;
    pending_exec_v1 *pending;
    __u64 *profile_task_refs;
    struct cgroup *cgroup = NULL;
    __u64 path_composite_atom_id = 0;
    bool admitted_exact_object = false;
    int visible_path_result;
    int binding_lookup;

    config = identity_runtime_config();
    if (!config || !config->enabled)
        return ret;
    scratch = identity_scratch_record();
    health = identity_health_record();
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (scratch && label)
        scratch->observation.task_cookie = label->task_cookie;
    if (task_cgroup(task, &cgroup)) {
        if (health)
            health->placement_mismatches++;
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup) {
        if (health)
            health->placement_mismatches++;
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    if (!label) {
        if (binding) {
            if (health)
                health->missing_identity_denials++;
            return identity_or_prior_effect_result(
                config, scratch, ret,
                effect_observation_reason_v1_missing_identity);
        }
        return ret;
    }
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label)) {
        if (health)
            health->placement_mismatches++;
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!coordinate || coordinate->state != task_coordinate_state_v1_runnable ||
        !scratch || refresh_real_parent(task, label, coordinate, scratch) ||
        (config->effect_policy_enabled &&
         migrate_process_generation(config, binding, label, process, scratch)) ||
        snapshot_process_state(process, &scratch->process) ||
        scratch->process.state != process_security_state_kind_v1_active ||
        !scratch->process.live_thread_refs || !entry ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &scratch->process.authority_domain_id);
    execution = bpf_map_lookup_elem(&process_execution_instances,
                                    &scratch->process.active_execution_id);
    image = execution ? bpf_map_lookup_elem(
                            &image_provenance,
                            &execution->image_provenance_id)
                      : NULL;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &scratch->process.active_profile_generation_ref_id);
    process_vector = bpf_map_lookup_elem(&process_state_vectors,
                                         &label->process_state_id);
    if (!id128_equal(&scratch->process.entry_instance_id,
                     &label->entry_instance_id) ||
        !domain || domain->state != authority_domain_state_kind_v1_active ||
        !domain->live_process_refs ||
        domain->label_epoch != config->label_epoch ||
        !id128_equal(&domain->node_boot_id, &config->node_boot_id) ||
        !execution ||
        execution->state != process_execution_state_v1_active ||
        !id128_equal(&execution->process_lineage_id,
                     &scratch->process.process_lineage_id) ||
        !image || image->state != image_provenance_state_v1_active ||
        !process_vector ||
        process_vector->state != process_state_vector_state_v1_active ||
        process_vector->process_state_vector_id !=
            scratch->process.process_state_vector_id ||
        process_vector->profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        process_vector->label_epoch != scratch->process.label_epoch ||
        !id128_equal(&process_vector->node_boot_id,
                     &scratch->process.node_boot_id) ||
        !profile_task_refs)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    populate_effect_actor(scratch, label, &scratch->process, entry, domain);
    scratch->observation.binding_id = binding->binding_id;
    scratch->observation.execution_set_id = binding->execution_set_id;
    if (ret)
        return emit_effect_observation(
            scratch, ret, effect_observation_reason_v1_prior_lsm_denial,
            effect_physical_result_v1_denied_before_effect);
    if (!config->effect_policy_enabled)
        return ret;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    if (!generation_allows_existing_holder(generation) ||
        generation->label_epoch != config->label_epoch ||
        generation->profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    if (scratch->observation.effect_family == kernel_effect_family_v1_exec &&
        scratch->observation.operation ==
            kernel_effect_operation_v1_execute &&
        scratch->effect_gate_flags & EFFECT_GATE_FILE_OPEN_ATTEMPT_V1 &&
        initial_exec_has_provisional_capture())
        return runtime_entry_infrastructure_effect_result(scratch);
    if (!(scratch->effect_gate_flags &
          EFFECT_GATE_PREPARED_EXEC_EVALUATION_V1) &&
        runtime_entry_bootstrap_actor_is_exact(
            config, binding, label, &scratch->process, entry))
        return runtime_entry_infrastructure_effect_result(scratch);
    /* Runtime setup can open anonymous exec objects after bprm state exists.
     * Keep the exact prepared actor outside normal object-policy resolution. */
    if (!(scratch->effect_gate_flags &
          EFFECT_GATE_PREPARED_EXEC_EVALUATION_V1) &&
        prepared_container_pre_active_actor_is_exact(binding, label, entry))
        return prepared_runtime_effect_result(scratch);
    if (file &&
        scratch->observation.effect_family == kernel_effect_family_v1_exec) {
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if (!scratch->image.ordered_candidates[0].mount_id)
            return admitted_default_or_hard_effect_result(
                config, scratch, binding, label, entry,
                effect_observation_reason_v1_unsupported_object);
    }
    if (scratch->process.exec_guard_state != exec_guard_state_v1_none) {
        pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
        if (!pending ||
            (scratch->process.exec_guard_state !=
                 exec_guard_state_v1_preparing &&
             scratch->process.exec_guard_state !=
                 exec_guard_state_v1_commit_pending) ||
            !id128_equal(&pending->process_state_id,
                         &label->process_state_id) ||
            ((scratch->process.exec_guard_state ==
              exec_guard_state_v1_preparing) !=
             (pending->state == pending_exec_state_v1_preparing)) ||
            ((scratch->process.exec_guard_state ==
              exec_guard_state_v1_commit_pending) !=
             (pending->state == pending_exec_state_v1_commit_pending)))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        if (!file && !(scratch->effect_gate_flags &
                       EFFECT_GATE_DEFER_DECISION_V1))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        if (file) {
            candidate_from_file(&scratch->image.ordered_candidates[0], file);
            if (!scratch->image.ordered_candidates[0].mount_id &&
                pending->exact_object_required)
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_unsupported_object);
            if (!scratch->image.ordered_candidates[0].mount_id)
                return admitted_default_or_hard_effect_result(
                    config, scratch, binding, label, entry,
                    effect_observation_reason_v1_unsupported_object);
            if (!pending_contains_candidate(
                    pending, &scratch->image.ordered_candidates[0]) &&
                !(pending->state == pending_exec_state_v1_preparing &&
                  !append_exec_candidate(
                      pending, &scratch->image.ordered_candidates[0])))
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_corrupt_identity_or_generation);
        }
    }
    if (!(scratch->effect_gate_flags & EFFECT_GATE_PATH_SUPPLIED_V1) &&
        file) {
        if (BPF_CORE_READ_INTO(&scratch->effect_path, file, f_path))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_unresolved_object);
        scratch->effect_gate_flags |= EFFECT_GATE_PATH_SUPPLIED_V1;
    }
    if (scratch->effect_gate_flags & EFFECT_GATE_MOUNT_CACHE_FAILED_V1)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);
    if (!(scratch->effect_gate_flags & EFFECT_GATE_PATH_SUPPLIED_V1)) {
        if (scratch->effect_gate_flags & EFFECT_GATE_DEFER_DECISION_V1)
            return 0;
        decision = effect_base_decision(scratch, &scratch->process,
                                        process_vector, entry, binding);
        return apply_effect_decision(config, scratch, generation, decision,
                                     prepared_container_admitted_actor_is_exact(
                                         binding, label, entry),
                                     !(scratch->effect_gate_flags &
                                       EFFECT_GATE_DENY_EXCEPTION_V1),
                                     scratch->effect_gate_flags &
                                         EFFECT_GATE_FILE_OPEN_ATTEMPT_V1);
    }
    /* A create target is an unhashed dentry before the VFS creates it. Its
     * complete path can still match an explicit recursive path rule. */
    if (scratch->observation.operation != kernel_effect_operation_v1_create &&
        path_unlinked(&scratch->effect_path))
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unsupported_object);
    visible_path_result = known_mount_path_candidate(
        &scratch->effect_path, binding,
        scratch->process.active_profile_generation_ref_id,
        scratch->process.active_role_id, scratch, true);
    if (!visible_path_result) {
        if (path_tree_denies(scratch, scratch->observation.operation)) {
            if (generation->mode != policy_generation_mode_v1_protect)
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_corrupt_identity_or_generation);
            return path_tree_effect_result(config, scratch);
        }
        if (scratch->path_terminal.exact_object_required) {
            path_composite_atom_id =
                scratch->path_terminal.composite_atom_id;
            exact_file_object_from_path(&scratch->file_object,
                                        &scratch->effect_path);
            scratch->file_object.profile_generation_ref_id =
                scratch->process.active_profile_generation_ref_id;
            scratch->file_object.mount_id_unique =
                scratch->canonical_mount_root.selected_mount_id_unique;
            object_binding = configured_file_object_binding(scratch);
            if (!object_binding ||
                object_binding->state !=
                    exact_object_binding_state_v1_read_back ||
                object_binding->profile_generation_ref_id !=
                    scratch->process.active_profile_generation_ref_id ||
                object_binding->composite_atom_id != path_composite_atom_id)
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_unresolved_object);
        }
    }
    visible_path_result = known_mount_path_candidate(
        &scratch->effect_path, binding,
        scratch->process.active_profile_generation_ref_id,
        scratch->process.active_role_id, scratch, false);
    if (visible_path_result &&
        scratch->canonical_mount_root.selected_mount_id_unique)
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unresolved_object);
    if (visible_path_result) {
        visible_path_result = container_visible_path_candidate(
            &scratch->effect_path,
            scratch->process.active_profile_generation_ref_id,
            scratch->process.active_role_id, scratch);
        __u8 reason = visible_path_result > 0
                          ? effect_observation_reason_v1_unsupported_object
                          : effect_observation_reason_v1_unresolved_object;

        if (visible_path_result) {
            visible_path_result = canonical_path_candidate(
                &scratch->effect_path, binding,
                scratch->process.active_profile_generation_ref_id,
                scratch->process.active_role_id, scratch, false);
            if (visible_path_result &&
                !scratch->mount_topology_generation)
                return hard_effect_result(
                    config, scratch,
                    effect_observation_reason_v1_unresolved_object);
            if (visible_path_result &&
                !scratch->path_terminal.exact_object_required &&
                !path_tree_denies(scratch,
                                  scratch->observation.operation))
                return admitted_default_or_hard_effect_result(
                    config, scratch, binding, label, entry, reason);
        }
    }
    if (scratch->path_terminal.exact_object_required) {
        path_composite_atom_id = scratch->path_terminal.composite_atom_id;
        exact_file_object_from_path(&scratch->live_file_object,
                                    &scratch->effect_path);
        scratch->live_file_object.profile_generation_ref_id =
            scratch->process.active_profile_generation_ref_id;
        if (!scratch->live_file_object.mount_id_unique &&
            scratch->path_mount_namespace_inode)
            scratch->live_file_object.mount_namespace_inode =
                scratch->path_mount_namespace_inode;
        else
            scratch->path_mount_namespace_inode = 0;
        scratch->observation.file_object = scratch->live_file_object;
        if (!scratch->live_file_object.mount_id_unique &&
            !scratch->live_file_object.mount_namespace_inode)
            return admitted_default_or_hard_effect_result(
                config, scratch, binding, label, entry,
                effect_observation_reason_v1_unsupported_object);
        /* Exact selectors also bind the source-aware mount view. Ordinary
         * path policy remains independent of inode-generation support. */
        scratch->file_object = scratch->live_file_object;
        if (scratch->canonical_mount_root.selected_mount_id_unique) {
            scratch->file_object.mount_id_unique =
                scratch->canonical_mount_root.selected_mount_id_unique;
            object_binding = configured_file_object_binding(scratch);
            admitted_exact_object =
                object_binding &&
                object_binding->state ==
                    exact_object_binding_state_v1_read_back &&
                object_binding->profile_generation_ref_id ==
                    scratch->process.active_profile_generation_ref_id &&
                object_binding->exact_object_key_id &&
                object_binding->composite_atom_id == path_composite_atom_id;
        }
        if (!admitted_exact_object) {
            scratch->file_object = scratch->live_file_object;
        }
        if (!admitted_exact_object && canonical_path_candidate(
                &scratch->effect_path, binding,
                scratch->process.active_profile_generation_ref_id,
                scratch->process.active_role_id, scratch, true)) {
            if (scratch->path_mount_namespace_inode) {
                scratch->path_mount_namespace_inode = 0;
                return admitted_default_or_hard_effect_result(
                    config, scratch, binding, label, entry,
                    effect_observation_reason_v1_unsupported_object);
            }
            return admitted_default_or_hard_effect_result(
                config, scratch, binding, label, entry,
                effect_observation_reason_v1_unresolved_object);
        }
        if (!scratch->path_terminal.exact_object_required ||
            scratch->path_terminal.composite_atom_id !=
                path_composite_atom_id) {
            scratch->path_mount_namespace_inode = 0;
            return admitted_default_or_hard_effect_result(
                config, scratch, binding, label, entry,
                effect_observation_reason_v1_unresolved_object);
        }
        scratch->observation.file_object = scratch->live_file_object;
    }
    scratch->path_mount_namespace_inode = 0;
    scratch->observation.composite_atom_id =
        scratch->path_terminal.composite_atom_id;
    if (path_tree_denies(scratch, scratch->observation.operation)) {
        if (generation->mode != policy_generation_mode_v1_protect)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        return path_tree_effect_result(config, scratch);
    }
    if (!scratch->path_terminal.exact_object_required) {
        if (scratch->effect_gate_flags & EFFECT_GATE_DEFER_DECISION_V1)
            return 0;
        decision = effect_base_decision(scratch, &scratch->process,
                                        process_vector, entry, binding);
        return apply_effect_decision(
            config, scratch, generation, decision,
            prepared_container_admitted_actor_is_exact(binding, label, entry),
            !(scratch->effect_gate_flags & EFFECT_GATE_DENY_EXCEPTION_V1),
            scratch->effect_gate_flags & EFFECT_GATE_FILE_OPEN_ATTEMPT_V1);
    }
    if (!scratch->file_object.inode)
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unsupported_object);
    if (synchronous_mount_snapshot_unchanged(scratch))
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unresolved_object);
    object_binding = configured_file_object_binding(scratch);
    if (!object_binding ||
        object_binding->state != exact_object_binding_state_v1_read_back ||
        object_binding->profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        !object_binding->exact_object_key_id ||
        !object_binding->composite_atom_id ||
        object_binding->composite_atom_id !=
            scratch->path_terminal.composite_atom_id)
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.exact_object_key_id =
        object_binding->exact_object_key_id;
    if (scratch->effect_gate_flags & EFFECT_GATE_DEFER_DECISION_V1)
        return 0;
    decision = effect_base_decision(scratch, &scratch->process,
                                    process_vector, entry, binding);
    if (synchronous_mount_snapshot_unchanged(scratch))
        return admitted_default_or_hard_effect_result(
            config, scratch, binding, label, entry,
            effect_observation_reason_v1_unresolved_object);
    return apply_effect_decision(config, scratch, generation, decision,
                                 prepared_container_admitted_actor_is_exact(
                                     binding, label, entry),
                                 !(scratch->effect_gate_flags &
                                   EFFECT_GATE_DENY_EXCEPTION_V1),
                                 scratch->effect_gate_flags &
                                     EFFECT_GATE_FILE_OPEN_ATTEMPT_V1);
}

static __always_inline int dispatch_identity_effect_gate(
    struct file *file, const struct path *path, __u16 effect_family,
    __u16 operation, int ret)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct identity_scratch_v1 *scratch;
    io_uring_execution_state_v1 *io_uring_execution;

    if (!config || !config->enabled)
        return ret;
    scratch = identity_scratch_record();
    if (scratch) {
        begin_effect_observation(scratch, effect_family, operation);
        scratch->mount_topology_generation = 0;
        __builtin_memset(&scratch->effect_path, 0,
                         sizeof(scratch->effect_path));
        __builtin_memset(&scratch->path_terminal, 0,
                         sizeof(scratch->path_terminal));
        if (path) {
            scratch->effect_gate_flags |= EFFECT_GATE_PATH_SUPPLIED_V1;
            (void)bpf_probe_read_kernel(&scratch->effect_path,
                                        sizeof(scratch->effect_path), path);
        }
        if (file || path) {
            int mount_cache_result =
                prepare_current_task_mount_cache(scratch);

            if (mount_cache_result) {
                scratch->effect_gate_operation_argument =
                    (__u32)-mount_cache_result;
                scratch->effect_gate_flags |=
                    EFFECT_GATE_MOUNT_CACHE_FAILED_V1;
            }
        }
        scratch->observation.operation_argument =
            scratch->effect_gate_operation_argument;
        scratch->effect_gate_operation_argument = 0;
    }
    io_uring_execution = bpf_task_storage_get(
        &io_uring_execution_states, bpf_get_current_task_btf(), 0, 0);
    if (io_uring_execution &&
        io_uring_execution->state !=
            io_uring_execution_state_kind_v1_inactive) {
        if (scratch)
            scratch->effect_gate_flags = 0;
        return resolved_io_uring_effect_gate(
            file, effect_family, operation, ret, scratch);
    }
    return resolved_identity_effect_gate(file, ret);
}

static __always_inline int identity_effect_gate(struct file *file,
                                                __u16 effect_family,
                                                __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = 0;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(file, NULL, effect_family, operation,
                                           ret);
}

static __noinline int prepared_exec_policy_gate(struct file *file)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags =
            EFFECT_GATE_PREPARED_EXEC_EVALUATION_V1 |
            EFFECT_GATE_DENY_EXCEPTION_V1;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    prepare_effect_identity();
    return dispatch_identity_effect_gate(
        file, NULL, kernel_effect_family_v1_exec,
        kernel_effect_operation_v1_execute, 0);
}

static __noinline int identity_effect_gate_without_exception(
    struct file *file, __u16 effect_family, __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = EFFECT_GATE_DENY_EXCEPTION_V1;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(file, NULL, effect_family, operation,
                                           ret);
}

static __noinline int identity_file_open_effect_gate(
    struct file *file, __u16 effect_family, __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = EFFECT_GATE_FILE_OPEN_ATTEMPT_V1;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(file, NULL, effect_family, operation,
                                           ret);
}

static __noinline int identity_effect_actor_gate(
    struct file *file, __u16 effect_family, __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = EFFECT_GATE_DEFER_DECISION_V1;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(file, NULL, effect_family, operation,
                                           ret);
}

static __noinline int identity_path_effect_gate(const struct path *path,
                                                __u16 effect_family,
                                                __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = 0;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(NULL, path, effect_family, operation,
                                           ret);
}

#include "identity_device_process.bpf.h"
#include "identity_ipc.bpf.h"

static __noinline int identity_unqualified_effect_gate(
    __u16 effect_family, __u16 operation, int ret)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    struct task_struct *task;
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding;

    ret = identity_effect_actor_gate(NULL, effect_family, operation, ret);
    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled || !config->effect_policy_enabled)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    scratch = identity_scratch_record();
    if (runtime_infrastructure_effect_was_allowed(scratch))
        return 0;
    if (!current_typed_effect_context(config, scratch, label))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    binding = ipc_current_binding();
    if (binding && current_admitted_actor_is_exact(binding))
        return application_default_effect_result(scratch);
    return hard_effect_result(
        config, scratch, effect_observation_reason_v1_unsupported_object);
}

static __noinline void prepare_path_mount_namespace(
    struct vfsmount *vfsmount, struct identity_scratch_v1 *scratch)
{
    struct mount *mount;
    struct mnt_namespace *mount_namespace = NULL;

    if (!vfsmount || !scratch)
        return;
    mount = mount_from_vfsmount(vfsmount);
    if (BPF_CORE_READ_INTO(&mount_namespace, mount, mnt_ns) ||
        !mount_namespace)
        return;
    (void)BPF_CORE_READ_INTO(&scratch->path_mount_namespace_inode,
                             mount_namespace, ns.inum);
}

static __always_inline int identity_dentry_effect_gate(
    const struct path *dir, struct dentry *dentry, __u16 operation, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    struct path target = {};

    if (scratch) {
        scratch->effect_gate_flags = 0;
        scratch->effect_gate_operation_argument = 0;
        scratch->path_mount_namespace_inode = 0;
    }
    if (!ret)
        prepare_effect_identity();
    if (!dir || !dentry || BPF_CORE_READ_INTO(&target.mnt, dir, mnt))
        return dispatch_identity_effect_gate(
            NULL, NULL, kernel_effect_family_v1_file, operation, ret);
    target.dentry = dentry;
    if (scratch)
        prepare_path_mount_namespace(target.mnt, scratch);
    return dispatch_identity_effect_gate(
        NULL, &target, kernel_effect_family_v1_file, operation, ret);
}

static __always_inline int file_mode_effects(struct file *file,
                                             bool allow_exception, int ret)
{
    fmode_t mode = 0;
    unsigned int flags = 0;

    if (BPF_CORE_READ_INTO(&flags, file, f_flags))
        return allow_exception
                   ? identity_file_open_effect_gate(
                         file, kernel_effect_family_v1_file,
                         kernel_effect_operation_v1_unknown, ret)
                   : identity_effect_gate_without_exception(
                         file, kernel_effect_family_v1_file,
                         kernel_effect_operation_v1_unknown, ret);
    if (flags & __FMODE_EXEC) {
        return allow_exception
                   ? identity_file_open_effect_gate(
                         file, kernel_effect_family_v1_exec,
                         kernel_effect_operation_v1_execute, ret)
                   : identity_effect_gate_without_exception(
                         file, kernel_effect_family_v1_exec,
                         kernel_effect_operation_v1_execute, ret);
    }
    if (BPF_CORE_READ_INTO(&mode, file, f_mode))
        return allow_exception
                   ? identity_file_open_effect_gate(
                         file, kernel_effect_family_v1_file,
                         kernel_effect_operation_v1_unknown, ret)
                   : identity_effect_gate_without_exception(
                         file, kernel_effect_family_v1_file,
                         kernel_effect_operation_v1_unknown, ret);
    if (mode & FMODE_READ)
        ret = allow_exception
                  ? identity_file_open_effect_gate(
                        file, kernel_effect_family_v1_file,
                        kernel_effect_operation_v1_open_read, ret)
                  : identity_effect_gate_without_exception(
                        file, kernel_effect_family_v1_file,
                        kernel_effect_operation_v1_open_read, ret);
    if (ret)
        return ret;
    if (mode & FMODE_WRITE)
        ret = allow_exception
                  ? identity_file_open_effect_gate(
                        file, kernel_effect_family_v1_file,
                        kernel_effect_operation_v1_open_write, ret)
                  : identity_effect_gate_without_exception(
                        file, kernel_effect_family_v1_file,
                        kernel_effect_operation_v1_open_write, ret);
    return ret;
}

static __always_inline bool file_is_socket(struct file *file)
{
    struct inode *inode = NULL;
    umode_t mode = 0;

    return file && !BPF_CORE_READ_INTO(&inode, file, f_inode) && inode &&
           !BPF_CORE_READ_INTO(&mode, inode, i_mode) &&
           (mode & S_IFMT) == S_IFSOCK;
}

SEC("lsm/file_open")
int BPF_PROG(erebor_identity_measure_file_open, struct file *file, int ret)
{
    /* Keep measurement outside the enforcement call stack and preserve the
     * decision from an earlier Linux Security Module. */
    complete_exact_file_measurement(file);
    return ret;
}

SEC("lsm/inode_free_security")
int BPF_PROG(erebor_identity_inode_free_security, struct inode *inode)
{
    retire_exact_inode_generation(inode);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(erebor_identity_file_open, struct file *file, int ret)
{
    return file_mode_effects(file, true, ret);
}

SEC("lsm/file_receive")
int BPF_PROG(erebor_identity_file_receive, struct file *file, int ret)
{
    if (file_is_socket(file))
        return ret;
    return file_mode_effects(file, false, ret);
}

SEC("lsm/file_permission")
int BPF_PROG(erebor_identity_file_permission, struct file *file, int mask,
             int ret)
{
    io_uring_execution_state_v1 *io_uring_execution =
        bpf_task_storage_get(&io_uring_execution_states,
                             bpf_get_current_task_btf(), 0, 0);
    unsigned int flags = 0;

    if ((!io_uring_execution ||
         io_uring_execution->state ==
             io_uring_execution_state_kind_v1_inactive) &&
        file_is_socket(file))
        return ret;
    if (file && !BPF_CORE_READ_INTO(&flags, file, f_flags) &&
        (flags & __FMODE_EXEC)) {
        if (initial_exec_has_provisional_capture())
            return identity_effect_actor_gate(
                NULL, kernel_effect_family_v1_exec,
                kernel_effect_operation_v1_execute, ret);
        return identity_effect_gate(file, kernel_effect_family_v1_exec,
                                    kernel_effect_operation_v1_execute, ret);
    }
    if (mask & MAY_READ)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_read, ret);
    if (ret)
        return ret;
    if (mask & (MAY_WRITE | MAY_APPEND))
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_write, ret);
    if (ret)
        return ret;
    if (mask & MAY_EXEC)
        ret = identity_effect_gate(file, kernel_effect_family_v1_exec,
                                   kernel_effect_operation_v1_execute, ret);
    return ret;
}

SEC("lsm/file_ioctl")
int BPF_PROG(erebor_identity_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
    return identity_device_ioctl_gate(file, cmd, ret);
}

SEC("lsm/mmap_file")
int BPF_PROG(erebor_identity_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags,
             int ret)
{
    int io_uring_result;

    /* Anonymous data mappings are not file effects. Only executable
     * anonymous memory crosses the code-authority boundary here. */
    if (!file || (flags & MAP_ANONYMOUS)) {
        if (!(prot & PROT_EXEC))
            return ret;
        return identity_unqualified_effect_gate(
            kernel_effect_family_v1_exec,
            kernel_effect_operation_v1_mmap_exec, ret);
    }
    io_uring_result =
        io_uring_file_mapping_gate(file, reqprot, prot, flags, ret);
    if (io_uring_result != IO_URING_MAPPING_NOT_APPLICABLE_V1)
        return io_uring_result;
    if (prot & PROT_READ)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_mmap_read,
                                   ret);
    if (ret)
        return ret;
    if (prot & PROT_WRITE)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_mmap_write,
                                   ret);
    if (ret)
        return ret;
    if (prot & PROT_EXEC)
        ret = identity_effect_gate(file, kernel_effect_family_v1_exec,
                                   kernel_effect_operation_v1_mmap_exec,
                                   ret);
    return ret;
}

SEC("lsm/file_mprotect")
int BPF_PROG(erebor_identity_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    struct file *file = NULL;
    unsigned long old_flags = 0;
    bool adds_write;
    bool adds_exec;

    if (!vma || BPF_CORE_READ_INTO(&old_flags, vma, vm_flags))
        return identity_effect_gate(
            NULL, kernel_effect_family_v1_exec,
            kernel_effect_operation_v1_mprotect, ret);
    adds_write = (prot & PROT_WRITE) && !(old_flags & VM_WRITE);
    adds_exec = (prot & PROT_EXEC) && !(old_flags & VM_EXEC);
    if (!adds_write && !adds_exec)
        return ret;
    BPF_CORE_READ_INTO(&file, vma, vm_file);
    if (!file) {
        if (!adds_exec)
            return ret;
        return identity_effect_gate(NULL, kernel_effect_family_v1_exec,
                                    kernel_effect_operation_v1_mprotect,
                                    ret);
    }
    if (adds_write)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_mprotect,
                                   ret);
    if (ret)
        return ret;
    if (adds_exec)
        ret = identity_effect_gate(file, kernel_effect_family_v1_exec,
                                   kernel_effect_operation_v1_mprotect,
                                   ret);
    return ret;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(erebor_identity_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
    return identity_process_control_gate(
        child, kernel_effect_operation_v1_ptrace, mode, ret);
}

SEC("lsm/task_kill")
int BPF_PROG(erebor_identity_task_kill, struct task_struct *task,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    return identity_process_control_gate(
        task, kernel_effect_operation_v1_signal, (__u32)sig, ret);
}

SEC("lsm/path_unlink")
int BPF_PROG(erebor_identity_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return identity_dentry_effect_gate(
        dir, dentry, kernel_effect_operation_v1_unlink, ret);
}

SEC("lsm/path_mknod")
int BPF_PROG(erebor_identity_path_mknod, const struct path *dir,
             struct dentry *dentry, umode_t mode, unsigned int device,
             int ret)
{
    return identity_dentry_effect_gate(
        dir, dentry, kernel_effect_operation_v1_create, ret);
}

SEC("lsm/path_mkdir")
int BPF_PROG(erebor_identity_path_mkdir, const struct path *dir,
             struct dentry *dentry, umode_t mode, int ret)
{
    return identity_dentry_effect_gate(
        dir, dentry, kernel_effect_operation_v1_create, ret);
}

SEC("lsm/path_symlink")
int BPF_PROG(erebor_identity_path_symlink, const struct path *dir,
             struct dentry *dentry, const char *old_name, int ret)
{
    return identity_dentry_effect_gate(
        dir, dentry, kernel_effect_operation_v1_create, ret);
}

SEC("lsm/path_rmdir")
int BPF_PROG(erebor_identity_path_rmdir, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return identity_dentry_effect_gate(
        dir, dentry, kernel_effect_operation_v1_unlink, ret);
}

SEC("lsm/path_chmod")
int BPF_PROG(erebor_identity_path_chmod, const struct path *path,
             umode_t mode, int ret)
{
    return identity_path_effect_gate(path, kernel_effect_family_v1_file,
                                     kernel_effect_operation_v1_setattr, ret);
}

SEC("lsm/path_chown")
int BPF_PROG(erebor_identity_path_chown, const struct path *path,
             unsigned int user, unsigned int group, int ret)
{
    return identity_path_effect_gate(path, kernel_effect_family_v1_file,
                                     kernel_effect_operation_v1_setattr, ret);
}

SEC("lsm/path_truncate")
int BPF_PROG(erebor_identity_path_truncate, const struct path *path, int ret)
{
    return identity_path_effect_gate(path, kernel_effect_family_v1_file,
                                     kernel_effect_operation_v1_setattr, ret);
}

SEC("lsm/file_truncate")
int BPF_PROG(erebor_identity_file_truncate, struct file *file, int ret)
{
    return identity_effect_gate(file, kernel_effect_family_v1_file,
                                kernel_effect_operation_v1_setattr, ret);
}

SEC("lsm/path_link")
int BPF_PROG(erebor_identity_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, int ret)
{
    /* Linux rejects cross-mount links before this hook. */
    ret = identity_dentry_effect_gate(
        new_dir, old_dentry, kernel_effect_operation_v1_link, ret);
    if (ret)
        return ret;
    return identity_dentry_effect_gate(
        new_dir, new_dentry, kernel_effect_operation_v1_link, 0);
}

SEC("lsm/path_rename")
int BPF_PROG(erebor_identity_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    ret = identity_dentry_effect_gate(
        old_dir, old_dentry, kernel_effect_operation_v1_rename, ret);
    if (ret)
        return ret;
    return identity_dentry_effect_gate(
        new_dir, new_dentry, kernel_effect_operation_v1_rename, 0);
}

static __always_inline bool initial_root_is_before_first_exec(void)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    task_label_v1 *label;
    entry_security_state_v1 *entry;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !config->enabled)
        return false;
    task = bpf_get_current_task_btf();
    if (!task || task_cgroup(task, &cgroup))
        return false;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding ||
        binding->lifecycle_state != binding_lifecycle_state_v1_active)
        return false;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return false;
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label))
        return false;
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    return prepared_container_pre_active_actor_is_exact(binding, label, entry);
}

static __always_inline int mount_mutation_effect(__u16 operation, int ret)
{
    /* An explicit mount denial wins before exact CAP_SYS_ADMIN authority. */
    if (!ret)
        prepare_effect_identity();
    if (ret || initial_root_is_before_first_exec())
        return ret;
    ret = identity_effect_gate(NULL, kernel_effect_family_v1_mount, operation,
                               ret);
    if (ret)
        return ret;
    return begin_mount_mutation();
}

SEC("lsm/sb_mount")
int BPF_PROG(erebor_identity_sb_mount, const char *dev_name,
             const struct path *path, const char *type, unsigned long flags,
             void *data, int ret)
{
    return mount_mutation_effect(kernel_effect_operation_v1_mount, ret);
}

SEC("lsm/sb_umount")
int BPF_PROG(erebor_identity_sb_umount, struct vfsmount *mnt, int flags,
             int ret)
{
    return mount_mutation_effect(kernel_effect_operation_v1_unmount, ret);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(erebor_identity_sb_pivotroot, const struct path *old_path,
             const struct path *new_path, int ret)
{
    return mount_mutation_effect(kernel_effect_operation_v1_pivot_root, ret);
}

SEC("lsm/move_mount")
int BPF_PROG(erebor_identity_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    return mount_mutation_effect(kernel_effect_operation_v1_move_mount, ret);
}

SEC("lsm/capable")
int BPF_PROG(erebor_identity_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    (void)cred;
    (void)ns;
    (void)opts;
    if (scratch) {
        scratch->effect_gate_flags = 0;
        scratch->effect_gate_operation_argument = (__u32)cap;
    }
    if (!ret)
        prepare_effect_identity();
    return dispatch_identity_effect_gate(
        NULL, NULL, kernel_effect_family_v1_privilege,
        kernel_effect_operation_v1_capability, ret);
}

SEC("lsm/bpf")
int BPF_PROG(erebor_identity_bpf, int cmd, union bpf_attr *attr,
             unsigned int size, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_privilege,
                                kernel_effect_operation_v1_bpf, ret);
}

#endif /* EREBOR_IDENTITY_EFFECTS_BPF_H */
