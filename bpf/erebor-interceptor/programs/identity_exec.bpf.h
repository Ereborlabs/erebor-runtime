/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_EXEC_BPF_H
#define EREBOR_IDENTITY_EXEC_BPF_H

static __always_inline void candidate_from_bprm(
    exact_executable_candidate_v1 *candidate, struct linux_binprm *bprm)
{
    struct file *file = NULL;

    BPF_CORE_READ_INTO(&file, bprm, file);
    candidate_from_file(candidate, file);
}

static __always_inline bool candidate_equal(
    const exact_executable_candidate_v1 *left,
    const exact_executable_candidate_v1 *right)
{
    return left->mount_namespace_inode == right->mount_namespace_inode &&
           left->mount_id == right->mount_id &&
           left->filesystem_device == right->filesystem_device &&
           left->inode == right->inode &&
           left->inode_generation == right->inode_generation;
}

static __always_inline bool image_contains_candidate(
    const image_provenance_v1 *image,
    const exact_executable_candidate_v1 *candidate)
{
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++) {
        if (index < image->candidate_count &&
            candidate_equal(&image->ordered_candidates[index], candidate))
            return true;
    }
    return false;
}

static __always_inline int append_exec_candidate(
    pending_exec_v1 *pending,
    const exact_executable_candidate_v1 *candidate)
{
    if (!candidate->mount_id)
        return -EACCES;
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++) {
        if (index < pending->candidate_count &&
            candidate_equal(&pending->ordered_candidates[index], candidate))
            return 0;
    }
    if (pending->candidate_count >= MAX_EXEC_CANDIDATES_V1)
        return -EACCES;
    pending->ordered_candidates[pending->candidate_count] = *candidate;
    pending->candidate_count++;
    pending->transition_version++;
    return 0;
}

static __always_inline int append_bprm_auxiliary_candidates(
    struct linux_binprm *bprm, pending_exec_v1 *pending,
    struct identity_scratch_v1 *scratch)
{
    struct file *file = NULL;

    BPF_CORE_READ_INTO(&file, bprm, executable);
    if (file) {
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if (append_exec_candidate(
                pending, &scratch->image.ordered_candidates[0]))
            return -EACCES;
    }
    file = NULL;
    BPF_CORE_READ_INTO(&file, bprm, interpreter);
    if (file) {
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if (append_exec_candidate(
                pending, &scratch->image.ordered_candidates[0]))
            return -EACCES;
    }
    return 0;
}

static __always_inline bool administrative_slot_matches_binding(
    approved_exec_slot_v1 *slot,
    const execution_set_binding_state_v1 *binding)
{
    bool body_digest_present = false;
    __u64 now = bpf_ktime_get_ns();

    if (slot) {
#pragma unroll
        for (int index = 0; index < 32; index++)
            body_digest_present |= slot->authorization_body_sha256[index] != 0;
        if (slot->state == approved_exec_slot_state_v1_armed &&
            now > slot->deadline_boottime_ns &&
            __sync_val_compare_and_swap(
                &slot->state, approved_exec_slot_state_v1_armed,
                approved_exec_slot_state_v1_expired) ==
                approved_exec_slot_state_v1_armed)
            __sync_fetch_and_add(&slot->transition_version, 1);
    }
    return slot && binding &&
           slot->state == approved_exec_slot_state_v1_armed &&
           !id128_is_zero(&slot->proof_id) &&
           !id128_is_zero(&slot->claim_slot_id) &&
           body_digest_present &&
           slot->container_generation == binding->container_generation &&
           slot->profile_generation_ref_id ==
               binding->active_profile_generation_ref_id &&
           slot->approved_role_numeric_id &&
           slot->resolved_executable.mount_namespace_inode &&
           slot->resolved_executable.mount_id &&
           slot->resolved_executable.filesystem_device &&
           slot->resolved_executable.inode &&
           slot->resolved_executable.inode_generation &&
           slot->expected_root_class ==
               external_root_class_v1_external_runtime_root &&
           id128_equal(&slot->cgroup_binding_nonce,
                       &binding->binding_nonce) &&
           slot->transition_version &&
           now <= slot->deadline_boottime_ns;
}

static __always_inline int administrative_argv_matches(
    const bounded_administrative_argv_v1 *expected,
    const char *const *argv, struct identity_scratch_v1 *scratch)
{
    __u32 aggregate = 0;
    const char *argument = NULL;
    long length;

    if (!argv || !expected->argument_count ||
        expected->argument_count > MAX_ADMINISTRATIVE_ARGUMENTS_V1 ||
        !expected->total_argument_bytes ||
        expected->total_argument_bytes >
            MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1)
        return -EACCES;
    for (__u32 argument_index = 0;
         argument_index < MAX_ADMINISTRATIVE_ARGUMENTS_V1;
         argument_index++) {
        __u32 expected_length;

        if (argument_index >= expected->argument_count)
            break;
        if (bpf_probe_read_user(&argument, sizeof(argument),
                                &argv[argument_index]) || !argument)
            return -EACCES;
        expected_length = expected->argument_lengths[argument_index];
        if (expected_length > MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 ||
            aggregate + expected_length > expected->total_argument_bytes)
            return -EACCES;
        length = bpf_probe_read_user_str(
            scratch->administrative_argument,
            sizeof(scratch->administrative_argument), argument);
        if (length != expected_length + 1)
            return -EACCES;
        for (__u32 byte_index = 0;
             byte_index < MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1;
             byte_index++) {
            __u32 expected_index;

            if (byte_index >= expected_length)
                break;
            expected_index = aggregate + byte_index;
            if (expected_index >= MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 ||
                scratch->administrative_argument[byte_index] !=
                    expected->argument_bytes[expected_index])
                return -EACCES;
        }
        aggregate += expected_length;
    }
    if (aggregate != expected->total_argument_bytes ||
        bpf_probe_read_user(&argument, sizeof(argument),
                            &argv[expected->argument_count]) ||
        argument)
        return -EACCES;
    return 0;
}

static __always_inline bool task_has_exclusive_mm(struct task_struct *task)
{
    struct mm_struct *mm = NULL;
    int users = 0;

    if (!task || BPF_CORE_READ_INTO(&mm, task, mm) || !mm ||
        BPF_CORE_READ_INTO(&users, mm, mm_users.counter))
        return false;
    return users == 1;
}

static __always_inline int prepare_administrative_match(
    const char *const *argv)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    process_security_state_v1 *process;
    execution_set_binding_state_v1 *binding;
    external_root_classification_v1 *classification;
    approved_exec_slot_key_v1 key;
    approved_exec_slot_v1 *slot;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !config->enabled)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    bpf_map_delete_elem(&pending_administrative_matches,
                        &label->task_cookie);
    if (task_cgroup(task, &cgroup))
        return 0;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    classification = bpf_map_lookup_elem(&external_root_classifications,
                                         &label->task_cookie);
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label) || !process ||
        process->state != process_security_state_kind_v1_active ||
        process->transition_guard ||
        process->exec_guard_state != exec_guard_state_v1_none ||
        process->live_thread_refs != 1 || !task_has_exclusive_mm(task) ||
        !classification ||
        classification->root_class !=
            external_root_class_v1_external_runtime_root ||
        classification->purpose != entry_purpose_v1_unknown ||
        classification->installed_role_class !=
            installed_role_class_v1_runtime_external_restricted ||
        classification->installed_role_numeric_id != process->active_role_id)
        return 0;
    key.node_boot_id = config->node_boot_id;
    key.cgroup_binding_id = binding->binding_id;
    slot = bpf_map_lookup_elem(&approved_exec_slots, &key);
    scratch = identity_scratch_record();
    if (!scratch || !administrative_slot_matches_binding(slot, binding) ||
        administrative_argv_matches(&slot->expected_argv, argv, scratch))
        return 0;
    scratch->administrative_match.task_cookie = label->task_cookie;
    scratch->administrative_match.exec_attempt_sequence =
        process->transition_version + 1;
    scratch->administrative_match.proof_id = slot->proof_id;
    scratch->administrative_match.claim_slot_id = slot->claim_slot_id;
    scratch->administrative_match.approved_role_numeric_id =
        slot->approved_role_numeric_id;
    scratch->administrative_match.reserved_0 = 0;
    scratch->administrative_match.profile_generation_ref_id =
        slot->profile_generation_ref_id;
    scratch->administrative_match.resolved_executable =
        slot->resolved_executable;
    scratch->administrative_match.transition_version = 1;
    scratch->administrative_match.state =
        pending_administrative_match_state_v1_arguments_matched;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->administrative_match.reserved_1[index] = 0;
    bpf_map_update_elem(&pending_administrative_matches,
                        &label->task_cookie,
                        &scratch->administrative_match, BPF_NOEXIST);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int erebor_sys_enter_execve(struct trace_event_raw_sys_enter *context)
{
    return prepare_administrative_match(
        (const char *const *)context->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int erebor_sys_enter_execveat(struct trace_event_raw_sys_enter *context)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    task_label_v1 *label;

    if (context->args[4] & AT_EXECVE_CHECK) {
        process_security_state_v1 *process;

        if (!config || !config->enabled)
            return 0;
        task = bpf_get_current_task_btf();
        label = bpf_task_storage_get(&task_labels, task, 0, 0);
        if (!label)
            return 0;
        process = bpf_map_lookup_elem(&process_states,
                                      &label->process_state_id);
        if (process)
            __sync_val_compare_and_swap(&process->exec_check_task_cookie, 0,
                                        label->task_cookie);
        return 0;
    }
    return prepare_administrative_match(
        (const char *const *)context->args[2]);
}

static __always_inline void consume_administrative_match(
    identity_runtime_config_v1 *config, const task_label_v1 *label,
    execution_set_binding_state_v1 *binding,
    process_security_state_v1 *process, const pending_exec_v1 *pending)
{
    pending_administrative_match_v1 *match = bpf_map_lookup_elem(
        &pending_administrative_matches, &label->task_cookie);
    approved_exec_slot_key_v1 key;
    approved_exec_slot_v1 *slot;

    if (!match)
        return;
    if (match->state !=
            pending_administrative_match_state_v1_arguments_matched ||
        match->exec_attempt_sequence != pending->exec_attempt_sequence ||
        match->profile_generation_ref_id !=
            process->active_profile_generation_ref_id ||
        !candidate_equal(&match->resolved_executable,
                         &pending->ordered_candidates[0]))
        goto reject;
    key.node_boot_id = config->node_boot_id;
    key.cgroup_binding_id = binding->binding_id;
    slot = bpf_map_lookup_elem(&approved_exec_slots, &key);
    if (!administrative_slot_matches_binding(slot, binding) ||
        !id128_equal(&slot->proof_id, &match->proof_id) ||
        !id128_equal(&slot->claim_slot_id, &match->claim_slot_id) ||
        !candidate_equal(&slot->resolved_executable,
                         &match->resolved_executable) ||
        __sync_val_compare_and_swap(
            &slot->state, approved_exec_slot_state_v1_armed,
            approved_exec_slot_state_v1_consumed) !=
            approved_exec_slot_state_v1_armed)
        goto reject;
    slot->transition_version++;
    match->state = pending_administrative_match_state_v1_slot_consumed;
    match->transition_version++;
    process->pending_target_role_id = match->approved_role_numeric_id;
    return;

reject:
    bpf_map_delete_elem(&pending_administrative_matches,
                        &label->task_cookie);
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
    process_security_state_v1 *snapshot;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    process_execution_instance_v1 *active_execution;
    image_provenance_v1 *active_image;
    process_state_vector_v1 *process_vector;
    execution_set_binding_state_v1 *binding;
    pending_exec_v1 *pending;
    __u64 *profile_task_refs;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    health = identity_health_record();
    if (task_cgroup(task, &cgroup)) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
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
    scratch = identity_scratch_record();
    if (!scratch || refresh_real_parent(task, label, coordinate, scratch))
        return identity_deny(config);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    snapshot = scratch ? &scratch->process : NULL;
    if (snapshot_process_state(process, snapshot) ||
        snapshot->state != process_security_state_kind_v1_active ||
        !snapshot->live_thread_refs ||
        !entry || entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs)
        return identity_deny(config);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &snapshot->authority_domain_id);
    if (!domain || domain->state != authority_domain_state_kind_v1_active ||
        !domain->live_process_refs ||
        domain->label_epoch != config->label_epoch ||
        !id128_equal(&domain->node_boot_id, &config->node_boot_id))
        return identity_deny(config);
    active_execution = bpf_map_lookup_elem(
        &process_execution_instances, &snapshot->active_execution_id);
    active_image = active_execution
                       ? bpf_map_lookup_elem(
                             &image_provenance,
                             &active_execution->image_provenance_id)
                       : NULL;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &snapshot->active_profile_generation_ref_id);
    process_vector = bpf_map_lookup_elem(&process_state_vectors,
                                         &label->process_state_id);
    if (!active_execution ||
        active_execution->state != process_execution_state_v1_active ||
        !id128_equal(&active_execution->process_lineage_id,
                     &snapshot->process_lineage_id) ||
        !active_image || active_image->state != image_provenance_state_v1_active ||
        !process_vector ||
        process_vector->state != process_state_vector_state_v1_active ||
        process_vector->process_state_vector_id !=
            snapshot->process_state_vector_id ||
        process_vector->profile_generation_ref_id !=
            snapshot->active_profile_generation_ref_id ||
        !profile_task_refs ||
        __sync_fetch_and_add(profile_task_refs, 0) == 0)
        return identity_deny(config);
    if (snapshot->exec_check_task_cookie)
        return snapshot->exec_check_task_cookie == label->task_cookie
                   ? 0
                   : identity_deny(config);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!pending) {
        if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
            if (health)
                health->exec_guard_denials++;
            return identity_deny(config);
        }
        if (process->transition_version != snapshot->transition_version ||
            process->exec_guard_state != exec_guard_state_v1_none ||
            process->state != process_security_state_kind_v1_active) {
            release_transition_guard(&process->transition_guard);
            if (health)
                health->exec_guard_denials++;
            return identity_deny(config);
        }
        if (allocate_id(config, &scratch->pending_exec.pending_exec_id) ||
            allocate_id(config, &scratch->pending_exec.target_execution_id) ||
            allocate_id(config,
                        &scratch->pending_exec.target_image_provenance_id)) {
            release_transition_guard(&process->transition_guard);
            return identity_deny(config);
        }
        scratch->pending_exec.task_cookie = label->task_cookie;
        scratch->pending_exec.process_state_id = label->process_state_id;
        scratch->pending_exec.exec_attempt_sequence = snapshot->transition_version + 1;
        scratch->pending_exec.source_execution_id = snapshot->active_execution_id;
        scratch->pending_exec.source_role_id = snapshot->active_role_id;
        scratch->pending_exec.candidate_count = 1;
        scratch->pending_exec.reserved_0 = 0;
        scratch->pending_exec.source_profile_generation_ref_id =
            snapshot->active_profile_generation_ref_id;
        scratch->pending_exec.pending_exec_response_set_ref_id =
            snapshot->effective_response_set_ref_id;
        candidate_from_bprm(&scratch->pending_exec.ordered_candidates[0], bprm);
        if (!scratch->pending_exec.ordered_candidates[0].mount_id) {
            release_transition_guard(&process->transition_guard);
            return identity_deny(config);
        }
#pragma unroll
        for (int candidate = 1; candidate < MAX_EXEC_CANDIDATES_V1; candidate++) {
            scratch->pending_exec.ordered_candidates[candidate]
                .mount_namespace_inode = 0;
            scratch->pending_exec.ordered_candidates[candidate].mount_id = 0;
            scratch->pending_exec.ordered_candidates[candidate]
                .filesystem_device = 0;
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
            release_transition_guard(&process->transition_guard);
            return identity_deny(config);
        }
        process->pending_exec_id = scratch->pending_exec.pending_exec_id;
        process->pending_target_execution_id =
            scratch->pending_exec.target_execution_id;
        process->pending_target_role_id = snapshot->active_role_id;
        process->pending_exec_response_set_ref_id =
            snapshot->effective_response_set_ref_id;
        process->exec_guard_state = exec_guard_state_v1_preparing;
        process->transition_version++;
        consume_administrative_match(config, label, binding, process,
                                     &scratch->pending_exec);
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    if (!id128_equal(&pending->process_state_id, &label->process_state_id) ||
        pending->state != pending_exec_state_v1_preparing ||
        snapshot->exec_guard_state != exec_guard_state_v1_preparing)
        return identity_deny(config);
    candidate_from_bprm(&scratch->image.ordered_candidates[0], bprm);
    if (append_exec_candidate(pending,
                              &scratch->image.ordered_candidates[0]))
        return identity_deny(config);
    return 0;
}

static __always_inline int prepare_exec_records(
    struct identity_scratch_v1 *scratch, const pending_exec_v1 *pending,
    const process_security_state_v1 *process)
{
    scratch->image.image_provenance_id =
        pending->target_image_provenance_id;
    scratch->image.candidate_count = pending->candidate_count;
#pragma unroll
    for (int index = 0; index < 6; index++)
        scratch->image.reserved_0[index] = 0;
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++)
        scratch->image.ordered_candidates[index] =
            pending->ordered_candidates[index];
    scratch->image.transition_version = 1;
    scratch->image.state = image_provenance_state_v1_preparing;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->image.reserved_1[index] = 0;
    prepare_execution(
        &scratch->execution, &pending->target_execution_id,
        &process->process_lineage_id, &pending->target_image_provenance_id,
        process_execution_started_by_v1_exec_commit,
        process_execution_state_v1_preparing);
    if (bpf_map_update_elem(&image_provenance,
                            &pending->target_image_provenance_id,
                            &scratch->image, BPF_NOEXIST))
        return -EACCES;
    if (bpf_map_update_elem(&process_execution_instances,
                            &pending->target_execution_id,
                            &scratch->execution, BPF_NOEXIST)) {
        bpf_map_delete_elem(&image_provenance,
                            &pending->target_image_provenance_id);
        return -EACCES;
    }
    return 0;
}

SEC("fentry/security_bprm_committing_creds")
int BPF_PROG(erebor_bprm_committing_creds, struct linux_binprm *bprm)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process)
        return 0;
    if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return 0;
    if (!pending) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    if (process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->state != pending_exec_state_v1_preparing ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    scratch = identity_scratch_record();
    if (!scratch ||
        append_bprm_auxiliary_candidates(bprm, pending, scratch) ||
        prepare_exec_records(scratch, pending, process)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        pending->state = pending_exec_state_v1_outcome_unknown;
        pending->transition_version++;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    process->exec_guard_state = exec_guard_state_v1_commit_pending;
    process->transition_version++;
    pending->state = pending_exec_state_v1_commit_pending;
    pending->transition_version++;
    release_transition_guard(&process->transition_guard);
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
    bpf_map_delete_elem(&pending_administrative_matches,
                        &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process || !pending ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return 0;
    if (process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->state != pending_exec_state_v1_preparing) {
        image_provenance_v1 *image = bpf_map_lookup_elem(
            &image_provenance, &pending->target_image_provenance_id);
        process_execution_instance_v1 *execution = bpf_map_lookup_elem(
            &process_execution_instances, &pending->target_execution_id);

        if (image) {
            image->state = image_provenance_state_v1_outcome_unknown;
            image->transition_version++;
        }
        if (execution) {
            execution->state = process_execution_state_v1_outcome_unknown;
            execution->transition_version++;
        }
        pending->state = pending_exec_state_v1_post_ponr_fatal;
        pending->transition_version++;
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        release_transition_guard(&process->transition_guard);
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
    release_transition_guard(&process->transition_guard);
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
    struct task_struct *task = bpf_get_current_task_btf();
    task_label_v1 *label = bpf_task_storage_get(&task_labels, task, 0, 0);
    process_security_state_v1 *process;

    if (label) {
        process = bpf_map_lookup_elem(&process_states,
                                      &label->process_state_id);
        if (process &&
            __sync_val_compare_and_swap(
                &process->exec_check_task_cookie, label->task_cookie, 0) ==
                label->task_cookie)
            return 0;
    }
    return complete_failed_exec(context->ret);
}

SEC("tracepoint/sched/sched_process_exec")
int erebor_sched_process_exec(struct trace_event_raw_sched_process_exec *context)
{
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;
    process_execution_instance_v1 *previous_execution;
    process_execution_instance_v1 *target_execution;
    image_provenance_v1 *target_image;
    pending_administrative_match_v1 *administrative_match;
    external_root_classification_v1 *classification;
    entry_security_state_v1 *administrative_entry;
    task_coordinate_v1 *coordinate;
    struct identity_scratch_v1 *scratch;
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;
    __u64 pid_tgid;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process)
        return 0;
    if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return 0;
    if (!pending) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    if (process->exec_guard_state != exec_guard_state_v1_commit_pending ||
        pending->state != pending_exec_state_v1_commit_pending ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        process->transition_version++;
        pending->transition_version++;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    previous_execution = bpf_map_lookup_elem(
        &process_execution_instances, &process->active_execution_id);
    target_execution = bpf_map_lookup_elem(
        &process_execution_instances, &pending->target_execution_id);
    target_image = bpf_map_lookup_elem(
        &image_provenance, &pending->target_image_provenance_id);
    scratch = identity_scratch_record();
    if (scratch) {
        candidate_from_file(&scratch->image.ordered_candidates[0], NULL);
        if (!BPF_CORE_READ_INTO(&mm, task, mm) && mm &&
            !BPF_CORE_READ_INTO(&executable, mm, exe_file) && executable)
            candidate_from_file(&scratch->image.ordered_candidates[0],
                                executable);
    }
    administrative_match = bpf_map_lookup_elem(
        &pending_administrative_matches, &label->task_cookie);
    classification = NULL;
    administrative_entry = NULL;
    if (administrative_match) {
        classification = bpf_map_lookup_elem(
            &external_root_classifications, &label->task_cookie);
        administrative_entry = bpf_map_lookup_elem(
            &entry_states, &label->entry_instance_id);
    }
    if (!previous_execution ||
        previous_execution->state != process_execution_state_v1_active ||
        !target_execution ||
        target_execution->state != process_execution_state_v1_preparing ||
        !target_image ||
        target_image->state != image_provenance_state_v1_preparing ||
        !scratch || !scratch->image.ordered_candidates[0].mount_id ||
        !image_contains_candidate(
            target_image, &scratch->image.ordered_candidates[0]) ||
        (process->pending_target_role_id != process->active_role_id &&
         !administrative_match) ||
        (administrative_match &&
         (administrative_match->state !=
              pending_administrative_match_state_v1_slot_consumed ||
          administrative_match->exec_attempt_sequence !=
              pending->exec_attempt_sequence ||
          administrative_match->approved_role_numeric_id !=
              process->pending_target_role_id ||
          administrative_match->profile_generation_ref_id !=
              process->active_profile_generation_ref_id ||
          !classification ||
          classification->task_cookie != label->task_cookie ||
          !id128_equal(&classification->process_state_id,
                       &label->process_state_id) ||
          classification->root_class !=
              external_root_class_v1_external_runtime_root ||
          classification->purpose != entry_purpose_v1_unknown ||
          classification->installed_role_class !=
              installed_role_class_v1_runtime_external_restricted ||
          !administrative_entry ||
          administrative_entry->admission_state !=
              entry_admission_state_v1_committed ||
          administrative_entry->lifetime_state !=
              entry_lifetime_state_v1_active))) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        pending->state = pending_exec_state_v1_outcome_unknown;
        pending->transition_version++;
        if (target_execution) {
            target_execution->state = process_execution_state_v1_outcome_unknown;
            target_execution->transition_version++;
        }
        if (target_image) {
            target_image->state = image_provenance_state_v1_outcome_unknown;
            target_image->transition_version++;
        }
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    previous_execution->end_boottime_ns = bpf_ktime_get_ns();
    previous_execution->state = process_execution_state_v1_complete;
    previous_execution->transition_version++;
    target_execution->start_boottime_ns = previous_execution->end_boottime_ns;
    target_execution->state = process_execution_state_v1_active;
    target_execution->transition_version++;
    target_image->state = image_provenance_state_v1_active;
    target_image->transition_version++;
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
    if (administrative_match &&
        administrative_match->state ==
            pending_administrative_match_state_v1_slot_consumed &&
        administrative_match->exec_attempt_sequence ==
            pending->exec_attempt_sequence &&
        administrative_match->approved_role_numeric_id ==
            process->active_role_id) {
        if (classification) {
            classification->purpose =
                entry_purpose_v1_approved_administrative_next_match;
            classification->installed_role_class =
                installed_role_class_v1_approved_administrative_role;
            classification->installed_role_numeric_id =
                administrative_match->approved_role_numeric_id;
            classification->administrative_approval_proof_id =
                administrative_match->proof_id;
            classification->administrative_claim_slot_id =
                administrative_match->claim_slot_id;
            if (administrative_entry) {
                administrative_entry->claim_slot_id =
                    administrative_match->claim_slot_id;
                administrative_entry->entry_kind =
                    entry_kind_v1_approved_administrative_exec_next_match;
                administrative_entry->committed_execution_id =
                    pending->target_execution_id;
                administrative_entry->transition_version++;
            }
        }
    }
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (coordinate) {
        pid_tgid = bpf_get_current_pid_tgid();
        coordinate->host_tid = (__u32)pid_tgid;
        coordinate->host_tgid = pid_tgid >> 32;
        coordinate->transition_version++;
        coordinate->state = task_coordinate_state_v1_runnable;
    }
    release_transition_guard(&process->transition_guard);
    bpf_map_delete_elem(&pending_administrative_matches,
                        &label->task_cookie);
    bpf_map_delete_elem(&pending_execs, &label->task_cookie);
    return 0;
}

#endif /* EREBOR_IDENTITY_EXEC_BPF_H */
