/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_EXEC_BPF_H
#define EREBOR_IDENTITY_EXEC_BPF_H

static __noinline bool provisional_exec_request_valid(
    const struct provisional_exec_request_v1 *request);
static __noinline bool execution_argv_snapshot_valid(
    const execution_argv_snapshot_v1 *snapshot);

static __always_inline void remember_pending_exec_exact_requirement(
    pending_exec_v1 *pending, const struct identity_scratch_v1 *scratch)
{
    if (!pending || !scratch ||
        !scratch->path_terminal.exact_object_required ||
        pending->exact_object_required)
        return;
    pending->exact_object_required = 1;
    pending->transition_version++;
}

static __noinline int reserve_entry_admission(
    identity_runtime_config_v1 *config, const task_label_v1 *label,
    execution_set_binding_state_v1 *binding, entry_security_state_v1 *entry,
    pending_exec_v1 *pending, struct identity_scratch_v1 *scratch)
{
    entry_admission_rule_key_v1 *key;
    entry_admission_rule_v1 *rule;
    process_security_state_v1 *process;
    external_root_classification_v1 *classification;
    __u64 admission_composite_atom_id;
    bool application;

    if (!config || !label || !binding || !entry || !pending || !scratch ||
        !scratch->entry_admission_key.composite_atom_id ||
        pending->admitted_entry_rule_id || entry->admitted_entry_rule_id)
        return 0;
    key = &scratch->entry_admission_key;
    admission_composite_atom_id = key->composite_atom_id;
    __builtin_memset(key, 0, sizeof(*key));
    key->profile_generation_ref_id =
        pending->source_profile_generation_ref_id;
    key->binding_id = binding->binding_id;
    key->composite_atom_id = admission_composite_atom_id;
    key->source_role_id = pending->source_role_id;
    rule = bpf_map_lookup_elem(&entry_admission_rules, key);
    if (!rule)
        return 0;
    scratch->observation.exact_object_key_id =
        rule->exact_object_key_id;
    scratch->observation.file_object = scratch->file_object;
    application = pending->source_role_id == binding->initial_role_id &&
                  id128_equal(&binding->prepared_container_entry_instance_id,
                              &label->entry_instance_id) &&
                  (binding->prepared_container_state ==
                       prepared_container_state_v1_prepared ||
                   binding->prepared_container_state ==
                       prepared_container_state_v1_exec_pending);
    if (!rule->target_role_id || !rule->target_process_state_vector_id ||
        !rule->admitted_entry_rule_id || rule->reserved ||
        (rule->exact_object_key_id &&
         (rule->executable_object.profile_generation_ref_id !=
              pending->source_profile_generation_ref_id ||
          !exact_file_keys_equal(&rule->executable_object,
                                 &scratch->file_object))))
        return -EACCES;
    process = bpf_map_lookup_elem(&process_states,
                                  &label->process_state_id);
    if (!process || process->active_role_id != pending->source_role_id ||
        process->process_state_vector_id !=
            rule->target_process_state_vector_id ||
        process->exec_guard_state != exec_guard_state_v1_preparing ||
        !id128_equal(&process->pending_exec_id, &pending->pending_exec_id))
        return -EACCES;
    if (application) {
        if (pending->source_role_id != binding->initial_role_id ||
            !prepared_container_actor_is_exact(binding, label, entry) ||
            prepared_container_reserve_activation(binding, label))
            return -EACCES;
    } else {
        classification = entry_root_classification(label, entry);
        if (pending->source_role_id != binding->external_role_id ||
            !classification ||
            classification->root_class !=
                external_root_class_v1_external_runtime_root ||
            classification->purpose != entry_purpose_v1_unknown ||
            classification->installed_role_numeric_id !=
                binding->external_role_id)
            return -EACCES;
    }
    if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
        if (application)
            prepared_container_rollback_activation(binding,
                                                   label->task_cookie);
        return -EACCES;
    }
    if (process->exec_guard_state != exec_guard_state_v1_preparing ||
        !id128_equal(&process->pending_exec_id, &pending->pending_exec_id) ||
        pending->state != pending_exec_state_v1_preparing ||
        pending->admitted_entry_rule_id) {
        release_transition_guard(&process->transition_guard);
        if (application)
            prepared_container_rollback_activation(binding,
                                                   label->task_cookie);
        return -EACCES;
    }
    process->pending_target_role_id = rule->target_role_id;
    process->transition_version++;
    pending->admitted_entry_rule_id = rule->admitted_entry_rule_id;
    pending->transition_version++;
    release_transition_guard(&process->transition_guard);
    return 1;
}

static __noinline int commit_entry_admission_metadata(
    const task_label_v1 *label, const pending_exec_v1 *pending,
    const process_security_state_v1 *process)
{
    entry_security_state_v1 *entry;
    external_root_classification_v1 *classification;
    pending_execution_approval_v1 *execution_approval = NULL;

    if (!pending->admitted_entry_rule_id)
        return 0;
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    classification = entry_root_classification(label, entry);
    if (!entry || !classification)
        return -EACCES;
    execution_approval = bpf_map_lookup_elem(
        &pending_execution_approvals, &label->task_cookie);
    if (execution_approval) {
        if (execution_approval->state !=
                pending_execution_approval_state_v1_slot_consumed ||
            execution_approval->exec_attempt_sequence !=
                pending->exec_attempt_sequence ||
            execution_approval->target_role_numeric_id !=
                process->pending_target_role_id)
            return -EACCES;
    }
    entry->admitted_entry_rule_id = pending->admitted_entry_rule_id;
    entry->committed_execution_id = pending->target_execution_id;
    entry->transition_version++;
    classification->installed_role_numeric_id =
        process->pending_target_role_id;
    if (execution_approval) {
        classification->purpose =
            entry_purpose_v1_approved_administrative_next_match;
        classification->installed_role_numeric_id =
            execution_approval->target_role_numeric_id;
        classification->administrative_approval_proof_id =
            execution_approval->proof_id;
        classification->administrative_claim_slot_id =
            execution_approval->claim_slot_id;
        entry->claim_slot_id = execution_approval->claim_slot_id;
        entry->transition_version++;
    } else if (classification->root_class ==
               external_root_class_v1_external_runtime_root) {
        classification->installed_role_class =
            installed_role_class_v1_qualified_registered_role;
    }
    return 0;
}

static __noinline bool entry_admission_matches_live_state(
    const task_label_v1 *label, const pending_exec_v1 *pending,
    const execution_set_binding_state_v1 *binding,
    const process_security_state_v1 *process,
    const pending_execution_approval_v1 *execution_approval)
{
    external_root_classification_v1 *classification;
    entry_security_state_v1 *entry;
    bool application;

    if (!label || !pending || !binding || !process)
        return false;
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!entry)
        return false;
    application =
        binding->prepared_container_state ==
            prepared_container_state_v1_exec_pending &&
        binding->prepared_container_exec_task_cookie == label->task_cookie;
    if (application)
        return !execution_approval &&
               pending->source_role_id == binding->initial_role_id &&
               id128_equal(&binding->prepared_container_entry_instance_id,
                           &label->entry_instance_id);
    classification = entry_root_classification(label, entry);
    if (!classification ||
        pending->source_role_id != binding->external_role_id ||
        classification->root_class !=
            external_root_class_v1_external_runtime_root ||
        classification->purpose != entry_purpose_v1_unknown ||
        classification->installed_role_numeric_id !=
            binding->external_role_id ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active)
        return false;
    return !execution_approval ||
           (execution_approval->state ==
                pending_execution_approval_state_v1_slot_consumed &&
            execution_approval->exec_attempt_sequence ==
                pending->exec_attempt_sequence &&
            execution_approval->target_role_numeric_id ==
                process->pending_target_role_id &&
            execution_approval->profile_generation_ref_id ==
                process->active_profile_generation_ref_id);
}

static __noinline int observe_declared_entry_admission(
    identity_runtime_config_v1 *config, struct task_struct *task,
    task_label_v1 *label, pending_exec_v1 *pending)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    execution_set_binding_state_v1 *binding;
    entry_security_state_v1 *entry;
    struct cgroup *cgroup = NULL;
    struct file *file;
    int binding_lookup;
    int admission;

    remember_pending_exec_exact_requirement(pending, scratch);
    if (!label || !pending)
        return 0;
    if (!scratch || task_cgroup(task, &cgroup))
        return identity_deny(config);
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (binding_lookup || !binding_matches_label(binding, label) || !entry)
        return identity_deny(config);
    {
        struct provisional_exec_request_v1 *provisional =
            bpf_task_storage_get(&provisional_exec_requests, task, 0, 0);
        declared_entry_request_v1 *request =
            provisional && provisional->transition_version &&
                    provisional->declared_entry.path_length
                ? &provisional->declared_entry
                : NULL;

        scratch->entry_admission_key.composite_atom_id =
            logical_exec_request_atom(
                request, pending->source_profile_generation_ref_id,
                scratch);
    }
    __builtin_memset(&scratch->file_object, 0,
                     sizeof(scratch->file_object));
    scratch->file_object.profile_generation_ref_id =
        pending->source_profile_generation_ref_id;
    if (scratch->image.ordered_candidates[0].mount_namespace_inode &&
        scratch->image.ordered_candidates[0].inode &&
        scratch->image.ordered_candidates[0].inode_generation &&
        scratch->image.ordered_candidates[0].filesystem_device &&
        scratch->effect_path.mnt &&
        (file = (void *)mount_from_vfsmount(scratch->effect_path.mnt)) &&
        bpf_core_field_exists(
            ((struct mount___unique *)file)->mnt_id_unique) &&
        !BPF_CORE_READ_INTO(&scratch->file_object.mount_id_unique,
                            (struct mount___unique *)file,
                            mnt_id_unique) &&
        scratch->file_object.mount_id_unique) {
        scratch->file_object.mount_namespace_inode =
            scratch->image.ordered_candidates[0].mount_namespace_inode;
        scratch->file_object.filesystem_device =
            scratch->image.ordered_candidates[0].filesystem_device;
        scratch->file_object.inode =
            scratch->image.ordered_candidates[0].inode;
        scratch->file_object.inode_generation =
            scratch->image.ordered_candidates[0].inode_generation;
    }
    admission = reserve_entry_admission(config, label, binding, entry,
                                        pending, scratch);
    if (admission < 0) {
        clear_runtime_entry_bootstrap(task);
        scratch->effect_gate_flags = 0;
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    }
    if (admission > 0)
        return 0;

    if (!prepared_container_pre_active_actor_is_exact(binding, label,
                                                       entry)) {
        clear_runtime_entry_bootstrap(task);
        if (pending->source_role_id != binding->external_role_id)
            return 0;
        scratch->effect_gate_flags = 0;
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    }
    if (!pending->prepared_runtime_exec) {
        if (binding->prepared_container_state ==
            prepared_container_state_v1_exec_pending)
            prepared_container_rollback_activation(binding,
                                                   label->task_cookie);
        clear_runtime_entry_bootstrap(task);
        scratch->effect_gate_flags = 0;
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    }
    if (binding->prepared_container_state ==
        prepared_container_state_v1_exec_pending)
        prepared_container_rollback_activation(binding,
                                               label->task_cookie);
    if (!prepared_container_actor_is_exact(binding, label, entry))
        return identity_deny(config);
    return prepared_runtime_effect_result(scratch);
}

static __always_inline int observe_bprm_effect(struct linux_binprm *bprm)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    task_label_v1 *label;
    entry_security_state_v1 *entry;
    pending_exec_v1 *pending;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    struct file *file = NULL;
    struct identity_scratch_v1 *scratch;
    int binding_lookup;
    int result;

    if (!config || !config->effect_policy_enabled)
        return 0;
    if (BPF_CORE_READ_INTO(&file, bprm, file))
        file = NULL;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    pending = label
                  ? bpf_map_lookup_elem(&pending_execs,
                                        &label->task_cookie)
                  : NULL;
    if (pending && pending->task_cookie == label->task_cookie &&
        pending->admitted_entry_rule_id)
        return 0;
    if (pending && pending->task_cookie == label->task_cookie &&
        pending->prepared_runtime_exec)
        return identity_effect_actor_gate(
            NULL, kernel_effect_family_v1_exec,
            kernel_effect_operation_v1_execute, 0);
    if (label && !task_cgroup(task, &cgroup)) {
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
        if (!binding_lookup &&
            prepared_container_admitted_actor_is_exact(binding, label,
                                                        entry)) {
            result = identity_effect_gate(
                file, kernel_effect_family_v1_exec,
                kernel_effect_operation_v1_execute, 0);
            remember_pending_exec_exact_requirement(
                pending, identity_scratch_record());
            return result;
        }
        if (pending && !binding_lookup && binding_matches_label(binding, label) &&
            binding->prepared_container_state ==
                prepared_container_state_v1_exec_pending &&
            binding->prepared_container_exec_task_cookie ==
                label->task_cookie)
            return identity_effect_actor_gate(
                NULL, kernel_effect_family_v1_exec,
                kernel_effect_operation_v1_execute, 0);
    }
    result = prepared_exec_policy_gate(file);
    if (result)
        return result;
    scratch = identity_scratch_record();
    if (!pending && scratch &&
        scratch->effect_gate_flags & EFFECT_GATE_PREPARED_EXEC_POLICY_MISS_V1) {
        scratch->effect_gate_flags = 0;
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    }
    return observe_declared_entry_admission(config, task, label, pending);
}

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
    __u32 candidate_count = pending->candidate_count;
    __u64 candidate_index;

    if (!candidate->mount_id && !pending->prepared_runtime_exec)
        return -EACCES;
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++) {
        if (index < candidate_count &&
            candidate_equal(&pending->ordered_candidates[index], candidate))
            return 0;
    }
    asm volatile("%[index] = %[count] ;\n"
                 "%[index] &= %2 ;\n"
                 : [index] "=&r"(candidate_index)
                 : [count] "r"((__u64)candidate_count),
                   "i"(MAX_EXEC_CANDIDATES_V1 - 1));
    if (candidate_count >= MAX_EXEC_CANDIDATES_V1)
        return -EACCES;
    pending->ordered_candidates[candidate_index] = *candidate;
    pending->candidate_count = candidate_count + 1;
    pending->transition_version++;
    return 0;
}

static __always_inline int append_bprm_auxiliary_candidates(
    struct linux_binprm *bprm, pending_exec_v1 *pending,
    struct identity_scratch_v1 *scratch, bool non_exact_candidate_allowed)
{
    struct file *file = NULL;

    BPF_CORE_READ_INTO(&file, bprm, executable);
    if (file) {
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if ((scratch->image.ordered_candidates[0].mount_id ||
             !non_exact_candidate_allowed ||
             pending->exact_object_required) &&
            append_exec_candidate(
                pending, &scratch->image.ordered_candidates[0]))
            return -EACCES;
    }
    file = NULL;
    BPF_CORE_READ_INTO(&file, bprm, interpreter);
    if (file) {
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if ((scratch->image.ordered_candidates[0].mount_id ||
             !non_exact_candidate_allowed ||
             pending->exact_object_required) &&
            append_exec_candidate(
                pending, &scratch->image.ordered_candidates[0]))
            return -EACCES;
    }
    return 0;
}

static __always_inline bool execution_approval_slot_identity_matches(
    execution_approval_slot_v1 *slot,
    const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id)
{
    bool body_digest_present = false;

    if (slot) {
#pragma clang loop unroll(disable)
        for (int index = 0; index < 32; index++)
            body_digest_present |= slot->authorization_body_sha256[index] != 0;
    }
    return slot && binding &&
           !id128_is_zero(&slot->proof_id) &&
           !id128_is_zero(&slot->claim_slot_id) &&
           body_digest_present &&
           slot->container_generation == binding->container_generation &&
           slot->profile_generation_ref_id == profile_generation_ref_id &&
           slot->target_role_numeric_id &&
           slot->resolved_executable.mount_namespace_inode &&
           slot->resolved_executable.mount_id &&
           slot->resolved_executable.filesystem_device &&
           slot->resolved_executable.inode &&
           slot->resolved_executable.inode_generation &&
           execution_argv_snapshot_valid(&slot->expected_argv) &&
           slot->expected_root_class ==
               external_root_class_v1_external_runtime_root &&
           id128_equal(&slot->cgroup_binding_nonce,
                       &binding->binding_nonce) &&
           slot->transition_version;
}

static __always_inline bool execution_approval_armed_slot_matches(
    execution_approval_slot_v1 *slot,
    const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id)
{
    __u64 now = bpf_ktime_get_ns();

    if (slot && slot->state == execution_approval_slot_state_v1_armed &&
        now > slot->deadline_boottime_ns &&
        __sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_armed,
            execution_approval_slot_state_v1_expired) ==
            execution_approval_slot_state_v1_armed)
        __sync_fetch_and_add(&slot->transition_version, 1);
    return execution_approval_slot_identity_matches(
               slot, binding, profile_generation_ref_id) &&
           slot->state == execution_approval_slot_state_v1_armed &&
           now <= slot->deadline_boottime_ns;
}

static __noinline bool execution_approval_reserved_slot_matches(
    execution_approval_slot_v1 *slot,
    const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id)
{
    return execution_approval_slot_identity_matches(
               slot, binding, profile_generation_ref_id) &&
           slot->state == execution_approval_slot_state_v1_reserved &&
           bpf_ktime_get_ns() <= slot->deadline_boottime_ns;
}

static __noinline bool execution_argv_snapshot_valid(
    const execution_argv_snapshot_v1 *snapshot)
{
    __u64 expected_chunks;

    if (!snapshot || id128_is_zero(&snapshot->snapshot_id) ||
        !snapshot->argument_count ||
        snapshot->argument_count > MAX_PROVISIONAL_EXEC_ARGUMENTS_V1 ||
        snapshot->total_argument_span < snapshot->argument_count ||
        snapshot->total_argument_span > 0xffffffffULL ||
        !snapshot->chunk_count ||
        snapshot->chunk_count > MAX_PROVISIONAL_EXEC_CHUNKS_V1 ||
        snapshot->reserved)
        return false;
    expected_chunks =
        ((snapshot->total_argument_span - 1) >>
         EXECUTION_ARGV_CHUNK_SHIFT_V1) + 1;
    return snapshot->chunk_count == expected_chunks;
}

static __noinline bool execution_argv_chunk_valid(
    const execution_argv_snapshot_v1 *snapshot, __u32 chunk_index,
    const execution_argv_chunk_v1 *chunk)
{
    __u64 preceding;
    __u64 remaining;
    __u32 expected_length;
    __u32 expected_flags;

    if (!execution_argv_snapshot_valid(snapshot) || !chunk ||
        chunk_index >= snapshot->chunk_count)
        return false;
    preceding = (__u64)chunk_index << EXECUTION_ARGV_CHUNK_SHIFT_V1;
    if (preceding >= snapshot->total_argument_span)
        return false;
    remaining = snapshot->total_argument_span - preceding;
    expected_length = remaining > EXECUTION_ARGV_CHUNK_BYTES_V1
                          ? EXECUTION_ARGV_CHUNK_BYTES_V1
                          : (__u32)remaining;
    expected_flags = chunk_index + 1 == snapshot->chunk_count
                         ? EXECUTION_ARGV_CHUNK_TERMINAL_V1
                         : 0;
    return chunk->length == expected_length &&
           chunk->flags == expected_flags;
}

struct execution_argv_copy_context {
    execution_argv_chunk_v1 *chunk;
    const __u8 *bytes;
    __u32 source_offset;
    __u32 destination_offset;
};

static long execution_argv_copy_step(__u32 step, void *data)
{
    struct execution_argv_copy_context *copy = data;
    __u32 source_index =
        (copy->source_offset + step) &
        (EXECUTION_ARGV_CHUNK_BYTES_V1 - 1);
    __u32 destination_index =
        (copy->destination_offset + step) &
        (EXECUTION_ARGV_CHUNK_BYTES_V1 - 1);

    copy->chunk->bytes[destination_index] = copy->bytes[source_index];
    return 0;
}

static __noinline int execution_argv_copy(
    execution_argv_chunk_v1 *chunk, const __u8 *bytes,
    __u32 source_offset, __u32 destination_offset, __u32 length)
{
    struct execution_argv_copy_context copy = {
        .chunk = chunk,
        .bytes = bytes,
        .source_offset = source_offset,
        .destination_offset = destination_offset,
    };
    long steps;

    if (!chunk || !bytes ||
        length > MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 ||
        source_offset >
            MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 - length ||
        destination_offset >
            EXECUTION_ARGV_CHUNK_BYTES_V1 - length)
        return -EACCES;
    if (!length)
        return 0;
    steps = bpf_loop(length, execution_argv_copy_step, &copy, 0);
    return steps == length ? 0 : -EACCES;
}

static __noinline int clear_execution_argv_chunk(
    struct identity_scratch_v1 *scratch)
{
    if (!scratch ||
        bpf_probe_read_kernel(
            scratch->exec_argv_chunk.bytes,
            sizeof(scratch->exec_argv_chunk.bytes),
            scratch->zero_bytes))
        return -EACCES;
    scratch->exec_argv_chunk.length = 0;
    scratch->exec_argv_chunk.flags = 0;
    return 0;
}

static __noinline int flush_provisional_execution_argv_chunk(
    execution_argv_snapshot_v1 *snapshot,
    struct identity_scratch_v1 *scratch, bool terminal)
{
    execution_argv_chunk_key_v1 *key;

    if (!snapshot || !scratch || id128_is_zero(&snapshot->snapshot_id) ||
        !scratch->exec_argv_chunk.length ||
        scratch->exec_argv_chunk.length >
            EXECUTION_ARGV_CHUNK_BYTES_V1 ||
        snapshot->chunk_count >= MAX_PROVISIONAL_EXEC_CHUNKS_V1 ||
        (!terminal &&
         scratch->exec_argv_chunk.length !=
             EXECUTION_ARGV_CHUNK_BYTES_V1))
        return -EACCES;
    key = &scratch->exec_argv_chunk_key;
    key->snapshot_id = snapshot->snapshot_id;
    key->chunk_index = snapshot->chunk_count;
    key->reserved = 0;
    scratch->exec_argv_chunk.flags =
        terminal ? EXECUTION_ARGV_CHUNK_TERMINAL_V1 : 0;
    if (bpf_map_update_elem(
            &execution_argv_provisional_chunks, key,
            &scratch->exec_argv_chunk, BPF_NOEXIST))
        return -EACCES;
    snapshot->chunk_count++;
    return clear_execution_argv_chunk(scratch);
}

static __noinline int append_provisional_execution_argv_bytes(
    execution_argv_snapshot_v1 *snapshot,
    struct identity_scratch_v1 *scratch, const __u8 *bytes,
    __u32 length)
{
    __u32 available;
    __u32 prefix;
    __u32 remainder;

    if (!snapshot || !scratch || !bytes || !length ||
        length > MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 ||
        scratch->exec_argv_chunk.length >
            EXECUTION_ARGV_CHUNK_BYTES_V1)
        return -EACCES;
    if (scratch->exec_argv_chunk.length ==
            EXECUTION_ARGV_CHUNK_BYTES_V1 &&
        flush_provisional_execution_argv_chunk(
            snapshot, scratch, false))
        return -EACCES;
    available = EXECUTION_ARGV_CHUNK_BYTES_V1 -
                scratch->exec_argv_chunk.length;
    prefix = length < available ? length : available;
    if (execution_argv_copy(
            &scratch->exec_argv_chunk, bytes, 0,
            scratch->exec_argv_chunk.length, prefix))
        return -EACCES;
    scratch->exec_argv_chunk.length += prefix;
    remainder = length - prefix;
    if (!remainder)
        return 0;
    if (flush_provisional_execution_argv_chunk(
            snapshot, scratch, false) ||
        execution_argv_copy(
            &scratch->exec_argv_chunk, bytes, prefix, 0,
            remainder))
        return -EACCES;
    scratch->exec_argv_chunk.length = remainder;
    return 0;
}

static __always_inline void capture_declared_exec_request(
    struct provisional_exec_request_v1 *request,
    struct identity_scratch_v1 *scratch, const char *argument)
{
    declared_entry_request_v1 *declared_entry = &request->declared_entry;
    __u8 *declared;
    __u8 terminator = 1;
    __u32 argument_length;
    long length;

    length = bpf_probe_read_user_str(scratch->exec_argument,
                                     sizeof(scratch->exec_argument),
                                     argument);
    if (length <= 1 || length > sizeof(scratch->exec_argument))
        return;
    argument_length = (__u32)length - 1;
    if (length == sizeof(scratch->exec_argument) &&
        (bpf_probe_read_user(&terminator, sizeof(terminator),
                             argument + argument_length) || terminator))
        return;
    if (argument_length > MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1)
        return;
    declared_entry->path_length = argument_length;
    declared_entry->reserved = 0;
    if (bpf_probe_read_kernel(declared_entry->path, argument_length,
                              scratch->exec_argument))
        return;
    declared = bpf_map_lookup_elem(&declared_entry_requests, declared_entry);
    if (!declared || !*declared)
        declared_entry->path_length = 0;
}

struct execution_argv_cleanup_context {
    id128_v1 snapshot_id;
};

static long cleanup_provisional_execution_argv_chunk(
    __u32 chunk_index, void *data)
{
    struct execution_argv_cleanup_context *cleanup = data;
    execution_argv_chunk_key_v1 key = {
        .snapshot_id = cleanup->snapshot_id,
        .chunk_index = chunk_index,
    };

    bpf_map_delete_elem(&execution_argv_provisional_chunks, &key);
    return 0;
}

static __noinline void cleanup_provisional_execution_argv(
    const execution_argv_snapshot_v1 *snapshot)
{
    long steps;
    struct execution_argv_cleanup_context cleanup = {};

    if (!snapshot || id128_is_zero(&snapshot->snapshot_id) ||
        !snapshot->chunk_count ||
        snapshot->chunk_count > MAX_PROVISIONAL_EXEC_CHUNKS_V1)
        return;
    cleanup.snapshot_id = snapshot->snapshot_id;
    steps = bpf_loop(snapshot->chunk_count,
                     cleanup_provisional_execution_argv_chunk,
                     &cleanup, 0);
    (void)steps;
}

static __noinline void clear_provisional_exec_request(
    struct task_struct *task)
{
    struct provisional_exec_request_v1 *request;

    if (!task)
        return;
    request = bpf_task_storage_get(
        &provisional_exec_requests, task, 0, 0);
    if (request)
        cleanup_provisional_execution_argv(&request->argv_snapshot);
    bpf_task_storage_delete(&provisional_exec_requests, task);
}

struct provisional_exec_capture_context {
    const char *const *argv;
    struct provisional_exec_request_v1 *request;
    struct identity_scratch_v1 *scratch;
    const char *current_argument;
    __u64 current_argument_span;
    __u32 argument_index;
    __u32 complete;
    __u32 failed;
};

static long capture_provisional_exec_stream(__u32 step, void *data)
{
    struct provisional_exec_capture_context *capture = data;
    const char *current_argument;
    __u64 current_argument_span;
    __u32 argument_index;
    __u32 length;
    long result;

    (void)step;
    if (bpf_probe_read_kernel(
            &current_argument, sizeof(current_argument),
            &capture->current_argument) ||
        bpf_probe_read_kernel(
            &current_argument_span, sizeof(current_argument_span),
            &capture->current_argument_span) ||
        bpf_probe_read_kernel(
            &argument_index, sizeof(argument_index),
            &capture->argument_index)) {
        capture->failed = 1;
        return 1;
    }
    if (!current_argument) {
        if (argument_index >= MAX_PROVISIONAL_EXEC_ARGUMENTS_V1) {
            capture->failed = 1;
            return 1;
        }
        asm volatile("%[index] &= %1 ;\n"
                     : [index] "+r"(argument_index)
                     : "i"(MAX_PROVISIONAL_EXEC_ARGUMENTS_V1 - 1));
        if (bpf_probe_read_user(
                &current_argument,
                sizeof(current_argument),
                &capture->argv[argument_index])) {
            capture->failed = 1;
            return 1;
        }
        if (!current_argument) {
            capture->complete = 1;
            return 1;
        }
        capture->current_argument = current_argument;
        if (!argument_index)
            capture_declared_exec_request(
                capture->request, capture->scratch,
                current_argument);
    }
    result = bpf_probe_read_user_str(
        capture->scratch->exec_argument,
        sizeof(capture->scratch->exec_argument),
        current_argument + current_argument_span);
    if (result <= 0 ||
        result > sizeof(capture->scratch->exec_argument)) {
        capture->failed = 1;
        return 1;
    }
    length = result == sizeof(capture->scratch->exec_argument)
                 ? MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1
                 : (__u32)result;
    if (current_argument_span >
            MAX_PROVISIONAL_EXEC_ARGUMENT_SPAN_V1 - length ||
        append_provisional_execution_argv_bytes(
            &capture->request->argv_snapshot, capture->scratch,
            capture->scratch->exec_argument, length)) {
        capture->failed = 1;
        return 1;
    }
    current_argument_span += length;
    capture->current_argument_span = current_argument_span;
    if (result == sizeof(capture->scratch->exec_argument))
        return 0;
    if (capture->request->argv_snapshot.argument_count == ~0ULL ||
        capture->request->argv_snapshot.total_argument_span >
            0xffffffffULL - current_argument_span) {
        capture->failed = 1;
        return 1;
    }
    capture->request->argv_snapshot.argument_count++;
    capture->request->argv_snapshot.total_argument_span +=
        current_argument_span;
    capture->argument_index = argument_index + 1;
    capture->current_argument = NULL;
    capture->current_argument_span = 0;
    return 0;
}

static __noinline void capture_provisional_exec_request(
    identity_runtime_config_v1 *config, struct task_struct *task,
    const char *const *argv, __u8 syscall_stage,
    __u32 syscall_flags)
{
    struct identity_scratch_v1 *scratch;
    struct provisional_exec_request_v1 *request;
    long steps;

    clear_provisional_exec_request(task);
    scratch = identity_scratch_record();
    if (!config || !task || !scratch)
        return;
    request = bpf_task_storage_get(
        &provisional_exec_requests, task, 0,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!request)
        return;
    request->declared_entry.path_length = 0;
    request->declared_entry.reserved = 0;
    bpf_probe_read_kernel(request->declared_entry.path,
                          sizeof(request->declared_entry.path),
                          scratch->zero_bytes);
    __builtin_memset(&request->argv_snapshot, 0,
                     sizeof(request->argv_snapshot));
    request->state = PROVISIONAL_EXEC_REQUEST_STATE_CAPTURING_V1;
    request->syscall_stage = syscall_stage;
    request->syscall_flags = syscall_flags;
    request->transition_version = 1;
    if (!argv ||
        allocate_id(config, &request->argv_snapshot.snapshot_id) ||
        clear_execution_argv_chunk(scratch))
        goto unavailable;
    struct provisional_exec_capture_context capture = {
        .argv = argv,
        .request = request,
        .scratch = scratch,
    };

    steps = bpf_loop(MAX_PROVISIONAL_EXEC_STREAM_STEPS_V1,
                     capture_provisional_exec_stream, &capture, 0);
    if (steps < 0 || capture.failed || !capture.complete ||
        flush_provisional_execution_argv_chunk(
            &request->argv_snapshot, scratch, true) ||
        !execution_argv_snapshot_valid(&request->argv_snapshot))
        goto unavailable;
    request->state = PROVISIONAL_EXEC_REQUEST_STATE_CAPTURED_V1;
    request->transition_version++;
    return;

unavailable:
    cleanup_provisional_execution_argv(&request->argv_snapshot);
    __builtin_memset(&request->argv_snapshot, 0,
                     sizeof(request->argv_snapshot));
    request->state = PROVISIONAL_EXEC_REQUEST_STATE_UNAVAILABLE_V1;
    request->transition_version++;
}

static __noinline bool provisional_exec_request_valid(
    const struct provisional_exec_request_v1 *request)
{
    return request &&
           request->state ==
               PROVISIONAL_EXEC_REQUEST_STATE_CAPTURED_V1 &&
           request->transition_version >= 2 &&
           execution_argv_snapshot_valid(&request->argv_snapshot);
}

struct execution_argv_compare_context {
    const execution_argv_snapshot_v1 *left;
    const execution_argv_snapshot_v1 *right;
    struct identity_scratch_v1 *scratch;
    __u32 right_is_expected;
    __u32 failed;
};

static long compare_execution_argv_word(__u32 word_index, void *data)
{
    struct execution_argv_compare_context *compare = data;
    execution_argv_chunk_key_v1 *left_key;
    execution_argv_chunk_key_v1 *right_key;
    execution_argv_chunk_v1 *left;
    execution_argv_chunk_v1 *right;
    __u32 chunk_index = word_index >> 9;
    __u32 byte_offset = (word_index & 511) << 3;

    if (!compare->scratch ||
        chunk_index >= compare->left->chunk_count ||
        chunk_index >= compare->right->chunk_count) {
        compare->failed = 1;
        return 1;
    }
    left_key = &compare->scratch->exec_argv_chunk_key;
    right_key = &compare->scratch->exec_argv_compare_chunk_key;
    left_key->snapshot_id = compare->left->snapshot_id;
    left_key->chunk_index = chunk_index;
    left_key->reserved = 0;
    right_key->snapshot_id = compare->right->snapshot_id;
    right_key->chunk_index = chunk_index;
    right_key->reserved = 0;
    left = bpf_map_lookup_elem(
        &execution_argv_provisional_chunks, left_key);
    if (compare->right_is_expected)
        right = bpf_map_lookup_elem(
            &execution_argv_expected_chunks, right_key);
    else
        right = bpf_map_lookup_elem(
            &execution_argv_provisional_chunks, right_key);
    compare->scratch->exec_argv_left_word = 0;
    compare->scratch->exec_argv_right_word = 0;
    if (!execution_argv_chunk_valid(
            compare->left, chunk_index, left) ||
        !execution_argv_chunk_valid(
            compare->right, chunk_index, right) ||
        bpf_probe_read_kernel(
            &compare->scratch->exec_argv_left_word,
            sizeof(compare->scratch->exec_argv_left_word),
            &left->bytes[byte_offset]) ||
        bpf_probe_read_kernel(
            &compare->scratch->exec_argv_right_word,
            sizeof(compare->scratch->exec_argv_right_word),
            &right->bytes[byte_offset]) ||
        compare->scratch->exec_argv_left_word !=
            compare->scratch->exec_argv_right_word) {
        compare->failed = 1;
        return 1;
    }
    return 0;
}

static __noinline bool execution_argv_snapshots_equal(
    const execution_argv_snapshot_v1 *left,
    const execution_argv_snapshot_v1 *right, bool right_is_expected)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    long steps;
    __u64 words;
    struct execution_argv_compare_context compare = {
        .left = left,
        .right = right,
        .scratch = scratch,
        .right_is_expected = right_is_expected,
    };

    if (!scratch || !execution_argv_snapshot_valid(left) ||
        !execution_argv_snapshot_valid(right) ||
        left->argument_count != right->argument_count ||
        left->total_argument_span != right->total_argument_span ||
        left->chunk_count != right->chunk_count)
        return false;
    words = (left->total_argument_span + 7) >> 3;
    if (!words || words > MAX_EXECUTION_ARGV_COMPARE_WORDS_V1)
        return false;
    steps = bpf_loop((__u32)words, compare_execution_argv_word,
                     &compare, 0);
    return steps >= 0 && (__u64)steps == words && !compare.failed;
}

static __always_inline int provisional_execution_approval_matches(
    const struct provisional_exec_request_v1 *request,
    const execution_approval_slot_v1 *slot,
    struct identity_scratch_v1 *scratch)
{
    if (!scratch || !slot || !provisional_exec_request_valid(request) ||
        !execution_argv_snapshots_equal(
            &request->argv_snapshot, &slot->expected_argv, true))
        return -EACCES;
    return 0;
}

struct execution_argv_packed_context {
    __u64 cursor;
    __u64 end;
    execution_argv_snapshot_v1 *snapshot;
    struct identity_scratch_v1 *scratch;
    __u32 failed;
};

static long capture_execution_argv_packed_stream(
    __u32 step, void *data)
{
    struct execution_argv_packed_context *context = data;
    execution_argv_chunk_key_v1 *key;
    __u64 remaining;
    __u32 length;
    long read_result;
    bool terminal;

    if (context->cursor >= context->end ||
        step >= context->snapshot->chunk_count)
        return 1;
    remaining = context->end - context->cursor;
    length = remaining > EXECUTION_ARGV_CHUNK_BYTES_V1
                 ? EXECUTION_ARGV_CHUNK_BYTES_V1
                 : (__u32)remaining;
    if (!length ||
        length > EXECUTION_ARGV_CHUNK_BYTES_V1) {
        context->failed = 1;
        return 1;
    }
    if (length == EXECUTION_ARGV_CHUNK_BYTES_V1)
        read_result = bpf_probe_read_user(
            context->scratch->exec_argv_chunk.bytes,
            EXECUTION_ARGV_CHUNK_BYTES_V1,
            (const void *)context->cursor);
    else {
        asm volatile("%[length] &= 4095 ;\n"
                     : [length] "+r"(length));
        read_result = bpf_probe_read_user(
            context->scratch->exec_argv_chunk.bytes, length,
            (const void *)context->cursor);
    }
    if (read_result) {
        context->failed = 1;
        return 1;
    }
    context->scratch->exec_argv_chunk.length = length;
    context->cursor += length;
    terminal = context->cursor == context->end;
    key = &context->scratch->exec_argv_chunk_key;
    key->snapshot_id = context->snapshot->snapshot_id;
    key->chunk_index = step;
    key->reserved = 0;
    context->scratch->exec_argv_chunk.flags =
        terminal ? EXECUTION_ARGV_CHUNK_TERMINAL_V1 : 0;
    if (bpf_map_update_elem(
            &execution_argv_provisional_chunks, key,
            &context->scratch->exec_argv_chunk, BPF_NOEXIST) ||
        clear_execution_argv_chunk(context->scratch)) {
        context->failed = 1;
        return 1;
    }
    return terminal ? 1 : 0;
}

static __noinline int capture_execution_argv_packed_user(
    __u64 start, __u64 end, __u64 argument_count,
    struct identity_scratch_v1 *scratch,
    execution_argv_snapshot_v1 *snapshot)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    __u64 argument_span;
    __u64 expected_chunks;
    long steps;

    if (!config || !start || !end || end <= start ||
        !scratch || !snapshot ||
        !argument_count ||
        argument_count > MAX_PROVISIONAL_EXEC_ARGUMENTS_V1)
        return -EACCES;
    argument_span = end - start;
    expected_chunks = ((argument_span - 1) >>
                       EXECUTION_ARGV_CHUNK_SHIFT_V1) + 1;
    if (argument_span > 0xffffffffULL ||
        expected_chunks > MAX_PROVISIONAL_EXEC_PACKED_CHUNKS_V1)
        return -EACCES;
    __builtin_memset(snapshot, 0, sizeof(*snapshot));
    snapshot->argument_count = argument_count;
    snapshot->total_argument_span = argument_span;
    snapshot->chunk_count = (__u32)expected_chunks;
    if (allocate_id(config, &snapshot->snapshot_id) ||
        clear_execution_argv_chunk(scratch))
        goto unavailable;
    struct execution_argv_packed_context context = {
        .cursor = start,
        .end = end,
        .snapshot = snapshot,
        .scratch = scratch,
    };

    steps = bpf_loop((__u32)expected_chunks,
                     capture_execution_argv_packed_stream,
                     &context, 0);
    if (steps < 0 || context.failed ||
        context.cursor != end ||
        !execution_argv_snapshot_valid(snapshot))
        goto unavailable;
    return 0;

unavailable:
    cleanup_provisional_execution_argv(snapshot);
    __builtin_memset(snapshot, 0, sizeof(*snapshot));
    return -EACCES;
}

static __noinline int provisional_exec_request_matches_installed_argv(
    const struct provisional_exec_request_v1 *request, __u64 start,
    __u64 end, __u64 argument_count,
    struct identity_scratch_v1 *scratch)
{
    execution_argv_snapshot_v1 observed = {};
    bool matches;

    if (!provisional_exec_request_valid(request) ||
        request->argv_snapshot.argument_count != argument_count ||
        capture_execution_argv_packed_user(
            start, end, argument_count, scratch,
            &observed))
        return -EACCES;
    matches = execution_argv_snapshots_equal(
        &observed, &request->argv_snapshot, false);
    cleanup_provisional_execution_argv(&observed);
    return matches ? 0 : -EACCES;
}

static __noinline int provisional_exec_request_matches_bprm(
    const struct provisional_exec_request_v1 *request,
    struct linux_binprm *bprm, struct identity_scratch_v1 *scratch)
{
    unsigned long argument_start = 0;
    __u64 argument_end;
    int argument_count = 0;

    if (!bprm || BPF_CORE_READ_INTO(&argument_start, bprm, p) ||
        BPF_CORE_READ_INTO(&argument_count, bprm, argc) ||
        argument_count < 0 || !provisional_exec_request_valid(request) ||
        argument_start >
            ~0ULL - request->argv_snapshot.total_argument_span)
        return -EACCES;
    argument_end = argument_start +
                   request->argv_snapshot.total_argument_span;
    return provisional_exec_request_matches_installed_argv(
        request, argument_start, argument_end,
        (__u64)argument_count, scratch);
}

static __noinline int provisional_exec_request_matches_mm(
    const struct provisional_exec_request_v1 *request,
    struct mm_struct *mm, struct identity_scratch_v1 *scratch)
{
    unsigned long argument_start = 0;
    unsigned long argument_end = 0;

    if (!mm || BPF_CORE_READ_INTO(&argument_start, mm, arg_start) ||
        BPF_CORE_READ_INTO(&argument_end, mm, arg_end))
        return -EACCES;
    return provisional_exec_request_matches_installed_argv(
        request, argument_start, argument_end,
        request ? request->argv_snapshot.argument_count : 0,
        scratch);
}

static __always_inline bool initial_exec_has_provisional_capture(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    task_label_v1 *label;
    struct provisional_exec_request_v1 *request;

    if (!task)
        return false;
    request = bpf_task_storage_get(&provisional_exec_requests, task, 0, 0);
    if (!request || !request->transition_version ||
        (request->state != PROVISIONAL_EXEC_REQUEST_STATE_CAPTURED_V1 &&
         request->state != PROVISIONAL_EXEC_REQUEST_STATE_UNAVAILABLE_V1))
        return false;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    return label &&
           !bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
}

static __always_inline void begin_execution_approval_prepare_trace(
    struct identity_scratch_v1 *scratch,
    const execution_set_binding_state_v1 *binding,
    const execution_approval_slot_v1 *slot, __u8 stage,
    __u32 syscall_flags)
{
    begin_effect_observation(scratch, kernel_effect_family_v1_exec,
                             kernel_effect_operation_v1_execute);
    scratch->observation.binding_id = binding->binding_id;
    scratch->observation.execution_set_id = binding->execution_set_id;
    scratch->observation.execution_approval_trace.syscall_flags =
        syscall_flags;
    scratch->observation.execution_approval_trace.expected_executable =
        slot->resolved_executable;
    scratch->observation.execution_approval_trace.slot_state =
        (__u8)slot->state;
    scratch->observation.execution_approval_trace.stage = stage;
}

static __noinline void emit_execution_approval_prepare_trace(
    struct identity_scratch_v1 *scratch, __u64 failed_checks)
{
    scratch->observation.execution_approval_trace.failed_checks =
        failed_checks;
    runtime_entry_infrastructure_effect_result(scratch);
}

static __always_inline int prepare_exec_matches(
    const char *const *argv, __u8 trace_stage, __u32 syscall_flags)
{
    identity_runtime_config_v1 *config = identity_runtime_config();

    if (!config || !config->enabled)
        return 0;
    capture_provisional_exec_request(
        config, bpf_get_current_task_btf(), argv,
        trace_stage, syscall_flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int erebor_sys_enter_execve(struct trace_event_raw_sys_enter *context)
{
    return prepare_exec_matches((const char *const *)context->args[1],
                                EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1,
                                0);
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
            __sync_val_compare_and_swap(
                &process->exec_without_transition_task_cookie, 0,
                label->task_cookie);
        return 0;
    }
    return prepare_exec_matches(
        (const char *const *)context->args[2],
        EXECUTION_APPROVAL_TRACE_STAGE_EXECVEAT_ENTRY_V1,
        (__u32)context->args[4]);
}

static __always_inline int reserve_execution_approval(
    identity_runtime_config_v1 *config, const task_label_v1 *label,
    execution_set_binding_state_v1 *binding,
    process_security_state_v1 *process, pending_exec_v1 *pending,
    const struct provisional_exec_request_v1 *request,
    struct identity_scratch_v1 *scratch)
{
    execution_approval_slot_key_v1 *key;
    execution_approval_slot_v1 *slot;

    if (!config || !label || !binding || !process || !pending || !scratch ||
        !provisional_exec_request_valid(request))
        return 0;
    key = &scratch->execution_approval_slot_key;
    key->node_boot_id = config->node_boot_id;
    key->cgroup_binding_id = binding->binding_id;
    slot = bpf_map_lookup_elem(&execution_approval_slots, key);
    if (!slot)
        return 0;
    begin_execution_approval_prepare_trace(
        scratch, binding, slot, request->syscall_stage,
        request->syscall_flags);
    scratch->observation.task_cookie = label->task_cookie;
    scratch->observation.profile_generation_ref_id =
        process->active_profile_generation_ref_id;
    scratch->observation.execution_approval_trace.exec_attempt_sequence =
        pending->exec_attempt_sequence;
    scratch->observation.execution_approval_trace.observed_executable =
        pending->ordered_candidates[0];
    if (!execution_approval_armed_slot_matches(
            slot, binding, process->active_profile_generation_ref_id)) {
        emit_execution_approval_prepare_trace(
            scratch,
            EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_SLOT_GUARD_V1);
        return 0;
    }
    if (!slot->admitted_entry_rule_id ||
        !candidate_equal(&slot->resolved_executable,
                         &pending->ordered_candidates[0])) {
        emit_execution_approval_prepare_trace(
            scratch,
            EXECUTION_APPROVAL_TRACE_FAILURE_OBSERVED_EXECUTABLE_V1);
        return 0;
    }
    if (provisional_execution_approval_matches(request, slot, scratch)) {
        emit_execution_approval_prepare_trace(
            scratch, EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1);
        return 0;
    }
    scratch->execution_approval.task_cookie = label->task_cookie;
    scratch->execution_approval.exec_attempt_sequence =
        pending->exec_attempt_sequence;
    scratch->execution_approval.proof_id = slot->proof_id;
    scratch->execution_approval.claim_slot_id = slot->claim_slot_id;
    scratch->execution_approval.target_role_numeric_id =
        slot->target_role_numeric_id;
    scratch->execution_approval.reserved_0 = 0;
    scratch->execution_approval.profile_generation_ref_id =
        slot->profile_generation_ref_id;
    scratch->execution_approval.resolved_executable =
        slot->resolved_executable;
    scratch->execution_approval.transition_version = 1;
    scratch->execution_approval.state =
        pending_execution_approval_state_v1_slot_reserved;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->execution_approval.reserved_1[index] = 0;
    if (__sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_armed,
            execution_approval_slot_state_v1_reserved) !=
        execution_approval_slot_state_v1_armed) {
        emit_execution_approval_prepare_trace(
            scratch, EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_STATE_V1);
        return -EACCES;
    }
    slot->transition_version++;
    if (bpf_map_update_elem(
            &pending_execution_approvals, &label->task_cookie,
            &scratch->execution_approval, BPF_NOEXIST))
        goto reject_map_update;
    if (consume_bounded_exception(slot->profile_generation_ref_id,
                                  slot->exception_numeric_handle,
                                  &slot->claim_slot_id, 0, 0, 0)) {
        goto reject_slot_guard;
    }
    process->pending_target_role_id = slot->target_role_numeric_id;
    pending->admitted_entry_rule_id = slot->admitted_entry_rule_id;
    pending->transition_version++;
    emit_execution_approval_prepare_trace(scratch, 0);
    return 0;

reject_map_update:
    if (__sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_reserved,
            execution_approval_slot_state_v1_tampered) ==
        execution_approval_slot_state_v1_reserved)
        slot->transition_version++;
    bpf_map_delete_elem(&pending_execution_approvals,
                        &label->task_cookie);
    emit_execution_approval_prepare_trace(
        scratch, EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_MAP_UPDATE_V1);
    return -EACCES;

reject_slot_guard:
    if (__sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_reserved,
            execution_approval_slot_state_v1_tampered) ==
        execution_approval_slot_state_v1_reserved)
        slot->transition_version++;
    bpf_map_delete_elem(&pending_execution_approvals,
                        &label->task_cookie);
    emit_execution_approval_prepare_trace(
        scratch, EXECUTION_APPROVAL_TRACE_FAILURE_SLOT_GUARD_V1);
    return -EACCES;
}

#define MITHRIL_SIGKILL_V1 9

static __always_inline execution_approval_slot_v1 *
execution_approval_reserved_slot_for_match(
    identity_runtime_config_v1 *config, const execution_set_binding_state_v1 *binding,
    const process_security_state_v1 *process,
    const pending_execution_approval_v1 *match)
{
    execution_approval_slot_key_v1 key;
    execution_approval_slot_v1 *slot;

    if (!config || !binding || !process || !match)
        return NULL;
    key.node_boot_id = config->node_boot_id;
    key.cgroup_binding_id = binding->binding_id;
    slot = bpf_map_lookup_elem(&execution_approval_slots, &key);
    if (!execution_approval_reserved_slot_matches(
            slot, binding, process->active_profile_generation_ref_id) ||
        !id128_equal(&slot->proof_id, &match->proof_id) ||
        !id128_equal(&slot->claim_slot_id, &match->claim_slot_id) ||
        !candidate_equal(&slot->resolved_executable,
                         &match->resolved_executable))
        return NULL;
    return slot;
}

static __always_inline int verify_execution_approval_bprm_argv(
    identity_runtime_config_v1 *config,
    const task_label_v1 *label, const execution_set_binding_state_v1 *binding,
    const process_security_state_v1 *process, const pending_exec_v1 *pending,
    const struct provisional_exec_request_v1 *request)
{
    pending_execution_approval_v1 *match;
    execution_approval_slot_v1 *slot;

    match = bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie);
    if (!match)
        return 0;
    if (match->state !=
            pending_execution_approval_state_v1_slot_reserved ||
        match->exec_attempt_sequence != pending->exec_attempt_sequence ||
        match->target_role_numeric_id != process->pending_target_role_id ||
        match->profile_generation_ref_id !=
            process->active_profile_generation_ref_id)
        return -EACCES;
    slot = execution_approval_reserved_slot_for_match(
        config, binding, process, match);
    if (!slot || !provisional_exec_request_valid(request) ||
        !execution_argv_snapshots_equal(
            &request->argv_snapshot, &slot->expected_argv, true))
        return -EACCES;
    match->state =
        pending_execution_approval_state_v1_kernel_argv_verified;
    match->transition_version++;
    return 1;
}

static __always_inline int finalize_execution_approval(
    identity_runtime_config_v1 *config,
    const task_label_v1 *label, const execution_set_binding_state_v1 *binding,
    process_security_state_v1 *process, pending_exec_v1 *pending,
    const struct provisional_exec_request_v1 *request)
{
    pending_execution_approval_v1 *match;
    execution_approval_slot_v1 *slot;

    match = bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie);
    if (!match)
        return 0;
    if (match->state !=
            pending_execution_approval_state_v1_kernel_argv_verified ||
        match->exec_attempt_sequence != pending->exec_attempt_sequence ||
        match->target_role_numeric_id != process->pending_target_role_id ||
        match->profile_generation_ref_id !=
            process->active_profile_generation_ref_id)
        return -EACCES;
    slot = execution_approval_reserved_slot_for_match(
        config, binding, process, match);
    if (!slot || !provisional_exec_request_valid(request) ||
        !execution_argv_snapshots_equal(
            &request->argv_snapshot, &slot->expected_argv, true) ||
        __sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_reserved,
            execution_approval_slot_state_v1_consumed) !=
            execution_approval_slot_state_v1_reserved)
        return -EACCES;
    slot->transition_version++;
    match->state = pending_execution_approval_state_v1_slot_consumed;
    match->transition_version++;
    return 1;
}

static __noinline void fail_execution_approval_verification(
    identity_runtime_config_v1 *config, const task_label_v1 *label,
    execution_set_binding_state_v1 *binding,
    pending_exec_v1 *pending, struct identity_scratch_v1 *scratch)
{
    pending_execution_approval_v1 *match;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;
    execution_approval_slot_key_v1 key;
    execution_approval_slot_v1 *slot = NULL;
    int signal_result;

    clear_provisional_exec_request(bpf_get_current_task_btf());
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    match = bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie);
    if (match && binding) {
        key.node_boot_id = config->node_boot_id;
        key.cgroup_binding_id = binding->binding_id;
        slot = bpf_map_lookup_elem(&execution_approval_slots, &key);
        if (slot &&
            id128_equal(&slot->proof_id, &match->proof_id) &&
            id128_equal(&slot->claim_slot_id, &match->claim_slot_id)) {
            if (__sync_val_compare_and_swap(
                    &slot->state, execution_approval_slot_state_v1_reserved,
                    execution_approval_slot_state_v1_tampered) ==
                execution_approval_slot_state_v1_reserved)
                slot->transition_version++;
            else if (__sync_val_compare_and_swap(
                         &slot->state,
                         execution_approval_slot_state_v1_consumed,
                         execution_approval_slot_state_v1_tampered) ==
                     execution_approval_slot_state_v1_consumed)
                slot->transition_version++;
        }
        match->state = pending_execution_approval_state_v1_tampered;
        match->transition_version++;
    }
    if (pending) {
        pending->state = pending_exec_state_v1_post_ponr_fatal;
        pending->transition_version++;
    }
    if (process) {
        process->state = process_security_state_kind_v1_corrupt;
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->pending_target_role_id = 0;
        process->transition_version++;
    }
    signal_result = bpf_send_signal(MITHRIL_SIGKILL_V1);
    if (!scratch)
        return;
    begin_effect_observation(scratch, kernel_effect_family_v1_exec,
                             kernel_effect_operation_v1_execute);
    if (process && entry)
        populate_effect_actor(scratch, label, process, entry, NULL);
    if (binding) {
        scratch->observation.binding_id = binding->binding_id;
        scratch->observation.execution_set_id = binding->execution_set_id;
    }
    if (pending)
        scratch->observation.admitted_entry_rule_id =
            pending->admitted_entry_rule_id;
    emit_effect_observation(
        scratch, signal_result,
        effect_observation_reason_v1_execution_approval_verification_failed,
        signal_result == 0
            ? effect_physical_result_v1_termination_queued_before_user_mode
            : effect_physical_result_v1_unknown_after_pre_effect);
}

static __always_inline void close_current_execution_approval(
    const task_label_v1 *label)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    pending_execution_approval_v1 *match;
    execution_approval_slot_key_v1 key;
    execution_approval_slot_v1 *slot;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !label)
        return;
    match = bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie);
    if (!match ||
        (match->state !=
             pending_execution_approval_state_v1_slot_reserved &&
         match->state !=
             pending_execution_approval_state_v1_kernel_argv_verified) ||
        task_cgroup(bpf_get_current_task_btf(), &cgroup))
        return;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding_matches_label(binding, label))
        return;
    key.node_boot_id = config->node_boot_id;
    key.cgroup_binding_id = binding->binding_id;
    slot = bpf_map_lookup_elem(&execution_approval_slots, &key);
    if (!slot || !id128_equal(&slot->proof_id, &match->proof_id) ||
        !id128_equal(&slot->claim_slot_id, &match->claim_slot_id) ||
        __sync_val_compare_and_swap(
            &slot->state, execution_approval_slot_state_v1_reserved,
            execution_approval_slot_state_v1_consumed) !=
            execution_approval_slot_state_v1_reserved)
        return;
    slot->transition_version++;
    match->state = pending_execution_approval_state_v1_slot_consumed;
    match->transition_version++;
}

#define BPRM_OBSERVE_EFFECT_V1 1

static __noinline int identity_bprm_transition(struct linux_binprm *bprm,
                                               int ret)
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
    struct provisional_exec_request_v1 *request;
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
            if (label_external_root(task, binding, config)) {
                if (health)
                    health->missing_identity_denials++;
                return identity_deny(config);
            }
            label = bpf_task_storage_get(&task_labels, task, 0, 0);
            if (!label) {
                if (health)
                    health->missing_identity_denials++;
                return identity_deny(config);
            }
        } else {
            return 0;
        }
    }
    request = bpf_task_storage_get(&provisional_exec_requests, task, 0, 0);
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
    if ((config->effect_policy_enabled &&
         migrate_process_generation(config, binding, label, process, scratch)) ||
        snapshot_process_state(process, snapshot) ||
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
        !profile_task_refs)
        return identity_deny(config);
    if (snapshot->exec_without_transition_task_cookie)
        return snapshot->exec_without_transition_task_cookie ==
                       label->task_cookie
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
        candidate_from_bprm(&scratch->pending_exec.ordered_candidates[0], bprm);
        scratch->pending_exec.prepared_runtime_exec =
            PREPARED_RUNTIME_EXEC_NONE_V1;
        /* A post-mount runtime hook is a child of the held initial entry.
         * Permit its process-birth exec, but keep the initial task and every
         * later exec on the declared-entry path. */
        if (prepared_container_bootstrap_exec_is_exact(
                binding, label, entry, coordinate, active_execution))
            scratch->pending_exec.prepared_runtime_exec =
                PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1;
        /* A runtime can re-exec its current image while it prepares an entry.
         * A different image must match a declared entry before exec commits. */
        if (runtime_entry_bootstrap_actor_is_exact(
                config, binding, label, snapshot, entry) &&
            image_contains_candidate(
                active_image, &scratch->pending_exec.ordered_candidates[0]))
            scratch->pending_exec.prepared_runtime_exec =
                PREPARED_RUNTIME_EXEC_ENTRY_V1;
        if (!scratch->pending_exec.ordered_candidates[0].mount_id) {
            /* The prepared runtime can use anonymous executable objects. The
             * policy gate still decides whether this exec activates the app. */
            if (!prepared_container_actor_is_exact(binding, label, entry)) {
                release_transition_guard(&process->transition_guard);
                return config->effect_policy_enabled ? BPRM_OBSERVE_EFFECT_V1
                                                     : identity_deny(config);
            }
            scratch->pending_exec.prepared_runtime_exec =
                PREPARED_RUNTIME_EXEC_ENTRY_V1;
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
        scratch->pending_exec.exact_object_required = 0;
        scratch->pending_exec.source_profile_generation_ref_id =
            snapshot->active_profile_generation_ref_id;
        scratch->pending_exec.pending_exec_response_set_ref_id =
            snapshot->effective_response_set_ref_id;
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
        scratch->pending_exec.admitted_entry_rule_id = 0;
        scratch->pending_exec.state = pending_exec_state_v1_preparing;
#pragma unroll
        for (int index = 0; index < 3; index++)
            scratch->pending_exec.reserved_1[index] = 0;
        if (bpf_map_update_elem(&pending_execs, &label->task_cookie,
                                &scratch->pending_exec, BPF_NOEXIST)) {
            release_transition_guard(&process->transition_guard);
            return identity_deny(config);
        }
        if (scratch->pending_exec.prepared_runtime_exec ==
                PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1 &&
            prepared_container_reserve_bootstrap_exec(binding, label)) {
            bpf_map_delete_elem(&pending_execs, &label->task_cookie);
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
        pending = bpf_map_lookup_elem(&pending_execs,
                                      &label->task_cookie);
        if (!pending) {
            release_transition_guard(&process->transition_guard);
            return identity_deny(config);
        }
        int administrative_result = reserve_execution_approval(
            config, label, binding, process, pending, request, scratch);

        release_transition_guard(&process->transition_guard);
        if (administrative_result)
            return identity_deny(config);
        return BPRM_OBSERVE_EFFECT_V1;
    }
    if (pending->task_cookie != label->task_cookie ||
        !id128_equal(&pending->process_state_id, &label->process_state_id) ||
        pending->state != pending_exec_state_v1_preparing ||
        snapshot->exec_guard_state != exec_guard_state_v1_preparing)
        return identity_deny(config);
    candidate_from_bprm(&scratch->image.ordered_candidates[0], bprm);
    if (append_exec_candidate(pending,
                              &scratch->image.ordered_candidates[0]))
        return identity_deny(config);
    return BPRM_OBSERVE_EFFECT_V1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(erebor_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    int result = identity_bprm_transition(bprm, ret);

    if (result != BPRM_OBSERVE_EFFECT_V1)
        return result;
    return observe_bprm_effect(bprm);
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
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task = bpf_get_current_task_btf();
    struct identity_scratch_v1 *scratch;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;
    struct provisional_exec_request_v1 *request;
    entry_security_state_v1 *entry = NULL;
    execution_set_binding_state_v1 *binding = NULL;
    struct cgroup *cgroup = NULL;
    bool non_exact_candidate_allowed = false;
    int administrative_result;
    int binding_lookup = -1;

    request = bpf_task_storage_get(&provisional_exec_requests, task, 0, 0);
    if (!config) {
        clear_provisional_exec_request(task);
        return 0;
    }
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label) {
        clear_provisional_exec_request(task);
        return 0;
    }
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!task_cgroup(task, &cgroup)) {
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        entry = bpf_map_lookup_elem(&entry_states,
                                    &label->entry_instance_id);
        non_exact_candidate_allowed =
            !binding_lookup &&
            (prepared_container_pre_active_actor_is_exact(
                 binding, label, entry) ||
             prepared_container_admitted_actor_is_exact(
                 binding, label, entry) ||
             (pending &&
              (pending->prepared_runtime_exec ||
               (pending->admitted_entry_rule_id &&
                 !pending->exact_object_required))));
    }
    if (!process) {
        clear_provisional_exec_request(task);
        return 0;
    }
    if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1))
        return 0;
    if (!pending) {
        /* Cgroup attachment can make a prepared entry visible after the
         * bprm check. Mark that in-flight bootstrap exec for completion. */
        if (!binding_lookup && binding && entry &&
            process->exec_guard_state == exec_guard_state_v1_none &&
            !process->exec_without_transition_task_cookie &&
            runtime_entry_bootstrap_actor_is_exact(
                config, binding, label, process, entry)) {
            process->exec_without_transition_task_cookie =
                label->task_cookie;
            process->transition_version++;
            release_transition_guard(&process->transition_guard);
            return 0;
        }
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    if (pending->task_cookie != label->task_cookie ||
        process->exec_guard_state != exec_guard_state_v1_preparing ||
        pending->state != pending_exec_state_v1_preparing ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    scratch = identity_scratch_record();
    if (!scratch ||
        (pending->prepared_runtime_exec ==
             PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1 &&
         !prepared_container_bootstrap_exec_is_pending(
             binding, label)) ||
        append_bprm_auxiliary_candidates(
            bprm, pending, scratch, non_exact_candidate_allowed)) {
        if (bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie))
            fail_execution_approval_verification(
                config, label, binding, pending, scratch);
        else {
            process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
            process->transition_version++;
            pending->state = pending_exec_state_v1_outcome_unknown;
            pending->transition_version++;
        }
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    if (provisional_exec_request_valid(request) &&
        provisional_exec_request_matches_bprm(
            request, bprm, scratch)) {
        fail_execution_approval_verification(
            config, label, binding, pending, scratch);
        release_transition_guard(&process->transition_guard);
        return 0;
    }
    administrative_result = verify_execution_approval_bprm_argv(
        config, label, binding, process, pending, request);
    if (administrative_result < 0 ||
        prepare_exec_records(scratch, pending, process)) {
        if (administrative_result ||
            bpf_map_lookup_elem(&pending_execution_approvals,
                                &label->task_cookie))
            fail_execution_approval_verification(
                config, label, binding, pending, scratch);
        else {
            process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
            process->transition_version++;
            pending->state = pending_exec_state_v1_outcome_unknown;
            pending->transition_version++;
        }
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

static __always_inline void activate_prepared_container_for_application(
    struct task_struct *task)
{
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding = NULL;
    entry_security_state_v1 *entry = NULL;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label || task_cgroup(task, &cgroup))
        return;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding_matches_label(binding, label) ||
        binding->prepared_container_state !=
            prepared_container_state_v1_exec_pending)
        return;
    if (binding->prepared_container_exec_task_cookie !=
        label->task_cookie)
        return;
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    /* The first syscall entry proves that the new image reached user space.
     * Keep kernel exec-finalization work inside the prepared boundary. */
    if (!prepared_container_pre_active_actor_is_exact(binding, label, entry) ||
        !entry->admitted_entry_rule_id ||
        !prepared_container_commit_activation(binding, label->task_cookie))
        prepared_container_mark_corrupt(binding);
}

static __always_inline int complete_failed_exec(long result)
{
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (result >= 0)
        return 0;
    task = bpf_get_current_task_btf();
    clear_provisional_exec_request(task);
    clear_runtime_entry_bootstrap(task);
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    close_current_execution_approval(label);
    bpf_map_delete_elem(&pending_execution_approvals,
                        &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (process && !pending) {
        __sync_val_compare_and_swap(
            &process->exec_without_transition_task_cookie,
            label->task_cookie, 0);
        return 0;
    }
    if (!process || !pending || pending->task_cookie != label->task_cookie ||
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
    if (!task_cgroup(task, &cgroup)) {
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        if (!binding_lookup && binding_matches_label(binding, label)) {
            if (pending->prepared_runtime_exec ==
                PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1)
                prepared_container_rollback_bootstrap_exec(
                    binding, label->task_cookie);
            else if (!pending->prepared_runtime_exec)
                prepared_container_rollback_activation(binding,
                                                       label->task_cookie);
        }
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
                &process->exec_without_transition_task_cookie,
                label->task_cookie, 0) ==
                label->task_cookie)
            return 0;
    }
    return complete_failed_exec(context->ret);
}

SEC("tracepoint/sched/sched_process_exec")
int erebor_sched_process_exec(struct trace_event_raw_sched_process_exec *context)
{
    identity_runtime_config_v1 *config;
    struct task_struct *task;
    task_label_v1 *label;
    process_security_state_v1 *process;
    pending_exec_v1 *pending;
    struct provisional_exec_request_v1 *request;
    process_execution_instance_v1 *previous_execution;
    process_execution_instance_v1 *target_execution;
    image_provenance_v1 *target_image;
    pending_execution_approval_v1 *execution_approval;
    task_coordinate_v1 *coordinate;
    struct identity_scratch_v1 *scratch;
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;
    __u64 pid_tgid;
    execution_set_binding_state_v1 *binding;
    entry_security_state_v1 *entry;
    struct cgroup *cgroup = NULL;
    bool non_exact_candidate_allowed;
    bool entry_admission;
    int administrative_result;
    int binding_lookup = -1;

    config = identity_runtime_config();
    task = bpf_get_current_task_btf();
    request = bpf_task_storage_get(&provisional_exec_requests, task, 0, 0);
    if (!config) {
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label) {
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!process) {
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    if (!task_cgroup(task, &cgroup)) {
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        entry = bpf_map_lookup_elem(&entry_states,
                                    &label->entry_instance_id);
    }
    if (__sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    if (!pending) {
        /* This marker proves that the credential hook accepted this exact
         * task as an in-flight prepared bootstrap exec. */
        if (!binding_lookup && binding && entry &&
            process->exec_guard_state == exec_guard_state_v1_none &&
            process->exec_without_transition_task_cookie ==
                label->task_cookie &&
            runtime_entry_bootstrap_actor_is_exact(
                config, binding, label, process, entry)) {
            process->exec_without_transition_task_cookie = 0;
            process->transition_version++;
            release_transition_guard(&process->transition_guard);
            clear_provisional_exec_request(task);
            return 0;
        }
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        release_transition_guard(&process->transition_guard);
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    if (task_cgroup(task, &cgroup)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        pending->state = pending_exec_state_v1_outcome_unknown;
        pending->transition_version++;
        release_transition_guard(&process->transition_guard);
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    non_exact_candidate_allowed =
        !binding_lookup && !pending->exact_object_required &&
        (prepared_container_pre_active_actor_is_exact(
             binding, label, entry) ||
         prepared_container_admitted_actor_is_exact(
             binding, label, entry) ||
         pending->prepared_runtime_exec ||
         pending->admitted_entry_rule_id);
    if (pending->task_cookie != label->task_cookie ||
        process->exec_guard_state != exec_guard_state_v1_commit_pending ||
        pending->state != pending_exec_state_v1_commit_pending ||
        !id128_equal(&pending->pending_exec_id, &process->pending_exec_id)) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        pending->state = pending_exec_state_v1_outcome_unknown;
        process->transition_version++;
        pending->transition_version++;
        release_transition_guard(&process->transition_guard);
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
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
    if (!scratch ||
        (provisional_exec_request_valid(request) &&
         provisional_exec_request_matches_mm(
             request, mm, scratch))) {
        fail_execution_approval_verification(
            config, label, binding, pending, scratch);
        release_transition_guard(&process->transition_guard);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    execution_approval = bpf_map_lookup_elem(
        &pending_execution_approvals, &label->task_cookie);
    administrative_result = finalize_execution_approval(
        config, label, binding, process, pending, request);
    if (administrative_result < 0) {
        fail_execution_approval_verification(
            config, label, binding, pending, scratch);
        release_transition_guard(&process->transition_guard);
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    entry_admission = pending->admitted_entry_rule_id != 0;
    if (!entry) {
        process->exec_guard_state = exec_guard_state_v1_outcome_unknown;
        process->transition_version++;
        pending->state = pending_exec_state_v1_outcome_unknown;
        pending->transition_version++;
        if (target_execution) {
            target_execution->state =
                process_execution_state_v1_outcome_unknown;
            target_execution->transition_version++;
        }
        if (target_image) {
            target_image->state = image_provenance_state_v1_outcome_unknown;
            target_image->transition_version++;
        }
        release_transition_guard(&process->transition_guard);
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    if (!previous_execution ||
        previous_execution->state != process_execution_state_v1_active ||
        !target_execution ||
        target_execution->state != process_execution_state_v1_preparing ||
        !target_image ||
        target_image->state != image_provenance_state_v1_preparing ||
        binding_lookup || !binding_matches_label(binding, label) ||
        !scratch ||
        (((!scratch->image.ordered_candidates[0].mount_id &&
           !pending->prepared_runtime_exec) ||
          !image_contains_candidate(
              target_image, &scratch->image.ordered_candidates[0])) &&
         !non_exact_candidate_allowed) ||
        (pending->prepared_runtime_exec ==
             PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1
             ? !prepared_container_bootstrap_exec_is_pending(binding, label)
             : (pending->prepared_runtime_exec &&
                !prepared_container_actor_is_exact(binding, label, entry) &&
                !runtime_entry_bootstrap_actor_is_exact(
                    config, binding, label, process, entry))) ||
        (process->pending_target_role_id != process->active_role_id &&
         !entry_admission) ||
        (entry_admission && !process->pending_target_role_id) ||
        (entry_admission &&
         !entry_admission_matches_live_state(
             label, pending, binding, process,
             execution_approval)) ||
        commit_entry_admission_metadata(label, pending, process) ||
        (pending->prepared_runtime_exec ==
             PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1 &&
         prepared_container_commit_bootstrap_exec(
             binding, label->task_cookie))) {
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
        clear_provisional_exec_request(task);
        clear_runtime_entry_bootstrap(task);
        return 0;
    }
    /* Keep entry preparation across successful runtime-internal execs. A
     * declared entry consumes it when that entry's role becomes active. */
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
    if (entry_admission)
        process->runtime_entry_bootstrap_prepared = 0;
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
    release_transition_guard(&process->transition_guard);
    if (entry_admission)
        clear_runtime_entry_bootstrap(task);
    bpf_map_delete_elem(&pending_execution_approvals,
                        &label->task_cookie);
    bpf_map_delete_elem(&pending_execs, &label->task_cookie);
    clear_provisional_exec_request(task);
    return 0;
}

#endif /* EREBOR_IDENTITY_EXEC_BPF_H */
