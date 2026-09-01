/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_IO_URING_BPF_H
#define EREBOR_IDENTITY_IO_URING_BPF_H

static __noinline int snapshot_io_uring_actor(
    struct task_struct *task, struct identity_scratch_v1 *scratch,
    io_uring_actor_snapshot_v1 *actor,
    execution_set_binding_state_v1 *binding_snapshot)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    process_execution_instance_v1 *execution;
    image_provenance_v1 *image;
    execution_set_binding_state_v1 *binding;
    profile_generation_descriptor_v1 *generation;
    __u64 *task_refs;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !config->enabled || !task || !scratch || !actor ||
        !binding_snapshot)
        return -EACCES;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label || !label_matches_runtime(label, config) ||
        task_cgroup(task, &cgroup))
        return -EACCES;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding_matches_label(binding, label))
        return -EACCES;
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    vector = bpf_map_lookup_elem(&process_state_vectors,
                                 &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!coordinate ||
        coordinate->state != task_coordinate_state_v1_runnable ||
        coordinate->task_cookie != label->task_cookie ||
        !id128_equal(&coordinate->process_instance_id,
                     &label->process_instance_id) ||
        !id128_equal(&coordinate->process_state_id,
                     &label->process_state_id) ||
        refresh_real_parent(task, label, coordinate, scratch) ||
        snapshot_process_state(process, &scratch->process))
        return -EACCES;
    process = &scratch->process;
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &process->authority_domain_id);
    execution = bpf_map_lookup_elem(&process_execution_instances,
                                    &process->active_execution_id);
    image = execution ? bpf_map_lookup_elem(
                            &image_provenance,
                            &execution->image_provenance_id)
                      : NULL;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &process->active_profile_generation_ref_id);
    task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &process->active_profile_generation_ref_id);
    if (process->state != process_security_state_kind_v1_active ||
        !process->live_thread_refs ||
        process->exec_guard_state != exec_guard_state_v1_none ||
        process->exec_without_transition_task_cookie ||
        !id128_equal(&process->process_state_id, &label->process_state_id) ||
        !id128_equal(&process->process_lineage_id,
                     &label->process_lineage_id) ||
        !id128_equal(&process->process_instance_id,
                     &label->process_instance_id) ||
        !id128_equal(&process->entry_instance_id,
                     &label->entry_instance_id) ||
        !entry || entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs || !domain ||
        domain->state != authority_domain_state_kind_v1_active ||
        !domain->live_process_refs || !execution ||
        execution->state != process_execution_state_v1_active || !image ||
        image->state != image_provenance_state_v1_active || !vector ||
        vector->state != process_state_vector_state_v1_active ||
        vector->process_state_vector_id != process->process_state_vector_id ||
        vector->profile_generation_ref_id !=
            process->active_profile_generation_ref_id ||
        !generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id !=
            process->active_profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id) ||
        !task_refs || __sync_fetch_and_add(task_refs, 0) == 0)
        return -EACCES;

    __builtin_memset(actor, 0, sizeof(*actor));
    actor->node_boot_id = config->node_boot_id;
    actor->process_lineage_id = process->process_lineage_id;
    actor->process_instance_id = process->process_instance_id;
    actor->process_state_id = process->process_state_id;
    actor->entry_instance_id = process->entry_instance_id;
    actor->authority_domain_id = process->authority_domain_id;
    actor->binding_id = binding->binding_id;
    actor->binding_nonce = binding->binding_nonce;
    actor->execution_set_id = binding->execution_set_id;
    actor->profile_id = binding->profile_id;
    actor->task_cookie = label->task_cookie;
    actor->label_epoch = config->label_epoch;
    actor->profile_generation_ref_id =
        process->active_profile_generation_ref_id;
    actor->root_cgroup_id = binding->root_cgroup_id;
    actor->container_generation = binding->container_generation;
    actor->lifecycle_generation = binding->lifecycle_generation;
    actor->process_transition_version = process->transition_version;
    actor->active_role_id = process->active_role_id;
    actor->process_state_vector_id = process->process_state_vector_id;
    actor->admitted_entry_rule_id = entry->admitted_entry_rule_id;
    actor->binding_lifecycle_state = binding->lifecycle_state;
    *binding_snapshot = *binding;
    return 0;
}

static __always_inline bool io_uring_actor_equal(
    const io_uring_actor_snapshot_v1 *left,
    const io_uring_actor_snapshot_v1 *right)
{
    return left && right &&
           id128_equal(&left->node_boot_id, &right->node_boot_id) &&
           id128_equal(&left->process_lineage_id,
                       &right->process_lineage_id) &&
           id128_equal(&left->process_instance_id,
                       &right->process_instance_id) &&
           id128_equal(&left->process_state_id, &right->process_state_id) &&
           id128_equal(&left->entry_instance_id,
                       &right->entry_instance_id) &&
           id128_equal(&left->authority_domain_id,
                       &right->authority_domain_id) &&
           id128_equal(&left->binding_id, &right->binding_id) &&
           id128_equal(&left->binding_nonce, &right->binding_nonce) &&
           id128_equal(&left->execution_set_id, &right->execution_set_id) &&
           id128_equal(&left->profile_id, &right->profile_id) &&
           left->task_cookie == right->task_cookie &&
           left->label_epoch == right->label_epoch &&
           left->profile_generation_ref_id ==
               right->profile_generation_ref_id &&
           left->root_cgroup_id == right->root_cgroup_id &&
           left->container_generation == right->container_generation &&
           left->lifecycle_generation == right->lifecycle_generation &&
           left->process_transition_version ==
               right->process_transition_version &&
           left->active_role_id == right->active_role_id &&
           left->process_state_vector_id ==
               right->process_state_vector_id &&
           left->admitted_entry_rule_id == right->admitted_entry_rule_id &&
           left->binding_lifecycle_state ==
               right->binding_lifecycle_state;
}

static __always_inline bool io_uring_binding_equal(
    const execution_set_binding_state_v1 *left,
    const execution_set_binding_state_v1 *right)
{
    return left && right &&
           id128_equal(&left->binding_id, &right->binding_id) &&
           id128_equal(&left->binding_nonce, &right->binding_nonce) &&
           id128_equal(&left->node_boot_id, &right->node_boot_id) &&
           id128_equal(&left->execution_set_id, &right->execution_set_id) &&
           id128_equal(&left->protected_scope_id,
                       &right->protected_scope_id) &&
           id128_equal(&left->profile_id, &right->profile_id) &&
           left->label_epoch == right->label_epoch &&
           left->root_cgroup_id == right->root_cgroup_id &&
           left->root_cgroup_live_interval_id.high ==
               right->root_cgroup_live_interval_id.high &&
           left->root_cgroup_live_interval_id.low ==
               right->root_cgroup_live_interval_id.low &&
           left->container_generation == right->container_generation &&
           left->lifecycle_generation == right->lifecycle_generation &&
           left->lifecycle_state == right->lifecycle_state;
}

static __always_inline bool io_uring_admitted_actor_is_exact(
    const io_uring_actor_snapshot_v1 *actor,
    const execution_set_binding_state_v1 *binding)
{
    return actor && binding &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active &&
           binding->prepared_container_state ==
               prepared_container_state_v1_active &&
           actor->admitted_entry_rule_id &&
           id128_equal(&binding->binding_id, &actor->binding_id) &&
           id128_equal(&binding->binding_nonce, &actor->binding_nonce) &&
           id128_equal(&binding->execution_set_id, &actor->execution_set_id) &&
           id128_equal(&binding->profile_id, &actor->profile_id) &&
           binding->active_profile_generation_ref_id ==
               actor->profile_generation_ref_id;
}

static __always_inline int io_uring_application_default_or_hard(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    bool application_default_allow, __u8 reason)
{
    if (application_default_allow)
        return application_default_effect_result(scratch);
    return hard_effect_result(config, scratch, reason);
}

static __always_inline void populate_io_uring_observation(
    struct identity_scratch_v1 *scratch,
    const io_uring_request_state_v1 *request,
    const io_uring_execution_state_v1 *execution)
{
    scratch->observation.task_cookie = request->actor.task_cookie;
    scratch->observation.profile_generation_ref_id =
        request->actor.profile_generation_ref_id;
    scratch->observation.process_lineage_id =
        request->actor.process_lineage_id;
    scratch->observation.process_instance_id =
        request->actor.process_instance_id;
    scratch->observation.entry_instance_id =
        request->actor.entry_instance_id;
    scratch->observation.authority_domain_id =
        request->actor.authority_domain_id;
    scratch->observation.binding_id = request->actor.binding_id;
    scratch->observation.execution_set_id = request->actor.execution_set_id;
    scratch->observation.active_role_id = request->actor.active_role_id;
    scratch->observation.process_state_vector_id =
        request->actor.process_state_vector_id;
    scratch->observation.admitted_entry_rule_id =
        request->actor.admitted_entry_rule_id;
    scratch->observation.io_uring_ring_id = request->ring_id;
    scratch->observation.io_uring_ring_generation = request->ring_generation;
    scratch->observation.io_uring_submission_sequence =
        request->submission_sequence;
    scratch->observation.io_uring_user_data = request->user_data;
    scratch->observation.io_uring_file_offset = request->file_offset;
    scratch->observation.io_uring_buffer_address = request->buffer_address;
    scratch->observation.io_uring_file_cookie = request->file_cookie;
    scratch->observation.io_uring_executor_pid_tgid =
        execution->executor_pid_tgid;
    scratch->observation.io_uring_byte_length = request->byte_length;
    scratch->observation.io_uring_sqe_index = request->sqe_index;
    scratch->observation.io_uring_request_flags = request->request_flags;
    scratch->observation.io_uring_rw_flags = request->rw_flags;
    scratch->observation.io_uring_opcode = request->opcode;
}

static __noinline int io_uring_file_mapping_gate(
    struct file *file, unsigned long reqprot, unsigned long prot,
    unsigned long flags, int ret)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    struct task_struct *task = bpf_get_current_task_btf();
    struct io_ring_ctx *context = NULL;
    io_uring_ring_state_v1 *ring;
    profile_generation_descriptor_v1 *generation;
    __u64 key;

    if (!file || BPF_CORE_READ_INTO(&context, file, private_data) || !context)
        return IO_URING_MAPPING_NOT_APPLICABLE_V1;
    key = (__u64)context;
    ring = bpf_map_lookup_elem(&io_uring_ring_states, &key);
    if (!ring)
        return IO_URING_MAPPING_NOT_APPLICABLE_V1;
    if (ret)
        return ret;
    if (!config || !scratch ||
        (ring->state != io_uring_ring_state_kind_v1_disabled &&
         ring->state != io_uring_ring_state_kind_v1_restricted &&
         ring->state != io_uring_ring_state_kind_v1_active) ||
        (flags & MAP_TYPE) != MAP_SHARED ||
        ((reqprot | prot) & ~(PROT_READ | PROT_WRITE)) ||
        snapshot_io_uring_actor(task, scratch, &scratch->io_uring_actor,
                                &scratch->io_uring_ring_draft.binding) ||
        !io_uring_actor_equal(&ring->owner, &scratch->io_uring_actor) ||
        !io_uring_binding_equal(&ring->binding,
                                &scratch->io_uring_ring_draft.binding))
        return identity_deny(config);
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &ring->owner.profile_generation_ref_id);
    if (!generation || generation->state != policy_generation_state_v1_active ||
        generation->profile_generation_ref_id !=
            ring->owner.profile_generation_ref_id ||
        generation->label_epoch != ring->owner.label_epoch ||
        !id128_equal(&generation->node_boot_id, &ring->owner.node_boot_id) ||
        !id128_equal(&generation->profile_id, &ring->owner.profile_id))
        return identity_deny(config);
    return 0;
}

static __noinline int resolved_io_uring_effect_gate(
    struct file *file, __u16 effect_family, __u16 operation, int ret,
    struct identity_scratch_v1 *scratch)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    io_uring_execution_state_v1 *execution = bpf_task_storage_get(
        &io_uring_execution_states, bpf_get_current_task_btf(), 0, 0);
    io_uring_request_state_v1 *request;
    io_uring_ring_state_v1 *ring;
    profile_generation_descriptor_v1 *generation;
    exact_object_binding_v1 *object_binding;
    physical_decision_v1 *decision;
    __u64 *async_refs;
    struct path file_path = {};
    __u64 file_cookie;
    __u64 previous_file_cookie;
    bool application_default_allow;

    if (!config || !scratch || !execution)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    if (execution->state != io_uring_execution_state_kind_v1_active)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    request = bpf_map_lookup_elem(&io_uring_request_states,
                                  &execution->request_cookie);
    ring = bpf_map_lookup_elem(&io_uring_ring_states,
                               &execution->context_cookie);
    if (!request || !ring ||
        request->state != io_uring_request_state_kind_v1_submitted ||
        ring->state != io_uring_ring_state_kind_v1_active ||
        ring->restriction_state !=
            io_uring_restriction_state_v1_exact_read_write ||
        request->request_cookie != execution->request_cookie ||
        request->context_cookie != execution->context_cookie ||
        request->submission_sequence != execution->submission_sequence ||
        request->user_data != execution->user_data ||
        request->opcode != execution->opcode ||
        !id128_equal(&request->ring_id, &execution->ring_id) ||
        !id128_equal(&request->ring_id, &ring->ring_id) ||
        request->ring_generation != ring->ring_generation ||
        !io_uring_actor_equal(&request->actor, &ring->owner) ||
        !id128_equal(&request->actor.binding_id,
                     &ring->binding.binding_id) ||
        !id128_equal(&request->actor.binding_nonce,
                     &ring->binding.binding_nonce) ||
        request->actor.profile_generation_ref_id !=
            ring->owner.profile_generation_ref_id ||
        request->actor.node_boot_id.high != config->node_boot_id.high ||
        request->actor.node_boot_id.low != config->node_boot_id.low ||
        request->actor.label_epoch != config->label_epoch)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    populate_io_uring_observation(scratch, request, execution);
    application_default_allow =
        io_uring_admitted_actor_is_exact(&request->actor, &ring->binding);
    if (ret)
        return emit_effect_observation(
            scratch, ret, effect_observation_reason_v1_prior_lsm_denial,
            effect_physical_result_v1_denied_before_effect);
    if (!config->effect_policy_enabled)
        return 0;
    if (!file || effect_family != kernel_effect_family_v1_file ||
        ((request->opcode == IORING_OP_READ &&
          operation != kernel_effect_operation_v1_read) ||
         (request->opcode == IORING_OP_WRITE &&
          operation != kernel_effect_operation_v1_write) ||
         (request->opcode != IORING_OP_READ &&
          request->opcode != IORING_OP_WRITE)))
        return hard_effect_result(
            config, scratch, effect_observation_reason_v1_unsupported_object);
    file_cookie = (__u64)file;
    previous_file_cookie = __sync_val_compare_and_swap(
        &request->file_cookie, 0, file_cookie);
    if (previous_file_cookie && previous_file_cookie != file_cookie)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    scratch->observation.io_uring_file_cookie = file_cookie;
    async_refs = bpf_map_lookup_elem(
        &profile_generation_async_refs,
        &request->actor.profile_generation_ref_id);
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &request->actor.profile_generation_ref_id);
    if (!async_refs || __sync_fetch_and_add(async_refs, 0) == 0 ||
        !generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id !=
            request->actor.profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &request->actor.profile_id))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    if (BPF_CORE_READ_INTO(&file_path, file, f_path))
        return io_uring_application_default_or_hard(
            config, scratch, application_default_allow,
            effect_observation_reason_v1_unresolved_object);
    exact_file_object_from_path(&scratch->file_object, &file_path);
    scratch->file_object.profile_generation_ref_id =
        request->actor.profile_generation_ref_id;
    scratch->observation.file_object = scratch->file_object;
    if (!scratch->file_object.mount_id_unique)
        return io_uring_application_default_or_hard(
            config, scratch, application_default_allow,
            effect_observation_reason_v1_unsupported_object);
    if (canonical_path_candidate(
            &file_path, &ring->binding,
            request->actor.profile_generation_ref_id,
            request->actor.active_role_id, scratch))
        return io_uring_application_default_or_hard(
            config, scratch, application_default_allow,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.composite_atom_id =
        scratch->path_terminal.composite_atom_id;
    if (path_tree_denies(scratch, operation)) {
        if (generation->mode != policy_generation_mode_v1_protect)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        return path_tree_effect_result(config, scratch);
    }
    if (!scratch->path_terminal.exact_object_required) {
        __builtin_memset(&scratch->effect_default, 0,
                         sizeof(scratch->effect_default));
        scratch->effect_default.profile_generation_ref_id =
            request->actor.profile_generation_ref_id;
        scratch->effect_default.active_role_id = request->actor.active_role_id;
        scratch->effect_default.effect_family = effect_family;
        scratch->effect_default.operation = operation;
        scratch->effect_default.composite_atom_id =
            scratch->observation.composite_atom_id;
        scratch->effect_default.process_state_vector_id =
            request->actor.process_state_vector_id;
        scratch->effect_default.binding_lifecycle_state =
            request->actor.binding_lifecycle_state;
        decision =
            bpf_map_lookup_elem(&effect_defaults, &scratch->effect_default);
        return apply_effect_decision(config, scratch, generation, decision,
                                     application_default_allow, false, false);
    }
    object_binding = configured_file_object_binding(scratch);
    if (!object_binding ||
        object_binding->state != exact_object_binding_state_v1_read_back ||
        object_binding->profile_generation_ref_id !=
            request->actor.profile_generation_ref_id ||
        !object_binding->exact_object_key_id ||
        object_binding->composite_atom_id !=
            scratch->path_terminal.composite_atom_id)
        return io_uring_application_default_or_hard(
            config, scratch, application_default_allow,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.exact_object_key_id =
        object_binding->exact_object_key_id;
    __builtin_memset(&scratch->effect_key, 0, sizeof(scratch->effect_key));
    scratch->effect_key.profile_generation_ref_id =
        request->actor.profile_generation_ref_id;
    scratch->effect_key.active_role_id = request->actor.active_role_id;
    scratch->effect_key.effect_family = effect_family;
    scratch->effect_key.operation = operation;
    scratch->effect_key.composite_atom_id =
        scratch->observation.composite_atom_id;
    scratch->effect_key.exact_object_key_id =
        scratch->observation.exact_object_key_id;
    scratch->effect_key.process_state_vector_id =
        request->actor.process_state_vector_id;
    scratch->effect_key.binding_lifecycle_state =
        request->actor.binding_lifecycle_state;
    decision = bpf_map_lookup_elem(&effect_decisions, &scratch->effect_key);
    if (!decision) {
        __builtin_memset(&scratch->effect_default, 0,
                         sizeof(scratch->effect_default));
        scratch->effect_default.profile_generation_ref_id =
            scratch->effect_key.profile_generation_ref_id;
        scratch->effect_default.active_role_id =
            scratch->effect_key.active_role_id;
        scratch->effect_default.effect_family =
            scratch->effect_key.effect_family;
        scratch->effect_default.operation = scratch->effect_key.operation;
        scratch->effect_default.composite_atom_id =
            scratch->effect_key.composite_atom_id;
        scratch->effect_default.process_state_vector_id =
            scratch->effect_key.process_state_vector_id;
        scratch->effect_default.binding_lifecycle_state =
            scratch->effect_key.binding_lifecycle_state;
        decision =
            bpf_map_lookup_elem(&effect_defaults, &scratch->effect_default);
    }
    return apply_effect_decision(config, scratch, generation, decision,
                                 application_default_allow, false, false);
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int erebor_io_uring_setup_enter(struct trace_event_raw_sys_enter *context)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    io_uring_setup_state_v1 *state;
    struct io_uring_params *params;
    task_label_v1 *label;
    __u32 flags = 0;
    __u32 sq_thread_cpu = 0;
    __u32 sq_thread_idle = 0;
    __u32 wq_fd = 0;
    __u32 reserved[3] = {};

    if (!config || !config->enabled)
        return 0;
    task = bpf_get_current_task_btf();
    state = bpf_task_storage_get(&io_uring_setup_states, task, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state)
        return 0;
    __builtin_memset(state, 0, sizeof(*state));
    state->entries = (__u32)context->args[0];
    state->setup_attempt_sequence = bpf_ktime_get_ns();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (label)
        state->task_cookie = label->task_cookie;
    params = (struct io_uring_params *)context->args[1];
    if (!params ||
        bpf_probe_read_user(&flags, sizeof(flags), &params->flags) ||
        bpf_probe_read_user(&sq_thread_cpu, sizeof(sq_thread_cpu),
                            &params->sq_thread_cpu) ||
        bpf_probe_read_user(&sq_thread_idle, sizeof(sq_thread_idle),
                            &params->sq_thread_idle) ||
        bpf_probe_read_user(&wq_fd, sizeof(wq_fd), &params->wq_fd) ||
        bpf_probe_read_user(reserved, sizeof(reserved), params->resv)) {
        state->state = io_uring_setup_state_kind_v1_invalid;
        return 0;
    }
    state->flags = flags;
    state->state =
        state->entries > 0 && state->entries <= MAX_IO_URING_ENTRIES_V1 &&
                flags == IORING_SETUP_MITHRIL_V1 && !sq_thread_cpu &&
                !sq_thread_idle && !wq_fd && !reserved[0] && !reserved[1] &&
                !reserved[2]
            ? io_uring_setup_state_kind_v1_prepared
            : io_uring_setup_state_kind_v1_invalid;
    return 0;
}

static __always_inline bool io_uring_anon_name(const struct qstr *name)
{
    char observed[11] = {};
    const unsigned char *source;
    __u32 length;

    if (!name || BPF_CORE_READ_INTO(&length, name, len) || length != 10 ||
        BPF_CORE_READ_INTO(&source, name, name) || !source ||
        bpf_probe_read_kernel_str(observed, sizeof(observed), source) != 11)
        return false;
    return observed[0] == '[' && observed[1] == 'i' && observed[2] == 'o' &&
           observed[3] == '_' && observed[4] == 'u' && observed[5] == 'r' &&
           observed[6] == 'i' && observed[7] == 'n' && observed[8] == 'g' &&
           observed[9] == ']' && observed[10] == '\0';
}

SEC("lsm/inode_init_security_anon")
int BPF_PROG(erebor_identity_inode_init_security_anon, struct inode *inode,
             const struct qstr *name, const struct inode *context_inode,
             int ret)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct task_struct *task;
    io_uring_setup_state_v1 *state;
    io_uring_execution_state_v1 *execution;
    task_label_v1 *label;
    int result;

    (void)inode;
    (void)context_inode;
    if (!config || !config->enabled || !io_uring_anon_name(name))
        return ret;
    task = bpf_get_current_task_btf();
    execution = bpf_task_storage_get(
        &io_uring_execution_states, task, 0,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!execution ||
        execution->state != io_uring_execution_state_kind_v1_inactive)
        return identity_deny(config);
    state = bpf_task_storage_get(&io_uring_setup_states, task, 0, 0);
    if (!state || state->state != io_uring_setup_state_kind_v1_prepared)
        return identity_unqualified_effect_gate(
            kernel_effect_family_v1_privilege,
            kernel_effect_operation_v1_io_uring_setup, ret);
    result = identity_effect_gate_without_exception(
        NULL, kernel_effect_family_v1_privilege,
        kernel_effect_operation_v1_io_uring_setup, ret);
    if (result)
        return result;
    // Setup can finish, but it must not publish authority across activation.
    if (runtime_infrastructure_effect_was_allowed(identity_scratch_record())) {
        state->state = io_uring_setup_state_kind_v1_invalid;
        return 0;
    }
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (label)
        state->task_cookie = label->task_cookie;
    state->state = io_uring_setup_state_kind_v1_authorized;
    return 0;
}

SEC("tp_btf/io_uring_create")
int BPF_PROG(erebor_io_uring_create, int fd, struct io_ring_ctx *context,
             __u32 sq_entries, __u32 cq_entries, __u32 flags)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    struct task_struct *task = bpf_get_current_task_btf();
    io_uring_setup_state_v1 *setup;
    io_uring_ring_state_v1 *existing;
    profile_generation_descriptor_v1 *generation;
    __u64 *async_refs;
    __u64 key = (__u64)context;

    (void)fd;
    if (!config || !config->enabled || !scratch || !context)
        return 0;
    setup = bpf_task_storage_get(&io_uring_setup_states, task, 0, 0);
    if (!setup || setup->state != io_uring_setup_state_kind_v1_authorized ||
        setup->flags != flags || flags != IORING_SETUP_MITHRIL_V1 ||
        !sq_entries || sq_entries > MAX_IO_URING_ENTRIES_V1 ||
        sq_entries < setup->entries || !cq_entries)
        return 0;
    setup->state = io_uring_setup_state_kind_v1_invalid;
    __builtin_memset(&scratch->io_uring_ring_draft, 0,
                     sizeof(scratch->io_uring_ring_draft));
    if (snapshot_io_uring_actor(
            task, scratch, &scratch->io_uring_ring_draft.owner,
            &scratch->io_uring_ring_draft.binding))
        return 0;
    if (setup->task_cookie &&
        setup->task_cookie != scratch->io_uring_ring_draft.owner.task_cookie)
        return 0;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->io_uring_ring_draft.owner.profile_generation_ref_id);
    if (!generation || generation->state != policy_generation_state_v1_active ||
        generation->profile_generation_ref_id !=
            scratch->io_uring_ring_draft.owner.profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id,
                     &scratch->io_uring_ring_draft.owner.profile_id))
        return 0;
    async_refs = bpf_map_lookup_elem(
        &profile_generation_async_refs,
        &scratch->io_uring_ring_draft.owner.profile_generation_ref_id);
    if (!async_refs || !increment_bounded_counter(async_refs))
        return 0;
    if (allocate_id(config, &scratch->io_uring_ring_draft.ring_id)) {
        decrement_nonzero_counter(async_refs);
        return 0;
    }
    scratch->io_uring_ring_draft.context_cookie = key;
    scratch->io_uring_ring_draft.ring_generation = 1;
    scratch->io_uring_ring_draft.next_submission_sequence = 1;
    scratch->io_uring_ring_draft.transition_version = 1;
    scratch->io_uring_ring_draft.sq_entries = sq_entries;
    scratch->io_uring_ring_draft.cq_entries = cq_entries;
    scratch->io_uring_ring_draft.setup_flags = flags;
    scratch->io_uring_ring_draft.state =
        io_uring_ring_state_kind_v1_disabled;
    scratch->io_uring_ring_draft.restriction_state =
        io_uring_restriction_state_v1_none;
    if (bpf_map_update_elem(&io_uring_ring_states, &key,
                            &scratch->io_uring_ring_draft, BPF_NOEXIST)) {
        decrement_nonzero_counter(async_refs);
        existing = bpf_map_lookup_elem(&io_uring_ring_states, &key);
        if (existing) {
            existing->state = io_uring_ring_state_kind_v1_corrupt;
            existing->transition_version++;
        }
    }
    return 0;
}

static __always_inline bool io_uring_exact_restrictions(
    struct io_ring_ctx *context)
{
    unsigned long register_ops = 0;
    unsigned long sqe_ops = 0;
    __u8 allowed = 0;
    __u8 required = 0;
    bool registered = false;

    if (!context ||
        BPF_CORE_READ_INTO(&register_ops, context,
                           restrictions.register_op[0]) ||
        BPF_CORE_READ_INTO(&sqe_ops, context, restrictions.sqe_op[0]) ||
        BPF_CORE_READ_INTO(&allowed, context,
                           restrictions.sqe_flags_allowed) ||
        BPF_CORE_READ_INTO(&required, context,
                           restrictions.sqe_flags_required) ||
        BPF_CORE_READ_INTO(&registered, context, restrictions.registered))
        return false;
    return registered &&
           register_ops == (1UL << IORING_REGISTER_ENABLE_RINGS) &&
           sqe_ops == ((1UL << IORING_OP_READ) | (1UL << IORING_OP_WRITE)) &&
           allowed == IOSQE_ASYNC && required == 0;
}

SEC("tp_btf/io_uring_register")
int BPF_PROG(erebor_io_uring_register, struct io_ring_ctx *context,
             unsigned int opcode, unsigned int nr_files,
             unsigned int nr_buffers, long result)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    io_uring_ring_state_v1 *ring;
    unsigned int context_flags = 0;
    bool restricted;
    __u64 key = (__u64)context;

    (void)nr_files;
    (void)nr_buffers;
    if (!scratch || !context)
        return 0;
    ring = bpf_map_lookup_elem(&io_uring_ring_states, &key);
    if (!ring)
        return 0;
    if (snapshot_io_uring_actor(
            bpf_get_current_task_btf(), scratch, &scratch->io_uring_actor,
            &scratch->io_uring_ring_draft.binding) ||
        !io_uring_actor_equal(&ring->owner, &scratch->io_uring_actor) ||
        !io_uring_binding_equal(&ring->binding,
                                &scratch->io_uring_ring_draft.binding)) {
        ring->state = io_uring_ring_state_kind_v1_corrupt;
        ring->transition_version++;
        return 0;
    }
    if (result)
        return 0;
    if (opcode == IORING_REGISTER_RESTRICTIONS &&
        ring->state == io_uring_ring_state_kind_v1_disabled &&
        io_uring_exact_restrictions(context)) {
        ring->restriction_state =
            io_uring_restriction_state_v1_exact_read_write;
        ring->state = io_uring_ring_state_kind_v1_restricted;
        ring->transition_version++;
        return 0;
    }
    if (opcode == IORING_REGISTER_ENABLE_RINGS &&
        ring->state == io_uring_ring_state_kind_v1_restricted &&
        ring->restriction_state ==
            io_uring_restriction_state_v1_exact_read_write &&
        !BPF_CORE_READ_INTO(&context_flags, context, flags) &&
        (restricted = BPF_CORE_READ_BITFIELD_PROBED(context, restricted)) &&
        context_flags == IORING_SETUP_SINGLE_ISSUER) {
        ring->state = io_uring_ring_state_kind_v1_active;
        ring->transition_version++;
        return 0;
    }
    ring->state = io_uring_ring_state_kind_v1_corrupt;
    ring->transition_version++;
    return 0;
}

static __always_inline __u64 next_io_uring_submission(
    io_uring_ring_state_v1 *ring)
{
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 value = __sync_fetch_and_add(&ring->next_submission_sequence, 0);

        if (!value || value == ~0ULL)
            return 0;
        if (__sync_val_compare_and_swap(&ring->next_submission_sequence, value,
                                        value + 1) == value)
            return value;
    }
    return 0;
}

SEC("tp_btf/io_uring_submit_req")
int BPF_PROG(erebor_io_uring_submit_req, struct io_kiocb *request)
{
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    struct task_struct *submitter = bpf_get_current_task_btf();
    struct task_struct *request_task = NULL;
    struct io_ring_ctx *context = NULL;
    struct io_rw *rw = (struct io_rw *)request;
    io_uring_ring_state_v1 *ring;
    profile_generation_descriptor_v1 *generation;
    __u64 *async_refs;
    __u64 context_key;
    __u64 request_key = (__u64)request;
    __u64 sequence;
    __u64 user_data = 0;
    __u64 buffer_address = 0;
    __s64 file_offset = 0;
    __u64 request_flags = 0;
    __u32 byte_length = 0;
    __u32 rw_flags = 0;
    __u32 cached_head = 0;
    __u8 opcode = 0;

    if (!scratch || !request ||
        BPF_CORE_READ_INTO(&context, request, ctx) || !context ||
        BPF_CORE_READ_INTO(&request_task, request, task) ||
        request_task != submitter ||
        BPF_CORE_READ_INTO(&opcode, request, opcode) ||
        BPF_CORE_READ_INTO(&request_flags, request, flags) ||
        BPF_CORE_READ_INTO(&user_data, request, cqe.user_data) ||
        BPF_CORE_READ_INTO(&file_offset, rw, kiocb.ki_pos) ||
        BPF_CORE_READ_INTO(&buffer_address, rw, addr) ||
        BPF_CORE_READ_INTO(&byte_length, rw, len) ||
        BPF_CORE_READ_INTO(&rw_flags, rw, flags) || !byte_length ||
        file_offset < 0 || rw_flags ||
        (opcode != IORING_OP_READ && opcode != IORING_OP_WRITE))
        return 0;
    context_key = (__u64)context;
    ring = bpf_map_lookup_elem(&io_uring_ring_states, &context_key);
    if (!ring || ring->state != io_uring_ring_state_kind_v1_active ||
        ring->restriction_state !=
            io_uring_restriction_state_v1_exact_read_write ||
        ring->setup_flags != IORING_SETUP_MITHRIL_V1 ||
        snapshot_io_uring_actor(
            submitter, scratch, &scratch->io_uring_actor,
            &scratch->io_uring_ring_draft.binding) ||
        !io_uring_actor_equal(&ring->owner, &scratch->io_uring_actor) ||
        !io_uring_binding_equal(&ring->binding,
                                &scratch->io_uring_ring_draft.binding))
        return 0;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &ring->owner.profile_generation_ref_id);
    if (!generation || generation->state != policy_generation_state_v1_active ||
        generation->profile_generation_ref_id !=
            ring->owner.profile_generation_ref_id ||
        generation->label_epoch != ring->owner.label_epoch ||
        !id128_equal(&generation->node_boot_id, &ring->owner.node_boot_id) ||
        !id128_equal(&generation->profile_id, &ring->owner.profile_id))
        return 0;
    sequence = next_io_uring_submission(ring);
    async_refs = bpf_map_lookup_elem(
        &profile_generation_async_refs,
        &ring->owner.profile_generation_ref_id);
    if (!sequence || !async_refs || !increment_bounded_counter(async_refs))
        return 0;
    if (!increment_counter_below(&ring->outstanding_requests,
                                 ring->sq_entries)) {
        decrement_nonzero_counter(async_refs);
        ring->state = io_uring_ring_state_kind_v1_corrupt;
        ring->transition_version++;
        return 0;
    }
    if (BPF_CORE_READ_INTO(&cached_head, context, cached_sq_head)) {
        decrement_nonzero_counter(&ring->outstanding_requests);
        decrement_nonzero_counter(async_refs);
        return 0;
    }
    __builtin_memset(&scratch->io_uring_request_draft, 0,
                     sizeof(scratch->io_uring_request_draft));
    scratch->io_uring_request_draft.actor = scratch->io_uring_actor;
    scratch->io_uring_request_draft.ring_id = ring->ring_id;
    scratch->io_uring_request_draft.context_cookie = context_key;
    scratch->io_uring_request_draft.request_cookie = request_key;
    scratch->io_uring_request_draft.ring_generation = ring->ring_generation;
    scratch->io_uring_request_draft.submission_sequence = sequence;
    scratch->io_uring_request_draft.user_data = user_data;
    scratch->io_uring_request_draft.file_offset = file_offset;
    scratch->io_uring_request_draft.buffer_address = buffer_address;
    scratch->io_uring_request_draft.transition_version = 1;
    scratch->io_uring_request_draft.byte_length = byte_length;
    scratch->io_uring_request_draft.sqe_index =
        (cached_head - 1) & (ring->sq_entries - 1);
    scratch->io_uring_request_draft.request_flags = (__u32)request_flags;
    scratch->io_uring_request_draft.rw_flags = rw_flags;
    scratch->io_uring_request_draft.opcode = opcode;
    scratch->io_uring_request_draft.state =
        io_uring_request_state_kind_v1_submitted;
    if (bpf_map_update_elem(&io_uring_request_states, &request_key,
                            &scratch->io_uring_request_draft, BPF_NOEXIST)) {
        decrement_nonzero_counter(&ring->outstanding_requests);
        decrement_nonzero_counter(async_refs);
        ring->state = io_uring_ring_state_kind_v1_corrupt;
        ring->transition_version++;
    }
    return 0;
}

SEC("fentry/io_issue_sqe")
int BPF_PROG(erebor_io_uring_issue_enter, struct io_kiocb *request,
             unsigned int issue_flags)
{
    struct task_struct *task = bpf_get_current_task_btf();
    io_uring_execution_state_v1 *execution;
    io_uring_request_state_v1 *request_state;
    io_uring_ring_state_v1 *ring;
    struct io_ring_ctx *context = NULL;
    __u64 request_key = (__u64)request;
    __u64 context_key = 0;
    __u64 user_data = 0;
    __u8 opcode = 0;

    (void)issue_flags;
    execution = bpf_task_storage_get(&io_uring_execution_states, task, 0, 0);
    if (!execution)
        return 0;
    if (execution->state != io_uring_execution_state_kind_v1_inactive) {
        execution->state = io_uring_execution_state_kind_v1_fail_closed;
        return 0;
    }
    __builtin_memset(execution, 0, sizeof(*execution));
    execution->state = io_uring_execution_state_kind_v1_fail_closed;
    if (!request || BPF_CORE_READ_INTO(&context, request, ctx) || !context ||
        BPF_CORE_READ_INTO(&opcode, request, opcode) ||
        BPF_CORE_READ_INTO(&user_data, request, cqe.user_data))
        return 0;
    context_key = (__u64)context;
    request_state = bpf_map_lookup_elem(&io_uring_request_states,
                                        &request_key);
    ring = bpf_map_lookup_elem(&io_uring_ring_states, &context_key);
    if (!request_state || !ring ||
        request_state->state != io_uring_request_state_kind_v1_submitted ||
        ring->state != io_uring_ring_state_kind_v1_active ||
        request_state->context_cookie != context_key ||
        request_state->request_cookie != request_key ||
        request_state->opcode != opcode || request_state->user_data != user_data ||
        !id128_equal(&request_state->ring_id, &ring->ring_id))
        return 0;
    execution->ring_id = request_state->ring_id;
    execution->context_cookie = context_key;
    execution->request_cookie = request_key;
    execution->submission_sequence = request_state->submission_sequence;
    execution->user_data = user_data;
    execution->executor_pid_tgid = bpf_get_current_pid_tgid();
    execution->opcode = opcode;
    execution->state = io_uring_execution_state_kind_v1_active;
    return 0;
}

SEC("fexit/io_issue_sqe")
int BPF_PROG(erebor_io_uring_issue_exit, struct io_kiocb *request,
             unsigned int issue_flags, int result)
{
    io_uring_execution_state_v1 *execution = bpf_task_storage_get(
        &io_uring_execution_states, bpf_get_current_task_btf(), 0, 0);

    (void)request;
    (void)issue_flags;
    (void)result;
    if (execution)
        __builtin_memset(execution, 0, sizeof(*execution));
    return 0;
}

static __always_inline void release_io_uring_request(
    __u64 request_key, io_uring_request_state_v1 *request)
{
    io_uring_ring_state_v1 *ring;
    __u64 *async_refs;

    if (!request)
        return;
    ring = bpf_map_lookup_elem(&io_uring_ring_states,
                               &request->context_cookie);
    async_refs = bpf_map_lookup_elem(
        &profile_generation_async_refs,
        &request->actor.profile_generation_ref_id);
    if (!async_refs || !decrement_nonzero_counter(async_refs)) {
        identity_health_v1 *health = identity_health_record();
        if (health)
            health->reconciliation_required++;
        if (ring && id128_equal(&ring->ring_id, &request->ring_id)) {
            ring->state = io_uring_ring_state_kind_v1_corrupt;
            ring->transition_version++;
        }
    }
    if (ring && id128_equal(&ring->ring_id, &request->ring_id)) {
        if (!decrement_nonzero_counter(&ring->outstanding_requests)) {
            ring->state = io_uring_ring_state_kind_v1_corrupt;
            ring->transition_version++;
        }
    }
    bpf_map_delete_elem(&io_uring_request_states, &request_key);
}

SEC("tp_btf/io_uring_complete")
int BPF_PROG(erebor_io_uring_complete, struct io_ring_ctx *context,
             struct io_kiocb *request, __u64 user_data, int result,
             unsigned int cflags, __u64 extra1, __u64 extra2)
{
    __u64 key = (__u64)request;
    io_uring_request_state_v1 *state =
        bpf_map_lookup_elem(&io_uring_request_states, &key);

    (void)context;
    (void)user_data;
    (void)result;
    (void)cflags;
    (void)extra1;
    (void)extra2;
    release_io_uring_request(key, state);
    return 0;
}

struct io_uring_cleanup_context_v1 {
    __u64 context_cookie;
    id128_v1 ring_id;
};

static long cleanup_io_uring_request(struct bpf_map *map, const __u64 *key,
                                     io_uring_request_state_v1 *request,
                                     struct io_uring_cleanup_context_v1 *cleanup)
{
    (void)map;
    if (request && cleanup &&
        request->context_cookie == cleanup->context_cookie &&
        id128_equal(&request->ring_id, &cleanup->ring_id))
        release_io_uring_request(*key, request);
    return 0;
}

SEC("fentry/io_ring_ctx_free")
int BPF_PROG(erebor_io_uring_context_free, struct io_ring_ctx *context)
{
    __u64 key = (__u64)context;
    io_uring_ring_state_v1 *ring =
        bpf_map_lookup_elem(&io_uring_ring_states, &key);
    struct io_uring_cleanup_context_v1 cleanup = {};
    __u64 *async_refs;
    long result;

    if (!ring)
        return 0;
    cleanup.context_cookie = key;
    cleanup.ring_id = ring->ring_id;
    result = bpf_for_each_map_elem(&io_uring_request_states,
                                   cleanup_io_uring_request, &cleanup, 0);
    ring = bpf_map_lookup_elem(&io_uring_ring_states, &key);
    if (!ring || !id128_equal(&ring->ring_id, &cleanup.ring_id))
        return 0;
    if (result < 0 || ring->outstanding_requests) {
        ring->state = io_uring_ring_state_kind_v1_corrupt;
        ring->transition_version++;
        return 0;
    }
    async_refs = bpf_map_lookup_elem(
        &profile_generation_async_refs,
        &ring->owner.profile_generation_ref_id);
    if (!async_refs || !decrement_nonzero_counter(async_refs)) {
        ring->state = io_uring_ring_state_kind_v1_corrupt;
        ring->transition_version++;
        return 0;
    }
    ring->state = io_uring_ring_state_kind_v1_closed;
    ring->transition_version++;
    bpf_map_delete_elem(&io_uring_ring_states, &key);
    return 0;
}

SEC("lsm/uring_sqpoll")
int BPF_PROG(erebor_identity_uring_sqpoll, int ret)
{
    return identity_unqualified_effect_gate(
        kernel_effect_family_v1_privilege,
        kernel_effect_operation_v1_io_uring_sqpoll, ret);
}

SEC("lsm/uring_override_creds")
int BPF_PROG(erebor_identity_uring_override_creds, const struct cred *new,
             int ret)
{
    (void)new;
    return identity_unqualified_effect_gate(
        kernel_effect_family_v1_privilege,
        kernel_effect_operation_v1_io_uring_override_creds, ret);
}

SEC("lsm/uring_cmd")
int BPF_PROG(erebor_identity_uring_cmd, struct io_uring_cmd *command, int ret)
{
    (void)command;
    return identity_unqualified_effect_gate(
        kernel_effect_family_v1_privilege,
        kernel_effect_operation_v1_io_uring_command, ret);
}

#endif /* EREBOR_IDENTITY_IO_URING_BPF_H */
