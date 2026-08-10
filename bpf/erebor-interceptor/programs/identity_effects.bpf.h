/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_EFFECTS_BPF_H
#define EREBOR_IDENTITY_EFFECTS_BPF_H

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

    if (health)
        health->attempted++;
    if (!scratch) {
        if (health)
            health->lost++;
        return result;
    }
    scratch->observation.kernel_result = result;
    scratch->observation.reason = reason;
    scratch->observation.physical_result = physical_result;
    event = bpf_ringbuf_reserve(&effect_observations, sizeof(*event), 0);
    if (!event) {
        if (health)
            health->lost++;
        return result;
    }
    __builtin_memcpy(event, &scratch->observation, sizeof(*event));
    bpf_ringbuf_submit(event, 0);
    if (health)
        health->emitted++;
    return result;
}

static __always_inline int hard_effect_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    __u8 reason)
{
    int result = identity_deny(config);

    if (reason == effect_observation_reason_v1_unresolved_object ||
        reason == effect_observation_reason_v1_unsupported_object) {
        effect_observation_health_v1 *health = effect_health_record();
        if (health)
            health->unresolved++;
    }
    return emit_effect_observation(
        scratch, result, reason,
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
    scratch->observation.entry_kind = entry->entry_kind;
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
    scratch->effect_key.entry_kind = entry->entry_kind;
    scratch->effect_key.effect_family = scratch->observation.effect_family;
    scratch->effect_key.operation = scratch->observation.operation;
    scratch->effect_key.composite_atom_id =
        scratch->observation.composite_atom_id;
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
    scratch->effect_default.entry_kind = scratch->effect_key.entry_kind;
    scratch->effect_default.effect_family = scratch->effect_key.effect_family;
    scratch->effect_default.operation = scratch->effect_key.operation;
    scratch->effect_default.composite_atom_id =
        scratch->effect_key.composite_atom_id;
    scratch->effect_default.process_state_vector_id =
        scratch->effect_key.process_state_vector_id;
    scratch->effect_default.binding_lifecycle_state =
        scratch->effect_key.binding_lifecycle_state;
    return bpf_map_lookup_elem(&effect_defaults, &scratch->effect_default);
}

static __always_inline exact_object_binding_v1 *file_object_binding(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    __u64 profile_generation_ref_id)
{
    exact_object_binding_v1 candidate = {};
    exact_object_binding_v1 *binding;
    id128_v1 allocated = {};

    binding = bpf_map_lookup_elem(&exact_file_objects,
                                  &scratch->file_object);
    if (binding)
        return binding;
    if (allocate_id(config, &allocated) || !allocated.low ||
        (allocated.low & (1ULL << 63)))
        return NULL;
    candidate.profile_generation_ref_id = profile_generation_ref_id;
    candidate.exact_object_key_id = allocated.low | (1ULL << 63);
    candidate.composite_atom_id = scratch->path_terminal.composite_atom_id;
    candidate.state = exact_object_binding_state_v1_active_dynamic;
    bpf_map_update_elem(&exact_file_objects, &scratch->file_object,
                        &candidate, BPF_NOEXIST);
    return bpf_map_lookup_elem(&exact_file_objects, &scratch->file_object);
}

static __noinline int identity_effect_gate(struct file *file,
                                           __u16 effect_family,
                                           __u16 operation, int ret)
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
    process_security_state_v1 *snapshot;
    pending_exec_v1 *pending;
    __u64 *profile_task_refs;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    config = identity_runtime_config();
    if (!config || !config->enabled)
        return ret;
    scratch = identity_scratch_record();
    if (scratch)
        begin_effect_observation(scratch, effect_family, operation);
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
    snapshot = scratch ? &scratch->process : NULL;
    if (!coordinate || coordinate->state != task_coordinate_state_v1_runnable ||
        !scratch || refresh_real_parent(task, label, coordinate, scratch) ||
        snapshot_process_state(process, snapshot) ||
        snapshot->state != process_security_state_kind_v1_active ||
        !snapshot->live_thread_refs || !entry ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &snapshot->authority_domain_id);
    execution = bpf_map_lookup_elem(&process_execution_instances,
                                    &snapshot->active_execution_id);
    image = execution ? bpf_map_lookup_elem(
                            &image_provenance,
                            &execution->image_provenance_id)
                      : NULL;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &snapshot->active_profile_generation_ref_id);
    process_vector = bpf_map_lookup_elem(&process_state_vectors,
                                         &label->process_state_id);
    if (!id128_equal(&snapshot->entry_instance_id,
                     &label->entry_instance_id) ||
        !domain || domain->state != authority_domain_state_kind_v1_active ||
        !domain->live_process_refs ||
        domain->label_epoch != config->label_epoch ||
        !id128_equal(&domain->node_boot_id, &config->node_boot_id) ||
        !execution ||
        execution->state != process_execution_state_v1_active ||
        !id128_equal(&execution->process_lineage_id,
                     &snapshot->process_lineage_id) ||
        !image || image->state != image_provenance_state_v1_active ||
        !process_vector ||
        process_vector->state != process_state_vector_state_v1_active ||
        process_vector->process_state_vector_id !=
            snapshot->process_state_vector_id ||
        process_vector->profile_generation_ref_id !=
            snapshot->active_profile_generation_ref_id ||
        process_vector->label_epoch != snapshot->label_epoch ||
        !id128_equal(&process_vector->node_boot_id, &snapshot->node_boot_id) ||
        !profile_task_refs || __sync_fetch_and_add(profile_task_refs, 0) == 0)
        return identity_or_prior_effect_result(
            config, scratch, ret,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    populate_effect_actor(scratch, label, snapshot, entry, domain);
    scratch->observation.binding_id = binding->binding_id;
    scratch->observation.execution_set_id = binding->execution_set_id;
    if (ret)
        return emit_effect_observation(
            scratch, ret, effect_observation_reason_v1_prior_lsm_denial,
            effect_physical_result_v1_denied_before_effect);
    if (snapshot->exec_guard_state != exec_guard_state_v1_none) {
        if (!file)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
        if (!pending ||
            (snapshot->exec_guard_state != exec_guard_state_v1_preparing &&
             snapshot->exec_guard_state !=
                 exec_guard_state_v1_commit_pending) ||
            !id128_equal(&pending->process_state_id,
                         &label->process_state_id) ||
            ((snapshot->exec_guard_state == exec_guard_state_v1_preparing) !=
             (pending->state == pending_exec_state_v1_preparing)) ||
            ((snapshot->exec_guard_state ==
              exec_guard_state_v1_commit_pending) !=
             (pending->state == pending_exec_state_v1_commit_pending)))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        candidate_from_file(&scratch->image.ordered_candidates[0], file);
        if (!scratch->image.ordered_candidates[0].mount_id)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_unresolved_object);
        if (!pending_contains_candidate(
                pending, &scratch->image.ordered_candidates[0]) &&
            !(pending->state == pending_exec_state_v1_preparing &&
              !append_exec_candidate(
                  pending, &scratch->image.ordered_candidates[0])))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    if (!config->effect_observation_enabled)
        return ret;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &snapshot->active_profile_generation_ref_id);
    if (!generation ||
        generation->state != policy_generation_state_v1_read_back ||
        generation->label_epoch != config->label_epoch ||
        generation->profile_generation_ref_id !=
            snapshot->active_profile_generation_ref_id ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    if (!file)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    exact_file_object_from_file(&scratch->file_object, file);
    scratch->file_object.profile_generation_ref_id =
        snapshot->active_profile_generation_ref_id;
    scratch->observation.file_object = scratch->file_object;
    if (!scratch->file_object.mount_id_unique)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    if (canonical_path_candidate(
            file, binding, snapshot->active_profile_generation_ref_id,
            scratch))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.composite_atom_id =
        scratch->path_terminal.composite_atom_id;
    object_binding = file_object_binding(
        config, scratch, snapshot->active_profile_generation_ref_id);
    if (!object_binding ||
        (object_binding->state != exact_object_binding_state_v1_read_back &&
         object_binding->state !=
             exact_object_binding_state_v1_active_dynamic) ||
        object_binding->profile_generation_ref_id !=
            snapshot->active_profile_generation_ref_id ||
        !object_binding->exact_object_key_id ||
        !object_binding->composite_atom_id ||
        object_binding->composite_atom_id !=
            scratch->path_terminal.composite_atom_id)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.exact_object_key_id =
        object_binding->exact_object_key_id;
    decision = effect_base_decision(scratch, snapshot, process_vector, entry,
                                    binding);
    if (!decision)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    scratch->observation.configured_errno = decision->errno;
    if (decision->decision == physical_decision_kind_v1_deny)
        return emit_effect_observation(
            scratch, 0, effect_observation_reason_v1_would_deny,
            effect_physical_result_v1_unknown_after_pre_effect);
    if (decision->decision == physical_decision_kind_v1_audit_allow)
        return emit_effect_observation(
            scratch, 0,
            effect_observation_reason_v1_exact_policy_audit_allow,
            effect_physical_result_v1_unknown_after_pre_effect);
    if (decision->decision == physical_decision_kind_v1_allow)
        return emit_effect_observation(
            scratch, 0, effect_observation_reason_v1_exact_policy_allow,
            effect_physical_result_v1_unknown_after_pre_effect);
    return hard_effect_result(
        config, scratch,
        effect_observation_reason_v1_corrupt_identity_or_generation);
}

static __always_inline int file_mode_effects(struct file *file, int ret)
{
    fmode_t mode = 0;

    if (BPF_CORE_READ_INTO(&mode, file, f_mode))
        return identity_effect_gate(
            file, kernel_effect_family_v1_file,
            kernel_effect_operation_v1_unknown, ret);
    if (mode & FMODE_READ)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_open_read,
                                   ret);
    if (ret)
        return ret;
    if (mode & FMODE_WRITE)
        ret = identity_effect_gate(file, kernel_effect_family_v1_file,
                                   kernel_effect_operation_v1_open_write,
                                   ret);
    return ret;
}

SEC("lsm/file_open")
int BPF_PROG(erebor_identity_file_open, struct file *file, int ret)
{
    return file_mode_effects(file, ret);
}

SEC("lsm/file_permission")
int BPF_PROG(erebor_identity_file_permission, struct file *file, int mask,
             int ret)
{
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
    /* Command and argument shape are not yet physically qualified. */
    return identity_effect_gate(NULL, kernel_effect_family_v1_device,
                                kernel_effect_operation_v1_ioctl, ret);
}

SEC("lsm/mmap_file")
int BPF_PROG(erebor_identity_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags,
             int ret)
{
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

SEC("lsm/ipc_permission")
int BPF_PROG(erebor_identity_ipc_permission, struct kern_ipc_perm *ipcp,
             short flag, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_ipc,
                                kernel_effect_operation_v1_ipc_access, ret);
}

SEC("lsm/socket_connect")
int BPF_PROG(erebor_identity_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_network,
                                kernel_effect_operation_v1_connect, ret);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(erebor_identity_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_network,
                                kernel_effect_operation_v1_send, ret);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(erebor_identity_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_privilege,
                                kernel_effect_operation_v1_ptrace, ret);
}

SEC("lsm/task_kill")
int BPF_PROG(erebor_identity_task_kill, struct task_struct *task,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_privilege,
                                kernel_effect_operation_v1_signal, ret);
}

SEC("lsm/path_unlink")
int BPF_PROG(erebor_identity_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_file,
                                kernel_effect_operation_v1_unlink, ret);
}

SEC("lsm/path_link")
int BPF_PROG(erebor_identity_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_file,
                                kernel_effect_operation_v1_link, ret);
}

SEC("lsm/path_rename")
int BPF_PROG(erebor_identity_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_file,
                                kernel_effect_operation_v1_rename, ret);
}

SEC("lsm/sb_mount")
int BPF_PROG(erebor_identity_sb_mount, const char *dev_name,
             const struct path *path, const char *type, unsigned long flags,
             void *data, int ret)
{
    int dirty = begin_mount_mutation();
    if (ret)
        return ret;
    if (dirty)
        return dirty;
    return identity_effect_gate(NULL, kernel_effect_family_v1_mount,
                                kernel_effect_operation_v1_mount, ret);
}

SEC("lsm/sb_umount")
int BPF_PROG(erebor_identity_sb_umount, struct vfsmount *mnt, int flags,
             int ret)
{
    int dirty = begin_mount_mutation();
    if (ret)
        return ret;
    if (dirty)
        return dirty;
    return identity_effect_gate(NULL, kernel_effect_family_v1_mount,
                                kernel_effect_operation_v1_unmount, ret);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(erebor_identity_sb_pivotroot, const struct path *old_path,
             const struct path *new_path, int ret)
{
    int dirty = begin_mount_mutation();
    if (ret)
        return ret;
    if (dirty)
        return dirty;
    return identity_effect_gate(NULL, kernel_effect_family_v1_mount,
                                kernel_effect_operation_v1_pivot_root, ret);
}

SEC("lsm/move_mount")
int BPF_PROG(erebor_identity_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    int dirty = begin_mount_mutation();
    if (ret)
        return ret;
    if (dirty)
        return dirty;
    return identity_effect_gate(NULL, kernel_effect_family_v1_mount,
                                kernel_effect_operation_v1_move_mount, ret);
}

SEC("lsm/capable")
int BPF_PROG(erebor_identity_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
    return identity_effect_gate(NULL, kernel_effect_family_v1_privilege,
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
