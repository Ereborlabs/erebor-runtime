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

static __noinline int identity_effect_gate(struct file *exec_file, int ret)
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
    struct identity_scratch_v1 *scratch;
    process_security_state_v1 *snapshot;
    pending_exec_v1 *pending;
    __u64 *profile_task_refs;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (ret)
        return ret;
    config = identity_runtime_config();
    if (!config || !config->enabled)
        return 0;
    health = identity_health_record();
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
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
    if (!label_matches_runtime(label, config) ||
        !binding_matches_label(binding, label)) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    scratch = identity_scratch_record();
    snapshot = scratch ? &scratch->process : NULL;
    if (!coordinate || coordinate->state != task_coordinate_state_v1_runnable ||
        !scratch || refresh_real_parent(task, label, coordinate, scratch) ||
        snapshot_process_state(process, snapshot) ||
        snapshot->state != process_security_state_kind_v1_active ||
        !snapshot->live_thread_refs || !entry ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs)
        return identity_deny(config);
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
    if (!id128_equal(&snapshot->entry_instance_id, &label->entry_instance_id) ||
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
        !profile_task_refs ||
        __sync_fetch_and_add(profile_task_refs, 0) == 0)
        return identity_deny(config);
    if (snapshot->exec_guard_state == exec_guard_state_v1_none)
        return 0;
    if (!exec_file)
        return identity_deny(config);
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    if (!pending ||
        (snapshot->exec_guard_state != exec_guard_state_v1_preparing &&
         snapshot->exec_guard_state != exec_guard_state_v1_commit_pending) ||
        !id128_equal(&pending->process_state_id, &label->process_state_id) ||
        ((snapshot->exec_guard_state == exec_guard_state_v1_preparing) !=
         (pending->state == pending_exec_state_v1_preparing)) ||
        ((snapshot->exec_guard_state == exec_guard_state_v1_commit_pending) !=
         (pending->state == pending_exec_state_v1_commit_pending)))
        return identity_deny(config);
    candidate_from_file(&scratch->image.ordered_candidates[0], exec_file);
    if (!scratch->image.ordered_candidates[0].mount_id)
        return identity_deny(config);
    if (pending_contains_candidate(
            pending, &scratch->image.ordered_candidates[0]))
        return 0;
    if (pending->state == pending_exec_state_v1_preparing &&
        !append_exec_candidate(pending,
                               &scratch->image.ordered_candidates[0]))
        return 0;
    return identity_deny(config);
}

SEC("lsm/file_open")
int BPF_PROG(erebor_identity_file_open, struct file *file, int ret)
{
    return identity_effect_gate(file, ret);
}

SEC("lsm/file_permission")
int BPF_PROG(erebor_identity_file_permission, struct file *file, int mask,
             int ret)
{
    return identity_effect_gate(file, ret);
}

SEC("lsm/file_ioctl")
int BPF_PROG(erebor_identity_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/mmap_file")
int BPF_PROG(erebor_identity_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags,
             int ret)
{
    return identity_effect_gate(file, ret);
}

SEC("lsm/file_mprotect")
int BPF_PROG(erebor_identity_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/ipc_permission")
int BPF_PROG(erebor_identity_ipc_permission, struct kern_ipc_perm *ipcp,
             short flag, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/socket_connect")
int BPF_PROG(erebor_identity_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(erebor_identity_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(erebor_identity_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/task_kill")
int BPF_PROG(erebor_identity_task_kill, struct task_struct *task,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/path_unlink")
int BPF_PROG(erebor_identity_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/path_link")
int BPF_PROG(erebor_identity_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/path_rename")
int BPF_PROG(erebor_identity_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/sb_mount")
int BPF_PROG(erebor_identity_sb_mount, const char *dev_name,
             const struct path *path, const char *type, unsigned long flags,
             void *data, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/sb_umount")
int BPF_PROG(erebor_identity_sb_umount, struct vfsmount *mnt, int flags,
             int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(erebor_identity_sb_pivotroot, const struct path *old_path,
             const struct path *new_path, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/move_mount")
int BPF_PROG(erebor_identity_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/capable")
int BPF_PROG(erebor_identity_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
    return identity_effect_gate(NULL, ret);
}

SEC("lsm/bpf")
int BPF_PROG(erebor_identity_bpf, int cmd, union bpf_attr *attr,
             unsigned int size, int ret)
{
    return identity_effect_gate(NULL, ret);
}

#endif /* EREBOR_IDENTITY_EFFECTS_BPF_H */
