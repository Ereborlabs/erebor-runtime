// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright Erebor Labs and contributors */
#include "vmlinux.h"
#include "erebor_interceptor_abi.h"
#include "linux_uapi.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "identity_maps.h"

_Static_assert(sizeof(task_label_v1) == 328, "task label ABI size");
_Static_assert(sizeof(task_coordinate_v1) == 96, "task coordinate ABI size");
_Static_assert(sizeof(identity_runtime_config_v1) == 40,
               "identity runtime config ABI size");
_Static_assert(__builtin_offsetof(task_label_v1, process_state_id) == 64,
               "task process-state offset");

static __always_inline void candidate_from_file(
    exact_executable_candidate_v1 *candidate, struct file *file)
{
    struct inode *inode = NULL;
    struct super_block *superblock = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *mount = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    int mount_id = 0;

    candidate->mount_namespace_inode = 0;
    candidate->mount_id = 0;
    candidate->filesystem_device = 0;
    candidate->inode = 0;
    candidate->inode_generation = 0;
    if (!file || BPF_CORE_READ_INTO(&inode, file, f_inode) ||
        !inode || BPF_CORE_READ_INTO(&superblock, inode, i_sb) ||
        !superblock || BPF_CORE_READ_INTO(&vfsmount, file, f_path.mnt) ||
        !vfsmount)
        return;
    mount = container_of(vfsmount, struct mount, mnt);
    if (BPF_CORE_READ_INTO(&mount_namespace, mount, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&mount_id, mount, mnt_id) || mount_id <= 0 ||
        BPF_CORE_READ_INTO(&candidate->mount_namespace_inode, mount_namespace,
                           ns.inum) ||
        !candidate->mount_namespace_inode ||
        BPF_CORE_READ_INTO(&candidate->filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&candidate->inode, inode, i_ino) ||
        !candidate->inode ||
        BPF_CORE_READ_INTO(&candidate->inode_generation, inode, i_generation))
        return;
    candidate->mount_id = mount_id;
}

static __always_inline int prepare_task_image(
    struct task_struct *task, struct identity_scratch_v1 *scratch,
    const id128_v1 *image_provenance_id)
{
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;

    if (BPF_CORE_READ_INTO(&mm, task, mm) || !mm ||
        BPF_CORE_READ_INTO(&executable, mm, exe_file) || !executable)
        return -EACCES;
    scratch->image.image_provenance_id = *image_provenance_id;
    scratch->image.candidate_count = 1;
#pragma unroll
    for (int index = 0; index < 6; index++)
        scratch->image.reserved_0[index] = 0;
    candidate_from_file(&scratch->image.ordered_candidates[0], executable);
    if (!scratch->image.ordered_candidates[0].mount_id)
        return -EACCES;
#pragma unroll
    for (int index = 1; index < MAX_EXEC_CANDIDATES_V1; index++) {
        scratch->image.ordered_candidates[index].mount_namespace_inode = 0;
        scratch->image.ordered_candidates[index].mount_id = 0;
        scratch->image.ordered_candidates[index].filesystem_device = 0;
        scratch->image.ordered_candidates[index].inode = 0;
        scratch->image.ordered_candidates[index].inode_generation = 0;
    }
    scratch->image.transition_version = 1;
    scratch->image.state = image_provenance_state_v1_active;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->image.reserved_1[index] = 0;
    return 0;
}

static __always_inline int read_real_parent_interval(
    struct task_struct *task, __u64 child_task_cookie, __u8 change_reason,
    kernel_real_parent_interval_v1 *interval)
{
    struct task_struct *parent = NULL;
    struct pid *thread_pid = NULL;
    struct pid_namespace *pid_namespace = NULL;
    task_label_v1 *parent_label;
    __u32 level = 0;

    if (!task || !interval ||
        BPF_CORE_READ_INTO(&parent, task, real_parent) || !parent)
        return -EACCES;
    interval->child_task_cookie = child_task_cookie;
    parent_label = bpf_task_storage_get(&task_labels, parent, 0, 0);
    interval->real_parent_task_cookie =
        parent_label ? parent_label->task_cookie : 0;
    BPF_CORE_READ_INTO(&interval->real_parent_host_tid, parent, pid);
    BPF_CORE_READ_INTO(&interval->real_parent_host_tgid, parent, tgid);
    BPF_CORE_READ_INTO(&thread_pid, parent, thread_pid);
    if (thread_pid)
        BPF_CORE_READ_INTO(&level, thread_pid, level);
    if (thread_pid && level < 32)
        BPF_CORE_READ_INTO(&pid_namespace, thread_pid, numbers[level].ns);
    if (pid_namespace)
        BPF_CORE_READ_INTO(&interval->real_parent_pid_namespace_inode,
                           pid_namespace, ns.inum);
    else
        interval->real_parent_pid_namespace_inode = 0;
    if (bpf_core_field_exists(parent->start_boottime))
        BPF_CORE_READ_INTO(&interval->real_parent_start_boottime_ns, parent,
                           start_boottime);
    else
        BPF_CORE_READ_INTO(&interval->real_parent_start_boottime_ns, parent,
                           start_time);
    if (!interval->real_parent_host_tid ||
        !interval->real_parent_host_tgid ||
        !interval->real_parent_pid_namespace_inode ||
        !interval->real_parent_start_boottime_ns)
        return -EACCES;
    interval->interval_start_boottime_ns = bpf_ktime_get_ns();
    interval->interval_end_boottime_ns = 0;
    interval->transition_version = 1;
    interval->change_reason = change_reason;
    interval->kernel_direct_proof = 1;
#pragma unroll
    for (int index = 0; index < 6; index++)
        interval->reserved[index] = 0;
    return 0;
}

static __always_inline bool real_parent_equal(
    const kernel_real_parent_interval_v1 *left,
    const kernel_real_parent_interval_v1 *right)
{
    return left->real_parent_task_cookie == right->real_parent_task_cookie &&
           left->real_parent_host_tid == right->real_parent_host_tid &&
           left->real_parent_host_tgid == right->real_parent_host_tgid &&
           left->real_parent_pid_namespace_inode ==
               right->real_parent_pid_namespace_inode &&
           left->real_parent_start_boottime_ns ==
               right->real_parent_start_boottime_ns;
}

static __always_inline int refresh_real_parent(
    struct task_struct *task, const task_label_v1 *label,
    task_coordinate_v1 *coordinate, struct identity_scratch_v1 *scratch)
{
    kernel_real_parent_interval_key_v1 key = {
        .child_task_cookie = label->task_cookie,
        .interval_sequence = coordinate->real_parent_interval_sequence,
    };
    kernel_real_parent_interval_v1 *current;
    __u64 next_sequence;

    current = bpf_map_lookup_elem(&kernel_real_parent_intervals, &key);
    if (!current ||
        read_real_parent_interval(
            task, label->task_cookie,
            kernel_real_parent_change_reason_v1_parent_exit_or_reparent,
            &scratch->real_parent))
        return -EACCES;
    if (real_parent_equal(current, &scratch->real_parent))
        return 0;
    next_sequence = coordinate->real_parent_interval_sequence + 1;
    if (!next_sequence)
        return -EACCES;
    current->interval_end_boottime_ns = bpf_ktime_get_ns();
    current->transition_version++;
    key.interval_sequence = next_sequence;
    if (bpf_map_update_elem(&kernel_real_parent_intervals, &key,
                            &scratch->real_parent, BPF_NOEXIST))
        return -EACCES;
    coordinate->real_parent_interval_sequence = next_sequence;
    coordinate->transition_version++;
    return 0;
}

static __always_inline void delete_initial_real_parent(__u64 task_cookie)
{
    kernel_real_parent_interval_key_v1 key = {
        .child_task_cookie = task_cookie,
        .interval_sequence = 1,
    };

    bpf_map_delete_elem(&kernel_real_parent_intervals, &key);
}

static __always_inline void prepare_execution(
    process_execution_instance_v1 *execution, const id128_v1 *execution_id,
    const id128_v1 *lineage_id, const id128_v1 *image_provenance_id,
    __u8 started_by, __u8 state)
{
    execution->process_execution_instance_id = *execution_id;
    execution->process_lineage_id = *lineage_id;
    execution->image_provenance_id = *image_provenance_id;
    execution->start_boottime_ns = bpf_ktime_get_ns();
    execution->end_boottime_ns = 0;
    execution->transition_version = 1;
    execution->started_by = started_by;
    execution->state = state;
#pragma unroll
    for (int index = 0; index < 6; index++)
        execution->reserved[index] = 0;
}

static __always_inline int publish_task(struct task_struct *task,
                                        struct identity_scratch_v1 *scratch)
{
    kernel_real_parent_interval_key_v1 parent_key = {
        .child_task_cookie = scratch->label.task_cookie,
        .interval_sequence = 1,
    };
    task_label_v1 *installed;

    if (bpf_map_update_elem(&kernel_real_parent_intervals, &parent_key,
                            &scratch->real_parent, BPF_NOEXIST))
        return -EACCES;
    if (bpf_map_update_elem(&task_coordinates, &scratch->label.task_cookie,
                            &scratch->coordinate, BPF_NOEXIST)) {
        bpf_map_delete_elem(&kernel_real_parent_intervals, &parent_key);
        return -EACCES;
    }
    if (bpf_map_update_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie, &scratch->tombstone,
                            BPF_NOEXIST)) {
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        bpf_map_delete_elem(&kernel_real_parent_intervals, &parent_key);
        return -EACCES;
    }
    installed = bpf_task_storage_get(&task_labels, task, 0,
                                     BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!installed) {
        bpf_map_delete_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie);
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        bpf_map_delete_elem(&kernel_real_parent_intervals, &parent_key);
        return -EACCES;
    }
    *installed = scratch->label;
    __asm__ volatile("" ::: "memory");
    if (installed->task_cookie != scratch->label.task_cookie ||
        !id128_equal(&installed->process_state_id,
                     &scratch->label.process_state_id) ||
        !id128_equal(&installed->entry_instance_id,
                     &scratch->label.entry_instance_id) ||
        !id128_equal(&installed->placement.protected_root_binding_id,
                     &scratch->label.placement.protected_root_binding_id)) {
        bpf_task_storage_delete(&task_labels, task);
        bpf_map_delete_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie);
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        bpf_map_delete_elem(&kernel_real_parent_intervals, &parent_key);
        return -EACCES;
    }
    return 0;
}

static __always_inline void prepare_child_process(
    process_security_state_v1 *target, const process_security_state_v1 *parent,
    const task_label_v1 *child)
{
    target->process_state_id = child->process_state_id;
    target->node_boot_id = child->node_boot_id;
    target->label_epoch = child->label_epoch;
    target->process_lineage_id = child->process_lineage_id;
    target->process_instance_id = child->process_instance_id;
    target->entry_instance_id = child->entry_instance_id;
    target->entry_root_process_state_id = parent->entry_root_process_state_id;
    target->active_execution_id = child->birth_execution_id;
    target->active_role_id = parent->active_role_id;
    target->process_state_vector_id = parent->process_state_vector_id;
    target->active_profile_generation_ref_id =
        parent->active_profile_generation_ref_id;
    target->authority_domain_id = parent->authority_domain_id;
    target->effective_response_set_ref_id =
        parent->effective_response_set_ref_id;
    zero_id(&target->pending_exec_id);
    zero_id(&target->pending_target_execution_id);
    target->pending_target_role_id = 0;
    target->reserved_pending_role = 0;
    target->transition_guard = 0;
    target->pending_exec_response_set_ref_id = 0;
    target->exec_check_task_cookie = 0;
    target->transition_version = 1;
    target->live_thread_refs = 1;
    target->exec_guard_state = exec_guard_state_v1_none;
    target->state = process_security_state_kind_v1_allocating;
#pragma unroll
    for (int index = 0; index < 6; index++)
        target->reserved[index] = 0;
}

static __always_inline void prepare_process_vector(
    process_state_vector_v1 *target, const task_label_v1 *label,
    __u64 profile_generation_ref_id, __u64 state_bits)
{
    target->node_boot_id = label->node_boot_id;
    target->label_epoch = label->label_epoch;
    target->state_bits = state_bits;
    target->profile_generation_ref_id = profile_generation_ref_id;
    target->transition_version = 1;
    target->process_state_vector_id = CONSERVATIVE_PROCESS_STATE_VECTOR_V1;
    target->state = process_state_vector_state_v1_preparing;
#pragma unroll
    for (int index = 0; index < 3; index++)
        target->reserved[index] = 0;
}

static __always_inline int create_native_child(
    struct task_struct *task, unsigned long clone_flags,
    identity_runtime_config_v1 *config, const task_label_v1 *parent_label,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch)
{
    bool thread = (clone_flags & CLONE_THREAD) != 0;
    id128_v1 task_identity;
    process_security_state_v1 *parent_process;
    process_state_vector_v1 *parent_vector;
    process_execution_instance_v1 *parent_execution;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    __u64 *profile_task_refs;

    parent_process = bpf_map_lookup_elem(&process_states,
                                         &parent_label->process_state_id);
    parent_vector = bpf_map_lookup_elem(&process_state_vectors,
                                        &parent_label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states,
                                &parent_label->entry_instance_id);
    if (!parent_process || !parent_vector || !entry)
        return identity_deny(config);
    domain = bpf_map_lookup_elem(&authority_domains,
                                 &parent_process->authority_domain_id);
    if (!domain ||
        parent_process->state != process_security_state_kind_v1_active ||
        !parent_process->live_thread_refs ||
        parent_vector->state != process_state_vector_state_v1_active ||
        parent_vector->process_state_vector_id !=
            parent_process->process_state_vector_id ||
        parent_vector->profile_generation_ref_id !=
            parent_process->active_profile_generation_ref_id ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs ||
        domain->state != authority_domain_state_kind_v1_active ||
        !domain->live_process_refs ||
        !binding_matches_label(binding, parent_label))
        return identity_deny(config);
    if (!thread && parent_label->lineage_depth >=
                       MAX_ANCESTOR_PROCESS_LINEAGES_V1)
        return identity_deny(config);
    if (__sync_val_compare_and_swap(&parent_process->transition_guard, 0, 1))
        return identity_deny(config);
    if (parent_process->exec_guard_state != exec_guard_state_v1_none ||
        parent_process->exec_check_task_cookie ||
        parent_process->state != process_security_state_kind_v1_active)
        goto fail_locked;
    parent_execution = bpf_map_lookup_elem(
        &process_execution_instances, &parent_process->active_execution_id);
    if (!parent_execution ||
        parent_execution->state != process_execution_state_v1_active)
        goto fail_locked;

    scratch->label = *parent_label;
    scratch->label.birth_profile_generation_ref_id =
        parent_process->active_profile_generation_ref_id;
    scratch->label.birth_authority_domain_id = parent_process->authority_domain_id;
    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs,
        &scratch->label.birth_profile_generation_ref_id);
    if (!profile_task_refs ||
        __sync_fetch_and_add(profile_task_refs, 0) == 0)
        goto fail_locked;
    if (allocate_id(config, &task_identity))
        goto fail_locked;
    scratch->label.task_cookie = task_identity.low;
    if (thread) {
        scratch->label.birth_execution_id = parent_process->active_execution_id;
    } else {
        if (allocate_id(config, &scratch->label.birth_execution_id) ||
            allocate_id(config, &scratch->label.process_lineage_id) ||
            allocate_id(config, &scratch->label.process_instance_id) ||
            allocate_id(config, &scratch->label.process_state_id))
            goto fail_locked;
    }
    copy_ancestors(&scratch->label, parent_label, !thread);
    prepare_coordinate(&scratch->coordinate, scratch->label.task_cookie,
                       &scratch->label.process_instance_id,
                       &scratch->label.process_state_id);
    if (read_real_parent_interval(
            task, scratch->label.task_cookie,
            clone_flags & CLONE_PARENT
                ? kernel_real_parent_change_reason_v1_clone_parent
                : kernel_real_parent_change_reason_v1_birth,
            &scratch->real_parent))
        goto fail_locked;
    if (allocate_id(config, &scratch->created_by.clone_attempt_id))
        goto fail_locked;
    scratch->created_by.child_task_cookie = scratch->label.task_cookie;
    scratch->created_by.creator_task_cookie = parent_label->task_cookie;
    scratch->created_by.child_process_lineage_id =
        scratch->label.process_lineage_id;
    scratch->created_by.creator_process_lineage_id =
        parent_label->process_lineage_id;
    scratch->created_by.clone_flags = clone_flags;
    scratch->created_by.task_alloc_hook_id = TASK_ALLOC_HOOK_LSM_V1;
    scratch->created_by.reserved = 0;
    prepare_tombstone(&scratch->tombstone, &scratch->label);

    if (!thread) {
        prepare_child_process(&scratch->process, parent_process,
                              &scratch->label);
        prepare_process_vector(
            &scratch->process_vector, &scratch->label,
            parent_vector->profile_generation_ref_id,
            parent_vector->state_bits);
        prepare_execution(
            &scratch->execution, &scratch->label.birth_execution_id,
            &scratch->label.process_lineage_id,
            &parent_execution->image_provenance_id,
            process_execution_started_by_v1_process_birth,
            process_execution_state_v1_active);
        if (bpf_map_update_elem(&process_execution_instances,
                                &scratch->label.birth_execution_id,
                                &scratch->execution, BPF_NOEXIST))
            goto fail_locked;
        if (bpf_map_update_elem(&process_state_vectors,
                                &scratch->label.process_state_id,
                                &scratch->process_vector, BPF_NOEXIST)) {
            bpf_map_delete_elem(&process_execution_instances,
                                &scratch->label.birth_execution_id);
            goto fail_locked;
        }
        if (bpf_map_update_elem(&process_states,
                                &scratch->label.process_state_id,
                                &scratch->process, BPF_NOEXIST)) {
            bpf_map_delete_elem(&process_execution_instances,
                                &scratch->label.birth_execution_id);
            bpf_map_delete_elem(&process_state_vectors,
                                &scratch->label.process_state_id);
            goto fail_locked;
        }
    }
    __sync_fetch_and_add(&entry->live_task_refs, 1);
    __sync_fetch_and_add(profile_task_refs, 1);
    if (thread) {
        __sync_fetch_and_add(&parent_process->live_thread_refs, 1);
    } else {
        __sync_fetch_and_add(&domain->live_process_refs, 1);
    }
    if (bpf_map_update_elem(&created_by_edges, &scratch->label.task_cookie,
                            &scratch->created_by, BPF_NOEXIST))
        goto rollback_references;
    if (publish_task(task, scratch)) {
        bpf_map_delete_elem(&created_by_edges, &scratch->label.task_cookie);
        goto rollback_references;
    }
    if (!thread) {
        process_security_state_v1 *installed = bpf_map_lookup_elem(
            &process_states, &scratch->label.process_state_id);

        if (!installed ||
            !id128_equal(&installed->process_instance_id,
                         &scratch->label.process_instance_id)) {
            bpf_task_storage_delete(&task_labels, task);
            bpf_map_delete_elem(&task_reference_tombstones,
                                &scratch->label.task_cookie);
            bpf_map_delete_elem(&task_coordinates,
                                &scratch->label.task_cookie);
            delete_initial_real_parent(scratch->label.task_cookie);
            bpf_map_delete_elem(&created_by_edges,
                                &scratch->label.task_cookie);
            goto rollback_references;
        }
        installed->state = process_security_state_kind_v1_active;
        installed->transition_version++;
        {
            process_state_vector_v1 *installed_vector =
                bpf_map_lookup_elem(&process_state_vectors,
                                    &scratch->label.process_state_id);

            if (!installed_vector)
                goto rollback_published;
            installed_vector->state = process_state_vector_state_v1_active;
            installed_vector->transition_version++;
        }
    }
    release_transition_guard(&parent_process->transition_guard);
    return 0;

rollback_published:
    bpf_task_storage_delete(&task_labels, task);
    bpf_map_delete_elem(&task_reference_tombstones,
                        &scratch->label.task_cookie);
    bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
    delete_initial_real_parent(scratch->label.task_cookie);
    bpf_map_delete_elem(&created_by_edges, &scratch->label.task_cookie);
    goto rollback_references;

rollback_references:
    __sync_fetch_and_sub(&entry->live_task_refs, 1);
    __sync_fetch_and_sub(profile_task_refs, 1);
    if (thread) {
        __sync_fetch_and_sub(&parent_process->live_thread_refs, 1);
    } else {
        __sync_fetch_and_sub(&domain->live_process_refs, 1);
        bpf_map_delete_elem(&process_states, &scratch->label.process_state_id);
        bpf_map_delete_elem(&process_state_vectors,
                            &scratch->label.process_state_id);
        bpf_map_delete_elem(&process_execution_instances,
                            &scratch->label.birth_execution_id);
    }
fail_locked:
    release_transition_guard(&parent_process->transition_guard);
    return identity_deny(config);
}

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
            task, scratch->label.task_cookie,
            kernel_real_parent_change_reason_v1_birth,
            &scratch->real_parent))
        return identity_deny(config);
    if (prepare_task_image(task, scratch,
                           &scratch->image.image_provenance_id))
        return identity_deny(config);
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
        __sync_fetch_and_sub(profile_task_refs, 1);
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
            __sync_fetch_and_sub(profile_task_refs, 1);
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
                __sync_fetch_and_sub(profile_task_refs, 1);
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
    __u8 root_class = external_root_class_v1_external_runtime_root;
    __u8 role_class = installed_role_class_v1_runtime_external_restricted;
    __u32 role_id = binding->external_role_id;

    bool initial_root = consume_initial_root(binding);

    if (binding->lifecycle_state != binding_lifecycle_state_v1_active) {
        root_class = external_root_class_v1_unresolved_protected;
        role_class = installed_role_class_v1_fail_closed_unknown;
    } else if (initial_root) {
        root_class = external_root_class_v1_initial_container_root;
        role_class = installed_role_class_v1_initial_role;
        role_id = binding->initial_role_id;
    }
    return create_root(task, config, binding, scratch, root_class, role_class,
                       role_id);
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

SEC("lsm/task_alloc")
int BPF_PROG(erebor_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
    identity_runtime_config_v1 *config;
    identity_health_v1 *health;
    struct identity_scratch_v1 *scratch;
    struct task_struct *creator;
    struct cgroup *child_cgroup = NULL;
    struct cgroup *creator_cgroup = NULL;
    task_label_v1 *parent_label;
    execution_set_binding_state_v1 *binding;
    execution_set_binding_state_v1 *creator_binding;
    int binding_lookup;
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
    creator = bpf_get_current_task_btf();
    parent_label = bpf_task_storage_get(&task_labels, creator, 0, 0);
    if (task_cgroup(task, &child_cgroup)) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    binding = binding_for_cgroup(child_cgroup, &binding_lookup);
    if (binding_lookup) {
        if (health)
            health->placement_mismatches++;
        return identity_deny(config);
    }
    if (parent_label) {
        if (!label_matches_runtime(parent_label, config) || !binding) {
            if (health)
                health->placement_mismatches++;
            return identity_deny(config);
        }
        result = create_native_child(task, clone_flags, config, parent_label,
                                     binding, scratch);
    } else {
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
        if (creator_binding) {
            if (health)
                health->missing_identity_denials++;
            return identity_deny(config);
        }
        if (!binding)
            return 0;
        result = create_external_root(task, config, binding, scratch);
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
    struct identity_scratch_v1 *scratch;
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
    scratch = identity_scratch_record();
    health = identity_health_record();
    if (!scratch || create_external_root(task, config, binding, scratch)) {
        if (health)
            health->allocation_failures++;
    } else if (finalize_task_coordinate(task, &scratch->label)) {
        task_coordinate_v1 *coordinate =
            bpf_map_lookup_elem(&task_coordinates, &scratch->label.task_cookie);
        if (coordinate) {
            coordinate->state = task_coordinate_state_v1_fail_closed_unknown;
            coordinate->transition_version++;
        }
        if (health)
            health->coordinate_failures++;
    }
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
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    identity_health_v1 *health;

    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
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
    consume_initial_root(binding);
    scratch = identity_scratch_record();
    health = identity_health_record();
    if (!scratch || create_root(
                        task, config, binding, scratch,
                        external_root_class_v1_restored_or_unknown_root,
                        installed_role_class_v1_fail_closed_unknown,
                        binding->external_role_id) ||
        finalize_task_coordinate(task, &scratch->label)) {
        if (health)
            health->reconciliation_required++;
    }
    return 0;
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

static __always_inline void close_entry_if_last_task(
    entry_security_state_v1 *entry)
{
    if (entry && entry->live_task_refs == 0 &&
        entry->lifetime_state == entry_lifetime_state_v1_active) {
        entry->lifetime_state = entry_lifetime_state_v1_draining;
        entry->transition_version++;
    }
}

SEC("tracepoint/sched/sched_process_exit")
int erebor_sched_process_exit(struct trace_event_raw_sched_process_template *context)
{
    struct task_struct *task;
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    task_reference_tombstone_v1 *tombstone;
    process_security_state_v1 *process;
    process_state_vector_v1 *process_vector;
    entry_security_state_v1 *entry;
    authority_domain_state_v1 *domain;
    __u64 *profile_task_refs;
    identity_health_v1 *health;
    __u64 previous;
    bool released = true;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    bpf_map_delete_elem(&pending_administrative_matches,
                        &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    if (process)
        __sync_val_compare_and_swap(&process->exec_check_task_cookie,
                                    label->task_cookie, 0);
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (coordinate) {
        kernel_real_parent_interval_key_v1 parent_key = {
            .child_task_cookie = label->task_cookie,
            .interval_sequence = coordinate->real_parent_interval_sequence,
        };
        kernel_real_parent_interval_v1 *parent_interval =
            bpf_map_lookup_elem(&kernel_real_parent_intervals, &parent_key);

        if (parent_interval && !parent_interval->interval_end_boottime_ns) {
            parent_interval->interval_end_boottime_ns = bpf_ktime_get_ns();
            parent_interval->transition_version++;
        }
        coordinate->state = task_coordinate_state_v1_exited;
        coordinate->transition_version++;
    }
    tombstone = bpf_map_lookup_elem(&task_reference_tombstones,
                                    &label->task_cookie);
    if (!tombstone)
        return 0;
    tombstone->task_free_observed = 1;

    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_ENTRY_V1);
    if (!(previous & TASK_REFERENCE_ENTRY_V1)) {
        if (entry) {
            if (__sync_fetch_and_sub(&entry->live_task_refs, 1) == 0)
                released = false;
        } else {
            released = false;
        }
    }

    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_PROCESS_V1);
    if (!(previous & TASK_REFERENCE_PROCESS_V1)) {
        if (process) {
            previous = __sync_fetch_and_sub(&process->live_thread_refs, 1);
            if (previous == 0) {
                released = false;
            } else if (previous == 1) {
                process_execution_instance_v1 *execution =
                    bpf_map_lookup_elem(&process_execution_instances,
                                        &process->active_execution_id);

                process_vector = bpf_map_lookup_elem(
                    &process_state_vectors, &label->process_state_id);

                if (execution &&
                    execution->state == process_execution_state_v1_active) {
                    execution->end_boottime_ns = bpf_ktime_get_ns();
                    execution->state = process_execution_state_v1_complete;
                    execution->transition_version++;
                } else {
                    released = false;
                }
                if (process_vector &&
                    process_vector->state ==
                        process_state_vector_state_v1_active) {
                    process_vector->state =
                        process_state_vector_state_v1_retiring;
                    process_vector->transition_version++;
                } else {
                    released = false;
                }
                process->state = process_security_state_kind_v1_reclaimable;
                process->transition_version++;
                domain = bpf_map_lookup_elem(&authority_domains,
                                             &process->authority_domain_id);
                if (!domain ||
                    __sync_fetch_and_sub(&domain->live_process_refs, 1) == 0)
                    released = false;
            }
        } else {
            released = false;
        }
    }

    close_entry_if_last_task(entry);

    profile_task_refs = bpf_map_lookup_elem(
        &profile_generation_task_refs, &tombstone->profile_generation_ref_id);
    previous = __sync_fetch_and_or(
        &tombstone->released_bits, TASK_REFERENCE_PROFILE_GENERATION_V1);
    if (!(previous & TASK_REFERENCE_PROFILE_GENERATION_V1)) {
        if (!profile_task_refs ||
            __sync_fetch_and_sub(profile_task_refs, 1) == 0)
            released = false;
    }

    tombstone->state = released ? reference_tombstone_state_v1_released
                                : reference_tombstone_state_v1_owned;
    tombstone->transition_version++;
    if (!released) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
