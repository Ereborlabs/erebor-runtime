/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_RUNTIME_BOOTSTRAP_H
#define EREBOR_IDENTITY_RUNTIME_BOOTSTRAP_H

#define RUNTIME_BOOTSTRAP_NOT_APPLICABLE_V1 1

static __always_inline bool runtime_bootstrap_binding_is_armed(
    execution_set_binding_state_v1 *binding)
{
    __u64 now;

    if (!binding ||
        binding->lifecycle_state != binding_lifecycle_state_v1_active ||
        binding->runtime_bootstrap_state != runtime_bootstrap_state_v1_armed)
        return false;
    now = bpf_ktime_get_ns();
    if (!binding->runtime_bootstrap_deadline_boottime_ns ||
        now >= binding->runtime_bootstrap_deadline_boottime_ns) {
        if (__sync_val_compare_and_swap(
                &binding->runtime_bootstrap_state,
                runtime_bootstrap_state_v1_armed,
                runtime_bootstrap_state_v1_expired) ==
            runtime_bootstrap_state_v1_armed)
            __sync_fetch_and_add(&binding->transition_version, 1);
        return false;
    }
    return true;
}

static __always_inline bool runtime_bootstrap_actor_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry)
{
    return runtime_bootstrap_binding_is_armed(binding) && label && entry &&
           !id128_is_zero(&binding->runtime_bootstrap_entry_instance_id) &&
           id128_equal(&binding->runtime_bootstrap_entry_instance_id,
                       &label->entry_instance_id) &&
           id128_equal(&entry->entry_instance_id,
                       &label->entry_instance_id) &&
           entry->entry_kind == entry_kind_v1_container_start &&
           entry->admission_state == entry_admission_state_v1_committed &&
           entry->lifetime_state == entry_lifetime_state_v1_active &&
           entry->live_task_refs;
}

static __always_inline __u8 runtime_bootstrap_inode_kind(struct inode *inode)
{
    struct super_block *superblock = NULL;
    unsigned long magic = 0;
    umode_t mode = 0;

    if (!inode || BPF_CORE_READ_INTO(&mode, inode, i_mode) ||
        BPF_CORE_READ_INTO(&superblock, inode, i_sb) || !superblock ||
        BPF_CORE_READ_INTO(&magic, superblock, s_magic))
        return runtime_bootstrap_object_kind_v1_unknown;
    if ((mode & S_IFMT) == S_IFIFO && magic == PIPEFS_MAGIC)
        return runtime_bootstrap_object_kind_v1_pipe;
    if ((mode & S_IFMT) == S_IFREG && magic == TMPFS_MAGIC)
        return runtime_bootstrap_object_kind_v1_memfd;
    return runtime_bootstrap_object_kind_v1_unknown;
}

static __always_inline bool runtime_bootstrap_memfd_is_sealed(
    struct inode *inode)
{
    struct shmem_inode_info *info;
    unsigned int seals = 0;

    if (!inode || !bpf_core_field_exists(((struct shmem_inode_info *)0)->seals))
        return false;
    info = EREBOR_CORE_CONTAINER_OF(inode, struct shmem_inode_info, vfs_inode);
    if (BPF_CORE_READ_INTO(&seals, info, seals))
        return false;
    return (seals & RUNTIME_BOOTSTRAP_REQUIRED_SEALS_V1) ==
           RUNTIME_BOOTSTRAP_REQUIRED_SEALS_V1;
}

static __always_inline bool runtime_bootstrap_memfd_name(struct file *file)
{
    struct dentry *dentry = NULL;
    const unsigned char *name = NULL;
    char observed[7] = {};

    if (!file || BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) ||
        !dentry || BPF_CORE_READ_INTO(&name, dentry, d_name.name) || !name ||
        bpf_probe_read_kernel_str(observed, sizeof(observed), name) < 0)
        return false;
    return observed[0] == 'm' && observed[1] == 'e' && observed[2] == 'm' &&
           observed[3] == 'f' && observed[4] == 'd' && observed[5] == ':';
}

static __always_inline int runtime_bootstrap_claim_inode(
    struct inode *inode, __u8 kind, execution_set_binding_state_v1 *binding,
    const task_label_v1 *label, const entry_security_state_v1 *entry)
{
    runtime_bootstrap_object_state_v1 *object;

    if (!runtime_bootstrap_actor_is_exact(binding, label, entry) ||
        (kind != runtime_bootstrap_object_kind_v1_pipe &&
         kind != runtime_bootstrap_object_kind_v1_memfd))
        return -EACCES;
    object = bpf_inode_storage_get(&runtime_bootstrap_objects, inode, 0, 0);
    if (!object) {
        object = bpf_inode_storage_get(
            &runtime_bootstrap_objects, inode, 0,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!object)
            return -EACCES;
        object->binding_id = binding->binding_id;
        object->binding_nonce = binding->binding_nonce;
        object->entry_instance_id = label->entry_instance_id;
        object->deadline_boottime_ns =
            binding->runtime_bootstrap_deadline_boottime_ns;
        object->transition_version = 1;
        object->kind = kind;
#pragma unroll
        for (int index = 0; index < 7; index++)
            object->reserved[index] = 0;
    }
    return id128_equal(&object->binding_id, &binding->binding_id) &&
                   id128_equal(&object->binding_nonce,
                               &binding->binding_nonce) &&
                   id128_equal(&object->entry_instance_id,
                               &label->entry_instance_id) &&
                   object->deadline_boottime_ns ==
                       binding->runtime_bootstrap_deadline_boottime_ns &&
                   object->kind == kind && object->transition_version
               ? 0
               : -EACCES;
}

static __always_inline bool runtime_bootstrap_operation_is_fixed(
    __u8 kind, __u16 family, __u16 operation, struct inode *inode)
{
    if (kind == runtime_bootstrap_object_kind_v1_pipe)
        return family == kernel_effect_family_v1_file &&
               (operation == kernel_effect_operation_v1_open_read ||
                operation == kernel_effect_operation_v1_open_write ||
                operation == kernel_effect_operation_v1_read ||
                operation == kernel_effect_operation_v1_write);
    if (kind != runtime_bootstrap_object_kind_v1_memfd)
        return false;
    if (family == kernel_effect_family_v1_file)
        return operation == kernel_effect_operation_v1_open_read ||
               operation == kernel_effect_operation_v1_open_write ||
               operation == kernel_effect_operation_v1_read ||
               operation == kernel_effect_operation_v1_write ||
               operation == kernel_effect_operation_v1_mmap_read ||
               operation == kernel_effect_operation_v1_mmap_write;
    return family == kernel_effect_family_v1_exec &&
           (operation == kernel_effect_operation_v1_execute ||
            operation == kernel_effect_operation_v1_mmap_exec ||
            operation == kernel_effect_operation_v1_mprotect) &&
           runtime_bootstrap_memfd_is_sealed(inode);
}

static __always_inline int runtime_bootstrap_file_access(
    struct file *file, __u16 family, __u16 operation,
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry, bool may_claim_inherited,
    bool received)
{
    runtime_bootstrap_object_state_v1 *object;
    struct inode *inode = NULL;
    __u8 kind;

    if (!file || BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode)
        return RUNTIME_BOOTSTRAP_NOT_APPLICABLE_V1;
    kind = runtime_bootstrap_inode_kind(inode);
    if (kind == runtime_bootstrap_object_kind_v1_memfd &&
        !runtime_bootstrap_memfd_name(file))
        kind = runtime_bootstrap_object_kind_v1_unknown;
    if (kind == runtime_bootstrap_object_kind_v1_unknown)
        return RUNTIME_BOOTSTRAP_NOT_APPLICABLE_V1;
    if (received || !runtime_bootstrap_actor_is_exact(binding, label, entry))
        return -EACCES;
    object = bpf_inode_storage_get(&runtime_bootstrap_objects, inode, 0, 0);
    if (!object && may_claim_inherited) {
        if (runtime_bootstrap_claim_inode(inode, kind, binding, label, entry))
            return -EACCES;
        object = bpf_inode_storage_get(&runtime_bootstrap_objects, inode, 0, 0);
    }
    if (!object ||
        !id128_equal(&object->binding_id, &binding->binding_id) ||
        !id128_equal(&object->binding_nonce, &binding->binding_nonce) ||
        !id128_equal(&object->entry_instance_id, &label->entry_instance_id) ||
        object->deadline_boottime_ns !=
            binding->runtime_bootstrap_deadline_boottime_ns ||
        object->kind != kind || !object->transition_version ||
        !runtime_bootstrap_operation_is_fixed(kind, family, operation, inode))
        return -EACCES;
    return 0;
}

static __always_inline int runtime_bootstrap_set_initial_entry(
    execution_set_binding_state_v1 *binding, const id128_v1 *entry_instance_id)
{
    if (!binding || !entry_instance_id || id128_is_zero(entry_instance_id) ||
        !runtime_bootstrap_binding_is_armed(binding) ||
        !id128_is_zero(&binding->runtime_bootstrap_entry_instance_id))
        return -EACCES;
    binding->runtime_bootstrap_entry_instance_id = *entry_instance_id;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline int runtime_bootstrap_reserve_handoff(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label)
{
    __u64 previous;

    if (!binding || !label)
        return -EACCES;
    if (binding->runtime_bootstrap_state ==
        runtime_bootstrap_state_v1_handoff_pending)
        return binding->runtime_bootstrap_handoff_task_cookie ==
                       label->task_cookie
                   ? 0
                   : -EACCES;
    if (binding->runtime_bootstrap_state ==
            runtime_bootstrap_state_v1_unarmed ||
        binding->runtime_bootstrap_state ==
            runtime_bootstrap_state_v1_consumed)
        return 0;
    if (!runtime_bootstrap_actor_is_exact(
            binding, label,
            bpf_map_lookup_elem(&entry_states, &label->entry_instance_id)))
        return -EACCES;
    previous = __sync_val_compare_and_swap(
        &binding->runtime_bootstrap_state,
        runtime_bootstrap_state_v1_armed,
        runtime_bootstrap_state_v1_handoff_pending);
    if (previous != runtime_bootstrap_state_v1_armed)
        return -EACCES;
    if (__sync_val_compare_and_swap(
            &binding->runtime_bootstrap_handoff_task_cookie, 0,
            label->task_cookie)) {
        binding->runtime_bootstrap_state =
            runtime_bootstrap_state_v1_corrupt;
        __sync_fetch_and_add(&binding->transition_version, 1);
        return -EACCES;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline void runtime_bootstrap_rollback_handoff(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->runtime_bootstrap_state !=
            runtime_bootstrap_state_v1_handoff_pending ||
        binding->runtime_bootstrap_handoff_task_cookie != task_cookie)
        return;
    if (__sync_val_compare_and_swap(
            &binding->runtime_bootstrap_handoff_task_cookie, task_cookie, 0) !=
        task_cookie ||
        __sync_val_compare_and_swap(
            &binding->runtime_bootstrap_state,
            runtime_bootstrap_state_v1_handoff_pending,
            runtime_bootstrap_state_v1_armed) !=
            runtime_bootstrap_state_v1_handoff_pending) {
        binding->runtime_bootstrap_state =
            runtime_bootstrap_state_v1_corrupt;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
}

static __always_inline bool runtime_bootstrap_commit_handoff(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->runtime_bootstrap_handoff_task_cookie != task_cookie ||
        __sync_val_compare_and_swap(
            &binding->runtime_bootstrap_state,
            runtime_bootstrap_state_v1_handoff_pending,
            runtime_bootstrap_state_v1_consumed) !=
            runtime_bootstrap_state_v1_handoff_pending)
        return false;
    binding->runtime_bootstrap_handoff_task_cookie = 0;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return true;
}

#endif /* EREBOR_IDENTITY_RUNTIME_BOOTSTRAP_H */
