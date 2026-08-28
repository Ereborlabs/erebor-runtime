/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_TASK_HELPERS_H
#define EREBOR_IDENTITY_TASK_HELPERS_H

static __always_inline bool runtime_entry_bootstrap_state_valid(
    const struct runtime_entry_bootstrap_state_v1 *state,
    const identity_runtime_config_v1 *config)
{
    return state && config && state->active == 1 &&
           state->label_epoch == config->label_epoch &&
           state->profile_generation_ref_id &&
           !id128_is_zero(&state->binding_id) &&
           !id128_is_zero(&state->target_entry_instance_id) &&
           id128_equal(&state->node_boot_id, &config->node_boot_id);
}

static __always_inline struct task_struct *runtime_entry_bootstrap_owner(
    struct task_struct *task)
{
    struct task_struct *leader = NULL;

    if (!task)
        return NULL;
    leader = task->group_leader;
    return leader ? leader : task;
}

static __noinline void clear_runtime_entry_bootstrap(
    struct task_struct *task)
{
    struct task_struct *owner = runtime_entry_bootstrap_owner(task);

    if (owner)
        bpf_task_storage_delete(&runtime_entry_bootstrap_states, owner);
}

static __always_inline struct runtime_entry_bootstrap_state_v1 *
runtime_entry_bootstrap_for_task(struct task_struct *task)
{
    struct runtime_entry_bootstrap_state_v1 *state;
    struct task_struct *owner;
    struct task_struct *parent;

    owner = runtime_entry_bootstrap_owner(task);
    state = owner ? bpf_task_storage_get(&runtime_entry_bootstrap_states,
                                         owner, 0, 0)
                  : NULL;
    if (state)
        return state;
    parent = task ? task->real_parent : NULL;
    owner = runtime_entry_bootstrap_owner(parent);
    return owner ? bpf_task_storage_get(&runtime_entry_bootstrap_states,
                                        owner, 0, 0)
                 : NULL;
}

static __always_inline int mark_runtime_entry_bootstrap(
    struct task_struct *task, const identity_runtime_config_v1 *config,
    const execution_set_binding_state_v1 *binding,
    const task_label_v1 *target_label)
{
    struct runtime_entry_bootstrap_state_v1 *state;
    execution_set_binding_state_v1 *activation;
    struct task_struct *owner;
    task_label_v1 *label;
    process_security_state_v1 *process;

    if (!task || !config || !binding || !target_label)
        return -EACCES;
    activation = binding_activation_for_new_root(binding, config);
    if (!activation)
        return -EACCES;
    owner = runtime_entry_bootstrap_owner(task);
    state = bpf_task_storage_get(&runtime_entry_bootstrap_states, owner, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state)
        return -EACCES;
    __builtin_memset(state, 0, sizeof(*state));
    state->node_boot_id = config->node_boot_id;
    state->binding_id = activation->binding_id;
    state->target_entry_instance_id = target_label->entry_instance_id;
    state->label_epoch = config->label_epoch;
    state->profile_generation_ref_id =
        activation->active_profile_generation_ref_id;
    state->active = 1;
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
    if (!process || !binding_matches_label(activation, label) ||
        __sync_val_compare_and_swap(&process->transition_guard, 0, 1)) {
        state->active = 0;
        return -EACCES;
    }
    if (process->state != process_security_state_kind_v1_active ||
        process->exec_guard_state != exec_guard_state_v1_none ||
        process->active_role_id != activation->external_role_id) {
        release_transition_guard(&process->transition_guard);
        state->active = 0;
        return -EACCES;
    }
    if (process->runtime_entry_bootstrap_prepared != 1) {
        process->runtime_entry_bootstrap_prepared = 1;
        process->transition_version++;
    }
    release_transition_guard(&process->transition_guard);
    return 0;
}

static __always_inline int inherit_runtime_entry_bootstrap(
    struct task_struct *creator, struct task_struct *child,
    const identity_runtime_config_v1 *config)
{
    struct runtime_entry_bootstrap_state_v1 *source;
    struct runtime_entry_bootstrap_state_v1 *target;
    struct task_struct *child_owner;

    child_owner = runtime_entry_bootstrap_owner(child);
    if (!child_owner)
        return -EACCES;
    source = runtime_entry_bootstrap_for_task(creator);
    if (!source)
        return 0;
    if (!runtime_entry_bootstrap_state_valid(source, config))
        return -EACCES;
    target = bpf_task_storage_get(&runtime_entry_bootstrap_states,
                                  child_owner, 0,
                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!target)
        return -EACCES;
    *target = *source;
    return 0;
}

static __always_inline external_root_classification_v1 *
entry_root_classification(const task_label_v1 *label,
                          const entry_security_state_v1 *entry)
{
    external_root_classification_v1 *classification;

    if (!label || !entry || !entry->root_task_cookie)
        return NULL;
    classification = bpf_map_lookup_elem(&external_root_classifications,
                                         &entry->root_task_cookie);
    if (!classification ||
        classification->task_cookie != entry->root_task_cookie ||
        !id128_equal(&classification->process_state_id,
                     &entry->root_process_state_id) ||
        !id128_equal(&classification->entry_instance_id,
                     &label->entry_instance_id) ||
        !id128_equal(&classification->execution_set_id,
                     &label->execution_set_id) ||
        classification->label_epoch != label->label_epoch ||
        !id128_equal(&classification->node_boot_id, &label->node_boot_id))
        return NULL;
    return classification;
}

static __noinline bool runtime_entry_bootstrap_actor_is_exact(
    const identity_runtime_config_v1 *config,
    const execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const process_security_state_v1 *process,
    const entry_security_state_v1 *entry)
{
    external_root_classification_v1 *classification;
    pending_exec_v1 *pending;
    bool valid_exec_state;

    classification = entry_root_classification(label, entry);
    if (!config || !binding || !label || !process || !entry ||
        !classification ||
        binding->prepared_container_state !=
            prepared_container_state_v1_active ||
        !binding_matches_label(binding, label) ||
        process->runtime_entry_bootstrap_prepared != 1 ||
        entry->admitted_entry_rule_id ||
        classification->root_class !=
            external_root_class_v1_external_runtime_root ||
        classification->purpose != entry_purpose_v1_unknown ||
        classification->installed_role_numeric_id !=
            process->active_role_id ||
        classification->profile_generation_ref_id !=
            process->active_profile_generation_ref_id)
        return false;
    if (process->exec_guard_state == exec_guard_state_v1_none)
        return true;
    pending = bpf_map_lookup_elem(&pending_execs, &label->task_cookie);
    /* The pending exec belongs to one thread. Sibling threads keep the
     * active runtime bootstrap identity until the exec commits. */
    if (!pending)
        return true;
    valid_exec_state =
        (process->exec_guard_state == exec_guard_state_v1_preparing &&
         pending && pending->state == pending_exec_state_v1_preparing) ||
        (process->exec_guard_state == exec_guard_state_v1_commit_pending &&
         pending && pending->state == pending_exec_state_v1_commit_pending);
    return valid_exec_state &&
           (pending->admitted_entry_rule_id ||
            pending->prepared_runtime_exec) &&
           pending->source_role_id == process->active_role_id &&
           pending->source_profile_generation_ref_id ==
               process->active_profile_generation_ref_id &&
           id128_equal(&pending->process_state_id,
                       &label->process_state_id) &&
           id128_equal(&pending->pending_exec_id,
                       &process->pending_exec_id);
}

#define TASK_LABEL_CLAIM_COOKIE_V1 (~0ULL)
#define TASK_LABEL_EXIT_COOKIE_V1 (~0ULL - 1)
/* Linux sets PF_EXITING before the sched_process_exit tracepoint. */
#define TASK_FLAG_EXITING_V1 0x00000004
#define SYNTHETIC_INODE_GENERATION_V1 (1ULL << 63)

struct mount___unique {
    __u64 mnt_id_unique;
} __attribute__((preserve_access_index));

static __always_inline struct mount *mount_from_vfsmount(
    struct vfsmount *vfsmount)
{
    return EREBOR_CORE_CONTAINER_OF(vfsmount, struct mount, mnt);
}

/* Linux new_encode_dev(): expose the same device number as statx/makedev. */
static __always_inline __u32 encoded_filesystem_device(dev_t device)
{
    __u32 major = device >> 20;
    __u32 minor = device & ((1U << 20) - 1);

    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

/* Linux d_unlinked(): an unhashed non-root dentry no longer names an object. */
static __always_inline bool dentry_unlinked(struct dentry *dentry)
{
    struct dentry *parent = NULL;
    struct hlist_bl_node **previous = NULL;

    if (!dentry || BPF_CORE_READ_INTO(&parent, dentry, d_parent) || !parent ||
        BPF_CORE_READ_INTO(&previous, dentry, d_hash.pprev))
        return true;
    return !previous && parent != dentry;
}

static __always_inline bool path_unlinked(const struct path *path)
{
    struct dentry *dentry = NULL;

    if (!path || BPF_CORE_READ_INTO(&dentry, path, dentry))
        return true;
    return dentry_unlinked(dentry);
}

static __always_inline int exact_inode_generation(
    struct inode *inode, __u32 filesystem_device, bool create,
    __u64 *generation)
{
    struct exact_inode_lifetime_key_v1 key = {};
    __u64 *stored;
    __u64 *allocator;
    __u64 allocated;
    __u64 proposed;
    __u32 native_generation = 0;
    __u32 allocator_key = 0;

    if (!inode || !generation ||
        BPF_CORE_READ_INTO(&native_generation, inode, i_generation))
        return -EACCES;
    if (native_generation) {
        *generation = native_generation;
        return 0;
    }
    if (BPF_CORE_READ_INTO(&key.inode, inode, i_ino) || !key.inode)
        return -EACCES;
    key.filesystem_device = filesystem_device;
    stored = bpf_map_lookup_elem(&exact_inode_lifetime_generations, &key);
    if (stored && *stored) {
        *generation = *stored;
        return 0;
    }
    if (!create)
        return -EACCES;
    allocator = bpf_map_lookup_elem(&exact_inode_generation_allocator,
                                    &allocator_key);
    if (!allocator)
        return -EACCES;
    allocated = __sync_fetch_and_add(allocator, 1);
    if (allocated >= SYNTHETIC_INODE_GENERATION_V1 - 1)
        return -EACCES;
    proposed = SYNTHETIC_INODE_GENERATION_V1 | (allocated + 1);
    bpf_map_update_elem(&exact_inode_lifetime_generations, &key, &proposed,
                        BPF_NOEXIST);
    stored = bpf_map_lookup_elem(&exact_inode_lifetime_generations, &key);
    if (!stored || !*stored)
        return -EACCES;
    *generation = *stored;
    return 0;
}

static __always_inline int retire_exact_inode_generation(struct inode *inode)
{
    struct exact_inode_lifetime_key_v1 key = {};
    struct super_block *superblock = NULL;
    dev_t filesystem_device = 0;

    if (!inode || BPF_CORE_READ_INTO(&superblock, inode, i_sb) ||
        !superblock ||
        BPF_CORE_READ_INTO(&filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&key.inode, inode, i_ino) || !key.inode)
        return -EACCES;
    key.filesystem_device = encoded_filesystem_device(filesystem_device);
    return bpf_map_delete_elem(&exact_inode_lifetime_generations, &key);
}

static __always_inline int measure_exact_file_object_from_path(
    exact_file_object_key_v1 *object, const struct path *path, umode_t *mode,
    bool create_generation)
{
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;
    struct super_block *superblock = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *mount = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    struct mount___unique *unique_mount;
    __u32 mount_namespace_inode = 0;
    dev_t filesystem_device = 0;
    umode_t measured_mode = 0;

    __builtin_memset(object, 0, sizeof(*object));
    if (!path || BPF_CORE_READ_INTO(&dentry, path, dentry) ||
        dentry_unlinked(dentry) ||
        BPF_CORE_READ_INTO(&inode, dentry, d_inode) || !inode ||
        BPF_CORE_READ_INTO(&superblock, inode, i_sb) || !superblock ||
        BPF_CORE_READ_INTO(&vfsmount, path, mnt) || !vfsmount)
        return -EACCES;
    mount = mount_from_vfsmount(vfsmount);
    unique_mount = (void *)mount;
    if (!bpf_core_field_exists(unique_mount->mnt_id_unique) ||
        BPF_CORE_READ_INTO(&mount_namespace, mount, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&mount_namespace_inode, mount_namespace, ns.inum) ||
        BPF_CORE_READ_INTO(&object->mount_id_unique, unique_mount,
                           mnt_id_unique) ||
        BPF_CORE_READ_INTO(&filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&object->inode, inode, i_ino) ||
        BPF_CORE_READ_INTO(&measured_mode, inode, i_mode) ||
        !mount_namespace_inode || !object->mount_id_unique ||
        !object->inode) {
        __builtin_memset(object, 0, sizeof(*object));
        return -EACCES;
    }
    object->mount_namespace_inode = mount_namespace_inode;
    object->filesystem_device = encoded_filesystem_device(filesystem_device);
    if ((measured_mode & S_IFMT) != S_IFCHR &&
        (measured_mode & S_IFMT) != S_IFBLK &&
        exact_inode_generation(inode, object->filesystem_device,
                               create_generation,
                               &object->inode_generation)) {
        __builtin_memset(object, 0, sizeof(*object));
        return -EACCES;
    }
    if (mode)
        *mode = measured_mode;
    return 0;
}

static __always_inline void exact_file_object_from_path(
    exact_file_object_key_v1 *object, const struct path *path)
{
    umode_t mode = 0;

    if (measure_exact_file_object_from_path(object, path, &mode, false) ||
        (!object->inode_generation &&
         (mode & S_IFMT) != S_IFCHR && (mode & S_IFMT) != S_IFBLK)) {
        __builtin_memset(object, 0, sizeof(*object));
        return;
    }
    /* Linux does not expose device-node i_generation to user space. */
    if ((mode & S_IFMT) == S_IFCHR || (mode & S_IFMT) == S_IFBLK)
        object->inode_generation = 0;
}

static __always_inline bool exact_file_keys_equal(
    const exact_file_object_key_v1 *left,
    const exact_file_object_key_v1 *right)
{
    return left->profile_generation_ref_id ==
               right->profile_generation_ref_id &&
           left->mount_id_unique == right->mount_id_unique &&
           left->inode == right->inode &&
           left->mount_namespace_inode == right->mount_namespace_inode &&
           left->filesystem_device == right->filesystem_device &&
           left->inode_generation == right->inode_generation;
}

static __always_inline int measure_exact_file_object_from_file(
    exact_file_object_key_v1 *object, struct file *file)
{
    struct path path = {};

    if (!file || BPF_CORE_READ_INTO(&path, file, f_path)) {
        __builtin_memset(object, 0, sizeof(*object));
        return -EACCES;
    }
    return measure_exact_file_object_from_path(object, &path, NULL, true);
}

static __always_inline void complete_exact_file_measurement(struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    exact_file_measurement_v1 *request =
        bpf_map_lookup_elem(&exact_file_measurements, &pid_tgid);
    struct identity_scratch_v1 *scratch;

    if (!request || !request->request_nonce ||
        request->state != exact_file_measurement_state_v1_requested)
        return;
    request->state = exact_file_measurement_state_v1_invalid;
    scratch = identity_scratch_record();
    if (!scratch ||
        measure_exact_file_object_from_file(&scratch->file_object, file))
        return;
    request->mount_id_unique = scratch->file_object.mount_id_unique;
    request->inode = scratch->file_object.inode;
    request->mount_namespace_inode =
        scratch->file_object.mount_namespace_inode;
    request->filesystem_device = scratch->file_object.filesystem_device;
    request->inode_generation = scratch->file_object.inode_generation;
    request->state = exact_file_measurement_state_v1_measured;
}

static __always_inline void exact_file_object_from_file(
    exact_file_object_key_v1 *object, struct file *file)
{
    struct path path = {};

    if (!file || BPF_CORE_READ_INTO(&path, file, f_path)) {
        __builtin_memset(object, 0, sizeof(*object));
        return;
    }
    exact_file_object_from_path(object, &path);
}

static __always_inline int exact_device_from_file(
    exact_file_object_key_v1 *object, struct file *file,
    exact_device_type_v1 *device_type, __u32 *device_major,
    __u32 *device_minor)
{
    struct inode *inode = NULL;
    dev_t represented_device = 0;
    umode_t mode = 0;

    *device_type = exact_device_type_v1_unknown;
    *device_major = 0;
    *device_minor = 0;
    exact_file_object_from_file(object, file);
    if (!object->mount_id_unique || !file ||
        BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode ||
        BPF_CORE_READ_INTO(&mode, inode, i_mode) ||
        BPF_CORE_READ_INTO(&represented_device, inode, i_rdev))
        return -EACCES;
    if ((mode & S_IFMT) == S_IFCHR)
        *device_type = exact_device_type_v1_character;
    else if ((mode & S_IFMT) == S_IFBLK)
        *device_type = exact_device_type_v1_block;
    else
        return -EACCES;
    *device_major = represented_device >> 20;
    *device_minor = represented_device & ((1U << 20) - 1);
    return 0;
}

static __always_inline void candidate_from_file(
    exact_executable_candidate_v1 *candidate, struct file *file)
{
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;
    struct super_block *superblock = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *mount = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    __u32 mount_namespace_inode = 0;
    __u64 inode_generation = 0;
    dev_t filesystem_device = 0;
    int mount_id = 0;

    candidate->mount_namespace_inode = 0;
    candidate->mount_id = 0;
    candidate->filesystem_device = 0;
    candidate->inode = 0;
    candidate->inode_generation = 0;
    if (!file || BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) ||
        dentry_unlinked(dentry) ||
        BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode ||
        BPF_CORE_READ_INTO(&superblock, inode, i_sb) ||
        !superblock || BPF_CORE_READ_INTO(&vfsmount, file, f_path.mnt) ||
        !vfsmount)
        return;
    mount = mount_from_vfsmount(vfsmount);
    if (BPF_CORE_READ_INTO(&mount_namespace, mount, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&mount_id, mount, mnt_id) || mount_id <= 0 ||
        BPF_CORE_READ_INTO(&mount_namespace_inode, mount_namespace, ns.inum) ||
        !mount_namespace_inode ||
        BPF_CORE_READ_INTO(&filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&candidate->inode, inode, i_ino) ||
        !candidate->inode)
        return;
    candidate->mount_namespace_inode = mount_namespace_inode;
    candidate->mount_id = mount_id;
    candidate->filesystem_device =
        encoded_filesystem_device(filesystem_device);
    /* Workload exec policy uses the live signed path graph. Keep an available
     * inode generation for provenance and exact administrative exec only. */
    (void)exact_inode_generation(inode, candidate->filesystem_device, false,
                                 &inode_generation);
    candidate->inode_generation = inode_generation;
}

static __always_inline void prepare_task_image(
    struct task_struct *task, struct identity_scratch_v1 *scratch,
    const id128_v1 *image_provenance_id)
{
    struct mm_struct *mm = NULL;
    struct file *executable = NULL;

    scratch->image.image_provenance_id = *image_provenance_id;
    scratch->image.candidate_count = 0;
#pragma unroll
    for (int index = 0; index < 6; index++)
        scratch->image.reserved_0[index] = 0;
#pragma unroll
    for (int index = 0; index < MAX_EXEC_CANDIDATES_V1; index++)
        candidate_from_file(&scratch->image.ordered_candidates[index], NULL);
    if (!BPF_CORE_READ_INTO(&mm, task, mm) && mm &&
        !BPF_CORE_READ_INTO(&executable, mm, exe_file) && executable) {
        candidate_from_file(&scratch->image.ordered_candidates[0], executable);
        if (scratch->image.ordered_candidates[0].mount_id)
            scratch->image.candidate_count = 1;
    }
    scratch->image.transition_version = 1;
    scratch->image.state = image_provenance_state_v1_active;
#pragma unroll
    for (int index = 0; index < 7; index++)
        scratch->image.reserved_1[index] = 0;
}

static __always_inline int read_parent_interval(
    struct task_struct *parent, __u64 child_task_cookie,
    __u64 real_parent_task_cookie, __u8 change_reason,
    kernel_real_parent_interval_v1 *interval)
{
    struct pid *thread_pid = NULL;
    struct pid_namespace *pid_namespace = NULL;
    __u32 pid_namespace_inode = 0;
    __u32 level = 0;

    if (!parent || !interval)
        return -EACCES;
    interval->child_task_cookie = child_task_cookie;
    interval->real_parent_task_cookie = real_parent_task_cookie;
    BPF_CORE_READ_INTO(&interval->real_parent_host_tid, parent, pid);
    BPF_CORE_READ_INTO(&interval->real_parent_host_tgid, parent, tgid);
    BPF_CORE_READ_INTO(&thread_pid, parent, thread_pid);
    if (thread_pid)
        BPF_CORE_READ_INTO(&level, thread_pid, level);
    if (thread_pid && level < 32)
        BPF_CORE_READ_INTO(&pid_namespace, thread_pid, numbers[level].ns);
    if (pid_namespace)
        BPF_CORE_READ_INTO(&pid_namespace_inode, pid_namespace, ns.inum);
    interval->real_parent_pid_namespace_inode = pid_namespace_inode;
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
    for (int index = 0; index < 2; index++)
        interval->reserved[index] = 0;
    return 0;
}

static __always_inline int read_real_parent_interval(
    struct task_struct *task, __u64 child_task_cookie,
    __u64 real_parent_task_cookie, __u8 change_reason,
    kernel_real_parent_interval_v1 *interval)
{
    struct task_struct *parent = NULL;

    if (!task || BPF_CORE_READ_INTO(&parent, task, real_parent) || !parent)
        return -EACCES;
    return read_parent_interval(parent, child_task_cookie,
                                real_parent_task_cookie, change_reason,
                                interval);
}

static __always_inline bool real_parent_coordinates_equal(
    const kernel_real_parent_interval_v1 *left,
    const kernel_real_parent_interval_v1 *right)
{
    return left->real_parent_host_tid == right->real_parent_host_tid &&
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
            task, label->task_cookie, 0,
            kernel_real_parent_change_reason_v1_parent_exit_or_reparent,
            &scratch->real_parent))
        return -EACCES;
    if (real_parent_coordinates_equal(current, &scratch->real_parent))
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
    __u64 installed_cookie;
    __u64 task_cookie = scratch->label.task_cookie;

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
    installed_cookie = __sync_val_compare_and_swap(
        &installed->task_cookie, 0, TASK_LABEL_CLAIM_COOKIE_V1);
    if (installed_cookie != 0 &&
        installed_cookie != TASK_LABEL_CLAIM_COOKIE_V1) {
        bpf_task_storage_delete(&task_labels, task);
        bpf_map_delete_elem(&task_reference_tombstones,
                            &scratch->label.task_cookie);
        bpf_map_delete_elem(&task_coordinates, &scratch->label.task_cookie);
        bpf_map_delete_elem(&kernel_real_parent_intervals, &parent_key);
        return -EACCES;
    }
    scratch->label.task_cookie = TASK_LABEL_CLAIM_COOKIE_V1;
    *installed = scratch->label;
    scratch->label.task_cookie = task_cookie;
    __asm__ volatile("" ::: "memory");
    installed_cookie = __sync_val_compare_and_swap(
        &installed->task_cookie, TASK_LABEL_CLAIM_COOKIE_V1, task_cookie);
    if (installed_cookie != TASK_LABEL_CLAIM_COOKIE_V1 ||
        installed->task_cookie != scratch->label.task_cookie ||
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

/* Return zero when this call owns the task-label transaction. */
static __always_inline int claim_task_label(struct task_struct *task)
{
    task_label_v1 *label;
    __u64 cookie;
    unsigned int flags = 0;

    if (BPF_CORE_READ_INTO(&flags, task, flags) ||
        (flags & TASK_FLAG_EXITING_V1))
        return -EACCES;
    label = bpf_task_storage_get(&task_labels, task, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!label)
        return -EACCES;
    cookie = __sync_val_compare_and_swap(&label->task_cookie, 0,
                                         TASK_LABEL_CLAIM_COOKIE_V1);
    if (!cookie)
        return 0;
    if (cookie == TASK_LABEL_CLAIM_COOKIE_V1 ||
        cookie == TASK_LABEL_EXIT_COOKIE_V1)
        return -EACCES;
    return 1;
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
    target->runtime_entry_bootstrap_prepared =
        parent->runtime_entry_bootstrap_prepared;
    target->transition_guard = 0;
    target->pending_exec_response_set_ref_id = 0;
    target->exec_without_transition_task_cookie = 0;
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
    struct task_struct *task, struct task_struct *creator,
    unsigned long clone_flags,
    identity_runtime_config_v1 *config, const task_label_v1 *parent_label,
    execution_set_binding_state_v1 *binding, struct identity_scratch_v1 *scratch)
{
    bool thread = (clone_flags & CLONE_THREAD) != 0;
    struct task_struct *real_parent = creator;
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
        parent_process->exec_without_transition_task_cookie ||
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
    if ((clone_flags & (CLONE_PARENT | CLONE_THREAD)) &&
        (BPF_CORE_READ_INTO(&real_parent, creator, real_parent) ||
         !real_parent))
        goto fail_locked;
    if (read_parent_interval(
            real_parent, scratch->label.task_cookie,
            clone_flags & (CLONE_PARENT | CLONE_THREAD)
                ? 0
                : parent_label->task_cookie,
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
    decrement_nonzero_counter(&entry->live_task_refs);
    decrement_nonzero_counter(profile_task_refs);
    if (thread) {
        if (!decrement_nonzero_counter(&parent_process->live_thread_refs)) {
            parent_process->state = process_security_state_kind_v1_corrupt;
            parent_process->transition_version++;
        }
    } else {
        decrement_nonzero_counter(&domain->live_process_refs);
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

#endif /* EREBOR_IDENTITY_TASK_HELPERS_H */
