/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_PATH_BPF_H
#define EREBOR_IDENTITY_PATH_BPF_H

static __always_inline __u64 current_mount_namespace_inode(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct nsproxy *nsproxy = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    __u64 inode = 0;

    if (!task || BPF_CORE_READ_INTO(&nsproxy, task, nsproxy) || !nsproxy ||
        BPF_CORE_READ_INTO(&mount_namespace, nsproxy, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&inode, mount_namespace, ns.inum))
        return 0;
    return inode;
}

static __always_inline int begin_mount_mutation(void)
{
    mount_security_view_key_v1 view_key = {};
    mount_security_view_state_v1 *view;
    struct mount_security_view_lock_v1 *view_lock;
    __u64 *mutation_epoch;
    mount_mutation_attempt_v1 *attempt;
    struct task_struct *task;
    execution_set_binding_state_v1 *binding;
    struct cgroup *cgroup = NULL;
    __u64 mount_namespace_inode;
    __u64 next_epoch;
    __u64 next_transition_version;
    int binding_lookup;

    mount_namespace_inode = current_mount_namespace_inode();
    if (!mount_namespace_inode)
        return 0;
    task = bpf_get_current_task_btf();
    if (task_cgroup(task, &cgroup))
        return -EACCES;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup)
        return -EACCES;
    if (!binding)
        return 0;
    view_key.profile_generation_ref_id =
        binding->active_profile_generation_ref_id;
    view_key.mount_namespace_inode = mount_namespace_inode;
    view_key.binding_id = binding->binding_id;
    view = bpf_map_lookup_elem(&mount_security_views, &view_key);
    if (!view)
        return 0;
    view_lock = bpf_map_lookup_elem(&mount_security_view_locks, &view_key);
    mutation_epoch = bpf_map_lookup_elem(&mount_mutation_epochs, &view_key);
    if (!view_lock || !mutation_epoch)
        return -EACCES;
    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!attempt || attempt->active)
        return -EACCES;
    bpf_spin_lock(&view_lock->lock);
    /* Linux cannot have enough live tasks to overflow this u64 counter. */
    view->pending_mutations++;
    view->state = mount_topology_state_v1_dirty;
    (*mutation_epoch)++;
    next_epoch = *mutation_epoch;
    view->transition_version++;
    next_transition_version = view->transition_version;
    bpf_spin_unlock(&view_lock->lock);
    __builtin_memset(attempt, 0, sizeof(*attempt));
    attempt->view_key = view_key;
    attempt->topology_generation = next_epoch;
    attempt->transition_version = next_transition_version;
    attempt->active = 1;
    return 0;
}

static __always_inline void finish_mount_mutation(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    mount_mutation_attempt_v1 *attempt;
    mount_security_view_state_v1 *view;
    struct mount_security_view_lock_v1 *view_lock;

    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0, 0);
    if (!attempt || !attempt->active)
        return;
    view = bpf_map_lookup_elem(&mount_security_views, &attempt->view_key);
    view_lock = bpf_map_lookup_elem(&mount_security_view_locks,
                                    &attempt->view_key);
    if (view && view_lock) {
        bpf_spin_lock(&view_lock->lock);
        if (view->pending_mutations)
            view->pending_mutations--;
        view->state = mount_topology_state_v1_dirty;
        view->transition_version++;
        bpf_spin_unlock(&view_lock->lock);
    }
    attempt->active = 0;
    attempt->transition_version++;
}

static __always_inline int read_mount_root_identity(
    struct vfsmount *vfsmount, canonical_mount_root_key_v1 *key)
{
    struct dentry *root = NULL;
    struct inode *inode = NULL;
    struct super_block *superblock = NULL;

    if (!vfsmount || BPF_CORE_READ_INTO(&root, vfsmount, mnt_root) || !root ||
        BPF_CORE_READ_INTO(&inode, root, d_inode) || !inode ||
        BPF_CORE_READ_INTO(&superblock, inode, i_sb) || !superblock ||
        BPF_CORE_READ_INTO(&key->filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&key->root_inode, inode, i_ino) ||
        !key->root_inode)
        return -EACCES;
    return 0;
}

static __always_inline int collect_mount_components(
    struct file *file, struct identity_scratch_v1 *scratch, __u32 *count,
    struct vfsmount **vfsmount_out)
{
    struct dentry *current = NULL;
    struct dentry *root = NULL;
    struct vfsmount *vfsmount = NULL;
    __u32 component_count = 0;

    if (!file || BPF_CORE_READ_INTO(&current, file, f_path.dentry) ||
        !current || BPF_CORE_READ_INTO(&vfsmount, file, f_path.mnt) ||
        !vfsmount || BPF_CORE_READ_INTO(&root, vfsmount, mnt_root) || !root)
        return -EACCES;
#pragma clang loop unroll(disable)
    for (int depth = 0; depth < MAX_CANONICAL_PATH_COMPONENTS_V1; depth++) {
        canonical_path_component_v1 *component;
        struct dentry *parent = NULL;
        const unsigned char *name = NULL;
        __u32 length = 0;

        if (current == root)
            break;
        component = &scratch->path_components[depth];
        __builtin_memset(component, 0, sizeof(*component));
        if (BPF_CORE_READ_INTO(&parent, current, d_parent) || !parent ||
            parent == current ||
            BPF_CORE_READ_INTO(&length, current, d_name.len) || !length ||
            length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
            BPF_CORE_READ_INTO(&name, current, d_name.name) || !name ||
            bpf_probe_read_kernel(component->bytes, length, name))
            return -EACCES;
        component->length = length;
        component_count++;
        current = parent;
    }
    if (current != root)
        return -EACCES;
    *count = component_count;
    *vfsmount_out = vfsmount;
    return 0;
}

static __always_inline int snapshot_mount_view(
    const mount_security_view_key_v1 *key, __u64 topology_generation,
    __u64 snapshot_digest_id, __u64 transition_version, bool reconcile,
    __u64 *topology_generation_out, __u64 *snapshot_digest_id_out,
    __u64 *transition_version_out)
{
    mount_security_view_state_v1 *view =
        bpf_map_lookup_elem(&mount_security_views, key);
    struct mount_security_view_lock_v1 *view_lock =
        bpf_map_lookup_elem(&mount_security_view_locks, key);
    __u64 *mutation_epoch =
        bpf_map_lookup_elem(&mount_mutation_epochs, key);
    mount_reconciliation_proposal_v1 *proposal = reconcile
        ? bpf_map_lookup_elem(&mount_reconciliation_proposals, key)
        : NULL;
    int result = -EACCES;

    if (!view || !view_lock || !mutation_epoch)
        return -EACCES;
    bpf_spin_lock(&view_lock->lock);
    if (proposal && proposal->topology_generation == *mutation_epoch &&
        proposal->snapshot_digest_id && !view->pending_mutations &&
        proposal->expected_transition_version == view->transition_version &&
        proposal->transition_version == view->transition_version + 1) {
        view->topology_generation = proposal->topology_generation;
        view->snapshot_digest_id = proposal->snapshot_digest_id;
        view->state = mount_topology_state_v1_clean;
        view->transition_version = proposal->transition_version;
    }
    if (*mutation_epoch == view->topology_generation &&
        view->state == mount_topology_state_v1_clean &&
        !view->pending_mutations && view->topology_generation &&
        view->snapshot_digest_id &&
        (!topology_generation ||
         view->topology_generation == topology_generation) &&
        (!snapshot_digest_id || view->snapshot_digest_id == snapshot_digest_id) &&
        (!transition_version || view->transition_version == transition_version)) {
        *topology_generation_out = view->topology_generation;
        *snapshot_digest_id_out = view->snapshot_digest_id;
        *transition_version_out = view->transition_version;
        result = 0;
    }
    bpf_spin_unlock(&view_lock->lock);
    return result;
}

/*
 * The userspace compiler determinizes exact+wildcard pattern subsets. That
 * keeps the kernel hot path to one bounded state instead of an NFA state set.
 */
static __noinline int canonical_path_candidate(
    struct file *file, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch)
{
    canonical_mount_root_v1 *mount_root;
    path_graph_transition_v1 *transition;
    path_graph_terminal_v1 *terminal;
    struct vfsmount *vfsmount = NULL;
    __u64 topology_generation;
    __u64 snapshot_digest_id;
    __u64 transition_version;
    __u32 component_count = 0;
    __u32 state_id;

    if (collect_mount_components(file, scratch, &component_count, &vfsmount))
        return -EACCES;
    __builtin_memset(&scratch->mount_view_key, 0,
                     sizeof(scratch->mount_view_key));
    scratch->mount_view_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->mount_view_key.mount_namespace_inode =
        scratch->file_object.mount_namespace_inode;
    scratch->mount_view_key.binding_id = binding->binding_id;
    if (snapshot_mount_view(&scratch->mount_view_key, 0, 0, 0, true,
                            &topology_generation, &snapshot_digest_id,
                            &transition_version))
        return -EACCES;

    __builtin_memset(&scratch->mount_root_key, 0,
                     sizeof(scratch->mount_root_key));
    scratch->mount_root_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->mount_root_key.mount_namespace_inode =
        scratch->file_object.mount_namespace_inode;
    scratch->mount_root_key.binding_id = binding->binding_id;
    scratch->mount_root_key.topology_generation = topology_generation;
    if (read_mount_root_identity(vfsmount, &scratch->mount_root_key))
        return -EACCES;
    mount_root = bpf_map_lookup_elem(&canonical_mount_roots,
                                     &scratch->mount_root_key);
    if (!mount_root || !mount_root->selected_mount_id_unique ||
        mount_root->snapshot_digest_id != snapshot_digest_id)
        return -EACCES;
    state_id = mount_root->graph_prefix_state_id;

#pragma clang loop unroll(disable)
    for (int offset = 0; offset < MAX_CANONICAL_PATH_COMPONENTS_V1;
         offset++) {
        __u32 index;

        if ((__u32)offset >= component_count)
            break;
        index = component_count - (__u32)offset - 1;
        __builtin_memset(&scratch->path_transition_key, 0,
                         sizeof(scratch->path_transition_key));
        scratch->path_transition_key.profile_generation_ref_id =
            profile_generation_ref_id;
        scratch->path_transition_key.current_state_id = state_id;
        __builtin_memcpy(&scratch->path_transition_key.component,
                         &scratch->path_components[index],
                         sizeof(scratch->path_transition_key.component));
        transition = bpf_map_lookup_elem(&path_graph_exact_transitions,
                                         &scratch->path_transition_key);
        if (!transition) {
            __builtin_memset(&scratch->path_state_key, 0,
                             sizeof(scratch->path_state_key));
            scratch->path_state_key.profile_generation_ref_id =
                profile_generation_ref_id;
            scratch->path_state_key.state_id = state_id;
            transition = bpf_map_lookup_elem(
                &path_graph_wildcard_transitions,
                &scratch->path_state_key);
        }
        if (!transition)
            return -EACCES;
        state_id = transition->next_state_id;
    }
    __builtin_memset(&scratch->path_state_key, 0,
                     sizeof(scratch->path_state_key));
    scratch->path_state_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_state_key.state_id = state_id;
    terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                   &scratch->path_state_key);
    if (!terminal || !terminal->composite_atom_id ||
        !terminal->rule_numeric_id)
        return -EACCES;
    if (snapshot_mount_view(&scratch->mount_view_key, topology_generation,
                            snapshot_digest_id, transition_version, false,
                            &topology_generation, &snapshot_digest_id,
                            &transition_version))
        return -EACCES;
    scratch->path_terminal = *terminal;
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int erebor_mount_mutation_sys_exit(struct trace_event_raw_sys_exit *context)
{
    finish_mount_mutation();
    return 0;
}

#endif /* EREBOR_IDENTITY_PATH_BPF_H */
