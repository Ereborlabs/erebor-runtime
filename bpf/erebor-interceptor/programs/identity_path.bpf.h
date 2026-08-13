/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_PATH_BPF_H
#define EREBOR_IDENTITY_PATH_BPF_H

static __always_inline __u32 current_mount_namespace_inode(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct nsproxy *nsproxy = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    __u32 inode = 0;

    if (!task || BPF_CORE_READ_INTO(&nsproxy, task, nsproxy) || !nsproxy ||
        BPF_CORE_READ_INTO(&mount_namespace, nsproxy, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&inode, mount_namespace, ns.inum))
        return 0;
    return inode;
}

static __always_inline int begin_mount_mutation(void)
{
    mount_security_view_state_v1 *view;
    struct mount_security_view_lock_v1 *view_lock;
    __u64 *mutation_epoch;
    mount_mutation_attempt_v1 *attempt;
    struct task_struct *task;
    task_label_v1 *label;
    __u32 mount_namespace_inode;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    mount_namespace_inode = current_mount_namespace_inode();
    if (!mount_namespace_inode)
        return label ? -EACCES : 0;
    view = bpf_map_lookup_elem(&mount_security_views,
                               &mount_namespace_inode);
    if (!view)
        return label ? -EACCES : 0;
    view_lock = bpf_map_lookup_elem(&mount_security_view_locks,
                                    &mount_namespace_inode);
    mutation_epoch = bpf_map_lookup_elem(&mount_mutation_epochs,
                                         &mount_namespace_inode);
    if (!view_lock || !mutation_epoch)
        return -EACCES;
    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!attempt || attempt->active)
        return -EACCES;
    bpf_spin_lock(&view_lock->lock);
    /* Linux cannot have enough live tasks to overflow this u64 counter. */
    __sync_fetch_and_add(&view->pending_mutations, 1);
    view->state = mount_topology_state_v1_dirty;
    (*mutation_epoch)++;
    __sync_fetch_and_add(&view->transition_version, 1);
    bpf_spin_unlock(&view_lock->lock);
    __builtin_memset(attempt, 0, sizeof(*attempt));
    attempt->mount_namespace_inode = mount_namespace_inode;
    attempt->active = 1;
    return 0;
}

static __always_inline void finish_mount_mutation(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    mount_mutation_attempt_v1 *attempt;
    mount_security_view_state_v1 *view;

    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0, 0);
    if (!attempt || !attempt->active)
        return;
    view = bpf_map_lookup_elem(&mount_security_views,
                               &attempt->mount_namespace_inode);
    if (view)
        /* The pre-effect hook already published DIRTY and its new version. */
        decrement_nonzero_counter(&view->pending_mutations);
    attempt->active = 0;
}

static __always_inline int read_mount_root_identity(
    struct vfsmount *vfsmount, canonical_mount_root_key_v1 *key)
{
    struct dentry *root = NULL;
    struct inode *inode = NULL;
    struct super_block *superblock = NULL;
    dev_t filesystem_device = 0;

    if (!vfsmount || BPF_CORE_READ_INTO(&root, vfsmount, mnt_root) || !root ||
        BPF_CORE_READ_INTO(&inode, root, d_inode) || !inode ||
        BPF_CORE_READ_INTO(&superblock, inode, i_sb) || !superblock ||
        BPF_CORE_READ_INTO(&filesystem_device, superblock, s_dev) ||
        BPF_CORE_READ_INTO(&key->root_inode, inode, i_ino) ||
        !key->root_inode)
        return -EACCES;
    key->filesystem_device = encoded_filesystem_device(filesystem_device);
    return 0;
}

static __always_inline int collect_mount_components(
    const struct path *path, struct identity_scratch_v1 *scratch, __u32 *count,
    struct vfsmount **vfsmount_out)
{
    struct dentry *current = NULL;
    struct dentry *root = NULL;
    struct vfsmount *vfsmount = NULL;
    __u32 component_count = 0;

    if (!path || BPF_CORE_READ_INTO(&current, path, dentry) ||
        !current || BPF_CORE_READ_INTO(&vfsmount, path, mnt) ||
        !vfsmount || BPF_CORE_READ_INTO(&root, vfsmount, mnt_root) || !root)
        return -EACCES;
#pragma clang loop unroll(disable)
    for (int depth = 0; depth < MAX_CANONICAL_PATH_COMPONENTS_V1; depth++) {
        struct canonical_path_view_v1 *component;
        struct dentry *parent = NULL;
        const unsigned char *name = NULL;
        __u32 length = 0;

        if (current == root)
            break;
        component = &scratch->path_component_views[depth];
        __builtin_memset(component, 0, sizeof(*component));
        if (BPF_CORE_READ_INTO(&parent, current, d_parent) || !parent ||
            parent == current ||
            BPF_CORE_READ_INTO(&length, current, d_name.len) || !length ||
            length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
            BPF_CORE_READ_INTO(&name, current, d_name.name) || !name)
            return -EACCES;
        component->name_address = (__u64)name;
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
    __u32 mount_namespace_inode, __u64 topology_generation,
    __u64 snapshot_digest_id, __u64 transition_version, bool reconcile,
    __u64 *topology_generation_out, __u64 *snapshot_digest_id_out,
    __u64 *transition_version_out)
{
    mount_security_view_state_v1 *view =
        bpf_map_lookup_elem(&mount_security_views, &mount_namespace_inode);
    struct mount_security_view_lock_v1 *view_lock =
        bpf_map_lookup_elem(&mount_security_view_locks,
                            &mount_namespace_inode);
    __u64 *mutation_epoch =
        bpf_map_lookup_elem(&mount_mutation_epochs, &mount_namespace_inode);
    mount_reconciliation_proposal_v1 *proposal = reconcile
        ? bpf_map_lookup_elem(&mount_reconciliation_proposals,
                              &mount_namespace_inode)
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

struct canonical_path_match {
    struct identity_scratch_v1 *scratch;
    __u64 profile_generation_ref_id;
    __u32 component_count;
    __u32 state_id;
    __u32 unresolved;
};

static long canonical_path_match_step(__u32 offset, void *data)
{
    struct canonical_path_match *match = data;
    path_graph_transition_v1 *transition;
    struct canonical_path_view_v1 *view;
    canonical_path_component_v1 *component;
    __u32 raw_length;
    __u64 copy_length;
    __u32 raw_index;
    __u64 index;

    if (offset >= match->component_count)
        return 1;
    raw_index = match->component_count - offset - 1;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)raw_index),
                   "i"(MAX_CANONICAL_PATH_COMPONENTS_V1 - 1));
    view = &match->scratch->path_component_views[index];
    raw_length = view->length;
    if (!raw_length || raw_length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
        !view->name_address)
        goto unresolved;
    component = &match->scratch->path_transition_key.component;
    if (bpf_probe_read_kernel(component->bytes, sizeof(component->bytes),
                              match->scratch->zero_bytes))
        goto unresolved;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= 0xff ;\n"
                 : [bounded] "=&r"(copy_length)
                 : [raw] "r"((__u64)raw_length));
    if (bpf_probe_read_kernel(component->bytes, copy_length,
                              (const void *)view->name_address))
        goto unresolved;
    match->scratch->path_transition_key.profile_generation_ref_id =
        match->profile_generation_ref_id;
    match->scratch->path_transition_key.current_state_id = match->state_id;
    component->length = raw_length;
    match->scratch->path_transition_key.reserved = 0;
    transition = bpf_map_lookup_elem(
        &path_graph_exact_transitions,
        &match->scratch->path_transition_key);
    if (!transition) {
        __builtin_memset(&match->scratch->path_state_key, 0,
                         sizeof(match->scratch->path_state_key));
        match->scratch->path_state_key.profile_generation_ref_id =
            match->profile_generation_ref_id;
        match->scratch->path_state_key.state_id = match->state_id;
        transition = bpf_map_lookup_elem(
            &path_graph_wildcard_transitions,
            &match->scratch->path_state_key);
    }
    if (!transition) {
        match->unresolved = 1;
        return 1;
    }
    match->state_id = transition->next_state_id;
    return 0;

unresolved:
    match->unresolved = 1;
    return 1;
}

/*
 * The userspace compiler determinizes exact+wildcard pattern subsets. That
 * keeps the kernel hot path to one bounded state instead of an NFA state set.
 */
static __always_inline int canonical_path_candidate(
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch)
{
    canonical_mount_root_v1 *mount_root;
    path_graph_terminal_v1 *terminal;
    struct vfsmount *vfsmount = NULL;
    __u64 topology_generation;
    __u64 snapshot_digest_id;
    __u64 transition_version;
    __u32 component_count = 0;
    long steps;

    if (collect_mount_components(path, scratch, &component_count, &vfsmount))
        return -EACCES;
    if (snapshot_mount_view(scratch->file_object.mount_namespace_inode,
                            0, 0, 0, true,
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
    /* Exact authority follows the verified oldest mount for this root. */
    scratch->file_object.mount_id_unique =
        mount_root->selected_mount_id_unique;
    struct canonical_path_match match = {
        .scratch = scratch,
        .profile_generation_ref_id = profile_generation_ref_id,
        .component_count = component_count,
        .state_id = mount_root->graph_prefix_state_id,
    };

    steps = bpf_loop(MAX_CANONICAL_PATH_COMPONENTS_V1,
                     canonical_path_match_step, &match, 0);
    if (steps < 0 || match.unresolved)
        return -EACCES;
    __builtin_memset(&scratch->path_state_key, 0,
                     sizeof(scratch->path_state_key));
    scratch->path_state_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_state_key.state_id = match.state_id;
    terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                   &scratch->path_state_key);
    if (!terminal || !terminal->composite_atom_id ||
        !terminal->rule_numeric_id)
        return -EACCES;
    if (snapshot_mount_view(scratch->file_object.mount_namespace_inode,
                            topology_generation,
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
