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

static __always_inline int begin_global_mount_mutation(void)
{
    const __u32 global_key = 0;
    __u64 *global_epoch;
    __u64 *global_pending;
    mount_mutation_attempt_v1 *attempt;
    struct task_struct *task;
    task_label_v1 *label;
    __u32 mount_namespace_inode;

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    mount_namespace_inode = current_mount_namespace_inode();
    if (!label &&
        (!mount_namespace_inode ||
         !bpf_map_lookup_elem(&mount_security_views,
                              &mount_namespace_inode)))
        return 0;
    global_epoch = bpf_map_lookup_elem(&mount_global_mutation_epoch,
                                       &global_key);
    global_pending = bpf_map_lookup_elem(&mount_global_pending_mutations,
                                         &global_key);
    if (!global_epoch || !global_pending)
        return label ? -EACCES : 0;
    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!attempt) {
        __sync_fetch_and_add(global_epoch, 1);
        return -EACCES;
    }
    if (attempt->active)
        return 0;
    __builtin_memset(attempt, 0, sizeof(*attempt));
    __sync_fetch_and_add(global_pending, 1);
    __sync_fetch_and_add(global_epoch, 1);
    attempt->active = 1;
    return 0;
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
    int result;

    result = begin_global_mount_mutation();
    if (result)
        return result;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0, 0);
    if (!attempt || !attempt->active)
        return label ? -EACCES : 0;

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
    bpf_spin_lock(&view_lock->lock);
    /* Linux cannot have enough live tasks to overflow this u64 counter. */
    __sync_fetch_and_add(&view->pending_mutations, 1);
    view->state = mount_topology_state_v1_dirty;
    (*mutation_epoch)++;
    __sync_fetch_and_add(&view->transition_version, 1);
    bpf_spin_unlock(&view_lock->lock);
    attempt->mount_namespace_inode = mount_namespace_inode;
    return 0;
}

static __always_inline void finish_mount_mutation(void)
{
    const __u32 global_key = 0;
    struct task_struct *task = bpf_get_current_task_btf();
    mount_mutation_attempt_v1 *attempt;
    mount_security_view_state_v1 *view;
    __u64 *global_pending;

    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0, 0);
    if (!attempt || !attempt->active)
        return;
    if (attempt->mount_namespace_inode) {
        view = bpf_map_lookup_elem(&mount_security_views,
                                   &attempt->mount_namespace_inode);
        /* The pre-effect hook already published DIRTY and its new version. */
        if (view)
            decrement_nonzero_counter(&view->pending_mutations);
    }
    global_pending = bpf_map_lookup_elem(&mount_global_pending_mutations,
                                         &global_key);
    if (global_pending)
        decrement_nonzero_counter(global_pending);
    attempt->active = 0;
}

static __always_inline int read_unique_mount_id(struct mount *mount,
                                                __u64 *mount_id_unique)
{
    struct mount___unique *unique_mount = (void *)mount;

    if (!mount || !bpf_core_field_exists(unique_mount->mnt_id_unique) ||
        BPF_CORE_READ_INTO(mount_id_unique, unique_mount, mnt_id_unique) ||
        !*mount_id_unique)
        return -EACCES;
    return 0;
}

struct canonical_mount_cache_build_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static __always_inline int global_mount_epoch_snapshot(__u64 *epoch)
{
    const __u32 key = 0;
    __u64 *current = bpf_map_lookup_elem(&mount_global_mutation_epoch, &key);
    __u64 *pending =
        bpf_map_lookup_elem(&mount_global_pending_mutations, &key);

    if (!current || !pending || !*current || *pending)
        return -EACCES;
    *epoch = *current;
    return 0;
}

static __always_inline int global_mount_epoch_unchanged(__u64 epoch)
{
    const __u32 key = 0;
    __u64 *current = bpf_map_lookup_elem(&mount_global_mutation_epoch, &key);
    __u64 *pending =
        bpf_map_lookup_elem(&mount_global_pending_mutations, &key);

    return current && pending && *current == epoch && !*pending ? 0
                                                               : -EACCES;
}

static __always_inline int global_mount_epoch_is_clean(__u64 epoch)
{
    const __u32 key = 0;
    __u64 *current = bpf_map_lookup_elem(&mount_global_mutation_epoch, &key);
    __u64 *clean = bpf_map_lookup_elem(&mount_global_clean_epoch, &key);
    __u64 *pending =
        bpf_map_lookup_elem(&mount_global_pending_mutations, &key);

    return current && clean && pending && *current == epoch &&
                   *clean == epoch && !*pending
               ? 0
               : -EACCES;
}

static __always_inline int exact_mount_view_snapshot(
    __u32 mount_namespace_inode, __u64 expected_transition_version,
    __u64 *transition_version_out)
{
    mount_security_view_state_v1 *view =
        bpf_map_lookup_elem(&mount_security_views,
                            &mount_namespace_inode);
    struct mount_security_view_lock_v1 *view_lock =
        bpf_map_lookup_elem(&mount_security_view_locks,
                            &mount_namespace_inode);
    __u64 *mutation_epoch = bpf_map_lookup_elem(
        &mount_mutation_epochs, &mount_namespace_inode);
    int result = -EACCES;

    if (!view || !view_lock || !mutation_epoch || !transition_version_out)
        return -EACCES;
    bpf_spin_lock(&view_lock->lock);
    if (view->state == mount_topology_state_v1_clean &&
        !view->pending_mutations && view->topology_generation &&
        view->topology_generation == *mutation_epoch &&
        view->snapshot_digest_id && view->transition_version &&
        (!expected_transition_version ||
         view->transition_version == expected_transition_version)) {
        *transition_version_out = view->transition_version;
        result = 0;
    }
    bpf_spin_unlock(&view_lock->lock);
    return result;
}

static __always_inline int exact_mount_event_snapshot(
    struct identity_scratch_v1 *scratch, __u64 transition_version,
    bool allow_publish)
{
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct exact_mount_event_key_v1 *key =
        &scratch->exact_mount_event_key;
    struct exact_mount_event_v1 *initial = &scratch->exact_mount_event;
    struct exact_mount_event_v1 *event;
    const __u32 global_key = 0;
    __u64 *ambiguous = bpf_map_lookup_elem(
        &mount_global_ambiguous_epoch, &global_key);
    __u64 ambiguous_epoch;
    bool clean;
    bool published = false;
    int result = -EACCES;

    if (!ambiguous || !(ambiguous_epoch = *ambiguous) ||
        !transition_version || !walk->mount_namespace_address ||
        !walk->namespace_root_mount_id_unique ||
        !scratch->file_object.mount_namespace_inode)
        return -EACCES;
    clean = !global_mount_epoch_is_clean(
        scratch->mount_topology_generation);
    __builtin_memset(key, 0, sizeof(*key));
    key->mount_namespace_address = walk->mount_namespace_address;
    key->namespace_root_mount_id_unique =
        walk->namespace_root_mount_id_unique;
    key->mount_namespace_inode =
        scratch->file_object.mount_namespace_inode;
    event = bpf_map_lookup_elem(&exact_mount_events, key);
    if (!event) {
        if (!allow_publish || !clean)
            return -EACCES;
        __builtin_memset(initial, 0, sizeof(*initial));
        initial->transition_version = transition_version;
        initial->namespace_event = walk->namespace_event;
        initial->ambiguous_mount_epoch = ambiguous_epoch;
        if (bpf_map_update_elem(&exact_mount_events, key, initial,
                                BPF_NOEXIST) &&
            !bpf_map_lookup_elem(&exact_mount_events, key))
            return -EACCES;
        event = bpf_map_lookup_elem(&exact_mount_events, key);
        published = true;
    }
    if (!event)
        return -EACCES;
    bpf_spin_lock(&event->lock);
    if (event->transition_version == transition_version &&
        event->namespace_event == walk->namespace_event &&
        event->ambiguous_mount_epoch == ambiguous_epoch) {
        result = 0;
    } else if (allow_publish && clean &&
               event->transition_version != transition_version) {
        event->transition_version = transition_version;
        event->namespace_event = walk->namespace_event;
        event->ambiguous_mount_epoch = ambiguous_epoch;
        published = true;
        result = 0;
    }
    bpf_spin_unlock(&event->lock);
    if (!result && *ambiguous != ambiguous_epoch)
        return -EACCES;
    if (!result && published && global_mount_epoch_is_clean(
                                      scratch->mount_topology_generation))
        return -EACCES;
    return result;
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)
static __always_inline int mount_scan_push(
    struct identity_scratch_v1 *scratch,
    struct canonical_mount_cache_build_state_v1 *build, struct rb_node *node)
{
    __u64 index;

    if (!node)
        return 0;
    if (build->stack_depth >= MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1)
        return -EACCES;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)build->stack_depth),
                   "i"(MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1));
    scratch->mount_scan_stack[index] = (__u64)node;
    build->stack_depth++;
    return 0;
}

static long canonical_mount_cache_build_step(__u32 offset, void *data)
{
    struct canonical_mount_cache_build_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_mount_cache_build_state_v1 *build =
        &scratch->mount_cache_build;
    struct canonical_mount_cache_key_v1 *key =
        &scratch->mount_cache_key;
    struct canonical_mount_cache_value_v1 *initial =
        &scratch->mount_cache_value;
    struct canonical_mount_cache_value_v1 *cached;
    struct rb_node *node;
    struct mount *candidate;
    __u64 index;

    if (build->failed || !build->stack_depth)
        return 1;
    __builtin_memset(key, 0, sizeof(*key));
    __builtin_memset(initial, 0, sizeof(*initial));
    build->stack_depth--;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)build->stack_depth),
                   "i"(MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1));
    node = (struct rb_node *)scratch->mount_scan_stack[index];
    build->left_node_address = 0;
    build->right_node_address = 0;
    if (!node ||
        BPF_CORE_READ_INTO(&build->left_node_address, node, rb_left) ||
        BPF_CORE_READ_INTO(&build->right_node_address, node, rb_right) ||
        mount_scan_push(scratch, build,
                        (struct rb_node *)build->right_node_address) ||
        mount_scan_push(scratch, build,
                        (struct rb_node *)build->left_node_address))
        goto failed;
    candidate = EREBOR_CORE_CONTAINER_OF(node, struct mount, mnt_node);
    build->candidate_mount_address = (__u64)candidate;
    build->candidate_namespace_address = 0;
    build->candidate_root_address = 0;
    build->candidate_mount_id_unique = 0;
    if (BPF_CORE_READ_INTO(
            &build->candidate_namespace_address, candidate, mnt_ns) ||
        build->candidate_namespace_address !=
            build->mount_namespace_address ||
        BPF_CORE_READ_INTO(
            &build->candidate_root_address, candidate, mnt.mnt_root) ||
        !build->candidate_root_address ||
        read_unique_mount_id(candidate,
                             &build->candidate_mount_id_unique))
        goto failed;

    key->mount_namespace_address = build->mount_namespace_address;
    key->namespace_root_mount_id_unique =
        build->namespace_root_mount_id_unique;
    key->namespace_event = build->namespace_event;
    key->root_dentry_address = build->candidate_root_address;
    initial->selected_mount_address = build->candidate_mount_address;
    initial->selected_mount_id_unique =
        build->candidate_mount_id_unique;
    (void)bpf_map_update_elem(&canonical_mount_cache, key, initial,
                              BPF_NOEXIST);
    cached = bpf_map_lookup_elem(&canonical_mount_cache, key);
    if (!cached)
        goto failed;
    bpf_spin_lock(&cached->lock);
    if (!cached->selected_mount_id_unique ||
        build->candidate_mount_id_unique <
            cached->selected_mount_id_unique) {
        cached->selected_mount_address = build->candidate_mount_address;
        cached->selected_mount_id_unique =
            build->candidate_mount_id_unique;
    }
    bpf_spin_unlock(&cached->lock);
    return offset + 1 == build->expected_mounts ? 1 : 0;

failed:
    build->failed = 1;
    return 1;
}

static __always_inline int ensure_canonical_mount_cache(
    struct mnt_namespace *mount_namespace, struct identity_scratch_v1 *scratch,
    __u64 global_epoch, __u64 *namespace_event_out,
    __u64 *namespace_root_mount_id_unique_out)
{
    struct canonical_mount_cache_state_key_v1 *state_key =
        &scratch->mount_cache_state_key;
    struct canonical_mount_cache_state_v1 *ready =
        &scratch->mount_cache_state;
    struct canonical_mount_cache_state_v1 *state;
    struct canonical_mount_cache_build_state_v1 *build =
        &scratch->mount_cache_build;
    struct canonical_mount_cache_build_context_v1 context = {
        .scratch = scratch,
    };
    struct mount *namespace_root = NULL;
    struct rb_node *tree_root = NULL;
    __u64 namespace_event = 0;
    __u64 root_mount_id_unique = 0;
    __u64 checked_event = 0;
    __u32 mount_count = 0;
    __u32 checked_mount_count = 0;
    long steps;

    if (!mount_namespace ||
        !bpf_core_field_exists(mount_namespace->mounts.rb_node) ||
        BPF_CORE_READ_INTO(&namespace_root, mount_namespace, root) ||
        !namespace_root ||
        read_unique_mount_id(namespace_root, &root_mount_id_unique) ||
        BPF_CORE_READ_INTO(&namespace_event, mount_namespace, event) ||
        BPF_CORE_READ_INTO(&mount_count, mount_namespace, nr_mounts) ||
        !mount_count || mount_count > MAX_CANONICAL_MOUNTS_V1)
        return -EACCES;
    __builtin_memset(state_key, 0, sizeof(*state_key));
    state_key->mount_namespace_address = (__u64)mount_namespace;
    state_key->namespace_root_mount_id_unique = root_mount_id_unique;
    state_key->namespace_event = namespace_event;
    state = bpf_map_lookup_elem(&canonical_mount_cache_states, state_key);
    if (state && state->state == CANONICAL_MOUNT_CACHE_READY_V1 &&
        state->mount_count == mount_count)
        goto ready;

    if (BPF_CORE_READ_INTO(&tree_root, mount_namespace, mounts.rb_node) ||
        !tree_root)
        return -EACCES;
    __builtin_memset(build, 0, sizeof(*build));
    build->mount_namespace_address = (__u64)mount_namespace;
    build->namespace_root_mount_id_unique = root_mount_id_unique;
    build->namespace_event = namespace_event;
    build->expected_mounts = mount_count;
    if (mount_scan_push(scratch, build, tree_root))
        return -EACCES;
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1,
                     canonical_mount_cache_build_step, &context, 0);
    if (steps != mount_count || build->failed || build->stack_depth ||
        BPF_CORE_READ_INTO(&checked_event, mount_namespace, event) ||
        BPF_CORE_READ_INTO(&checked_mount_count, mount_namespace, nr_mounts) ||
        checked_event != namespace_event || checked_mount_count != mount_count ||
        global_mount_epoch_unchanged(global_epoch))
        return -EACCES;
    __builtin_memset(ready, 0, sizeof(*ready));
    ready->mount_count = mount_count;
    ready->state = CANONICAL_MOUNT_CACHE_READY_V1;
    if (bpf_map_update_elem(&canonical_mount_cache_states, state_key, ready,
                            BPF_ANY))
        return -EACCES;

ready:
    *namespace_event_out = namespace_event;
    *namespace_root_mount_id_unique_out = root_mount_id_unique;
    return 0;
}
#else
static __always_inline int ensure_canonical_mount_cache(
    struct mnt_namespace *mount_namespace, struct identity_scratch_v1 *scratch,
    __u64 global_epoch, __u64 *namespace_event_out,
    __u64 *namespace_root_mount_id_unique_out)
{
    (void)mount_namespace;
    (void)scratch;
    (void)global_epoch;
    (void)namespace_event_out;
    (void)namespace_root_mount_id_unique_out;
    return -EACCES;
}
#endif

static __always_inline int selected_mount_for_root(
    struct identity_scratch_v1 *scratch,
    struct mnt_namespace *mount_namespace, __u64 namespace_event,
    __u64 namespace_root_mount_id_unique, struct dentry *root)
{
    struct canonical_mount_cache_key_v1 *key = &scratch->mount_cache_key;
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct canonical_mount_cache_value_v1 *cached;
    struct mount *selected;

    __builtin_memset(key, 0, sizeof(*key));
    key->mount_namespace_address = (__u64)mount_namespace;
    key->namespace_root_mount_id_unique = namespace_root_mount_id_unique;
    key->namespace_event = namespace_event;
    key->root_dentry_address = (__u64)root;
    cached = bpf_map_lookup_elem(&canonical_mount_cache, key);
    if (!cached)
        return CANONICAL_MOUNT_CACHE_MISS_V1;
    walk->selected_mount_address = 0;
    walk->selected_mount_id_unique = 0;
    walk->selected_mount_namespace_address = 0;
    walk->selected_mount_root_address = 0;
    walk->live_selected_mount_id_unique = 0;
    bpf_spin_lock(&cached->lock);
    walk->selected_mount_address = cached->selected_mount_address;
    walk->selected_mount_id_unique = cached->selected_mount_id_unique;
    bpf_spin_unlock(&cached->lock);
    selected = (struct mount *)walk->selected_mount_address;
    if (!walk->selected_mount_address || !walk->selected_mount_id_unique ||
        BPF_CORE_READ_INTO(
            &walk->selected_mount_namespace_address, selected, mnt_ns) ||
        walk->selected_mount_namespace_address != (__u64)mount_namespace ||
        BPF_CORE_READ_INTO(
            &walk->selected_mount_root_address, selected, mnt.mnt_root) ||
        walk->selected_mount_root_address != (__u64)root ||
        read_unique_mount_id(selected,
                             &walk->live_selected_mount_id_unique) ||
        walk->live_selected_mount_id_unique !=
            walk->selected_mount_id_unique)
        return -EACCES;
    return 0;
}

static __always_inline int record_canonical_dentry_component(
    struct identity_scratch_v1 *scratch, struct dentry *current)
{
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct canonical_path_view_v1 *component;
    __u64 index;

    if (walk->component_count >= MAX_CANONICAL_PATH_COMPONENTS_V1)
        return -EACCES;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)walk->component_count),
                   "i"(MAX_CANONICAL_PATH_COMPONENTS_V1));
    walk->next_dentry_address = 0;
    walk->component_name_address = 0;
    walk->component_length = 0;
    if (BPF_CORE_READ_INTO(&walk->next_dentry_address, current, d_parent) ||
        !walk->next_dentry_address ||
        walk->next_dentry_address == (__u64)current ||
        BPF_CORE_READ_INTO(&walk->component_length, current, d_name.len) ||
        !walk->component_length ||
        walk->component_length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
        BPF_CORE_READ_INTO(&walk->component_name_address, current,
                           d_name.name) ||
        !walk->component_name_address)
        return -EACCES;
    component = &scratch->path_component_views[index];
    __builtin_memset(component, 0, sizeof(*component));
    component->name_address = walk->component_name_address;
    component->length = walk->component_length;
    walk->component_count++;
    walk->current_dentry_address = walk->next_dentry_address;
    return 0;
}

struct canonical_mount_path_walk_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static long canonical_mount_path_walk_step(__u32 offset, void *data)
{
    struct canonical_mount_path_walk_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct mnt_namespace *mount_namespace;
    struct mount *selected_mount;
    struct mount *current_mount;
    struct dentry *mount_root = NULL;
    struct dentry *current;
    struct dentry *source_parent = NULL;
    int selected_result;

    (void)offset;
    if (walk->failed || walk->reached_namespace_root)
        return 1;
    mount_namespace =
        (struct mnt_namespace *)walk->mount_namespace_address;
    current_mount = (struct mount *)walk->current_mount_address;
    current = (struct dentry *)walk->current_dentry_address;
    if (BPF_CORE_READ_INTO(&mount_root, current_mount, mnt.mnt_root) ||
        !mount_root)
        goto failed;
    selected_result = selected_mount_for_root(
        scratch, mount_namespace, walk->namespace_event,
        walk->namespace_root_mount_id_unique, current);
    if (selected_result == CANONICAL_MOUNT_CACHE_MISS_V1) {
        if (BPF_CORE_READ_INTO(&source_parent, current, d_parent) ||
            !source_parent)
            goto failed;
        if (source_parent == current) {
            /* A Kubernetes bind can expose a source filesystem whose root
             * mount is not represented in this namespace. The complete
             * source-dentry walk remains bound to the entered unique mount. */
            if (current == mount_root ||
                !walk->selected_mount_id_unique)
                goto failed;
            if (!walk->first_selected_mount_id_unique)
                walk->first_selected_mount_id_unique =
                    walk->selected_mount_id_unique;
            walk->reached_namespace_root = 1;
            return 1;
        }
        if (current == mount_root ||
            record_canonical_dentry_component(scratch, current))
            goto failed;
        return 0;
    }
    if (selected_result)
        goto failed;
    if (walk->selected_mount_address == walk->namespace_root_address) {
        if (!walk->first_selected_mount_id_unique)
            walk->first_selected_mount_id_unique =
                walk->selected_mount_id_unique;
        walk->reached_namespace_root = 1;
        return 1;
    }
    if (BPF_CORE_READ_INTO(&source_parent, current, d_parent) ||
        !source_parent)
        goto failed;
    if (source_parent != current) {
        if (record_canonical_dentry_component(scratch, current))
            goto failed;
        return 0;
    }
    if (!walk->first_selected_mount_id_unique)
        walk->first_selected_mount_id_unique =
            walk->selected_mount_id_unique;
    walk->next_mount_address = 0;
    walk->next_dentry_address = 0;
    selected_mount = (struct mount *)walk->selected_mount_address;
    if (BPF_CORE_READ_INTO(
            &walk->next_mount_address, selected_mount, mnt_parent) ||
        !walk->next_mount_address ||
        walk->next_mount_address == walk->selected_mount_address ||
        BPF_CORE_READ_INTO(
            &walk->next_dentry_address, selected_mount, mnt_mountpoint) ||
        !walk->next_dentry_address)
        goto failed;
    walk->current_mount_address = walk->next_mount_address;
    walk->current_dentry_address = walk->next_dentry_address;
    return 0;

failed:
    walk->failed = 1;
    return 1;
}

static __always_inline int collect_mount_components(
    const struct path *path, struct identity_scratch_v1 *scratch, __u32 *count)
{
    struct dentry *current = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *current_mount = NULL;
    struct mount *namespace_root = NULL;
    struct mnt_namespace *mount_namespace = NULL;
    __u64 global_epoch = 0;
    __u64 namespace_event = 0;
    __u64 checked_namespace_event = 0;
    __u64 namespace_root_mount_id_unique = 0;
    struct canonical_mount_path_walk_state_v1 *walk;
    struct canonical_mount_path_walk_context_v1 context = {
        .scratch = scratch,
    };
    long steps;

    if (global_mount_epoch_snapshot(&global_epoch) || !path ||
        BPF_CORE_READ_INTO(&current, path, dentry) || !current ||
        BPF_CORE_READ_INTO(&vfsmount, path, mnt) || !vfsmount)
        return -EACCES;
    current_mount = mount_from_vfsmount(vfsmount);
    if (!current_mount ||
        BPF_CORE_READ_INTO(&mount_namespace, current_mount, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&namespace_root, mount_namespace, root) ||
        !namespace_root ||
        ensure_canonical_mount_cache(
            mount_namespace, scratch, global_epoch, &namespace_event,
            &namespace_root_mount_id_unique))
        return -EACCES;
    walk = &scratch->mount_path_walk;
    __builtin_memset(walk, 0, sizeof(*walk));
    walk->mount_namespace_address = (__u64)mount_namespace;
    walk->namespace_root_address = (__u64)namespace_root;
    walk->current_mount_address = (__u64)current_mount;
    walk->current_dentry_address = (__u64)current;
    walk->namespace_event = namespace_event;
    walk->namespace_root_mount_id_unique = namespace_root_mount_id_unique;
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1 +
                         MAX_CANONICAL_PATH_COMPONENTS_V1,
                     canonical_mount_path_walk_step, &context, 0);
    if (steps < 0 || walk->failed || !walk->reached_namespace_root ||
        !walk->first_selected_mount_id_unique ||
        BPF_CORE_READ_INTO(&checked_namespace_event, mount_namespace, event) ||
        checked_namespace_event != namespace_event ||
        global_mount_epoch_unchanged(global_epoch))
        return -EACCES;
    scratch->file_object.mount_id_unique =
        walk->first_selected_mount_id_unique;
    scratch->mount_topology_generation = global_epoch;
    *count = walk->component_count;
    return 0;
}

struct visible_path_walk_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static long visible_path_walk_step(__u32 offset, void *data)
{
    struct visible_path_walk_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct mount *current_mount;
    struct mount *root_mount;
    struct mount *parent_mount = NULL;
    struct dentry *current;
    struct dentry *root_dentry;
    struct dentry *mount_root = NULL;
    struct dentry *parent = NULL;
    struct dentry *mountpoint = NULL;

    (void)offset;
    if (walk->failed || walk->reached_namespace_root)
        return 1;
    current_mount = (struct mount *)walk->current_mount_address;
    root_mount = (struct mount *)walk->namespace_root_address;
    current = (struct dentry *)walk->current_dentry_address;
    root_dentry = (struct dentry *)walk->selected_mount_root_address;
    if (!current_mount || !root_mount || !current || !root_dentry)
        goto failed;
    if (current_mount == root_mount && current == root_dentry) {
        walk->reached_namespace_root = 1;
        return 1;
    }
    if (BPF_CORE_READ_INTO(&mount_root, current_mount, mnt.mnt_root) ||
        !mount_root || BPF_CORE_READ_INTO(&parent, current, d_parent) ||
        !parent)
        goto failed;
    if (current == mount_root || parent == current) {
        if (current_mount == root_mount ||
            BPF_CORE_READ_INTO(&parent_mount, current_mount, mnt_parent) ||
            !parent_mount || parent_mount == current_mount ||
            BPF_CORE_READ_INTO(&mountpoint, current_mount, mnt_mountpoint) ||
            !mountpoint)
            goto failed;
        walk->current_mount_address = (__u64)parent_mount;
        walk->current_dentry_address = (__u64)mountpoint;
        return 0;
    }
    if (record_canonical_dentry_component(scratch, current))
        goto failed;
    return 0;

failed:
    walk->failed = 1;
    return 1;
}

/* Signed paths follow the current task root. Exact file selectors use the
 * separate source-aware walk for object identity. */
static __always_inline int collect_visible_path_components(
    const struct path *path, struct identity_scratch_v1 *scratch, __u32 *count)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct fs_struct *fs = NULL;
    struct path root = {};
    struct dentry *current = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *current_mount;
    struct mount *root_mount;
    struct canonical_mount_path_walk_state_v1 *walk;
    struct visible_path_walk_context_v1 context = {
        .scratch = scratch,
    };
    long steps;

    if (!task || !path || BPF_CORE_READ_INTO(&fs, task, fs) || !fs ||
        BPF_CORE_READ_INTO(&root, fs, root) ||
        BPF_CORE_READ_INTO(&current, path, dentry) || !current ||
        BPF_CORE_READ_INTO(&vfsmount, path, mnt) || !vfsmount)
        return -EACCES;
    current_mount = mount_from_vfsmount(vfsmount);
    root_mount = mount_from_vfsmount(root.mnt);
    if (!current_mount || !root_mount || !root.dentry)
        return -EACCES;
    walk = &scratch->mount_path_walk;
    __builtin_memset(walk, 0, sizeof(*walk));
    walk->namespace_root_address = (__u64)root_mount;
    walk->selected_mount_root_address = (__u64)root.dentry;
    walk->current_mount_address = (__u64)current_mount;
    walk->current_dentry_address = (__u64)current;
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1 +
                         MAX_CANONICAL_PATH_COMPONENTS_V1,
                     visible_path_walk_step, &context, 0);
    if (steps < 0 || walk->failed || !walk->reached_namespace_root)
        return -EACCES;
    *count = walk->component_count;
    return 0;
}

static __always_inline int apply_mount_reconciliation_proposal(
    mount_security_view_state_v1 *view,
    struct mount_security_view_lock_v1 *view_lock, __u64 *mutation_epoch,
    mount_reconciliation_proposal_v1 *proposal, __u64 global_generation,
    bool require_dirty)
{
    int result = -EACCES;

    if (!view || !view_lock || !mutation_epoch || !proposal ||
        !global_generation)
        return -EACCES;
    bpf_spin_lock(&view_lock->lock);
    if (proposal->topology_generation == global_generation &&
        proposal->topology_generation == *mutation_epoch &&
        proposal->snapshot_digest_id &&
        (view->state == mount_topology_state_v1_dirty ||
         (!require_dirty &&
          view->state == mount_topology_state_v1_clean &&
          view->topology_generation &&
          view->topology_generation < global_generation)) &&
        !view->pending_mutations &&
        proposal->expected_transition_version == view->transition_version &&
        view->transition_version != ~0ULL &&
        proposal->transition_version == view->transition_version + 1) {
        view->topology_generation = proposal->topology_generation;
        view->snapshot_digest_id = proposal->snapshot_digest_id;
        view->state = mount_topology_state_v1_clean;
        view->transition_version = proposal->transition_version;
        result = 0;
    }
    bpf_spin_unlock(&view_lock->lock);
    return result;
}

static __always_inline int commit_mount_reconciliation_proposal(
    __u32 mount_namespace_inode)
{
    const __u32 global_key = 0;
    __u64 *global_epoch =
        bpf_map_lookup_elem(&mount_global_mutation_epoch, &global_key);
    __u64 *global_clean =
        bpf_map_lookup_elem(&mount_global_clean_epoch, &global_key);
    __u64 *global_pending =
        bpf_map_lookup_elem(&mount_global_pending_mutations, &global_key);
    mount_security_view_state_v1 *view =
        bpf_map_lookup_elem(&mount_security_views, &mount_namespace_inode);
    struct mount_security_view_lock_v1 *view_lock =
        bpf_map_lookup_elem(&mount_security_view_locks,
                            &mount_namespace_inode);
    __u64 *mutation_epoch =
        bpf_map_lookup_elem(&mount_mutation_epochs, &mount_namespace_inode);
    mount_reconciliation_proposal_v1 *proposal =
        bpf_map_lookup_elem(&mount_reconciliation_proposals,
                            &mount_namespace_inode);
    __u64 global_generation;

    if (!global_epoch || !global_clean || !global_pending || !view ||
        !view_lock || !mutation_epoch || !proposal)
        return -EACCES;
    global_generation = *global_epoch;
    if (!global_generation || *global_clean > global_generation ||
        *global_pending)
        return -EACCES;
    if (apply_mount_reconciliation_proposal(view, view_lock, mutation_epoch,
                                            proposal, global_generation, false))
        return -EACCES;
    if (*global_epoch != global_generation ||
        *global_clean > global_generation || *global_pending ||
        *mutation_epoch != global_generation)
        return -EACCES;
    return 0;
}

static __always_inline int advance_logical_path_component(
    struct identity_scratch_v1 *scratch)
{
    struct logical_path_match_state_v1 *match =
        &scratch->logical_path_match;
    path_graph_transition_key_v1 *key = &scratch->path_transition_key;
    canonical_path_component_v1 *component = &key->component;
    path_graph_transition_v1 *transition;
    __u32 length = match->component_length;

    if (!length || length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
        match->component_count >= MAX_CANONICAL_PATH_COMPONENTS_V1 ||
        (length == 1 && component->bytes[0] == '.') ||
        (length == 2 && component->bytes[0] == '.' &&
         component->bytes[1] == '.'))
        return -EACCES;
    key->current_state_id = match->state_id;
    component->length = length;
    transition = bpf_map_lookup_elem(&path_graph_exact_transitions, key);
    if (!transition || !transition->next_state_id)
        return -EACCES;
    match->state_id = transition->next_state_id;
    match->component_count++;
    match->component_length = 0;
    if (bpf_probe_read_kernel(component->bytes, sizeof(component->bytes),
                              scratch->zero_bytes))
        return -EACCES;
    return 0;
}

struct logical_path_match_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static long logical_path_match_step(__u32 offset, void *data)
{
    struct logical_path_match_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct logical_path_match_state_v1 *match =
        &scratch->logical_path_match;
    canonical_path_component_v1 *component =
        &scratch->path_transition_key.component;
    __u32 raw_index = offset + 1;
    __u64 index;
    __u64 component_index;
    __u8 byte;

    if (raw_index >= match->path_length)
        return 1;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)raw_index),
                   "i"(MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 - 1));
    byte = scratch->exec_argument[index];
    if (byte == '/') {
        if (advance_logical_path_component(scratch)) {
            match->failed = 1;
            return 1;
        }
        return 0;
    }
    if (!byte ||
        match->component_length >= MAX_CANONICAL_COMPONENT_BYTES_V1) {
        match->failed = 1;
        return 1;
    }
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= 0xff ;\n"
                 : [bounded] "=&r"(component_index)
                 : [raw] "r"((__u64)match->component_length));
    component->bytes[component_index] = byte;
    match->component_length++;
    return 0;
}

static __noinline __u64 logical_exec_request_atom(
    const struct pending_exec_request_path_v1 *request,
    __u64 profile_generation_ref_id,
    struct identity_scratch_v1 *scratch)
{
    struct logical_path_match_state_v1 *match;
    path_graph_terminal_v1 *terminal;
    struct logical_path_match_context_v1 context = {
        .scratch = scratch,
    };
    __u64 last_index;
    long steps;

    if (!request || !request->path_length ||
        request->path_length >= MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 ||
        !profile_generation_ref_id || !scratch ||
        bpf_probe_read_kernel(scratch->exec_argument,
                              sizeof(scratch->exec_argument),
                              request->path))
        return 0;
    match = &scratch->logical_path_match;
    __builtin_memset(match, 0, sizeof(*match));
    match->path_length = request->path_length;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(last_index)
                 : [raw] "r"((__u64)match->path_length - 1),
                   "i"(MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1 - 1));
    if (scratch->exec_argument[0] != '/' ||
        scratch->exec_argument[last_index] == '/')
        return 0;
    __builtin_memset(&scratch->path_transition_key, 0,
                     sizeof(scratch->path_transition_key));
    scratch->path_transition_key.profile_generation_ref_id =
        profile_generation_ref_id;
    steps = bpf_loop(MAX_ADMINISTRATIVE_ARGUMENT_BYTES_V1,
                     logical_path_match_step, &context, 0);
    if (steps < 0 || match->failed ||
        advance_logical_path_component(scratch))
        return 0;
    __builtin_memset(&scratch->path_state_key, 0,
                     sizeof(scratch->path_state_key));
    scratch->path_state_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_state_key.state_id = match->state_id;
    terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                   &scratch->path_state_key);
    if (!terminal || !terminal->composite_atom_id ||
        !terminal->rule_numeric_id)
        return 0;
    return terminal->composite_atom_id;
}

struct canonical_path_match_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static long canonical_path_match_step(__u32 offset, void *data)
{
    struct canonical_path_match_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_path_match_state_v1 *match = &scratch->path_match;
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
                   "i"(MAX_CANONICAL_PATH_COMPONENTS_V1));
    view = &scratch->path_component_views[index];
    raw_length = view->length;
    if (!raw_length || raw_length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
        !view->name_address)
        goto unresolved;
    component = &scratch->path_transition_key.component;
    if (bpf_probe_read_kernel(component->bytes, sizeof(component->bytes),
                              scratch->zero_bytes))
        goto unresolved;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= 0xff ;\n"
                 : [bounded] "=&r"(copy_length)
                 : [raw] "r"((__u64)raw_length));
    if (bpf_probe_read_kernel(component->bytes, copy_length,
                              (const void *)view->name_address))
        goto unresolved;
    scratch->path_transition_key.profile_generation_ref_id =
        match->profile_generation_ref_id;
    scratch->path_transition_key.current_state_id = match->state_id;
    component->length = raw_length;
    scratch->path_transition_key.reserved = 0;
    transition = bpf_map_lookup_elem(
        &path_graph_exact_transitions, &scratch->path_transition_key);
    if (!transition) {
        __builtin_memset(&scratch->path_state_key, 0,
                         sizeof(scratch->path_state_key));
        scratch->path_state_key.profile_generation_ref_id =
            match->profile_generation_ref_id;
        scratch->path_state_key.state_id = match->state_id;
        transition = bpf_map_lookup_elem(
            &path_graph_wildcard_transitions, &scratch->path_state_key);
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
static __always_inline int match_path_components(
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch,
    __u32 component_count)
{
    path_graph_terminal_v1 *terminal;
    struct canonical_path_match_state_v1 *match = &scratch->path_match;
    struct canonical_path_match_context_v1 context = {
        .scratch = scratch,
    };
    long steps;

    __builtin_memset(match, 0, sizeof(*match));
    match->profile_generation_ref_id = profile_generation_ref_id;
    match->component_count = component_count;
    match->state_id = 0;

    steps = bpf_loop(MAX_CANONICAL_PATH_COMPONENTS_V1,
                     canonical_path_match_step, &context, 0);
    if (steps < 0 || match->unresolved)
        return -EACCES;
    __builtin_memset(&scratch->path_state_key, 0,
                     sizeof(scratch->path_state_key));
    scratch->path_state_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_state_key.state_id = match->state_id;
    terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                   &scratch->path_state_key);
    if (!terminal ||
        ((!terminal->composite_atom_id || !terminal->rule_numeric_id) &&
         !terminal->path_tree_deny_operation_mask))
        return -EACCES;
    scratch->path_terminal = *terminal;
    return 0;
}

static __always_inline int canonical_path_candidate(
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch)
{
    __u32 component_count = 0;

    (void)binding;
    if (collect_mount_components(path, scratch, &component_count))
        return -EACCES;
    return match_path_components(profile_generation_ref_id, scratch,
                                 component_count);
}

static __always_inline int container_visible_path_candidate(
    const struct path *path, __u64 profile_generation_ref_id,
    struct identity_scratch_v1 *scratch)
{
    __u32 component_count = 0;

    /* A positive result means that no task-root path represents the object. */
    if (collect_visible_path_components(path, scratch, &component_count))
        return 1;
    return match_path_components(profile_generation_ref_id, scratch,
                                 component_count);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int erebor_mount_mutation_sys_exit(struct trace_event_raw_sys_exit *context)
{
    finish_mount_mutation();
    return 0;
}

#define MOUNT_SYSCALL_INVALIDATION(NAME)                                  \
    SEC("tracepoint/syscalls/sys_enter_" #NAME)                           \
    int erebor_mount_sys_enter_##NAME(struct trace_event_raw_sys_enter *context) \
    {                                                                     \
        (void)context;                                                    \
        const __u32 global_key = 0;                                      \
        __u32 mount_namespace_inode = current_mount_namespace_inode();    \
        __u64 *ambiguous = bpf_map_lookup_elem(                           \
            &mount_global_ambiguous_epoch, &global_key);                  \
        begin_global_mount_mutation();                                   \
        if (ambiguous && mount_namespace_inode &&                         \
            bpf_map_lookup_elem(&mount_security_views,                    \
                                &mount_namespace_inode))                  \
            __sync_fetch_and_add(ambiguous, 1);                           \
        return 0;                                                         \
    }

MOUNT_SYSCALL_INVALIDATION(open_tree)
MOUNT_SYSCALL_INVALIDATION(fsconfig)
MOUNT_SYSCALL_INVALIDATION(fsmount)
MOUNT_SYSCALL_INVALIDATION(mount_setattr)

#endif /* EREBOR_IDENTITY_PATH_BPF_H */
