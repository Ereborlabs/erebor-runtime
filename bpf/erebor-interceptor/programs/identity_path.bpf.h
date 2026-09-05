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

static __always_inline void record_mount_activity(void)
{
    const __u32 global_key = 0;
    __u64 *sequence = bpf_map_lookup_elem(
        &mount_global_activity_sequence, &global_key);

    if (sequence)
        __sync_fetch_and_add(sequence, 1);
}

static __always_inline int begin_global_mount_mutation(void)
{
    const __u32 global_key = 0;
    __u64 *global_epoch;
    __u64 *global_pending;
    __u64 *ambiguous;
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
    ambiguous = bpf_map_lookup_elem(&mount_global_ambiguous_epoch,
                                    &global_key);
    if (!global_epoch || !global_pending || !ambiguous)
        return label ? -EACCES : 0;
    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!attempt) {
        __sync_fetch_and_add(global_epoch, 1);
        __sync_fetch_and_add(ambiguous, 1);
        return -EACCES;
    }
    if (attempt->active)
        return 0;
    __builtin_memset(attempt, 0, sizeof(*attempt));
    __sync_fetch_and_add(global_pending, 1);
    __sync_fetch_and_add(global_epoch, 1);
    __sync_fetch_and_add(ambiguous, 1);
    attempt->active = 1;
    return 0;
}

static __always_inline int begin_mount_mutation(void)
{
    struct task_struct *task;
    task_label_v1 *label;
    mount_mutation_attempt_v1 *attempt;
    __u32 mount_namespace_inode;
    int result = begin_global_mount_mutation();

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
    if (!bpf_map_lookup_elem(&mount_security_views,
                             &mount_namespace_inode) ||
        !bpf_map_lookup_elem(&mount_security_view_locks,
                             &mount_namespace_inode) ||
        !bpf_map_lookup_elem(&mount_mutation_epochs,
                             &mount_namespace_inode))
        return label ? -EACCES : 0;
    attempt->mount_namespace_inode = mount_namespace_inode;
    return 0;
}

static __always_inline void finish_mount_mutation(void)
{
    const __u32 global_key = 0;
    struct task_struct *task = bpf_get_current_task_btf();
    mount_mutation_attempt_v1 *attempt;
    __u64 *global_pending;

    attempt = bpf_task_storage_get(&mount_mutation_attempts, task, 0, 0);
    if (!attempt || !attempt->active)
        return;
    if (attempt->mount_namespace_inode)
        (void)bpf_map_lookup_elem(&mount_security_views,
                                  &attempt->mount_namespace_inode);
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

static __always_inline int mount_cache_trace_failure(
    struct identity_scratch_v1 *scratch, __u32 stage, __u64 detail)
{
    (void)scratch;
    (void)detail;
    return -(int)stage;
}

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

static __always_inline int synchronous_mount_snapshot_unchanged(
    struct identity_scratch_v1 *scratch)
{
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct mnt_namespace *mount_namespace =
        (struct mnt_namespace *)walk->mount_namespace_address;
    __u64 namespace_event = 0;

    if (!scratch->mount_topology_generation || !mount_namespace ||
        BPF_CORE_READ_INTO(&namespace_event, mount_namespace, event) ||
        namespace_event != walk->namespace_event)
        return -EACCES;
    return global_mount_epoch_unchanged(
        scratch->mount_topology_generation);
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
    struct canonical_mount_cache_build_state_v1 *build,
    struct mount *mount)
{
    __u64 index;

    if (!mount)
        return 0;
    if (build->stack_depth >= MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1)
        return -EACCES;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)build->stack_depth),
                   "i"(MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1));
    scratch->mount_scan_stack[index] = (__u64)mount;
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
    struct mount *candidate;
    __u64 index;

    (void)offset;
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
    candidate = (struct mount *)scratch->mount_scan_stack[index];
    build->child_node_address = 0;
    build->sibling_node_address = 0;
    if (!candidate)
        goto failed;
    if ((__u64)candidate != build->walk_root_mount_address) {
        build->candidate_namespace_address = 0;
        if (BPF_CORE_READ_INTO(&build->candidate_namespace_address,
                               candidate, mnt_parent) ||
            !build->candidate_namespace_address)
            goto failed;
        build->candidate_root_address =
            build->candidate_namespace_address +
            EREBOR_CORE_OFFSETOF(struct mount, mnt_mounts);
        if (BPF_CORE_READ_INTO(
                &scratch->mount_cache_build.sibling_node_address,
                               candidate, mnt_child.next))
            goto failed;
        if (scratch->mount_cache_build.sibling_node_address !=
            build->candidate_root_address) {
            if (mount_scan_push(
                    scratch, build,
                    EREBOR_CORE_CONTAINER_OF(
                        (struct list_head *)scratch->mount_cache_build
                            .sibling_node_address,
                        struct mount, mnt_child)))
                goto failed;
        }
    }
    if (BPF_CORE_READ_INTO(&build->child_node_address,
                           candidate, mnt_mounts.next))
        goto failed;
    if (build->child_node_address !=
        (__u64)candidate +
            EREBOR_CORE_OFFSETOF(struct mount, mnt_mounts)) {
        if (mount_scan_push(
                scratch, build,
                EREBOR_CORE_CONTAINER_OF(
                    (struct list_head *)build->child_node_address,
                    struct mount, mnt_child)))
            goto failed;
    }
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
    key->security_view_epoch = build->security_view_epoch;
    key->reserved = 0;
    key->walk_root_mount_address = build->walk_root_mount_address;
    key->walk_root_dentry_address = build->walk_root_dentry_address;
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
    build->processed_mounts++;
    return build->stack_depth ? 0 : 1;

failed:
    build->failed = 1;
    return 1;
}

static __noinline int publish_canonical_mount_cache_state(
    struct identity_scratch_v1 *scratch)
{
    return bpf_map_update_elem(&canonical_mount_cache_states,
                               &scratch->mount_cache_state_key,
                               &scratch->mount_cache_state, BPF_ANY);
}

static __always_inline int ensure_canonical_mount_cache(
    struct mnt_namespace *mount_namespace, struct identity_scratch_v1 *scratch,
    struct mount *walk_root_mount, struct dentry *walk_root_dentry,
    __u64 global_epoch)
{
    struct canonical_mount_cache_state_v1 *ready =
        &scratch->mount_cache_state;
    struct canonical_mount_cache_state_v1 *state;
    struct canonical_mount_cache_build_state_v1 *build =
        &scratch->mount_cache_build;
    struct canonical_mount_cache_build_context_v1 context = {
        .scratch = scratch,
    };
    struct mount *namespace_root = NULL;
    long steps;

    __builtin_memset(&scratch->mount_cache_state_key, 0,
                     sizeof(scratch->mount_cache_state_key));
    __builtin_memset(ready, 0, sizeof(*ready));
    if (!mount_namespace || !walk_root_mount || !walk_root_dentry ||
        !bpf_core_field_exists(walk_root_mount->mnt_mounts.next))
        return mount_cache_trace_failure(scratch, 1, 0);
    if (BPF_CORE_READ_INTO(&namespace_root, mount_namespace, root) ||
        !namespace_root)
        return mount_cache_trace_failure(scratch, 2, 0);
    if (read_unique_mount_id(
            namespace_root,
            &scratch->mount_cache_state_key
                 .namespace_root_mount_id_unique))
        return mount_cache_trace_failure(scratch, 3, 0);
    if (BPF_CORE_READ_INTO(&ready->namespace_mount_count, mount_namespace,
                           nr_mounts))
        return mount_cache_trace_failure(scratch, 4, 0);
    if (!ready->namespace_mount_count ||
        ready->namespace_mount_count > MAX_CANONICAL_MOUNTS_V1)
        return mount_cache_trace_failure(
            scratch, 5, ready->namespace_mount_count);
    if (BPF_CORE_READ_INTO(&scratch->mount_cache_state_key.reserved,
                           mount_namespace, event))
        return mount_cache_trace_failure(scratch, 6, 0);
    scratch->mount_cache_state_key.mount_namespace_address =
        (__u64)mount_namespace;
    scratch->mount_cache_state_key.security_view_epoch = global_epoch;
    scratch->mount_cache_state_key.walk_root_mount_address =
        (__u64)walk_root_mount;
    scratch->mount_cache_state_key.walk_root_dentry_address =
        (__u64)walk_root_dentry;
    scratch->mount_path_walk.namespace_event =
        scratch->mount_cache_state_key.reserved;
    scratch->mount_cache_state_key.reserved = 0;
    scratch->mount_path_walk.namespace_root_mount_id_unique =
        scratch->mount_cache_state_key.namespace_root_mount_id_unique;
    state = bpf_map_lookup_elem(
        &canonical_mount_cache_states, &scratch->mount_cache_state_key);
    if (state && state->state == CANONICAL_MOUNT_CACHE_READY_V1 &&
        state->namespace_mount_count) {
        if (state->namespace_mount_count !=
            ready->namespace_mount_count)
            return mount_cache_trace_failure(
                scratch, 15,
                ((__u64)state->namespace_mount_count << 32) |
                    ready->namespace_mount_count);
        goto ready;
    }
    __builtin_memset(build, 0, sizeof(*build));
    build->mount_namespace_address = (__u64)mount_namespace;
    build->namespace_root_mount_id_unique =
        scratch->mount_path_walk.namespace_root_mount_id_unique;
    build->namespace_event = scratch->mount_path_walk.namespace_event;
    build->security_view_epoch = global_epoch;
    build->walk_root_mount_address = (__u64)walk_root_mount;
    build->walk_root_dentry_address = (__u64)walk_root_dentry;
    if (mount_scan_push(scratch, build, walk_root_mount))
        return mount_cache_trace_failure(scratch, 7, 0);
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1,
                     canonical_mount_cache_build_step, &context, 0);
    if (steps != build->processed_mounts)
        return mount_cache_trace_failure(scratch, 8, (__u64)steps);
    if (!build->processed_mounts ||
        build->processed_mounts > ready->namespace_mount_count)
        return mount_cache_trace_failure(scratch, 9, build->processed_mounts);
    if (build->failed || build->stack_depth)
        return mount_cache_trace_failure(
            scratch, 10,
            ((__u64)build->failed << 32) | build->stack_depth);
    if (BPF_CORE_READ_INTO(&ready->namespace_mount_count,
                           mount_namespace, nr_mounts) ||
        !ready->namespace_mount_count ||
        build->processed_mounts > ready->namespace_mount_count)
        return mount_cache_trace_failure(
            scratch, 16,
            ((__u64)build->processed_mounts << 32) |
                ready->namespace_mount_count);
    if (BPF_CORE_READ_INTO(&build->candidate_namespace_address,
                           mount_namespace, event))
        return mount_cache_trace_failure(scratch, 11, 0);
    if (build->candidate_namespace_address !=
        scratch->mount_path_walk.namespace_event)
        return mount_cache_trace_failure(
            scratch, 12, build->candidate_namespace_address);
    if (global_mount_epoch_unchanged(global_epoch))
        return mount_cache_trace_failure(scratch, 13, global_epoch);
    ready->state = CANONICAL_MOUNT_CACHE_READY_V1;
    if (publish_canonical_mount_cache_state(scratch))
        return mount_cache_trace_failure(scratch, 14, global_epoch);

ready:
    return 0;
}

static __noinline int prepare_current_task_mount_cache(
    struct identity_scratch_v1 *scratch)
{
    struct task_struct *task = bpf_get_current_task_btf();
    void *owner = NULL;
    struct mount *walk_root_mount;
    __u64 global_epoch = 0;

    if (!scratch || !task)
        return mount_cache_trace_failure(scratch, 20, 0);
    if (!bpf_task_storage_get(&task_labels, task, 0, 0))
        return 0;
    if (global_mount_epoch_snapshot(&global_epoch))
        return mount_cache_trace_failure(scratch, 21, 0);
    if (BPF_CORE_READ_INTO(&owner, task, nsproxy) || !owner)
        return mount_cache_trace_failure(scratch, 22, 0);
    if (BPF_CORE_READ_INTO(&owner, (struct nsproxy *)owner, mnt_ns) ||
        !owner)
        return mount_cache_trace_failure(scratch, 23, 0);
    __builtin_memset(&scratch->mount_path_walk, 0,
                     sizeof(scratch->mount_path_walk));
    scratch->mount_path_walk.mount_namespace_address = (__u64)owner;
    owner = NULL;
    if (BPF_CORE_READ_INTO(&owner, task, fs) || !owner)
        return mount_cache_trace_failure(scratch, 24, 0);
    if (BPF_CORE_READ_INTO(&scratch->mount_walk_root,
                           (struct fs_struct *)owner, root) ||
        !scratch->mount_walk_root.mnt ||
        !scratch->mount_walk_root.dentry)
        return mount_cache_trace_failure(scratch, 25, 0);
    walk_root_mount = mount_from_vfsmount(scratch->mount_walk_root.mnt);
    if (!walk_root_mount)
        return mount_cache_trace_failure(scratch, 26, 0);
    int cache_result = ensure_canonical_mount_cache(
        (struct mnt_namespace *)
            scratch->mount_path_walk.mount_namespace_address,
        scratch, walk_root_mount, scratch->mount_walk_root.dentry,
        global_epoch);
    if (cache_result)
        return cache_result;
    scratch->mount_path_walk.topology_generation = global_epoch;
    scratch->mount_topology_generation = global_epoch;
    return 0;
}
#else
static __always_inline int ensure_canonical_mount_cache(
    struct mnt_namespace *mount_namespace, struct identity_scratch_v1 *scratch,
    struct mount *walk_root_mount, struct dentry *walk_root_dentry,
    __u64 global_epoch)
{
    (void)mount_namespace;
    (void)scratch;
    (void)walk_root_mount;
    (void)walk_root_dentry;
    (void)global_epoch;
    return -EACCES;
}

static __always_inline int prepare_current_task_mount_cache(
    struct identity_scratch_v1 *scratch)
{
    (void)scratch;
    return -EACCES;
}
#endif

static __always_inline int selected_mount_for_root(
    struct identity_scratch_v1 *scratch, struct dentry *root)
{
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct canonical_mount_cache_value_v1 *cached;
    struct mount *selected;

    __builtin_memset(&scratch->mount_cache_key, 0,
                     sizeof(scratch->mount_cache_key));
    scratch->mount_cache_key.mount_namespace_address =
        walk->mount_namespace_address;
    scratch->mount_cache_key.namespace_root_mount_id_unique =
        walk->namespace_root_mount_id_unique;
    scratch->mount_cache_key.security_view_epoch =
        walk->topology_generation;
    scratch->mount_cache_key.reserved = 0;
    scratch->mount_cache_key.walk_root_mount_address =
        walk->walk_root_mount_address;
    scratch->mount_cache_key.walk_root_dentry_address =
        walk->walk_root_dentry_address;
    scratch->mount_cache_key.root_dentry_address = (__u64)root;
    cached = bpf_map_lookup_elem(&canonical_mount_cache,
                                 &scratch->mount_cache_key);
    if (!cached)
        return CANONICAL_MOUNT_CACHE_MISS_V1;
    walk->selected_mount_address = 0;
    walk->selected_mount_id_unique = 0;
    bpf_spin_lock(&cached->lock);
    walk->selected_mount_address = cached->selected_mount_address;
    walk->selected_mount_id_unique = cached->selected_mount_id_unique;
    bpf_spin_unlock(&cached->lock);
    selected = (struct mount *)walk->selected_mount_address;
    if (!walk->selected_mount_address || !walk->selected_mount_id_unique)
        return -EACCES;
    walk->read_address = 0;
    if (BPF_CORE_READ_INTO(&walk->read_address, selected, mnt_ns) ||
        walk->read_address != walk->mount_namespace_address)
        return -EACCES;
    walk->read_address = 0;
    if (BPF_CORE_READ_INTO(&walk->read_address, selected, mnt.mnt_root) ||
        walk->read_address != (__u64)root)
        return -EACCES;
    walk->read_address = 0;
    if (read_unique_mount_id(selected, &walk->read_address) ||
        walk->read_address != walk->selected_mount_id_unique)
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
    walk->next_dentry_address = 0;
    walk->read_address = 0;
    walk->component_length = 0;
    if (BPF_CORE_READ_INTO(&walk->next_dentry_address, current, d_parent) ||
        !walk->next_dentry_address ||
        walk->next_dentry_address == (__u64)current ||
        BPF_CORE_READ_INTO(&walk->component_length, current, d_name.len) ||
        !walk->component_length ||
        walk->component_length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
        BPF_CORE_READ_INTO(&walk->read_address, current, d_name.name) ||
        !walk->read_address)
        return -EACCES;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(index)
                 : [raw] "r"((__u64)walk->component_count),
                   "i"(MAX_CANONICAL_PATH_COMPONENTS_V1));
    component = &scratch->path_component_views[index];
    __builtin_memset(component, 0, sizeof(*component));
    component->name_address = walk->read_address;
    component->length = walk->component_length;
    walk->component_count++;
    walk->current_dentry_address = walk->next_dentry_address;
    return 0;
}

struct canonical_mount_path_walk_context_v1 {
    struct identity_scratch_v1 *scratch;
};

static __always_inline int load_known_mount_root(
    struct identity_scratch_v1 *scratch)
{
    __u64 topology_generation =
        scratch->canonical_mount_root_key.topology_generation;
    canonical_mount_root_v1 *route;

    scratch->canonical_mount_root_key.topology_generation = 0;
    route = bpf_map_lookup_elem(
        &canonical_mount_roots, &scratch->canonical_mount_root_key);
    scratch->canonical_mount_root_key.topology_generation =
        topology_generation;
    if (route && route->selected_mount_id_unique &&
        route->graph_prefix_state_count <= MAX_CANONICAL_ROUTE_STATES_V1) {
        scratch->canonical_mount_root = *route;
        return 1;
    }
    if (!topology_generation)
        return 0;
    route = bpf_map_lookup_elem(
        &canonical_mount_roots, &scratch->canonical_mount_root_key);
    if (!route || !route->selected_mount_id_unique ||
        !route->graph_prefix_state_count ||
        route->graph_prefix_state_count > MAX_CANONICAL_ROUTE_STATES_V1)
        return 0;
    scratch->canonical_mount_root = *route;
    return 1;
}

static long known_mount_path_walk_step(__u32 offset, void *data)
{
    struct canonical_mount_path_walk_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct inode *inode;
    struct super_block *superblock;

    (void)offset;
    if (walk->failed || walk->reached_walk_root)
        return 1;
    if (!walk->current_dentry_address)
        goto failed;
    walk->read_address = 0;
    {
        struct dentry *current =
            (struct dentry *)walk->current_dentry_address;

        if (BPF_CORE_READ_INTO(&walk->read_address, current, d_inode))
            goto failed;
    }
    if (!walk->read_address) {
        struct dentry *current =
            (struct dentry *)walk->current_dentry_address;

        if (record_canonical_dentry_component(scratch, current))
            goto failed;
        return 0;
    }
    inode = (struct inode *)walk->read_address;
    if (BPF_CORE_READ_INTO(
            &scratch->canonical_mount_root_key.root_inode, inode, i_ino) ||
        !scratch->canonical_mount_root_key.root_inode ||
        BPF_CORE_READ_INTO(&walk->read_address, inode, i_sb) ||
        !walk->read_address)
        goto failed;
    superblock = (struct super_block *)walk->read_address;
    if (BPF_CORE_READ_INTO(
            &scratch->canonical_mount_root_key.filesystem_device,
            superblock, s_dev))
        goto failed;
    scratch->canonical_mount_root_key.filesystem_device =
        encoded_filesystem_device(
            scratch->canonical_mount_root_key.filesystem_device);
    if (load_known_mount_root(scratch)) {
        walk->reached_walk_root = 1;
        return 1;
    }
    {
        struct dentry *current =
            (struct dentry *)walk->current_dentry_address;

        if (record_canonical_dentry_component(scratch, current))
            goto failed;
    }
    return 0;

failed:
    walk->failed = 1;
    return 1;
}

/* Initial mount routes are binding-scoped inode facts. They remain valid
 * while a topology change prevents the oldest-mount fallback. */
static __always_inline int collect_known_mount_components(
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch,
    __u32 *count, bool require_mount_attachment)
{
    struct dentry *current = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *current_mount;
    struct mnt_namespace *mount_namespace = NULL;
    struct canonical_mount_path_walk_state_v1 *walk;
    struct canonical_mount_path_walk_context_v1 context = {
        .scratch = scratch,
    };
    __u64 global_epoch = 0;
    __u64 namespace_event = 0;
    __u64 checked_namespace_event = 0;
    long steps;

    if (global_mount_epoch_snapshot(&global_epoch) || !path ||
        scratch->mount_topology_generation != global_epoch ||
        BPF_CORE_READ_INTO(&current, path, dentry) || !current ||
        BPF_CORE_READ_INTO(&vfsmount, path, mnt) || !vfsmount)
        return -EACCES;
    current_mount = mount_from_vfsmount(vfsmount);
    walk = &scratch->mount_path_walk;
    __builtin_memset(walk, 0, sizeof(*walk));
    if (require_mount_attachment) {
        if (!current_mount ||
            BPF_CORE_READ_INTO(&walk->read_address, current_mount,
                               mnt.mnt_root) ||
            walk->read_address != (__u64)current ||
            BPF_CORE_READ_INTO(&walk->next_mount_address, current_mount,
                               mnt_parent) ||
            !walk->next_mount_address ||
            walk->next_mount_address == (__u64)current_mount ||
            BPF_CORE_READ_INTO(&walk->next_dentry_address, current_mount,
                               mnt_mountpoint) ||
            !walk->next_dentry_address)
            return -EACCES;
        current_mount = (struct mount *)walk->next_mount_address;
        current = (struct dentry *)walk->next_dentry_address;
    }
    if (!current_mount ||
        BPF_CORE_READ_INTO(&mount_namespace, current_mount, mnt_ns) ||
        !mount_namespace ||
        BPF_CORE_READ_INTO(&namespace_event, mount_namespace, event))
        return -EACCES;
    __builtin_memset(&scratch->canonical_mount_root_key, 0,
                     sizeof(scratch->canonical_mount_root_key));
    __builtin_memset(&scratch->canonical_mount_root, 0,
                     sizeof(scratch->canonical_mount_root));
    scratch->canonical_mount_root_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->canonical_mount_root_key.binding_id = binding->binding_id;
    scratch->canonical_mount_root_key.mount_namespace_inode =
        current_mount_namespace_inode();
    if (!scratch->canonical_mount_root_key.mount_namespace_inode)
        return -EACCES;
    walk->mount_namespace_address = (__u64)mount_namespace;
    walk->current_dentry_address = (__u64)current;
    walk->namespace_event = namespace_event;
    walk->topology_generation = global_epoch;
    steps = bpf_loop(MAX_CANONICAL_PATH_COMPONENTS_V1 + 1,
                     known_mount_path_walk_step, &context, 0);
    if (steps < 0 || walk->failed || !walk->reached_walk_root ||
        !scratch->canonical_mount_root.selected_mount_id_unique)
        return -EACCES;
    if (BPF_CORE_READ_INTO(&checked_namespace_event, mount_namespace, event) ||
        checked_namespace_event != namespace_event ||
        global_mount_epoch_unchanged(global_epoch))
        return -EACCES;
    scratch->mount_topology_generation = global_epoch;
    *count = walk->component_count;
    return 0;
}

static long canonical_mount_path_walk_step(__u32 offset, void *data)
{
    struct canonical_mount_path_walk_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_mount_path_walk_state_v1 *walk =
        &scratch->mount_path_walk;
    struct mount *walk_root_mount;
    struct mount *selected_mount;
    struct mount *current_mount;
    struct dentry *mount_root = NULL;
    struct dentry *walk_root_dentry;
    struct dentry *current;
    struct dentry *source_parent = NULL;
    struct inode *inode;
    struct super_block *superblock;
    int selected_result;

    (void)offset;
    if (walk->failed || walk->reached_walk_root)
        return 1;
    if (!walk->walk_root_mount_address ||
        !walk->walk_root_dentry_address ||
        !walk->current_mount_address || !walk->current_dentry_address)
        goto failed;
    current = (struct dentry *)walk->current_dentry_address;
    walk->read_address = 0;
    if (BPF_CORE_READ_INTO(&walk->read_address, current, d_inode) ||
        !walk->read_address)
        goto failed;
    inode = (struct inode *)walk->read_address;
    if (BPF_CORE_READ_INTO(
            &scratch->canonical_mount_root_key.root_inode, inode, i_ino) ||
        !scratch->canonical_mount_root_key.root_inode)
        goto failed;
    if (BPF_CORE_READ_INTO(&walk->read_address, inode, i_sb) ||
        !walk->read_address)
        goto failed;
    superblock = (struct super_block *)walk->read_address;
    if (BPF_CORE_READ_INTO(
            &scratch->canonical_mount_root_key.filesystem_device,
            superblock, s_dev))
        goto failed;
    scratch->canonical_mount_root_key.filesystem_device =
        encoded_filesystem_device(
            scratch->canonical_mount_root_key.filesystem_device);
    if (!walk->ignore_known_route && load_known_mount_root(scratch)) {
        walk->first_selected_mount_id_unique =
            scratch->canonical_mount_root.selected_mount_id_unique;
        walk->reached_walk_root = 1;
        return 1;
    }
    walk_root_mount =
        (struct mount *)walk->walk_root_mount_address;
    walk_root_dentry =
        (struct dentry *)walk->walk_root_dentry_address;
    current_mount = (struct mount *)walk->current_mount_address;
    current = (struct dentry *)walk->current_dentry_address;
    if (current_mount == walk_root_mount && current == walk_root_dentry) {
        if (!walk->first_selected_mount_id_unique &&
            read_unique_mount_id(
                current_mount,
                &walk->first_selected_mount_id_unique))
            goto failed;
        walk->reached_walk_root = 1;
        return 1;
    }
    if (BPF_CORE_READ_INTO(&mount_root, current_mount, mnt.mnt_root) ||
        !mount_root)
        goto failed;
    if (current == mount_root)
        walk->source_ancestry_started = 1;
    selected_result = selected_mount_for_root(scratch, current);
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
            walk->reached_walk_root = 1;
            return 1;
        }
        if (current == mount_root ||
            record_canonical_dentry_component(scratch, current))
            goto failed;
        return 0;
    }
    if (selected_result)
        goto failed;
    if (walk->selected_mount_address == walk->walk_root_mount_address &&
        current == walk_root_dentry) {
        if (!walk->first_selected_mount_id_unique)
            walk->first_selected_mount_id_unique =
                walk->selected_mount_id_unique;
        walk->reached_walk_root = 1;
        return 1;
    }
    if (walk->source_ancestry_started &&
        walk->selected_mount_address != walk->current_mount_address) {
        /* A child bind can enter below an existing source mount. Switch to
         * that source mount before the dentry walk enters the host path. */
        goto selected_mount_target;
    }
    if (BPF_CORE_READ_INTO(&source_parent, current, d_parent) ||
        !source_parent)
        goto failed;
    if (source_parent != current) {
        if (record_canonical_dentry_component(scratch, current))
            goto failed;
        return 0;
    }

selected_mount_target:
    selected_mount = (struct mount *)walk->selected_mount_address;
    if (!walk->first_selected_mount_id_unique)
        walk->first_selected_mount_id_unique =
            walk->selected_mount_id_unique;
    walk->next_mount_address = 0;
    walk->next_dentry_address = 0;
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
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch,
    __u32 *count, bool ignore_known_route)
{
    struct dentry *current = NULL;
    struct vfsmount *vfsmount = NULL;
    struct mount *current_mount = NULL;
    struct mount *walk_root_mount = NULL;
    void *owner = NULL;
    __u64 global_epoch = 0;
    __u64 checked_namespace_event = 0;
    struct canonical_mount_path_walk_state_v1 *walk;
    struct canonical_mount_path_walk_context_v1 context = {
        .scratch = scratch,
    };
    long steps;

    if (global_mount_epoch_snapshot(&global_epoch) || !path ||
        BPF_CORE_READ_INTO(&current, path, dentry) || !current ||
        BPF_CORE_READ_INTO(&vfsmount, path, mnt) || !vfsmount)
        return -EACCES;
    scratch->mount_topology_generation = 0;
    current_mount = mount_from_vfsmount(vfsmount);
    if (!current_mount ||
        BPF_CORE_READ_INTO(&owner, current_mount, mnt_ns) || !owner)
        return -EACCES;
    walk = &scratch->mount_path_walk;
    __builtin_memset(walk, 0, sizeof(*walk));
    walk->ignore_known_route = ignore_known_route;
    __builtin_memset(&scratch->mount_walk_root, 0,
                     sizeof(scratch->mount_walk_root));
    walk->mount_namespace_address = (__u64)owner;
    walk->current_mount_address = (__u64)current_mount;
    walk->current_dentry_address = (__u64)current;
    __builtin_memset(&scratch->canonical_mount_root_key, 0,
                     sizeof(scratch->canonical_mount_root_key));
    __builtin_memset(&scratch->canonical_mount_root, 0,
                     sizeof(scratch->canonical_mount_root));
    scratch->canonical_mount_root_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->canonical_mount_root_key.binding_id = binding->binding_id;
    scratch->canonical_mount_root_key.topology_generation = global_epoch;
    scratch->canonical_mount_root_key.mount_namespace_inode =
        current_mount_namespace_inode();
    if (!scratch->canonical_mount_root_key.mount_namespace_inode)
        return -EACCES;
    /* Reuse one pointer slot so this nested effect-gate chain stays within
     * the verifier's combined stack limit. */
    owner = NULL;
    if (BPF_CORE_READ_INTO(&owner, bpf_get_current_task_btf(), fs) ||
        !owner ||
        BPF_CORE_READ_INTO(&scratch->mount_walk_root,
                           (struct fs_struct *)owner, root) ||
        !scratch->mount_walk_root.mnt ||
        !scratch->mount_walk_root.dentry)
        return -EACCES;
    walk_root_mount = mount_from_vfsmount(scratch->mount_walk_root.mnt);
    if (!walk_root_mount)
        return -EACCES;
    walk->walk_root_mount_address = (__u64)walk_root_mount;
    if (ensure_canonical_mount_cache(
            (struct mnt_namespace *)walk->mount_namespace_address, scratch,
            (struct mount *)walk->walk_root_mount_address,
            scratch->mount_walk_root.dentry, global_epoch))
        return -EACCES;
    /* A source walk may cross a bind target. It must not cross the task root
     * and turn a container path into its host rootfs path. */
    walk->walk_root_dentry_address = (__u64)scratch->mount_walk_root.dentry;
    walk->topology_generation = global_epoch;
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1 +
                         MAX_CANONICAL_PATH_COMPONENTS_V1,
                     canonical_mount_path_walk_step, &context, 0);
    owner = (void *)walk->mount_namespace_address;
    if (steps < 0 || walk->failed || !walk->reached_walk_root ||
        !walk->first_selected_mount_id_unique || !owner ||
        BPF_CORE_READ_INTO(&checked_namespace_event,
                           (struct mnt_namespace *)owner, event) ||
        checked_namespace_event != walk->namespace_event ||
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
    struct dentry *current;

    (void)offset;
    if (walk->failed || walk->reached_walk_root)
        return 1;
    if (!walk->current_mount_address || !walk->walk_root_mount_address ||
        !walk->current_dentry_address || !walk->walk_root_dentry_address)
        goto failed;
    if (walk->current_mount_address == walk->walk_root_mount_address &&
        walk->current_dentry_address == walk->walk_root_dentry_address) {
        walk->reached_walk_root = 1;
        return 1;
    }
    walk->read_address = 0;
    walk->next_mount_address = 0;
    walk->next_dentry_address = 0;
    current_mount = (struct mount *)walk->current_mount_address;
    if (BPF_CORE_READ_INTO(&walk->read_address, current_mount, mnt.mnt_root) ||
        !walk->read_address ||
        !walk->current_dentry_address)
        goto failed;
    current = (struct dentry *)walk->current_dentry_address;
    if (BPF_CORE_READ_INTO(&walk->next_dentry_address, current, d_parent) ||
        !walk->next_dentry_address)
        goto failed;
    if (walk->current_dentry_address == walk->read_address ||
        walk->next_dentry_address == walk->current_dentry_address) {
        if (walk->current_mount_address == walk->walk_root_mount_address)
            goto failed;
        current_mount = (struct mount *)walk->current_mount_address;
        if (BPF_CORE_READ_INTO(&walk->next_mount_address,
                               current_mount, mnt_parent) ||
            !walk->next_mount_address ||
            walk->next_mount_address == walk->current_mount_address)
            goto failed;
        current_mount = (struct mount *)walk->current_mount_address;
        if (BPF_CORE_READ_INTO(&walk->next_dentry_address,
                               current_mount, mnt_mountpoint) ||
            !walk->next_dentry_address)
            goto failed;
        walk->current_mount_address = walk->next_mount_address;
        walk->current_dentry_address = walk->next_dentry_address;
        return 0;
    }
    current = (struct dentry *)walk->current_dentry_address;
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
    walk->walk_root_mount_address = (__u64)root_mount;
    walk->walk_root_dentry_address = (__u64)root.dentry;
    walk->current_mount_address = (__u64)current_mount;
    walk->current_dentry_address = (__u64)current;
    steps = bpf_loop(MAX_CANONICAL_MOUNTS_V1 +
                         MAX_CANONICAL_PATH_COMPONENTS_V1,
                     visible_path_walk_step, &context, 0);
    if (steps < 0 || walk->failed || !walk->reached_walk_root)
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
        *mutation_epoch <= global_generation &&
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
        *mutation_epoch = proposal->topology_generation;
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
                   "i"(MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 - 1));
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
    const declared_entry_request_v1 *request,
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
        request->path_length >= MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 ||
        !profile_generation_ref_id || !scratch ||
        bpf_probe_read_kernel(scratch->exec_argument,
                              sizeof(request->path), request->path))
        return 0;
    match = &scratch->logical_path_match;
    __builtin_memset(match, 0, sizeof(*match));
    match->path_length = request->path_length;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(last_index)
                 : [raw] "r"((__u64)match->path_length - 1),
                   "i"(MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1 - 1));
    if (scratch->exec_argument[0] != '/' ||
        scratch->exec_argument[last_index] == '/')
        return 0;
    __builtin_memset(&scratch->path_transition_key, 0,
                     sizeof(scratch->path_transition_key));
    scratch->path_transition_key.profile_generation_ref_id =
        profile_generation_ref_id;
    steps = bpf_loop(MAX_EXECUTION_APPROVAL_ARGUMENT_BYTES_V1,
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

#define CANONICAL_ROUTE_STATE_UNRESOLVED_V1 0xffffffffU
#define MAX_CANONICAL_ROUTED_PATH_MATCH_STEPS_V1                         \
    ((MAX_CANONICAL_PATH_COMPONENTS_V1 + 1) *                           \
     MAX_CANONICAL_ROUTE_STATES_V1)

static long canonical_routed_path_match_step(__u32 offset, void *data)
{
    struct canonical_path_match_context_v1 *context = data;
    struct identity_scratch_v1 *scratch = context->scratch;
    struct canonical_path_match_state_v1 *match = &scratch->path_match;
    __u32 route_count =
        scratch->canonical_mount_root.graph_prefix_state_count;
    __u32 component_offset;
    __u32 slot;
    __u32 state_id;
    __u64 bounded_slot;

    if (!route_count || route_count > MAX_CANONICAL_ROUTE_STATES_V1)
        goto unresolved;
    component_offset = offset / route_count;
    if (component_offset > match->component_count)
        return 1;
    slot = offset % route_count;
    asm volatile("%[bounded] = %[raw] ;\n"
                 "%[bounded] &= %2 ;\n"
                 : [bounded] "=&r"(bounded_slot)
                 : [raw] "r"((__u64)slot),
                   "i"(MAX_CANONICAL_ROUTE_STATES_V1 - 1));
    slot = bounded_slot;
    state_id = scratch->canonical_mount_root.graph_prefix_state_ids[slot];

    if (component_offset == match->component_count) {
        if (state_id != CANONICAL_ROUTE_STATE_UNRESOLVED_V1) {
            path_graph_terminal_v1 *terminal;
            __u64 *path_tree_deny_operation_mask;

            scratch->path_tree_deny_key.profile_generation_ref_id =
                match->profile_generation_ref_id;
            scratch->path_tree_deny_key.state_id = state_id;
            scratch->path_tree_deny_key.active_role_id = match->reserved;
            path_tree_deny_operation_mask = bpf_map_lookup_elem(
                &path_tree_denials, &scratch->path_tree_deny_key);
            if (path_tree_deny_operation_mask) {
                scratch->path_tree_deny_operation_mask |=
                    *path_tree_deny_operation_mask;
                match->state_id = 1;
            }
            scratch->path_state_key.profile_generation_ref_id =
                match->profile_generation_ref_id;
            scratch->path_state_key.state_id = state_id;
            scratch->path_state_key.reserved = 0;
            terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                           &scratch->path_state_key);
            if (terminal && terminal->composite_atom_id &&
                terminal->rule_numeric_id) {
                if (scratch->path_terminal.composite_atom_id &&
                    (scratch->path_terminal.composite_atom_id !=
                         terminal->composite_atom_id ||
                     scratch->path_terminal.rule_numeric_id !=
                         terminal->rule_numeric_id ||
                     scratch->path_terminal.exact_object_required !=
                         terminal->exact_object_required))
                    goto unresolved;
                scratch->path_terminal = *terminal;
                match->state_id = 1;
            }
        }
        return slot + 1 >= route_count;
    }

    if (!slot) {
        struct canonical_path_view_v1 *view;
        canonical_path_component_v1 *component;
        __u32 raw_index =
            match->component_count - component_offset - 1;
        __u32 raw_length;
        __u64 copy_length;
        __u64 index;

        asm volatile("%[bounded] = %[raw] ;\n"
                     "%[bounded] &= %2 ;\n"
                     : [bounded] "=&r"(index)
                     : [raw] "r"((__u64)raw_index),
                       "i"(MAX_CANONICAL_PATH_COMPONENTS_V1));
        view = &scratch->path_component_views[index];
        raw_length = view->length;
        if (!raw_length ||
            raw_length > MAX_CANONICAL_COMPONENT_BYTES_V1 ||
            !view->name_address)
            goto unresolved;
        component = &scratch->path_transition_key.component;
        if (bpf_probe_read_kernel(component->bytes,
                                  sizeof(component->bytes),
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
        component->length = raw_length;
        scratch->path_transition_key.reserved = 0;
    }

    if (state_id != CANONICAL_ROUTE_STATE_UNRESOLVED_V1) {
        path_graph_transition_v1 *transition;

        scratch->path_transition_key.current_state_id = state_id;
        transition = bpf_map_lookup_elem(
            &path_graph_exact_transitions,
            &scratch->path_transition_key);
        if (!transition) {
            scratch->path_state_key.profile_generation_ref_id =
                match->profile_generation_ref_id;
            scratch->path_state_key.state_id = state_id;
            scratch->path_state_key.reserved = 0;
            transition = bpf_map_lookup_elem(
                &path_graph_wildcard_transitions,
                &scratch->path_state_key);
        }
        scratch->canonical_mount_root.graph_prefix_state_ids[slot] =
            transition ? transition->next_state_id
                       : CANONICAL_ROUTE_STATE_UNRESOLVED_V1;
    }
    return 0;

unresolved:
    match->unresolved = 1;
    return 1;
}

/*
 * Each route state already belongs to the immutable policy graph. Equivalent
 * source paths stay separate so one denial cannot hide another denial.
 */
static __always_inline int match_routed_path_components(
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch,
    __u32 component_count, __u32 active_role_id,
    struct canonical_path_match_context_v1 *context)
{
    if (!scratch->canonical_mount_root.graph_prefix_state_count ||
        scratch->canonical_mount_root.graph_prefix_state_count >
            MAX_CANONICAL_ROUTE_STATES_V1)
        return -EACCES;
    __builtin_memset(&scratch->path_match, 0,
                     sizeof(scratch->path_match));
    scratch->path_match.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_match.component_count = component_count;
    scratch->path_match.reserved = active_role_id;
    if (bpf_loop(MAX_CANONICAL_ROUTED_PATH_MATCH_STEPS_V1,
                 canonical_routed_path_match_step, context, 0) < 0 ||
        scratch->path_match.unresolved ||
        !scratch->path_match.state_id)
        return -EACCES;
    return 0;
}

static __always_inline int match_path_components(
    __u64 profile_generation_ref_id, struct identity_scratch_v1 *scratch,
    __u32 component_count, __u32 active_role_id)
{
    path_graph_terminal_v1 *terminal;
    __u64 *path_tree_deny_operation_mask;
    struct canonical_path_match_context_v1 context = {
        .scratch = scratch,
    };
    long steps;

    __builtin_memset(&scratch->path_terminal, 0,
                     sizeof(scratch->path_terminal));
    scratch->path_tree_deny_operation_mask = 0;
    if (scratch->canonical_mount_root.graph_prefix_state_count)
        return match_routed_path_components(
            profile_generation_ref_id, scratch, component_count,
            active_role_id, &context);
    __builtin_memset(&scratch->path_match, 0,
                     sizeof(scratch->path_match));
    scratch->path_match.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_match.component_count = component_count;
    steps = bpf_loop(MAX_CANONICAL_PATH_COMPONENTS_V1,
                     canonical_path_match_step, &context, 0);
    if (steps < 0 || scratch->path_match.unresolved)
        return -EACCES;
    __builtin_memset(&scratch->path_state_key, 0,
                     sizeof(scratch->path_state_key));
    scratch->path_state_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_state_key.state_id = scratch->path_match.state_id;
    terminal = bpf_map_lookup_elem(&path_graph_terminals,
                                   &scratch->path_state_key);
    __builtin_memset(&scratch->path_tree_deny_key, 0,
                     sizeof(scratch->path_tree_deny_key));
    scratch->path_tree_deny_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->path_tree_deny_key.state_id =
        scratch->path_match.state_id;
    scratch->path_tree_deny_key.active_role_id = active_role_id;
    path_tree_deny_operation_mask = bpf_map_lookup_elem(
        &path_tree_denials, &scratch->path_tree_deny_key);
    if ((!terminal || !terminal->composite_atom_id ||
         !terminal->rule_numeric_id) && !path_tree_deny_operation_mask)
        return -EACCES;
    if (terminal)
        scratch->path_terminal = *terminal;
    if (path_tree_deny_operation_mask)
        scratch->path_tree_deny_operation_mask =
            *path_tree_deny_operation_mask;
    return 0;
}

static __always_inline int canonical_path_candidate(
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, __u32 active_role_id,
    struct identity_scratch_v1 *scratch, bool ignore_known_route)
{
    __u32 component_count = 0;

    if (collect_mount_components(path, binding, profile_generation_ref_id,
                                 scratch, &component_count,
                                 ignore_known_route))
        return -EACCES;
    return match_path_components(profile_generation_ref_id, scratch,
                                 component_count, active_role_id);
}

static __always_inline int known_mount_path_candidate(
    const struct path *path, const execution_set_binding_state_v1 *binding,
    __u64 profile_generation_ref_id, __u32 active_role_id,
    struct identity_scratch_v1 *scratch, bool require_mount_attachment)
{
    __u32 component_count = 0;

    if (collect_known_mount_components(
            path, binding, profile_generation_ref_id, scratch,
            &component_count, require_mount_attachment))
        return -EACCES;
    if (!scratch->canonical_mount_root.graph_prefix_state_count)
        return -EACCES;
    return match_path_components(profile_generation_ref_id, scratch,
                                 component_count, active_role_id);
}

static __always_inline int container_visible_path_candidate(
    const struct path *path, __u64 profile_generation_ref_id,
    __u32 active_role_id, struct identity_scratch_v1 *scratch)
{
    __u32 component_count = 0;

    /* A positive result means that no task-root path represents the object. */
    if (collect_visible_path_components(path, scratch, &component_count))
        return 1;
    __builtin_memset(&scratch->canonical_mount_root, 0,
                     sizeof(scratch->canonical_mount_root));
    return match_path_components(profile_generation_ref_id, scratch,
                                 component_count, active_role_id);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int erebor_mount_mutation_sys_exit(struct trace_event_raw_sys_exit *context)
{
    finish_mount_mutation();
    return 0;
}

#define MOUNT_ACTIVITY_ONLY(NAME)                                         \
    SEC("tracepoint/syscalls/sys_enter_" #NAME)                           \
    int erebor_mount_sys_enter_##NAME(struct trace_event_raw_sys_enter *context) \
    {                                                                     \
        (void)context;                                                    \
        record_mount_activity();                                         \
        return 0;                                                         \
    }

MOUNT_ACTIVITY_ONLY(open_tree)
MOUNT_ACTIVITY_ONLY(fsmount)

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int erebor_mount_sys_enter_fsconfig(struct trace_event_raw_sys_enter *context)
{
    record_mount_activity();
    if (context->args[1] == FSCONFIG_CMD_RECONFIGURE)
        (void)begin_global_mount_mutation();
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int erebor_mount_sys_enter_mount_setattr(
    struct trace_event_raw_sys_enter *context)
{
    (void)context;
    record_mount_activity();
    (void)begin_global_mount_mutation();
    return 0;
}

#endif /* EREBOR_IDENTITY_PATH_BPF_H */
