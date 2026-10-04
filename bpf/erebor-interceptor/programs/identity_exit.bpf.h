/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_EXIT_BPF_H
#define EREBOR_IDENTITY_EXIT_BPF_H

static __always_inline void close_entry_if_last_task(
    entry_security_state_v1 *entry)
{
    if (entry && entry->live_task_refs == 0 &&
        entry->lifetime_state == entry_lifetime_state_v1_active) {
        entry->lifetime_state = entry_lifetime_state_v1_draining;
        entry->transition_version++;
    }
}

static __always_inline void release_task_references(
    __u64 task_cookie, const id128_v1 *process_state_id,
    const id128_v1 *entry_instance_id)
{
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

    process = bpf_map_lookup_elem(&process_states, process_state_id);
    if (process)
        __sync_val_compare_and_swap(&process->exec_without_transition_task_cookie,
                                    task_cookie, 0);
    coordinate = bpf_map_lookup_elem(&task_coordinates, &task_cookie);
    if (coordinate) {
        kernel_real_parent_interval_key_v1 parent_key = {
            .child_task_cookie = task_cookie,
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
                                    &task_cookie);
    if (!tombstone) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
        return;
    }
    tombstone->task_free_observed = 1;

    entry = bpf_map_lookup_elem(&entry_states, entry_instance_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_ENTRY_V1);
    if (!(previous & TASK_REFERENCE_ENTRY_V1)) {
        if (entry) {
            if (!decrement_nonzero_counter(&entry->live_task_refs))
                released = false;
        } else {
            released = false;
        }
    }

    process = bpf_map_lookup_elem(&process_states, process_state_id);
    previous = __sync_fetch_and_or(&tombstone->released_bits,
                                   TASK_REFERENCE_PROCESS_V1);
    if (!(previous & TASK_REFERENCE_PROCESS_V1)) {
        if (process) {
            previous = decrement_nonzero_counter(&process->live_thread_refs);
            if (previous == 0) {
                process->state = process_security_state_kind_v1_corrupt;
                process->transition_version++;
                released = false;
            } else if (previous == 1) {
                process_execution_instance_v1 *execution =
                    bpf_map_lookup_elem(&process_execution_instances,
                                        &process->active_execution_id);

                process_vector = bpf_map_lookup_elem(
                    &process_state_vectors, process_state_id);

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
                    !decrement_nonzero_counter(&domain->live_process_refs))
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
            !decrement_nonzero_counter(profile_task_refs))
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
}

extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;

static __always_inline int task_coordinate_lifetime_exists(
    const task_coordinate_v1 *coordinate)
{
    struct task_struct *task = bpf_task_from_pid(coordinate->host_tid);
    kernel_real_parent_interval_v1 lifetime = {};
    int result = -EACCES;

    if (!task)
        return 0;
    if (!read_parent_interval(task, 0, 0, 0, &lifetime))
        result = lifetime.real_parent_host_tid == coordinate->host_tid &&
                 lifetime.real_parent_host_tgid == coordinate->host_tgid &&
                 lifetime.real_parent_pid_namespace_inode ==
                     coordinate->pid_namespace_inode &&
                 lifetime.real_parent_start_boottime_ns ==
                     coordinate->task_start_boottime_ns;
    bpf_task_release(task);
    return result;
}

static long reconcile_orphan_task_reference(
    struct bpf_map *map, const __u64 *key, task_coordinate_v1 *coordinate,
    void *context)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    task_reference_tombstone_v1 *tombstone;
    external_root_classification_v1 *root;
    process_security_state_v1 *process;
    entry_security_state_v1 *entry;

    (void)map;
    (void)context;
    if (!config || !config->enabled || !coordinate || !*key ||
        coordinate->task_cookie != *key || !coordinate->host_tid ||
        coordinate->host_tid != coordinate->host_tgid ||
        !coordinate->pid_namespace_inode || !coordinate->task_start_boottime_ns ||
        !coordinate->finalized_boottime_ns ||
        (coordinate->state != task_coordinate_state_v1_runnable &&
         coordinate->state != task_coordinate_state_v1_fail_closed_unknown))
        return 0;
    tombstone = bpf_map_lookup_elem(&task_reference_tombstones, key);
    root = bpf_map_lookup_elem(&external_root_classifications, key);
    if (!tombstone || !root || tombstone->task_cookie != *key ||
        tombstone->state != reference_tombstone_state_v1_owned ||
        tombstone->acquired_bits != TASK_REFERENCE_ALL_V1 ||
        tombstone->released_bits || tombstone->task_free_observed ||
        tombstone->birth_transition_version != 1 ||
        tombstone->birth_transaction_id.low != *key || root->task_cookie != *key ||
        root->profile_generation_ref_id != tombstone->profile_generation_ref_id ||
        id128_is_zero(&root->cgroup_binding_id) ||
        id128_is_zero(&root->cgroup_lifetime_id) ||
        root->creator_task_cookie ||
        (root->root_class != external_root_class_v1_external_runtime_root &&
         root->root_class != external_root_class_v1_restored_or_unknown_root) ||
        !id128_equal(&root->node_boot_id, &config->node_boot_id) ||
        root->label_epoch != config->label_epoch ||
        !id128_equal(&root->process_state_id, &tombstone->process_state_id) ||
        !id128_equal(&root->entry_instance_id, &tombstone->entry_instance_id) ||
        !id128_equal(&coordinate->process_state_id, &tombstone->process_state_id))
        return 0;
    process = bpf_map_lookup_elem(&process_states, &tombstone->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &tombstone->entry_instance_id);
    if (!process || !entry ||
        !id128_equal(&process->process_state_id, &tombstone->process_state_id) ||
        !id128_equal(&process->process_instance_id, &coordinate->process_instance_id) ||
        !id128_equal(&process->entry_instance_id, &tombstone->entry_instance_id) ||
        !id128_equal(&entry->entry_instance_id, &tombstone->entry_instance_id) ||
        !id128_equal(&entry->root_process_state_id, &tombstone->process_state_id) ||
        !id128_equal(&entry->execution_set_id, &root->execution_set_id) ||
        entry->root_task_cookie != *key ||
        !id128_equal(&process->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&entry->node_boot_id, &config->node_boot_id) ||
        process->label_epoch != config->label_epoch ||
        entry->label_epoch != config->label_epoch ||
        tombstone->birth_transaction_id.high != config->label_epoch ||
        process->state != process_security_state_kind_v1_active ||
        !process->live_thread_refs || !entry->live_task_refs ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->transition_guard ||
        process->transition_guard || process->exec_guard_state != exec_guard_state_v1_none ||
        !id128_is_zero(&process->pending_exec_id) ||
        bpf_map_lookup_elem(&pending_execution_approvals, key))
        return 0;
    /* A live exact lifetime retains ownership even if its label changed. */
    if (task_coordinate_lifetime_exists(coordinate) != 0)
        return 0;
    if (tombstone->state != reference_tombstone_state_v1_owned ||
        tombstone->released_bits || tombstone->task_free_observed)
        return 0;
    release_task_references(*key, &tombstone->process_state_id,
                             &tombstone->entry_instance_id);
    return 0;
}

static __noinline int reconcile_orphan_task_references(void)
{
    long result = bpf_for_each_map_elem(&task_coordinates,
                                       reconcile_orphan_task_reference, NULL, 0);

    if (result < 0) {
        identity_health_v1 *health = identity_health_record();

        if (health)
            health->reconciliation_required++;
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int erebor_sched_process_exit(struct trace_event_raw_sched_process_template *context)
{
    struct task_struct *task;
    struct cgroup *cgroup = NULL;
    identity_runtime_config_v1 *config;
    execution_set_binding_state_v1 *binding;
    task_label_v1 *label;
    __u64 task_cookie;
    int binding_lookup = -EACCES;

    finish_mount_mutation();
    task = bpf_get_current_task_btf();
    config = identity_runtime_config();
    if (config && !task_cgroup(task, &cgroup)) {
        binding = binding_for_cgroup(cgroup, &binding_lookup);
        if (!binding_lookup)
            recovered_container_task_set_changed(binding);
    }
    exit_task_effect_attempts(task);
    clear_provisional_exec_request(task);
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    task_cookie = __sync_fetch_and_add(&label->task_cookie, 0);
    if (!task_cookie) {
        task_cookie = __sync_val_compare_and_swap(
            &label->task_cookie, 0, TASK_LABEL_EXIT_COOKIE_V1);
        if (!task_cookie)
            return 0;
    }
    if (task_cookie == TASK_LABEL_CLAIM_COOKIE_V1) {
        task_cookie = __sync_val_compare_and_swap(
            &label->task_cookie, TASK_LABEL_CLAIM_COOKIE_V1,
            TASK_LABEL_EXIT_COOKIE_V1);
        if (task_cookie == TASK_LABEL_CLAIM_COOKIE_V1)
            return 0;
    }
    if (task_cookie == TASK_LABEL_EXIT_COOKIE_V1)
        return 0;
    close_current_execution_approval(label);
    bpf_map_delete_elem(&pending_execution_approvals, &label->task_cookie);
    release_task_references(label->task_cookie, &label->process_state_id,
                             &label->entry_instance_id);
    return 0;
}
#endif /* EREBOR_IDENTITY_EXIT_BPF_H */
