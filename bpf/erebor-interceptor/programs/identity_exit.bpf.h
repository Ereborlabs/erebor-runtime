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
    __u64 task_cookie;
    bool released = true;

    finish_mount_mutation();
    task = bpf_get_current_task_btf();
    exit_task_effect_attempts(task);
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
    if (!tombstone) {
        health = identity_health_record();
        if (health)
            health->reconciliation_required++;
        return 0;
    }
    tombstone->task_free_observed = 1;

    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
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

    process = bpf_map_lookup_elem(&process_states, &label->process_state_id);
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
    return 0;
}
#endif /* EREBOR_IDENTITY_EXIT_BPF_H */
