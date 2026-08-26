/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_PREPARED_CONTAINER_H
#define EREBOR_IDENTITY_PREPARED_CONTAINER_H

#define PREPARED_CONTAINER_IDENTITY_DEFER_V1 1
#define PREPARED_RUNTIME_EXEC_NONE_V1 0
#define PREPARED_RUNTIME_EXEC_ENTRY_V1 1
#define PREPARED_RUNTIME_EXEC_CONTAINER_BOOTSTRAP_V1 2
#define PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1 0
#define PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1 1
#define PREPARED_CONTAINER_BOOTSTRAP_COMPLETE_V1 2

static __always_inline void prepared_container_mark_corrupt(
    execution_set_binding_state_v1 *binding)
{
    if (!binding)
        return;
    binding->prepared_container_state = prepared_container_state_v1_corrupt;
    __sync_fetch_and_add(&binding->transition_version, 1);
}

static __always_inline bool prepared_container_binding_is_prepared(
    execution_set_binding_state_v1 *binding)
{
    return binding &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active &&
           binding->prepared_container_state ==
               prepared_container_state_v1_prepared;
}

static __always_inline bool prepared_container_actor_identity_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry)
{
    task_coordinate_v1 *coordinate;

    if (!binding || !label || !entry ||
        !binding_matches_label(binding, label) ||
        !id128_equal(&label->execution_set_id, &binding->execution_set_id) ||
        label->birth_profile_generation_ref_id !=
            binding->active_profile_generation_ref_id ||
        id128_is_zero(&binding->prepared_container_entry_instance_id) ||
        !id128_equal(&entry->entry_instance_id, &label->entry_instance_id) ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs)
        return false;
    coordinate = bpf_map_lookup_elem(&task_coordinates, &label->task_cookie);
    if (!coordinate || coordinate->task_cookie != label->task_cookie ||
        coordinate->state != task_coordinate_state_v1_runnable ||
        !binding->prepared_container_initial_host_tgid ||
        !coordinate->host_tgid || !coordinate->host_tid)
        return false;
    /* PREPARED is an exact binding state, not a runtime implementation
     * model. Every valid task in this binding receives the same state-bound bypass. */
    return true;
}

static __always_inline bool prepared_container_actor_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry)
{
    return prepared_container_binding_is_prepared(binding) &&
           prepared_container_actor_identity_is_exact(binding, label, entry);
}

static __always_inline bool prepared_container_bootstrap_exec_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry,
    const task_coordinate_v1 *coordinate,
    const process_execution_instance_v1 *active_execution)
{
    return prepared_container_actor_is_exact(binding, label, entry) &&
           coordinate && active_execution && label->lineage_depth > 0 &&
           binding->prepared_container_bootstrap_state ==
               PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1 &&
           !binding->prepared_container_exec_task_cookie &&
           id128_equal(&label->entry_instance_id,
                       &binding->prepared_container_entry_instance_id) &&
           coordinate->host_tgid !=
               binding->prepared_container_initial_host_tgid &&
           active_execution->started_by ==
               process_execution_started_by_v1_process_birth;
}

static __always_inline int prepared_container_reserve_bootstrap_exec(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label)
{
    if (!binding || !label ||
        binding->prepared_container_bootstrap_state !=
            PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1 ||
        __sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie, 0,
            label->task_cookie))
        return -EACCES;
    if (!prepared_container_binding_is_prepared(binding) ||
        binding->prepared_container_bootstrap_state !=
            PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1) {
        __sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie,
            label->task_cookie, 0);
        return -EACCES;
    }
    binding->prepared_container_bootstrap_state =
        PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline bool prepared_container_bootstrap_exec_is_pending(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label)
{
    return prepared_container_binding_is_prepared(binding) && label &&
           binding->prepared_container_bootstrap_state ==
               PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1 &&
           binding->prepared_container_exec_task_cookie ==
               label->task_cookie;
}

static __always_inline void prepared_container_rollback_bootstrap_exec(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->prepared_container_bootstrap_state !=
            PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1 ||
        binding->prepared_container_exec_task_cookie != task_cookie)
        return;
    binding->prepared_container_bootstrap_state =
        PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1;
    if (__sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie,
            task_cookie, 0) != task_cookie) {
        prepared_container_mark_corrupt(binding);
        return;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
}

static __always_inline int prepared_container_commit_bootstrap_exec(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->prepared_container_bootstrap_state !=
            PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1 ||
        binding->prepared_container_exec_task_cookie != task_cookie)
        return -EACCES;
    binding->prepared_container_bootstrap_state =
        PREPARED_CONTAINER_BOOTSTRAP_COMPLETE_V1;
    if (__sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie,
            task_cookie, 0) != task_cookie) {
        prepared_container_mark_corrupt(binding);
        return -EACCES;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline bool prepared_container_pre_active_actor_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry)
{
    if (prepared_container_actor_is_exact(binding, label, entry))
        return true;
    /* EXEC_PENDING is not active authority. Only the reserved exec task keeps
     * the bootstrap bypass until the successful exec commit. */
    if (!binding || !label || !entry ||
        binding->lifecycle_state != binding_lifecycle_state_v1_active ||
        binding->prepared_container_state !=
            prepared_container_state_v1_exec_pending ||
        binding->prepared_container_exec_task_cookie != label->task_cookie)
        return false;
    return prepared_container_actor_identity_is_exact(binding, label, entry);
}

static __always_inline bool prepared_container_admitted_actor_is_exact(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label,
    const entry_security_state_v1 *entry)
{
    return binding && label && entry &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active &&
           (binding->prepared_container_state ==
                prepared_container_state_v1_prepared ||
            binding->prepared_container_state ==
                prepared_container_state_v1_exec_pending ||
            binding->prepared_container_state ==
                prepared_container_state_v1_active) &&
           entry->admitted_entry_rule_id &&
           prepared_container_actor_identity_is_exact(binding, label, entry);
}

static __always_inline int prepared_container_set_initial_entry(
    execution_set_binding_state_v1 *binding, const id128_v1 *entry_instance_id)
{
    if (!binding || !entry_instance_id || id128_is_zero(entry_instance_id) ||
        !prepared_container_binding_is_prepared(binding) ||
        !id128_is_zero(&binding->prepared_container_entry_instance_id))
        return -EACCES;
    binding->prepared_container_entry_instance_id = *entry_instance_id;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline int prepared_container_reserve_activation(
    execution_set_binding_state_v1 *binding, const task_label_v1 *label)
{
    __u64 previous;

    if (!binding || !label)
        return -EACCES;
    if (binding->prepared_container_state ==
        prepared_container_state_v1_exec_pending)
        return binding->prepared_container_exec_task_cookie ==
                       label->task_cookie
                   ? 0
                   : -EACCES;
    if (binding->prepared_container_state ==
            prepared_container_state_v1_unarmed ||
        binding->prepared_container_state ==
            prepared_container_state_v1_active)
        return 0;
    if (binding->prepared_container_bootstrap_state ==
            PREPARED_CONTAINER_BOOTSTRAP_PENDING_V1 ||
        binding->prepared_container_exec_task_cookie)
        return -EACCES;
    if (!prepared_container_actor_is_exact(
            binding, label,
            bpf_map_lookup_elem(&entry_states, &label->entry_instance_id)))
        return -EACCES;
    if (__sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie, 0,
            label->task_cookie))
        return -EACCES;
    previous = __sync_val_compare_and_swap(
        &binding->prepared_container_state,
        prepared_container_state_v1_prepared,
        prepared_container_state_v1_exec_pending);
    if (previous != prepared_container_state_v1_prepared) {
        __sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie,
            label->task_cookie, 0);
        return -EACCES;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
    return 0;
}

static __always_inline void prepared_container_rollback_activation(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->prepared_container_state !=
            prepared_container_state_v1_exec_pending ||
        binding->prepared_container_exec_task_cookie != task_cookie)
        return;
    if (__sync_val_compare_and_swap(
            &binding->prepared_container_exec_task_cookie, task_cookie, 0) !=
            task_cookie ||
        __sync_val_compare_and_swap(
            &binding->prepared_container_state,
            prepared_container_state_v1_exec_pending,
            prepared_container_state_v1_prepared) !=
            prepared_container_state_v1_exec_pending) {
        prepared_container_mark_corrupt(binding);
        return;
    }
    __sync_fetch_and_add(&binding->transition_version, 1);
}

static __always_inline bool prepared_container_commit_activation(
    execution_set_binding_state_v1 *binding, __u64 task_cookie)
{
    if (!binding ||
        binding->prepared_container_exec_task_cookie != task_cookie ||
        __sync_val_compare_and_swap(
            &binding->prepared_container_state,
            prepared_container_state_v1_exec_pending,
            prepared_container_state_v1_active) !=
            prepared_container_state_v1_exec_pending)
        return false;
    binding->prepared_container_exec_task_cookie = 0;
    binding->prepared_container_bootstrap_state =
        PREPARED_CONTAINER_BOOTSTRAP_AVAILABLE_V1;
    __sync_fetch_and_add(&binding->transition_version, 1);
    return true;
}

#endif /* EREBOR_IDENTITY_PREPARED_CONTAINER_H */
