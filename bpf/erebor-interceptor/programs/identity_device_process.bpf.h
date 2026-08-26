/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_DEVICE_PROCESS_BPF_H
#define EREBOR_IDENTITY_DEVICE_PROCESS_BPF_H

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

static __always_inline bool current_typed_effect_context(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    task_label_v1 *label)
{
    return config && config->enabled && config->effect_policy_enabled &&
           scratch && label && label_matches_runtime(label, config) &&
           scratch->observation.task_cookie == label->task_cookie &&
           scratch->observation.profile_generation_ref_id ==
               scratch->process.active_profile_generation_ref_id &&
           id128_equal(&label->process_state_id,
                       &scratch->process.process_state_id);
}

static __noinline int identity_device_ioctl_effect(struct file *file,
                                                   __u32 cmd)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    struct task_struct *task;
    task_label_v1 *label;
    execution_set_binding_state_v1 *binding;
    profile_generation_descriptor_v1 *generation;
    physical_decision_v1 *decision;
    exact_device_type_v1 device_type;
    __u32 device_major;
    __u32 device_minor;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    config = identity_runtime_config();
    if (!config || !config->enabled || !config->effect_policy_enabled)
        return 0;
    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);
    if (!label)
        return 0;
    scratch = identity_scratch_record();
    if (!current_typed_effect_context(config, scratch, label) ||
        task_cgroup(task, &cgroup))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding_matches_label(binding, label))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    scratch->observation.controller_process_state_id = label->process_state_id;
    scratch->observation.controller_transition_version =
        scratch->process.transition_version;
    scratch->observation.operation_argument = cmd;
    if (exact_device_from_file(&scratch->file_object, file, &device_type,
                               &device_major, &device_minor))
        return current_admitted_actor_is_exact(binding)
                   ? application_default_effect_result(scratch)
                   : hard_effect_result(
                         config, scratch,
                         effect_observation_reason_v1_unsupported_object);
    scratch->file_object.profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    if (!exact_file_keys_equal(&scratch->file_object,
                               &scratch->observation.file_object) ||
        !scratch->observation.exact_object_key_id)
        return current_admitted_actor_is_exact(binding)
                   ? application_default_effect_result(scratch)
                   : hard_effect_result(
                         config, scratch,
                         effect_observation_reason_v1_unresolved_object);

    __builtin_memset(&scratch->device_effect_key, 0,
                     sizeof(scratch->device_effect_key));
    scratch->device_effect_key.profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    scratch->device_effect_key.mount_id_unique =
        scratch->file_object.mount_id_unique;
    scratch->device_effect_key.inode = scratch->file_object.inode;
    scratch->device_effect_key.exact_object_key_id =
        scratch->observation.exact_object_key_id;
    scratch->device_effect_key.active_role_id =
        scratch->process.active_role_id;
    scratch->device_effect_key.process_state_vector_id =
        scratch->process.process_state_vector_id;
    scratch->device_effect_key.mount_namespace_inode =
        scratch->file_object.mount_namespace_inode;
    scratch->device_effect_key.filesystem_device =
        scratch->file_object.filesystem_device;
    scratch->device_effect_key.inode_generation =
        scratch->file_object.inode_generation;
    scratch->device_effect_key.device_major = device_major;
    scratch->device_effect_key.device_minor = device_minor;
    scratch->device_effect_key.ioctl_command = cmd;
    scratch->device_effect_key.operation =
        kernel_effect_operation_v1_ioctl;
    scratch->device_effect_key.binding_lifecycle_state =
        binding->lifecycle_state;
    scratch->device_effect_key.device_type = device_type;
    decision = bpf_map_lookup_elem(&device_effect_decisions,
                                   &scratch->device_effect_key);
    if (!decision) {
        scratch->device_effect_key.ioctl_command = 0;
        scratch->device_effect_key.command_wildcard = 1;
        decision = bpf_map_lookup_elem(&device_effect_decisions,
                                       &scratch->device_effect_key);
    }
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    if (!generation)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    return apply_effect_decision(
        config, scratch, generation, decision,
        current_admitted_actor_is_exact(binding), true, false);
}

static __always_inline int identity_device_ioctl_gate(struct file *file,
                                                      __u32 cmd, int ret)
{
    struct identity_scratch_v1 *scratch;

    ret = identity_effect_actor_gate(
        file, kernel_effect_family_v1_device,
        kernel_effect_operation_v1_ioctl, ret);
    if (ret)
        return ret;
    scratch = identity_scratch_record();
    if (runtime_infrastructure_effect_was_allowed(scratch))
        return 0;
    return identity_device_ioctl_effect(file, cmd);
}

static __always_inline int snapshot_process_control_target(
    struct task_struct *target, identity_runtime_config_v1 *config,
    struct identity_scratch_v1 *scratch,
    execution_set_binding_state_v1 **target_binding_out,
    process_security_state_v1 **target_process_out,
    task_coordinate_v1 **target_coordinate_out)
{
    task_label_v1 *label;
    task_coordinate_v1 *coordinate;
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    entry_security_state_v1 *entry;
    execution_set_binding_state_v1 *binding;
    profile_generation_descriptor_v1 *generation;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!target)
        return -EACCES;
    label = bpf_task_storage_get(&task_labels, target, 0, 0);
    if (!label || !label_matches_runtime(label, config) ||
        task_cgroup(target, &cgroup))
        return -EACCES;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    if (binding_lookup || !binding_matches_label(binding, label))
        return -EACCES;
    coordinate = bpf_map_lookup_elem(&task_coordinates,
                                     &label->task_cookie);
    process = bpf_map_lookup_elem(&process_states,
                                  &label->process_state_id);
    vector = bpf_map_lookup_elem(&process_state_vectors,
                                 &label->process_state_id);
    entry = bpf_map_lookup_elem(&entry_states, &label->entry_instance_id);
    if (!coordinate || !process || !vector || !entry ||
        snapshot_process_state(process, &scratch->target_process))
        return -EACCES;
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->target_process.active_profile_generation_ref_id);
    scratch->target_label = *label;
    scratch->target_coordinate = *coordinate;
    scratch->target_process_vector = *vector;
    if (scratch->target_coordinate.state !=
            task_coordinate_state_v1_runnable ||
        scratch->target_coordinate.task_cookie !=
            scratch->target_label.task_cookie ||
        !id128_equal(&scratch->target_coordinate.process_instance_id,
                     &scratch->target_label.process_instance_id) ||
        !id128_equal(&scratch->target_coordinate.process_state_id,
                     &scratch->target_label.process_state_id) ||
        scratch->target_process.state !=
            process_security_state_kind_v1_active ||
        !scratch->target_process.live_thread_refs ||
        !id128_equal(&scratch->target_process.process_state_id,
                     &scratch->target_label.process_state_id) ||
        !id128_equal(&scratch->target_process.process_lineage_id,
                     &scratch->target_label.process_lineage_id) ||
        !id128_equal(&scratch->target_process.process_instance_id,
                     &scratch->target_label.process_instance_id) ||
        !id128_equal(&scratch->target_process.entry_instance_id,
                     &scratch->target_label.entry_instance_id) ||
        entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs || entry->label_epoch != config->label_epoch ||
        !id128_equal(&entry->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&entry->entry_instance_id,
                     &scratch->target_label.entry_instance_id) ||
        !id128_equal(&entry->execution_set_id, &binding->execution_set_id) ||
        scratch->target_process.label_epoch != config->label_epoch ||
        !id128_equal(&scratch->target_process.node_boot_id,
                     &config->node_boot_id) ||
        scratch->target_process.active_profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        !generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id !=
            scratch->target_process.active_profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id) ||
        scratch->target_process_vector.state !=
            process_state_vector_state_v1_active ||
        scratch->target_process_vector.process_state_vector_id !=
            scratch->target_process.process_state_vector_id ||
        scratch->target_process_vector.profile_generation_ref_id !=
            scratch->target_process.active_profile_generation_ref_id ||
        scratch->target_process_vector.label_epoch != config->label_epoch ||
        !id128_equal(&scratch->target_process_vector.node_boot_id,
                     &config->node_boot_id))
        return -EACCES;
    *target_binding_out = binding;
    *target_process_out = process;
    *target_coordinate_out = coordinate;
    return 0;
}

#define EFFECT_CONTROLLER_PTRACE_READ_V1 0x01U
#define EFFECT_CONTROLLER_PTRACE_ATTACH_V1 0x02U
#define EFFECT_CONTROLLER_PTRACE_NOAUDIT_V1 0x04U
#define EFFECT_CONTROLLER_PTRACE_FSCREDS_V1 0x08U
#define EFFECT_CONTROLLER_PTRACE_REALCREDS_V1 0x10U
#define EFFECT_CONTROLLER_PTRACE_ALLOWED_V1                                  \
    (EFFECT_CONTROLLER_PTRACE_READ_V1 |                                    \
     EFFECT_CONTROLLER_PTRACE_NOAUDIT_V1 |                                 \
     EFFECT_CONTROLLER_PTRACE_FSCREDS_V1 |                                 \
     EFFECT_CONTROLLER_PTRACE_REALCREDS_V1)

static __always_inline bool ptrace_mode_is_read_only(__u16 operation,
                                                      __u32 argument)
{
    return operation == kernel_effect_operation_v1_ptrace &&
           argument & EFFECT_CONTROLLER_PTRACE_READ_V1 &&
           !(argument & EFFECT_CONTROLLER_PTRACE_ATTACH_V1) &&
           !(argument & ~EFFECT_CONTROLLER_PTRACE_ALLOWED_V1) &&
           !!(argument & EFFECT_CONTROLLER_PTRACE_FSCREDS_V1) !=
               !!(argument & EFFECT_CONTROLLER_PTRACE_REALCREDS_V1);
}

static __always_inline bool effect_controller_may_read_target(
    const identity_runtime_config_v1 *config, struct task_struct *target,
    __u16 operation, __u32 operation_argument)
{
    execution_set_binding_state_v1 *binding;
    struct cgroup *target_cgroup = NULL;
    int binding_lookup;

    if (!ptrace_mode_is_read_only(operation, operation_argument) ||
        !config->effect_controller_cgroup_id ||
        bpf_get_current_cgroup_id() !=
            config->effect_controller_cgroup_id ||
        task_cgroup(target, &target_cgroup))
        return false;
    binding = binding_for_cgroup(target_cgroup, &binding_lookup);
    return !binding_lookup && binding &&
           binding->lifecycle_state == binding_lifecycle_state_v1_active &&
           binding->label_epoch == config->label_epoch &&
           id128_equal(&binding->node_boot_id, &config->node_boot_id);
}

static __always_inline bool prepared_container_target_is_exact(
    const identity_runtime_config_v1 *config, struct task_struct *target,
    task_label_v1 **target_label_out)
{
    execution_set_binding_state_v1 *binding;
    entry_security_state_v1 *entry;
    task_label_v1 *label;
    struct cgroup *cgroup = NULL;
    int binding_lookup;

    if (!config || !target || task_cgroup(target, &cgroup))
        return false;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    label = bpf_task_storage_get(&task_labels, target, 0, 0);
    entry = label
                ? bpf_map_lookup_elem(&entry_states,
                                      &label->entry_instance_id)
                : NULL;
    if (binding_lookup || !label || !label_matches_runtime(label, config) ||
        !prepared_container_pre_active_actor_is_exact(binding, label, entry))
        return false;
    if (target_label_out)
        *target_label_out = label;
    return true;
}

static __noinline bool runtime_entry_may_control_initial_target(
    const identity_runtime_config_v1 *config, struct task_struct *target,
    __u16 operation, __u32 operation_argument,
    task_label_v1 **target_label_out)
{
    struct task_struct *current = bpf_get_current_task_btf();
    struct runtime_entry_bootstrap_state_v1 *bootstrap;
    task_label_v1 *current_label;
    task_label_v1 *target_label;
    entry_security_state_v1 *current_entry;
    entry_security_state_v1 *target_entry;
    external_root_classification_v1 *classification;
    execution_set_binding_state_v1 *binding;
    struct cgroup *target_cgroup = NULL;
    bool prepares_runtime;
    bool signals_target;
    int binding_lookup;

    prepares_runtime = ptrace_mode_is_read_only(operation, operation_argument);
    signals_target = operation == kernel_effect_operation_v1_signal;
    if (!config || !target || (!prepares_runtime && !signals_target) ||
        task_cgroup(target, &target_cgroup))
        return false;
    binding = binding_for_cgroup(target_cgroup, &binding_lookup);
    target_label = bpf_task_storage_get(&task_labels, target, 0, 0);
    target_entry = target_label
                       ? bpf_map_lookup_elem(&entry_states,
                                             &target_label->entry_instance_id)
                       : NULL;
    if (binding_lookup || !binding || !target_label || !target_entry ||
        binding->prepared_container_state != prepared_container_state_v1_active ||
        !binding_matches_label(binding, target_label) ||
        !id128_equal(&binding->prepared_container_entry_instance_id,
                     &target_label->entry_instance_id) ||
        !target_entry->admitted_entry_rule_id)
        return false;
    if (signals_target) {
        bootstrap = runtime_entry_bootstrap_for_task(current);
        if (!runtime_entry_bootstrap_state_valid(bootstrap, config) ||
            bootstrap->profile_generation_ref_id !=
                binding->active_profile_generation_ref_id ||
            !id128_equal(&bootstrap->binding_id, &binding->binding_id) ||
            !id128_equal(&bootstrap->target_entry_instance_id,
                         &target_label->entry_instance_id))
            return false;
        *target_label_out = target_label;
        return true;
    }
    current_label = current
                        ? bpf_task_storage_get(&task_labels, current, 0, 0)
                        : NULL;
    if (!current_label) {
        if (mark_runtime_entry_bootstrap(current, config, binding,
                                         target_label))
            return false;
        *target_label_out = target_label;
        return true;
    }
    current_entry = bpf_map_lookup_elem(&entry_states,
                                        &current_label->entry_instance_id);
    classification = entry_root_classification(current_label, current_entry);
    if (!current_entry || !classification ||
        !binding_matches_label(binding, current_label) ||
        current_entry->admitted_entry_rule_id ||
        classification->root_class !=
            external_root_class_v1_external_runtime_root ||
        classification->installed_role_class !=
            installed_role_class_v1_runtime_external_restricted)
        return false;
    if (mark_runtime_entry_bootstrap(current, config, binding, target_label))
        return false;
    *target_label_out = target_label;
    return true;
}

static __noinline int identity_process_control_effect(
    struct task_struct *target, __u16 operation, __u32 operation_argument)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    struct task_struct *controller;
    task_label_v1 *controller_label;
    task_label_v1 *target_live_label;
    process_security_state_v1 *controller_process;
    process_security_state_v1 *target_process;
    task_coordinate_v1 *target_coordinate;
    execution_set_binding_state_v1 *binding;
    execution_set_binding_state_v1 *target_binding;
    execution_set_binding_state_v1 *unlabeled_target_binding;
    profile_generation_descriptor_v1 *generation;
    physical_decision_v1 *rule;
    struct cgroup *cgroup = NULL;
    struct cgroup *target_cgroup = NULL;
    int binding_lookup;
    int target_binding_lookup;

    scratch = identity_scratch_record();
    config = identity_runtime_config();
    if (!config || !config->enabled || !config->effect_policy_enabled)
        return 0;
    controller = bpf_get_current_task_btf();
    controller_label = bpf_task_storage_get(&task_labels, controller, 0, 0);
    if (!controller_label) {
        if (effect_controller_may_read_target(
                config, target, operation, operation_argument))
            return 0;
        target_live_label = bpf_task_storage_get(&task_labels, target, 0, 0);
        if (target_live_label && label_matches_runtime(target_live_label, config))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_missing_identity);
        if (task_cgroup(target, &target_cgroup))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        unlabeled_target_binding = binding_for_cgroup(
            target_cgroup, &target_binding_lookup);
        if (target_binding_lookup)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        if (unlabeled_target_binding)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_missing_identity);
        return 0;
    }
    scratch = identity_scratch_record();
    if (!current_typed_effect_context(config, scratch, controller_label) ||
        task_cgroup(controller, &cgroup))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    controller_process = bpf_map_lookup_elem(
        &process_states, &controller_label->process_state_id);
    if (binding_lookup || !binding_matches_label(binding, controller_label) ||
        !controller_process ||
        snapshot_process_control_target(
            target, config, scratch, &target_binding, &target_process,
            &target_coordinate))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);

    scratch->observation.controller_process_state_id =
        controller_label->process_state_id;
    scratch->observation.controller_transition_version =
        scratch->process.transition_version;
    scratch->observation.target_task_cookie = scratch->target_label.task_cookie;
    scratch->observation.target_profile_generation_ref_id =
        scratch->target_process.active_profile_generation_ref_id;
    scratch->observation.target_process_state_id =
        scratch->target_label.process_state_id;
    scratch->observation.target_transition_version =
        scratch->target_process.transition_version;
    scratch->observation.target_role_id = scratch->target_process.active_role_id;
    scratch->observation.target_process_state_vector_id =
        scratch->target_process.process_state_vector_id;
    scratch->observation.operation_argument = operation_argument;
    __builtin_memset(&scratch->process_control_rule_key, 0,
                     sizeof(scratch->process_control_rule_key));
    scratch->process_control_rule_key.profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    scratch->process_control_rule_key.controller_role_id =
        scratch->process.active_role_id;
    scratch->process_control_rule_key.controller_process_state_vector_id =
        scratch->process.process_state_vector_id;
    scratch->process_control_rule_key.target_role_id =
        scratch->target_process.active_role_id;
    scratch->process_control_rule_key.target_process_state_vector_id =
        scratch->target_process.process_state_vector_id;
    scratch->process_control_rule_key.operation_argument = operation_argument;
    scratch->process_control_rule_key.operation = operation;
    scratch->process_control_rule_key.binding_lifecycle_state =
        binding->lifecycle_state;
    rule = bpf_map_lookup_elem(&process_control_rules,
                               &scratch->process_control_rule_key);
    if (!rule) {
        scratch->process_control_rule_key.operation_argument = 0;
        scratch->process_control_rule_key.argument_wildcard = 1;
        rule = bpf_map_lookup_elem(&process_control_rules,
                                   &scratch->process_control_rule_key);
    }
    if (rule && scratch->process_control_rule_key.argument_wildcard &&
        rule->decision != physical_decision_kind_v1_deny)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);

    target_live_label = bpf_task_storage_get(&task_labels, target, 0, 0);
    if (!target_live_label ||
        !label_matches_runtime(target_live_label, config) ||
        target_live_label->task_cookie !=
            scratch->observation.target_task_cookie ||
        !id128_equal(&target_live_label->process_state_id,
                     &scratch->observation.target_process_state_id) ||
        __sync_fetch_and_add(&controller_process->transition_guard, 0) ||
        __sync_fetch_and_add(&controller_process->transition_version, 0) !=
            scratch->observation.controller_transition_version ||
        __sync_fetch_and_add(&target_process->transition_guard, 0) ||
        __sync_fetch_and_add(&target_process->transition_version, 0) !=
            scratch->observation.target_transition_version ||
        target_coordinate->state != task_coordinate_state_v1_runnable ||
        target_coordinate->task_cookie !=
            scratch->observation.target_task_cookie ||
        !id128_equal(&target_coordinate->process_state_id,
                     &scratch->observation.target_process_state_id) ||
        !id128_equal(&target_coordinate->process_instance_id,
                     &scratch->target_label.process_instance_id) ||
        !binding_matches_label(binding, controller_label) ||
        !binding_matches_label(target_binding, target_live_label))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    if (!generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    return apply_effect_decision(
        config, scratch, generation, rule,
        current_admitted_actor_is_exact(binding), true, false);
}

static __always_inline int identity_process_control_gate(
    struct task_struct *target, __u16 operation, __u32 operation_argument,
    int ret)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    task_label_v1 *target_label = NULL;

    config = identity_runtime_config();
    if (!ret && config && config->enabled && config->effect_policy_enabled &&
        prepared_container_target_is_exact(config, target, &target_label)) {
        /* Stock runtimes inspect and signal the held task from outside its
         * cgroup. PREPARED therefore follows the exact target, not the caller. */
        scratch = identity_scratch_record();
        if (scratch) {
            begin_effect_observation(
                scratch, kernel_effect_family_v1_privilege, operation);
            scratch->observation.target_task_cookie = target_label->task_cookie;
            scratch->observation.operation_argument = operation_argument;
        }
        return prepared_runtime_effect_result(scratch);
    }
    if (!ret && config && config->enabled && config->effect_policy_enabled &&
        runtime_entry_may_control_initial_target(
            config, target, operation, operation_argument, &target_label)) {
        scratch = identity_scratch_record();
        if (scratch) {
            begin_effect_observation(
                scratch, kernel_effect_family_v1_privilege, operation);
            scratch->observation.target_task_cookie = target_label->task_cookie;
            scratch->observation.operation_argument = operation_argument;
        }
        return runtime_entry_infrastructure_effect_result(scratch);
    }

    ret = identity_effect_actor_gate(
        NULL, kernel_effect_family_v1_privilege, operation, ret);
    if (ret)
        return ret;
    scratch = identity_scratch_record();
    if (runtime_infrastructure_effect_was_allowed(scratch))
        return 0;
    return identity_process_control_effect(target, operation,
                                           operation_argument);
}

#endif /* EREBOR_IDENTITY_DEVICE_PROCESS_BPF_H */
