use std::collections::{BTreeMap, BTreeSet};

use erebor_interceptor_abi::{
    BindingLifecycleStateV1, DeviceEffectKeyV1, ExactDeviceTypeV1, KernelEffectFamilyV1,
    KernelEffectOperationV1, PhysicalDecisionKindV1, PhysicalDecisionV1, ProcessControlRuleKeyV1,
};
use mithril_control::{CompiledDecisionCellV1, CompiledOperationV1};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::error::IdentityStateSnafu;
use crate::{ExactDeviceType, ExactFileObjectConfig, Result};

use super::insert_exact;

pub(super) struct TypedEffectContext<'a> {
    pub profile_generation_ref_id: u64,
    pub actor_role_id: u32,
    pub actor_process_state_vector_id: u32,
    pub entry_kind: u16,
    pub binding_lifecycle_state: BindingLifecycleStateV1,
    pub exact_objects: &'a [&'a ExactFileObjectConfig],
    pub signed_device_classes: &'a BTreeSet<String>,
    pub role_states: &'a BTreeMap<String, (u32, u32)>,
}

pub(super) fn lower_typed_effect(
    cell: &CompiledDecisionCellV1,
    context: &TypedEffectContext<'_>,
    decision: PhysicalDecisionV1,
    device_rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    process_rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<bool> {
    if let Some(selector) = cell.key.object_selector.strip_prefix("DEVICE:") {
        lower_device(cell, selector, context, decision, device_rows)?;
        return Ok(true);
    }
    if let Some(target_role) = cell.key.object_selector.strip_prefix("SECURITY:PROCESS:") {
        lower_process(cell, target_role, context, decision, process_rows)?;
        return Ok(true);
    }
    Ok(false)
}

fn lower_device(
    cell: &CompiledDecisionCellV1,
    selector: &str,
    context: &TypedEffectContext<'_>,
    decision: PhysicalDecisionV1,
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    ensure!(
        KernelEffectFamilyV1::from(cell.key.effect_family) == KernelEffectFamilyV1::Device
            && CompiledOperationV1::try_from(cell.key.operation_id.as_str())
                .is_ok_and(|operation| operation.kernel_id == KernelEffectOperationV1::Ioctl),
        IdentityStateSnafu {
            reason: "a DEVICE selector is valid only for the DEVICE/IOCTL effect",
        }
    );
    let (device_class, command) = selector.rsplit_once(':').ok_or_else(|| {
        IdentityStateSnafu {
            reason: format!("invalid compiled device selector `DEVICE:{selector}`"),
        }
        .build()
    })?;
    ensure!(
        !device_class.is_empty(),
        IdentityStateSnafu {
            reason: "a compiled device selector has an empty device class",
        }
    );
    ensure!(
        context.signed_device_classes.contains(device_class),
        IdentityStateSnafu {
            reason: format!("device class `{device_class}` has no signed path selector"),
        }
    );
    let (ioctl_command, command_wildcard) = if command == "*" {
        (0, 1)
    } else {
        (
            command.parse::<u32>().map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("invalid ioctl command `{command}`: {error}"),
                }
                .build()
            })?,
            0,
        )
    };
    for object in context.exact_objects {
        let Some(device) = object
            .device
            .as_ref()
            .filter(|device| device.device_class_id == device_class)
        else {
            continue;
        };
        let key = DeviceEffectKeyV1 {
            profile_generation_ref_id: context.profile_generation_ref_id,
            mount_id_unique: object.mount_id_unique,
            inode: object.inode,
            exact_object_key_id: object.exact_object_key_id,
            active_role_id: context.actor_role_id,
            process_state_vector_id: context.actor_process_state_vector_id,
            mount_namespace_inode: object.mount_namespace_inode,
            filesystem_device: object.filesystem_device,
            inode_generation: object.inode_generation,
            device_major: device.major,
            device_minor: device.minor,
            ioctl_command,
            entry_kind: context.entry_kind,
            operation: KernelEffectOperationV1::Ioctl as u16,
            binding_lifecycle_state: context.binding_lifecycle_state,
            device_type: match device.device_type {
                ExactDeviceType::Character => ExactDeviceTypeV1::Character,
                ExactDeviceType::Block => ExactDeviceTypeV1::Block,
            },
            command_wildcard,
            reserved: 0,
            reserved_tail: [0; 4],
        };
        insert_exact(rows, key.as_bytes(), decision.as_bytes())?;
    }
    Ok(())
}

fn lower_process(
    cell: &CompiledDecisionCellV1,
    target_role: &str,
    context: &TypedEffectContext<'_>,
    decision: PhysicalDecisionV1,
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    let operation = CompiledOperationV1::try_from(cell.key.operation_id.as_str())
        .ok()
        .and_then(CompiledOperationV1::process_control)
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "process-control selector has unknown operation `{}`",
                    cell.key.operation_id
                ),
            }
            .build()
        })?;
    ensure!(
        KernelEffectFamilyV1::from(cell.key.effect_family) == KernelEffectFamilyV1::Privilege
            && matches!(
                operation.kernel_id,
                KernelEffectOperationV1::Ptrace | KernelEffectOperationV1::Signal
            ),
        IdentityStateSnafu {
            reason: "a SECURITY:PROCESS selector is valid only for PTRACE or SIGNAL",
        }
    );
    ensure!(
        !operation.argument_wildcard || decision.decision == PhysicalDecisionKindV1::Deny,
        IdentityStateSnafu {
            reason: "a process-control argument wildcard is denial-only",
        }
    );
    ensure!(
        target_role != "*",
        IdentityStateSnafu {
            reason: "process control requires one exact signed target role",
        }
    );
    let &(target_role_id, target_process_state_vector_id) =
        context.role_states.get(target_role).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("process-control selector has unknown target role `{target_role}`"),
            }
            .build()
        })?;
    let key = ProcessControlRuleKeyV1 {
        profile_generation_ref_id: context.profile_generation_ref_id,
        controller_role_id: context.actor_role_id,
        controller_process_state_vector_id: context.actor_process_state_vector_id,
        target_role_id,
        target_process_state_vector_id,
        operation_argument: operation.argument,
        entry_kind: context.entry_kind,
        operation: operation.kernel_id as u16,
        binding_lifecycle_state: context.binding_lifecycle_state,
        argument_wildcard: u8::from(operation.argument_wildcard),
        reserved: [0; 6],
    };
    insert_exact(rows, key.as_bytes(), decision.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::LazyLock;

    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, DeviceEffectKeyV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
        ProcessControlRuleKeyV1,
    };
    use mithril_control::{
        BindingLifecycleV1, CompiledDecisionCellV1, CompiledPhysicalResultV1, EffectFamilyV1,
        EntryKindV1, ErrnoV1, StaticDecisionKeyV1,
    };
    use zerocopy::{IntoBytes as _, TryFromBytes as _};

    use crate::{ExactDeviceConfig, ExactDeviceType, ExactFileObjectConfig};

    use super::{lower_typed_effect, TypedEffectContext};

    static SIGNED_DEVICE_CLASSES: LazyLock<BTreeSet<String>> =
        LazyLock::new(|| BTreeSet::from(["gpu".to_owned()]));

    #[test]
    fn exact_and_explicit_wildcard_ioctl_rows_are_distinct() -> crate::Result<()> {
        let object = device_object();
        let exact_objects = [&object];
        let roles = role_states();
        let context = context(&exact_objects, &roles, 1, 11);
        let allow = decision(PhysicalDecisionKindV1::Allow, 0);
        let mut devices = BTreeMap::new();
        let mut processes = BTreeMap::new();

        assert!(lower_typed_effect(
            &cell(EffectFamilyV1::Device, "IOCTL", "DEVICE:gpu:21531"),
            &context,
            allow,
            &mut devices,
            &mut processes,
        )?);
        let exact = first_device_key(&devices)?;
        assert_eq!(exact.ioctl_command, 21_531);
        assert_eq!(exact.command_wildcard, 0);
        assert_eq!(exact.device_major, 226);
        assert_eq!(exact.device_minor, 128);

        devices.clear();
        assert!(lower_typed_effect(
            &cell(EffectFamilyV1::Device, "IOCTL", "DEVICE:gpu:*"),
            &context,
            allow,
            &mut devices,
            &mut processes,
        )?);
        let wildcard = first_device_key(&devices)?;
        assert_eq!(wildcard.ioctl_command, 0);
        assert_eq!(wildcard.command_wildcard, 1);
        Ok(())
    }

    #[test]
    fn process_control_keeps_direction_and_exact_hook_arguments() -> crate::Result<()> {
        let roles = role_states();
        let exact_objects = [];
        let mut devices = BTreeMap::new();
        let mut processes = BTreeMap::new();
        let allow = decision(PhysicalDecisionKindV1::Allow, 0);
        let deny = decision(PhysicalDecisionKindV1::Deny, ErrnoV1::Eacces.negative());

        assert!(lower_typed_effect(
            &cell(
                EffectFamilyV1::Privilege,
                "SIGNAL_15",
                "SECURITY:PROCESS:target",
            ),
            &context(&exact_objects, &roles, 1, 11),
            allow,
            &mut devices,
            &mut processes,
        )?);
        let allow_key = first_process_key(&processes)?;
        assert_eq!(allow_key.controller_role_id, 1);
        assert_eq!(allow_key.target_role_id, 2);
        assert_eq!(allow_key.operation_argument, 15);
        assert_eq!(allow_key.argument_wildcard, 0);

        processes.clear();
        assert!(lower_typed_effect(
            &cell(
                EffectFamilyV1::Privilege,
                "SIGNAL",
                "SECURITY:PROCESS:controller",
            ),
            &context(&exact_objects, &roles, 2, 22),
            deny,
            &mut devices,
            &mut processes,
        )?);
        assert_eq!(processes.len(), 1);
        for (bytes, value) in &processes {
            let key = ProcessControlRuleKeyV1::try_read_from_bytes(bytes).map_err(|error| {
                test_error(format!("invalid process-control test key: {error}"))
            })?;
            assert_eq!(key.controller_role_id, 2);
            assert_eq!(key.target_role_id, 1);
            assert_eq!(key.operation_argument, 0);
            assert_eq!(key.argument_wildcard, 1);
            assert_eq!(value, deny.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn unknown_devices_and_wildcard_process_targets_do_not_broaden() {
        let object = device_object();
        let exact_objects = [&object];
        let roles = role_states();
        let context = context(&exact_objects, &roles, 1, 11);
        let decision = decision(PhysicalDecisionKindV1::Allow, 0);
        let mut devices = BTreeMap::new();
        let mut processes = BTreeMap::new();

        assert!(lower_typed_effect(
            &cell(EffectFamilyV1::Device, "IOCTL", "DEVICE:unknown:1"),
            &context,
            decision,
            &mut devices,
            &mut processes,
        )
        .is_err());
        assert!(lower_typed_effect(
            &cell(EffectFamilyV1::Privilege, "PTRACE", "SECURITY:PROCESS:*",),
            &context,
            decision,
            &mut devices,
            &mut processes,
        )
        .is_err());
        assert!(devices.is_empty());
        assert!(processes.is_empty());
    }

    fn context<'a>(
        exact_objects: &'a [&'a ExactFileObjectConfig],
        role_states: &'a BTreeMap<String, (u32, u32)>,
        actor_role_id: u32,
        actor_process_state_vector_id: u32,
    ) -> TypedEffectContext<'a> {
        TypedEffectContext {
            profile_generation_ref_id: 7,
            actor_role_id,
            actor_process_state_vector_id,
            entry_kind: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            exact_objects,
            signed_device_classes: &SIGNED_DEVICE_CLASSES,
            role_states,
        }
    }

    fn role_states() -> BTreeMap<String, (u32, u32)> {
        BTreeMap::from([
            ("controller".to_owned(), (1, 11)),
            ("target".to_owned(), (2, 22)),
        ])
    }

    fn first_device_key(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> crate::Result<DeviceEffectKeyV1> {
        let bytes = rows
            .keys()
            .next()
            .ok_or_else(|| test_error("expected one device decision row"))?;
        DeviceEffectKeyV1::try_read_from_bytes(bytes)
            .map_err(|error| test_error(format!("invalid device test key: {error}")))
    }

    fn first_process_key(
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> crate::Result<ProcessControlRuleKeyV1> {
        let bytes = rows
            .keys()
            .next()
            .ok_or_else(|| test_error("expected one process-control decision row"))?;
        ProcessControlRuleKeyV1::try_read_from_bytes(bytes)
            .map_err(|error| test_error(format!("invalid process-control test key: {error}")))
    }

    fn test_error(reason: impl Into<String>) -> crate::Error {
        crate::error::IdentityStateSnafu {
            reason: reason.into(),
        }
        .build()
    }

    fn decision(kind: PhysicalDecisionKindV1, errno: i16) -> PhysicalDecisionV1 {
        PhysicalDecisionV1 {
            decision: kind,
            reserved: 0,
            errno,
            evidence_class_id: 1,
            transition_id: 0,
            exception_numeric_handle: 0,
        }
    }

    fn cell(
        effect_family: EffectFamilyV1,
        operation_id: &str,
        object_selector: &str,
    ) -> CompiledDecisionCellV1 {
        CompiledDecisionCellV1 {
            key: StaticDecisionKeyV1 {
                workload_selector_id: "workload".to_owned(),
                protected_scope_id: "scope".to_owned(),
                execution_set_id: "execution".to_owned(),
                entry_kind: EntryKindV1::ContainerStart,
                role_id: "controller".to_owned(),
                process_state_id: "normal".to_owned(),
                effect_family,
                operation_id: operation_id.to_owned(),
                object_selector: object_selector.to_owned(),
                binding_lifecycle: BindingLifecycleV1::Active,
            },
            physical_result: CompiledPhysicalResultV1::AllowEffect,
            errno: None,
            consuming_exception_id: None,
            action_plan_digest: "digest".to_owned(),
            source_rule_ids: vec!["rule".to_owned()],
        }
    }

    fn device_object() -> ExactFileObjectConfig {
        ExactFileObjectConfig {
            profile_generation_ref_id: 7,
            exact_object_key_id: 9,
            object_class_id: "DEVICE_NODE".to_owned(),
            mount_namespace_inode: 10,
            mount_id_unique: 11,
            filesystem_device: 12,
            inode: 13,
            inode_generation: 0,
            device: Some(ExactDeviceConfig {
                device_class_id: "gpu".to_owned(),
                device_type: ExactDeviceType::Character,
                major: 226,
                minor: 128,
            }),
            canonical_component_hex: vec!["646576".to_owned(), "67707530".to_owned()],
            mount_relative_component_count: 2,
            mount_root_filesystem_device: 12,
            mount_root_inode: 1,
            selected_mount_id_unique: 11,
            mount_snapshot_digest_id: 14,
            mount_topology_generation: 1,
            mount_view_root_pid: 1,
        }
    }
}
