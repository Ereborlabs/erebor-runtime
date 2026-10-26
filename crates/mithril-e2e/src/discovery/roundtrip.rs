use std::{collections::BTreeSet, error::Error as StdError, fs, path::Path};

use mithril_control::EvidenceIdV1;

use crate::control_fixture::{OutagePolicyFixture, OUTAGE_NAMESPACE_UID};

fn fixture_handle<'a>(
    values: impl Iterator<Item = &'a str>,
    selected: &str,
) -> Result<u32, Box<dyn StdError>> {
    Ok(values
        .collect::<BTreeSet<_>>()
        .into_iter()
        .position(|value| value == selected)
        .ok_or("the synthetic kernel handle is absent")? as u32
        + 1)
}

pub(super) struct SignedCatalog {
    pub(super) catalog: mithril_node::NodeDiscoveryContextCatalog,
    pub(super) raw: erebor_interceptor_abi::EffectObservationV1,
    pub(super) workload: mithril_control::WorkloadTargetFactV1,
    pub(super) bundle: mithril_control::PolicyBundleV1,
}

pub(super) fn signed_catalog(
    owner: mithril_control::PolicyDesiredStateOwner,
    root: &Path,
    boot: EvidenceIdV1,
    now: i64,
    runtime_container: Option<&str>,
) -> Result<SignedCatalog, Box<dyn StdError>> {
    let fixture = OutagePolicyFixture { owner };
    let resource = fixture.resource(1)?;
    let mut inventory = fixture.inventory(&resource)?;
    for workload in &mut inventory {
        let identity = workload
            .kubernetes
            .as_mut()
            .ok_or("the workload identity is absent")?;
        identity.binding_id = mithril_node::ScheduledRuntimeBindingV1::authority_binding_id(
            &workload.pod_uid,
            &workload.container_name,
        );
        workload.workload_binding_generation_digest =
            mithril_control::workload_target_fact_digest(workload)?;
    }
    let result = fixture
        .owner
        .reconcile(&resource, OUTAGE_NAMESPACE_UID, &inventory, now)?;
    let bundle = result
        .bundles
        .first()
        .ok_or("the policy bundle is absent")?;
    let artifact_path = root.join("signed-profile.json");
    super::write_json(&artifact_path, &bundle.profile_artifact)?;
    let key_path = root.join("policy-public-key");
    let (_, public_key, _) = fixture.owner.signer_identity();
    fs::write(&key_path, public_key)?;
    let artifact = mithril_control::PolicyArtifactOwner::default().load_verified_at(
        &artifact_path,
        &key_path,
        now,
    )?;
    let document = &artifact.policy_document;
    let workload = inventory.remove(0);
    let identity = workload
        .kubernetes
        .as_ref()
        .ok_or("the workload identity is absent")?;
    let assignment = document
        .entry_role_assignments
        .iter()
        .find(|assignment| assignment.admission_execution_rule_id.is_some())
        .ok_or("the application entry is absent")?;
    let cell = artifact
        .compiled_profile
        .compiled_cells
        .iter()
        .find(|cell| {
            cell.key.role_id == assignment.resulting_role_id
                && cell.key.object_selector.starts_with("PATH:")
                && cell.key.operation_id == "OPEN_READ"
                && assignment.entry_kinds.contains(&cell.key.entry_kind)
        })
        .ok_or("the file-read policy cell is absent")?;
    let selector = document
        .path_selectors
        .iter()
        .find(|selector| cell.key.object_selector == format!("PATH:{}", selector.path_selector_id))
        .ok_or("the signed path selector is absent")?;
    let binding = mithril_node::WorkloadBindingConfig {
        binding_id: runtime_container.map_or_else(
            || identity.binding_id.clone(),
            |container| {
                mithril_node::ScheduledRuntimeBindingV1::runtime_binding_id(
                    &identity.binding_id,
                    container,
                )
            },
        ),
        scheduled_binding_authority_id: Some(identity.binding_id.clone()),
        scheduled_target_digest: Some(workload.workload_binding_generation_digest.clone()),
        execution_set_id: workload.execution_set_id.clone(),
        protected_scope_id: identity.protected_scope_id.clone(),
        workload_selector_id: identity.workload_selector_id.clone(),
        profile_id: artifact.header.profile_id.clone(),
        container_id: runtime_container
            .unwrap_or(&workload.container_id)
            .to_owned(),
        namespace: identity.namespace_name.clone(),
        cluster_uid: workload.cluster_uid.clone(),
        namespace_uid: workload.namespace_uid.clone(),
        controller_uid: workload.controller_uid.clone(),
        service_account_uid: workload.service_account_uid.clone(),
        pod_labels: workload.pod_labels.clone(),
        pod_uid: workload.pod_uid.clone(),
        sandbox_id: "synthetic-sandbox".into(),
        container_name: workload.container_name.clone(),
        image_digest: workload.image_digest.clone(),
        container_kind: mithril_node::ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: None,
        lifecycle_generation: 1,
        active_profile_generation_ref_id: 8,
        initial_role_id: 1,
        external_role_id: 1,
        arm_initial_root: false,
    };
    let object = mithril_node::ExactFileObjectConfig {
        profile_generation_ref_id: 8,
        exact_object_key_id: selector.kernel_handle(),
        object_class_id: selector.object_class_id.clone(),
        mount_namespace_inode: 24,
        mount_id_unique: 21,
        filesystem_device: 25,
        inode: 22,
        inode_generation: 23,
        device: None,
        canonical_component_hex: vec![],
        mount_relative_component_count: 0,
        mount_root_filesystem_device: 25,
        mount_root_inode: 1,
        selected_mount_id_unique: 21,
        mount_snapshot_digest_id: 1,
        mount_topology_generation: 1,
        mount_view_root_pid: 1,
    };
    let operation = mithril_control::CompiledOperationV1::try_from(cell.key.operation_id.as_str())?;
    let raw = erebor_interceptor_abi::EffectObservationV1 {
        binding_id: uuid::Uuid::parse_str(&binding.binding_id)?
            .into_bytes()
            .into(),
        execution_set_id: uuid::Uuid::parse_str(&binding.execution_set_id)?
            .into_bytes()
            .into(),
        authority_domain_id: uuid::Uuid::parse_str(&binding.protected_scope_id)?
            .into_bytes()
            .into(),
        profile_generation_ref_id: 8,
        active_role_id: fixture_handle(
            document.roles.iter().map(|role| role.role_id.as_str()),
            &cell.key.role_id,
        )?,
        process_state_vector_id: fixture_handle(
            document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str()),
            &cell.key.process_state_id,
        )?,
        admitted_entry_rule_id: fixture_handle(
            document
                .entry_role_assignments
                .iter()
                .map(|entry| entry.assignment_id.as_str()),
            &assignment.assignment_id,
        )?,
        effect_family: erebor_interceptor_abi::KernelEffectFamilyV1::from(cell.key.effect_family)
            as u16,
        operation: operation.kernel_id as u16,
        file_object: erebor_interceptor_abi::ExactFileObjectKeyV1 {
            profile_generation_ref_id: 8,
            mount_id_unique: object.mount_id_unique,
            inode: object.inode,
            inode_generation: object.inode_generation,
            mount_namespace_inode: object.mount_namespace_inode,
            filesystem_device: object.filesystem_device,
        },
        exact_object_key_id: object.exact_object_key_id,
        composite_atom_id: u64::from(fixture_handle(
            document
                .protected_universe
                .object_class_ids
                .iter()
                .map(String::as_str),
            &selector.object_class_id,
        )?),
        ..Default::default()
    };
    if let Some(container) = runtime_container {
        let authority = mithril_node::ScheduledRuntimeBindingV1::authority_binding_id(
            &workload.pod_uid,
            &workload.container_name,
        );
        let runtime =
            mithril_node::ScheduledRuntimeBindingV1::runtime_binding_id(&authority, container);
        assert_eq!(identity.binding_id, authority);
        assert_eq!(
            binding.scheduled_binding_authority_id.as_deref(),
            Some(authority.as_str())
        );
        assert_eq!(
            binding.scheduled_target_digest.as_deref(),
            Some(workload.workload_binding_generation_digest.as_str())
        );
        assert_eq!(binding.container_id, container);
        assert_ne!(runtime, authority);
        assert_eq!(
            raw.binding_id.to_be_bytes(),
            uuid::Uuid::parse_str(&runtime)?.into_bytes()
        );
        assert!(workload.container_id.starts_with("scheduled:"));
        assert_eq!(
            bundle.candidate.exact_target.workload_targets,
            vec![workload.clone()]
        );
        assert_eq!(
            mithril_control::workload_target_fact_digest(&workload)?,
            workload.workload_binding_generation_digest
        );
    }
    let mut catalog = mithril_node::NodeDiscoveryContextCatalog::default();
    catalog.add_verified_binding(&artifact, &binding, &[object], boot);
    Ok(SignedCatalog {
        catalog,
        raw,
        workload,
        bundle: bundle.clone(),
    })
}
