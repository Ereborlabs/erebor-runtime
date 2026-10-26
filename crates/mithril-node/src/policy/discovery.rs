use std::collections::btree_map::Entry;

use mithril_control::{
    DiscoveryDigestV1, EvidenceDecisionCatalogV1, EvidenceExactFileObject, EvidenceFileObjectV1,
    EvidenceRuntimeBindingV1, ObservationEnvelopeV1,
};

use super::*;

#[cfg(test)]
mod runtime_tests;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextKey {
    boot: Id128V1,
    generation: u64,
    binding: Id128V1,
    role: u32,
    state: u32,
    entry_rule: u32,
    family: u16,
    operation: u16,
    object: Id128V1,
    composite_atom: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObservationCanonicalizer;
    use erebor_interceptor_abi::{EffectObservationV1, ExactFileObjectKeyV1};
    use mithril_control::TemporalCoverageV1;

    #[test]
    fn discovery_catalog_exact_coordinates() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let (artifact, binding) = super::super::tests::entry_roles_artifact()?;
        let objects = super::super::tests::entry_role_objects(&artifact, &binding)?;
        let boot = Id128V1::new(1, 2);
        let mut catalog = NodeDiscoveryContextCatalog::default();
        catalog.add_verified_binding(&artifact, &binding, &objects, boot);
        assert!(!catalog.entries.is_empty());
        assert!(catalog.unavailable.is_none());
        let (key, bytes) = catalog
            .entries
            .iter()
            .find_map(|(key, value)| {
                value
                    .as_ref()
                    .ok()
                    .map(|bytes| (key.clone(), bytes.clone()))
            })
            .ok_or("no unambiguous signed context")?;
        let sealed: EvidenceDecisionCatalogV1 = serde_json::from_slice(&bytes)?;
        assert!(sealed.runtime_binding.is_none());
        assert_eq!(
            sealed.policy_document_digest,
            artifact.header.policy_document_digest
        );
        assert_eq!(sealed.digest, sealed.content_digest()?);
        let exact = sealed.exact_file_object;
        let mut observation = ObservationCanonicalizer::new(boot, Id128V1::new(3, 4), 1, boot)?
            .normalize_kernel(
                EffectObservationV1 {
                    source_sequence: 101,
                    observed_boottime_ns: 102,
                    task_cookie: 103,
                    process_instance_id: Id128V1::new(104, 105),
                    entry_instance_id: Id128V1::new(106, 107),
                    binding_id: key.binding,
                    profile_generation_ref_id: key.generation,
                    active_role_id: key.role,
                    process_state_vector_id: key.state,
                    admitted_entry_rule_id: key.entry_rule,
                    effect_family: key.family,
                    operation: key.operation,
                    exact_object_key_id: sealed.exact_object_key_id,
                    composite_atom_id: key.composite_atom,
                    file_object: ExactFileObjectKeyV1 {
                        profile_generation_ref_id: exact.profile_generation_ref_id,
                        mount_id_unique: exact.mount_id_unique,
                        inode: exact.inode,
                        inode_generation: exact.inode_generation,
                        mount_namespace_inode: exact.mount_namespace_inode,
                        filesystem_device: exact.filesystem_device,
                    },
                    physical_result: 1,
                    reason: 9,
                    ..Default::default()
                },
                Id128V1::new(5, 6),
                TemporalCoverageV1::Complete,
                200,
            )?;
        catalog.attach(&mut observation);
        observation.validate()?;
        assert_eq!(
            EvidenceDecisionCatalogV1::from_context(
                observation.decision_context.as_ref().ok_or("context")?,
            )?,
            Some(sealed.clone())
        );
        let record = observation.to_wire_record()?;
        let directory = tempfile::tempdir()?;
        let mut wal =
            crate::EvidenceWal::open(directory.path(), crate::EvidenceWalLimits::default())?;
        wal.append(&observation)?;
        let batch = wal.next_batch().ok_or("missing durable context")?;
        drop(wal);
        let mut changed = observation.clone();
        changed.node_boot_id = Id128V1::new(7, 8);
        assert!(changed.validate().is_err());
        catalog.attach(&mut changed);
        assert_eq!(
            changed
                .decision_context
                .as_ref()
                .ok_or("context")?
                .catalog_state,
            "NO_EXACT_MATCH"
        );
        changed.validate()?;
        let mut damaged = sealed.clone();
        damaged.policy_document_digest = "a".repeat(64);
        changed = observation.clone();
        changed
            .decision_context
            .as_mut()
            .ok_or("context")?
            .catalog_json = serde_json::to_vec(&damaged)?;
        assert!(changed.validate().is_err());

        let retained = catalog.entries.len();
        catalog.insert(key.clone(), bytes.clone());
        assert_eq!(catalog.entries.len(), retained);
        catalog.insert(key.clone(), damaged.seal()?);
        catalog.attach(&mut changed);
        assert_eq!(
            changed
                .decision_context
                .as_ref()
                .ok_or("context")?
                .catalog_state,
            "AMBIGUOUS"
        );
        changed.validate()?;
        assert_eq!(observation.to_wire_record()?, record);
        let reopened =
            crate::EvidenceWal::open(directory.path(), crate::EvidenceWalLimits::default())?;
        assert_eq!(reopened.next_batch().ok_or("missing replay")?, batch);
        assert_eq!(batch.decode_records()?, vec![record]);
        let mut next_binding = binding.clone();
        next_binding.active_profile_generation_ref_id += 1;
        let mut next_objects = objects.clone();
        for object in &mut next_objects {
            object.profile_generation_ref_id = next_binding.active_profile_generation_ref_id;
        }
        let mut next_catalog = NodeDiscoveryContextCatalog::default();
        next_catalog.add_verified_binding(&artifact, &next_binding, &next_objects, boot);
        let mut historical = observation.clone();
        next_catalog.attach(&mut historical);
        assert_eq!(
            historical
                .decision_context
                .as_ref()
                .ok_or("context")?
                .catalog_state,
            "NO_EXACT_MATCH"
        );
        let context = observation.decision_context.as_ref().ok_or("context")?;
        assert_eq!(
            context.process_instance_id,
            Id128V1::new(104, 105).to_be_bytes()
        );
        assert_eq!(
            context.entry_instance_id,
            Id128V1::new(106, 107).to_be_bytes()
        );
        assert_eq!(
            EvidenceDecisionCatalogV1::from_context(context)?,
            Some(sealed.clone())
        );
        let mut other_boot = NodeDiscoveryContextCatalog::default();
        other_boot.add_verified_binding(&artifact, &binding, &objects, Id128V1::new(7, 8));
        other_boot.attach(&mut changed);
        assert_eq!(
            changed
                .decision_context
                .as_ref()
                .ok_or("context")?
                .catalog_state,
            "NO_EXACT_MATCH"
        );

        let mut large_catalog = NodeDiscoveryContextCatalog::default();
        let mut large_bytes = bytes.clone();
        large_bytes.extend(std::iter::repeat_n(b' ', 17 * 1_024 * 1_024));
        large_catalog.insert(key.clone(), large_bytes.clone());
        let mut large = observation.clone();
        large_catalog.attach(&mut large);
        large.validate()?;
        assert_eq!(
            large
                .decision_context
                .as_ref()
                .ok_or("context")?
                .catalog_json,
            large_bytes
        );
        assert_eq!(
            EvidenceDecisionCatalogV1::from_context(
                large.decision_context.as_ref().ok_or("context")?
            )?,
            Some(sealed)
        );
        let directory = tempfile::tempdir()?;
        let mut wal =
            crate::EvidenceWal::open(directory.path(), crate::EvidenceWalLimits::default())?;
        wal.append(&large)?;
        wal.append(&observation)?;
        let first = wal.next_batch().ok_or("large first batch absent")?;
        assert_eq!((first.first_cursor, first.last_cursor), (1, 1));
        let wire: mithril_control::EvidenceBatch = first.clone().into();
        assert!(wire.framed_records.len() > 17 * 1_024 * 1_024);
        assert_eq!(first.decode_records()?, vec![large.to_wire_record()?]);
        drop(wal);
        let reduced = crate::EvidenceWalLimits {
            maximum_record_bytes: Some(1),
            maximum_retained_bytes: Some(1),
            maximum_retained_records: Some(1),
            ..crate::EvidenceWalLimits::default()
        };
        let mut reopened = crate::EvidenceWal::open(directory.path(), reduced)?;
        assert_eq!(reopened.next_batch(), Some(first));
        assert!(reopened.append(&observation).is_err());
        reopened.acknowledge(crate::EvidenceAckV1 {
            contiguous_cursor: 1,
        })?;
        let next = reopened.next_batch().ok_or("following batch absent")?;
        assert_eq!((next.first_cursor, next.last_cursor), (2, 2));
        assert_eq!(next.decode_records()?, vec![observation.to_wire_record()?]);
        reopened.acknowledge(crate::EvidenceAckV1 {
            contiguous_cursor: 2,
        })?;
        assert_eq!(reopened.pending_records(), 0);
        Ok(())
    }
}

#[derive(Default)]
pub struct NodeDiscoveryContextCatalog {
    entries: BTreeMap<ContextKey, std::result::Result<Vec<u8>, &'static str>>,
    unavailable: Option<&'static str>,
}

impl NodeDiscoveryContextCatalog {
    pub fn attach(&self, observation: &mut ObservationEnvelopeV1) {
        let Some(context) = observation.decision_context.as_mut() else {
            return;
        };
        context.catalog_json.clear();
        context.catalog_state = "NO_EXACT_MATCH".to_owned();
        if let Some(reason) = self.unavailable {
            context.catalog_state = reason.to_owned();
            return;
        }
        let (Ok(binding), Some(object)) = (
            <[u8; 16]>::try_from(context.binding_id.as_slice()),
            observation.effect.exact_object_id,
        ) else {
            return;
        };
        let key = ContextKey {
            boot: observation.node_boot_id,
            generation: context.profile_generation_ref_id,
            binding: binding.into(),
            role: context.role_id,
            state: context.state_id,
            entry_rule: context.entry_rule_id,
            family: observation.effect.effect_family,
            operation: observation.effect.operation,
            object,
            composite_atom: context.composite_atom_id,
        };
        match self.entries.get(&key) {
            Some(Ok(bytes)) => {
                context.catalog_json.clone_from(bytes);
                context.catalog_state = "AVAILABLE".to_owned();
            }
            Some(Err(reason)) => context.catalog_state = (*reason).to_owned(),
            None => {}
        }
    }

    /// Add a verified candidate and measured exact objects to the lookup.
    pub fn add_verified_binding(
        &mut self,
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        objects: &[ExactFileObjectConfig],
        boot: Id128V1,
    ) {
        if self.unavailable.is_some() {
            return;
        }
        if self
            .extend_verified(artifact, binding, objects, boot)
            .is_err()
        {
            self.entries.clear();
            self.unavailable = Some("MISSING_CATALOG");
        }
    }

    fn extend_verified(
        &mut self,
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        objects: &[ExactFileObjectConfig],
        boot: Id128V1,
    ) -> Result<()> {
        let runtime_binding = match (
            &binding.scheduled_binding_authority_id,
            &binding.scheduled_target_digest,
        ) {
            (None, None) => None,
            (Some(authority), Some(digest)) => {
                ensure!(
                    authority
                        == &crate::ScheduledRuntimeBindingV1::authority_binding_id(
                            &binding.pod_uid,
                            &binding.container_name,
                        )
                        && digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                    IdentityStateSnafu {
                        reason: "catalog binding has invalid signed scheduling metadata",
                    }
                );
                if binding.container_id.starts_with("scheduled:") {
                    ensure!(
                        binding.binding_id == *authority,
                        IdentityStateSnafu {
                            reason: "catalog placeholder differs from its scheduled authority",
                        }
                    );
                    None
                } else {
                    let proof = EvidenceRuntimeBindingV1 {
                        container_id: binding.container_id.clone(),
                        signed_target_digest: digest.clone(),
                    };
                    ensure!(
                        proof.valid()
                            && binding.binding_id
                                == crate::ScheduledRuntimeBindingV1::runtime_binding_id(
                                    authority,
                                    &proof.container_id,
                                ),
                        IdentityStateSnafu {
                            reason: "catalog binding differs from its concrete runtime identity",
                        }
                    );
                    Some(proof)
                }
            }
            _ => {
                return IdentityStateSnafu {
                    reason: "catalog binding has incomplete signed scheduling metadata",
                }
                .fail();
            }
        };
        let roles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let states = handles(
            artifact
                .policy_document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str()),
        );
        let assignments = handles(
            artifact
                .policy_document
                .entry_role_assignments
                .iter()
                .map(|entry| entry.assignment_id.as_str()),
        );
        let composites = LoweredGeneration::composite_handles(artifact);
        let binding_id = parse_id("binding_id", &binding.binding_id)?;
        for cell in &artifact.compiled_profile.compiled_cells {
            if !cell_matches_binding(&cell.key, binding, &artifact.policy_document) {
                continue;
            }
            let Some(selector_id) = cell.key.object_selector.strip_prefix("PATH:") else {
                continue;
            };
            let Some(selector) = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| selector.path_selector_id == selector_id)
            else {
                continue;
            };
            let Some(object) = objects.iter().find(|object| {
                object.profile_generation_ref_id == binding.active_profile_generation_ref_id
                    && object.exact_object_key_id == selector.kernel_handle()
            }) else {
                continue;
            };
            let exact = EvidenceExactFileObject {
                profile_generation_ref_id: object.profile_generation_ref_id,
                mount_id_unique: object.mount_id_unique,
                inode: object.inode,
                inode_generation: object.inode_generation,
                mount_namespace_inode: object.mount_namespace_inode,
                filesystem_device: object.filesystem_device,
            };
            let Some((&role, &state, &composite)) = roles
                .get(&cell.key.role_id)
                .zip(states.get(&cell.key.process_state_id))
                .zip(composites.get(&cell.key.object_selector))
                .map(|((role, state), composite)| (role, state, composite))
            else {
                continue;
            };
            let Ok(operation) = CompiledOperationV1::try_from(cell.key.operation_id.as_str())
            else {
                continue;
            };
            for assignment in &artifact.policy_document.entry_role_assignments {
                if !assignment
                    .workload_selector_ids
                    .contains(&binding.workload_selector_id)
                    || !assignment
                        .container_kinds
                        .contains(&policy_container_kind(binding.container_kind))
                    || !assignment.entry_kinds.contains(&cell.key.entry_kind)
                {
                    continue;
                }
                let entry_rule = if assignment.admission_execution_rule_id.is_some() {
                    assignments[&assignment.assignment_id]
                } else {
                    0
                };
                let key = ContextKey {
                    boot,
                    generation: binding.active_profile_generation_ref_id,
                    binding: binding_id,
                    role,
                    state,
                    entry_rule,
                    family: KernelEffectFamilyV1::from(cell.key.effect_family) as u16,
                    operation: operation.kernel_id as u16,
                    object: EvidenceFileObjectV1::from(&exact)
                        .observation_id(object.exact_object_key_id),
                    composite_atom: composite,
                };
                let bytes = EvidenceDecisionCatalogV1 {
                    node_boot_id: boot,
                    profile_id: artifact.header.profile_id.clone(),
                    profile_version: artifact.header.profile_version,
                    policy_document_digest: artifact.header.policy_document_digest.clone(),
                    profile_generation_ref_id: key.generation,
                    binding_id,
                    runtime_binding: runtime_binding.clone(),
                    role_id: role,
                    state_id: state,
                    entry_rule_id: entry_rule,
                    exact_file_object: exact,
                    exact_object_key_id: object.exact_object_key_id,
                    composite_atom_id: composite,
                    static_key: cell.key.clone(),
                    digest: DiscoveryDigestV1([0; 32]),
                }
                .seal()
                .map_err(mithril_control::Error::from)
                .context(PolicySnafu)?;
                self.insert(key, bytes);
                if self.unavailable.is_some() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn insert(&mut self, key: ContextKey, bytes: Vec<u8>) {
        if self.unavailable.is_some() {
            return;
        }
        let value = Ok(bytes);
        match self.entries.entry(key) {
            Entry::Occupied(mut entry) => {
                if entry.get().is_ok() && entry.get() != &value {
                    *entry.get_mut() = Err("AMBIGUOUS");
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
        }
    }
}
