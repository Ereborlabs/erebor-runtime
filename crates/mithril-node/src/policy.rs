use std::collections::{BTreeMap, BTreeSet};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, EffectDecisionKeyV1, EffectDefaultKeyV1, ExactFileObjectKeyV1,
    ExactObjectBindingStateV1, ExactObjectBindingV1, Id128V1, PhysicalDecisionKindV1,
    PhysicalDecisionV1, PolicyGenerationStateV1, ProfileGenerationDescriptorV1,
};
use mithril_control::{
    kernel_operation_id, AntiRollbackStore, CompiledPhysicalResultV1,
    ContainerKindV1 as PolicyContainerKindV1, EntryKindV1, PolicyArtifactOwner,
    ProfileCandidateArtifactV1, StaticDecisionKeyV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use uuid::Uuid;
use zerocopy::IntoBytes as _;

use crate::error::{IdentityStateSnafu, InterceptorSnafu, PolicySnafu};
use crate::{ExactFileObjectConfig, NodeConfig, Result, WorkloadBindingConfig};

pub struct NodePolicyGenerationOwner;

impl NodePolicyGenerationOwner {
    pub fn load_and_install(
        config: &NodeConfig,
        host: &KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        platform_scope_digest: &str,
    ) -> Result<Self> {
        let artifact_owner = PolicyArtifactOwner::default();
        let mut artifacts = BTreeMap::new();
        let now_utc_ns = current_utc_ns()?;
        for candidate in &config.policy_candidates {
            let artifact = artifact_owner
                .load_verified_at(
                    &candidate.artifact_path,
                    &candidate.public_key_path,
                    now_utc_ns,
                )
                .context(PolicySnafu)?;
            ensure!(
                artifacts
                    .insert(artifact.header.profile_id.clone(), artifact)
                    .is_none(),
                IdentityStateSnafu {
                    reason: "one node candidate is allowed per profile ID",
                }
            );
        }
        let mut rollback =
            AntiRollbackStore::load(config.state_directory.join("policy-anti-rollback-v1.json"))
                .context(PolicySnafu)?;
        let mut generations = BTreeMap::<u64, LoweredGeneration>::new();
        for binding in &config.workload_bindings {
            let artifact = artifacts.get(&binding.profile_id).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has no verified observe candidate for profile `{}`",
                        binding.binding_id, binding.profile_id
                    ),
                }
                .build()
            })?;
            rollback
                .accept(artifact, None, platform_scope_digest, now_utc_ns)
                .context(PolicySnafu)?;
            let lowered = LoweredGeneration::for_binding(
                artifact,
                binding,
                &config.exact_file_objects,
                node_boot_id,
                label_epoch,
            )?;
            match generations.get_mut(&binding.active_profile_generation_ref_id) {
                Some(existing) => existing.merge(lowered)?,
                None => {
                    generations.insert(binding.active_profile_generation_ref_id, lowered);
                }
            }
        }
        for generation in generations.values() {
            generation.install(host)?;
        }
        Ok(Self)
    }
}

struct LoweredGeneration {
    descriptor: ProfileGenerationDescriptorV1,
    decisions: BTreeMap<Vec<u8>, Vec<u8>>,
    defaults: BTreeMap<Vec<u8>, Vec<u8>>,
    file_objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl LoweredGeneration {
    fn for_binding(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        configured_objects: &[ExactFileObjectConfig],
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        ensure!(
            artifact.header.profile_id == binding.profile_id,
            IdentityStateSnafu {
                reason: "candidate profile does not match its workload binding",
            }
        );
        let profile_id = parse_id("profile_id", &binding.profile_id)?;
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let process_state_handles = handles(
            artifact
                .policy_document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str()),
        );
        let composite_handles = composite_handles(artifact);
        let generation_objects = configured_objects
            .iter()
            .filter(|object| {
                object.profile_generation_ref_id == binding.active_profile_generation_ref_id
            })
            .collect::<Vec<_>>();
        let mut exact_object_handles = BTreeMap::new();
        for object in &generation_objects {
            let composite_atom_id = *composite_handles
                .get(&format!("CLASS:{}", object.object_class_id))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "object class `{}` is outside the signed policy universe",
                            object.object_class_id
                        ),
                    }
                    .build()
                })?;
            ensure!(
                exact_object_handles
                    .insert(object.exact_object_key_id, composite_atom_id)
                    .is_none(),
                IdentityStateSnafu {
                    reason: format!(
                        "exact object key {} is configured more than once",
                        object.exact_object_key_id
                    ),
                }
            );
        }
        validate_binding_roles(artifact, binding, &role_handles, &process_state_handles)?;
        let mut decisions = BTreeMap::new();
        let mut defaults = BTreeMap::new();
        for cell in &artifact.compiled_profile.compiled_cells {
            if !cell_matches_binding(&cell.key, binding) {
                continue;
            }
            let role = *role_handles.get(&cell.key.role_id).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!("compiled cell has unknown role `{}`", cell.key.role_id),
                }
                .build()
            })?;
            let process_state = *process_state_handles
                .get(&cell.key.process_state_id)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "compiled cell has unknown process state `{}`",
                            cell.key.process_state_id
                        ),
                    }
                    .build()
                })?;
            let family = cell.key.effect_family.kernel_id() as u16;
            let operation = kernel_operation_id(&cell.key.operation_id).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!("unsupported kernel operation `{}`", cell.key.operation_id),
                }
                .build()
            })? as u16;
            let physical = physical_decision(cell.physical_result, cell.errno);
            if let Some(exact_object_key_id) = cell.key.object_selector.strip_prefix("EXACT:") {
                let exact_object_key_id = exact_object_key_id.parse::<u64>().map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("invalid exact object key: {error}"),
                    }
                    .build()
                })?;
                let key = EffectDecisionKeyV1 {
                    profile_generation_ref_id: binding.active_profile_generation_ref_id,
                    active_role_id: role,
                    entry_kind: entry_kind(cell.key.entry_kind),
                    effect_family: family,
                    operation,
                    reserved: 0,
                    reserved_alignment: [0; 4],
                    composite_atom_id: *exact_object_handles
                        .get(&exact_object_key_id)
                        .ok_or_else(|| {
                            IdentityStateSnafu {
                                reason: format!(
                                    "exact object key {exact_object_key_id} has no configured kernel object and signed class"
                                ),
                            }
                            .build()
                        })?,
                    exact_object_key_id,
                    process_state_vector_id: process_state,
                    binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                    reserved_tail: [0; 3],
                };
                insert_exact(&mut decisions, key.as_bytes(), physical.as_bytes())?;
            } else {
                let key = EffectDefaultKeyV1 {
                    profile_generation_ref_id: binding.active_profile_generation_ref_id,
                    active_role_id: role,
                    entry_kind: entry_kind(cell.key.entry_kind),
                    effect_family: family,
                    operation,
                    reserved: 0,
                    reserved_alignment: [0; 4],
                    composite_atom_id: *composite_handles
                        .get(&cell.key.object_selector)
                        .ok_or_else(|| {
                            IdentityStateSnafu {
                                reason: format!(
                                    "compiled cell has unknown object selector `{}`",
                                    cell.key.object_selector
                                ),
                            }
                            .build()
                        })?,
                    process_state_vector_id: process_state,
                    binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                    reserved_tail: [0; 3],
                };
                insert_exact(&mut defaults, key.as_bytes(), physical.as_bytes())?;
            }
        }
        ensure!(
            !decisions.is_empty() || !defaults.is_empty(),
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` selected no exact candidate cells",
                    binding.binding_id
                ),
            }
        );
        let mut file_objects = BTreeMap::new();
        for object in generation_objects {
            let key = ExactFileObjectKeyV1 {
                profile_generation_ref_id: object.profile_generation_ref_id,
                mount_namespace_inode: object.mount_namespace_inode,
                mount_id_unique: object.mount_id_unique,
                filesystem_device: object.filesystem_device,
                inode: object.inode,
                inode_generation: object.inode_generation,
                reserved: 0,
            };
            let value = ExactObjectBindingV1 {
                profile_generation_ref_id: object.profile_generation_ref_id,
                exact_object_key_id: object.exact_object_key_id,
                composite_atom_id: exact_object_handles[&object.exact_object_key_id],
                state: ExactObjectBindingStateV1::ReadBack,
                reserved: [0; 7],
            };
            insert_exact(&mut file_objects, key.as_bytes(), value.as_bytes())?;
        }
        let table_digest = table_digest(&decisions, &defaults, &file_objects);
        let descriptor = ProfileGenerationDescriptorV1 {
            node_boot_id,
            profile_id,
            label_epoch,
            profile_generation_ref_id: binding.active_profile_generation_ref_id,
            owner_generation: artifact.header.profile_version,
            row_count: decisions.len().try_into().map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("decision row count overflow: {error}"),
                }
                .build()
            })?,
            default_count: defaults.len().try_into().map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("default row count overflow: {error}"),
                }
                .build()
            })?,
            state: PolicyGenerationStateV1::Preparing,
            reserved: [0; 7],
            table_digest,
            transition_version: 1,
        };
        Ok(Self {
            descriptor,
            decisions,
            defaults,
            file_objects,
        })
    }

    fn merge(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.descriptor.node_boot_id == other.descriptor.node_boot_id
                && self.descriptor.profile_id == other.descriptor.profile_id
                && self.descriptor.label_epoch == other.descriptor.label_epoch
                && self.descriptor.owner_generation == other.descriptor.owner_generation,
            IdentityStateSnafu {
                reason: "one generation handle cannot name different candidate artifacts",
            }
        );
        merge_rows(&mut self.decisions, other.decisions)?;
        merge_rows(&mut self.defaults, other.defaults)?;
        merge_rows(&mut self.file_objects, other.file_objects)?;
        self.descriptor.row_count = self.decisions.len() as u32;
        self.descriptor.default_count = self.defaults.len() as u32;
        self.descriptor.table_digest =
            table_digest(&self.decisions, &self.defaults, &self.file_objects);
        Ok(())
    }

    fn install(&self, host: &KernelHost) -> Result<()> {
        let descriptor_key = self.descriptor.profile_generation_ref_id.to_le_bytes();
        if let Some(existing) = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
        {
            let preparing = self.descriptor.as_bytes();
            let mut read_back = self.descriptor;
            read_back.state = PolicyGenerationStateV1::ReadBack;
            read_back.transition_version = 2;
            ensure!(
                existing == preparing || existing == read_back.as_bytes(),
                IdentityStateSnafu {
                    reason: "generation handle already belongs to different content",
                }
            );
        }
        host.update_map(
            "profile_generation_descriptors",
            &descriptor_key,
            self.descriptor.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        install_rows(host, "effect_decisions", &self.decisions)?;
        install_rows(host, "effect_defaults", &self.defaults)?;
        install_rows(host, "exact_file_objects", &self.file_objects)?;
        let mut read_back = self.descriptor;
        read_back.state = PolicyGenerationStateV1::ReadBack;
        read_back.transition_version = 2;
        host.update_map(
            "profile_generation_descriptors",
            &descriptor_key,
            read_back.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("profile_generation_descriptors", &descriptor_key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(read_back.as_bytes()),
            IdentityStateSnafu {
                reason: "candidate descriptor READ_BACK verification failed",
            }
        );
        Ok(())
    }
}

fn install_rows(host: &KernelHost, map: &str, rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    for (key, value) in rows {
        host.update_map(map, key, value).context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map(map, key)
                .context(InterceptorSnafu)?
                .as_ref()
                == Some(value),
            IdentityStateSnafu {
                reason: format!("candidate `{map}` row readback failed"),
            }
        );
    }
    Ok(())
}

fn cell_matches_binding(key: &StaticDecisionKeyV1, binding: &WorkloadBindingConfig) -> bool {
    key.workload_selector_id == binding.workload_selector_id
        && key.protected_scope_id == binding.protected_scope_id
        && key.execution_set_id == binding.execution_set_id
}

fn validate_binding_roles(
    artifact: &ProfileCandidateArtifactV1,
    binding: &WorkloadBindingConfig,
    role_handles: &BTreeMap<String, u32>,
    process_state_handles: &BTreeMap<String, u32>,
) -> Result<()> {
    for (entry_kind, configured_handle) in [
        (EntryKindV1::ContainerStart, binding.initial_role_id),
        (
            EntryKindV1::ExternalRuntimeUnknown,
            binding.external_role_id,
        ),
    ] {
        let role_ids = artifact
            .policy_document
            .entry_role_assignments
            .iter()
            .filter(|assignment| {
                assignment
                    .workload_selector_ids
                    .contains(&binding.workload_selector_id)
                    && assignment.entry_kinds.contains(&entry_kind)
                    && assignment
                        .container_kinds
                        .contains(&policy_container_kind(binding.container_kind))
            })
            .map(|assignment| assignment.resulting_role_id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            role_ids.len() == 1,
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` needs one exact signed {entry_kind:?} role assignment",
                    binding.binding_id
                ),
            }
        );
        let role_id = role_ids.iter().next().copied().ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` lost its signed {entry_kind:?} role assignment",
                    binding.binding_id
                ),
            }
            .build()
        })?;
        ensure!(
            role_handles.get(role_id) == Some(&configured_handle),
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` configured role handle does not match signed {entry_kind:?} role `{role_id}`",
                    binding.binding_id
                ),
            }
        );
        let role = artifact
            .policy_document
            .roles
            .iter()
            .find(|role| role.role_id == role_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!("signed role `{role_id}` is not defined"),
                }
                .build()
            })?;
        let state = artifact
            .policy_document
            .process_state_definitions
            .iter()
            .find(|state| state.process_state_id == role.default_process_state_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!(
                        "signed role `{role_id}` references undefined process state `{}`",
                        role.default_process_state_id
                    ),
                }
                .build()
            })?;
        ensure!(
            process_state_handles.get(&state.process_state_id) == Some(&1)
                && state.state_bits.is_empty(),
            IdentityStateSnafu {
                reason: format!(
                    "signed role `{role_id}` needs the conservative empty process-state vector supported by the Phase 3 BPF root path"
                ),
            }
        );
    }
    Ok(())
}

const fn policy_container_kind(kind: crate::ContainerKindV1) -> PolicyContainerKindV1 {
    match kind {
        crate::ContainerKindV1::Init => PolicyContainerKindV1::Init,
        crate::ContainerKindV1::Sidecar => PolicyContainerKindV1::Sidecar,
        crate::ContainerKindV1::Application => PolicyContainerKindV1::Application,
        crate::ContainerKindV1::Ephemeral => PolicyContainerKindV1::Ephemeral,
    }
}

fn handles<'a>(ids: impl Iterator<Item = &'a str>) -> BTreeMap<String, u32> {
    ids.collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id.to_owned(), index as u32 + 1))
        .collect()
}

fn physical_decision(result: CompiledPhysicalResultV1, errno: Option<i16>) -> PhysicalDecisionV1 {
    PhysicalDecisionV1 {
        decision: match result {
            CompiledPhysicalResultV1::AllowEffect => PhysicalDecisionKindV1::Allow,
            CompiledPhysicalResultV1::AuditAllowEffect => PhysicalDecisionKindV1::AuditAllow,
            CompiledPhysicalResultV1::SimulatablePolicyDeny => PhysicalDecisionKindV1::Deny,
        },
        reserved: 0,
        errno: errno.unwrap_or(0),
        evidence_class_id: 1,
        transition_id: 0,
        exception_numeric_handle: 0,
    }
}

const fn entry_kind(entry: EntryKindV1) -> u16 {
    use erebor_interceptor_abi::EntryKindV1 as Abi;
    match entry {
        EntryKindV1::ContainerStart => Abi::ContainerStart as u16,
        EntryKindV1::ExternalRuntimeUnknown => Abi::UnknownExternal as u16,
        EntryKindV1::QualifiedJoinedPurpose => Abi::QualifiedExecProbe as u16,
        EntryKindV1::ApprovedAdministrativeExec => Abi::ApprovedAdministrativeExecNextMatch as u16,
        EntryKindV1::RestoredUnknown => Abi::CheckpointRestoreUnknown as u16,
    }
}

const fn lifecycle(state: mithril_control::BindingLifecycleV1) -> BindingLifecycleStateV1 {
    match state {
        mithril_control::BindingLifecycleV1::Preparing => BindingLifecycleStateV1::Preparing,
        mithril_control::BindingLifecycleV1::Active => BindingLifecycleStateV1::Active,
        mithril_control::BindingLifecycleV1::Draining => BindingLifecycleStateV1::Draining,
        mithril_control::BindingLifecycleV1::Terminating => BindingLifecycleStateV1::Terminating,
        mithril_control::BindingLifecycleV1::Tombstoned => BindingLifecycleStateV1::Tombstoned,
    }
}

fn composite_handles(artifact: &ProfileCandidateArtifactV1) -> BTreeMap<String, u64> {
    artifact
        .policy_document
        .protected_universe
        .object_class_ids
        .iter()
        .map(|id| format!("CLASS:{id}"))
        .chain(
            artifact
                .compiled_profile
                .compiled_cells
                .iter()
                .map(|cell| cell.key.object_selector.clone())
                .filter(|selector| !selector.starts_with("EXACT:")),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, id)| (id, index as u64 + 1))
        .collect()
}

fn table_digest(
    decisions: &BTreeMap<Vec<u8>, Vec<u8>>,
    defaults: &BTreeMap<Vec<u8>, Vec<u8>>,
    objects: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (domain, rows) in [
        (b"decision".as_slice(), decisions),
        (b"default".as_slice(), defaults),
        (b"object".as_slice(), objects),
    ] {
        for (key, value) in rows {
            digest.update(domain);
            digest.update((key.len() as u64).to_le_bytes());
            digest.update(key);
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value);
        }
    }
    digest.finalize().into()
}

fn insert_exact(map: &mut BTreeMap<Vec<u8>, Vec<u8>>, key: &[u8], value: &[u8]) -> Result<()> {
    if let Some(existing) = map.insert(key.to_vec(), value.to_vec()) {
        ensure!(
            existing == value,
            IdentityStateSnafu {
                reason: "node lowering produced an unequal exact-key conflict",
            }
        );
    }
    Ok(())
}

fn merge_rows(
    target: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    source: BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    for (key, value) in source {
        insert_exact(target, &key, &value)?;
    }
    Ok(())
}

fn parse_id(name: &str, value: &str) -> Result<Id128V1> {
    let uuid = Uuid::parse_str(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{name} is not an Id128 UUID: {error}"),
        }
        .build()
    })?;
    let bytes = uuid.into_bytes();
    Ok(Id128V1::new(
        u64::from_be_bytes(bytes[..8].try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("{name} high half is invalid: {error}"),
            }
            .build()
        })?),
        u64::from_be_bytes(bytes[8..].try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("{name} low half is invalid: {error}"),
            }
            .build()
        })?),
    ))
}

fn current_utc_ns() -> Result<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            IdentityStateSnafu {
                reason: format!("system UTC clock predates the Unix epoch: {error}"),
            }
            .build()
        })?;
    duration.as_nanos().try_into().map_err(|error| {
        IdentityStateSnafu {
            reason: format!("system UTC clock exceeds the signed i64 range: {error}"),
        }
        .build()
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use ed25519_dalek::SigningKey;
    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, EffectDecisionKeyV1, EntryKindV1 as AbiEntryKindV1, Id128V1,
        KernelEffectFamilyV1, KernelEffectOperationV1,
    };
    use mithril_control::{
        LocalObjectSelectorV1, PolicyCompiler, PolicyDocumentV1, ProfileCandidateArtifactV1,
        ProfileSealRequestV1, RegistryDigestsV1, RuleMatchV1,
    };
    use zerocopy::IntoBytes as _;

    use super::LoweredGeneration;
    use crate::{ContainerKindV1, ExactFileObjectConfig, WorkloadBindingConfig};

    #[test]
    fn exact_decision_key_contains_its_signed_composite_atom() -> crate::Result<()> {
        let (artifact, binding, object) = exact_artifact()?;
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            3,
        )?;
        let expected = EffectDecisionKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 1,
            entry_kind: AbiEntryKindV1::ContainerStart as u16,
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            reserved: 0,
            reserved_alignment: [0; 4],
            composite_atom_id: 1,
            exact_object_key_id: object.exact_object_key_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        let expected_bytes = expected.as_bytes().to_vec();
        assert_eq!(generation.decisions.keys().next(), Some(&expected_bytes));

        assert!(
            LoweredGeneration::for_binding(&artifact, &binding, &[], Id128V1::new(1, 2), 3,)
                .is_err()
        );
        let mut swapped_roles = binding;
        std::mem::swap(
            &mut swapped_roles.initial_role_id,
            &mut swapped_roles.external_role_id,
        );
        assert!(LoweredGeneration::for_binding(
            &artifact,
            &swapped_roles,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            3,
        )
        .is_err());
        Ok(())
    }

    fn exact_artifact() -> crate::Result<(
        ProfileCandidateArtifactV1,
        WorkloadBindingConfig,
        ExactFileObjectConfig,
    )> {
        let mut document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../../mithril-control/tests/fixtures/policy-v1.yaml"),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        let RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match else {
            unreachable!("fixture contains one local rule")
        };
        effect.object = LocalObjectSelectorV1::ExactObjectKeys {
            exact_object_key_ids: vec![99],
        };
        let compiled =
            PolicyCompiler
                .compile(&document)
                .map_err(|source| crate::Error::Policy {
                    source,
                    location: snafu::Location::default(),
                })?;
        let digests = RegistryDigestsV1 {
            provider_numeric_registry_bundle_digest: "1".repeat(64),
            required_capability_schema_digest: "2".repeat(64),
            source_selector_registry_digest: "3".repeat(64),
            object_classifier_registry_digest: "4".repeat(64),
            reason_code_registry_digest: "5".repeat(64),
            correlation_package_registry_digest: "6".repeat(64),
            provider_vocabulary_registry_digest: "7".repeat(64),
        };
        let artifact = ProfileCandidateArtifactV1::sign(
            &document,
            compiled,
            ProfileSealRequestV1 {
                signing_key_id: "test-key".to_owned(),
                issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                sequence_epoch: 1,
                issuer_sequence: 1,
                rollback_authorization_id: None,
                registry_digests: digests,
            },
            &SigningKey::from_bytes(&[9; 32]),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        let binding = WorkloadBindingConfig {
            binding_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: document.metadata.profile_id.clone(),
            container_id: "a".repeat(64),
            pod_uid: "pod".to_owned(),
            sandbox_id: "sandbox".to_owned(),
            container_name: "converter".to_owned(),
            image_digest: "sha256:image".to_owned(),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: Some(PathBuf::from("/sys/fs/cgroup/test")),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: 1,
            external_role_id: 2,
            arm_initial_root: false,
        };
        let object = ExactFileObjectConfig {
            profile_generation_ref_id: 1,
            exact_object_key_id: 99,
            object_class_id: "PROJECTED_TOKEN".to_owned(),
            mount_namespace_inode: 10,
            mount_id_unique: 20,
            filesystem_device: 30,
            inode: 40,
            inode_generation: 50,
        };
        Ok((artifact, binding, object))
    }
}
