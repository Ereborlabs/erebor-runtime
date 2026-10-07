use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ops::Index;

use erebor_interceptor_abi::{ExceptionRuntimeStateV1, PolicyActivationProbeMapKindV1};
use sha2::{Digest as _, Sha256};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::error::IdentityStateSnafu;
use crate::Result;
use std::collections::BTreeSet;

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, EffectDecisionKeyV1, EffectDefaultKeyV1, EntryAdmissionRuleKeyV1,
    EntryAdmissionRuleV1, ExactFileObjectKeyV1, ExactObjectBindingStateV1, ExactObjectBindingV1,
    ExceptionBindingStateV1, ExceptionHandleBindingKeyV1, ExceptionHandleBindingV1,
    ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1, Id128V1, KernelEffectFamilyV1,
    KernelEffectOperationV1, NetworkDestinationDecisionKeyV1, PhysicalDecisionV1,
    PolicyActivationProbeV1, PolicyGenerationModeV1, PolicyGenerationStateV1,
    ProfileGenerationDescriptorV1, MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1,
};
use mithril_control::{
    canonical_path_components, CompiledOperationV1, EntryKindV1, LocalObjectSelectorV1,
    PathPatternComponentV1, PathSelectorV1, PolicyDispositionV1, PolicyDocumentV1,
    ProfileCandidateArtifactV1, ProfileModeV1, RuleMatchV1, StaticDecisionKeyV1,
};
use snafu::{OptionExt as _, ResultExt as _};
use zerocopy::TryFromBytes as _;

use crate::error::{InterceptorSnafu, PolicySnafu};
use crate::identity::PortableProfileGenerationIdentityV1;
use crate::{ExactFileObjectConfig, WorkloadBindingConfig};

use super::publication::GENERATION_REFERENCES;
use super::{
    decode_sha256, handles, insert_exact, install_missing_rows, install_rows, lifecycle, parse_id,
    physical_decision, policy_container_kind, read_abi_value, verify_rows,
    AdministrativePolicyPlanV1, ExceptionAuthorityOwner, GenerationRows, GenerationSemantics,
    MeasuredMountRouteV1, MountRootReconciliation, ProfileActivation, TypedEffectContext,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum NativeTable {
    EntryAdmission,
    EffectDecision,
    EffectDefault,
    DeviceEffect,
    ProcessControl,
    IpcRelationship,
    NetworkIpv4Class,
    NetworkIpv6Class,
    NetworkDecision,
    ExceptionState,
    ExceptionBinding,
    FileObject,
    MountView,
    MountEpoch,
    MountLock,
    MountRoot,
    PathExact,
    PathWildcard,
    PathTerminal,
    PathTreeDenial,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Publication {
    Immutable,
    Dependency,
    ExceptionBinding,
    MountGuard,
    Entry,
    Exception,
}

impl NativeTable {
    pub(super) const ALL: [Self; 20] = [
        Self::EntryAdmission,
        Self::EffectDecision,
        Self::EffectDefault,
        Self::DeviceEffect,
        Self::ProcessControl,
        Self::IpcRelationship,
        Self::NetworkIpv4Class,
        Self::NetworkIpv6Class,
        Self::NetworkDecision,
        Self::ExceptionState,
        Self::ExceptionBinding,
        Self::FileObject,
        Self::MountView,
        Self::MountEpoch,
        Self::MountLock,
        Self::MountRoot,
        Self::PathExact,
        Self::PathWildcard,
        Self::PathTerminal,
        Self::PathTreeDenial,
    ];

    pub(super) const fn map_name(self) -> &'static str {
        match self {
            Self::EntryAdmission => "entry_admission_rules",
            Self::EffectDecision => "effect_decisions",
            Self::EffectDefault => "effect_defaults",
            Self::DeviceEffect => "device_effect_decisions",
            Self::ProcessControl => "process_control_rules",
            Self::IpcRelationship => "ipc_relationship_decisions",
            Self::NetworkIpv4Class => "network_ipv4_destination_classes",
            Self::NetworkIpv6Class => "network_ipv6_destination_classes",
            Self::NetworkDecision => "network_destination_decisions",
            Self::ExceptionState => "exception_runtime_states",
            Self::ExceptionBinding => "exception_handle_bindings",
            Self::FileObject => "exact_file_objects",
            Self::MountView => "mount_security_views",
            Self::MountEpoch => "mount_mutation_epochs",
            Self::MountLock => "mount_security_view_locks",
            Self::MountRoot => "canonical_mount_roots",
            Self::PathExact => "path_graph_exact_transitions",
            Self::PathWildcard => "path_graph_wildcard_transitions",
            Self::PathTerminal => "path_graph_terminals",
            Self::PathTreeDenial => "path_tree_denials",
        }
    }

    pub(super) const fn publication(self) -> Publication {
        match self {
            Self::EntryAdmission => Publication::Entry,
            Self::DeviceEffect | Self::FileObject | Self::MountRoot => Publication::Dependency,
            Self::ExceptionState => Publication::Exception,
            Self::ExceptionBinding => Publication::ExceptionBinding,
            Self::MountView | Self::MountEpoch | Self::MountLock => Publication::MountGuard,
            Self::EffectDecision
            | Self::EffectDefault
            | Self::ProcessControl
            | Self::IpcRelationship
            | Self::NetworkIpv4Class
            | Self::NetworkIpv6Class
            | Self::NetworkDecision
            | Self::PathExact
            | Self::PathWildcard
            | Self::PathTerminal
            | Self::PathTreeDenial => Publication::Immutable,
        }
    }

    pub(super) const fn digest_domain(self) -> Option<&'static str> {
        match self {
            Self::EntryAdmission => Some("entry-admission"),
            Self::EffectDecision => Some("decision"),
            Self::EffectDefault => Some("default"),
            Self::ProcessControl => Some("process-control-rule"),
            Self::IpcRelationship => Some("ipc-relationship"),
            Self::NetworkIpv4Class => Some("network-ipv4-class"),
            Self::NetworkIpv6Class => Some("network-ipv6-class"),
            Self::NetworkDecision => Some("network-decision"),
            Self::PathExact => Some("path-exact"),
            Self::PathWildcard => Some("path-wildcard"),
            Self::PathTerminal => Some("path-terminal"),
            Self::PathTreeDenial => Some("path-tree-denial"),
            _ => None,
        }
    }

    pub(super) const fn probe_kind(self) -> Option<PolicyActivationProbeMapKindV1> {
        match self {
            Self::EffectDecision => Some(PolicyActivationProbeMapKindV1::EffectDecision),
            Self::EffectDefault => Some(PolicyActivationProbeMapKindV1::EffectDefault),
            Self::IpcRelationship => Some(PolicyActivationProbeMapKindV1::IpcRelationship),
            Self::DeviceEffect => Some(PolicyActivationProbeMapKindV1::DeviceEffect),
            Self::ProcessControl => Some(PolicyActivationProbeMapKindV1::ProcessControl),
            Self::NetworkDecision => Some(PolicyActivationProbeMapKindV1::NetworkDestination),
            _ => None,
        }
    }

    pub(super) const fn is_dynamic(self) -> bool {
        matches!(
            self.publication(),
            Publication::Entry | Publication::Dependency | Publication::MountGuard
        )
    }

    pub(super) const fn retirement(self) -> Option<(u8, usize)> {
        match self {
            Self::ExceptionState | Self::MountView | Self::MountEpoch | Self::MountLock => None,
            Self::EntryAdmission => Some((0, 0)),
            Self::EffectDecision => Some((1, 0)),
            Self::EffectDefault => Some((2, 0)),
            Self::IpcRelationship => Some((3, 0)),
            Self::NetworkDecision => Some((4, 0)),
            Self::DeviceEffect => Some((5, 0)),
            Self::ProcessControl => Some((6, 0)),
            Self::ExceptionBinding => Some((7, 0)),
            Self::FileObject => Some((8, 0)),
            Self::MountRoot => Some((9, 0)),
            Self::PathExact => Some((10, 0)),
            Self::PathWildcard => Some((11, 0)),
            Self::PathTerminal => Some((12, 0)),
            Self::PathTreeDenial => Some((13, 0)),
            Self::NetworkIpv4Class => Some((14, 8)),
            Self::NetworkIpv6Class => Some((15, 8)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExceptionRow {
    pub(super) state: ExceptionRuntimeStateV1,
    pub(super) deadline_utc_ns: i64,
}

pub(super) struct GenerationPlan {
    tables: BTreeMap<NativeTable, GenerationRows>,
    pub(super) exceptions: BTreeMap<Vec<u8>, ExceptionRow>,
}

impl Default for GenerationPlan {
    fn default() -> Self {
        Self {
            tables: NativeTable::ALL
                .into_iter()
                .filter(|table| *table != NativeTable::ExceptionState)
                .map(|table| (table, GenerationRows::new()))
                .collect(),
            exceptions: BTreeMap::new(),
        }
    }
}

impl Index<NativeTable> for GenerationPlan {
    type Output = GenerationRows;

    fn index(&self, table: NativeTable) -> &Self::Output {
        &self.tables[&table]
    }
}

impl GenerationPlan {
    pub(super) fn digest(&self, authority: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
        let mut digest = Sha256::new();
        for table in NativeTable::ALL {
            let Some(domain) = table.digest_domain() else {
                continue;
            };
            let rows = if table == NativeTable::EntryAdmission {
                authority
            } else {
                &self[table]
            };
            for (key, value) in rows {
                digest.update(domain.as_bytes());
                digest.update((key.len() as u64).to_le_bytes());
                digest.update(key);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value);
            }
        }
        digest.finalize().into()
    }

    pub(super) fn insert(
        &mut self,
        table: NativeTable,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<()> {
        let rows = self.tables.get_mut(&table).context(IdentityStateSnafu {
            reason: "exception runtime state requires its signed UTC deadline",
        })?;
        let value = value.into();
        match rows.entry(key.into()) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(entry) => ensure!(
                *entry.get() == value,
                IdentityStateSnafu {
                    reason: "node lowering produced an unequal exact-key conflict",
                }
            ),
        }
        Ok(())
    }

    pub(super) fn insert_exception(&mut self, key: &[u8], row: ExceptionRow) -> Result<()> {
        match self.exceptions.entry(key.to_vec()) {
            Entry::Vacant(entry) => {
                entry.insert(row);
            }
            Entry::Occupied(entry) => {
                ensure!(
                    entry.get().state.as_bytes() == row.state.as_bytes(),
                    IdentityStateSnafu {
                        reason: "node lowering produced an unequal exact-key conflict",
                    }
                );
                ensure!(
                    entry.get().deadline_utc_ns == row.deadline_utc_ns,
                    IdentityStateSnafu {
                        reason: "one exception instance has unequal activation deadlines",
                    }
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct GenerationBinding<'a> {
    pub(super) config: &'a WorkloadBindingConfig,
    pub(super) objects: &'a [ExactFileObjectConfig],
    pub(super) routes: &'a [MeasuredMountRouteV1],
    pub(super) deferred: bool,
}

#[derive(Default)]
pub(super) struct LoweredGeneration {
    pub(super) descriptor: ProfileGenerationDescriptorV1,
    pub(super) semantics: GenerationSemantics,
    pub(super) rows: GenerationPlan,
    pub(super) requests: BTreeSet<Vec<u8>>,
    pub(super) administrative_plans: Vec<AdministrativePolicyPlanV1>,
    pub(super) mount_reconciliation: Vec<MountRootReconciliation>,
}

struct PreparedSelector<'a> {
    source: &'a PathSelectorV1,
    handle: u64,
    composite: u64,
}

struct EntryAdmission<'a> {
    rule: &'a mithril_control::DetectionDispositionRuleV1,
    effect: &'a mithril_control::LocalEffectMatchV1,
    selector: &'a PathSelectorV1,
}

struct BindingEntry<'a> {
    assignment: &'a mithril_control::EntryRoleAssignmentV1,
    admission: Option<EntryAdmission<'a>>,
}

struct ProvenBinding<'a, 's> {
    input: &'a GenerationBinding<'a>,
    entries: Vec<BindingEntry<'s>>,
    proven: Vec<(&'a ExactFileObjectConfig, &'s PreparedSelector<'s>)>,
    decision: bool,
}

impl LoweredGeneration {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compile(
        artifact: &ProfileCandidateArtifactV1,
        generation: u64,
        bindings: &[GenerationBinding<'_>],
        node_boot_id: Id128V1,
        node_id: Id128V1,
        label_epoch: u64,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<Self> {
        ensure!(
            !bindings.is_empty(),
            IdentityStateSnafu {
                reason: "generation needs at least one workload binding",
            }
        );
        let semantics = GenerationSemantics::try_from(artifact)?;
        let role_states = artifact
            .policy_document
            .roles
            .iter()
            .map(|role| {
                Ok((
                    role.role_id.clone(),
                    (
                        semantics.role_handles[&role.role_id],
                        semantics
                            .process_state_handles
                            .get(&role.default_process_state_id)
                            .map(|(handle, _)| *handle)
                            .ok_or_else(|| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "signed role `{}` references unknown process state `{}`",
                                        role.role_id, role.default_process_state_id
                                    ),
                                }
                                .build()
                            })?,
                    ),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let composite_handles = LoweredGeneration::composite_handles(artifact);
        let signed_device_classes = artifact
            .policy_document
            .path_selectors
            .iter()
            .filter_map(|selector| selector.device_class_id.clone())
            .collect::<BTreeSet<_>>();
        let exception_handles = handles(
            artifact
                .policy_document
                .exceptions
                .iter()
                .map(|exception| exception.exception_id.as_str())
                .chain(
                    artifact
                        .policy_document
                        .file_exception_grants
                        .iter()
                        .map(|grant| grant.grant_id.as_str()),
                ),
        );
        let mut selectors = Vec::new();
        // The candidate verifier checks selector IDs and signed class pairs.
        for source in &artifact.policy_document.path_selectors {
            selectors.push(PreparedSelector {
                source,
                handle: source.kernel_handle(),
                composite: *composite_handles
                    .get(&format!("PATH:{}", source.path_selector_id))
                    .context(IdentityStateSnafu {
                        reason: format!(
                            "path selector `{}` has an unknown signed object class",
                            source.path_selector_id
                        ),
                    })?,
            });
        }
        let graph = LoweredGeneration::compile_path_graph(artifact)?;
        let mut rows = GenerationPlan::for_graph(
            artifact,
            &graph,
            generation,
            &composite_handles,
            &semantics.role_handles,
        )?;
        rows.add_ipc_relationships(
            &artifact.policy_document,
            generation,
            &semantics.role_handles,
            artifact.compiled_profile.mode,
        )?;
        rows.add_network_classes(&artifact.policy_document, generation)?;

        let mut lowered = Self {
            semantics,
            rows,
            ..Self::default()
        };
        let assignment_handles = handles(
            artifact
                .policy_document
                .entry_role_assignments
                .iter()
                .map(|assignment| assignment.assignment_id.as_str()),
        );
        let mut proofs = Vec::new();
        for input in bindings {
            let binding = input.config;
            ensure!(
                artifact.header.profile_id == binding.profile_id
                    && generation == binding.active_profile_generation_ref_id,
                IdentityStateSnafu {
                    reason: "candidate profile or generation does not match its workload binding",
                }
            );
            let generation_objects = input
                .objects
                .iter()
                .filter(|object| object.profile_generation_ref_id == generation);
            let entries = BindingEntry::for_binding(artifact, binding)?;
            for admission in entries.iter().filter_map(|entry| entry.admission.as_ref()) {
                let request = erebor_interceptor_abi::DeclaredEntryRequestV1::from_path(
                    admission.selector.path_expression().as_bytes(),
                )
                .context(IdentityStateSnafu {
                    reason: "entry admission request path exceeds the kernel bound",
                })?;
                lowered.requests.insert(request.as_bytes().to_vec());
            }
            let mut proven = Vec::new();
            for object in generation_objects {
                let mut matching = selectors
                    .iter()
                    .filter(|selector| selector.handle == object.exact_object_key_id);
                let selector = matching
                    .clone()
                    .find(|selector| {
                        selector.source.requires_exact_object()
                            || entries.iter().any(|entry| {
                                entry.admission.as_ref().is_some_and(|admission| {
                                    admission.selector.path_selector_id
                                        == selector.source.path_selector_id
                                })
                            })
                    })
                    .context(IdentityStateSnafu {
                        reason: format!(
                            "measured object handle {} has no signed path selector",
                            object.exact_object_key_id
                        ),
                    })?;
                let signed = selector.source;
                let signed_components = canonical_path_components(
                    artifact.header.profile_id.as_str(),
                    signed.path_expression(),
                )
                .context(PolicySnafu)?;
                ensure!(
                    signed.object_class_id == object.object_class_id
                        && signed.device_class_id.is_some() == object.device.is_some()
                        && object.canonical_component_hex
                            == signed_components
                                .iter()
                                .map(hex::encode)
                                .collect::<Vec<_>>(),
                    IdentityStateSnafu {
                        reason: "measured exact object differs from its signed path selector",
                    }
                );
                if let Some(device) = &object.device {
                    ensure!(
                        signed.device_class_id.as_deref() == Some(device.device_class_id.as_str()),
                        IdentityStateSnafu {
                            reason: format!(
                                "device class `{}` is not signed for object class `{}`",
                                device.device_class_id, object.object_class_id
                            ),
                        }
                    );
                }
                if matching
                    .clone()
                    .any(|selector| selector.source.requires_exact_object())
                {
                    proven.push((object, matching.next().unwrap_or(selector)));
                }
            }
            if let Some(selector) = selectors
                .iter()
                .filter(|selector| {
                    selector.source.requires_exact_object()
                        && !proven
                            .iter()
                            .any(|(object, _)| object.exact_object_key_id == selector.handle)
                })
                .min_by_key(|selector| selector.source.path_selector_id.as_str())
            {
                return IdentityStateSnafu {
                    reason: format!(
                        "exact selector `{}` has no proven object in the container",
                        selector.source.path_selector_id
                    ),
                }
                .fail();
            }

            lowered.validate_binding_roles(binding, &entries, &role_states)?;
            proofs.push(ProvenBinding {
                input,
                entries,
                proven,
                decision: false,
            });
        }
        let semantics = &lowered.semantics;
        let context = TypedEffectContext {
            signed_device_classes: &signed_device_classes,
            role_states: &role_states,
        };
        let mut used_exceptions = BTreeSet::new();
        for cell in &artifact.compiled_profile.compiled_cells {
            let mut matching = proofs
                .iter_mut()
                .filter(|proof| {
                    cell_matches_binding(&cell.key, proof.input.config, &artifact.policy_document)
                })
                .peekable();
            if matching.peek().is_none() {
                continue;
            }
            let mut key = EffectDefaultKeyV1 {
                profile_generation_ref_id: generation,
                active_role_id: *semantics.role_handles.get(&cell.key.role_id).context(
                    IdentityStateSnafu {
                        reason: format!("compiled cell has unknown role `{}`", cell.key.role_id),
                    },
                )?,
                process_state_vector_id: semantics
                    .process_state_handles
                    .get(&cell.key.process_state_id)
                    .map(|(handle, _)| *handle)
                    .context(IdentityStateSnafu {
                        reason: format!(
                            "compiled cell has unknown process state `{}`",
                            cell.key.process_state_id
                        ),
                    })?,
                effect_family: KernelEffectFamilyV1::from(cell.key.effect_family) as u16,
                operation: CompiledOperationV1::try_from(cell.key.operation_id.as_str())
                    .ok()
                    .context(IdentityStateSnafu {
                        reason: format!("unsupported kernel operation `{}`", cell.key.operation_id),
                    })?
                    .kernel_id as u16,
                composite_atom_id: 0,
                binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                reserved_tail: [0; 3],
            };
            let exception_handle = if let Some(id) = cell.consuming_exception_id.as_deref() {
                used_exceptions.insert(id);
                *exception_handles.get(id).context(IdentityStateSnafu {
                    reason: format!("compiled cell has unknown exception `{id}`"),
                })?
            } else {
                0
            };
            let physical = physical_decision(cell.physical_result, cell.errno, exception_handle);
            if cell.key.object_selector.starts_with("DEVICE:") {
                for binding in matching {
                    binding.decision |= lowered
                        .rows
                        .lower_typed_effect(
                            cell,
                            &key,
                            &context,
                            binding.proven.iter().map(|(object, _)| *object),
                            physical,
                        )?
                        .is_some_and(|emitted| emitted);
                }
                continue;
            }
            let emitted = 'effect: {
                if let Some(capability) = LoweredGeneration::linux_capability(cell)? {
                    ensure!(
                        key.effect_family == KernelEffectFamilyV1::Privilege as u16
                            && key.operation == KernelEffectOperationV1::Capability as u16,
                        IdentityStateSnafu {
                            reason:
                                "a Linux capability selector is valid only for PRIVILEGE/CAPABILITY",
                        }
                    );
                    key.composite_atom_id = u64::from(capability) + 1;
                } else if let Some(destination_id) =
                    cell.key.object_selector.strip_prefix("DESTINATION:")
                {
                    ensure!(
                        cell.key.effect_family == mithril_control::EffectFamilyV1::Network,
                        IdentityStateSnafu {
                            reason: "a destination selector lowered outside NETWORK".to_owned(),
                        }
                    );
                    let (destination, destination_policy_handle) = artifact
                        .policy_document
                        .network_policy
                        .iter()
                        .flat_map(|policy| &policy.destination_policies)
                        .zip(1_u64..)
                        .find(|(policy, _)| policy.destination_policy_id == destination_id)
                        .context(IdentityStateSnafu {
                            reason: format!(
                                "compiled cell has unknown destination `{destination_id}`"
                            ),
                        })?;
                    lowered.rows.add_network_decisions(
                        NetworkDestinationDecisionKeyV1 {
                            profile_generation_ref_id: generation,
                            destination_policy_handle,
                            active_role_id: key.active_role_id,
                            process_state_vector_id: key.process_state_vector_id,
                            operation: key.operation,
                            binding_lifecycle_state: key.binding_lifecycle_state,
                            ..NetworkDestinationDecisionKeyV1::default()
                        },
                        &destination.protocols,
                        physical,
                    )?;
                    break 'effect !destination.protocols.is_empty();
                } else if let Some(emitted) = lowered.rows.lower_typed_effect(
                    cell,
                    &key,
                    &context,
                    std::iter::empty(),
                    physical,
                )? {
                    break 'effect emitted;
                } else if let Some(id) = cell.key.object_selector.strip_prefix("PATH:") {
                    let selector = selectors
                        .iter()
                        .find(|selector| selector.source.path_selector_id == id)
                        .context(IdentityStateSnafu {
                            reason: format!("compiled cell has unknown path selector `{id}`"),
                        })?;
                    key.composite_atom_id = selector.composite;
                    if selector.source.requires_exact_object() {
                        let exact_key = EffectDecisionKeyV1 {
                            profile_generation_ref_id: generation,
                            active_role_id: key.active_role_id,
                            effect_family: key.effect_family,
                            operation: key.operation,
                            composite_atom_id: key.composite_atom_id,
                            exact_object_key_id: selector.handle,
                            process_state_vector_id: key.process_state_vector_id,
                            binding_lifecycle_state: key.binding_lifecycle_state,
                            reserved_tail: [0; 3],
                        };
                        lowered.rows.insert(
                            NativeTable::EffectDecision,
                            exact_key.as_bytes(),
                            physical.as_bytes(),
                        )?;
                        break 'effect true;
                    }
                } else if cell.key.object_selector != "DEFAULT" {
                    key.composite_atom_id = *composite_handles
                        .get(&cell.key.object_selector)
                        .context(IdentityStateSnafu {
                            reason: format!(
                                "compiled cell has unknown object selector `{}`",
                                cell.key.object_selector
                            ),
                        })?;
                }
                lowered.rows.insert(
                    NativeTable::EffectDefault,
                    key.as_bytes(),
                    physical.as_bytes(),
                )?;
                true
            };
            for binding in matching {
                binding.decision |= emitted;
            }
        }

        for binding in &proofs {
            ensure!(
                binding.decision,
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` selected no exact candidate cells",
                        binding.input.config.binding_id
                    ),
                }
            );
        }
        for exception in &artifact.policy_document.exceptions {
            let binding_key = ExceptionHandleBindingKeyV1 {
                profile_generation_ref_id: generation,
                exception_numeric_handle: exception_handles[&exception.exception_id],
                reserved: 0,
            };
            if !used_exceptions.contains(exception.exception_id.as_str()) {
                continue;
            }
            ensure!(
                exception.valid_from_utc_ns <= now_utc_ns
                    && now_utc_ns < exception.valid_until_utc_ns,
                IdentityStateSnafu {
                    reason: format!(
                        "exception `{}` is not valid at node activation",
                        exception.exception_id
                    ),
                }
            );
            let remaining = exception
                .valid_until_utc_ns
                .checked_sub(now_utc_ns)
                .context(IdentityStateSnafu {
                    reason: "exception UTC lifetime overflow",
                })?;
            let lifetime =
                remaining.min(i64::try_from(exception.maximum_lifetime_ns).unwrap_or(i64::MAX));
            // The bounded lifetime is nonnegative and cannot exceed the checked remainder.
            let deadline_utc_ns = exception.valid_until_utc_ns - (remaining - lifetime);
            let deadline_boottime_ns = now_boottime_ns
                .checked_add(lifetime.unsigned_abs())
                .context(IdentityStateSnafu {
                    reason: "exception monotonic deadline overflow",
                })?;
            let exception_instance_id =
                parse_id("exception_instance_id", &exception.exception_instance_id)?;
            ensure!(
                !exception_instance_id.is_zero(),
                IdentityStateSnafu {
                    reason: "exception_instance_id must be nonzero",
                }
            );
            let runtime_state_key = ExceptionRuntimeStateKeyV1 {
                node_id,
                exception_instance_id,
            };
            let exception_definition_sha256 =
                Sha256::digest(serde_json::to_vec(exception).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("serialize signed exception definition: {error}"),
                    }
                    .build()
                })?)
                .into();
            let value = ExceptionRuntimeStateV1 {
                maximum_uses: exception.maximum_uses,
                bound_profile_generation_refs: 1,
                deadline_boottime_ns,
                transition_version: 1,
                exception_definition_sha256,
                state: ExceptionRuntimeStateKindV1::Active,
                ..ExceptionRuntimeStateV1::default()
            };
            lowered.rows.insert_exception(
                runtime_state_key.as_bytes(),
                ExceptionRow {
                    state: value,
                    deadline_utc_ns,
                },
            )?;
            let binding_value = ExceptionHandleBindingV1 {
                runtime_state_key,
                state: ExceptionBindingStateV1::Active,
                ..ExceptionHandleBindingV1::default()
            };
            lowered.rows.insert(
                NativeTable::ExceptionBinding,
                binding_key.as_bytes(),
                binding_value.as_bytes(),
            )?;
        }

        for binding in &proofs {
            let config = binding.input.config;
            lowered.lower_entry_admissions(
                binding,
                &composite_handles,
                &role_states,
                &assignment_handles,
            )?;
            for (object, selector) in &binding.proven {
                let key = ExactFileObjectKeyV1 {
                    profile_generation_ref_id: object.profile_generation_ref_id,
                    mount_namespace_inode: object.mount_namespace_inode,
                    mount_id_unique: object.selected_mount_id_unique,
                    filesystem_device: object.filesystem_device,
                    inode: object.inode,
                    inode_generation: object.inode_generation,
                };
                let value = ExactObjectBindingV1 {
                    profile_generation_ref_id: object.profile_generation_ref_id,
                    exact_object_key_id: object.exact_object_key_id,
                    composite_atom_id: selector.composite,
                    state: ExactObjectBindingStateV1::ReadBack,
                    reserved: [0; 7],
                };
                lowered
                    .rows
                    .insert(NativeTable::FileObject, key.as_bytes(), value.as_bytes())?;
            }

            let objects = binding
                .proven
                .iter()
                .map(|(object, _)| *object)
                .collect::<Vec<_>>();
            lowered.mount_reconciliation.extend(lowered.rows.add_paths(
                &graph,
                config,
                &objects,
                binding.input.routes,
            )?);
            lowered.rows.add_mount_namespace_guards(
                binding
                    .input
                    .objects
                    .iter()
                    .filter(|object| object.profile_generation_ref_id == generation),
            )?;
            lowered.lower_administrative_plans(
                artifact,
                config,
                &binding.entries,
                &assignment_handles,
            )?;
        }
        lowered.descriptor = ProfileGenerationDescriptorV1 {
            node_boot_id,
            profile_id: lowered.semantics.profile_id,
            label_epoch,
            profile_generation_ref_id: generation,
            owner_generation: artifact.header.profile_version,
            row_count: 0,
            default_count: 0,
            state: PolicyGenerationStateV1::Preparing,
            mode: match artifact.compiled_profile.mode {
                ProfileModeV1::Observe => PolicyGenerationModeV1::Observe,
                ProfileModeV1::Protect => PolicyGenerationModeV1::Protect,
            },
            reserved: [0; 6],
            table_digest: [0; 32],
            transition_version: 1,
        };
        let entry_authority =
            entry_admission_authority_rows(lowered.rows[NativeTable::EntryAdmission].iter())?;
        lowered.descriptor.row_count = NativeTable::ALL
            .into_iter()
            .filter(|table| {
                matches!(
                    table,
                    NativeTable::EffectDecision
                        | NativeTable::EntryAdmission
                        | NativeTable::ProcessControl
                        | NativeTable::IpcRelationship
                        | NativeTable::NetworkIpv4Class
                        | NativeTable::NetworkIpv6Class
                        | NativeTable::NetworkDecision
                )
            })
            .try_fold(0_usize, |count, table| {
                count.checked_add(if table == NativeTable::EntryAdmission {
                    entry_authority.len()
                } else {
                    lowered.rows[table].len()
                })
            })
            .and_then(|count| count.try_into().ok())
            .context(IdentityStateSnafu {
                reason: "decision row count overflow",
            })?;
        lowered.descriptor.default_count = lowered.rows[NativeTable::EffectDefault]
            .len()
            .try_into()
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("default row count overflow: {error}"),
                }
                .build()
            })?;
        lowered.descriptor.table_digest = lowered.rows.digest(&entry_authority);

        Ok(lowered)
    }

    fn lower_entry_admissions(
        &mut self,
        proof: &ProvenBinding<'_, '_>,
        composite_handles: &BTreeMap<String, u64>,
        role_states: &BTreeMap<String, (u32, u32)>,
        assignment_handles: &BTreeMap<String, u32>,
    ) -> Result<()> {
        let binding = proof.input.config;
        let semantics = &self.semantics;
        let binding_id = if proof.input.deferred {
            binding
                .scheduled_binding_authority_id
                .as_deref()
                .map(|binding_id| parse_id("scheduled_binding_authority_id", binding_id))
                .transpose()?
                .unwrap_or(parse_id("binding_id", &binding.binding_id)?)
        } else {
            parse_id("binding_id", &binding.binding_id)?
        };
        let external_role_id = semantics
            .role_handles
            .iter()
            .find_map(|(role, handle)| {
                (*handle == binding.external_role_id).then_some(role.as_str())
            })
            .context(IdentityStateSnafu {
                reason: "configured external role has no signed role ID",
            })?;
        for entry in &proof.entries {
            let Some(admission) = &entry.admission else {
                continue;
            };
            let assignment = entry.assignment;
            let [entry_kind] = assignment.entry_kinds.as_slice() else {
                return IdentityStateSnafu {
                    reason: format!(
                        "entry admission `{}` does not have one entry kind",
                        assignment.assignment_id
                    ),
                }
                .fail();
            };
            let source_role_id = match entry_kind {
                EntryKindV1::ContainerStart => assignment.resulting_role_id.as_str(),
                EntryKindV1::DeclaredPostStart
                | EntryKindV1::DeclaredPreStop
                | EntryKindV1::DeclaredStartupProbe
                | EntryKindV1::DeclaredReadinessProbe
                | EntryKindV1::DeclaredLivenessProbe => external_role_id,
                _ => {
                    return IdentityStateSnafu {
                        reason: format!(
                            "entry admission `{}` uses an unsupported transition kind",
                            assignment.assignment_id
                        ),
                    }
                    .fail();
                }
            };
            let rule = admission.rule;
            let effect = admission.effect;
            let selector = admission.selector;
            ensure!(
                rule.enabled
                    && rule.requested_disposition == PolicyDispositionV1::Allow
                    && effect.effect_families == [mithril_control::EffectFamilyV1::Exec]
                    && effect.operation_ids.iter().any(|operation| operation == "EXECUTE")
                    && effect.subject.role_ids == [assignment.resulting_role_id.as_str()]
                    && effect.subject.entry_kind_ids.contains(entry_kind)
                    && !selector.requires_exact_object(),
                IdentityStateSnafu {
                    reason: format!(
                        "entry admission rule `{}` is not one literal-path Allow Execute rule for its role and entry kind",
                        rule.rule_id
                    ),
                }
            );
            let &(target_role_id, target_state) = role_states
                .get(&assignment.resulting_role_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "entry admission `{}` has no signed target role",
                        assignment.assignment_id
                    ),
                })?;
            let key = EntryAdmissionRuleKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                binding_id,
                composite_atom_id: composite_handles
                    [&format!("PATH:{}", selector.path_selector_id)],
                source_role_id: semantics.role_handles[source_role_id],
                reserved: 0,
            };
            let value = EntryAdmissionRuleV1 {
                target_role_id,
                target_process_state_vector_id: target_state,
                admitted_entry_rule_id: assignment_handles[&assignment.assignment_id],
                reserved: 0,
                exact_object_key_id: 0,
                executable_object: ExactFileObjectKeyV1::default(),
            };
            self.rows.insert(
                NativeTable::EntryAdmission,
                key.as_bytes(),
                value.as_bytes(),
            )?;
        }
        Ok(())
    }

    fn validate_binding_roles(
        &self,
        binding: &WorkloadBindingConfig,
        entries: &[BindingEntry<'_>],
        role_states: &BTreeMap<String, (u32, u32)>,
    ) -> Result<()> {
        let semantics = &self.semantics;
        for (entry_kind, configured_handle) in [
            (EntryKindV1::ContainerStart, binding.initial_role_id),
            (
                EntryKindV1::ExternalRuntimeUnknown,
                binding.external_role_id,
            ),
        ] {
            let role_ids = entries
                .iter()
                .map(|entry| entry.assignment)
                .filter(|assignment| assignment.entry_kinds.contains(&entry_kind))
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
                semantics.role_handles.get(role_id) == Some(&configured_handle),
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` configured role handle does not match signed {entry_kind:?} role `{role_id}`",
                        binding.binding_id
                    ),
                }
            );
            ensure!(
                role_states.get(role_id).is_some_and(|(_, state)| *state == 1)
                    && semantics.process_state_handles.values().any(|state| *state == (1, 0)),
                IdentityStateSnafu {
                    reason: format!(
                        "signed role `{role_id}` needs the conservative empty process-state vector supported by the BPF root path"
                    ),
                }
            );
        }
        Ok(())
    }

    fn lower_administrative_plans(
        &mut self,
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        entries: &[BindingEntry<'_>],
        assignment_handles: &BTreeMap<String, u32>,
    ) -> Result<()> {
        let semantics = &self.semantics;
        let assignments = entries
            .iter()
            .map(|entry| entry.assignment)
            .filter(|assignment| {
                assignment.entry_kinds.as_slice() == [EntryKindV1::ApprovedAdministrativeExec]
                    && assignment.required_administrative_exec_approval
            })
            .collect::<Vec<_>>();
        if assignments.is_empty() {
            return Ok(());
        }
        ensure!(
            assignments.len() == 1,
            IdentityStateSnafu {
                reason: "one container binding must have one administrative entry",
            }
        );
        let artifact_sha256 = decode_sha256(&artifact.header.policy_document_digest)?;
        let profile = PortableProfileGenerationIdentityV1 {
            profile_id: parse_id("profile_id", &artifact.header.profile_id)?,
            owner_generation: artifact.header.profile_version,
            artifact_sha256,
        };
        for assignment in assignments {
            let role = artifact
                .policy_document
                .roles
                .iter()
                .find(|role| role.role_id == assignment.resulting_role_id)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "administrative assignment has no signed role".to_owned(),
                    }
                    .build()
                })?;
            ensure!(
                role.permitted_entry_kinds.contains(&EntryKindV1::ApprovedAdministrativeExec)
                    && semantics.process_state_handles.get(&role.default_process_state_id) == Some(&(1, 0)),
                IdentityStateSnafu {
                    reason: "administrative role needs the supported approved entry and conservative process state",
                }
            );
            let approved_role_numeric_id = semantics.role_handles[&role.role_id];
            self.administrative_plans.push(AdministrativePolicyPlanV1 {
                binding_id: parse_id("binding_id", &binding.binding_id)?,
                approved_role_id: role.role_id.clone(),
                approved_role_numeric_id,
                admitted_entry_rule_id: assignment_handles[&assignment.assignment_id],
                profile: profile.clone(),
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_binding(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        measured_objects: &[ExactFileObjectConfig],
        node_boot_id: Id128V1,
        node_id: Id128V1,
        label_epoch: u64,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<Self> {
        Self::for_binding_with_mount_routes(
            artifact,
            binding,
            measured_objects,
            &[],
            node_boot_id,
            node_id,
            label_epoch,
            now_utc_ns,
            now_boottime_ns,
            false,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_binding_with_mount_routes(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        measured_objects: &[ExactFileObjectConfig],
        measured_mount_routes: &[MeasuredMountRouteV1],
        node_boot_id: Id128V1,
        node_id: Id128V1,
        label_epoch: u64,
        now_utc_ns: i64,
        now_boottime_ns: u64,
        defer_binding_entries: bool,
    ) -> Result<Self> {
        Self::compile(
            artifact,
            binding.active_profile_generation_ref_id,
            &[GenerationBinding {
                config: binding,
                objects: measured_objects,
                routes: measured_mount_routes,
                deferred: defer_binding_entries,
            }],
            node_boot_id,
            node_id,
            label_epoch,
            now_utc_ns,
            now_boottime_ns,
        )
    }

    pub(super) fn probe_staged_rows(&self, host: &mut KernelHost) -> Result<()> {
        let mut tables = NativeTable::ALL;
        tables.sort_by_key(|table| table.probe_kind().map(|kind| kind as u8).unwrap_or(u8::MAX));
        for table in tables {
            let Some(map_kind) = table.probe_kind() else {
                continue;
            };
            for (key, value) in &self.rows[table] {
                ensure!(
                    key.len() <= MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1,
                    IdentityStateSnafu {
                        reason: "policy activation probe key exceeds its ABI bound",
                    }
                );
                let expected = PhysicalDecisionV1::try_read_from_bytes(value).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("policy activation probe decision is invalid: {error}"),
                    }
                    .build()
                })?;
                let mut probe_key = [0; MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1];
                probe_key[..key.len()].copy_from_slice(key);
                let request = PolicyActivationProbeV1 {
                    map_kind,
                    reserved: [0; 7],
                    key_size: key.len().try_into().map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!("policy activation probe key is invalid: {error}"),
                        }
                        .build()
                    })?,
                    reserved_alignment: 0,
                    key: probe_key,
                    expected,
                };
                host.run_policy_activation_probe(request.as_bytes())
                    .context(InterceptorSnafu)?;
            }
        }
        Ok(())
    }

    pub(super) fn install(
        &self,
        host: &KernelHost,
        exception_authority: &mut ExceptionAuthorityOwner,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<()> {
        let descriptor_key = self.descriptor.profile_generation_ref_id.to_le_bytes();
        let existing = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?;
        let active = self.active_descriptor();
        if let Some(existing) = existing.as_deref() {
            let read_back = self.read_back_descriptor();
            ensure!(
                existing == self.descriptor.as_bytes()
                    || existing == read_back.as_bytes()
                    || existing == active.as_bytes(),
                IdentityStateSnafu {
                    reason: "generation handle already belongs to different content",
                }
            );
        }
        let is_active = existing.as_deref() == Some(active.as_bytes());
        if is_active {
            self.verify_immutable_rows(host)?;
        } else if existing.is_none() {
            host.update_map(
                "profile_generation_descriptors",
                &descriptor_key,
                self.descriptor.as_bytes(),
            )
            .context(InterceptorSnafu)?;
        }
        for table in NativeTable::ALL {
            match table.publication() {
                Publication::Entry => continue,
                Publication::Immutable if is_active => continue,
                Publication::Exception => self.rows.install_exceptions(
                    host,
                    exception_authority,
                    now_utc_ns,
                    now_boottime_ns,
                )?,
                Publication::MountGuard => {
                    install_missing_rows(host, table.map_name(), &self.rows[table])?
                }
                _ => install_rows(host, table.map_name(), &self.rows[table])?,
            }
        }
        if !is_active {
            self.verify_immutable_rows(host)?;
        }
        self.verify_dynamic_dependency_rows(host)?;
        if is_active {
            return Ok(());
        }
        let read_back = self.read_back_descriptor();
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
        host.update_map(
            "profile_generation_descriptors",
            &descriptor_key,
            active.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("profile_generation_descriptors", &descriptor_key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(active.as_bytes()),
            IdentityStateSnafu {
                reason: "candidate descriptor ACTIVE publication readback failed",
            }
        );
        Ok(())
    }

    pub(super) fn active_descriptor(&self) -> ProfileGenerationDescriptorV1 {
        let mut active = self.descriptor;
        active.state = PolicyGenerationStateV1::Active;
        active.transition_version = 3;
        active
    }

    pub(super) fn read_back_descriptor(&self) -> ProfileGenerationDescriptorV1 {
        let mut read_back = self.descriptor;
        read_back.state = PolicyGenerationStateV1::ReadBack;
        read_back.transition_version = 2;
        read_back
    }

    pub(super) fn verify_immutable_rows(&self, host: &KernelHost) -> Result<()> {
        for table in NativeTable::ALL
            .into_iter()
            .filter(|table| table.publication() == Publication::Immutable)
        {
            verify_rows(host, table.map_name(), &self.rows[table])?;
        }
        Ok(())
    }

    pub(super) fn verify_dynamic_dependency_rows(&self, host: &KernelHost) -> Result<()> {
        for table in NativeTable::ALL
            .into_iter()
            .filter(|table| table.publication() == Publication::Dependency)
        {
            verify_rows(host, table.map_name(), &self.rows[table])?;
        }
        Ok(())
    }

    pub(super) fn install_entry_admissions(&self, host: &KernelHost) -> Result<()> {
        let table = NativeTable::EntryAdmission;
        install_rows(host, table.map_name(), &self.rows[table])?;
        verify_rows(host, table.map_name(), &self.rows[table])
    }

    pub(super) fn revoke_entry_admissions(&self, host: &KernelHost) -> Result<()> {
        let table = NativeTable::EntryAdmission;
        for key in self.rows[table].keys() {
            if host
                .lookup_map(table.map_name(), key)
                .context(InterceptorSnafu)?
                .is_some()
            {
                host.delete_map_entry(table.map_name(), key)
                    .context(InterceptorSnafu)?;
            }
            ensure!(
                host.lookup_map(table.map_name(), key)
                    .context(InterceptorSnafu)?
                    .is_none(),
                IdentityStateSnafu {
                    reason: "entry admission survived failed publication cleanup",
                }
            );
        }
        Ok(())
    }
}

pub(super) fn preflight_policy_map_capacity<'a>(
    host: &KernelHost,
    generations: impl IntoIterator<Item = &'a LoweredGeneration>,
    activations: impl IntoIterator<Item = (&'a Id128V1, &'a ProfileActivation)>,
    process_generation_migrations: &GenerationRows,
) -> Result<()> {
    let mut planned = BTreeMap::<&'static str, BTreeSet<Vec<u8>>>::new();
    for map in [
        "canonical_mount_cache_generation",
        "mount_global_activity_sequence",
        "mount_global_ambiguous_epoch",
        "mount_global_mutation_epoch",
        "mount_global_clean_epoch",
        "mount_global_pending_mutations",
    ] {
        planned
            .entry(map)
            .or_default()
            .insert(0_u32.to_ne_bytes().to_vec());
    }
    for generation in generations {
        let handle = generation.descriptor.profile_generation_ref_id;
        planned
            .entry("profile_generation_descriptors")
            .or_default()
            .insert(handle.to_ne_bytes().to_vec());
        for (map, _) in GENERATION_REFERENCES {
            planned
                .entry(map)
                .or_default()
                .insert(handle.to_ne_bytes().to_vec());
        }
        for table in NativeTable::ALL {
            let keys = planned.entry(table.map_name()).or_default();
            if table == NativeTable::ExceptionState {
                keys.extend(generation.rows.exceptions.keys().cloned());
            } else {
                keys.extend(generation.rows[table].keys().cloned());
            }
        }
        planned
            .entry("mount_reconciliation_proposals")
            .or_default()
            .extend(generation.rows[NativeTable::MountView].keys().cloned());
    }
    for (profile_id, activation) in activations {
        planned
            .entry("active_profile_generations")
            .or_default()
            .insert(profile_id.as_bytes().to_vec());
        for binding_id in activation.bindings.keys() {
            planned
                .entry("binding_activation_targets")
                .or_default()
                .insert(
                    BindingActivationTargetKeyV1 {
                        binding_id: *binding_id,
                        profile_generation_ref_id: activation.generation,
                    }
                    .as_bytes()
                    .to_vec(),
                );
        }
    }
    planned
        .entry("process_generation_migrations")
        .or_default()
        .extend(process_generation_migrations.keys().cloned());
    for (map, planned_keys) in planned {
        let capacity = host
            .manifest()
            .maps
            .iter()
            .find(|candidate| candidate.name == map)
            .map(|candidate| u64::from(candidate.max_entries))
            .context(IdentityStateSnafu {
                reason: format!("required policy map `{map}` has no manifest capacity"),
            })?;
        let existing = host.map_keys(map).context(InterceptorSnafu)?;
        ensure_map_capacity(map, capacity, existing, planned_keys)?;
    }
    Ok(())
}

pub(super) fn ensure_map_capacity(
    map: &str,
    capacity: u64,
    existing: impl IntoIterator<Item = Vec<u8>>,
    planned: impl IntoIterator<Item = Vec<u8>>,
) -> Result<()> {
    let mut keys = existing.into_iter().collect::<BTreeSet<_>>();
    keys.extend(planned);
    ensure!(
        u64::try_from(keys.len()).unwrap_or(u64::MAX) <= capacity,
        IdentityStateSnafu {
            reason: format!(
                "policy map `{map}` needs {} rows but its capacity is {capacity}",
                keys.len()
            ),
        }
    );
    Ok(())
}

impl GenerationPlan {
    fn install_exceptions(
        &self,
        host: &KernelHost,
        authority: &mut ExceptionAuthorityOwner,
        now_utc_ns: i64,
        now_boottime_ns: u64,
    ) -> Result<()> {
        for (key, row) in &self.exceptions {
            let existing_bytes = host
                .lookup_map_locked("exception_runtime_states", key)
                .context(InterceptorSnafu)?;
            let desired = row.state;
            let deadline_utc_ns = row.deadline_utc_ns;
            let installed = authority.prepare_runtime(
                key,
                desired,
                deadline_utc_ns,
                existing_bytes.as_deref(),
                now_utc_ns,
                now_boottime_ns,
            )?;
            if let Some(existing) = existing_bytes {
                let existing = read_abi_value::<ExceptionRuntimeStateV1>(
                    &existing,
                    "existing exception runtime state",
                )?;
                ensure!(
                    existing.maximum_uses == desired.maximum_uses
                        && existing.bound_profile_generation_refs
                            == desired.bound_profile_generation_refs
                        && existing.exception_definition_sha256
                            == desired.exception_definition_sha256
                        && exception_counter_is_consistent(
                            existing.maximum_uses,
                            existing.consumed_uses,
                            existing.state,
                        )
                        && existing.deadline_boottime_ns <= desired.deadline_boottime_ns
                        && existing.transition_version > 0,
                    IdentityStateSnafu {
                        reason: "existing exception runtime state is inconsistent with the signed generation",
                    }
                );
                continue;
            }
            host.update_map("exception_runtime_states", key, installed.as_bytes())
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map_locked("exception_runtime_states", key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(installed.as_bytes()),
                IdentityStateSnafu {
                    reason: "exception runtime state readback failed",
                }
            );
        }
        Ok(())
    }
}

pub(super) fn exception_counter_is_consistent(
    maximum_uses: u32,
    consumed_uses: u32,
    state: ExceptionRuntimeStateKindV1,
) -> bool {
    maximum_uses > 0
        && consumed_uses <= maximum_uses
        && ((state == ExceptionRuntimeStateKindV1::Active && consumed_uses < maximum_uses)
            || (state == ExceptionRuntimeStateKindV1::Exhausted && consumed_uses == maximum_uses)
            || state == ExceptionRuntimeStateKindV1::Expired)
}

pub(super) fn cell_matches_binding(
    key: &StaticDecisionKeyV1,
    binding: &WorkloadBindingConfig,
    document: &PolicyDocumentV1,
) -> bool {
    // A scheduled binding gives the signed policy slot a unique runtime execution-set identity.
    let execution_set_id = if binding.scheduled_binding_authority_id.is_some() {
        let [execution_set_id] = document.protected_universe.execution_set_ids.as_slice() else {
            return false;
        };
        execution_set_id
    } else {
        &binding.execution_set_id
    };
    key.workload_selector_id == binding.workload_selector_id
        && key.protected_scope_id == binding.protected_scope_id
        && key.execution_set_id == *execution_set_id
}

impl<'a> BindingEntry<'a> {
    pub(super) fn for_binding(
        artifact: &'a ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
    ) -> Result<Vec<Self>> {
        let mut entries = Vec::new();
        for assignment in artifact
            .policy_document
            .entry_role_assignments
            .iter()
            .filter(|assignment| {
                assignment
                    .workload_selector_ids
                    .contains(&binding.workload_selector_id)
                    && assignment
                        .container_kinds
                        .contains(&policy_container_kind(binding.container_kind))
            })
        {
            let Some(rule_id) = assignment.admission_execution_rule_id.as_deref() else {
                entries.push(Self {
                    assignment,
                    admission: None,
                });
                continue;
            };
            let rule = artifact
                .policy_document
                .rules
                .iter()
                .find(|rule| rule.rule_id == rule_id)
                .context(IdentityStateSnafu {
                    reason: format!("entry admission rule `{rule_id}` is not signed"),
                })?;
            let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match else {
                return IdentityStateSnafu {
                    reason: format!("entry admission rule `{rule_id}` is not a local effect"),
                }
                .fail();
            };
            let LocalObjectSelectorV1::PathSelectors { path_selector_ids } = &effect.object else {
                return IdentityStateSnafu {
                    reason: format!("entry admission rule `{rule_id}` has no path selector"),
                }
                .fail();
            };
            let [selector_id] = path_selector_ids.as_slice() else {
                return IdentityStateSnafu {
                    reason: format!("entry admission rule `{rule_id}` is not one exact path match"),
                }
                .fail();
            };
            let selector = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| selector.path_selector_id == *selector_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "entry admission rule `{rule_id}` has an unknown path selector"
                    ),
                })?;
            let components = selector
                .target
                .pattern_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?;
            ensure!(
                !selector.requires_exact_object()
                    && components
                        .iter()
                        .all(|component| matches!(component, PathPatternComponentV1::Exact(_))),
                IdentityStateSnafu {
                    reason: format!(
                        "entry admission rule `{rule_id}` does not use one literal request path"
                    ),
                }
            );
            entries.push(Self {
                assignment,
                admission: Some(EntryAdmission {
                    rule,
                    effect,
                    selector,
                }),
            });
        }
        Ok(entries)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn entry_admission_path_selector_ids(
    artifact: &ProfileCandidateArtifactV1,
    binding: &WorkloadBindingConfig,
) -> Result<BTreeSet<String>> {
    Ok(BindingEntry::for_binding(artifact, binding)?
        .into_iter()
        .filter_map(|entry| entry.admission)
        .map(|admission| admission.selector.path_selector_id.clone())
        .collect())
}

fn entry_admission_authority_rows<'a>(
    rows: impl IntoIterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>,
) -> Result<GenerationRows> {
    let mut authority = GenerationRows::new();
    for (key, value) in rows {
        let mut key: EntryAdmissionRuleKeyV1 = read_abi_value(key, "entry admission rule key")?;
        key.binding_id = Id128V1::default();
        let mut rule: EntryAdmissionRuleV1 = read_abi_value(value, "entry admission rule")?;
        rule.exact_object_key_id = 0;
        rule.executable_object = ExactFileObjectKeyV1::default();
        insert_exact(&mut authority, key.as_bytes(), rule.as_bytes())?;
    }
    Ok(authority)
}
