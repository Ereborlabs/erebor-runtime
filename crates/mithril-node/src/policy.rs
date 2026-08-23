use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;
use std::sync::Mutex;

use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    ApprovedExecSlotStateV1, ApprovedExecSlotV1, AuthorityDomainStateV1,
    BindingActivationTargetKeyV1, BindingLifecycleStateV1, CanonicalMountRootKeyV1,
    CanonicalMountRootV1, CanonicalPathComponentV1, EffectDecisionKeyV1, EffectDefaultKeyV1,
    ExactExecutableCandidateV1, ExactFileObjectKeyV1, ExactObjectBindingStateV1,
    ExactObjectBindingV1, ExceptionBindingStateV1, ExceptionHandleBindingKeyV1,
    ExceptionHandleBindingV1, ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1,
    ExceptionRuntimeStateV1, ExecutionSetBindingStateV1, Id128V1, IoUringRequestStateV1,
    IoUringRingStateV1, KernelEffectFamilyV1, MountReconciliationProposalV1,
    MountSecurityViewStateV1, MountTopologyStateV1, NetworkDestinationDecisionKeyV1,
    NetworkResponseFloorKeyV1, NetworkResponseFloorV1, NetworkResponseScopeV1, PathGraphStateKeyV1,
    PathGraphTerminalV1, PathGraphTransitionKeyV1, PathGraphTransitionV1,
    PendingAdministrativeMatchV1, PendingExecV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
    PolicyActivationProbeMapKindV1, PolicyActivationProbeV1, PolicyGenerationModeV1,
    PolicyGenerationStateV1, ProcessSecurityStateKindV1, ProcessSecurityStateV1,
    ProfileGenerationDescriptorV1, ReferenceTombstoneStateV1, TaskReferenceTombstoneV1,
    MAX_CANONICAL_COMPONENT_BYTES_V1, MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1,
};
use mithril_control::{
    canonical_path_components, AntiRollbackStore, CanonicalPathGraphV1, CompiledOperationV1,
    CompiledPhysicalResultV1, ContainerKindV1 as PolicyContainerKindV1, EntryKindV1,
    ExceptionActivationStateV1, ExceptionDeliveryCandidateV1, ExceptionDeliveryOperationV1,
    ObjectClassifierSelectorV1, PathPatternV1, PathSelectorTargetV1, PathTreeDenyPatternV1,
    PendingProfileActivationV1, PolicyArtifactOwner, PolicyDocumentV1, ProfileActivationMetadataV1,
    ProfileCandidateArtifactV1, ProfileModeV1, StaticDecisionKeyV1, ValidatedProfileCandidateV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::{FromBytes as _, IntoBytes as _, KnownLayout, TryFromBytes};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, PolicySnafu};
use crate::identity::{
    AdministrativeFileObjectIdentityV1, ExactObjectBindingTargetV1,
    PortableProfileGenerationIdentityV1, ResolvedAdministrativeExecutableIdentityV1,
};
use crate::{
    AdministrativeBindingTargetV1, ExactFileObjectConfig, NodeConfig, Result,
    WorkloadBindingConfig, WorkloadBindingOwner,
};

mod device_process;
mod exception_authority;
mod generation_allocator;
mod ipc;
mod network;

use self::device_process::{lower_typed_effect, TypedEffectContext};
use self::exception_authority::ExceptionAuthorityOwner;
use self::generation_allocator::GenerationHandleAllocator;
use self::ipc::lower_ipc_relationships;
use self::network::LoweredNetworkPolicy;

pub struct NodePolicyGenerationOwner {
    node_boot_id: Id128V1,
    label_epoch: u64,
    mount_roots: Vec<MountRootReconciliation>,
    mount_view_handles: BTreeMap<u32, crate::exact_object::ExactFileObjectView>,
    prevention_enabled: bool,
    administrative_required: bool,
    administrative_plans: Vec<AdministrativePolicyPlanV1>,
    measured_exact_objects: Vec<MeasuredExactObjectV1>,
    dynamic_rows: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    exception_authority: Mutex<ExceptionAuthorityOwner>,
}

pub(crate) struct PolicyActivationReceiptV1 {
    pub node_bound_generation_digest: String,
    pub profile_generation_ref_id: u64,
    pub readback_digest: String,
    pub probe_result_digest: String,
}

pub(crate) struct ExceptionRuntimeObservationV1 {
    pub state: ExceptionActivationStateV1,
    pub consumed_uses: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MeasuredExactObjectV1 {
    binding_id: String,
    object: ExactFileObjectConfig,
}

#[derive(Clone, Debug)]
struct AdministrativePolicyPlanV1 {
    binding_id: Id128V1,
    approved_role_id: String,
    approved_role_numeric_id: u32,
    profile: PortableProfileGenerationIdentityV1,
    profile_generation_ref_id: u64,
    exception_numeric_handle: u32,
    executable_object: ExactFileObjectConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedAdministrativePolicyV1 {
    pub approved_role_numeric_id: u32,
    pub profile_generation_ref_id: u64,
    pub exception_numeric_handle: u32,
    pub profile: PortableProfileGenerationIdentityV1,
    pub resolved_executable: ResolvedAdministrativeExecutableIdentityV1,
    pub kernel_executable: ExactExecutableCandidateV1,
}

#[derive(Clone, Copy)]
struct BindingActivationTarget {
    generation: u64,
    initial_role_id: u32,
    external_role_id: u32,
    requires_live_cgroup: bool,
}

struct ProfileActivation {
    generation: u64,
    bindings: BTreeMap<Id128V1, BindingActivationTarget>,
}

struct StagedActivationTarget {
    key: Vec<u8>,
    previous: Option<Vec<u8>>,
    desired: ExecutionSetBindingStateV1,
}

type GenerationRows = BTreeMap<Vec<u8>, Vec<u8>>;
type PlannedGenerationRow<'a> = (&'static str, &'a GenerationRows);
type ActivationDecisionRow<'a> = (PolicyActivationProbeMapKindV1, &'a GenerationRows);

impl NodePolicyGenerationOwner {
    pub(crate) fn next_generation_ref_id(
        config: &NodeConfig,
        host: &KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<u64> {
        // The allocator reconciles durable handles with live maps before it returns a new handle.
        GenerationHandleAllocator::load(
            config.state_directory.join("generation-handles-v1.json"),
            host,
            node_boot_id,
            label_epoch,
        )?
        .next_handle()
    }

    pub(crate) fn activation_receipt(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<PolicyActivationReceiptV1> {
        let profile_id = parse_id("profile_id", profile_id)?;
        // Read the published pointer and descriptor; staged bytes do not prove activation.
        let active = host
            .lookup_map("active_profile_generations", profile_id.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the activated profile has no active pointer",
            })?;
        ensure!(
            u64::read_from_bytes(&active)
                .is_ok_and(|active| { active == profile_generation_ref_id }),
            IdentityStateSnafu {
                reason: "the activated profile pointer failed exact readback",
            }
        );
        let descriptor = host
            .lookup_map(
                "profile_generation_descriptors",
                &profile_generation_ref_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the activated profile has no generation descriptor",
            })?;
        let parsed =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the activated generation descriptor is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            parsed.profile_id == profile_id
                && parsed.profile_generation_ref_id == profile_generation_ref_id
                && parsed.state == PolicyGenerationStateV1::Active,
            IdentityStateSnafu {
                reason: "the activated generation descriptor is not current",
            }
        );
        // Bind the acknowledgement to exact descriptor bytes and the controlled probe domain.
        let readback_digest = format!("{:x}", Sha256::digest(&descriptor));
        let mut probe = Sha256::new();
        probe.update(b"MITHRIL-POLICY-CONTROLLED-PROBE-V1\0");
        probe.update(parsed.table_digest);
        probe.update(profile_generation_ref_id.to_be_bytes());
        Ok(PolicyActivationReceiptV1 {
            node_bound_generation_digest: hex::encode(parsed.table_digest),
            profile_generation_ref_id,
            readback_digest,
            probe_result_digest: format!("{:x}", probe.finalize()),
        })
    }

    pub(crate) fn apply_exception_candidate(
        &self,
        host: &KernelHost,
        candidate: &ExceptionDeliveryCandidateV1,
        grant_handle: u32,
    ) -> Result<ExceptionRuntimeObservationV1> {
        let profile_id = parse_id("profile_id", &candidate.profile_id)?;
        let exception_instance_id =
            parse_id("exception_instance_id", &candidate.exception_instance_id)?;
        let descriptor_key = candidate.profile_generation_ref_id.to_ne_bytes();
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
            .map(|descriptor| {
                ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("the exception base-policy descriptor is invalid: {error}"),
                    }
                    .build()
                })
            })
            .transpose()?;
        ensure!(
            descriptor.as_ref().is_none_or(|descriptor| {
                descriptor.profile_id == profile_id
                    && descriptor.profile_generation_ref_id == candidate.profile_generation_ref_id
                    && descriptor.node_boot_id == self.node_boot_id
                    && descriptor.label_epoch == self.label_epoch
                    && matches!(
                        descriptor.state,
                        PolicyGenerationStateV1::Active | PolicyGenerationStateV1::Retiring
                    )
            }),
            IdentityStateSnafu {
                reason: "the exception target differs from its local policy generation",
            }
        );
        ensure!(
            candidate.operation == ExceptionDeliveryOperationV1::Revoke || descriptor.is_some(),
            IdentityStateSnafu {
                reason: "the exception base-policy generation is not installed",
            }
        );
        let mut authority = self.exception_authority.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "exception authority owner lock is poisoned".to_owned(),
            }
            .build()
        })?;
        let runtime_key = ExceptionRuntimeStateKeyV1 {
            node_id: authority.node_id(),
            exception_instance_id,
        };
        let binding_key = ExceptionHandleBindingKeyV1 {
            profile_generation_ref_id: candidate.profile_generation_ref_id,
            exception_numeric_handle: grant_handle,
            reserved: 0,
        };
        match candidate.operation {
            ExceptionDeliveryOperationV1::Activate => {
                let now_utc_ns = current_utc_ns()?;
                let remaining_ns = u64::try_from(candidate.valid_until_utc_ns - now_utc_ns)
                    .map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!(
                                "the exception activation deadline is invalid: {error}"
                            ),
                        }
                        .build()
                    })?;
                let now_boottime_ns = current_boottime_ns()?;
                let deadline_boottime_ns =
                    now_boottime_ns.checked_add(remaining_ns).ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "the exception boottime deadline overflows".to_owned(),
                        }
                        .build()
                    })?;
                let definition_bytes =
                    hex::decode(&candidate.candidate_content_id).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!(
                                "the exception candidate content identity is invalid: {error}"
                            ),
                        }
                        .build()
                    })?;
                let definition: [u8; 32] = definition_bytes.try_into().map_err(|_| {
                    IdentityStateSnafu {
                        reason: "the exception candidate content identity has an invalid size"
                            .to_owned(),
                    }
                    .build()
                })?;
                let desired = ExceptionRuntimeStateV1 {
                    lock: 0,
                    maximum_uses: candidate.maximum_uses,
                    consumed_uses: 0,
                    bound_profile_generation_refs: 1,
                    deadline_boottime_ns,
                    transition_version: 1,
                    exception_definition_sha256: definition,
                    state: ExceptionRuntimeStateKindV1::Active,
                    reserved: [0; 7],
                };
                let existing = host
                    .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                    .context(InterceptorSnafu)?;
                let installed = authority.prepare_runtime(
                    runtime_key.as_bytes(),
                    desired,
                    candidate.valid_until_utc_ns,
                    existing.as_deref(),
                    now_utc_ns,
                    now_boottime_ns,
                )?;
                // Durable runtime authority must exist before a grant handle can reach it.
                if existing.is_none() {
                    host.update_map(
                        "exception_runtime_states",
                        runtime_key.as_bytes(),
                        installed.as_bytes(),
                    )
                    .context(InterceptorSnafu)?;
                }
                ensure!(
                    host.lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .is_some_and(|live| live == installed.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the exception runtime state failed exact readback",
                    }
                );
                let mut binding = ExceptionHandleBindingV1 {
                    runtime_state_key: runtime_key,
                    state: ExceptionBindingStateV1::Preparing,
                    reserved: [0; 7],
                };
                // Preparing readback makes a partial binding fail closed during recovery.
                host.update_map(
                    "exception_handle_bindings",
                    binding_key.as_bytes(),
                    binding.as_bytes(),
                )
                .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the preparing exception binding failed exact readback",
                    }
                );
                binding.state = ExceptionBindingStateV1::Active;
                host.update_map(
                    "exception_handle_bindings",
                    binding_key.as_bytes(),
                    binding.as_bytes(),
                )
                .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the active exception binding failed exact readback",
                    }
                );
                Ok(ExceptionRuntimeObservationV1 {
                    state: ExceptionActivationStateV1::Active,
                    consumed_uses: installed.consumed_uses,
                })
            }
            ExceptionDeliveryOperationV1::Revoke => {
                let binding = host
                    .lookup_map("exception_handle_bindings", binding_key.as_bytes())
                    .context(InterceptorSnafu)?;
                // A retired base generation may remove its binding before Control sends revoke.
                ensure!(
                    descriptor.is_some() || binding.is_none(),
                    IdentityStateSnafu {
                        reason: "an exception binding outlived its base-policy generation",
                    }
                );
                if let Some(binding) = binding {
                    let mut binding = ExceptionHandleBindingV1::try_read_from_bytes(&binding)
                        .map_err(|error| {
                            IdentityStateSnafu {
                                reason: format!("the exception binding is invalid: {error}"),
                            }
                            .build()
                        })?;
                    ensure!(
                        binding.runtime_state_key == runtime_key,
                        IdentityStateSnafu {
                            reason: "the exception grant is bound to another runtime instance",
                        }
                    );
                    // Retiring blocks new BPF claims before authority reconciliation runs.
                    binding.state = ExceptionBindingStateV1::Retiring;
                    host.update_map(
                        "exception_handle_bindings",
                        binding_key.as_bytes(),
                        binding.as_bytes(),
                    )
                    .context(InterceptorSnafu)?;
                    ensure!(
                        host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                            .context(InterceptorSnafu)?
                            .as_deref()
                            == Some(binding.as_bytes()),
                        IdentityStateSnafu {
                            reason: "the retiring exception binding failed exact readback",
                        }
                    );
                }
                authority.reconcile(host, current_utc_ns()?)?;
                // Keep the final use count after revocation for the durable Control receipt.
                let consumed_uses = host
                    .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                    .context(InterceptorSnafu)?
                    .map_or(Ok(0), |state| {
                        ExceptionRuntimeStateV1::try_read_from_bytes(&state)
                            .map(|state| state.consumed_uses)
                            .map_err(|error| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "the revoked exception runtime state is invalid: {error}"
                                    ),
                                }
                                .build()
                            })
                    })?;
                Ok(ExceptionRuntimeObservationV1 {
                    state: ExceptionActivationStateV1::Revoked,
                    consumed_uses,
                })
            }
        }
    }

    pub(crate) fn observe_exception_candidate(
        &self,
        host: &KernelHost,
        candidate: &ExceptionDeliveryCandidateV1,
    ) -> Result<ExceptionRuntimeObservationV1> {
        let exception_instance_id =
            parse_id("exception_instance_id", &candidate.exception_instance_id)?;
        let mut authority = self.exception_authority.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "exception authority owner lock is poisoned".to_owned(),
            }
            .build()
        })?;
        authority.reconcile(host, current_utc_ns()?)?;
        let runtime_key = ExceptionRuntimeStateKeyV1 {
            node_id: authority.node_id(),
            exception_instance_id,
        };
        let state = host
            .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the active exception has no runtime state",
            })?;
        let state = ExceptionRuntimeStateV1::try_read_from_bytes(&state).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("the active exception runtime state is invalid: {error}"),
            }
            .build()
        })?;
        let observed = match state.state {
            // The deadline is authoritative even if no later BPF operation updates the map state.
            ExceptionRuntimeStateKindV1::Active
                if current_boottime_ns()? >= state.deadline_boottime_ns =>
            {
                ExceptionActivationStateV1::Expired
            }
            ExceptionRuntimeStateKindV1::Active => ExceptionActivationStateV1::Active,
            ExceptionRuntimeStateKindV1::Exhausted => ExceptionActivationStateV1::Consumed,
            ExceptionRuntimeStateKindV1::Expired => ExceptionActivationStateV1::Expired,
            ExceptionRuntimeStateKindV1::ReconciliationRequired
            | ExceptionRuntimeStateKindV1::Unknown => ExceptionActivationStateV1::Stale,
        };
        Ok(ExceptionRuntimeObservationV1 {
            state: observed,
            consumed_uses: state.consumed_uses,
        })
    }

    pub fn fence_network_socket(
        &self,
        host: &KernelHost,
        key: NetworkResponseFloorKeyV1,
    ) -> Result<bool> {
        ensure!(
            key.profile_generation_ref_id > 0 && key.socket_key_id > 0 && key.socket_generation > 0,
            IdentityStateSnafu {
                reason: "a network response fence needs exact nonzero socket identity",
            }
        );
        let generation_key = key.profile_generation_ref_id.to_ne_bytes();
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &generation_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the network response generation does not exist",
            })?;
        let descriptor =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the network response generation is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            descriptor.profile_generation_ref_id == key.profile_generation_ref_id
                && descriptor.node_boot_id == self.node_boot_id
                && descriptor.label_epoch == self.label_epoch
                && matches!(
                    descriptor.state,
                    PolicyGenerationStateV1::Active | PolicyGenerationStateV1::Retiring
                ),
            IdentityStateSnafu {
                reason: "the network response generation is not a live local generation",
            }
        );
        let references = host
            .lookup_map("profile_generation_socket_refs", &generation_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the network response generation has no socket references",
            })?;
        ensure!(
            u64::read_from_bytes(&references).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the network socket reference count is invalid: {error}"),
                }
                .build()
            })? > 0,
            IdentityStateSnafu {
                reason: "the network response generation has no live socket",
            }
        );
        let floor = NetworkResponseFloorV1 {
            scope: NetworkResponseScopeV1::WholeSocket,
            reserved: [0; 7],
        };
        let inserted = host
            .insert_map("network_response_floors", key.as_bytes(), floor.as_bytes())
            .context(InterceptorSnafu)?
            == MapInsertResult::Inserted;
        ensure!(
            host.lookup_map("network_response_floors", key.as_bytes())
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(floor.as_bytes()),
            IdentityStateSnafu {
                reason: "the whole-socket response fence failed exact readback",
            }
        );
        Ok(inserted)
    }

    pub fn load_and_install(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            Vec::new(),
            BTreeMap::new(),
        )
    }

    pub(crate) fn load_and_install_for_bindings(
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let measured_exact_objects =
            Self::resolve_cri_exact_objects(config, host, bindings.exact_object_binding_targets())?;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            measured_exact_objects,
            BTreeMap::new(),
        )
    }

    pub fn reload_and_install(
        self,
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let measured_exact_objects = self.measured_exact_objects;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            measured_exact_objects,
            self.mount_view_handles,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn load_and_install_for_test_objects<I, S>(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        objects: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        let measured_exact_objects = Self::resolve_test_exact_objects(config, objects)?;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            measured_exact_objects,
            BTreeMap::new(),
        )
    }

    #[cfg(feature = "test-support")]
    pub fn reload_and_install_for_test_objects<I, S>(
        self,
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        objects: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        let measured_exact_objects = Self::resolve_test_exact_objects(config, objects)?;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            measured_exact_objects,
            self.mount_view_handles,
        )
    }

    fn install(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        measured_exact_objects: Vec<MeasuredExactObjectV1>,
        mut retained_mount_views: BTreeMap<u32, crate::exact_object::ExactFileObjectView>,
    ) -> Result<Self> {
        let platform_scope_digest = format!(
            "{:x}",
            Sha256::digest(
                [
                    host.manifest().preflight.kernel_release.as_bytes(),
                    host.manifest().preflight.runtime_btf_sha256.as_bytes(),
                    host.manifest().object_sha256.as_bytes(),
                ]
                .concat()
            )
        );
        let artifact_owner = PolicyArtifactOwner::default();
        let mut artifacts = BTreeMap::new();
        let now_utc_ns = current_utc_ns()?;
        let now_boottime_ns = current_boottime_ns()?;
        for candidate in &config.policy_candidates {
            let artifact = artifact_owner
                .load_verified_at(
                    &candidate.artifact_path,
                    &candidate.public_key_path,
                    now_utc_ns,
                )
                .context(PolicySnafu)?;
            let rollback = match (
                candidate.rollback_authorization_path.as_deref(),
                candidate.rollback_public_key_path.as_deref(),
            ) {
                (Some(artifact_path), Some(public_key_path)) => Some(
                    artifact_owner
                        .load_verified_rollback(artifact_path, public_key_path)
                        .context(PolicySnafu)?,
                ),
                (None, None) => None,
                _ => unreachable!("NodeConfig validation requires a complete rollback pair"),
            };
            ensure!(
                artifacts
                    .insert(artifact.header.profile_id.clone(), (artifact, rollback))
                    .is_none(),
                IdentityStateSnafu {
                    reason: "one node candidate is allowed per profile ID",
                }
            );
        }
        let mut rollback =
            AntiRollbackStore::load(config.state_directory.join("policy-anti-rollback-v1.json"))
                .context(PolicySnafu)?;
        reconcile_pending_activations(host, &mut rollback, node_boot_id, label_epoch)?;
        let mut generations = BTreeMap::<u64, LoweredGeneration>::new();
        let mut activations = BTreeMap::<Id128V1, ProfileActivation>::new();
        let mut validated = BTreeMap::<Id128V1, ValidatedProfileCandidateV1>::new();
        let node_id = stable_node_id(&config.node_id)?;
        for binding in &config.workload_bindings {
            let (artifact, rollback_authorization) =
                artifacts.get(&binding.profile_id).ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "binding `{}` has no verified candidate for profile `{}`",
                            binding.binding_id, binding.profile_id
                        ),
                    }
                    .build()
                })?;
            let profile_id = parse_id("profile_id", &binding.profile_id)?;
            if let std::collections::btree_map::Entry::Vacant(entry) = validated.entry(profile_id) {
                entry.insert(
                    rollback
                        .validate(
                            artifact,
                            rollback_authorization
                                .as_ref()
                                .map(|(proof, key)| (proof, key)),
                            &platform_scope_digest,
                            now_utc_ns,
                        )
                        .context(PolicySnafu)?,
                );
            }
            let binding_id = parse_id("binding_id", &binding.binding_id)?;
            add_binding_activation(&mut activations, profile_id, binding_id, binding)?;
            let measured_for_binding = measured_exact_objects
                .iter()
                .filter(|measured| measured.binding_id == binding.binding_id)
                .map(|measured| measured.object.clone())
                .collect::<Vec<_>>();
            let lowered = LoweredGeneration::for_binding(
                artifact,
                binding,
                &measured_for_binding,
                node_boot_id,
                node_id,
                label_epoch,
                now_utc_ns,
                now_boottime_ns,
            )?;
            match generations.get_mut(&binding.active_profile_generation_ref_id) {
                Some(existing) => existing.merge(lowered)?,
                None => {
                    generations.insert(binding.active_profile_generation_ref_id, lowered);
                }
            }
        }
        let mut generation_allocator = GenerationHandleAllocator::load(
            config.state_directory.join("generation-handles-v1.json"),
            host,
            node_boot_id,
            label_epoch,
        )?;
        for generation in generations.values() {
            generation_allocator.reserve(&generation.descriptor)?;
        }
        preflight_policy_map_capacity(host, &generations, &activations)?;
        let mut exception_authority =
            ExceptionAuthorityOwner::load(&config.state_directory, node_id, node_boot_id)?;
        exception_authority.restore_receipts(host)?;
        let mount_roots = generations
            .values()
            .flat_map(|generation| generation.mount_reconciliation.iter().cloned())
            .collect::<Vec<_>>();
        let mut mount_view_root_pids = BTreeMap::new();
        let mut mount_view_handles = BTreeMap::new();
        let mut mount_view_is_retained = BTreeMap::new();
        for root in &mount_roots {
            let root_pid = root.configured.mount_view_root_pid;
            if let Some(existing) =
                mount_view_root_pids.insert(root.mount_namespace_inode, root_pid)
            {
                ensure!(
                    existing == root_pid,
                    IdentityStateSnafu {
                        reason: "one mount security view has multiple live root processes",
                    }
                );
                let view = mount_view_handles
                    .get(&root.mount_namespace_inode)
                    .ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "mount security view lost its retained capability".to_owned(),
                        }
                        .build()
                    })?;
                validate_mount_view(
                    view,
                    root,
                    mount_view_is_retained[&root.mount_namespace_inode],
                )?;
                continue;
            }
            let retained = retained_mount_views.remove(&root.mount_namespace_inode);
            let is_retained = retained.is_some();
            let view = match retained {
                Some(view) => view,
                None => crate::exact_object::ExactFileObjectView::acquire(root_pid)?,
            };
            ensure!(
                view.mount_namespace_inode()? == root.mount_namespace_inode,
                IdentityStateSnafu {
                    reason: "held mount namespace differs from the configured security view",
                }
            );
            validate_mount_view(&view, root, is_retained)?;
            mount_view_is_retained.insert(root.mount_namespace_inode, is_retained);
            mount_view_handles.insert(root.mount_namespace_inode, view);
        }
        install_global_mount_barrier(host, &mount_roots)?;
        for generation in generations.values() {
            generation.install(host, &mut exception_authority, now_utc_ns, now_boottime_ns)?;
            generation.probe_staged_rows(host)?;
        }
        for (profile_id, activation) in &activations {
            activate_profile(
                host,
                profile_id,
                activation,
                &mut rollback,
                &validated[profile_id],
                node_boot_id,
                label_epoch,
            )?;
        }
        exception_authority.reconcile(host, now_utc_ns)?;
        reconcile_generation_retirement(host, node_boot_id, label_epoch)?;
        let administrative_plans = generations
            .values()
            .flat_map(|generation| generation.administrative_plans.iter().cloned())
            .collect();
        let administrative_required = generations
            .values()
            .any(|generation| generation.administrative_required);
        let dynamic_rows = Self::dynamic_generation_rows(&generations);
        let owner = Self {
            node_boot_id,
            label_epoch,
            mount_roots,
            mount_view_handles,
            prevention_enabled: generations
                .values()
                .any(|generation| generation.descriptor.mode == PolicyGenerationModeV1::Protect),
            administrative_required,
            administrative_plans,
            measured_exact_objects,
            dynamic_rows,
            exception_authority: Mutex::new(exception_authority),
        };
        owner.reconcile_mount_views(host)?;
        Ok(owner)
    }

    #[must_use]
    pub const fn prevention_enabled(&self) -> bool {
        self.prevention_enabled
    }

    #[must_use]
    pub(crate) fn administrative_enabled(&self) -> bool {
        self.administrative_required
    }

    pub(crate) fn reconcile_cri_exact_bindings(
        &mut self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
    ) -> Result<()> {
        let measured_exact_objects = match Self::resolve_cri_exact_objects(
            config,
            host,
            bindings.exact_object_binding_targets(),
        ) {
            Ok(measured) => measured,
            Err(error) => {
                self.revoke_dynamic_path_authority(host)?;
                return Err(error);
            }
        };
        if measured_exact_objects == self.measured_exact_objects {
            return Ok(());
        }

        self.revoke_dynamic_path_authority(host)?;
        let retained_mount_views = std::mem::take(&mut self.mount_view_handles);
        let next = Self::install(
            config,
            host,
            self.node_boot_id,
            self.label_epoch,
            measured_exact_objects,
            retained_mount_views,
        )?;
        *self = next;
        Ok(())
    }

    fn revoke_dynamic_path_authority(&mut self, host: &KernelHost) -> Result<()> {
        for map in [
            "device_effect_decisions",
            "exact_file_objects",
            "canonical_mount_roots",
            "mount_security_views",
            "mount_mutation_epochs",
            "mount_security_view_locks",
        ] {
            let Some(keys) = self.dynamic_rows.get(map) else {
                continue;
            };
            for key in keys {
                if host
                    .lookup_map(map, key)
                    .context(InterceptorSnafu)?
                    .is_some()
                {
                    host.delete_map_entry(map, key).context(InterceptorSnafu)?;
                }
                ensure!(
                    host.lookup_map(map, key)
                        .context(InterceptorSnafu)?
                        .is_none(),
                    IdentityStateSnafu {
                        reason: format!(
                            "dynamic path authority remained in `{map}` after revocation"
                        ),
                    }
                );
            }
        }
        self.dynamic_rows.clear();
        self.measured_exact_objects.clear();
        self.administrative_plans.clear();
        Ok(())
    }

    fn resolve_cri_exact_objects<'a>(
        config: &NodeConfig,
        host: &KernelHost,
        bindings: impl IntoIterator<Item = ExactObjectBindingTargetV1<'a>>,
    ) -> Result<Vec<MeasuredExactObjectV1>> {
        let now_utc_ns = current_utc_ns()?;
        let artifact_owner = PolicyArtifactOwner::default();
        let mut artifacts = BTreeMap::new();
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
        let topology_generation = Self::current_mount_topology_generation(host)?;
        let mut measured = Vec::new();
        let mut target_bindings = BTreeSet::new();
        for target in bindings {
            ensure!(
                target_bindings.insert(target.binding_id),
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has more than one authenticated CRI exact-object target",
                        target.binding_id
                    ),
                }
            );
            let binding = config
                .workload_bindings
                .iter()
                .find(|binding| binding.binding_id == target.binding_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "authenticated CRI exact-object target `{}` is not configured",
                        target.binding_id
                    ),
                })?;
            let artifact = artifacts
                .get(&binding.profile_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has no verified candidate for exact-object resolution",
                        binding.binding_id
                    ),
                })?;
            let selectors = artifact
                .policy_document
                .path_selectors
                .iter()
                .filter(|selector| selector.requires_exact_object());
            let view = crate::exact_object::ExactFileObjectView::acquire(target.init_pid)?;
            for selector in selectors {
                let canonical_path =
                    selector
                        .exact_canonical_path()
                        .context(IdentityStateSnafu {
                            reason: "exact path selector lost its canonical path",
                        })?;
                let path = PathBuf::from(canonical_path);
                let Some(object) = view.try_resolve_signed_selector(
                    &path,
                    binding.active_profile_generation_ref_id,
                    selector.kernel_handle(),
                    selector.object_class_id.clone(),
                    selector.device_class_id.clone(),
                    topology_generation,
                )?
                else {
                    continue;
                };
                let expected_components = selector
                    .target
                    .exact_components(artifact.header.profile_id.as_str())
                    .context(PolicySnafu)?
                    .context(IdentityStateSnafu {
                        reason: "exact path selector lost its literal components",
                    })?;
                ensure!(
                    object.canonical_component_hex
                        == expected_components
                            .iter()
                            .map(hex::encode)
                            .collect::<Vec<_>>(),
                    IdentityStateSnafu {
                        reason: format!(
                            "signed path selector `{}` resolved to a different canonical path",
                            selector.path_selector_id
                        ),
                    }
                );
                measured.push(MeasuredExactObjectV1 {
                    binding_id: binding.binding_id.clone(),
                    object,
                });
            }
        }
        Ok(measured)
    }

    #[cfg(feature = "test-support")]
    fn resolve_test_exact_objects<I, S>(
        config: &NodeConfig,
        objects: I,
    ) -> Result<Vec<MeasuredExactObjectV1>>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        let now_utc_ns = current_utc_ns()?;
        let artifact_owner = PolicyArtifactOwner::default();
        let mut artifacts = BTreeMap::new();
        for candidate in &config.policy_candidates {
            let artifact = artifact_owner
                .load_verified_at(
                    &candidate.artifact_path,
                    &candidate.public_key_path,
                    now_utc_ns,
                )
                .context(PolicySnafu)?;
            artifacts.insert(artifact.header.profile_id.clone(), artifact);
        }

        objects
            .into_iter()
            .map(|(binding_id, mut object)| {
                let binding_id = binding_id.into();
                let binding = config
                    .workload_bindings
                    .iter()
                    .find(|binding| binding.binding_id == binding_id)
                    .context(IdentityStateSnafu {
                        reason: format!("test object binding `{binding_id}` is not configured"),
                    })?;
                let artifact = artifacts.get(&binding.profile_id).context(IdentityStateSnafu {
                    reason: format!("test object binding `{binding_id}` has no verified policy"),
                })?;
                let mut selectors = artifact
                    .policy_document
                    .path_selectors
                    .iter()
                    .filter(|selector| {
                        if !selector.requires_exact_object()
                            || selector.object_class_id != object.object_class_id
                            || selector.device_class_id.as_deref()
                                != object
                                    .device
                                    .as_ref()
                                    .map(|device| device.device_class_id.as_str())
                        {
                            return false;
                        }
                        selector
                            .target
                            .exact_components(artifact.header.profile_id.as_str())
                            .is_ok_and(|components| components.is_some_and(|components| {
                            object.canonical_component_hex
                                == components.iter().map(hex::encode).collect::<Vec<_>>()
                            }))
                    });
                let selector = selectors.next().context(IdentityStateSnafu {
                    reason: format!(
                        "test object for binding `{binding_id}` has no signed path selector"
                    ),
                })?;
                ensure!(
                    selectors.next().is_none(),
                    IdentityStateSnafu {
                        reason: format!(
                            "test object for binding `{binding_id}` matches more than one signed path selector"
                        ),
                    }
                );
                object.profile_generation_ref_id = binding.active_profile_generation_ref_id;
                object.exact_object_key_id = selector.kernel_handle();
                Ok(MeasuredExactObjectV1 { binding_id, object })
            })
            .collect()
    }

    fn current_mount_topology_generation(host: &KernelHost) -> Result<u64> {
        let key = 0_u32.to_ne_bytes();
        let Some(bytes) = host
            .lookup_map("mount_global_mutation_epoch", &key)
            .context(InterceptorSnafu)?
        else {
            return Ok(1);
        };
        let epoch = u64::read_from_bytes(&bytes).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("global mount mutation epoch is invalid: {error}"),
            }
            .build()
        })?;
        Ok(epoch.max(1))
    }

    fn dynamic_generation_rows(
        generations: &BTreeMap<u64, LoweredGeneration>,
    ) -> BTreeMap<&'static str, BTreeSet<Vec<u8>>> {
        let mut rows = BTreeMap::<&'static str, BTreeSet<Vec<u8>>>::new();
        for generation in generations.values() {
            for (map, generation_rows) in [
                ("device_effect_decisions", &generation.device_decisions),
                ("exact_file_objects", &generation.file_objects),
                ("mount_security_views", &generation.mount_views),
                ("mount_mutation_epochs", &generation.mount_epochs),
                ("mount_security_view_locks", &generation.mount_locks),
                ("canonical_mount_roots", &generation.mount_roots),
            ] {
                rows.entry(map)
                    .or_default()
                    .extend(generation_rows.keys().cloned());
            }
        }
        rows
    }

    pub(crate) fn resolve_administrative_policy(
        &self,
        host: &KernelHost,
        target: &AdministrativeBindingTargetV1,
        requested_name: &[u8],
        approved_role_id: &str,
    ) -> Result<ResolvedAdministrativePolicyV1> {
        ensure!(
            (1..=4096).contains(&requested_name.len())
                && !requested_name.contains(&0)
                && !approved_role_id.is_empty(),
            IdentityStateSnafu {
                reason: "administrative command and role are not bounded",
            }
        );
        let plans = self
            .administrative_plans
            .iter()
            .filter(|plan| {
                plan.binding_id == target.binding_id
                    && plan.approved_role_id == approved_role_id
                    && plan.profile.profile_id == target.profile_id
                    && plan.profile_generation_ref_id == target.profile_generation_ref_id
            })
            .collect::<Vec<_>>();
        ensure!(
            !plans.is_empty(),
            IdentityStateSnafu {
                reason: "signed profile has no administrative plan for the exact target and role",
            }
        );
        let mount_namespace_inode = plans[0].executable_object.mount_namespace_inode;
        ensure!(
            plans.iter().all(|plan| {
                plan.executable_object.mount_namespace_inode == mount_namespace_inode
            }),
            IdentityStateSnafu {
                reason: "administrative executable plans span unequal mount views",
            }
        );
        let view = self
            .mount_view_handles
            .get(&mount_namespace_inode)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "administrative target has no retained mount view".to_owned(),
                }
                .build()
            })?;
        ensure!(
            view.mount_namespace_inode()? == mount_namespace_inode,
            IdentityStateSnafu {
                reason: "administrative retained mount view changed identity",
            }
        );
        let view_key = mount_namespace_inode.to_ne_bytes();
        let view_state = mount_state(host, "mount_security_views", &view_key)?;
        let global_key = 0_u32.to_ne_bytes();
        let global_epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)?;
        ensure!(
            view_state.state == MountTopologyStateV1::Clean
                && view_state.pending_mutations == 0
                && view_state.topology_generation == global_epoch
                && mount_epoch(host, &view_key)? == global_epoch
                && mount_epoch_from(host, "mount_global_clean_epoch", &global_key)? == global_epoch
                && mount_epoch_from(host, "mount_global_pending_mutations", &global_key)? == 0,
            IdentityStateSnafu {
                reason: "administrative executable mount view is not globally clean",
            }
        );
        let active = host
            .lookup_map("active_profile_generations", target.profile_id.as_bytes())
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "administrative profile has no active generation".to_owned(),
                }
                .build()
            })?;
        ensure!(
            u64::read_from_bytes(&active)
                .is_ok_and(|generation| { generation == target.profile_generation_ref_id }),
            IdentityStateSnafu {
                reason: "administrative target profile generation is not active",
            }
        );
        let requested = PathBuf::from(OsString::from_vec(requested_name.to_vec()));
        let (resolution_mode, candidates) = if requested.is_absolute() {
            (1, vec![requested])
        } else if requested_name.contains(&b'/') {
            (2, vec![target.working_directory.join(requested)])
        } else {
            (
                3,
                target
                    .path_entries
                    .iter()
                    .map(|entry| entry.join(&requested))
                    .collect::<Vec<_>>(),
            )
        };
        let mut selected = None;
        for path in candidates {
            let Some(live) = view.try_inspect(&path)? else {
                continue;
            };
            let is_regular_executable =
                u32::from(live.mode) & 0o170_000 == 0o100_000 && u32::from(live.mode) & 0o111 != 0;
            if !is_regular_executable && resolution_mode == 3 {
                continue;
            }
            ensure!(
                is_regular_executable,
                IdentityStateSnafu {
                    reason: "resolved administrative command is not a regular executable file",
                }
            );
            let matching = plans
                .iter()
                .filter(|plan| live.matches(&plan.executable_object))
                .collect::<Vec<_>>();
            ensure!(
                matching.len() == 1,
                IdentityStateSnafu {
                    reason: "resolved administrative command is absent from or ambiguous in the signed exact plans",
                }
            );
            selected = Some((path, live, matching[0]));
            break;
        }
        let (path, live, plan) = selected.ok_or_else(|| {
            IdentityStateSnafu {
                reason: "administrative command did not resolve in the target container view"
                    .to_owned(),
            }
            .build()
        })?;
        ensure!(
            live.mount_snapshot_digest_id == view_state.snapshot_digest_id,
            IdentityStateSnafu {
                reason: "administrative command resolution used a stale mount snapshot",
            }
        );
        let mount_namespace_id = derived_id(
            b"MITHRIL-MOUNT-NAMESPACE-V1\0",
            &[
                portable_id_bytes(self.node_boot_id),
                self.label_epoch.to_be_bytes().to_vec(),
                mount_namespace_inode.to_be_bytes().to_vec(),
            ],
        )?;
        let filesystem_instance_id = derived_id(
            b"MITHRIL-FILESYSTEM-INSTANCE-V1\0",
            &[
                portable_id_bytes(mount_namespace_id),
                live.filesystem_device.to_be_bytes().to_vec(),
            ],
        )?;
        let exact_live_object_id = derived_id(
            b"MITHRIL-EXACT-LIVE-FILE-V1\0",
            &[
                portable_id_bytes(filesystem_instance_id),
                live.mount_id.to_be_bytes().to_vec(),
                live.inode.to_be_bytes().to_vec(),
                plan.executable_object
                    .inode_generation
                    .to_be_bytes()
                    .to_vec(),
                global_epoch.to_be_bytes().to_vec(),
            ],
        )?;
        let backing_identity = derived_id(
            b"MITHRIL-ADMINISTRATIVE-EXECUTABLE-BACKING-V1\0",
            &[
                portable_id_bytes(plan.profile.profile_id),
                plan.profile_generation_ref_id.to_be_bytes().to_vec(),
                plan.executable_object
                    .exact_object_key_id
                    .to_be_bytes()
                    .to_vec(),
            ],
        )?;
        let live_interval_id = derived_id(
            b"MITHRIL-ADMINISTRATIVE-FILE-INTERVAL-V1\0",
            &[
                portable_id_bytes(target.binding_nonce),
                portable_id_bytes(exact_live_object_id),
                target.container_generation.to_be_bytes().to_vec(),
            ],
        )?;
        let resolved_display_path = path.as_os_str().as_bytes().to_vec();
        let container_working_directory = target.working_directory.as_os_str().as_bytes().to_vec();
        let effective_path_entries = target
            .path_entries
            .iter()
            .map(|entry| entry.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>();
        ensure!(
            (1..=4096).contains(&resolved_display_path.len())
                && resolved_display_path.first() == Some(&b'/')
                && (1..=4096).contains(&container_working_directory.len())
                && container_working_directory.first() == Some(&b'/')
                && effective_path_entries.len() <= 64
                && effective_path_entries.iter().all(|entry| {
                    (1..=4096).contains(&entry.len()) && entry.first() == Some(&b'/')
                }),
            IdentityStateSnafu {
                reason: "administrative resolved path, working directory, or PATH exceeds its signed bounds",
            }
        );
        Ok(ResolvedAdministrativePolicyV1 {
            approved_role_numeric_id: plan.approved_role_numeric_id,
            profile_generation_ref_id: plan.profile_generation_ref_id,
            exception_numeric_handle: plan.exception_numeric_handle,
            profile: plan.profile.clone(),
            resolved_executable: ResolvedAdministrativeExecutableIdentityV1 {
                requested_name: requested_name.to_vec(),
                resolution_mode,
                resolved_display_path,
                container_working_directory,
                effective_path_entries,
                target_mount_namespace_id: mount_namespace_id,
                target_mount_topology_generation: global_epoch,
                executable_object: AdministrativeFileObjectIdentityV1 {
                    mount_namespace_id,
                    mount_topology_generation: global_epoch,
                    mount_id: live.mount_id,
                    filesystem_instance_id,
                    inode: live.inode,
                    inode_generation: plan.executable_object.inode_generation,
                    exact_live_object_id,
                    object_kind: 1,
                    backing_identity,
                    live_interval_id,
                },
            },
            kernel_executable: ExactExecutableCandidateV1 {
                inode: live.inode,
                mount_namespace_inode,
                mount_id: live.mount_id,
                filesystem_device: live.filesystem_device,
                inode_generation: plan.executable_object.inode_generation,
            },
        })
    }

    pub fn reconcile_mount_views(&self, host: &mut KernelHost) -> Result<()> {
        self.exception_authority
            .lock()
            .map_err(|_| {
                IdentityStateSnafu {
                    reason: "exception authority owner lock is poisoned".to_owned(),
                }
                .build()
            })?
            .reconcile(host, current_utc_ns()?)?;
        reconcile_generation_retirement(host, self.node_boot_id, self.label_epoch)?;
        let mut views = BTreeMap::<u32, Vec<&MountRootReconciliation>>::new();
        for root in &self.mount_roots {
            views
                .entry(root.mount_namespace_inode)
                .or_default()
                .push(root);
        }
        if views.is_empty() {
            return Ok(());
        }
        let global_key = 0_u32.to_ne_bytes();
        let global_epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)?;
        let global_clean = mount_epoch_from(host, "mount_global_clean_epoch", &global_key)?;
        let global_pending = mount_epoch_from(host, "mount_global_pending_mutations", &global_key)?;
        if global_pending != 0 {
            return Ok(());
        }
        ensure!(
            global_epoch != 0 && global_clean <= global_epoch,
            IdentityStateSnafu {
                reason: "global mount security barrier is not usable",
            }
        );
        let mut all_views_clean = global_clean == global_epoch;
        if all_views_clean {
            for roots in views.values() {
                if !self.mount_view_is_clean(host, roots, global_epoch)? {
                    all_views_clean = false;
                    break;
                }
            }
        }
        if all_views_clean {
            return Ok(());
        }
        for roots in views.values() {
            if self
                .reconcile_mount_view(host, roots, global_epoch)?
                .is_none()
            {
                return Ok(());
            }
        }
        if mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)? != global_epoch
            || mount_epoch_from(host, "mount_global_pending_mutations", &global_key)? != 0
        {
            return Ok(());
        }
        for roots in views.values() {
            if !self.mount_view_is_clean(host, roots, global_epoch)? {
                return Ok(());
            }
        }
        if global_clean != global_epoch {
            host.update_map(
                "mount_global_clean_epoch",
                &global_key,
                &global_epoch.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?;
            ensure!(
                mount_epoch_from(host, "mount_global_clean_epoch", &global_key)? == global_epoch,
                IdentityStateSnafu {
                    reason: "global mount clean-epoch publication readback failed",
                }
            );
        }
        if mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)? != global_epoch
            || mount_epoch_from(host, "mount_global_pending_mutations", &global_key)? != 0
        {
            return Ok(());
        }
        for roots in views.values() {
            if !self.mount_view_is_clean(host, roots, global_epoch)? {
                return Ok(());
            }
        }
        Ok(())
    }

    fn mount_view_is_clean(
        &self,
        host: &KernelHost,
        roots: &[&MountRootReconciliation],
        target_epoch: u64,
    ) -> Result<bool> {
        let root = roots.first().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "mount reconciliation view has no roots".to_owned(),
            }
            .build()
        })?;
        let key = root.mount_namespace_inode.to_ne_bytes();
        let state = mount_state(host, "mount_security_views", &key)?;
        Ok(state.state == MountTopologyStateV1::Clean
            && state.topology_generation == target_epoch
            && state.snapshot_digest_id != 0
            && state.pending_mutations == 0
            && state.transition_version != 0
            && mount_epoch(host, &key)? == target_epoch)
    }

    fn reconcile_mount_view(
        &self,
        host: &mut KernelHost,
        roots: &[&MountRootReconciliation],
        target_epoch: u64,
    ) -> Result<Option<u64>> {
        let root = roots.first().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "mount reconciliation view has no roots".to_owned(),
            }
            .build()
        })?;
        let key = root.mount_namespace_inode.to_ne_bytes();
        let view = self
            .mount_view_handles
            .get(&root.mount_namespace_inode)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "mount reconciliation view has no retained namespace capability"
                        .to_owned(),
                }
                .build()
            })?;
        let state = mount_state(host, "mount_security_views", &key)?;
        let epoch = mount_epoch(host, &key)?;
        if state.state == MountTopologyStateV1::Clean
            && state.topology_generation == target_epoch
            && epoch == target_epoch
            && state.pending_mutations == 0
            && state.snapshot_digest_id != 0
            && state.transition_version != 0
        {
            return Ok(Some(state.snapshot_digest_id));
        }
        if state.pending_mutations != 0 {
            return Ok(None);
        }
        ensure!(
            matches!(
                state.state,
                MountTopologyStateV1::Clean | MountTopologyStateV1::Dirty
            ),
            IdentityStateSnafu {
                reason: "mount security view is not reconcilable",
            }
        );
        if epoch != target_epoch {
            host.update_map("mount_mutation_epochs", &key, &target_epoch.to_ne_bytes())
                .context(InterceptorSnafu)?;
            ensure!(
                mount_epoch(host, &key)? == target_epoch,
                IdentityStateSnafu {
                    reason: "mount mutation epoch synchronization failed",
                }
            );
        }
        let mut snapshot_digest_id = None;
        for planned in roots {
            let configured = &planned.configured;
            let resolved = view.resolve(
                &planned.canonical_path,
                configured.profile_generation_ref_id,
                configured.exact_object_key_id,
                configured.object_class_id.clone(),
                configured.inode_generation,
                configured
                    .device
                    .as_ref()
                    .map(|device| device.device_class_id.clone()),
            )?;
            ensure!(
                same_exact_file(configured, &resolved)
                    && resolved.canonical_component_hex == configured.canonical_component_hex
                    && resolved.mount_relative_component_count
                        == configured.mount_relative_component_count,
                IdentityStateSnafu {
                    reason: "mount reconciliation changed the exact object, actor view, or canonical policy path",
                }
            );
            if let Some(digest) = snapshot_digest_id {
                ensure!(
                    digest == resolved.mount_snapshot_digest_id,
                    IdentityStateSnafu {
                        reason: "one mount security view produced unequal topology snapshots",
                    }
                );
            } else {
                snapshot_digest_id = Some(resolved.mount_snapshot_digest_id);
            }
            let root_key = CanonicalMountRootKeyV1 {
                profile_generation_ref_id: configured.profile_generation_ref_id,
                mount_namespace_inode: configured.mount_namespace_inode,
                binding_id: planned.binding_id,
                topology_generation: target_epoch,
                filesystem_device: resolved.mount_root_filesystem_device,
                root_inode: resolved.mount_root_inode,
            };
            let value = CanonicalMountRootV1 {
                selected_mount_id_unique: resolved.selected_mount_id_unique,
                snapshot_digest_id: resolved.mount_snapshot_digest_id,
                graph_prefix_state_id: planned.graph_prefix_state_id,
                reserved: 0,
            };
            host.update_map(
                "canonical_mount_roots",
                root_key.as_bytes(),
                value.as_bytes(),
            )
            .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("canonical_mount_roots", root_key.as_bytes())
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(value.as_bytes()),
                IdentityStateSnafu {
                    reason: "canonical mount-root reconciliation readback failed",
                }
            );
        }
        let current = mount_state(host, "mount_security_views", &key)?;
        if mount_epoch(host, &key)? != target_epoch
            || current.pending_mutations != 0
            || current.transition_version != state.transition_version
        {
            return Ok(None);
        }
        let snapshot_digest_id = snapshot_digest_id.ok_or_else(|| {
            IdentityStateSnafu {
                reason: "mount reconciliation produced no snapshot".to_owned(),
            }
            .build()
        })?;
        let proposal = MountReconciliationProposalV1 {
            topology_generation: target_epoch,
            snapshot_digest_id,
            expected_transition_version: state.transition_version,
            transition_version: state.transition_version.checked_add(1).ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "mount transition version exhausted".to_owned(),
                }
                .build()
            })?,
        };
        host.update_map("mount_reconciliation_proposals", &key, proposal.as_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("mount_reconciliation_proposals", &key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(proposal.as_bytes()),
            IdentityStateSnafu {
                reason: "mount reconciliation proposal readback failed",
            }
        );
        if !host
            .apply_mount_reconciliation_proposal(root.mount_namespace_inode)
            .context(InterceptorSnafu)?
        {
            return Ok(None);
        }
        let committed = mount_state(host, "mount_security_views", &key)?;
        if mount_epoch(host, &key)? != target_epoch
            || committed.state != MountTopologyStateV1::Clean
            || committed.topology_generation != proposal.topology_generation
            || committed.snapshot_digest_id != proposal.snapshot_digest_id
            || committed.pending_mutations != 0
            || committed.transition_version != proposal.transition_version
        {
            return Ok(None);
        }
        Ok(Some(snapshot_digest_id))
    }
}

#[derive(Clone)]
struct MountRootReconciliation {
    mount_namespace_inode: u32,
    binding_id: Id128V1,
    configured: ExactFileObjectConfig,
    canonical_path: PathBuf,
    graph_prefix_state_id: u32,
}

struct MountViewSnapshot {
    topology_generation: u64,
    snapshot_digest_id: u64,
    pending_mutations: u64,
    transition_version: u64,
    state: MountTopologyStateV1,
}

fn install_global_mount_barrier(
    host: &KernelHost,
    roots: &[MountRootReconciliation],
) -> Result<()> {
    let key = 0_u32.to_ne_bytes();
    let zero = 0_u64.to_ne_bytes();
    let topology_generation = roots
        .iter()
        .map(|root| root.configured.mount_topology_generation)
        .max()
        .unwrap_or(1)
        .max(1);
    if host
        .lookup_map("mount_global_mutation_epoch", &key)
        .context(InterceptorSnafu)?
        .is_none()
    {
        host.update_map(
            "mount_global_mutation_epoch",
            &key,
            &topology_generation.to_ne_bytes(),
        )
        .context(InterceptorSnafu)?;
    }
    for map in ["mount_global_clean_epoch", "mount_global_pending_mutations"] {
        if host
            .lookup_map(map, &key)
            .context(InterceptorSnafu)?
            .is_none()
        {
            host.update_map(map, &key, &zero)
                .context(InterceptorSnafu)?;
        }
    }
    if host
        .lookup_map("mount_global_ambiguous_epoch", &key)
        .context(InterceptorSnafu)?
        .is_none()
    {
        host.update_map("mount_global_ambiguous_epoch", &key, &1_u64.to_ne_bytes())
            .context(InterceptorSnafu)?;
    }
    let epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &key)?;
    let clean = mount_epoch_from(host, "mount_global_clean_epoch", &key)?;
    let pending = mount_epoch_from(host, "mount_global_pending_mutations", &key)?;
    ensure!(
        epoch != 0
            && clean <= epoch
            && pending == 0
            && mount_epoch_from(host, "mount_global_ambiguous_epoch", &key)? != 0,
        IdentityStateSnafu {
            reason: "global mount security barrier readback is invalid",
        }
    );
    Ok(())
}

fn same_exact_file(left: &ExactFileObjectConfig, right: &ExactFileObjectConfig) -> bool {
    left.mount_namespace_inode == right.mount_namespace_inode
        && left.mount_id_unique == right.mount_id_unique
        && left.filesystem_device == right.filesystem_device
        && left.inode == right.inode
        && left.inode_generation == right.inode_generation
}

fn validate_mount_view(
    view: &crate::exact_object::ExactFileObjectView,
    planned: &MountRootReconciliation,
    retained: bool,
) -> Result<()> {
    let configured = &planned.configured;
    let resolved = view.resolve(
        &planned.canonical_path,
        configured.profile_generation_ref_id,
        configured.exact_object_key_id,
        configured.object_class_id.clone(),
        configured.inode_generation,
        configured
            .device
            .as_ref()
            .map(|device| device.device_class_id.clone()),
    )?;
    ensure!(
        same_exact_file(configured, &resolved)
            && resolved.canonical_component_hex == configured.canonical_component_hex
            && resolved.mount_relative_component_count == configured.mount_relative_component_count
            && (retained
                || resolved.mount_snapshot_digest_id == configured.mount_snapshot_digest_id),
        IdentityStateSnafu {
            reason: "retained mount view differs from its exact configured authority",
        }
    );
    Ok(())
}

struct LoweredGeneration {
    descriptor: ProfileGenerationDescriptorV1,
    decisions: BTreeMap<Vec<u8>, Vec<u8>>,
    defaults: BTreeMap<Vec<u8>, Vec<u8>>,
    device_decisions: BTreeMap<Vec<u8>, Vec<u8>>,
    process_control_rules: BTreeMap<Vec<u8>, Vec<u8>>,
    ipc_relationships: BTreeMap<Vec<u8>, Vec<u8>>,
    network_ipv4_classes: BTreeMap<Vec<u8>, Vec<u8>>,
    network_ipv6_classes: BTreeMap<Vec<u8>, Vec<u8>>,
    network_decisions: BTreeMap<Vec<u8>, Vec<u8>>,
    exceptions: BTreeMap<Vec<u8>, Vec<u8>>,
    exception_deadlines_utc: BTreeMap<Vec<u8>, i64>,
    exception_bindings: BTreeMap<Vec<u8>, Vec<u8>>,
    file_objects: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_views: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_epochs: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_locks: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_roots: BTreeMap<Vec<u8>, Vec<u8>>,
    path_exact: BTreeMap<Vec<u8>, Vec<u8>>,
    path_wildcards: BTreeMap<Vec<u8>, Vec<u8>>,
    path_terminals: BTreeMap<Vec<u8>, Vec<u8>>,
    administrative_required: bool,
    administrative_plans: Vec<AdministrativePolicyPlanV1>,
    mount_reconciliation: Vec<MountRootReconciliation>,
}

impl LoweredGeneration {
    #[allow(clippy::too_many_arguments)]
    fn for_binding(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        measured_objects: &[ExactFileObjectConfig],
        node_boot_id: Id128V1,
        node_id: Id128V1,
        label_epoch: u64,
        now_utc_ns: i64,
        now_boottime_ns: u64,
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
        let role_states = artifact
            .policy_document
            .roles
            .iter()
            .map(|role| {
                Ok((
                    role.role_id.clone(),
                    (
                        role_handles[&role.role_id],
                        *process_state_handles
                            .get(&role.default_process_state_id)
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
        let composite_handles = Self::composite_handles(artifact);
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
        let generation_objects = measured_objects
            .iter()
            .filter(|object| {
                object.profile_generation_ref_id == binding.active_profile_generation_ref_id
            })
            .collect::<Vec<_>>();
        let mut exact_object_handles = BTreeMap::new();
        for selector in artifact
            .policy_document
            .path_selectors
            .iter()
            .filter(|selector| selector.requires_exact_object())
        {
            let composite_atom_id = *composite_handles
                .get(&format!("PATH:{}", selector.path_selector_id))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "path selector `{}` has an unknown signed object class",
                            selector.path_selector_id
                        ),
                    }
                    .build()
                })?;
            ensure!(
                exact_object_handles
                    .insert(
                        selector.path_selector_id.clone(),
                        (selector.kernel_handle(), composite_atom_id),
                    )
                    .is_none(),
                IdentityStateSnafu {
                    reason: "signed path selector IDs are not unique",
                }
            );
        }
        for object in &generation_objects {
            let selector = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| {
                    selector.requires_exact_object()
                        && selector.kernel_handle() == object.exact_object_key_id
                })
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "measured object handle {} has no signed path selector",
                            object.exact_object_key_id
                        ),
                    }
                    .build()
                })?;
            let (handle, composite_atom_id) = exact_object_handles[&selector.path_selector_id];
            let signed_components = selector
                .target
                .exact_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?
                .context(IdentityStateSnafu {
                    reason: "measured exact object selector has no literal path",
                })?;
            ensure!(
                handle == object.exact_object_key_id
                    && selector.object_class_id == object.object_class_id
                    && selector.device_class_id.is_some() == object.device.is_some()
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
                    selector.device_class_id.as_deref() == Some(device.device_class_id.as_str())
                        && artifact
                            .policy_document
                            .classifier_bindings
                            .iter()
                            .any(|binding| {
                                binding.object_class_id == selector.object_class_id
                                    && matches!(&binding.selector,
                                    ObjectClassifierSelectorV1::Device { device_class_ids }
                                        if device_class_ids.contains(&device.device_class_id))
                            }),
                    IdentityStateSnafu {
                        reason: format!(
                            "device class `{}` is not signed for object class `{}`",
                            device.device_class_id, object.object_class_id
                        ),
                    }
                );
            }
            ensure!(
                composite_atom_id > 0,
                IdentityStateSnafu {
                    reason: "signed path selector has no composite object class",
                }
            );
        }
        validate_binding_roles(artifact, binding, &role_handles, &process_state_handles)?;
        let mut decisions = BTreeMap::new();
        let mut defaults = BTreeMap::new();
        let mut device_decisions = BTreeMap::new();
        let mut process_control_rules = BTreeMap::new();
        let mut network = LoweredNetworkPolicy::lower(
            &artifact.policy_document,
            binding.active_profile_generation_ref_id,
        )?;
        for cell in &artifact.compiled_profile.compiled_cells {
            if !cell_matches_binding(&cell.key, binding, &artifact.policy_document) {
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
            let family = KernelEffectFamilyV1::from(cell.key.effect_family) as u16;
            let operation = CompiledOperationV1::try_from(cell.key.operation_id.as_str())
                .map_err(|_| {
                    IdentityStateSnafu {
                        reason: format!("unsupported kernel operation `{}`", cell.key.operation_id),
                    }
                    .build()
                })?
                .kernel_id as u16;
            let exception_numeric_handle = cell
                .consuming_exception_id
                .as_ref()
                .map(|exception_id| {
                    exception_handles.get(exception_id).copied().ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: format!("compiled cell has unknown exception `{exception_id}`"),
                        }
                        .build()
                    })
                })
                .transpose()?
                .unwrap_or_default();
            let physical =
                physical_decision(cell.physical_result, cell.errno, exception_numeric_handle);
            if let Some(destination_id) = cell.key.object_selector.strip_prefix("DESTINATION:") {
                ensure!(
                    cell.key.effect_family == mithril_control::EffectFamilyV1::Network,
                    IdentityStateSnafu {
                        reason: "a destination selector lowered outside NETWORK".to_owned(),
                    }
                );
                let destination = artifact
                    .policy_document
                    .network_policy
                    .iter()
                    .flat_map(|policy| &policy.destination_policies)
                    .find(|policy| policy.destination_policy_id == destination_id)
                    .ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: format!(
                                "compiled cell has unknown destination `{destination_id}`"
                            ),
                        }
                        .build()
                    })?;
                let destination_policy_handle =
                    network.destination_handle(destination_id).ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: format!(
                                "compiled cell has no handle for destination `{destination_id}`"
                            ),
                        }
                        .build()
                    })?;
                network.insert_decisions(
                    NetworkDestinationDecisionKeyV1 {
                        profile_generation_ref_id: binding.active_profile_generation_ref_id,
                        destination_policy_handle,
                        active_role_id: role,
                        process_state_vector_id: process_state,
                        entry_kind: entry_kind(cell.key.entry_kind),
                        operation,
                        protocol: Default::default(),
                        binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                        reserved: [0; 2],
                    },
                    &destination.protocols,
                    physical,
                )?;
                continue;
            }
            if lower_typed_effect(
                cell,
                &TypedEffectContext {
                    profile_generation_ref_id: binding.active_profile_generation_ref_id,
                    actor_role_id: role,
                    actor_process_state_vector_id: process_state,
                    entry_kind: entry_kind(cell.key.entry_kind),
                    binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                    exact_objects: &generation_objects,
                    signed_device_classes: &signed_device_classes,
                    role_states: &role_states,
                },
                physical,
                &mut device_decisions,
                &mut process_control_rules,
            )? {
                continue;
            }
            if let Some(path_selector_id) = cell.key.object_selector.strip_prefix("PATH:") {
                let selector = artifact
                    .policy_document
                    .path_selectors
                    .iter()
                    .find(|selector| selector.path_selector_id == path_selector_id)
                    .context(IdentityStateSnafu {
                        reason: format!(
                            "compiled cell has unknown path selector `{path_selector_id}`"
                        ),
                    })?;
                match &selector.target {
                    PathSelectorTargetV1::Path { .. } => {
                        let key = EffectDefaultKeyV1 {
                            profile_generation_ref_id: binding.active_profile_generation_ref_id,
                            active_role_id: role,
                            entry_kind: entry_kind(cell.key.entry_kind),
                            effect_family: family,
                            operation,
                            reserved: 0,
                            reserved_alignment: [0; 4],
                            composite_atom_id: composite_handles[&cell.key.object_selector],
                            process_state_vector_id: process_state,
                            binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                            reserved_tail: [0; 3],
                        };
                        insert_exact(&mut defaults, key.as_bytes(), physical.as_bytes())?;
                    }
                    PathSelectorTargetV1::Exact { .. } => {
                        let (exact_object_key_id, composite_atom_id) = exact_object_handles
                            .get(path_selector_id)
                            .copied()
                            .context(IdentityStateSnafu {
                                reason: format!(
                                    "exact selector `{path_selector_id}` has no object handle"
                                ),
                            })?;
                        let key = EffectDecisionKeyV1 {
                            profile_generation_ref_id: binding.active_profile_generation_ref_id,
                            active_role_id: role,
                            entry_kind: entry_kind(cell.key.entry_kind),
                            effect_family: family,
                            operation,
                            reserved: 0,
                            reserved_alignment: [0; 4],
                            composite_atom_id,
                            exact_object_key_id,
                            process_state_vector_id: process_state,
                            binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                            reserved_tail: [0; 3],
                        };
                        insert_exact(&mut decisions, key.as_bytes(), physical.as_bytes())?;
                    }
                }
            } else {
                let key = EffectDefaultKeyV1 {
                    profile_generation_ref_id: binding.active_profile_generation_ref_id,
                    active_role_id: role,
                    entry_kind: entry_kind(cell.key.entry_kind),
                    effect_family: family,
                    operation,
                    reserved: 0,
                    reserved_alignment: [0; 4],
                    composite_atom_id: if cell.key.object_selector == "DEFAULT" {
                        0
                    } else {
                        *composite_handles
                            .get(&cell.key.object_selector)
                            .ok_or_else(|| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "compiled cell has unknown object selector `{}`",
                                        cell.key.object_selector
                                    ),
                                }
                                .build()
                            })?
                    },
                    process_state_vector_id: process_state,
                    binding_lifecycle_state: lifecycle(cell.key.binding_lifecycle),
                    reserved_tail: [0; 3],
                };
                insert_exact(&mut defaults, key.as_bytes(), physical.as_bytes())?;
            }
        }
        ensure!(
            !decisions.is_empty()
                || !defaults.is_empty()
                || !device_decisions.is_empty()
                || !process_control_rules.is_empty()
                || !network.decisions.is_empty(),
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` selected no exact candidate cells",
                    binding.binding_id
                ),
            }
        );
        let ipc_relationships = lower_ipc_relationships(
            &artifact.policy_document,
            binding.active_profile_generation_ref_id,
            &role_handles,
            artifact.compiled_profile.mode,
        )?;
        let mut exceptions = BTreeMap::new();
        let mut exception_deadlines_utc = BTreeMap::new();
        let mut exception_bindings = BTreeMap::new();
        for exception in &artifact.policy_document.exceptions {
            let handle = exception_handles[&exception.exception_id];
            if !artifact.compiled_profile.compiled_cells.iter().any(|cell| {
                cell_matches_binding(&cell.key, binding, &artifact.policy_document)
                    && cell.consuming_exception_id.as_deref()
                        == Some(exception.exception_id.as_str())
            }) {
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
            let remaining_ns =
                u64::try_from(exception.valid_until_utc_ns - now_utc_ns).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("exception UTC lifetime overflow: {error}"),
                    }
                    .build()
                })?;
            let deadline_boottime_ns = now_boottime_ns
                .checked_add(remaining_ns.min(exception.maximum_lifetime_ns))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "exception monotonic deadline overflow".to_owned(),
                    }
                    .build()
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
                lock: 0,
                maximum_uses: exception.maximum_uses,
                consumed_uses: 0,
                bound_profile_generation_refs: 1,
                deadline_boottime_ns,
                transition_version: 1,
                exception_definition_sha256,
                state: ExceptionRuntimeStateKindV1::Active,
                reserved: [0; 7],
            };
            insert_exact(
                &mut exceptions,
                runtime_state_key.as_bytes(),
                value.as_bytes(),
            )?;
            let deadline_utc_ns = now_utc_ns
                .checked_add(
                    i64::try_from(remaining_ns.min(exception.maximum_lifetime_ns)).map_err(
                        |error| {
                            IdentityStateSnafu {
                                reason: format!("exception UTC deadline overflow: {error}"),
                            }
                            .build()
                        },
                    )?,
                )
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "exception UTC deadline overflow".to_owned(),
                    }
                    .build()
                })?;
            if let Some(existing) = exception_deadlines_utc
                .insert(runtime_state_key.as_bytes().to_vec(), deadline_utc_ns)
            {
                ensure!(
                    existing == deadline_utc_ns,
                    IdentityStateSnafu {
                        reason: "one exception instance has unequal activation deadlines",
                    }
                );
            }
            let binding_key = ExceptionHandleBindingKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                exception_numeric_handle: handle,
                reserved: 0,
            };
            let binding_value = ExceptionHandleBindingV1 {
                runtime_state_key,
                state: ExceptionBindingStateV1::Active,
                reserved: [0; 7],
            };
            insert_exact(
                &mut exception_bindings,
                binding_key.as_bytes(),
                binding_value.as_bytes(),
            )?;
        }
        let mut file_objects = BTreeMap::new();
        for object in &generation_objects {
            let key = ExactFileObjectKeyV1 {
                profile_generation_ref_id: object.profile_generation_ref_id,
                mount_namespace_inode: object.mount_namespace_inode,
                mount_id_unique: object.selected_mount_id_unique,
                filesystem_device: object.filesystem_device,
                inode: object.inode,
                inode_generation: object.inode_generation,
                reserved: 0,
            };
            let value = ExactObjectBindingV1 {
                profile_generation_ref_id: object.profile_generation_ref_id,
                exact_object_key_id: object.exact_object_key_id,
                composite_atom_id: exact_object_handles
                    .values()
                    .find_map(|(handle, atom)| {
                        (*handle == object.exact_object_key_id).then_some(*atom)
                    })
                    .ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "measured object lost its signed selector class".to_owned(),
                        }
                        .build()
                    })?,
                state: ExactObjectBindingStateV1::ReadBack,
                reserved: [0; 7],
            };
            insert_exact(&mut file_objects, key.as_bytes(), value.as_bytes())?;
        }
        let (administrative_required, administrative_plans) = lower_administrative_plans(
            artifact,
            binding,
            &role_handles,
            &process_state_handles,
            &exception_handles,
            &generation_objects,
        )?;
        let path_tables =
            Self::lower_path_tables(artifact, binding, &generation_objects, &composite_handles)?;
        let tables = [
            ("decision", &decisions),
            ("default", &defaults),
            ("process-control-rule", &process_control_rules),
            ("ipc-relationship", &ipc_relationships),
            ("network-ipv4-class", &network.ipv4_classes),
            ("network-ipv6-class", &network.ipv6_classes),
            ("network-decision", &network.decisions),
            ("path-exact", &path_tables.exact),
            ("path-wildcard", &path_tables.wildcards),
            ("path-terminal", &path_tables.terminals),
        ];
        let table_digest = table_digest(&tables);
        let descriptor = ProfileGenerationDescriptorV1 {
            node_boot_id,
            profile_id,
            label_epoch,
            profile_generation_ref_id: binding.active_profile_generation_ref_id,
            owner_generation: artifact.header.profile_version,
            row_count: decisions
                .len()
                .checked_add(process_control_rules.len())
                .and_then(|count| count.checked_add(ipc_relationships.len()))
                .and_then(|count| count.checked_add(network.ipv4_classes.len()))
                .and_then(|count| count.checked_add(network.ipv6_classes.len()))
                .and_then(|count| count.checked_add(network.decisions.len()))
                .and_then(|count| count.try_into().ok())
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "decision row count overflow".to_owned(),
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
            mode: match artifact.compiled_profile.mode {
                ProfileModeV1::Observe => PolicyGenerationModeV1::Observe,
                ProfileModeV1::Protect => PolicyGenerationModeV1::Protect,
            },
            reserved: [0; 6],
            table_digest,
            transition_version: 1,
        };
        Ok(Self {
            descriptor,
            decisions,
            defaults,
            device_decisions,
            process_control_rules,
            ipc_relationships,
            network_ipv4_classes: network.ipv4_classes,
            network_ipv6_classes: network.ipv6_classes,
            network_decisions: network.decisions,
            exceptions,
            exception_deadlines_utc,
            exception_bindings,
            file_objects,
            mount_views: path_tables.mount_views,
            mount_epochs: path_tables.mount_epochs,
            mount_locks: path_tables.mount_locks,
            mount_roots: path_tables.mount_roots,
            path_exact: path_tables.exact,
            path_wildcards: path_tables.wildcards,
            path_terminals: path_tables.terminals,
            administrative_required,
            administrative_plans,
            mount_reconciliation: path_tables.reconciliation,
        })
    }

    fn merge(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.descriptor.node_boot_id == other.descriptor.node_boot_id
                && self.descriptor.profile_id == other.descriptor.profile_id
                && self.descriptor.label_epoch == other.descriptor.label_epoch
                && self.descriptor.owner_generation == other.descriptor.owner_generation
                && self.descriptor.mode == other.descriptor.mode,
            IdentityStateSnafu {
                reason: "one generation handle cannot name different candidate artifacts",
            }
        );
        merge_rows(&mut self.decisions, other.decisions)?;
        merge_rows(&mut self.defaults, other.defaults)?;
        merge_rows(&mut self.device_decisions, other.device_decisions)?;
        merge_rows(&mut self.process_control_rules, other.process_control_rules)?;
        merge_rows(&mut self.ipc_relationships, other.ipc_relationships)?;
        merge_rows(&mut self.network_ipv4_classes, other.network_ipv4_classes)?;
        merge_rows(&mut self.network_ipv6_classes, other.network_ipv6_classes)?;
        merge_rows(&mut self.network_decisions, other.network_decisions)?;
        merge_rows(&mut self.exceptions, other.exceptions)?;
        for (key, deadline) in other.exception_deadlines_utc {
            if let Some(existing) = self.exception_deadlines_utc.insert(key, deadline) {
                ensure!(
                    existing == deadline,
                    IdentityStateSnafu {
                        reason: "one exception instance has unequal activation deadlines",
                    }
                );
            }
        }
        merge_rows(&mut self.exception_bindings, other.exception_bindings)?;
        merge_rows(&mut self.file_objects, other.file_objects)?;
        merge_rows(&mut self.mount_views, other.mount_views)?;
        merge_rows(&mut self.mount_epochs, other.mount_epochs)?;
        merge_rows(&mut self.mount_locks, other.mount_locks)?;
        merge_rows(&mut self.mount_roots, other.mount_roots)?;
        merge_rows(&mut self.path_exact, other.path_exact)?;
        merge_rows(&mut self.path_wildcards, other.path_wildcards)?;
        merge_rows(&mut self.path_terminals, other.path_terminals)?;
        self.administrative_required |= other.administrative_required;
        self.administrative_plans.extend(other.administrative_plans);
        self.mount_reconciliation.extend(other.mount_reconciliation);
        self.descriptor.row_count = self
            .decisions
            .len()
            .checked_add(self.process_control_rules.len())
            .and_then(|count| count.checked_add(self.ipc_relationships.len()))
            .and_then(|count| count.checked_add(self.network_ipv4_classes.len()))
            .and_then(|count| count.checked_add(self.network_ipv6_classes.len()))
            .and_then(|count| count.checked_add(self.network_decisions.len()))
            .and_then(|count| count.try_into().ok())
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "merged decision row count overflow".to_owned(),
                }
                .build()
            })?;
        self.descriptor.default_count = self.defaults.len() as u32;
        self.descriptor.table_digest = table_digest(&[
            ("decision", &self.decisions),
            ("default", &self.defaults),
            ("process-control-rule", &self.process_control_rules),
            ("ipc-relationship", &self.ipc_relationships),
            ("network-ipv4-class", &self.network_ipv4_classes),
            ("network-ipv6-class", &self.network_ipv6_classes),
            ("network-decision", &self.network_decisions),
            ("path-exact", &self.path_exact),
            ("path-wildcard", &self.path_wildcards),
            ("path-terminal", &self.path_terminals),
        ]);
        Ok(())
    }

    fn planned_rows(&self) -> Vec<PlannedGenerationRow<'_>> {
        vec![
            ("effect_decisions", &self.decisions),
            ("effect_defaults", &self.defaults),
            ("device_effect_decisions", &self.device_decisions),
            ("process_control_rules", &self.process_control_rules),
            ("ipc_relationship_decisions", &self.ipc_relationships),
            (
                "network_ipv4_destination_classes",
                &self.network_ipv4_classes,
            ),
            (
                "network_ipv6_destination_classes",
                &self.network_ipv6_classes,
            ),
            ("network_destination_decisions", &self.network_decisions),
            ("exception_runtime_states", &self.exceptions),
            ("exception_handle_bindings", &self.exception_bindings),
            ("exact_file_objects", &self.file_objects),
            ("mount_security_views", &self.mount_views),
            ("mount_mutation_epochs", &self.mount_epochs),
            ("mount_security_view_locks", &self.mount_locks),
            ("canonical_mount_roots", &self.mount_roots),
            ("path_graph_exact_transitions", &self.path_exact),
            ("path_graph_wildcard_transitions", &self.path_wildcards),
            ("path_graph_terminals", &self.path_terminals),
        ]
    }

    fn decision_rows(&self) -> Vec<ActivationDecisionRow<'_>> {
        vec![
            (
                PolicyActivationProbeMapKindV1::EffectDecision,
                &self.decisions,
            ),
            (
                PolicyActivationProbeMapKindV1::EffectDefault,
                &self.defaults,
            ),
            (
                PolicyActivationProbeMapKindV1::IpcRelationship,
                &self.ipc_relationships,
            ),
            (
                PolicyActivationProbeMapKindV1::DeviceEffect,
                &self.device_decisions,
            ),
            (
                PolicyActivationProbeMapKindV1::ProcessControl,
                &self.process_control_rules,
            ),
            (
                PolicyActivationProbeMapKindV1::NetworkDestination,
                &self.network_decisions,
            ),
        ]
    }

    fn probe_staged_rows(&self, host: &mut KernelHost) -> Result<()> {
        for (map_kind, rows) in self.decision_rows() {
            for (key, value) in rows {
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

    fn install(
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
        if let Some(existing) = existing.as_deref() {
            let preparing = self.descriptor.as_bytes();
            let read_back = self.read_back_descriptor();
            let active = self.active_descriptor();
            ensure!(
                existing == preparing
                    || existing == read_back.as_bytes()
                    || existing == active.as_bytes(),
                IdentityStateSnafu {
                    reason: "generation handle already belongs to different content",
                }
            );
            if existing == active.as_bytes() {
                self.verify_immutable_rows(host)?;
                install_rows(host, "device_effect_decisions", &self.device_decisions)?;
                install_exception_rows(
                    host,
                    &self.exceptions,
                    &self.exception_deadlines_utc,
                    exception_authority,
                    now_utc_ns,
                    now_boottime_ns,
                )?;
                install_rows(host, "exception_handle_bindings", &self.exception_bindings)?;
                install_rows(host, "exact_file_objects", &self.file_objects)?;
                self.install_missing_mount_rows(host)?;
                self.verify_dynamic_authority_rows(host)?;
                return Ok(());
            }
        }
        if existing.is_none() {
            host.update_map(
                "profile_generation_descriptors",
                &descriptor_key,
                self.descriptor.as_bytes(),
            )
            .context(InterceptorSnafu)?;
        }
        install_rows(host, "effect_decisions", &self.decisions)?;
        install_rows(host, "effect_defaults", &self.defaults)?;
        install_rows(host, "device_effect_decisions", &self.device_decisions)?;
        install_rows(host, "process_control_rules", &self.process_control_rules)?;
        install_rows(host, "ipc_relationship_decisions", &self.ipc_relationships)?;
        install_rows(
            host,
            "network_ipv4_destination_classes",
            &self.network_ipv4_classes,
        )?;
        install_rows(
            host,
            "network_ipv6_destination_classes",
            &self.network_ipv6_classes,
        )?;
        install_rows(
            host,
            "network_destination_decisions",
            &self.network_decisions,
        )?;
        install_exception_rows(
            host,
            &self.exceptions,
            &self.exception_deadlines_utc,
            exception_authority,
            now_utc_ns,
            now_boottime_ns,
        )?;
        install_rows(host, "exception_handle_bindings", &self.exception_bindings)?;
        install_rows(host, "exact_file_objects", &self.file_objects)?;
        self.install_missing_mount_rows(host)?;
        install_rows(host, "path_graph_exact_transitions", &self.path_exact)?;
        install_rows(
            host,
            "path_graph_wildcard_transitions",
            &self.path_wildcards,
        )?;
        install_rows(host, "path_graph_terminals", &self.path_terminals)?;
        self.verify_immutable_rows(host)?;
        self.verify_dynamic_authority_rows(host)?;
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
        let active = self.active_descriptor();
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

    fn active_descriptor(&self) -> ProfileGenerationDescriptorV1 {
        let mut active = self.descriptor;
        active.state = PolicyGenerationStateV1::Active;
        active.transition_version = 3;
        active
    }

    fn read_back_descriptor(&self) -> ProfileGenerationDescriptorV1 {
        let mut read_back = self.descriptor;
        read_back.state = PolicyGenerationStateV1::ReadBack;
        read_back.transition_version = 2;
        read_back
    }

    fn verify_immutable_rows(&self, host: &KernelHost) -> Result<()> {
        for (map, rows) in [
            ("effect_decisions", &self.decisions),
            ("effect_defaults", &self.defaults),
            ("process_control_rules", &self.process_control_rules),
            ("ipc_relationship_decisions", &self.ipc_relationships),
            (
                "network_ipv4_destination_classes",
                &self.network_ipv4_classes,
            ),
            (
                "network_ipv6_destination_classes",
                &self.network_ipv6_classes,
            ),
            ("network_destination_decisions", &self.network_decisions),
            ("path_graph_exact_transitions", &self.path_exact),
            ("path_graph_wildcard_transitions", &self.path_wildcards),
            ("path_graph_terminals", &self.path_terminals),
        ] {
            verify_rows(host, map, rows)?;
        }
        Ok(())
    }

    fn verify_dynamic_authority_rows(&self, host: &KernelHost) -> Result<()> {
        for (map, rows) in [
            ("device_effect_decisions", &self.device_decisions),
            ("exact_file_objects", &self.file_objects),
            ("canonical_mount_roots", &self.mount_roots),
        ] {
            verify_rows(host, map, rows)?;
        }
        Ok(())
    }

    fn install_missing_mount_rows(&self, host: &KernelHost) -> Result<()> {
        for (map, rows) in [
            ("mount_security_views", &self.mount_views),
            ("mount_mutation_epochs", &self.mount_epochs),
            ("mount_security_view_locks", &self.mount_locks),
            ("canonical_mount_roots", &self.mount_roots),
        ] {
            install_missing_rows(host, map, rows)?;
        }
        Ok(())
    }
}

fn preflight_policy_map_capacity(
    host: &KernelHost,
    generations: &BTreeMap<u64, LoweredGeneration>,
    activations: &BTreeMap<Id128V1, ProfileActivation>,
) -> Result<()> {
    let mut planned = BTreeMap::<&'static str, BTreeSet<Vec<u8>>>::new();
    for map in [
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
    for (handle, generation) in generations {
        planned
            .entry("profile_generation_descriptors")
            .or_default()
            .insert(handle.to_ne_bytes().to_vec());
        planned
            .entry("profile_generation_task_refs")
            .or_default()
            .insert(handle.to_ne_bytes().to_vec());
        planned
            .entry("profile_generation_socket_refs")
            .or_default()
            .insert(handle.to_ne_bytes().to_vec());
        for (map, rows) in generation.planned_rows() {
            planned.entry(map).or_default().extend(rows.keys().cloned());
        }
        planned
            .entry("mount_reconciliation_proposals")
            .or_default()
            .extend(generation.mount_views.keys().cloned());
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

fn ensure_map_capacity(
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

fn reconcile_pending_activations(
    host: &KernelHost,
    rollback: &mut AntiRollbackStore,
    node_boot_id: Id128V1,
    label_epoch: u64,
) -> Result<()> {
    let node_boot_id = id_bytes(node_boot_id);
    for pending in rollback.pending_activations() {
        if pending.activation.node_boot_id != node_boot_id
            || pending.activation.label_epoch != label_epoch
        {
            rollback
                .clear_old_epoch_pending(&pending)
                .context(PolicySnafu)?;
            continue;
        }
        let profile_id = parse_id("pending profile_id", &pending.profile_id)?;
        let observed = read_active_generation(host, &profile_id)?;
        if observed == Some(pending.activation.profile_generation_ref_id) {
            verify_pending_descriptor(host, &pending)?;
            rollback.finalize_pending(&pending).context(PolicySnafu)?;
        } else {
            ensure!(
                observed == pending.previous_profile_generation_ref_id,
                IdentityStateSnafu {
                    reason: format!(
                        "pending profile `{}` has a missing or unexpected active pointer",
                        pending.profile_id
                    ),
                }
            );
        }
    }
    Ok(())
}

fn verify_pending_descriptor(
    host: &KernelHost,
    pending: &PendingProfileActivationV1,
) -> Result<()> {
    let descriptor = host
        .lookup_map(
            "profile_generation_descriptors",
            &pending.activation.profile_generation_ref_id.to_ne_bytes(),
        )
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: "committed pending activation has no generation descriptor",
        })?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&descriptor)) == pending.activation.descriptor_sha256,
        IdentityStateSnafu {
            reason: "committed pending activation descriptor failed durable digest proof",
        }
    );
    Ok(())
}

fn read_active_generation(host: &KernelHost, profile_id: &Id128V1) -> Result<Option<u64>> {
    host.lookup_map("active_profile_generations", profile_id.as_bytes())
        .context(InterceptorSnafu)?
        .as_deref()
        .map(|bytes| {
            u64::read_from_bytes(bytes).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("active generation pointer is invalid: {error}"),
                }
                .build()
            })
        })
        .transpose()
}

fn id_bytes(id: Id128V1) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(id.as_bytes());
    bytes
}

fn add_binding_activation(
    activations: &mut BTreeMap<Id128V1, ProfileActivation>,
    profile_id: Id128V1,
    binding_id: Id128V1,
    binding: &WorkloadBindingConfig,
) -> Result<()> {
    let activation = activations
        .entry(profile_id)
        .or_insert_with(|| ProfileActivation {
            generation: binding.active_profile_generation_ref_id,
            bindings: BTreeMap::new(),
        });
    ensure!(
        activation.generation == binding.active_profile_generation_ref_id,
        IdentityStateSnafu {
            reason: format!(
                "profile `{}` cannot activate more than one node generation",
                binding.profile_id
            ),
        }
    );
    ensure!(
        activation
            .bindings
            .insert(
                binding_id,
                BindingActivationTarget {
                    generation: binding.active_profile_generation_ref_id,
                    initial_role_id: binding.initial_role_id,
                    external_role_id: binding.external_role_id,
                    requires_live_cgroup: binding.root_cgroup_path.is_some(),
                },
            )
            .is_none(),
        IdentityStateSnafu {
            reason: format!(
                "binding `{}` occurs more than once in one activation",
                binding.binding_id
            ),
        }
    );
    Ok(())
}

fn activate_profile(
    host: &KernelHost,
    profile_id: &Id128V1,
    activation: &ProfileActivation,
    rollback: &mut AntiRollbackStore,
    validated: &ValidatedProfileCandidateV1,
    node_boot_id: Id128V1,
    label_epoch: u64,
) -> Result<()> {
    let descriptor_key = activation.generation.to_ne_bytes();
    let descriptor = host
        .lookup_map("profile_generation_descriptors", &descriptor_key)
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: format!(
                "generation {} has no staged descriptor",
                activation.generation
            ),
        })?;
    let descriptor_sha256 = Sha256::digest(&descriptor).into();
    let descriptor =
        ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("staged generation descriptor is invalid: {error}"),
            }
            .build()
        })?;
    ensure!(
        descriptor.state == PolicyGenerationStateV1::Active
            && descriptor.profile_generation_ref_id == activation.generation
            && descriptor.profile_id == *profile_id,
        IdentityStateSnafu {
            reason: "staged generation descriptor does not match its activation",
        }
    );
    ensure_generation_reference_row(
        host,
        "profile_generation_task_refs",
        activation.generation,
        "task",
    )?;
    ensure_generation_reference_row(
        host,
        "profile_generation_async_refs",
        activation.generation,
        "async",
    )?;
    ensure_generation_reference_row(
        host,
        "profile_generation_socket_refs",
        activation.generation,
        "socket",
    )?;

    let pointer_key = profile_id.as_bytes();
    let expected_pointer = host
        .lookup_map("active_profile_generations", pointer_key)
        .context(InterceptorSnafu)?;
    let expected_generation = expected_pointer
        .as_deref()
        .map(|bytes| {
            u64::read_from_bytes(bytes).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("active generation pointer is invalid: {error}"),
                }
                .build()
            })
        })
        .transpose()?;

    let mut live_bindings = BTreeMap::new();
    for key in host
        .map_keys("execution_set_bindings")
        .context(InterceptorSnafu)?
    {
        let value = host
            .lookup_map("execution_set_bindings", &key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "execution-set binding disappeared during activation",
            })?;
        let binding = ExecutionSetBindingStateV1::try_read_from_bytes(&value).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("execution-set binding is invalid: {error}"),
            }
            .build()
        })?;
        if binding.profile_id != *profile_id
            || binding.lifecycle_state != BindingLifecycleStateV1::Active
        {
            continue;
        }
        ensure!(
            activation.bindings.contains_key(&binding.binding_id),
            IdentityStateSnafu {
                reason: "active profile contains a binding outside this activation",
            }
        );
        ensure!(
            live_bindings
                .insert(binding.binding_id, (key, binding))
                .is_none(),
            IdentityStateSnafu {
                reason: "one binding identity names more than one active cgroup",
            }
        );
    }
    // Scheduled placeholders can activate before a live cgroup exists; static bindings cannot.
    ensure!(
        activation.bindings.iter().all(|(binding_id, target)| {
            !target.requires_live_cgroup || live_bindings.contains_key(binding_id)
        }),
        IdentityStateSnafu {
            reason: "not every cgroup-backed activation binding is live",
        }
    );
    let mut staged = Vec::with_capacity(live_bindings.len());
    for (binding_id, (_, current)) in &live_bindings {
        let target = &activation.bindings[binding_id];
        ensure!(
            target.generation == activation.generation,
            IdentityStateSnafu {
                reason: "binding target differs from its profile activation",
            }
        );
        let mut desired = *current;
        desired.active_profile_generation_ref_id = target.generation;
        desired.initial_role_id = target.initial_role_id;
        desired.external_role_id = target.external_role_id;
        let key = BindingActivationTargetKeyV1 {
            binding_id: *binding_id,
            profile_generation_ref_id: target.generation,
        };
        let previous = host
            .lookup_map("binding_activation_targets", key.as_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            previous
                .as_deref()
                .is_none_or(|previous| previous == desired.as_bytes()),
            IdentityStateSnafu {
                reason: "generation-keyed binding activation target is immutable",
            }
        );
        staged.push(StagedActivationTarget {
            key: key.as_bytes().to_vec(),
            previous,
            desired,
        });
    }

    let stage_result = (|| {
        for target in &staged {
            if target.previous.is_none() {
                ensure!(
                    host.insert_map(
                        "binding_activation_targets",
                        &target.key,
                        target.desired.as_bytes(),
                    )
                    .context(InterceptorSnafu)?
                        == MapInsertResult::Inserted,
                    IdentityStateSnafu {
                        reason: "binding activation target changed during staging",
                    }
                );
            }
            ensure!(
                host.lookup_map("binding_activation_targets", &target.key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(target.desired.as_bytes()),
                IdentityStateSnafu {
                    reason: "binding activation target failed readback",
                }
            );
        }
        Ok(())
    })();
    if let Err(error) = stage_result {
        return match restore_activation_targets(host, &staged) {
            Ok(()) => Err(error),
            Err(rollback) => IdentityStateSnafu {
                reason: format!(
                    "binding activation failed: {error}; target rollback failed: {rollback}"
                ),
            }
            .fail(),
        };
    }

    for (binding_id, (_, current)) in &live_bindings {
        let key = BindingActivationTargetKeyV1 {
            binding_id: *binding_id,
            profile_generation_ref_id: activation.generation,
        };
        let target = host
            .lookup_map("binding_activation_targets", key.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "binding activation target disappeared before publication",
            })?;
        let target = ExecutionSetBindingStateV1::try_read_from_bytes(&target).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("binding activation target is invalid: {error}"),
            }
            .build()
        })?;
        ensure!(
            same_activation_identity(current, &target)
                && target.active_profile_generation_ref_id == activation.generation,
            IdentityStateSnafu {
                reason: "binding activation target changed before publication",
            }
        );
    }

    let observed = host
        .lookup_map("active_profile_generations", pointer_key)
        .context(InterceptorSnafu)?;
    if let Err(error) =
        ensure_active_generation_unchanged(expected_pointer.as_deref(), observed.as_deref())
    {
        return match restore_activation_targets(host, &staged) {
            Ok(()) => Err(error),
            Err(rollback) => IdentityStateSnafu {
                reason: format!(
                    "active pointer changed: {error}; target rollback failed: {rollback}"
                ),
            }
            .fail(),
        };
    }

    let activation_metadata = ProfileActivationMetadataV1 {
        profile_generation_ref_id: activation.generation,
        node_boot_id: id_bytes(node_boot_id),
        label_epoch,
        descriptor_sha256,
    };
    if expected_generation == Some(activation.generation)
        && rollback.is_current_activation(validated, &activation_metadata)
    {
        return Ok(());
    }
    let pending = rollback
        .prepare_activation(validated, activation_metadata, expected_generation)
        .context(PolicySnafu)?;
    if expected_generation == Some(activation.generation) {
        rollback.finalize_pending(&pending).context(PolicySnafu)?;
        return Ok(());
    }

    let target = activation.generation.to_ne_bytes();
    if let Err(error) = host
        .update_map("active_profile_generations", pointer_key, &target)
        .context(InterceptorSnafu)
    {
        let observed = host
            .lookup_map("active_profile_generations", pointer_key)
            .context(InterceptorSnafu)?;
        if observed.as_deref() == expected_pointer.as_deref() {
            return match restore_activation_targets(host, &staged) {
                Ok(()) => Err(error),
                Err(target_rollback) => IdentityStateSnafu {
                    reason: format!(
                        "active-generation update failed: {error}; target rollback failed: {target_rollback}"
                    ),
                }
                .fail(),
            };
        }
        if observed.as_deref() == Some(target.as_slice()) {
            rollback.finalize_pending(&pending).context(PolicySnafu)?;
            return Ok(());
        }
        return IdentityStateSnafu {
            reason: format!(
                "active-generation update failed with an ambiguous committed pointer: {error}"
            ),
        }
        .fail();
    }
    let committed = host
        .lookup_map("active_profile_generations", pointer_key)
        .context(InterceptorSnafu)
        .map_err(|error| {
            IdentityStateSnafu {
                reason: format!(
                    "active-generation publication committed, but readback failed: {error}"
                ),
            }
            .build()
        })?;
    ensure_committed_generation(&target, committed.as_deref())?;
    rollback.finalize_pending(&pending).context(PolicySnafu)
}

fn same_activation_identity(
    live: &ExecutionSetBindingStateV1,
    target: &ExecutionSetBindingStateV1,
) -> bool {
    let mut live = *live;
    live.active_profile_generation_ref_id = target.active_profile_generation_ref_id;
    live.transition_version = target.transition_version;
    live.initial_role_id = target.initial_role_id;
    live.external_role_id = target.external_role_id;
    live.lifecycle_state = target.lifecycle_state;
    live.initial_root_state = target.initial_root_state;
    live == *target
}

fn ensure_generation_reference_row(
    host: &KernelHost,
    map: &str,
    generation: u64,
    kind: &str,
) -> Result<()> {
    let key = generation.to_ne_bytes();
    if let Some(references) = host.lookup_map(map, &key).context(InterceptorSnafu)? {
        u64::read_from_bytes(&references).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("generation {kind} references are invalid: {error}"),
            }
            .build()
        })?;
        return Ok(());
    }
    let zero = 0_u64.to_ne_bytes();
    host.update_map(map, &key, &zero)
        .context(InterceptorSnafu)?;
    ensure!(
        host.lookup_map(map, &key)
            .context(InterceptorSnafu)?
            .as_deref()
            == Some(zero.as_slice()),
        IdentityStateSnafu {
            reason: format!("generation {kind}-reference row failed readback"),
        }
    );
    Ok(())
}

fn ensure_committed_generation(target: &[u8], observed: Option<&[u8]>) -> Result<()> {
    ensure!(
        observed == Some(target),
        IdentityStateSnafu {
            reason: "active-generation publication committed, but readback did not match",
        }
    );
    Ok(())
}

fn restore_activation_targets(host: &KernelHost, staged: &[StagedActivationTarget]) -> Result<()> {
    for target in staged {
        if target.previous.is_none()
            && host
                .lookup_map("binding_activation_targets", &target.key)
                .context(InterceptorSnafu)?
                .is_some()
        {
            host.delete_map_entry("binding_activation_targets", &target.key)
                .context(InterceptorSnafu)?;
        }
        ensure!(
            host.lookup_map("binding_activation_targets", &target.key)
                .context(InterceptorSnafu)?
                .as_deref()
                == target.previous.as_deref(),
            IdentityStateSnafu {
                reason: "binding activation target rollback failed readback",
            }
        );
    }
    Ok(())
}

fn ensure_active_generation_unchanged(
    expected: Option<&[u8]>,
    observed: Option<&[u8]>,
) -> Result<()> {
    ensure!(
        expected == observed,
        IdentityStateSnafu {
            reason: "active-generation handle changed during serialized publication",
        }
    );
    Ok(())
}

fn reconcile_generation_retirement(
    host: &KernelHost,
    node_boot_id: Id128V1,
    label_epoch: u64,
) -> Result<()> {
    let active_generations = host
        .map_keys("active_profile_generations")
        .context(InterceptorSnafu)?
        .into_iter()
        .map(|key| {
            host.lookup_map("active_profile_generations", &key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "active profile generation disappeared during retirement",
                })
                .and_then(|value| {
                    u64::read_from_bytes(&value).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!("active profile generation is invalid: {error}"),
                        }
                        .build()
                    })
                })
        })
        .collect::<Result<BTreeSet<_>>>()?;

    for descriptor_key in host
        .map_keys("profile_generation_descriptors")
        .context(InterceptorSnafu)?
    {
        let Some(bytes) = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let mut descriptor = read_abi_value::<ProfileGenerationDescriptorV1>(
            &bytes,
            "profile generation descriptor",
        )?;
        if descriptor.node_boot_id != node_boot_id || descriptor.label_epoch != label_epoch {
            return IdentityStateSnafu {
                reason: "profile generation survived a node boot or label epoch change".to_owned(),
            }
            .fail();
        }
        let generation = descriptor.profile_generation_ref_id;
        ensure!(
            descriptor_key.as_slice() == generation.to_ne_bytes(),
            IdentityStateSnafu {
                reason: "profile generation descriptor key does not match its value",
            }
        );
        if active_generations.contains(&generation) {
            ensure!(
                descriptor.state == PolicyGenerationStateV1::Active,
                IdentityStateSnafu {
                    reason: "active profile pointer names a non-ACTIVE generation",
                }
            );
            continue;
        }
        if descriptor.state == PolicyGenerationStateV1::Active {
            descriptor.state = PolicyGenerationStateV1::Retiring;
            descriptor.transition_version =
                descriptor
                    .transition_version
                    .checked_add(1)
                    .context(IdentityStateSnafu {
                        reason: "profile generation transition version exhausted",
                    })?;
            host.update_map(
                "profile_generation_descriptors",
                &descriptor_key,
                descriptor.as_bytes(),
            )
            .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("profile_generation_descriptors", &descriptor_key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(descriptor.as_bytes()),
                IdentityStateSnafu {
                    reason: "RETIRING profile generation failed readback",
                }
            );
        }
        ensure!(
            descriptor.state == PolicyGenerationStateV1::Retiring,
            IdentityStateSnafu {
                reason: "inactive profile generation has an invalid lifecycle state",
            }
        );
        if generation_has_retained_authority(host, generation)? {
            continue;
        }
        retire_generation_rows(host, generation, &mut descriptor, &descriptor_key)?;
    }
    Ok(())
}

fn generation_has_retained_authority(host: &KernelHost, generation: u64) -> Result<bool> {
    let reference_key = generation.to_ne_bytes();
    let references = host
        .lookup_map("profile_generation_task_refs", &reference_key)
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: "RETIRING generation lost its task-reference row",
        })?;
    if u64::read_from_bytes(&references).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("generation task references are invalid: {error}"),
        }
        .build()
    })? != 0
    {
        return Ok(true);
    }
    let async_references = host
        .lookup_map("profile_generation_async_refs", &reference_key)
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: "RETIRING generation lost its async-reference row",
        })?;
    if u64::read_from_bytes(&async_references).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("generation async references are invalid: {error}"),
        }
        .build()
    })? != 0
    {
        return Ok(true);
    }
    let socket_references = host
        .lookup_map("profile_generation_socket_refs", &reference_key)
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: "RETIRING generation lost its socket-reference row",
        })?;
    if u64::read_from_bytes(&socket_references).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("generation socket references are invalid: {error}"),
        }
        .build()
    })? != 0
    {
        return Ok(true);
    }

    for key in host
        .map_keys("io_uring_ring_states")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("io_uring_ring_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<IoUringRingStateV1>(&value, "io_uring ring state")?
            .owner
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("io_uring_request_states")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("io_uring_request_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<IoUringRequestStateV1>(&value, "io_uring request state")?
            .actor
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }

    for key in host.map_keys("process_states").context(InterceptorSnafu)? {
        let Some(value) = host
            .lookup_map("process_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let process = read_abi_value::<ProcessSecurityStateV1>(&value, "process state")?;
        if process.active_profile_generation_ref_id == generation
            && (process.live_thread_refs != 0
                || process.state != ProcessSecurityStateKindV1::Reclaimable)
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("authority_domains")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("authority_domains", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let domain = read_abi_value::<AuthorityDomainStateV1>(&value, "authority domain")?;
        if domain.retained_generation_set_ref_id == generation
            && (domain.live_process_refs != 0
                || domain.response_plan_refs != 0
                || domain.reconciliation_hold_refs != 0)
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("task_reference_tombstones")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("task_reference_tombstones", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let tombstone =
            read_abi_value::<TaskReferenceTombstoneV1>(&value, "task reference tombstone")?;
        if tombstone.profile_generation_ref_id == generation
            && tombstone.state != ReferenceTombstoneStateV1::Released
            && tombstone.state != ReferenceTombstoneStateV1::Reclaimable
        {
            return Ok(true);
        }
    }
    for key in host.map_keys("pending_execs").context(InterceptorSnafu)? {
        let Some(value) = host
            .lookup_map("pending_execs", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<PendingExecV1>(&value, "pending exec")?.source_profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("pending_administrative_matches")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("pending_administrative_matches", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<PendingAdministrativeMatchV1>(&value, "pending administrative match")?
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("approved_exec_slots")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("approved_exec_slots", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let slot = read_abi_value::<ApprovedExecSlotV1>(&value, "approved exec slot")?;
        if slot.profile_generation_ref_id == generation
            && slot.state == ApprovedExecSlotStateV1::Armed
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn retire_generation_rows(
    host: &KernelHost,
    generation: u64,
    descriptor: &mut ProfileGenerationDescriptorV1,
    descriptor_key: &[u8],
) -> Result<()> {
    descriptor.state = PolicyGenerationStateV1::Tombstoned;
    descriptor.transition_version =
        descriptor
            .transition_version
            .checked_add(1)
            .context(IdentityStateSnafu {
                reason: "profile generation transition version exhausted",
            })?;
    host.update_map(
        "profile_generation_descriptors",
        descriptor_key,
        descriptor.as_bytes(),
    )
    .context(InterceptorSnafu)?;
    ensure!(
        host.lookup_map("profile_generation_descriptors", descriptor_key)
            .context(InterceptorSnafu)?
            .as_deref()
            == Some(descriptor.as_bytes()),
        IdentityStateSnafu {
            reason: "TOMBSTONED profile generation failed readback",
        }
    );

    for map in [
        "effect_decisions",
        "effect_defaults",
        "ipc_relationship_decisions",
        "network_destination_decisions",
        "device_effect_decisions",
        "process_control_rules",
        "exception_handle_bindings",
        "exact_file_objects",
        "canonical_mount_roots",
        "path_graph_exact_transitions",
        "path_graph_wildcard_transitions",
        "path_graph_terminals",
    ] {
        delete_generation_prefixed_rows(host, map, generation, 0)?;
    }
    for map in [
        "network_ipv4_destination_classes",
        "network_ipv6_destination_classes",
    ] {
        delete_generation_prefixed_rows(host, map, generation, 8)?;
    }
    delete_generation_prefixed_rows(host, "binding_activation_targets", generation, 16)?;
    host.delete_map_entry("profile_generation_task_refs", &generation.to_ne_bytes())
        .context(InterceptorSnafu)?;
    host.delete_map_entry("profile_generation_async_refs", &generation.to_ne_bytes())
        .context(InterceptorSnafu)?;
    host.delete_map_entry("profile_generation_socket_refs", &generation.to_ne_bytes())
        .context(InterceptorSnafu)?;
    host.delete_map_entry("profile_generation_descriptors", descriptor_key)
        .context(InterceptorSnafu)?;
    ensure!(
        host.lookup_map("profile_generation_descriptors", descriptor_key)
            .context(InterceptorSnafu)?
            .is_none(),
        IdentityStateSnafu {
            reason: "retired profile generation descriptor survived deletion",
        }
    );
    Ok(())
}

fn delete_generation_prefixed_rows(
    host: &KernelHost,
    map: &str,
    generation: u64,
    offset: usize,
) -> Result<()> {
    for key in host.map_keys(map).context(InterceptorSnafu)? {
        let end = offset
            .checked_add(size_of::<u64>())
            .context(IdentityStateSnafu {
                reason: "generation key offset overflow",
            })?;
        ensure!(
            key.len() >= end,
            IdentityStateSnafu {
                reason: format!("map `{map}` has a truncated generation key"),
            }
        );
        let mut bytes = [0; size_of::<u64>()];
        bytes.copy_from_slice(&key[offset..end]);
        if u64::from_ne_bytes(bytes) == generation {
            host.delete_map_entry(map, &key).context(InterceptorSnafu)?;
        }
    }
    Ok(())
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

fn verify_rows(host: &KernelHost, map: &str, rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    for (key, value) in rows {
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

fn install_exception_rows(
    host: &KernelHost,
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    deadlines_utc: &BTreeMap<Vec<u8>, i64>,
    authority: &mut ExceptionAuthorityOwner,
    now_utc_ns: i64,
    now_boottime_ns: u64,
) -> Result<()> {
    for (key, desired_bytes) in rows {
        let existing_bytes = host
            .lookup_map_locked("exception_runtime_states", key)
            .context(InterceptorSnafu)?;
        let desired = read_abi_value::<ExceptionRuntimeStateV1>(
            desired_bytes,
            "signed exception runtime state",
        )?;
        let deadline_utc_ns = *deadlines_utc.get(key).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "signed exception runtime state has no UTC deadline".to_owned(),
            }
            .build()
        })?;
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

fn exception_counter_is_consistent(
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

fn install_missing_rows(
    host: &KernelHost,
    map: &str,
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<()> {
    for (key, value) in rows {
        if host
            .lookup_map(map, key)
            .context(InterceptorSnafu)?
            .is_none()
        {
            host.update_map(map, key, value).context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map(map, key)
                    .context(InterceptorSnafu)?
                    .as_ref()
                    == Some(value),
                IdentityStateSnafu {
                    reason: format!("candidate `{map}` mutable row readback failed"),
                }
            );
        }
    }
    Ok(())
}

fn mount_state(host: &KernelHost, map: &str, key: &[u8]) -> Result<MountViewSnapshot> {
    let bytes = host
        .lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("mount security state `{map}` disappeared during reconciliation"),
            }
            .build()
        })?;
    let state = read_abi_value::<MountSecurityViewStateV1>(&bytes, "mount security view")?;
    Ok(MountViewSnapshot {
        topology_generation: state.topology_generation,
        snapshot_digest_id: state.snapshot_digest_id,
        pending_mutations: state.pending_mutations,
        state: state.state,
        transition_version: state.transition_version,
    })
}

fn mount_epoch(host: &KernelHost, key: &[u8]) -> Result<u64> {
    mount_epoch_from(host, "mount_mutation_epochs", key)
}

fn mount_epoch_from(host: &KernelHost, map: &str, key: &[u8]) -> Result<u64> {
    let bytes = host
        .lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("mount mutation epoch `{map}` disappeared during reconciliation"),
            }
            .build()
        })?;
    u64::read_from_bytes(&bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("mount mutation epoch has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn read_abi_value<T: KnownLayout + TryFromBytes>(bytes: &[u8], name: &str) -> Result<T> {
    T::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{name} has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn cell_matches_binding(
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
                    "signed role `{role_id}` needs the conservative empty process-state vector supported by the BPF root path"
                ),
            }
        );
    }
    Ok(())
}

fn lower_administrative_plans(
    artifact: &ProfileCandidateArtifactV1,
    binding: &WorkloadBindingConfig,
    role_handles: &BTreeMap<String, u32>,
    process_state_handles: &BTreeMap<String, u32>,
    exception_handles: &BTreeMap<String, u32>,
    generation_objects: &[&ExactFileObjectConfig],
) -> Result<(bool, Vec<AdministrativePolicyPlanV1>)> {
    let assignments = artifact
        .policy_document
        .entry_role_assignments
        .iter()
        .filter(|assignment| {
            assignment
                .workload_selector_ids
                .contains(&binding.workload_selector_id)
                && assignment.entry_kinds.as_slice() == [EntryKindV1::ApprovedAdministrativeExec]
                && assignment
                    .container_kinds
                    .contains(&policy_container_kind(binding.container_kind))
                && assignment.required_administrative_exec_approval
        })
        .collect::<Vec<_>>();
    if assignments.is_empty() {
        return Ok((false, Vec::new()));
    }
    let external_role_id = role_handles
        .iter()
        .find_map(|(role_id, handle)| (*handle == binding.external_role_id).then_some(role_id))
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "configured external role has no signed role ID".to_owned(),
            }
            .build()
        })?;
    let artifact_sha256 = decode_sha256(&artifact.header.policy_document_digest)?;
    let profile = PortableProfileGenerationIdentityV1 {
        profile_id: parse_id("profile_id", &artifact.header.profile_id)?,
        owner_generation: artifact.header.profile_version,
        artifact_sha256,
    };
    let mut plans = Vec::new();
    let mut plan_keys = BTreeSet::new();
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
        let process_state = artifact
            .policy_document
            .process_state_definitions
            .iter()
            .find(|state| state.process_state_id == role.default_process_state_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "administrative role has no signed process state".to_owned(),
                }
                .build()
            })?;
        ensure!(
            role.permitted_entry_kinds
                .contains(&EntryKindV1::ApprovedAdministrativeExec)
                && process_state.state_bits.is_empty()
                && process_state_handles.get(&process_state.process_state_id) == Some(&1),
            IdentityStateSnafu {
                reason: "administrative role needs the supported approved entry and conservative process state",
            }
        );
        let approved_role_numeric_id = role_handles[&role.role_id];
        let mut role_selector_count = 0;
        for cell in artifact
            .compiled_profile
            .compiled_cells
            .iter()
            .filter(|cell| {
                cell_matches_binding(&cell.key, binding, &artifact.policy_document)
                    && cell.key.entry_kind == EntryKindV1::ExternalRuntimeUnknown
                    && cell.key.role_id == *external_role_id
                    && cell.key.effect_family == mithril_control::EffectFamilyV1::Exec
                    && cell.key.operation_id == "EXECUTE"
                    && cell.key.binding_lifecycle == mithril_control::BindingLifecycleV1::Active
                    && matches!(
                        cell.physical_result,
                        CompiledPhysicalResultV1::AllowEffect
                            | CompiledPhysicalResultV1::AuditAllowEffect
                    )
            })
        {
            let Some(path_selector_id) = cell.key.object_selector.strip_prefix("PATH:") else {
                continue;
            };
            role_selector_count += 1;
            let exact_object_key_id = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| selector.path_selector_id == path_selector_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "administrative executable references unknown path selector `{path_selector_id}`"
                    ),
                })?
                .kernel_handle();
            let Some(executable_object) = generation_objects
                .iter()
                .find(|object| object.exact_object_key_id == exact_object_key_id)
                .copied()
            else {
                continue;
            };
            ensure!(
                plan_keys.insert((
                    parse_id("binding_id", &binding.binding_id)?,
                    role.role_id.clone(),
                    exact_object_key_id,
                )),
                IdentityStateSnafu {
                    reason: "administrative role and executable plan is ambiguous",
                }
            );
            plans.push(AdministrativePolicyPlanV1 {
                binding_id: parse_id("binding_id", &binding.binding_id)?,
                approved_role_id: role.role_id.clone(),
                approved_role_numeric_id,
                profile: profile.clone(),
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                exception_numeric_handle: cell
                    .consuming_exception_id
                    .as_ref()
                    .map(|id| exception_handles[id])
                    .unwrap_or_default(),
                executable_object: (*executable_object).clone(),
            });
        }
        ensure!(
            role_selector_count > 0,
            IdentityStateSnafu {
                reason: format!(
                    "administrative role `{}` has no signed executable selector for the restricted external root",
                    role.role_id
                ),
            }
        );
    }
    Ok((true, plans))
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("compiled profile digest is invalid: {error}"),
        }
        .build()
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        IdentityStateSnafu {
            reason: format!(
                "compiled profile digest has {} bytes instead of 32",
                bytes.len()
            ),
        }
        .build()
    })
}

fn portable_id_bytes(id: Id128V1) -> Vec<u8> {
    [id.high.to_be_bytes(), id.low.to_be_bytes()].concat()
}

fn derived_id(domain: &[u8], fields: &[Vec<u8>]) -> Result<Id128V1> {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    let digest = digest.finalize();
    let high = u64::from_be_bytes(digest[0..8].try_into().map_err(|error| {
        IdentityStateSnafu {
            reason: format!("derived identity high word is invalid: {error}"),
        }
        .build()
    })?);
    let low = u64::from_be_bytes(digest[8..16].try_into().map_err(|error| {
        IdentityStateSnafu {
            reason: format!("derived identity low word is invalid: {error}"),
        }
        .build()
    })?);
    let id = Id128V1::new(high, low);
    ensure!(
        !id.is_zero(),
        IdentityStateSnafu {
            reason: "derived identity is zero",
        }
    );
    Ok(id)
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

fn physical_decision(
    result: CompiledPhysicalResultV1,
    errno: Option<i16>,
    exception_numeric_handle: u32,
) -> PhysicalDecisionV1 {
    PhysicalDecisionV1 {
        decision: match result {
            CompiledPhysicalResultV1::AllowEffect => PhysicalDecisionKindV1::Allow,
            CompiledPhysicalResultV1::AuditAllowEffect => PhysicalDecisionKindV1::AuditAllow,
            CompiledPhysicalResultV1::SimulatablePolicyDeny => PhysicalDecisionKindV1::Deny,
            CompiledPhysicalResultV1::DenyEffect => PhysicalDecisionKindV1::Deny,
        },
        reserved: 0,
        errno: errno.unwrap_or(0),
        evidence_class_id: 1,
        transition_id: 0,
        exception_numeric_handle,
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

struct PathTables {
    mount_views: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_epochs: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_locks: BTreeMap<Vec<u8>, Vec<u8>>,
    mount_roots: BTreeMap<Vec<u8>, Vec<u8>>,
    exact: BTreeMap<Vec<u8>, Vec<u8>>,
    wildcards: BTreeMap<Vec<u8>, Vec<u8>>,
    terminals: BTreeMap<Vec<u8>, Vec<u8>>,
    reconciliation: Vec<MountRootReconciliation>,
}

impl LoweredGeneration {
    fn composite_handles(artifact: &ProfileCandidateArtifactV1) -> BTreeMap<String, u64> {
        let mut handles = artifact
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
                    .map(|cell| cell.key.object_selector.clone()),
            )
            .filter(|id| !id.starts_with("PATH:"))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index as u64 + 1))
            .collect::<BTreeMap<_, _>>();
        for selector in &artifact.policy_document.path_selectors {
            let object_class = format!("CLASS:{}", selector.object_class_id);
            let handle = handles[&object_class];
            handles.insert(format!("PATH:{}", selector.path_selector_id), handle);
        }
        handles
    }

    fn lower_path_tables(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
        objects: &[&ExactFileObjectConfig],
        composite_handles: &BTreeMap<String, u64>,
    ) -> Result<PathTables> {
        let mut patterns = Vec::new();
        let mut decoded = BTreeMap::new();
        for selector in &artifact.policy_document.path_selectors {
            let components = selector
                .target
                .pattern_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?;
            patterns.push(PathPatternV1 {
                rule_id: selector.path_selector_id.clone(),
                components,
                candidate_object_class_id: selector.object_class_id.clone(),
                physical_result_id: format!("CLASS:{}", selector.object_class_id),
                overrides_rule_ids: Vec::new(),
            });
            if let Some(components) = selector
                .target
                .exact_components(artifact.header.profile_id.as_str())
                .context(PolicySnafu)?
            {
                decoded.insert(selector.kernel_handle(), components);
            }
        }
        let path_tree_denies = artifact
            .policy_document
            .path_tree_deny_floors
            .iter()
            .map(|floor| {
                let mut operations = floor
                    .operation_ids
                    .iter()
                    .map(|operation| {
                        CompiledOperationV1::try_from(operation.as_str())
                            .map(|operation| operation.kernel_id as u16)
                            .map_err(|_| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "path-tree rule has unknown operation `{operation}`"
                                    ),
                                }
                                .build()
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                operations.sort_unstable();
                Ok(PathTreeDenyPatternV1 {
                    components: canonical_path_components(
                        artifact.header.profile_id.as_str(),
                        &floor.canonical_path,
                    )
                    .context(PolicySnafu)?,
                    operations,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let graph = CanonicalPathGraphV1::compile_with_path_tree_denies_and_precedence(
            artifact.header.profile_id.as_str(),
            &patterns,
            &path_tree_denies,
            artifact.policy_document.path_pattern_precedence,
        )
        .context(PolicySnafu)?
        .determinize(artifact.header.profile_id.as_str())
        .context(PolicySnafu)?;
        let mut tables = PathTables {
            mount_views: BTreeMap::new(),
            mount_epochs: BTreeMap::new(),
            mount_locks: BTreeMap::new(),
            mount_roots: BTreeMap::new(),
            exact: BTreeMap::new(),
            wildcards: BTreeMap::new(),
            terminals: BTreeMap::new(),
            reconciliation: Vec::new(),
        };
        for transition in &graph.exact_transitions {
            let component = path_component(&transition.component)?;
            let key = PathGraphTransitionKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                current_state_id: transition.current_state_id,
                component,
                reserved: 0,
            };
            let value = PathGraphTransitionV1 {
                next_state_id: transition.next_state_id,
                reserved: 0,
            };
            insert_exact(&mut tables.exact, key.as_bytes(), value.as_bytes())?;
        }
        for transition in &graph.wildcard_transitions {
            let key = PathGraphStateKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                state_id: transition.current_state_id,
                reserved: 0,
            };
            let value = PathGraphTransitionV1 {
                next_state_id: transition.next_state_id,
                reserved: 0,
            };
            insert_exact(&mut tables.wildcards, key.as_bytes(), value.as_bytes())?;
        }
        let rule_handles = handles(
            graph
                .terminals
                .iter()
                .map(|terminal| terminal.rule_id.as_str()),
        );
        let mut terminal_values = BTreeMap::<u32, PathGraphTerminalV1>::new();
        for terminal in &graph.terminals {
            let selector = artifact
                .policy_document
                .path_selectors
                .iter()
                .find(|selector| selector.path_selector_id == terminal.rule_id)
                .context(IdentityStateSnafu {
                    reason: format!("path terminal has unknown selector `{}`", terminal.rule_id),
                })?;
            let composite_atom_id = *composite_handles
                .get(&format!("PATH:{}", terminal.rule_id))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "path terminal has no composite atom for `{}`",
                            terminal.rule_id
                        ),
                    }
                    .build()
                })?;
            let value = PathGraphTerminalV1 {
                composite_atom_id,
                rule_numeric_id: rule_handles[&terminal.rule_id],
                exact_object_required: u8::from(selector.requires_exact_object()),
                reserved: [0; 3],
                path_tree_deny_operation_mask: 0,
            };
            ensure!(
                terminal_values.insert(terminal.state_id, value).is_none(),
                IdentityStateSnafu {
                    reason: "deterministic path state has multiple exact terminals",
                }
            );
        }
        for floor in &graph.path_tree_deny_floors {
            terminal_values
                .entry(floor.state_id)
                .or_default()
                .path_tree_deny_operation_mask |= floor.operation_mask;
        }
        for (state_id, value) in terminal_values {
            let key = PathGraphStateKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                state_id,
                reserved: 0,
            };
            insert_exact(&mut tables.terminals, key.as_bytes(), value.as_bytes())?;
        }
        let binding_id = parse_id("binding_id", &binding.binding_id)?;
        for object in objects {
            let components = &decoded[&object.exact_object_key_id];
            let prefix_len = components
                .len()
                .checked_sub(usize::from(object.mount_relative_component_count))
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "mount-relative path count exceeds the canonical path".to_owned(),
                    }
                    .build()
                })?;
            let graph_prefix_state_id =
                graph
                    .state_after(&components[..prefix_len])
                    .ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "canonical mount prefix is absent from its path graph"
                                .to_owned(),
                        }
                        .build()
                    })?;
            let view_map_key = object.mount_namespace_inode.to_ne_bytes();
            let view = MountSecurityViewStateV1 {
                topology_generation: object.mount_topology_generation,
                snapshot_digest_id: 0,
                pending_mutations: 0,
                state: MountTopologyStateV1::Dirty,
                reserved: [0; 7],
                transition_version: 1,
            };
            insert_exact(&mut tables.mount_views, &view_map_key, view.as_bytes())?;
            insert_exact(
                &mut tables.mount_epochs,
                &view_map_key,
                &object.mount_topology_generation.to_ne_bytes(),
            )?;
            insert_exact(&mut tables.mount_locks, &view_map_key, &0_u32.to_ne_bytes())?;
            let root_key = CanonicalMountRootKeyV1 {
                profile_generation_ref_id: binding.active_profile_generation_ref_id,
                mount_namespace_inode: object.mount_namespace_inode,
                binding_id,
                topology_generation: object.mount_topology_generation,
                filesystem_device: object.mount_root_filesystem_device,
                root_inode: object.mount_root_inode,
            };
            let root = CanonicalMountRootV1 {
                selected_mount_id_unique: object.selected_mount_id_unique,
                snapshot_digest_id: object.mount_snapshot_digest_id,
                graph_prefix_state_id,
                reserved: 0,
            };
            insert_exact(
                &mut tables.mount_roots,
                root_key.as_bytes(),
                root.as_bytes(),
            )?;
            tables.reconciliation.push(MountRootReconciliation {
                mount_namespace_inode: object.mount_namespace_inode,
                binding_id,
                configured: (*object).clone(),
                canonical_path: canonical_path(components),
                graph_prefix_state_id,
            });
        }
        Ok(tables)
    }
}

fn path_component(bytes: &[u8]) -> Result<CanonicalPathComponentV1> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CANONICAL_COMPONENT_BYTES_V1 && !bytes.contains(&0),
        IdentityStateSnafu {
            reason: "canonical path component is invalid",
        }
    );
    let mut component = CanonicalPathComponentV1 {
        length: bytes.len() as u16,
        ..CanonicalPathComponentV1::default()
    };
    component.bytes[..bytes.len()].copy_from_slice(bytes);
    Ok(component)
}

fn canonical_path(components: &[Vec<u8>]) -> PathBuf {
    let mut path = PathBuf::from("/");
    for component in components {
        path.push(OsStr::from_bytes(component));
    }
    path
}

type MapRows = BTreeMap<Vec<u8>, Vec<u8>>;

fn table_digest(tables: &[(&str, &MapRows)]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (domain, rows) in tables {
        for (key, value) in rows.iter() {
            digest.update(domain.as_bytes());
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

pub(crate) fn stable_node_id(value: &str) -> Result<Id128V1> {
    if let Ok(id) = parse_id("node_id", value) {
        return Ok(id);
    }
    let digest = Sha256::digest([b"MITHRIL-NODE-ID-V1\0".as_slice(), value.as_bytes()].concat());
    Ok(Id128V1::new(
        u64::from_be_bytes(digest[..8].try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("node_id digest high half is invalid: {error}"),
            }
            .build()
        })?),
        u64::from_be_bytes(digest[8..16].try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("node_id digest low half is invalid: {error}"),
            }
            .build()
        })?),
    ))
}

pub(crate) fn current_utc_ns() -> Result<i64> {
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

pub(crate) fn current_boottime_ns() -> Result<u64> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(u64::try_from(value.tv_nsec).ok()?))
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "system boot clock exceeds the unsigned nanosecond range".to_owned(),
            }
            .build()
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::mem::offset_of;
    use std::path::{Path, PathBuf};

    use ed25519_dalek::SigningKey;
    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, EffectDecisionKeyV1, EffectDefaultKeyV1,
        EntryKindV1 as AbiEntryKindV1, ExactFileObjectKeyV1, ExactObjectBindingStateV1,
        ExactObjectBindingV1, Id128V1, KernelEffectFamilyV1, KernelEffectOperationV1,
        PathGraphStateKeyV1, PathGraphTerminalV1, PathGraphTransitionKeyV1, PhysicalDecisionKindV1,
        PhysicalDecisionV1, PolicyGenerationModeV1,
    };
    use mithril_control::{
        EffectFamilyV1, FileExceptionGrantTemplateV1, LocalObjectSelectorV1,
        ObjectClassifierSelectorV1, PathSelectorTargetV1, PathSelectorV1, PathTreeDenyFloorV1,
        PolicyCompiler, PolicyDispositionV1, PolicyDocumentV1, ProfileCandidateArtifactV1,
        ProfileModeV1, ProfileSealRequestV1, RegistryDigestsV1, RuleMatchV1,
    };
    use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes as _};

    use super::{
        add_binding_activation, ensure_active_generation_unchanged, ensure_committed_generation,
        ensure_map_capacity, exception_counter_is_consistent, parse_id, same_exact_file,
        LoweredGeneration, ProfileActivation,
    };
    use crate::error::IdentityStateSnafu;
    use crate::{
        ContainerKindV1, ExactDeviceConfig, ExactDeviceType, ExactFileObjectConfig,
        WorkloadBindingConfig,
    };

    #[test]
    fn capacity_preflight_counts_existing_and_planned_unique_keys() -> crate::Result<()> {
        ensure_map_capacity(
            "effect_decisions",
            3,
            vec![vec![1], vec![2]],
            vec![vec![2], vec![3]],
        )?;
        assert!(ensure_map_capacity(
            "effect_decisions",
            2,
            vec![vec![1], vec![2]],
            vec![vec![2], vec![3]],
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn path_selector_and_its_object_class_share_one_kernel_atom() -> crate::Result<()> {
        let (artifact, _, _) = exact_artifact(ProfileModeV1::Observe)?;
        let handles = LoweredGeneration::composite_handles(&artifact);
        assert_eq!(
            handles["PATH:projected-token"],
            handles["CLASS:PROJECTED_TOKEN"]
        );
        Ok(())
    }

    #[test]
    fn exact_decision_key_contains_its_signed_composite_atom() -> crate::Result<()> {
        let (artifact, binding, mut object) = exact_artifact(ProfileModeV1::Observe)?;
        object.selected_mount_id_unique = object.mount_id_unique + 1;
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let terminal = generation
            .path_terminals
            .values()
            .find_map(|value| {
                PathGraphTerminalV1::read_from_bytes(value)
                    .ok()
                    .filter(|terminal| terminal.exact_object_required == 1)
            })
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "test generation has no exact path terminal".to_owned(),
                }
                .build()
            })?;
        let expected = EffectDecisionKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 1,
            entry_kind: AbiEntryKindV1::ContainerStart as u16,
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            reserved: 0,
            reserved_alignment: [0; 4],
            composite_atom_id: terminal.composite_atom_id,
            exact_object_key_id: object.exact_object_key_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert_eq!(
            generation.decisions.keys().next(),
            Some(&expected.as_bytes().to_vec())
        );
        let object_key = generation.file_objects.keys().next().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "test generation has no exact object row".to_owned(),
            }
            .build()
        })?;
        assert_eq!(
            ExactFileObjectKeyV1::read_from_bytes(object_key)
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("test exact object key has the wrong ABI: {error}"),
                    }
                    .build()
                })?
                .mount_id_unique,
            object.selected_mount_id_unique
        );
        assert_eq!(
            generation.mount_views.keys().next(),
            Some(&object.mount_namespace_inode.to_ne_bytes().to_vec())
        );
        let expected_binding = ExactObjectBindingV1 {
            profile_generation_ref_id: 1,
            exact_object_key_id: object.exact_object_key_id,
            composite_atom_id: terminal.composite_atom_id,
            state: ExactObjectBindingStateV1::ReadBack,
            reserved: [0; 7],
        };
        assert!(generation
            .file_objects
            .values()
            .any(|binding| binding == expected_binding.as_bytes()));

        let unresolved = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert!(unresolved.file_objects.is_empty());
        assert_eq!(unresolved.decisions, generation.decisions);
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
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn inactive_file_grant_lowers_to_a_fail_closed_exception_handle() -> crate::Result<()> {
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .file_exception_grants
            .push(FileExceptionGrantTemplateV1 {
                grant_id: "temporary-token-read".to_owned(),
                denied_file_rule_ids: vec!["deny-projected-token-open".to_owned()],
                maximum_duration_ns: 1_000_000_000,
                maximum_uses: 1,
            });
        artifact.compiled_profile =
            PolicyCompiler
                .compile(&artifact.policy_document)
                .map_err(|source| crate::Error::Policy {
                    source,
                    location: snafu::Location::default(),
                })?;
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[object],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let decision = generation
            .decisions
            .values()
            .find_map(|value| PhysicalDecisionV1::try_read_from_bytes(value).ok())
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "grant test generation has no effect decision".to_owned(),
                }
                .build()
            })?;
        assert_eq!(decision.decision, PhysicalDecisionKindV1::Allow);
        assert_eq!(decision.exception_numeric_handle, 1);
        assert!(generation.exception_bindings.is_empty());
        assert!(generation.exceptions.is_empty());
        Ok(())
    }

    #[test]
    fn protect_generation_lowers_to_an_active_physical_deny_table() -> crate::Result<()> {
        let (artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;

        assert_eq!(generation.descriptor.mode, PolicyGenerationModeV1::Protect);
        assert_eq!(
            generation.descriptor.state,
            erebor_interceptor_abi::PolicyGenerationStateV1::Preparing
        );
        assert_eq!(
            generation.read_back_descriptor().state,
            erebor_interceptor_abi::PolicyGenerationStateV1::ReadBack
        );
        assert_eq!(generation.read_back_descriptor().transition_version, 2);
        assert_eq!(
            generation.active_descriptor().state,
            erebor_interceptor_abi::PolicyGenerationStateV1::Active
        );
        assert_eq!(generation.active_descriptor().transition_version, 3);
        assert_eq!(
            generation.decisions.values().next().map(|value| value[0]),
            Some(PhysicalDecisionKindV1::Deny as u8)
        );
        Ok(())
    }

    #[test]
    fn scheduled_binding_lowers_one_policy_slot_for_its_exact_execution_set() -> crate::Result<()> {
        let (artifact, mut binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        binding.scheduled_binding_authority_id = Some(binding.binding_id.clone());
        binding.execution_set_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();

        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;

        assert_eq!(generation.decisions.len(), 1);
        Ok(())
    }

    #[test]
    fn recursive_signed_selector_stages_without_a_live_object() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact.policy_document.path_selectors[0].target = PathSelectorTargetV1::Path {
            path_pattern: "/var/**/token".to_owned(),
        };
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert!(generation.file_objects.is_empty());
        assert!(generation.mount_views.is_empty());
        assert!(generation.decisions.is_empty());
        assert!(generation
            .path_terminals
            .values()
            .any(|value| PathGraphTerminalV1::read_from_bytes(value)
                .is_ok_and(|terminal| terminal.exact_object_required == 0)));
        assert_eq!(generation.defaults.len(), 1);
        Ok(())
    }

    #[test]
    fn path_selector_stages_a_path_decision_without_an_exact_object() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact.policy_document.path_selectors[0].target = PathSelectorTargetV1::Path {
            path_pattern: "/var/*/token".to_owned(),
        };
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;

        assert!(generation.file_objects.is_empty());
        assert!(generation.mount_views.is_empty());
        assert!(generation.decisions.is_empty());
        let terminal = generation
            .path_terminals
            .values()
            .find_map(|value| PathGraphTerminalV1::read_from_bytes(value).ok())
            .filter(|terminal| {
                terminal.composite_atom_id > 0 && terminal.exact_object_required == 0
            })
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "test generation has no path-only terminal".to_owned(),
                }
                .build()
            })?;
        let expected = EffectDefaultKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 1,
            entry_kind: AbiEntryKindV1::ContainerStart as u16,
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            reserved: 0,
            reserved_alignment: [0; 4],
            composite_atom_id: terminal.composite_atom_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert!(generation.defaults.contains_key(expected.as_bytes()));
        Ok(())
    }

    #[test]
    fn device_object_requires_its_signed_class_pair() -> crate::Result<()> {
        let (mut artifact, binding, mut object) = exact_artifact(ProfileModeV1::Protect)?;
        object.device = Some(ExactDeviceConfig {
            device_class_id: "NULL_DEVICE".to_owned(),
            device_type: ExactDeviceType::Character,
            major: 1,
            minor: 3,
        });

        assert!(LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )
        .is_err());

        let classifier = artifact
            .policy_document
            .classifier_bindings
            .iter_mut()
            .find(|classifier| classifier.object_class_id == object.object_class_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "test policy has no classifier for its exact object".to_owned(),
                }
                .build()
            })?;
        classifier.selector = ObjectClassifierSelectorV1::Device {
            device_class_ids: vec!["NULL_DEVICE".to_owned()],
        };
        artifact.policy_document.path_selectors[0].device_class_id = Some("NULL_DEVICE".to_owned());
        assert!(LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn active_generation_switch_rejects_a_changed_expected_value() -> crate::Result<()> {
        let old = 7_u64.to_ne_bytes();
        let changed = 8_u64.to_ne_bytes();

        ensure_active_generation_unchanged(None, None)?;
        ensure_active_generation_unchanged(Some(&old), Some(&old))?;
        assert!(ensure_active_generation_unchanged(Some(&old), Some(&changed)).is_err());
        assert!(ensure_active_generation_unchanged(Some(&old), None).is_err());
        Ok(())
    }

    #[test]
    fn committed_generation_readback_requires_the_published_value() -> crate::Result<()> {
        let target = 8_u64.to_ne_bytes();
        ensure_committed_generation(&target, Some(&target))?;
        assert!(ensure_committed_generation(&target, None).is_err());
        assert!(ensure_committed_generation(&target, Some(&7_u64.to_ne_bytes())).is_err());
        Ok(())
    }

    #[test]
    fn one_profile_activation_has_one_node_generation() -> crate::Result<()> {
        let (_, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        let profile_id = parse_id("profile_id", &binding.profile_id)?;
        let binding_id = parse_id("binding_id", &binding.binding_id)?;
        let mut activations = BTreeMap::<Id128V1, ProfileActivation>::new();
        add_binding_activation(&mut activations, profile_id, binding_id, &binding)?;

        let mut second = binding.clone();
        second.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
        let second_id = parse_id("binding_id", &second.binding_id)?;
        add_binding_activation(&mut activations, profile_id, second_id, &second)?;
        assert_eq!(activations[&profile_id].bindings.len(), 2);

        second.active_profile_generation_ref_id += 1;
        assert!(add_binding_activation(&mut activations, profile_id, second_id, &second).is_err());
        Ok(())
    }

    #[test]
    fn activation_targets_keep_old_and_new_generations_separate() {
        let binding_id = Id128V1::new(1, 2);
        let old = erebor_interceptor_abi::BindingActivationTargetKeyV1 {
            binding_id,
            profile_generation_ref_id: 7,
        };
        let new = erebor_interceptor_abi::BindingActivationTargetKeyV1 {
            binding_id,
            profile_generation_ref_id: 8,
        };

        assert_ne!(old.as_bytes(), new.as_bytes());
    }

    #[test]
    fn default_cell_lowers_to_the_objectless_kernel_key() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact.compiled_profile.compiled_cells[0]
            .key
            .object_selector = "DEFAULT".to_owned();
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;

        assert!(generation.decisions.is_empty());
        let key = generation.defaults.keys().next().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "default test generation has no kernel row".to_owned(),
            }
            .build()
        })?;
        let offset = offset_of!(
            erebor_interceptor_abi::EffectDefaultKeyV1,
            composite_atom_id
        );
        let atom = key[offset..offset + 8]
            .try_into()
            .map(u64::from_ne_bytes)
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("default test atom is not a u64: {error}"),
                }
                .build()
            })?;
        assert_eq!(atom, 0);
        Ok(())
    }

    #[test]
    fn path_tree_floor_lowers_without_a_live_mount_view() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .path_tree_deny_floors
            .push(PathTreeDenyFloorV1 {
                schema_version: 1,
                rule_id: "secret-tree-deny".to_owned(),
                canonical_path: "/var/run/secrets".to_owned(),
                recursive: true,
                effect_families: vec![EffectFamilyV1::File],
                operation_ids: ["CREATE", "LINK", "OPEN_READ"].map(str::to_owned).to_vec(),
                requested_disposition: PolicyDispositionV1::Deny,
                exception_ids: Vec::new(),
            });
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let tables =
            LoweredGeneration::lower_path_tables(&artifact, &binding, &[], &composite_handles)?;
        let open_read_mask = 1_u64 << KernelEffectOperationV1::OpenRead as u16;

        assert!(tables.mount_roots.is_empty());
        assert!(tables.reconciliation.is_empty());
        assert!(!tables.exact.is_empty());
        assert!(tables.terminals.values().any(|value| {
            PathGraphTerminalV1::read_from_bytes(value).is_ok_and(|terminal| {
                terminal.composite_atom_id == 0
                    && terminal.path_tree_deny_operation_mask & open_read_mask != 0
            })
        }));
        Ok(())
    }

    #[test]
    fn path_graph_rows_are_scoped_to_the_bound_generation() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .path_tree_deny_floors
            .push(PathTreeDenyFloorV1 {
                schema_version: 1,
                rule_id: "secret-tree-deny".to_owned(),
                canonical_path: "/var/run/secrets".to_owned(),
                recursive: true,
                effect_families: vec![EffectFamilyV1::File],
                operation_ids: vec!["OPEN_READ".to_owned()],
                requested_disposition: PolicyDispositionV1::Deny,
                exception_ids: Vec::new(),
            });
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let first =
            LoweredGeneration::lower_path_tables(&artifact, &binding, &[], &composite_handles)?;
        let second_binding = WorkloadBindingConfig {
            active_profile_generation_ref_id: 2,
            ..binding
        };
        let second = LoweredGeneration::lower_path_tables(
            &artifact,
            &second_binding,
            &[],
            &composite_handles,
        )?;

        assert!(first.exact.keys().all(|key| {
            PathGraphTransitionKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 1)
        }));
        assert!(second.exact.keys().all(|key| {
            PathGraphTransitionKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 2)
        }));
        assert!(first.terminals.keys().all(|key| {
            PathGraphStateKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 1)
        }));
        assert!(second.terminals.keys().all(|key| {
            PathGraphStateKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 2)
        }));
        assert!(first
            .exact
            .keys()
            .all(|key| !second.exact.contains_key(key)));
        assert!(first
            .terminals
            .keys()
            .all(|key| !second.terminals.contains_key(key)));
        Ok(())
    }

    #[test]
    fn exception_counter_recovery_never_revives_or_overruns_a_budget() {
        use erebor_interceptor_abi::ExceptionRuntimeStateKindV1 as State;

        assert!(exception_counter_is_consistent(2, 0, State::Active));
        assert!(exception_counter_is_consistent(2, 1, State::Active));
        assert!(exception_counter_is_consistent(2, 2, State::Exhausted));
        assert!(exception_counter_is_consistent(2, 1, State::Expired));
        assert!(!exception_counter_is_consistent(2, 2, State::Active));
        assert!(!exception_counter_is_consistent(2, 1, State::Exhausted));
        assert!(!exception_counter_is_consistent(2, 3, State::Expired));
    }

    #[test]
    fn reconciliation_requires_the_same_exact_file() -> crate::Result<()> {
        let (_, _, object) = exact_artifact(ProfileModeV1::Observe)?;
        assert!(same_exact_file(&object, &object));

        for changed in [
            ExactFileObjectConfig {
                mount_namespace_inode: object.mount_namespace_inode + 1,
                ..object.clone()
            },
            ExactFileObjectConfig {
                mount_id_unique: object.mount_id_unique + 1,
                ..object.clone()
            },
            ExactFileObjectConfig {
                filesystem_device: object.filesystem_device + 1,
                ..object.clone()
            },
            ExactFileObjectConfig {
                inode: object.inode + 1,
                ..object.clone()
            },
            ExactFileObjectConfig {
                inode_generation: object.inode_generation + 1,
                ..object.clone()
            },
        ] {
            assert!(!same_exact_file(&object, &changed));
        }
        Ok(())
    }

    fn exact_artifact(
        mode: ProfileModeV1,
    ) -> crate::Result<(
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
        document.path_selectors = vec![PathSelectorV1::exact(
            "projected-token",
            "/var/run/token",
            "PROJECTED_TOKEN",
        )];
        let RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match else {
            unreachable!("fixture contains one local rule")
        };
        effect.object = LocalObjectSelectorV1::PathSelectors {
            path_selector_ids: vec!["projected-token".to_owned()],
        };
        document.rollout.desired_profile_mode = mode;
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
            scheduled_binding_authority_id: None,
            scheduled_target_digest: None,
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: document.metadata.profile_id.clone(),
            container_id: "a".repeat(64),
            namespace: "default".to_owned(),
            cluster_uid: String::new(),
            namespace_uid: String::new(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::new(),
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
            exact_object_key_id: document.path_selectors[0].kernel_handle(),
            object_class_id: "PROJECTED_TOKEN".to_owned(),
            mount_namespace_inode: 10,
            mount_id_unique: 20,
            filesystem_device: 30,
            inode: 40,
            inode_generation: 50,
            device: None,
            canonical_component_hex: ["var", "run", "token"]
                .map(|component| hex::encode(component.as_bytes()))
                .to_vec(),
            mount_relative_component_count: 3,
            mount_root_filesystem_device: 30,
            mount_root_inode: 2,
            selected_mount_id_unique: 20,
            mount_snapshot_digest_id: 60,
            mount_topology_generation: 1,
            mount_view_root_pid: 1,
        };
        Ok((artifact, binding, object))
    }
}
