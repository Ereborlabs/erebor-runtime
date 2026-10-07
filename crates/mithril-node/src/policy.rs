use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::mem::size_of;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, ExactExecutableCandidateV1, ExceptionBindingStateV1,
    ExceptionHandleBindingKeyV1, ExceptionHandleBindingV1, ExceptionRuntimeStateKeyV1,
    ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1, Id128V1, KernelEffectFamilyV1,
    NetworkResponseFloorKeyV1, NetworkResponseFloorV1, NetworkResponseScopeV1,
    PhysicalDecisionKindV1, PhysicalDecisionV1, PolicyGenerationStateV1,
    ProfileGenerationDescriptorV1,
};
use mithril_control::{
    canonical_path_components, CompiledOperationV1, CompiledPhysicalResultV1,
    ContainerKindV1 as PolicyContainerKindV1, ExceptionActivationStateV1,
    ExceptionDeliveryCandidateV1, ExceptionDeliveryOperationV1, ProfileCandidateArtifactV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes};

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
mod discovery;
mod exception_authority;
mod generation;
mod generation_allocator;
mod installation;
mod ipc;
mod network;
mod owner;
mod path;
mod publication;

use self::device_process::TypedEffectContext;
pub use self::discovery::NodeDiscoveryContextCatalog;
use self::exception_authority::ExceptionAuthorityOwner;
#[cfg(any(test, feature = "test-support"))]
use self::generation::entry_admission_path_selector_ids;
#[cfg(test)]
use self::generation::exception_counter_is_consistent;
use self::generation::{
    cell_matches_binding, ensure_map_capacity, preflight_policy_map_capacity, GenerationBinding,
    GenerationPlan, LoweredGeneration, NativeTable,
};
use self::generation_allocator::GenerationHandleAllocator;
#[cfg(test)]
use self::installation::same_exact_file;
use self::installation::{Candidates, MountRootReconciliation, PolicyInput, PolicyMeasurements};
use self::network::LoweredNetworkPolicy;
pub(crate) use self::publication::generation_publication_is_absent;
use self::publication::{
    build_process_generation_migrations, install_missing_rows, install_rows, mount_epoch_from,
    prepare_declared_entry_requests, read_abi_value, read_active_generation,
    reconcile_generation_retirement, reconcile_pending_activations,
    retire_undeclared_entry_requests, retire_unreachable_mount_cache_rows, verify_rows,
    ProfileActivation,
};
#[cfg(test)]
use self::publication::{
    ensure_active_generation_unchanged, ensure_committed_generation,
    generation_retirement_needs_tombstone, mount_cache_row_is_unreachable,
    pending_exec_retains_generation_authority,
};

const LINUX_CAPABILITY_SELECTOR_PREFIX: &str = "SECURITY:LINUX_CAPABILITY:";
const CANONICAL_MOUNT_CACHE_KEY_SIZE_V1: usize = 56;
const CANONICAL_MOUNT_CACHE_STATE_KEY_SIZE_V1: usize = 48;
const CANONICAL_MOUNT_CACHE_SECURITY_VIEW_EPOCH_OFFSET_V1: usize = 16;
const CANONICAL_MOUNT_CACHE_GENERATION_OFFSET_V1: usize = 24;

pub struct NodePolicyGenerationOwner {
    node_boot_id: Id128V1,
    label_epoch: u64,
    prevention_enabled: bool,
    administrative_plans: Vec<AdministrativePolicyPlanV1>,
    measured: PolicyMeasurements,
    generation_semantics: BTreeMap<u64, GenerationSemantics>,
    discovery_context: Arc<NodeDiscoveryContextCatalog>,
    dynamic_rows: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    exception_authority: Mutex<ExceptionAuthorityOwner>,
    retirement_pending: AtomicBool,
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

#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct MeasuredExactObjectV1 {
    binding_id: String,
    object: ExactFileObjectConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MeasuredMountRouteV1 {
    binding_id: String,
    mount_view_root_pid: u32,
    mount_topology_generation: u64,
    route: crate::exact_object::LiveMountRootRouteV1,
}

#[derive(Clone, Debug)]
struct AdministrativePolicyPlanV1 {
    binding_id: Id128V1,
    approved_role_id: String,
    approved_role_numeric_id: u32,
    admitted_entry_rule_id: u32,
    profile: PortableProfileGenerationIdentityV1,
    profile_generation_ref_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedAdministrativePolicyV1 {
    pub approved_role_numeric_id: u32,
    pub admitted_entry_rule_id: u32,
    pub profile_generation_ref_id: u64,
    pub exception_numeric_handle: u32,
    pub profile: PortableProfileGenerationIdentityV1,
    pub resolved_executable: ResolvedAdministrativeExecutableIdentityV1,
    pub kernel_executable: ExactExecutableCandidateV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct GenerationSemantics {
    profile_id: Id128V1,
    role_handles: BTreeMap<String, u32>,
    process_state_handles: BTreeMap<String, (u32, u64)>,
    live_role_states: BTreeSet<(String, String)>,
}

type GenerationRows = BTreeMap<Vec<u8>, Vec<u8>>;

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

impl TryFrom<&ProfileCandidateArtifactV1> for GenerationSemantics {
    type Error = crate::Error;

    fn try_from(artifact: &ProfileCandidateArtifactV1) -> Result<Self> {
        let profile_id = parse_id("profile_id", &artifact.header.profile_id)?;
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let mut process_states = artifact
            .policy_document
            .process_state_definitions
            .iter()
            .map(|state| {
                let mut bits = 0_u64;
                for bit in &state.state_bits {
                    bits |= 1_u64.checked_shl(u32::from(*bit)).ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: format!(
                                "process state `{}` has an out-of-range state bit",
                                state.process_state_id
                            ),
                        }
                        .build()
                    })?;
                }
                Ok((state.process_state_id.clone(), (0, bits)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (index, (handle, _)) in process_states.values_mut().enumerate() {
            *handle = index as u32 + 1;
        }
        let mut live_role_states = artifact
            .policy_document
            .roles
            .iter()
            .map(|role| (role.role_id.clone(), role.default_process_state_id.clone()))
            .collect::<BTreeSet<_>>();
        live_role_states.extend(artifact.policy_document.native_transition_rules.iter().map(
            |transition| {
                (
                    transition.resulting_role_id.clone(),
                    transition.resulting_process_state_id.clone(),
                )
            },
        ));
        ensure!(
            live_role_states.iter().all(|(role, state)| {
                role_handles.contains_key(role) && process_states.contains_key(state)
            }),
            IdentityStateSnafu {
                reason: "generation semantics contain an unknown live role or process state",
            }
        );
        Ok(Self {
            profile_id,
            role_handles,
            process_state_handles: process_states,
            live_role_states,
        })
    }
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

const fn lifecycle(state: mithril_control::BindingLifecycleV1) -> BindingLifecycleStateV1 {
    match state {
        mithril_control::BindingLifecycleV1::Preparing => BindingLifecycleStateV1::Preparing,
        mithril_control::BindingLifecycleV1::Active => BindingLifecycleStateV1::Active,
        mithril_control::BindingLifecycleV1::Draining => BindingLifecycleStateV1::Draining,
        mithril_control::BindingLifecycleV1::Terminating => BindingLifecycleStateV1::Terminating,
        mithril_control::BindingLifecycleV1::Tombstoned => BindingLifecycleStateV1::Tombstoned,
    }
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

pub(crate) fn parse_id(name: &str, value: &str) -> Result<Id128V1> {
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::mem::offset_of;
    use std::path::{Path, PathBuf};

    use ed25519_dalek::SigningKey;
    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, CanonicalMountRootV1, EffectDecisionKeyV1, EffectDefaultKeyV1,
        EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExactFileObjectKeyV1,
        ExactObjectBindingStateV1, ExactObjectBindingV1, Id128V1, KernelEffectFamilyV1,
        KernelEffectOperationV1, PathGraphStateKeyV1, PathGraphTerminalV1,
        PathGraphTransitionKeyV1, PathTreeDenyKeyV1, PendingExecStateV1, PhysicalDecisionKindV1,
        PhysicalDecisionV1, PolicyGenerationModeV1, ProcessGenerationMigrationKeyV1,
        ProcessGenerationMigrationV1,
    };
    use mithril_control::{
        lower_kubernetes_policy, policy_custom_resource, EffectFamilyV1,
        FileExceptionGrantTemplateV1, LocalObjectSelectorV1, ObjectClassifierSelectorV1,
        PathSelectorTargetV1, PathSelectorV1, PathTreeDenyFloorV1, PolicyCompiler,
        PolicyDocumentV1, ProfileCandidateArtifactV1, ProfileModeV1, ProfileSealRequestV1,
        RegistryDigestsV1, RuleMatchV1, WorkloadProtectionPolicySpec,
    };
    use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes as _};

    use super::{
        build_process_generation_migrations, ensure_active_generation_unchanged,
        ensure_committed_generation, ensure_map_capacity, entry_admission_path_selector_ids,
        exception_counter_is_consistent, generation_retirement_needs_tombstone, handles,
        mount_cache_row_is_unreachable, parse_id, pending_exec_retains_generation_authority,
        read_abi_value, same_exact_file, GenerationBinding, GenerationSemantics, LoweredGeneration,
        MeasuredMountRouteV1, NativeTable, ProfileActivation, CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
    };
    use crate::error::IdentityStateSnafu;
    use crate::{
        ContainerKindV1, ExactDeviceConfig, ExactDeviceType, ExactFileObjectConfig,
        WorkloadBindingConfig,
    };

    #[test]
    fn mount_cache_retirement_only_selects_older_rows() -> crate::Result<()> {
        let key = |security_view_epoch: u64, cache_generation: u64| {
            let mut key = vec![0_u8; CANONICAL_MOUNT_CACHE_KEY_SIZE_V1];
            key[16..24].copy_from_slice(&security_view_epoch.to_ne_bytes());
            key[24..32].copy_from_slice(&cache_generation.to_ne_bytes());
            key
        };
        assert!(mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &key(6, 9),
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )?);
        assert!(mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &key(7, 8),
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )?);
        assert!(!mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &key(7, 9),
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )?);
        assert!(!mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &key(8, 10),
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )?);
        assert!(mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &key(8, 8),
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )?);
        assert!(mount_cache_row_is_unreachable(
            "canonical_mount_cache",
            &[0_u8; 32],
            CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
            7,
            9,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn live_process_migration_translates_generation_local_handles() -> crate::Result<()> {
        let profile_id = Id128V1::new(1, 2);
        let source = GenerationSemantics {
            profile_id,
            role_handles: BTreeMap::from([("worker".to_owned(), 1), ("zz-admin".to_owned(), 2)]),
            process_state_handles: BTreeMap::from([("base".to_owned(), (1, 0))]),
            live_role_states: BTreeSet::from([("worker".to_owned(), "base".to_owned())]),
        };
        let target = GenerationSemantics {
            profile_id,
            role_handles: BTreeMap::from([("aa-auditor".to_owned(), 1), ("worker".to_owned(), 2)]),
            process_state_handles: BTreeMap::from([("base".to_owned(), (1, 0))]),
            live_role_states: BTreeSet::from([("worker".to_owned(), "base".to_owned())]),
        };
        let rows = build_process_generation_migrations(
            &BTreeMap::from([(
                profile_id,
                ProfileActivation {
                    generation: 2,
                    bindings: BTreeMap::new(),
                },
            )]),
            &BTreeMap::from([(1, source), (2, target)]),
        )?;
        let key = ProcessGenerationMigrationKeyV1 {
            source_profile_generation_ref_id: 1,
            target_profile_generation_ref_id: 2,
            source_state_bits: 0,
            source_role_id: 1,
            source_process_state_vector_id: 1,
        };
        let Some(value) = rows.get(key.as_bytes()) else {
            return IdentityStateSnafu {
                reason: "the generation migration fixture has no expected row",
            }
            .fail();
        };
        assert_eq!(
            read_abi_value::<ProcessGenerationMigrationV1>(value, "process generation migration",)?,
            ProcessGenerationMigrationV1 {
                target_state_bits: 0,
                target_role_id: 2,
                target_process_state_vector_id: 1,
            }
        );
        Ok(())
    }

    #[test]
    fn live_process_migration_omits_removed_semantics() -> crate::Result<()> {
        let profile_id = Id128V1::new(1, 2);
        let source = GenerationSemantics {
            profile_id,
            role_handles: BTreeMap::from([("worker".to_owned(), 1)]),
            process_state_handles: BTreeMap::from([("base".to_owned(), (1, 0))]),
            live_role_states: BTreeSet::from([("worker".to_owned(), "base".to_owned())]),
        };
        let target = GenerationSemantics {
            profile_id,
            role_handles: BTreeMap::from([("replacement".to_owned(), 1)]),
            process_state_handles: BTreeMap::from([("base".to_owned(), (1, 0))]),
            live_role_states: BTreeSet::from([("replacement".to_owned(), "base".to_owned())]),
        };
        let rows = build_process_generation_migrations(
            &BTreeMap::from([(
                profile_id,
                ProfileActivation {
                    generation: 2,
                    bindings: BTreeMap::new(),
                },
            )]),
            &BTreeMap::from([(1, source), (2, target)]),
        )?;
        assert!(rows.is_empty());
        Ok(())
    }

    #[test]
    fn tombstoned_generation_resumes_row_deletion_without_a_second_transition() -> crate::Result<()>
    {
        assert!(generation_retirement_needs_tombstone(
            erebor_interceptor_abi::PolicyGenerationStateV1::Retiring,
        )?);
        assert!(!generation_retirement_needs_tombstone(
            erebor_interceptor_abi::PolicyGenerationStateV1::Tombstoned,
        )?);
        assert!(generation_retirement_needs_tombstone(
            erebor_interceptor_abi::PolicyGenerationStateV1::Active,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn only_in_flight_execs_retain_generation_authority() {
        for state in [
            PendingExecStateV1::Unknown,
            PendingExecStateV1::Preparing,
            PendingExecStateV1::CommitPending,
        ] {
            assert!(pending_exec_retains_generation_authority(state));
        }
        for state in [
            PendingExecStateV1::PrePonrFailed,
            PendingExecStateV1::PostPonrFatal,
            PendingExecStateV1::Success,
            PendingExecStateV1::OutcomeUnknown,
        ] {
            assert!(!pending_exec_retains_generation_authority(state));
        }
    }

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
    fn generation_shares_binding_rows() -> crate::Result<()> {
        use snafu::ResultExt as _;

        let (artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let expected = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let compile = |bindings: &[GenerationBinding<'_>]| {
            LoweredGeneration::compile(
                &artifact,
                1,
                bindings,
                Id128V1::new(1, 2),
                Id128V1::new(3, 4),
                3,
                1_800_000_000_000_000_000,
                100,
            )
        };
        let first = GenerationBinding {
            config: &binding,
            objects: std::slice::from_ref(&object),
            routes: &[],
            deferred: false,
        };
        let second = WorkloadBindingConfig {
            binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ..binding.clone()
        };
        assert!(compile(&[
            first,
            GenerationBinding {
                config: &second,
                objects: &[],
                routes: &[],
                deferred: false,
            },
        ])
        .is_err());
        let empty = WorkloadBindingConfig {
            execution_set_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ..second.clone()
        };
        let error = compile(&[
            first,
            GenerationBinding {
                config: &empty,
                objects: std::slice::from_ref(&object),
                routes: &[],
                deferred: false,
            },
        ])
        .err()
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "a binding reused another binding's selected cells",
            }
            .build()
        })?;
        assert!(error
            .to_string()
            .contains("selected no exact candidate cells"));
        let other = ExactFileObjectConfig {
            mount_namespace_inode: object.mount_namespace_inode + 1,
            inode: object.inode + 1,
            ..object.clone()
        };
        let generation = compile(&[
            first,
            GenerationBinding {
                config: &second,
                objects: std::slice::from_ref(&other),
                routes: &[],
                deferred: false,
            },
        ])?;
        assert_ne!(generation.descriptor.row_count, 0);
        assert_ne!(generation.descriptor.table_digest, [0; 32]);
        assert_eq!(generation.descriptor, expected.descriptor);
        assert_eq!(generation.semantics, expected.semantics);
        assert_eq!(
            generation.rows[NativeTable::EffectDecision]
                .iter()
                .collect::<Vec<_>>(),
            expected.rows[NativeTable::EffectDecision]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            generation.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>(),
            expected.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            generation.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>(),
            expected.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            generation.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>(),
            expected.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            generation.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>(),
            expected.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(generation.rows[NativeTable::FileObject].len(), 2);
        assert_eq!(generation.rows[NativeTable::MountRoot].len(), 2);
        for measured in [&object, &other] {
            let key = ExactFileObjectKeyV1 {
                profile_generation_ref_id: 1,
                mount_namespace_inode: measured.mount_namespace_inode,
                mount_id_unique: measured.selected_mount_id_unique,
                filesystem_device: measured.filesystem_device,
                inode: measured.inode,
                inode_generation: measured.inode_generation,
            };
            assert!(generation.rows[NativeTable::FileObject].contains_key(key.as_bytes()));
        }
        let mut document = artifact.policy_document;
        document.path_selectors.push(PathSelectorV1::exact(
            "a-missing",
            "/var/run/other-token",
            "PROJECTED_TOKEN",
        ));
        let key = SigningKey::from_bytes(&[9; 32]);
        let artifact = ProfileCandidateArtifactV1::sign(
            &document,
            PolicyCompiler
                .compile(&document)
                .context(crate::error::PolicySnafu)?,
            ProfileSealRequestV1 {
                signing_key_id: "test-key".to_owned(),
                issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                sequence_epoch: 1,
                issuer_sequence: 1,
                rollback_authorization_id: None,
                registry_digests: RegistryDigestsV1 {
                    provider_numeric_registry_bundle_digest: "1".repeat(64),
                    required_capability_schema_digest: "2".repeat(64),
                    source_selector_registry_digest: "3".repeat(64),
                    object_classifier_registry_digest: "4".repeat(64),
                    reason_code_registry_digest: "5".repeat(64),
                    correlation_package_registry_digest: "6".repeat(64),
                    provider_vocabulary_registry_digest: "7".repeat(64),
                },
            },
            &key,
        )
        .context(crate::error::PolicySnafu)?;
        artifact
            .verify_at(&key.verifying_key(), 1_800_000_000_000_000_000)
            .context(crate::error::PolicySnafu)?;
        assert!(matches!(
            LoweredGeneration::for_binding(
                &artifact,
                &binding,
                &[],
                Id128V1::new(1, 2),
                Id128V1::new(3, 4),
                3,
                1_800_000_000_000_000_000,
                100,
            ),
            Err(crate::Error::IdentityState { reason, .. })
                if reason == "exact selector `a-missing` has no proven object in the container"
        ));
        Ok(())
    }

    #[test]
    fn generation_rejects_candidate_changes() -> crate::Result<()> {
        use snafu::ResultExt as _;

        let (artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let key = SigningKey::from_bytes(&[9; 32]);
        artifact
            .clone()
            .verify(&key.verifying_key())
            .context(crate::error::PolicySnafu)?;
        let mut other = artifact.clone();
        other.compiled_profile.compiled_cells[0].errno = Some(-1);
        assert!(other.verify(&key.verifying_key()).is_err());
        let other = WorkloadBindingConfig {
            active_profile_generation_ref_id: 2,
            ..binding
        };
        assert!(LoweredGeneration::compile(
            &artifact,
            1,
            &[GenerationBinding {
                config: &other,
                objects: &[object],
                routes: &[],
                deferred: false,
            }],
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
    fn generation_rejects_row_conflicts() -> crate::Result<()> {
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let second = WorkloadBindingConfig {
            binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            execution_set_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ..binding.clone()
        };
        let mut cell = artifact.compiled_profile.compiled_cells[0].clone();
        cell.key.execution_set_id = second.execution_set_id.clone();
        cell.physical_result = mithril_control::CompiledPhysicalResultV1::AllowEffect;
        cell.errno = None;
        artifact.compiled_profile.compiled_cells.push(cell);
        LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let error = LoweredGeneration::compile(
            &artifact,
            1,
            &[
                GenerationBinding {
                    config: &binding,
                    objects: std::slice::from_ref(&object),
                    routes: &[],
                    deferred: false,
                },
                GenerationBinding {
                    config: &second,
                    objects: std::slice::from_ref(&object),
                    routes: &[],
                    deferred: false,
                },
            ],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )
        .err()
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "unequal exact rows were accepted in one generation",
            }
            .build()
        })?;
        assert!(error.to_string().contains("unequal exact-key conflict"));
        Ok(())
    }

    #[test]
    fn generation_requires_device_witness() -> crate::Result<()> {
        let (mut artifact, binding, mut object) = exact_artifact(ProfileModeV1::Protect)?;
        artifact.policy_document.path_selectors[0].device_class_id = Some("gpu".to_owned());
        let cell = &mut artifact.compiled_profile.compiled_cells[0];
        cell.key.effect_family = EffectFamilyV1::Device;
        cell.key.operation_id = "IOCTL".to_owned();
        cell.key.object_selector = "DEVICE:gpu:*".to_owned();
        object.device = Some(crate::ExactDeviceConfig {
            device_class_id: "gpu".to_owned(),
            device_type: crate::ExactDeviceType::Character,
            major: 226,
            minor: 128,
        });
        let second = WorkloadBindingConfig {
            binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            ..binding.clone()
        };
        let compile = |candidate: &ProfileCandidateArtifactV1, second: &WorkloadBindingConfig| {
            LoweredGeneration::compile(
                candidate,
                1,
                &[
                    GenerationBinding {
                        config: &binding,
                        objects: std::slice::from_ref(&object),
                        routes: &[],
                        deferred: false,
                    },
                    GenerationBinding {
                        config: second,
                        objects: std::slice::from_ref(&object),
                        routes: &[],
                        deferred: false,
                    },
                ],
                Id128V1::new(1, 2),
                Id128V1::new(3, 4),
                3,
                1_800_000_000_000_000_000,
                100,
            )
        };
        let generation = compile(&artifact, &second)?;
        assert_eq!(generation.rows[NativeTable::DeviceEffect].len(), 1);
        let second = WorkloadBindingConfig {
            execution_set_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ..second
        };
        let mut unavailable = artifact.clone();
        let mut selector = PathSelectorV1::path("other-gpu", "/dev/other-gpu", "PROJECTED_TOKEN");
        selector.device_class_id = Some("other-gpu".to_owned());
        unavailable.policy_document.path_selectors.push(selector);
        let mut cell = unavailable.compiled_profile.compiled_cells[0].clone();
        cell.key.execution_set_id = second.execution_set_id.clone();
        cell.key.object_selector = "DEVICE:other-gpu:*".to_owned();
        unavailable.compiled_profile.compiled_cells.push(cell);
        assert!(matches!(
            compile(&unavailable, &second),
            Err(crate::Error::IdentityState { reason, .. })
                if reason.contains("selected no exact candidate cells")
        ));
        Ok(())
    }

    #[test]
    fn generation_keeps_deferred_bindings() -> crate::Result<()> {
        let (artifact, mut binding) = entry_roles_artifact()?;
        binding.scheduled_binding_authority_id =
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned());
        let second = WorkloadBindingConfig {
            binding_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            scheduled_binding_authority_id: Some("cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned()),
            ..binding.clone()
        };
        let generation = LoweredGeneration::compile(
            &artifact,
            1,
            &[
                GenerationBinding {
                    config: &binding,
                    objects: &[],
                    routes: &[],
                    deferred: true,
                },
                GenerationBinding {
                    config: &second,
                    objects: &[],
                    routes: &[],
                    deferred: false,
                },
            ],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let staged = parse_id("binding_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
        let runtime = parse_id("binding_id", &second.binding_id)?;
        let rows = generation.rows[NativeTable::EntryAdmission]
            .keys()
            .map(|key| read_abi_value::<EntryAdmissionRuleKeyV1>(key, "test entry key"))
            .collect::<crate::Result<Vec<_>>>()?;
        assert_eq!(
            rows.iter().filter(|key| key.binding_id == staged).count(),
            6
        );
        assert_eq!(
            rows.iter().filter(|key| key.binding_id == runtime).count(),
            6
        );
        assert_eq!(rows.len(), 12);
        let expected = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert_eq!(generation.descriptor, expected.descriptor);
        Ok(())
    }

    #[test]
    fn generation_keeps_exception_deadlines() -> crate::Result<()> {
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let now = 1_800_000_000_000_000_000;
        let exception = mithril_control::ExceptionV1 {
            exception_id: "lease".to_owned(),
            exception_instance_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            changed_rule_ids: vec!["deny-projected-token-open".to_owned()],
            exact_subject: mithril_control::ExactExceptionSubjectSelectorV1 {
                protected_scope_ids: vec![binding.protected_scope_id.clone()],
                execution_set_ids: vec![binding.execution_set_id.clone()],
                entry_kind_ids: vec![mithril_control::EntryKindV1::ContainerStart],
                role_ids: vec!["converter".to_owned()],
                immutable_definition_digests: Vec::new(),
                exact_compiled_key_digests: Vec::new(),
            },
            authority_delta: mithril_control::PermittedAuthorityDeltaV1 {
                from_physical_result: "DENY_EFFECT".to_owned(),
                to_physical_result: "ALLOW_EFFECT".to_owned(),
                added_or_removed_operation_cells: Vec::new(),
                added_or_removed_transition_cells: Vec::new(),
                maximum_blast_radius: mithril_control::BlastRadiusLimitV1::Local {
                    permitted_target_selector_ids: Vec::new(),
                    process_count: 1,
                    execution_set_count: 1,
                    socket_count: 0,
                    node_count: 1,
                },
            },
            approver_principal_id: "reviewer".to_owned(),
            approval_proof_digest: "1".repeat(64),
            closed_reason_code: "APPROVED".to_owned(),
            valid_from_utc_ns: now - 1,
            valid_until_utc_ns: now + 100,
            consumption_scope: mithril_control::ExceptionConsumptionScopeV1::PerTargetNode,
            maximum_uses: 2,
            maximum_lifetime_ns: 40,
        };
        let unused = mithril_control::ExceptionV1 {
            exception_id: "unused".to_owned(),
            valid_until_utc_ns: now,
            ..exception.clone()
        };
        artifact.policy_document.exceptions = vec![exception, unused];
        artifact.compiled_profile.compiled_cells[0].consuming_exception_id =
            Some("lease".to_owned());
        let first = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            now,
            100,
        )?;
        let rows = first
            .rows
            .exceptions
            .iter()
            .map(|(key, row)| (key.clone(), row.state))
            .collect::<BTreeMap<_, _>>();
        let deadlines = first
            .rows
            .exceptions
            .iter()
            .map(|(key, row)| (key.clone(), row.deadline_utc_ns))
            .collect::<BTreeMap<_, _>>();
        let second = WorkloadBindingConfig {
            binding_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            ..binding.clone()
        };
        let generation = LoweredGeneration::compile(
            &artifact,
            1,
            &[
                GenerationBinding {
                    config: &binding,
                    objects: std::slice::from_ref(&object),
                    routes: &[],
                    deferred: false,
                },
                GenerationBinding {
                    config: &second,
                    objects: std::slice::from_ref(&object),
                    routes: &[],
                    deferred: false,
                },
            ],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            now,
            100,
        )?;
        assert_eq!(
            generation
                .rows
                .exceptions
                .iter()
                .map(|(key, row)| (key.clone(), row.state))
                .collect::<BTreeMap<_, _>>(),
            rows
        );
        assert_eq!(
            generation
                .rows
                .exceptions
                .iter()
                .map(|(key, row)| (key.clone(), row.deadline_utc_ns))
                .collect::<BTreeMap<_, _>>(),
            deadlines
        );
        assert_eq!(generation.rows[NativeTable::ExceptionBinding].len(), 1);
        assert_eq!(generation.rows.exceptions.len(), 1);
        let row = generation
            .rows
            .exceptions
            .values()
            .map(|row| row.state.as_bytes())
            .next()
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "test exception has no runtime state",
                }
                .build()
            })?;
        let state: super::ExceptionRuntimeStateV1 = read_abi_value(row, "test exception state")?;
        assert_eq!(state.deadline_boottime_ns, 140);
        assert_eq!(state.maximum_uses, 2);
        assert_eq!(state.consumed_uses, 0);
        assert_eq!(state.bound_profile_generation_refs, 1);
        assert_eq!(
            generation
                .rows
                .exceptions
                .values()
                .map(|row| &row.deadline_utc_ns)
                .next(),
            Some(&(now + 40))
        );
        let mut overflow = artifact.clone();
        overflow.policy_document.exceptions[0].valid_from_utc_ns = i64::MIN;
        overflow.policy_document.exceptions[0].valid_until_utc_ns = i64::MAX;
        assert!(matches!(
            LoweredGeneration::for_binding(
                &overflow,
                &binding,
                std::slice::from_ref(&object),
                Id128V1::new(1, 2),
                Id128V1::new(3, 4),
                3,
                i64::MIN,
                100,
            ),
            Err(crate::Error::IdentityState { reason, .. })
                if reason == "exception UTC lifetime overflow"
        ));
        let mut expired = artifact.clone();
        expired.policy_document.exceptions[0].valid_until_utc_ns = now;
        assert!(LoweredGeneration::for_binding(
            &expired,
            &binding,
            &[object],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            now,
            100,
        )
        .is_err());
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
        let terminal = generation.rows[NativeTable::PathTerminal]
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
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            composite_atom_id: terminal.composite_atom_id,
            exact_object_key_id: object.exact_object_key_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert_eq!(
            generation.rows[NativeTable::EffectDecision].keys().next(),
            Some(&expected.as_bytes().to_vec())
        );
        let object_key = generation.rows[NativeTable::FileObject]
            .keys()
            .next()
            .ok_or_else(|| {
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
            generation.rows[NativeTable::MountView].keys().next(),
            Some(&object.mount_namespace_inode.to_ne_bytes().to_vec())
        );
        let expected_binding = ExactObjectBindingV1 {
            profile_generation_ref_id: 1,
            exact_object_key_id: object.exact_object_key_id,
            composite_atom_id: terminal.composite_atom_id,
            state: ExactObjectBindingStateV1::ReadBack,
            reserved: [0; 7],
        };
        assert!(generation.rows[NativeTable::FileObject]
            .values()
            .any(|binding| binding == expected_binding.as_bytes()));

        assert!(LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )
        .is_err());
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
        let decision = generation.rows[NativeTable::EffectDecision]
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
        assert!(generation.rows[NativeTable::ExceptionBinding].is_empty());
        assert!(generation.rows.exceptions.is_empty());
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
            generation.rows[NativeTable::EffectDecision]
                .values()
                .next()
                .map(|value| value[0]),
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

        assert_eq!(generation.rows[NativeTable::EffectDecision].len(), 1);
        Ok(())
    }

    #[test]
    fn independent_entries_lower_to_distinct_kernel_role_transitions() -> crate::Result<()> {
        let (artifact, binding) = entry_roles_artifact()?;
        let objects = entry_role_objects(&artifact, &binding)?;
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert_eq!(generation.rows[NativeTable::EntryAdmission].len(), 6);
        assert!(!generation.rows[NativeTable::MountView].is_empty());
        assert_eq!(
            generation.rows[NativeTable::MountView].len(),
            generation.rows[NativeTable::MountEpoch].len()
        );
        assert_eq!(
            generation.rows[NativeTable::MountView].len(),
            generation.rows[NativeTable::MountLock].len()
        );
        let rows = generation.rows[NativeTable::EntryAdmission]
            .iter()
            .map(|(key, value)| {
                Ok((
                    EntryAdmissionRuleKeyV1::try_read_from_bytes(key).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!("entry admission key has the wrong ABI: {error}"),
                        }
                        .build()
                    })?,
                    EntryAdmissionRuleV1::try_read_from_bytes(value).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!("entry admission value has the wrong ABI: {error}"),
                        }
                        .build()
                    })?,
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let admitted_ids = rows
            .iter()
            .map(|(_, value)| value.admitted_entry_rule_id)
            .collect::<BTreeSet<_>>();
        let target_roles = rows
            .iter()
            .map(|(_, value)| value.target_role_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(admitted_ids.len(), 6);
        assert_eq!(target_roles.len(), 6);
        assert_eq!(
            rows.iter()
                .filter(|(key, _)| key.source_role_id == binding.initial_role_id)
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|(key, _)| key.source_role_id == binding.external_role_id)
                .count(),
            5
        );
        assert_eq!(generation.administrative_plans.len(), 1);
        assert_ne!(generation.administrative_plans[0].admitted_entry_rule_id, 0);
        assert!(!generation.administrative_plans.is_empty());
        Ok(())
    }

    #[test]
    fn recovery_uses_the_normal_container_start_rule() -> crate::Result<()> {
        let (artifact, recovery_binding) = entry_roles_artifact()?;
        let objects = entry_role_objects(&artifact, &recovery_binding)?;
        let recovered = LoweredGeneration::for_binding(
            &artifact,
            &recovery_binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let mut held_binding = recovery_binding.clone();
        held_binding.arm_initial_root = true;
        let held = LoweredGeneration::for_binding(
            &artifact,
            &held_binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;

        assert_eq!(
            recovered.rows[NativeTable::EntryAdmission]
                .iter()
                .collect::<Vec<_>>(),
            held.rows[NativeTable::EntryAdmission]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            recovered.rows[NativeTable::FileObject]
                .iter()
                .collect::<Vec<_>>(),
            held.rows[NativeTable::FileObject]
                .iter()
                .collect::<Vec<_>>()
        );
        assert!(recovered.rows[NativeTable::FileObject].is_empty());
        Ok(())
    }

    #[test]
    fn exact_linux_capability_uses_the_existing_effect_default_map() -> crate::Result<()> {
        let (mut artifact, binding) = entry_roles_artifact()?;
        let objects = entry_role_objects(&artifact, &binding)?;
        let mut capability = artifact.compiled_profile.compiled_cells[0].clone();
        capability.key.role_id = "application".to_owned();
        capability.key.effect_family = EffectFamilyV1::Privilege;
        capability.key.operation_id = "CAPABILITY".to_owned();
        capability.key.object_selector = "SECURITY:LINUX_CAPABILITY:21".to_owned();
        capability.physical_result = mithril_control::CompiledPhysicalResultV1::AllowEffect;
        capability.errno = None;
        let capability_state = capability.key.process_state_id.clone();
        let capability_lifecycle = capability.key.binding_lifecycle;
        artifact.compiled_profile.compiled_cells.push(capability);

        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let application_role = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        )["application"];
        let process_state = handles(
            artifact
                .policy_document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str()),
        )[&capability_state];
        let expected_key = EffectDefaultKeyV1 {
            profile_generation_ref_id: binding.active_profile_generation_ref_id,
            active_role_id: application_role,
            effect_family: KernelEffectFamilyV1::Privilege as u16,
            operation: KernelEffectOperationV1::Capability as u16,
            composite_atom_id: 22,
            process_state_vector_id: process_state,
            binding_lifecycle_state: super::lifecycle(capability_lifecycle),
            reserved_tail: [0; 3],
        };
        assert!(generation.rows[NativeTable::EffectDefault]
            .iter()
            .any(|(key, value)| {
                key == expected_key.as_bytes()
                    && PhysicalDecisionV1::try_read_from_bytes(value)
                        .is_ok_and(|decision| decision.decision == PhysicalDecisionKindV1::Allow)
            }));
        assert!(LoweredGeneration::composite_handles(&artifact)
            .keys()
            .all(|selector| !selector.starts_with("SECURITY:LINUX_CAPABILITY:")));
        Ok(())
    }

    #[test]
    fn entry_admission_does_not_require_resolved_objects() -> crate::Result<()> {
        let (artifact, mut binding) = entry_roles_artifact()?;
        binding.arm_initial_root = true;
        let objects = entry_role_objects(&artifact, &binding)?;
        assert!(objects.len() > 1);
        let generation = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &objects[..objects.len() - 1],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert!(generation.rows[NativeTable::FileObject].is_empty());
        assert!(generation.rows[NativeTable::EntryAdmission]
            .values()
            .all(|value| {
                EntryAdmissionRuleV1::try_read_from_bytes(value).is_ok_and(|rule| {
                    rule.exact_object_key_id == 0
                        && rule.executable_object == ExactFileObjectKeyV1::default()
                })
            }));
        Ok(())
    }

    #[test]
    fn prepared_entry_rows_keep_logical_authority_without_inode_proof() -> crate::Result<()> {
        let (artifact, mut binding) = entry_roles_artifact()?;
        binding.arm_initial_root = true;
        let staged = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert_eq!(staged.rows[NativeTable::EntryAdmission].len(), 6);
        assert!(staged.rows[NativeTable::EntryAdmission]
            .values()
            .all(|value| {
                EntryAdmissionRuleV1::try_read_from_bytes(value)
                    .is_ok_and(|rule| rule.exact_object_key_id == 0)
            }));

        let mut objects = entry_role_objects(&artifact, &binding)?;
        let shared = objects[0].clone();
        for object in &mut objects[1..] {
            object.mount_namespace_inode = shared.mount_namespace_inode;
            object.mount_id_unique = shared.mount_id_unique;
            object.selected_mount_id_unique = shared.selected_mount_id_unique;
            object.filesystem_device = shared.filesystem_device;
            object.inode = shared.inode;
            object.inode_generation = shared.inode_generation;
        }
        let active = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert_eq!(
            staged.descriptor.table_digest,
            active.descriptor.table_digest
        );
        assert_eq!(staged.descriptor.row_count, active.descriptor.row_count);
        assert!(active.rows[NativeTable::EntryAdmission]
            .values()
            .all(|value| {
                EntryAdmissionRuleV1::try_read_from_bytes(value)
                    .is_ok_and(|rule| rule.exact_object_key_id == 0)
            }));

        let retry_binding = WorkloadBindingConfig {
            binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            container_id: "b".repeat(64),
            ..binding
        };
        let retry = LoweredGeneration::for_binding(
            &artifact,
            &retry_binding,
            &objects,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        assert_eq!(
            staged.descriptor.table_digest,
            retry.descriptor.table_digest
        );
        assert_eq!(staged.descriptor.row_count, retry.descriptor.row_count);
        Ok(())
    }

    #[test]
    fn runtime_entry_rows_remain_on_scheduled_authority_until_final_exec() -> crate::Result<()> {
        let (artifact, mut binding) = entry_roles_artifact()?;
        let authority = Id128V1::new(20, 21);
        binding.scheduled_binding_authority_id = Some(
            uuid::Uuid::from_bytes(authority.to_be_bytes())
                .hyphenated()
                .to_string(),
        );
        binding.arm_initial_root = true;
        let objects = entry_role_objects(&artifact, &binding)?;
        let staged = LoweredGeneration::for_binding_with_mount_routes(
            &artifact,
            &binding,
            &objects,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
            true,
        )?;
        assert!(staged.rows[NativeTable::EntryAdmission]
            .iter()
            .all(|(key, value)| {
                EntryAdmissionRuleKeyV1::try_read_from_bytes(key).is_ok_and(|key| {
                    key.binding_id == authority
                        && EntryAdmissionRuleV1::try_read_from_bytes(value)
                            .is_ok_and(|rule| rule.exact_object_key_id == 0)
                })
            }));

        let final_rows = LoweredGeneration::for_binding_with_mount_routes(
            &artifact,
            &binding,
            &objects,
            &[],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
            false,
        )?;
        let runtime_binding = parse_id("binding_id", &binding.binding_id)?;
        assert!(final_rows.rows[NativeTable::EntryAdmission]
            .iter()
            .all(|(key, value)| {
                EntryAdmissionRuleKeyV1::try_read_from_bytes(key).is_ok_and(|key| {
                    key.binding_id == runtime_binding
                        && EntryAdmissionRuleV1::try_read_from_bytes(value)
                            .is_ok_and(|rule| rule.exact_object_key_id == 0)
                })
            }));
        assert_eq!(
            staged.descriptor.table_digest,
            final_rows.descriptor.table_digest
        );
        assert_eq!(staged.descriptor.row_count, final_rows.descriptor.row_count);
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
        assert!(generation.rows[NativeTable::FileObject].is_empty());
        assert!(generation.rows[NativeTable::MountView].is_empty());
        assert!(generation.rows[NativeTable::EffectDecision].is_empty());
        assert!(generation.rows[NativeTable::PathTerminal]
            .values()
            .any(|value| PathGraphTerminalV1::read_from_bytes(value)
                .is_ok_and(|terminal| terminal.exact_object_required == 0)));
        assert_eq!(generation.rows[NativeTable::EffectDefault].len(), 1);
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

        assert!(generation.rows[NativeTable::FileObject].is_empty());
        assert!(generation.rows[NativeTable::MountView].is_empty());
        assert!(generation.rows[NativeTable::EffectDecision].is_empty());
        let terminal = generation.rows[NativeTable::PathTerminal]
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
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            composite_atom_id: terminal.composite_atom_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert!(generation.rows[NativeTable::EffectDefault].contains_key(expected.as_bytes()));
        Ok(())
    }

    #[test]
    fn execution_path_does_not_inherit_an_exact_file_requirement() -> crate::Result<()> {
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .path_selectors
            .push(PathSelectorV1::path(
                "projected-token-exec",
                "/var/run/token",
                "PROJECTED_TOKEN",
            ));
        let mut execution_rule = artifact.policy_document.rules[0].clone();
        execution_rule.rule_id = "execute-projected-token".to_owned();
        let RuleMatchV1::LocalPreEffect(effect) = &mut execution_rule.rule_match else {
            unreachable!("fixture contains one local rule")
        };
        effect.effect_families = vec![EffectFamilyV1::Exec];
        effect.operation_ids = vec!["EXECUTE".to_owned()];
        effect.object = LocalObjectSelectorV1::PathSelectors {
            path_selector_ids: vec!["projected-token-exec".to_owned()],
        };
        artifact.policy_document.rules.push(execution_rule);
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
        assert_eq!(generation.rows[NativeTable::EffectDecision].len(), 1);
        assert_eq!(generation.rows[NativeTable::EffectDefault].len(), 1);
        let terminal = generation.rows[NativeTable::PathTerminal]
            .values()
            .find_map(|value| PathGraphTerminalV1::read_from_bytes(value).ok())
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "test generation has no shared path terminal".to_owned(),
                }
                .build()
            })?;
        let expected = EffectDefaultKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 1,
            effect_family: KernelEffectFamilyV1::Exec as u16,
            operation: KernelEffectOperationV1::Execute as u16,
            composite_atom_id: terminal.composite_atom_id,
            process_state_vector_id: 1,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        assert!(generation.rows[NativeTable::EffectDefault].contains_key(expected.as_bytes()));
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
        let binding_id = parse_id("binding_id", &binding.binding_id)?;
        let mut activation = ProfileActivation {
            generation: binding.active_profile_generation_ref_id,
            bindings: BTreeMap::new(),
        };
        activation.add_binding(binding_id, &binding)?;

        let mut second = binding.clone();
        second.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
        let second_id = parse_id("binding_id", &second.binding_id)?;
        activation.add_binding(second_id, &second)?;
        assert_eq!(activation.bindings.len(), 2);

        second.active_profile_generation_ref_id += 1;
        assert!(activation.add_binding(second_id, &second).is_err());
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
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        artifact.compiled_profile.compiled_cells[0]
            .key
            .object_selector = "DEFAULT".to_owned();
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

        assert!(generation.rows[NativeTable::EffectDecision].is_empty());
        let key = generation.rows[NativeTable::EffectDefault]
            .keys()
            .next()
            .ok_or_else(|| {
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
                rule_id: "secret-tree-deny".to_owned(),
                role_id: "converter".to_owned(),
                path: "/var/*/secrets".to_owned(),
                operation_ids: ["CREATE", "LINK", "OPEN_READ"].map(str::to_owned).to_vec(),
            });
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let (tables, reconciliation) = LoweredGeneration::lower_path_tables(
            &artifact,
            &binding,
            &[],
            &[],
            &composite_handles,
            &role_handles,
        )?;
        let open_read_mask = 1_u64 << KernelEffectOperationV1::OpenRead as u16;

        assert!(tables[NativeTable::MountRoot].is_empty());
        assert!(reconciliation.is_empty());
        assert!(!tables[NativeTable::PathExact].is_empty());
        assert!(tables[NativeTable::PathTerminal].values().all(|value| {
            PathGraphTerminalV1::read_from_bytes(value)
                .is_ok_and(|terminal| terminal.composite_atom_id != 0)
        }));
        assert!(tables[NativeTable::PathTreeDenial]
            .iter()
            .any(|(key, value)| {
                let Ok(mask) = <[u8; 8]>::try_from(value.as_slice()).map(u64::from_ne_bytes) else {
                    return false;
                };
                PathTreeDenyKeyV1::read_from_bytes(key).is_ok_and(|key| {
                    key.active_role_id == role_handles["converter"] && mask & open_read_mask != 0
                })
            }));
        Ok(())
    }

    #[test]
    fn known_mount_route_is_independent_of_kubernetes_mount_order() -> crate::Result<()> {
        let (mut artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .path_tree_deny_floors
            .push(PathTreeDenyFloorV1 {
                rule_id: "secret-tree-deny".to_owned(),
                role_id: "converter".to_owned(),
                path: "/home/secret".to_owned(),
                operation_ids: vec!["OPEN_READ".to_owned()],
            });
        let route = |mountpoint_components: Vec<Vec<u8>>| MeasuredMountRouteV1 {
            binding_id: binding.binding_id.clone(),
            mount_view_root_pid: 10,
            mount_topology_generation: 1,
            route: crate::exact_object::LiveMountRootRouteV1 {
                mount_namespace_inode: 7,
                mountpoint_components,
                filesystem_device: 8,
                root_inode: 9,
                selected_mount_id_unique: 12,
                mount_snapshot_digest_id: 13,
            },
        };
        let protected = route(vec![b"home".to_vec(), b"secret".to_vec()]);
        let alias = route(vec![b"home".to_vec(), b"attack".to_vec()]);
        let mut unrelated = route(vec![b"dev".to_vec()]);
        unrelated.route.filesystem_device = 10;
        unrelated.route.root_inode = 11;
        unrelated.route.selected_mount_id_unique = 14;
        unrelated.route.mount_snapshot_digest_id = 15;
        let baseline = LoweredGeneration::for_binding(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
        )?;
        let routed = LoweredGeneration::for_binding_with_mount_routes(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            &[protected.clone(), alias.clone(), unrelated.clone()],
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
            false,
        )?;
        let refreshed_routes =
            [protected.clone(), alias.clone(), unrelated.clone()].map(|mut measured| {
                measured.route.mount_snapshot_digest_id = 16;
                measured
            });
        let refreshed = LoweredGeneration::for_binding_with_mount_routes(
            &artifact,
            &binding,
            std::slice::from_ref(&object),
            &refreshed_routes,
            Id128V1::new(1, 2),
            Id128V1::new(3, 4),
            3,
            1_800_000_000_000_000_000,
            100,
            false,
        )?;
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let (first, _) = LoweredGeneration::lower_path_tables(
            &artifact,
            &binding,
            &[],
            &[protected.clone(), alias.clone(), unrelated.clone()],
            &composite_handles,
            &role_handles,
        )?;
        let (second, _) = LoweredGeneration::lower_path_tables(
            &artifact,
            &binding,
            &[],
            &[unrelated, alias, protected],
            &composite_handles,
            &role_handles,
        )?;

        assert_eq!(baseline.descriptor, routed.descriptor);
        assert_eq!(
            baseline.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>(),
            routed.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            baseline.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>(),
            routed.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            baseline.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>(),
            routed.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            baseline.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>(),
            routed.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(routed.descriptor, refreshed.descriptor);
        assert_eq!(
            routed.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::PathExact]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            routed.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::PathWildcard]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            routed.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::PathTerminal]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            routed.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::PathTreeDenial]
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            routed.rows[NativeTable::MountRoot]
                .keys()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::MountRoot]
                .keys()
                .collect::<Vec<_>>()
        );
        assert_ne!(
            routed.rows[NativeTable::MountRoot]
                .iter()
                .collect::<Vec<_>>(),
            refreshed.rows[NativeTable::MountRoot]
                .iter()
                .collect::<Vec<_>>()
        );
        let refreshed_digests = refreshed.rows[NativeTable::MountRoot]
            .values()
            .filter_map(|value| CanonicalMountRootV1::read_from_bytes(value).ok())
            .map(|root| root.snapshot_digest_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(refreshed_digests, BTreeSet::from([16, 60]));
        assert_eq!(
            first[NativeTable::MountRoot].iter().collect::<Vec<_>>(),
            second[NativeTable::MountRoot].iter().collect::<Vec<_>>()
        );
        assert_eq!(first[NativeTable::MountRoot].len(), 2);
        let roots = first[NativeTable::MountRoot]
            .values()
            .filter_map(|value| CanonicalMountRootV1::read_from_bytes(value).ok())
            .collect::<Vec<_>>();
        let root = roots
            .iter()
            .find(|root| root.graph_prefix_state_count > 0)
            .copied()
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "known mount route test has no route row".to_owned(),
                }
                .build()
            })?;
        assert!(roots.iter().any(|root| {
            root.selected_mount_id_unique == 14 && root.graph_prefix_state_count == 0
        }));
        let open_read_mask = 1_u64 << KernelEffectOperationV1::OpenRead as u16;
        assert!(first[NativeTable::PathTreeDenial]
            .iter()
            .any(|(key, value)| {
                let Ok(mask) = <[u8; 8]>::try_from(value.as_slice()).map(u64::from_ne_bytes) else {
                    return false;
                };
                PathTreeDenyKeyV1::read_from_bytes(key).is_ok_and(|key| {
                    root.graph_prefix_state_ids[..root.graph_prefix_state_count as usize]
                        .contains(&key.state_id)
                        && key.active_role_id == role_handles["converter"]
                        && mask & open_read_mask != 0
                })
            }));
        Ok(())
    }

    #[test]
    fn authoritative_exact_only_view_keeps_its_canonical_root_route() -> crate::Result<()> {
        let (artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        assert!(artifact.policy_document.path_tree_deny_floors.is_empty());
        let routes = super::NodePolicyGenerationOwner::authoritative_mount_routes(
            &binding,
            10,
            17,
            vec![crate::exact_object::LiveMountRootRouteV1 {
                mount_namespace_inode: 41,
                mountpoint_components: Vec::new(),
                filesystem_device: 8,
                root_inode: 9,
                selected_mount_id_unique: 12,
                mount_snapshot_digest_id: 13,
            }],
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].binding_id, binding.binding_id);
        assert_eq!(routes[0].mount_view_root_pid, 10);
        assert_eq!(routes[0].mount_topology_generation, 17);
        Ok(())
    }

    #[test]
    fn mount_namespace_guard_does_not_create_an_exact_reconciliation_root() -> crate::Result<()> {
        let (artifact, binding, object) = exact_artifact(ProfileModeV1::Protect)?;
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let (mut tables, reconciliation) = LoweredGeneration::lower_path_tables(
            &artifact,
            &binding,
            &[],
            &[],
            &composite_handles,
            &role_handles,
        )?;
        tables.add_mount_namespace_guards(std::iter::once(&object))?;

        assert_eq!(tables[NativeTable::MountView].len(), 1);
        assert_eq!(tables[NativeTable::MountEpoch].len(), 1);
        assert_eq!(tables[NativeTable::MountLock].len(), 1);
        assert!(tables[NativeTable::MountRoot].is_empty());
        assert!(reconciliation.is_empty());
        Ok(())
    }

    #[test]
    fn path_graph_rows_are_scoped_to_the_bound_generation() -> crate::Result<()> {
        let (mut artifact, binding, _) = exact_artifact(ProfileModeV1::Protect)?;
        artifact
            .policy_document
            .path_tree_deny_floors
            .push(PathTreeDenyFloorV1 {
                rule_id: "secret-tree-deny".to_owned(),
                role_id: "converter".to_owned(),
                path: "/var/**/secrets".to_owned(),
                operation_ids: vec!["OPEN_READ".to_owned()],
            });
        let composite_handles = LoweredGeneration::composite_handles(&artifact);
        let role_handles = handles(
            artifact
                .policy_document
                .roles
                .iter()
                .map(|role| role.role_id.as_str()),
        );
        let (first, _) = LoweredGeneration::lower_path_tables(
            &artifact,
            &binding,
            &[],
            &[],
            &composite_handles,
            &role_handles,
        )?;
        let second_binding = WorkloadBindingConfig {
            active_profile_generation_ref_id: 2,
            ..binding
        };
        let (second, _) = LoweredGeneration::lower_path_tables(
            &artifact,
            &second_binding,
            &[],
            &[],
            &composite_handles,
            &role_handles,
        )?;

        assert!(first[NativeTable::PathExact].keys().all(|key| {
            PathGraphTransitionKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 1)
        }));
        assert!(second[NativeTable::PathExact].keys().all(|key| {
            PathGraphTransitionKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 2)
        }));
        assert!(first[NativeTable::PathTerminal].keys().all(|key| {
            PathGraphStateKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 1)
        }));
        assert!(second[NativeTable::PathTerminal].keys().all(|key| {
            PathGraphStateKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 2)
        }));
        assert!(first[NativeTable::PathTreeDenial].keys().all(|key| {
            PathTreeDenyKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 1)
        }));
        assert!(second[NativeTable::PathTreeDenial].keys().all(|key| {
            PathTreeDenyKeyV1::read_from_bytes(key)
                .is_ok_and(|key| key.profile_generation_ref_id == 2)
        }));
        assert!(first[NativeTable::PathExact]
            .keys()
            .all(|key| !second[NativeTable::PathExact].contains_key(key)));
        assert!(first[NativeTable::PathTerminal]
            .keys()
            .all(|key| !second[NativeTable::PathTerminal].contains_key(key)));
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

    pub(super) fn entry_roles_artifact(
    ) -> crate::Result<(ProfileCandidateArtifactV1, WorkloadBindingConfig)> {
        let spec = WorkloadProtectionPolicySpec::parse(
            Path::new("kubernetes-entry-roles-v1.yaml"),
            include_bytes!("../../mithril-control/tests/fixtures/kubernetes-entry-roles-v1.yaml"),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        let mut resource = policy_custom_resource("worker", "default", spec).map_err(|source| {
            crate::Error::Policy {
                source,
                location: snafu::Location::default(),
            }
        })?;
        resource.metadata.uid = Some("30000000-0000-4000-8000-000000000001".to_owned());
        resource.metadata.generation = Some(7);
        let document = lower_kubernetes_policy(
            &resource,
            "10000000-0000-4000-8000-000000000001",
            "10000000-0000-4000-8000-000000000002",
            "10000000-0000-4000-8000-000000000003",
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        let compiled =
            PolicyCompiler
                .compile(&document)
                .map_err(|source| crate::Error::Policy {
                    source,
                    location: snafu::Location::default(),
                })?;
        let artifact = ProfileCandidateArtifactV1::sign(
            &document,
            compiled,
            ProfileSealRequestV1 {
                signing_key_id: "test-key".to_owned(),
                issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                sequence_epoch: 1,
                issuer_sequence: 1,
                rollback_authorization_id: None,
                registry_digests: RegistryDigestsV1 {
                    provider_numeric_registry_bundle_digest: "1".repeat(64),
                    required_capability_schema_digest: "2".repeat(64),
                    source_selector_registry_digest: "3".repeat(64),
                    object_classifier_registry_digest: "4".repeat(64),
                    reason_code_registry_digest: "5".repeat(64),
                    correlation_package_registry_digest: "6".repeat(64),
                    provider_vocabulary_registry_digest: "7".repeat(64),
                },
            },
            &SigningKey::from_bytes(&[9; 32]),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        let role_handles = super::handles(document.roles.iter().map(|role| role.role_id.as_str()));
        let binding = WorkloadBindingConfig {
            binding_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            scheduled_binding_authority_id: None,
            scheduled_target_digest: None,
            execution_set_id: document.protected_universe.execution_set_ids[0].clone(),
            protected_scope_id: document.protected_universe.protected_scope_ids[0].clone(),
            workload_selector_id: "container-0".to_owned(),
            profile_id: document.metadata.profile_id.clone(),
            container_id: "a".repeat(64),
            namespace: "default".to_owned(),
            cluster_uid: "10000000-0000-4000-8000-000000000002".to_owned(),
            namespace_uid: "10000000-0000-4000-8000-000000000003".to_owned(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::from([("app".to_owned(), "worker".to_owned())]),
            pod_uid: "pod".to_owned(),
            sandbox_id: "sandbox".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            container_kind: ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: Some(PathBuf::from("/sys/fs/cgroup/test")),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 1,
            initial_role_id: role_handles["application"],
            external_role_id: role_handles["runtime-external"],
            arm_initial_root: false,
        };
        Ok((artifact, binding))
    }

    pub(super) fn entry_role_objects(
        artifact: &ProfileCandidateArtifactV1,
        binding: &WorkloadBindingConfig,
    ) -> crate::Result<Vec<ExactFileObjectConfig>> {
        let selector_ids = entry_admission_path_selector_ids(artifact, binding)?;
        artifact
            .policy_document
            .path_selectors
            .iter()
            .filter(|selector| selector_ids.contains(&selector.path_selector_id))
            .enumerate()
            .map(|(index, selector)| {
                let path = selector.path_expression();
                let components = path
                    .strip_prefix('/')
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "entry test selector path is not canonical".to_owned(),
                        }
                        .build()
                    })?
                    .split('/')
                    .map(|component| hex::encode(component.as_bytes()))
                    .collect::<Vec<_>>();
                Ok(ExactFileObjectConfig {
                    profile_generation_ref_id: 1,
                    exact_object_key_id: selector.kernel_handle(),
                    object_class_id: selector.object_class_id.clone(),
                    mount_namespace_inode: 10,
                    mount_id_unique: 20,
                    filesystem_device: 30,
                    inode: 100 + index as u64,
                    inode_generation: 1,
                    device: None,
                    mount_relative_component_count: components.len() as u16,
                    canonical_component_hex: components,
                    mount_root_filesystem_device: 30,
                    mount_root_inode: 2,
                    selected_mount_id_unique: 20,
                    mount_snapshot_digest_id: 60,
                    mount_topology_generation: 1,
                    mount_view_root_pid: 1,
                })
            })
            .collect()
    }
}
