mod child;
mod fixture_syscalls;
mod mailbox;
mod network;
mod runc;
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::mem::{offset_of, size_of};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use erebor_interceptor::{EffectObservationReader, KernelHost, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, ExceptionReceiptStateV1, ExceptionRuntimeStateKeyV1,
    ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1, ExceptionUseReceiptV1, Id128V1,
    IpcOperationV1, KernelEffectFamilyV1, KernelEffectOperationV1, MountReconciliationProposalV1,
    MountSecurityViewStateV1, MountTopologyStateV1, PolicyGenerationStateV1,
    ProfileGenerationDescriptorV1, QualificationResultV1, MAX_CANONICAL_PATH_COMPONENTS_V1,
};
use mithril_control::{
    EffectFamilyV1, PathSelectorV1, PathTreeDenyFloorV1, PolicyArtifactOwner, PolicyDispositionV1,
    PolicyDocumentV1, ProfileSealRequestV1,
};
use mithril_node::{
    CoverageGapReasonV1, EffectObservationHealth, EffectObservationStore, EvidenceIdV1,
    EvidenceWalLimits, ExactFileObjectResolver, NativeSecurityStateOwner,
    NodePolicyGenerationOwner, ObservationCanonicalizer, WorkloadBindingOwner,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use self::child::{EffectProcessFixture, HardClosedOperation};
use self::support::{
    effect_binding, effect_node_config, effect_peer_binding, effect_propagation_binding,
    global_mount_view_is_dirty, health_delta, inode_generation, mount_view_is_dirty,
    mount_views_are_clean, sample_observation_health, wait_for_effect, wait_for_exact_effect,
    wait_for_exact_io_uring_effect, wait_for_path_exec_effect, wait_for_reason,
    wait_for_unsupported_effect, ExternalMountNamespace,
};
use crate::capability::{BpfPrototypeCompiler, CompileRecordV1};
use crate::error::{
    InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::fixture::HuggingFaceFixture;
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::LatencyDistributionV1;
use crate::Result;

pub use child::{run_effect_child, run_mount_move_child, run_mount_setattr_child};
pub use network::{
    run_network_peer_server, NetworkFixtureResultV1, NetworkPeerServerResultV1,
    NetworkPeerTargetV1, NetworkPhysicalProbeBundleV1, NetworkTestRunner, NETWORK_PEER_DENIED_PORT,
    NETWORK_PEER_TCP_PORT, NETWORK_PEER_UDP_PORT,
};
pub use runc::RuncEntryRoleRuntimeProbeV1;

pub(super) const PROFILE_GENERATION_REF_ID: u64 = 1;
const NEXT_PROFILE_GENERATION_REF_ID: u64 = 2;
const QUALIFIED_TIOCGPTN_IOCTL: u32 = 2_147_767_344;
const QUALIFIED_TIOCGPTPEER_IOCTL: u32 = 0x5441;
const BOUNDED_EXCEPTION_INSTANCE_ID: Id128V1 =
    Id128V1::new(0x8888_8888_8888_4888, 0x8888_8888_8888_8889);
const EXPIRED_EXCEPTION_INSTANCE_ID: Id128V1 =
    Id128V1::new(0x8888_8888_8888_4888, 0x8888_8888_8888_888a);

fn reconcile_mount_views_until_clean(
    policy: &NodePolicyGenerationOwner,
    host: &mut KernelHost,
    mount_namespaces: &BTreeSet<u32>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        policy.reconcile_mount_views(host).context(NodeSnafu)?;
        if mount_views_are_clean(host, mount_namespaces)? {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("mount_security_views"),
                reason:
                    "mount reconciliation did not restore clean views before an exact-effect check",
            }
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn process_descriptor_set(pid: u32) -> Result<BTreeSet<u32>> {
    let path = PathBuf::from(format!("/proc/{pid}/fd"));
    let mut descriptors = BTreeSet::new();
    for entry in fs::read_dir(&path).context(IoSnafu { path: &path })? {
        let entry = entry.context(IoSnafu { path: &path })?;
        if let Some(descriptor) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            descriptors.insert(descriptor);
        }
    }
    Ok(descriptors)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EffectHealthV1 {
    pub attempted: u64,
    pub suppressed: u64,
    pub requested: u64,
    pub emitted: u64,
    pub lost: u64,
    pub classifier_miss_count: u64,
    pub unresolved: u64,
    pub decoder_errors: u64,
    pub evidence_errors: u64,
    pub wal_capacity_blocked: u64,
    pub reader_queue_dropped_events: u64,
}

impl From<EffectObservationHealth> for EffectHealthV1 {
    fn from(value: EffectObservationHealth) -> Self {
        Self {
            attempted: value.attempted,
            suppressed: value.suppressed,
            requested: value.requested,
            emitted: value.emitted,
            lost: value.lost,
            classifier_miss_count: value.classifier_miss_count,
            unresolved: value.unresolved,
            decoder_errors: value.decoder_errors,
            evidence_errors: value.evidence_errors,
            wal_capacity_blocked: value.wal_capacity_blocked,
            reader_queue_dropped_events: value.reader_queue_dropped_events,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HfStaticEffectClassificationV1 {
    LocalPreventionProbe,
    HardCloseProbe,
    NoCoveredEffect,
    OutsideAuthority,
    DeferredNetwork,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HfStaticEffectClassificationCaseV1 {
    pub incident_event_id: &'static str,
    pub branch_id: &'static str,
    pub classification: HfStaticEffectClassificationV1,
    pub declared_denial_before_effect: bool,
    pub declared_no_file_descriptor_or_bytes: bool,
    pub declared_legitimate_control_succeeded: bool,
    pub classification_basis: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalEnforcementFixtureResultV1 {
    pub fixture_id: String,
    pub result: QualificationResultV1,
    pub reason_code: String,
}

#[derive(Clone, Copy)]
enum LocalFixtureDisposition {
    Physical(&'static str),
    Unsupported(&'static str),
}

#[derive(Clone, Copy)]
struct LocalFixtureSpec {
    fixture_id: &'static str,
    disposition: LocalFixtureDisposition,
}

const LOCAL_ENFORCEMENT_FIXTURES: [LocalFixtureSpec; 29] = [
    LocalFixtureSpec {
        fixture_id: "ADMIN-EXEC-APPROVAL-001",
        disposition: LocalFixtureDisposition::Unsupported("ADMIN_EXEC_CLAIM_NOT_ADVERTISED"),
    },
    LocalFixtureSpec {
        fixture_id: "DEVICE-DERIVED-001",
        disposition: LocalFixtureDisposition::Physical(
            "DERIVED_DEVICE_MINT_DENIED_BEFORE_DESCRIPTOR_INSTALL",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "EXEC-CONCURRENT-002",
        disposition: LocalFixtureDisposition::Unsupported(
            "PROTECTED_CONCURRENT_EXEC_NOT_PHYSICALLY_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-CONTENT-RACE-002",
        disposition: LocalFixtureDisposition::Unsupported(
            "IMMUTABLE_SOURCE_MUTABILITY_PROOF_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-FD-PASS-001",
        disposition: LocalFixtureDisposition::Physical(
            "PASSED_DESCRIPTOR_ACQUISITION_AND_USE_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-IDENTITY-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "OVERLAY_COPY_UP_PROVENANCE_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-MMAP-001",
        disposition: LocalFixtureDisposition::Physical(
            "FILE_MAPPING_DENY_AND_BENIGN_CONTROL_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-MMAP-SHARED-011",
        disposition: LocalFixtureDisposition::Physical(
            "INDEPENDENT_ROOT_MAPPING_ACQUISITION_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-NAMESPACE-001",
        disposition: LocalFixtureDisposition::Physical(
            "EXACT_MOUNT_VIEW_INVALIDATION_AND_RECONCILIATION_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-PATH-TREE-DENY-001",
        disposition: LocalFixtureDisposition::Physical("RECURSIVE_PATH_TREE_DENY_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-SA-TOKEN-OPEN-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "PROJECTED_TOKEN_ROTATION_BINDING_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "FILE-VMA-SNAPSHOT-001",
        disposition: LocalFixtureDisposition::Unsupported("COMPLETE_VMA_SNAPSHOT_NOT_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "HF-LOCAL-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "PROJECTED_TOKEN_AND_CONTROLLER_CONTROL_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "IPC-ASYNC-UNSUPPORTED-010",
        disposition: LocalFixtureDisposition::Physical(
            "RESTRICTED_IO_URING_AND_SQPOLL_HARD_CLOSE_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "IPC-PEER-RACE-004",
        disposition: LocalFixtureDisposition::Physical("UNIX_PEER_GENERATION_RACE_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "IPC-PROCESS-CHANNEL-009",
        disposition: LocalFixtureDisposition::Physical(
            "PROCESS_CHANNEL_AND_CONTROL_DIRECTION_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "IPC-RELATIONSHIP-ALLOW-003",
        disposition: LocalFixtureDisposition::Physical("EXACT_UNIX_STREAM_RELATIONSHIP_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "IPC-RELATIONSHIP-UNMATCHED-005",
        disposition: LocalFixtureDisposition::Physical("UNMATCHED_AND_STALE_UNIX_PEERS_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "LSM-DENY-SATURATION-001",
        disposition: LocalFixtureDisposition::Physical(
            "DENIAL_INDEPENDENT_FROM_OBSERVATION_DELIVERY_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "MEM-EXEC-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "IMMUTABLE_EXECUTABLE_SOURCE_PROOF_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "MEM-KERNEL-MAP-002",
        disposition: LocalFixtureDisposition::Unsupported("MM_AND_VMA_STATE_NOT_QUALIFIED"),
    },
    LocalFixtureSpec {
        fixture_id: "MOUNT-ATTR-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "COMPLETE_MOUNT_ATTRIBUTE_VARIANTS_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "MOUNT-CAS-002",
        disposition: LocalFixtureDisposition::Physical(
            "MOUNT_PROPOSAL_CAS_AND_EXACT_RECONCILIATION_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "MOUNT-PROPAGATION-003",
        disposition: LocalFixtureDisposition::Unsupported(
            "COMPLETE_PROPAGATION_FANOUT_AND_OVERFLOW_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "MOUNT-SNAPSHOT-004",
        disposition: LocalFixtureDisposition::Physical(
            "INCOMPLETE_SNAPSHOT_HARD_CLOSE_AND_RECOVERY_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "SELF-PROTECT-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "COMPLETE_LOCAL_SELF_PROTECTION_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "STATE-FORK-IPC-002",
        disposition: LocalFixtureDisposition::Physical(
            "INHERITED_CHANNEL_AUTHORITY_DENIAL_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "STATE-PERSISTENT-FILE-LIFETIME-007",
        disposition: LocalFixtureDisposition::Unsupported(
            "PERSISTENT_FILE_INSTANCE_LIFETIME_NOT_QUALIFIED",
        ),
    },
    LocalFixtureSpec {
        fixture_id: "STATE-THREAD-RACE-001",
        disposition: LocalFixtureDisposition::Unsupported(
            "PROTECTED_EFFECT_ROLE_TRANSITION_RACE_NOT_QUALIFIED",
        ),
    },
];

fn local_enforcement_fixture_results(protect: bool) -> Vec<LocalEnforcementFixtureResultV1> {
    LOCAL_ENFORCEMENT_FIXTURES
        .into_iter()
        .map(|spec| {
            let (result, reason_code) = match spec.disposition {
                LocalFixtureDisposition::Physical(reason_code) if protect => {
                    (QualificationResultV1::Pass, reason_code)
                }
                LocalFixtureDisposition::Physical(_) => (
                    QualificationResultV1::Degraded,
                    "OBSERVE_MODE_HAS_NO_PREVENTION_RESULT",
                ),
                LocalFixtureDisposition::Unsupported(reason_code) => {
                    (QualificationResultV1::Unsupported, reason_code)
                }
            };
            LocalEnforcementFixtureResultV1 {
                fixture_id: spec.fixture_id.to_owned(),
                result,
                reason_code: reason_code.to_owned(),
            }
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub protect_mode: bool,
    pub protected_deployment_digest: String,
    pub local_enforcement_fixture_results: Vec<LocalEnforcementFixtureResultV1>,
    pub hf_static_effect_classification: Vec<HfStaticEffectClassificationCaseV1>,
    pub managed_proc_read_hard_closed: bool,
    pub exact_open_observed: bool,
    pub exact_open_denied_before_effect: bool,
    pub inherited_fd_read_denied: bool,
    pub file_mmap_denied: bool,
    pub writable_shared_mmap_denied: bool,
    pub independent_root_shared_mmap_denied: bool,
    pub independent_root_benign_mmap_allowed: bool,
    pub independent_root_shared_mmap_distinct_identity: bool,
    pub executable_mmap_denied: bool,
    pub file_mprotect_exec_denied: bool,
    pub benign_mmap_allowed: bool,
    pub benign_read_allowed: bool,
    pub execve_denied: bool,
    pub execveat_denied: bool,
    pub fexecve_denied: bool,
    pub script_exec_denied: bool,
    pub deleted_exec_denied: bool,
    pub non_leader_exec_denied: bool,
    pub external_exec_allow_cannot_admit: bool,
    pub memfd_exec_failed_closed: bool,
    pub anonymous_exec_hard_closed: bool,
    pub anonymous_executable_mmap_hard_closed: bool,
    pub anonymous_read_mmap_allowed: bool,
    pub pkey_executable_mprotect_hard_closed: bool,
    pub pkey_read_mprotect_allowed: bool,
    pub file_create_hard_closed: bool,
    pub file_setattr_hard_closed: bool,
    pub file_truncate_hard_closed: bool,
    pub file_unlink_hard_closed: bool,
    pub file_link_hard_closed: bool,
    pub file_rename_hard_closed: bool,
    pub sysv_ipc_access_hard_closed: bool,
    pub unix_stream_relationship_allowed: bool,
    pub inherited_unix_stream_send_denied: bool,
    pub unix_stream_stale_peer_denied: bool,
    pub unix_stream_unmatched_denied: bool,
    pub ptrace_hard_closed: bool,
    pub process_ptrace_exact_denied: bool,
    pub process_signal_zero_permission_allowed: bool,
    pub process_signal_unmatched_denied: bool,
    pub namespace_privilege_hard_closed: bool,
    pub ptmx_ioctl_exact_allowed: bool,
    pub ptmx_derived_peer_hard_closed: bool,
    pub ptmx_derived_peer_installed_nothing: bool,
    pub zero_device_ioctl_exact_denied: bool,
    pub bpf_hard_closed: bool,
    pub managed_link_pin_unlink_denied: bool,
    pub bounded_exception_maximum_uses: u32,
    pub bounded_exception_n_allows: bool,
    pub bounded_exception_n_plus_one_denied: bool,
    pub bounded_exception_expiry_denied: bool,
    pub bounded_exception_restart_preserved: bool,
    pub hard_link_alias_denied: bool,
    pub symlink_alias_denied: bool,
    pub proc_fd_alias_denied: bool,
    pub passed_fd_read_denied: bool,
    pub passed_benign_fd_read_allowed: bool,
    pub passed_fd_acquisition_denied: bool,
    pub passed_fd_acquisition_installed_nothing: bool,
    pub passed_benign_fd_acquisition_allowed: bool,
    pub passed_benign_fd_acquisition_read_allowed: bool,
    pub io_uring_secret_read_observed: bool,
    pub io_uring_secret_read_denied_before_effect: bool,
    pub io_uring_benign_read_allowed: bool,
    pub io_uring_worker_request_attributed: bool,
    pub io_uring_sqpoll_denied_before_ring: bool,
    pub io_uring_lifecycle_released: bool,
    pub bind_alias_canonicalized: bool,
    pub path_tree_preexisting_child_denied: bool,
    pub path_tree_meta_depth_denied: bool,
    pub path_tree_future_namespace_denied: bool,
    pub path_tree_later_child_denied: bool,
    pub path_tree_replacement_child_denied: bool,
    pub path_tree_outside_control_allowed: bool,
    pub path_tree_preexisting_bind_alias_denied: bool,
    pub path_tree_postactivation_bind_alias_denied: bool,
    pub allowed_bind_alias_allowed: bool,
    pub path_tree_recursive_bind_alias_denied: bool,
    pub allowed_recursive_bind_alias_allowed: bool,
    pub path_tree_move_mount_alias_denied: bool,
    pub allowed_move_mount_alias_allowed: bool,
    pub path_tree_mount_attack_failed_closed: bool,
    pub protected_mount_race_denied: bool,
    pub mount_stale_proposal_failed_closed: bool,
    pub mount_propagation_reached_peer: bool,
    pub mount_propagation_all_views_failed_closed: bool,
    pub mount_propagation_reconciled: bool,
    pub mount_setattr_global_invalidation: bool,
    pub mount_setattr_reconciled: bool,
    pub external_mount_replacement_failed_closed: bool,
    pub exact_object_restored_after_reconciliation: bool,
    pub new_roots_generation_published_atomically: bool,
    pub existing_tasks_retained_old_generation: bool,
    pub old_generation_deleted_after_last_holder: bool,
    pub baseline_average_open_ns: u64,
    pub observed_average_open_ns: u64,
    pub baseline_open_latency: LatencyDistributionV1,
    pub observed_open_latency: LatencyDistributionV1,
    pub measured_opens: u32,
    pub saturation_opens: u32,
    pub pre_saturation_health: EffectHealthV1,
    pub saturated_health: EffectHealthV1,
    pub saturation_preserved_network_denial: bool,
    pub saturation_preserved_benign_allow: bool,
    pub emitted_source_sequences_monotonic: bool,
    pub durable_evidence_batch_records: usize,
    pub durable_evidence_batch_is_contiguous: bool,
    pub wal_capacity_gapped: bool,
    pub ring_loss_gapped: bool,
    pub negative_claim_blocked: bool,
    pub evidence_errors: u64,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub fixture_root_removed: bool,
}

fn build_generation_artifact(
    policy_source: &Path,
    seal_source: &Path,
    signing_key: &Path,
    fixture_root: &Path,
    generation: u64,
    path_tree_root: Option<&Path>,
) -> Result<PathBuf> {
    ensure!(
        generation == 1 || generation == 2,
        InvalidInputSnafu {
            path: policy_source,
            reason: "the effect fixture supports policy generations 1 and 2",
        }
    );
    let mut document = PolicyDocumentV1::parse(
        policy_source,
        &fs::read(policy_source).context(IoSnafu {
            path: policy_source,
        })?,
    )
    .context(PolicySnafu)?;
    document.path_selectors.clear();
    for (path_selector_id, path, object_class_id, device_class_id) in [
        (
            "manual-secret",
            fixture_root.join("source/secret"),
            "MANUAL_SECRET",
            None,
        ),
        (
            "manual-benign",
            fixture_root.join("benign"),
            "MANUAL_BENIGN",
            None,
        ),
        (
            "manual-benign-bind",
            fixture_root.join("allowed-bind-source/allowed"),
            "MANUAL_BENIGN",
            None,
        ),
        (
            "manual-exec",
            fixture_root.join("exec-target"),
            "MANUAL_EXEC",
            None,
        ),
        (
            "manual-script",
            fixture_root.join("script-target"),
            "MANUAL_EXEC",
            None,
        ),
        (
            "manual-exec-allowed",
            fixture_root.join("allowed-exec-target"),
            "MANUAL_EXEC_ALLOWED",
            None,
        ),
        (
            "manual-device-ptmx",
            PathBuf::from("/dev/pts/ptmx"),
            "MANUAL_DEVICE_ALLOWED",
            Some("PTMX_DEVICE"),
        ),
        (
            "manual-device-zero",
            PathBuf::from("/dev/zero"),
            "MANUAL_DEVICE_DENIED",
            Some("ZERO_DEVICE"),
        ),
    ] {
        if !document
            .protected_universe
            .object_class_ids
            .iter()
            .any(|class| class == object_class_id)
        {
            continue;
        }
        let canonical_path = path.to_str().ok_or_else(|| {
            InvalidInputSnafu {
                path: &path,
                reason: "the signed fixture path selector must be UTF-8",
            }
            .build()
        })?;
        let selector = if matches!(
            path_selector_id,
            "manual-exec" | "manual-script" | "manual-exec-allowed"
        ) {
            PathSelectorV1::path(path_selector_id, canonical_path, object_class_id)
        } else {
            PathSelectorV1::exact(path_selector_id, canonical_path, object_class_id)
        };
        document.path_selectors.push(match device_class_id {
            Some(device_class_id) => selector.with_device_class(device_class_id),
            None => selector,
        });
    }
    if let Some(path_tree_root) = path_tree_root {
        let canonical_path = path_tree_root.to_str().ok_or_else(|| {
            InvalidInputSnafu {
                path: path_tree_root,
                reason: "the path-tree fixture path must be UTF-8",
            }
            .build()
        })?;
        document.path_tree_deny_floors.push(PathTreeDenyFloorV1 {
            schema_version: 1,
            rule_id: "manual-secret-tree-deny".to_owned(),
            canonical_path: canonical_path.to_owned(),
            recursive: true,
            effect_families: vec![EffectFamilyV1::File],
            operation_ids: [
                "CREATE",
                "LINK",
                "MMAP_READ",
                "MMAP_WRITE",
                "MPROTECT",
                "OPEN_READ",
                "OPEN_WRITE",
                "READ",
                "RENAME",
                "SETATTR",
                "UNLINK",
                "WRITE",
            ]
            .map(str::to_owned)
            .to_vec(),
            requested_disposition: PolicyDispositionV1::Deny,
            exception_ids: Vec::new(),
        });
    }
    sign_generation_artifact(document, seal_source, signing_key, fixture_root, generation)
}

fn sign_generation_artifact(
    mut document: PolicyDocumentV1,
    seal_source: &Path,
    signing_key: &Path,
    fixture_root: &Path,
    generation: u64,
) -> Result<PathBuf> {
    let generation_delta = generation - 1;
    document.metadata.profile_version = document
        .metadata
        .profile_version
        .checked_add(generation_delta)
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: fixture_root,
                reason: "profile version exhausted",
            }
            .build()
        })?;
    document.rollout.rollout_generation = document
        .rollout
        .rollout_generation
        .checked_add(generation_delta)
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: fixture_root,
                reason: "rollout generation exhausted",
            }
            .build()
        })?;
    let generated_policy = fixture_root.join(format!("profile-generation-{generation}.json"));
    fs::write(
        &generated_policy,
        serde_json::to_vec_pretty(&document).context(JsonSnafu {
            path: &generated_policy,
        })?,
    )
    .context(IoSnafu {
        path: &generated_policy,
    })?;

    let mut seal: ProfileSealRequestV1 =
        serde_json::from_slice(&fs::read(seal_source).context(IoSnafu { path: seal_source })?)
            .context(JsonSnafu { path: seal_source })?;
    seal.issuer_sequence = seal
        .issuer_sequence
        .checked_add(generation_delta)
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: seal_source,
                reason: "issuer sequence exhausted",
            }
            .build()
        })?;
    let generated_seal = fixture_root.join(format!("profile-seal-generation-{generation}.json"));
    fs::write(
        &generated_seal,
        serde_json::to_vec_pretty(&seal).context(JsonSnafu {
            path: &generated_seal,
        })?,
    )
    .context(IoSnafu {
        path: &generated_seal,
    })?;
    let artifact = fixture_root.join(format!("profile-generation-{generation}-artifact.json"));
    PolicyArtifactOwner::default()
        .compile_and_sign(&generated_policy, &generated_seal, signing_key, &artifact)
        .context(PolicySnafu)?;
    Ok(artifact)
}

pub struct EffectTestRunner {
    repo_root: PathBuf,
}

fn hf_static_effect_classification() -> Vec<HfStaticEffectClassificationCaseV1> {
    use HfStaticEffectClassificationV1::{
        DeferredNetwork, HardCloseProbe, LocalPreventionProbe, NoCoveredEffect, OutsideAuthority,
        Unsupported,
    };
    vec![
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-002",
            branch_id: "managed-proc-object",
            classification: HardCloseProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: true,
            declared_legitimate_control_succeeded: true,
            classification_basis: "managed /proc/self/environ open returned EACCES; the exact benign file remained readable",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-002",
            branch_id: "managed-helper",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the unapproved helper returned EACCES; the exact file-backed BusyBox control completed without proving immutable executable authority",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-002",
            branch_id: "resident-environment",
            classification: NoCoveredEffect,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "an environment value already in process memory has no new kernel file effect",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-002",
            branch_id: "external-reconnaissance",
            classification: OutsideAuthority,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the external subject has no managed Linux task",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-003",
            branch_id: "managed-copied-executable",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the copied executable returned EACCES; the exact file-backed BusyBox control completed without proving immutable executable authority",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-004",
            branch_id: "managed-capture-destination",
            classification: DeferredNetwork,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "destination-aware connect, send, packet, and provider results are outside local non-network enforcement",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-004",
            branch_id: "external-send",
            classification: OutsideAuthority,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "the external sender has no managed Linux task",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-005",
            branch_id: "managed-staged-code",
            classification: Unsupported,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "the fixture has no trusted content-provenance class for in-process Python interpretation",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-005",
            branch_id: "external-stage",
            classification: OutsideAuthority,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "the external staging subject has no managed Linux task",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-006",
            branch_id: "pure-memory-packing",
            classification: NoCoveredEffect,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "pure CPU packing has no protected kernel effect",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-006",
            branch_id: "later-protected-file-boundary",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: true,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the later exact protected-file open returned EACCES; the exact benign read completed",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-007",
            branch_id: "managed-public-service",
            classification: DeferredNetwork,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "destination and provider-query decisions are outside local non-network enforcement",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-007",
            branch_id: "external-search",
            classification: OutsideAuthority,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "the external search subject has no managed Linux task",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-008",
            branch_id: "worker-local-forbidden-object",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: true,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the exact forbidden object returned EACCES; the admitted file remained readable",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-008",
            branch_id: "optional-upload-gate",
            classification: Unsupported,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "no synchronous artifact upload gate is installed",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-009",
            branch_id: "protected-local-read",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: true,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the exact protected-file open returned EACCES; the ordinary input read completed",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-009",
            branch_id: "resident-environment",
            classification: NoCoveredEffect,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "an environment value already in process memory has no new file-read effect",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-009",
            branch_id: "later-output-or-same-tls",
            classification: DeferredNetwork,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "publication and opaque TLS results require network or provider authority",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-010",
            branch_id: "pure-in-process-expression",
            classification: NoCoveredEffect,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the in-process expression creates no native transition",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-010",
            branch_id: "later-managed-helper",
            classification: LocalPreventionProbe,
            declared_denial_before_effect: true,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: true,
            classification_basis: "the later unapproved executable returned EACCES; the exact file-backed executable control completed without proving immutable executable authority",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-011",
            branch_id: "projected-token-open-and-read",
            classification: Unsupported,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "the fixture has no rotating projected-token object and signed controller-role positive control",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-011",
            branch_id: "resident-token-memory",
            classification: NoCoveredEffect,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "token bytes already in process memory cannot be unread",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-012",
            branch_id: "api-or-imds-channel",
            classification: DeferredNetwork,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "new, rewritten, and existing channel decisions require destination-aware network enforcement",
        },
        HfStaticEffectClassificationCaseV1 {
            incident_event_id: "HF-012",
            branch_id: "controller-semantic-operation",
            classification: Unsupported,
            declared_denial_before_effect: false,
            declared_no_file_descriptor_or_bytes: false,
            declared_legitimate_control_succeeded: false,
            classification_basis: "no Kubernetes or cloud semantic authority is installed in this local fixture",
        },
    ]
}

fn require_hard_close(
    fixture: &mut EffectProcessFixture,
    reader: &EffectObservationReader,
    observations: &EffectObservationStore,
    operation: HardClosedOperation,
    expected_reason: &str,
    expected_effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
    label: &str,
) -> Result<u64> {
    let marker = observations.cursor();
    ensure!(
        fixture.hard_closed(operation)?.denied(),
        InvalidInputSnafu {
            path: Path::new("live effect state"),
            reason: format!("{label} was not physically hard-closed"),
        }
    );
    wait_for_effect(
        reader,
        observations,
        marker,
        expected_reason,
        expected_effect,
    )
    .map_err(|error| {
        InvalidInputSnafu {
            path: Path::new("effect_observations"),
            reason: format!("{label}: {error}"),
        }
        .build()
    })?;
    Ok(marker)
}

fn require_exact_process_control(
    fixture: &mut EffectProcessFixture,
    reader: &EffectObservationReader,
    observations: &EffectObservationStore,
    operation: HardClosedOperation,
    kernel_operation: KernelEffectOperationV1,
    expected_reason: &str,
    denied: bool,
) -> Result<()> {
    let marker = observations.cursor();
    let outcome = fixture.run_prepared(operation)?;
    ensure!(
        if denied {
            outcome.denied()
        } else {
            outcome.allowed
        },
        InvalidInputSnafu {
            path: Path::new("live effect state"),
            reason: format!(
                "exact process-control {} did not produce its signed physical result",
                kernel_operation as u16
            ),
        }
    );
    wait_for_effect(
        reader,
        observations,
        marker,
        expected_reason,
        (KernelEffectFamilyV1::Privilege, kernel_operation),
    )?;
    let zero_id = "0".repeat(32);
    ensure!(
        observations.recent_since(marker).iter().any(|event| {
            event.reason == expected_reason
                && event.effect_family == u32::from(KernelEffectFamilyV1::Privilege as u16)
                && event.operation == u32::from(kernel_operation as u16)
                && event.profile_generation_ref_id == PROFILE_GENERATION_REF_ID
                && event.target_profile_generation_ref_id == PROFILE_GENERATION_REF_ID
                && event.task_cookie > 0
                && event.target_task_cookie > 0
                && event.task_cookie != event.target_task_cookie
                && event.active_role_id > 0
                && event.target_role_id > 0
                && event.process_state_vector_id > 0
                && event.target_process_state_vector_id > 0
                && event.controller_process_state_id != zero_id
                && event.target_process_state_id != zero_id
                && event.controller_process_state_id != event.target_process_state_id
        }),
        InvalidInputSnafu {
            path: Path::new("effect_observations"),
            reason:
                "process-control evidence did not bind the current controller and exact live target",
        }
    );
    Ok(())
}

impl EffectTestRunner {
    pub fn compile_retained_identity_fixture(
        &self,
        output_directory: &Path,
    ) -> Result<CompileRecordV1> {
        BpfPrototypeCompiler::new(&self.repo_root).compile_retained_identity(output_directory)
    }

    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn physical_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        cgroup_path: &Path,
        measured_opens: u32,
        saturation_opens: u32,
        protect: bool,
    ) -> Result<EffectPhysicalProbeBundleV1> {
        ensure!(
            measured_opens > 0 && saturation_opens >= 30_000,
            InvalidInputSnafu {
                path: output_directory,
                reason:
                    "measured_opens must be nonzero and saturation_opens must be at least 30000",
            }
        );
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the dedicated effect-test pin root and lease must not already exist",
            }
        );
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let fixture_root = output_directory.join("effect-runtime");
        ensure!(
            !fixture_root.exists(),
            InvalidInputSnafu {
                path: &fixture_root,
                reason: "the effect-test runtime directory must not already exist",
            }
        );
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let fixture_root = fs::canonicalize(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let fixture_cleanup = ProbeDirectory::new(&fixture_root);
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let peer_cgroup_path = cgroup_path.with_file_name({
            let mut name = cgroup_path
                .file_name()
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: cgroup_path,
                        reason: "effect-test cgroup path has no final component",
                    }
                    .build()
                })?
                .to_os_string();
            name.push("-peer");
            name
        });
        let propagation_cgroup_path = cgroup_path.with_file_name({
            let mut name = cgroup_path
                .file_name()
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: cgroup_path,
                        reason: "effect-test cgroup path has no final component",
                    }
                    .build()
                })?
                .to_os_string();
            name.push("-propagation");
            name
        });
        let cgroup_cleanup = ProbeCgroup::create(cgroup_path)?;
        let cgroup_path = cgroup_cleanup.path().to_path_buf();
        let peer_cgroup_cleanup = ProbeCgroup::create(&peer_cgroup_path)?;
        let peer_cgroup_path = peer_cgroup_cleanup.path().to_path_buf();
        let propagation_cgroup_cleanup = ProbeCgroup::create(&propagation_cgroup_path)?;
        let propagation_cgroup_path = propagation_cgroup_cleanup.path().to_path_buf();

        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: &self.repo_root,
        })?;
        let protected_deployment_digest =
            HuggingFaceFixture::new(repo_root.join("crates/mithril-e2e/fixtures/hugging-face"))
                .verify()?
                .protected_deployment_digest;
        let policy_fixture = repo_root.join("crates/mithril-e2e/fixtures/mithril-policy");
        let policy_source = policy_fixture.join(if protect {
            "protect-policy-v1.yaml"
        } else {
            "observe-policy-v1.yaml"
        });
        let path_tree_root = if protect {
            let component_count = fixture_root
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count();
            ensure!(
                component_count < MAX_CANONICAL_PATH_COMPONENTS_V1 - 1,
                InvalidInputSnafu {
                    path: &fixture_root,
                    reason: "the fixture root leaves no room for the 255-component path proof",
                }
            );
            let mut path = fixture_root.clone();
            for index in component_count..MAX_CANONICAL_PATH_COMPONENTS_V1 - 1 {
                path.push(format!("d{index}"));
            }
            path
        } else {
            fixture_root.join("secret-dir")
        };
        let path_tree_floor = protect.then_some(path_tree_root.as_path());
        let seal_source = policy_fixture.join("observe-profile-seal-request.json");
        let signing_key = policy_fixture.join("test-signing-key.hex");
        let artifact_path = build_generation_artifact(
            &policy_source,
            &seal_source,
            &signing_key,
            &fixture_root,
            1,
            path_tree_floor,
        )?;
        let next_artifact_path = build_generation_artifact(
            &policy_source,
            &seal_source,
            &signing_key,
            &fixture_root,
            2,
            path_tree_floor,
        )?;

        let (boot_id, node_boot_id) = boot_identity()?;
        let kernel_config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        );
        let mut host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let binding = effect_binding(&cgroup_path);
        let peer_binding = effect_peer_binding(&peer_cgroup_path);
        let propagation_binding = effect_propagation_binding(&propagation_cgroup_path);
        let binding_set = [
            binding.clone(),
            peer_binding.clone(),
            propagation_binding.clone(),
        ];
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, &binding_set)
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut host)
            .context(NodeSnafu)?;

        let mut fixture = EffectProcessFixture::start(&fixture_root)?;
        let paths = fixture.setup()?;
        let path_tree_preexisting = path_tree_root.join("pre-existing");
        let path_tree_later = path_tree_root.join("created-after-activation");
        let path_tree_replacement = path_tree_root.join("replacement");
        let path_tree_actor_create = path_tree_root.join("actor-created");
        let path_tree_preexisting_bind_target =
            fixture_root.join("path-tree-preexisting-bind-alias");
        let path_tree_postactivation_bind_target =
            fixture_root.join("path-tree-postactivation-bind-alias");
        let path_tree_recursive_bind_target = fixture_root.join("path-tree-recursive-bind-alias");
        let path_tree_move_mount_target = fixture_root.join("path-tree-move-mount-alias");
        let allowed_bind_source = fixture_root.join("allowed-bind-source");
        let allowed_bind_source_file = allowed_bind_source.join("allowed");
        let allowed_bind_target = fixture_root.join("allowed-bind-alias");
        let allowed_bind_alias = allowed_bind_target.join("allowed");
        let allowed_recursive_bind_target = fixture_root.join("allowed-recursive-bind-alias");
        let allowed_recursive_bind_alias = allowed_recursive_bind_target.join("allowed");
        let allowed_move_mount_target = fixture_root.join("allowed-move-mount-alias");
        let allowed_move_mount_alias = allowed_move_mount_target.join("allowed");
        fs::create_dir_all(&path_tree_root).context(IoSnafu {
            path: &path_tree_root,
        })?;
        fs::create_dir(&allowed_bind_source).context(IoSnafu {
            path: &allowed_bind_source,
        })?;
        fs::write(&allowed_bind_source_file, b"allowed bind source\n").context(IoSnafu {
            path: &allowed_bind_source_file,
        })?;
        for target in [
            &path_tree_preexisting_bind_target,
            &path_tree_postactivation_bind_target,
            &path_tree_recursive_bind_target,
            &path_tree_move_mount_target,
            &allowed_bind_target,
            &allowed_recursive_bind_target,
            &allowed_move_mount_target,
        ] {
            fs::create_dir(target).context(IoSnafu { path: target })?;
        }
        ensure!(
            !protect
                || path_tree_preexisting
                    .components()
                    .filter(|component| matches!(component, Component::Normal(_)))
                    .count()
                    == MAX_CANONICAL_PATH_COMPONENTS_V1,
            InvalidInputSnafu {
                path: &path_tree_preexisting,
                reason: "the Meta-depth path-tree fixture does not have 255 components",
            }
        );
        fs::write(&path_tree_preexisting, b"restricted before activation\n").context(IoSnafu {
            path: &path_tree_preexisting,
        })?;
        fs::write(&path_tree_replacement, b"first object\n").context(IoSnafu {
            path: &path_tree_replacement,
        })?;
        let propagation_peer_pid = fixture.prepare_propagation_peer(&paths)?;
        let external_mount_namespace = ExternalMountNamespace::acquire(fixture.pid())?;
        external_mount_namespace.bind_mount(&path_tree_root, &path_tree_preexisting_bind_target)?;
        external_mount_namespace.bind_mount(&allowed_bind_source, &allowed_bind_target)?;
        let create_target = paths.mutation_root.join("forbidden-create");
        let setattr_target = paths.mutation_root.join("setattr-target");
        let truncate_target = paths.mutation_root.join("truncate-target");
        let unlink_target = paths.mutation_root.join("unlink-target");
        let mutation_source = paths.mutation_root.join("mutation-source");
        let link_target = paths.mutation_root.join("link-target");
        let rename_target = paths.mutation_root.join("rename-target");
        let mount_race_target = if protect {
            &path_tree_root
        } else {
            &paths.mount_target
        };
        fixture.prepare_mount_race(&paths.source, mount_race_target, 8)?;
        fixture.prepare_operations(&paths, &truncate_target)?;
        let shared_mmap_target_pid = fixture.shared_mmap_target_pid()?;
        let unix_stream_peer_pid = fixture.prepare_unix_stream_target()?;
        if protect {
            fs::remove_file(&paths.deleted_exec_target).context(IoSnafu {
                path: &paths.deleted_exec_target,
            })?;
        }
        ensure!(
            fixture.hard_closed(HardClosedOperation::Exec)?.allowed,
            InvalidInputSnafu {
                path: &paths.exec_target,
                reason: "executable control failed before effect policy activation",
            }
        );
        if protect {
            fixture.prepare_write_race(&paths.secret, 8)?;
        }
        fs::write(cgroup_path.join("cgroup.procs"), fixture.pid().to_string()).context(
            IoSnafu {
                path: cgroup_path.join("cgroup.procs"),
            },
        )?;
        fs::write(
            cgroup_path.join("cgroup.procs"),
            shared_mmap_target_pid.to_string(),
        )
        .context(IoSnafu {
            path: cgroup_path.join("cgroup.procs"),
        })?;
        fs::write(
            peer_cgroup_path.join("cgroup.procs"),
            unix_stream_peer_pid.to_string(),
        )
        .context(IoSnafu {
            path: peer_cgroup_path.join("cgroup.procs"),
        })?;
        fs::write(
            propagation_cgroup_path.join("cgroup.procs"),
            propagation_peer_pid.to_string(),
        )
        .context(IoSnafu {
            path: propagation_cgroup_path.join("cgroup.procs"),
        })?;
        let baseline_samples = fixture.open_samples(&paths.secret, measured_opens)?;
        let baseline = baseline_samples.batch;
        ensure!(
            baseline.denied == 0
                && baseline.other_errors == 0
                && baseline.allowed == measured_opens,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "baseline file opens failed before effect observation was enabled",
            }
        );
        if protect {
            fixture.prepare_file(&paths.secret)?;
        }
        let secret_inode_generation = inode_generation(fixture.pid(), &paths.secret)?;
        let exact_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.secret,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            "MANUAL_SECRET".to_owned(),
            secret_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        let bind_alias_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.bind_alias,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            "MANUAL_SECRET".to_owned(),
            secret_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        let second_bind_alias_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.second_bind_alias,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            "MANUAL_SECRET".to_owned(),
            secret_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        ensure!(
            exact_object.mount_id_unique != bind_alias_object.mount_id_unique
                && exact_object.mount_id_unique != second_bind_alias_object.mount_id_unique
                && bind_alias_object.mount_id_unique != second_bind_alias_object.mount_id_unique
                && exact_object.selected_mount_id_unique
                    == bind_alias_object.selected_mount_id_unique
                && exact_object.selected_mount_id_unique
                    == second_bind_alias_object.selected_mount_id_unique
                && exact_object.canonical_component_hex
                    == bind_alias_object.canonical_component_hex
                && exact_object.canonical_component_hex
                    == second_bind_alias_object.canonical_component_hex
                && exact_object.mount_namespace_inode
                    == bind_alias_object.mount_namespace_inode
                && exact_object.mount_namespace_inode
                    == second_bind_alias_object.mount_namespace_inode
                && exact_object.filesystem_device == bind_alias_object.filesystem_device
                && exact_object.filesystem_device
                    == second_bind_alias_object.filesystem_device
                && exact_object.inode == bind_alias_object.inode
                && exact_object.inode == second_bind_alias_object.inode
                && exact_object.inode_generation == bind_alias_object.inode_generation
                && exact_object.inode_generation == second_bind_alias_object.inode_generation,
            InvalidInputSnafu {
                path: &paths.second_bind_alias,
                reason: "the bind fixtures are not distinct live mounts of the same canonical exact object",
            }
        );
        let benign_inode_generation = inode_generation(fixture.pid(), &paths.benign)?;
        let benign_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &paths.benign,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-benign"),
            "MANUAL_BENIGN".to_owned(),
            benign_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        let allowed_bind_inode_generation =
            inode_generation(fixture.pid(), &allowed_bind_source_file)?;
        let allowed_bind_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &allowed_bind_source_file,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
            "MANUAL_BENIGN".to_owned(),
            allowed_bind_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        let allowed_bind_alias_object = ExactFileObjectResolver::resolve(
            fixture.pid(),
            &allowed_bind_alias,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
            "MANUAL_BENIGN".to_owned(),
            allowed_bind_inode_generation,
            None,
        )
        .context(NodeSnafu)?;
        ensure!(
            allowed_bind_object.mount_id_unique != allowed_bind_alias_object.mount_id_unique
                && allowed_bind_object.selected_mount_id_unique
                    == allowed_bind_alias_object.selected_mount_id_unique
                && allowed_bind_object.canonical_component_hex
                    == allowed_bind_alias_object.canonical_component_hex
                && allowed_bind_object.filesystem_device
                    == allowed_bind_alias_object.filesystem_device
                && allowed_bind_object.inode == allowed_bind_alias_object.inode
                && allowed_bind_object.inode_generation
                    == allowed_bind_alias_object.inode_generation,
            InvalidInputSnafu {
                path: &allowed_bind_alias,
                reason:
                    "the allowed bind fixture is not a distinct mount of the same canonical file",
            }
        );
        let propagation_benign_object = ExactFileObjectResolver::resolve(
            propagation_peer_pid,
            &paths.benign,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-benign"),
            "MANUAL_BENIGN".to_owned(),
            inode_generation(propagation_peer_pid, &paths.benign)?,
            None,
        )
        .context(NodeSnafu)?;
        let propagation_secret_object = ExactFileObjectResolver::resolve(
            propagation_peer_pid,
            &paths.secret,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            "MANUAL_SECRET".to_owned(),
            inode_generation(propagation_peer_pid, &paths.secret)?,
            None,
        )
        .context(NodeSnafu)?;
        let propagation_allowed_bind_object = ExactFileObjectResolver::resolve(
            propagation_peer_pid,
            &allowed_bind_source_file,
            PROFILE_GENERATION_REF_ID,
            PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
            "MANUAL_BENIGN".to_owned(),
            inode_generation(propagation_peer_pid, &allowed_bind_source_file)?,
            None,
        )
        .context(NodeSnafu)?;
        let mut exact_objects = vec![
            exact_object.clone(),
            benign_object,
            allowed_bind_object,
            propagation_secret_object,
            propagation_benign_object,
            propagation_allowed_bind_object,
        ];
        if protect {
            exact_objects.push(
                ExactFileObjectResolver::resolve(
                    fixture.pid(),
                    Path::new("/dev/pts/ptmx"),
                    PROFILE_GENERATION_REF_ID,
                    PathSelectorV1::kernel_handle_for_id("manual-device-ptmx"),
                    "MANUAL_DEVICE_ALLOWED".to_owned(),
                    0,
                    Some("PTMX_DEVICE".to_owned()),
                )
                .context(NodeSnafu)?,
            );
            exact_objects.push(
                ExactFileObjectResolver::resolve(
                    fixture.pid(),
                    Path::new("/dev/zero"),
                    PROFILE_GENERATION_REF_ID,
                    PathSelectorV1::kernel_handle_for_id("manual-device-zero"),
                    "MANUAL_DEVICE_DENIED".to_owned(),
                    0,
                    Some("ZERO_DEVICE".to_owned()),
                )
                .context(NodeSnafu)?,
            );
            exact_objects.push(
                ExactFileObjectResolver::resolve(
                    propagation_peer_pid,
                    Path::new("/dev/pts/ptmx"),
                    PROFILE_GENERATION_REF_ID,
                    PathSelectorV1::kernel_handle_for_id("manual-device-ptmx"),
                    "MANUAL_DEVICE_ALLOWED".to_owned(),
                    0,
                    Some("PTMX_DEVICE".to_owned()),
                )
                .context(NodeSnafu)?,
            );
            exact_objects.push(
                ExactFileObjectResolver::resolve(
                    propagation_peer_pid,
                    Path::new("/dev/zero"),
                    PROFILE_GENERATION_REF_ID,
                    PathSelectorV1::kernel_handle_for_id("manual-device-zero"),
                    "MANUAL_DEVICE_DENIED".to_owned(),
                    0,
                    Some("ZERO_DEVICE".to_owned()),
                )
                .context(NodeSnafu)?,
            );
        }
        let mount_namespaces = exact_objects
            .iter()
            .map(|object| object.mount_namespace_inode)
            .collect::<BTreeSet<_>>();
        let mut test_exact_objects = Vec::with_capacity(exact_objects.len() * 2);
        for object in &exact_objects {
            if object.mount_view_root_pid == propagation_peer_pid {
                test_exact_objects.push((propagation_binding.binding_id.clone(), object.clone()));
                continue;
            }
            /* The application and peer bindings use the same live mount
             * namespace, so both consume the same measured object view. */
            test_exact_objects.push((binding.binding_id.clone(), object.clone()));
            test_exact_objects.push((peer_binding.binding_id.clone(), object.clone()));
        }
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            artifact_path,
            binding_set.to_vec(),
        );
        let mut next_bindings = binding_set.to_vec();
        for binding in &mut next_bindings {
            binding.active_profile_generation_ref_id = NEXT_PROFILE_GENERATION_REF_ID;
        }
        let mut next_test_exact_objects = test_exact_objects.clone();
        for (_, object) in &mut next_test_exact_objects {
            object.profile_generation_ref_id = NEXT_PROFILE_GENERATION_REF_ID;
        }
        let next_node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            next_artifact_path,
            next_bindings,
        );

        host.shutdown().context(InterceptorSnafu)?;
        let mut host = KernelHostOwner::new(kernel_config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let mut recovered_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        recovered_bindings
            .publish_all(&host, &binding_set)
            .context(NodeSnafu)?;
        let mut policy = NodePolicyGenerationOwner::load_and_install_for_test_objects(
            &node_config,
            &mut host,
            node_boot_id,
            1,
            test_exact_objects.clone(),
        )
        .context(NodeSnafu)?;
        ensure!(
            mount_views_are_clean(&host, &mount_namespaces)?,
            InvalidInputSnafu {
                path: Path::new("mount_security_views"),
                reason: "policy activation did not complete every kernel mount reconciliation",
            }
        );
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate_initial_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        let observations = EffectObservationStore::durable(
            1_024,
            output_directory.join("evidence-wal-v2"),
            EvidenceWalLimits {
                maximum_retained_records: 1_024,
                ..EvidenceWalLimits::default()
            },
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(0x6000_0000_0000_4000, 0x8000_0000_0000_0001),
                EvidenceIdV1::new(0x6000_0000_0000_4000, 0x8000_0000_0000_0002),
                1,
                node_boot_id,
            )
            .context(NodeSnafu)?,
        )
        .context(NodeSnafu)?;
        let sink = observations.clone();
        let mut reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        sample_observation_health(&host, &observations)?;

        let mut path_tree_future_namespace_denied = false;
        let mut path_tree_meta_depth_denied = false;
        let mut path_tree_preexisting_bind_alias_denied = false;
        let mut path_tree_postactivation_bind_alias_denied = false;
        let mut allowed_bind_alias_allowed = false;
        let mut path_tree_recursive_bind_alias_denied = false;
        let mut allowed_recursive_bind_alias_allowed = false;
        let mut path_tree_move_mount_alias_denied = false;
        let mut allowed_move_mount_alias_allowed = false;
        if protect {
            let protected_alias_child = path_tree_preexisting_bind_target.join("pre-existing");
            let protected_alias_marker = observations.cursor();
            ensure!(
                fixture.open(&protected_alias_child)?.denied(),
                InvalidInputSnafu {
                    path: &protected_alias_child,
                    reason: "a pre-existing successful bind exposed a protected child",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                protected_alias_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            path_tree_preexisting_bind_alias_denied = true;

            let allowed_alias_marker = observations.cursor();
            ensure!(
                fixture.open(&allowed_bind_alias)?.allowed,
                InvalidInputSnafu {
                    path: &allowed_bind_alias,
                    reason: "the allowed pre-existing bind alias was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                allowed_alias_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
                None,
            )?;
            allowed_bind_alias_allowed = true;

            let future_fixture_root = fixture_root.join("future-mount-namespace");
            fs::create_dir(&future_fixture_root).context(IoSnafu {
                path: &future_fixture_root,
            })?;
            let mut future_fixture = EffectProcessFixture::start(&future_fixture_root)?;
            let future_namespace_inode: u32 =
                fs::metadata(format!("/proc/{}/ns/mnt", future_fixture.pid()))
                    .context(IoSnafu {
                        path: Path::new("future process mount namespace"),
                    })?
                    .ino()
                    .try_into()
                    .map_err(|error| {
                        InvalidInputSnafu {
                            path: Path::new("future process mount namespace"),
                            reason: format!("mount namespace inode exceeds u32: {error}"),
                        }
                        .build()
                    })?;
            ensure!(
                !mount_namespaces.contains(&future_namespace_inode),
                InvalidInputSnafu {
                    path: Path::new("future process mount namespace"),
                    reason:
                        "future process reused a mount namespace present during policy activation",
                }
            );
            fs::write(
                cgroup_path.join("cgroup.procs"),
                future_fixture.pid().to_string(),
            )
            .context(IoSnafu {
                path: cgroup_path.join("cgroup.procs"),
            })?;
            let marker = observations.cursor();
            ensure!(
                future_fixture.open(&path_tree_preexisting)?.denied(),
                InvalidInputSnafu {
                    path: &path_tree_preexisting,
                    reason: "a process in a mount namespace created after policy activation opened the protected path",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            future_fixture.stop()?;
            path_tree_future_namespace_denied = true;
        }

        if protect {
            for (path, label) in [
                (&path_tree_preexisting, "pre-existing path-tree child"),
                (&path_tree_replacement, "initial replacement-test child"),
            ] {
                let marker = observations.cursor();
                ensure!(
                    fixture.open(path)?.denied(),
                    InvalidInputSnafu {
                        path,
                        reason: format!("the {label} returned a file descriptor"),
                    }
                );
                wait_for_effect(
                    &reader,
                    &observations,
                    marker,
                    "PATH_TREE_POLICY_DENY",
                    (
                        KernelEffectFamilyV1::File,
                        KernelEffectOperationV1::OpenRead,
                    ),
                )?;
            }
            path_tree_meta_depth_denied = true;

            fs::write(&path_tree_later, b"created after activation\n").context(IoSnafu {
                path: &path_tree_later,
            })?;
            let later_marker = observations.cursor();
            ensure!(
                fixture.open(&path_tree_later)?.denied(),
                InvalidInputSnafu {
                    path: &path_tree_later,
                    reason: "a child created after activation returned a file descriptor",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                later_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;

            let create_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::Create {
                        path: path_tree_actor_create.clone(),
                    })?
                    .denied()
                    && !path_tree_actor_create.exists(),
                InvalidInputSnafu {
                    path: &path_tree_actor_create,
                    reason: "a managed create produced a child in the protected tree",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                create_marker,
                "PATH_TREE_POLICY_DENY",
                (KernelEffectFamilyV1::File, KernelEffectOperationV1::Create),
            )?;

            fs::remove_file(&path_tree_replacement).context(IoSnafu {
                path: &path_tree_replacement,
            })?;
            fs::write(&path_tree_replacement, b"replacement object\n").context(IoSnafu {
                path: &path_tree_replacement,
            })?;
            let replacement_marker = observations.cursor();
            ensure!(
                fixture.open(&path_tree_replacement)?.denied(),
                InvalidInputSnafu {
                    path: &path_tree_replacement,
                    reason: "a replacement child returned a file descriptor",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                replacement_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;

            let outside_marker = observations.cursor();
            ensure!(
                fixture.read(&paths.benign)?.allowed,
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: "the exact file outside the protected tree was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                outside_marker,
                "EXACT_POLICY_ALLOW",
                (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
                PathSelectorV1::kernel_handle_for_id("manual-benign"),
                None,
            )?;

            let exception_marker = observations.cursor();
            let exception_race = fixture.write_race(&paths.secret, 8)?;
            ensure!(
                exception_race.allowed == 2
                    && exception_race.denied == 6
                    && exception_race.other_errors == 0,
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: format!(
                        "concurrent bounded exception did not allow exactly N=2 uses: {exception_race:?}"
                    ),
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                exception_marker,
                "EXACT_POLICY_ALLOW",
            )?;
            wait_for_reason(
                &reader,
                &observations,
                exception_marker,
                "EXCEPTION_UNAVAILABLE",
            )?;
            let exception_events = observations.recent_since(exception_marker);
            ensure!(
                exception_events
                    .iter()
                    .filter(|event| event.reason == "EXACT_POLICY_ALLOW")
                    .count()
                    == 2
                    && exception_events
                        .iter()
                        .filter(|event| event.reason == "EXCEPTION_UNAVAILABLE")
                        .count()
                        == 6,
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "concurrent bounded-exception evidence did not match N and N+1",
                }
            );
            let keys = host
                .map_keys("exception_runtime_states")
                .context(InterceptorSnafu)?;
            ensure!(
                keys.len() == 2,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "exception fixture did not install its bounded and expiry instances",
                }
            );
            let key_for_instance = |instance_id| {
                keys.iter().find_map(|key| {
                    ExceptionRuntimeStateKeyV1::try_read_from_bytes(key)
                        .ok()
                        .filter(|key| key.exception_instance_id == instance_id)
                        .map(|_| key.clone())
                })
            };
            let key = key_for_instance(BOUNDED_EXCEPTION_INSTANCE_ID).ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "bounded-exception fixture has no signed stable instance",
                }
                .build()
            })?;
            let expiry_key = key_for_instance(EXPIRED_EXCEPTION_INSTANCE_ID).ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "expiry fixture has no signed stable instance",
                }
                .build()
            })?;
            let exception = host
                .lookup_map_locked("exception_runtime_states", &key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: "bounded exception state disappeared after consumption",
                    }
                    .build()
                })?;
            ensure!(
                exception.len() == size_of::<ExceptionRuntimeStateV1>()
                    && u32::from_ne_bytes(
                        exception[offset_of!(ExceptionRuntimeStateV1, consumed_uses)
                            ..offset_of!(ExceptionRuntimeStateV1, consumed_uses) + 4]
                            .try_into()
                            .unwrap_or_default()
                    ) == 2
                    && exception[offset_of!(ExceptionRuntimeStateV1, state)]
                        == ExceptionRuntimeStateKindV1::Exhausted as u8,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "bounded exception did not finish in exact exhausted state",
                }
            );
            let mut consumed_ordinals = Vec::new();
            let mut other_receipts = 0_usize;
            for receipt_key in host
                .map_keys("exception_use_receipts")
                .context(InterceptorSnafu)?
                .into_iter()
                .filter(|receipt_key| receipt_key.starts_with(&key))
            {
                let receipt = host
                    .lookup_map("exception_use_receipts", &receipt_key)
                    .context(InterceptorSnafu)?
                    .ok_or_else(|| {
                        InvalidInputSnafu {
                            path: Path::new("exception_use_receipts"),
                            reason: "bounded-exception receipt disappeared during readback",
                        }
                        .build()
                    })?;
                let receipt =
                    ExceptionUseReceiptV1::try_read_from_bytes(&receipt).map_err(|error| {
                        InvalidInputSnafu {
                            path: Path::new("exception_use_receipts"),
                            reason: format!("bounded-exception receipt has invalid ABI: {error}"),
                        }
                        .build()
                    })?;
                match receipt.state {
                    ExceptionReceiptStateV1::Consumed => {
                        consumed_ordinals.push(receipt.consumed_ordinal);
                    }
                    _ => other_receipts += 1,
                }
            }
            consumed_ordinals.sort_unstable();
            ensure!(
                consumed_ordinals == [1, 2] && other_receipts == 0,
                InvalidInputSnafu {
                    path: Path::new("exception_use_receipts"),
                    reason: "bounded exception did not retain only successful-use receipts",
                }
            );

            drop(reader);
            host.shutdown().context(InterceptorSnafu)?;
            host = KernelHostOwner::new(kernel_config.clone())
                .start()
                .context(InterceptorSnafu)?;
            policy = policy
                .reload_and_install_for_test_objects(
                    &node_config,
                    &mut host,
                    node_boot_id,
                    1,
                    test_exact_objects.clone(),
                )
                .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate_initial_with_effect_policy(&mut host, true)
                .context(NodeSnafu)?;
            let sink = observations.clone();
            reader = host
                .effect_observation_reader(move |bytes| {
                    sink.record_bytes(bytes);
                    0
                })
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map_locked("exception_runtime_states", &key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(exception.as_slice()),
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "loader restart changed the exhausted exception state",
                }
            );
            let restart_marker = observations.cursor();
            ensure!(
                fixture.open_write(&paths.secret)?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "loader restart revived an exhausted bounded exception",
                }
            );
            wait_for_reason(
                &reader,
                &observations,
                restart_marker,
                "EXCEPTION_UNAVAILABLE",
            )?;

            let pending_expiry = host
                .lookup_map_locked("exception_runtime_states", &expiry_key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: "expiry exception state disappeared before its effect",
                    }
                    .build()
                })?;
            let pending_expiry = ExceptionRuntimeStateV1::try_read_from_bytes(&pending_expiry)
                .map_err(|error| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: format!("expiry exception state has invalid ABI: {error}"),
                    }
                    .build()
                })?;
            ensure!(
                pending_expiry.maximum_uses == 1
                    && pending_expiry.consumed_uses == 0
                    && pending_expiry.transition_version == 1
                    && pending_expiry.state == ExceptionRuntimeStateKindV1::Active,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "expiry exception did not start as one unused signed authority",
                }
            );
            let expiry_marker = observations.cursor();
            ensure!(
                fixture.open_write(&paths.benign)?.denied(),
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: "an expired bounded exception allowed a write-open",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                expiry_marker,
                "EXCEPTION_UNAVAILABLE",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenWrite,
                ),
            )?;
            let expired = host
                .lookup_map_locked("exception_runtime_states", &expiry_key)
                .context(InterceptorSnafu)?
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: "expired exception state disappeared",
                    }
                    .build()
                })?;
            let expired =
                ExceptionRuntimeStateV1::try_read_from_bytes(&expired).map_err(|error| {
                    InvalidInputSnafu {
                        path: Path::new("exception_runtime_states"),
                        reason: format!("expired exception state has invalid ABI: {error}"),
                    }
                    .build()
                })?;
            ensure!(
                expired.maximum_uses == 1
                    && expired.consumed_uses == 0
                    && expired.transition_version == 2
                    && expired.state == ExceptionRuntimeStateKindV1::Expired,
                InvalidInputSnafu {
                    path: Path::new("exception_runtime_states"),
                    reason: "expired exception was consumed or did not enter EXPIRED state",
                }
            );

            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
            let inherited_marker = observations.cursor();
            ensure!(
                fixture.read_prepared()?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "a descriptor acquired before activation bypassed the read decision",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                inherited_marker,
                "EXACT_POLICY_DENY",
                (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
                PathSelectorV1::kernel_handle_for_id("manual-secret"),
                None,
            )?;
            let mmap_marker = observations.cursor();
            ensure!(
                fixture.mmap_prepared()?.denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "a descriptor acquired before activation bypassed the mmap decision",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                mmap_marker,
                "EXACT_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::MmapRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-secret"),
                None,
            )?;
            let main_mapping_identity = observations
                .recent_since(mmap_marker)
                .iter()
                .find(|event| {
                    event.reason == "EXACT_POLICY_DENY"
                        && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::MmapRead as u16)
                        && event.exact_object_key_id
                            == PathSelectorV1::kernel_handle_for_id("manual-secret")
                })
                .map(|event| {
                    (
                        event.task_cookie,
                        event.process_lineage_id.clone(),
                        event.process_instance_id.clone(),
                    )
                })
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("effect_observations"),
                        reason: "the primary-root mapping decision has no identity",
                    }
                    .build()
                })?;
            let independent_deny_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::IndependentSecretMmapWrite)?
                    .denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "an independent root acquired the protected shared mapping",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                independent_deny_marker,
                "EXACT_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::MmapWrite,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-secret"),
                None,
            )?;
            let independent_mapping_identity = observations
                .recent_since(independent_deny_marker)
                .iter()
                .find(|event| {
                    event.reason == "EXACT_POLICY_DENY"
                        && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::MmapWrite as u16)
                        && event.exact_object_key_id
                            == PathSelectorV1::kernel_handle_for_id("manual-secret")
                })
                .map(|event| {
                    (
                        event.task_cookie,
                        event.process_lineage_id.clone(),
                        event.process_instance_id.clone(),
                    )
                })
                .ok_or_else(|| {
                    InvalidInputSnafu {
                        path: Path::new("effect_observations"),
                        reason: "the independent-root mapping decision has no identity",
                    }
                    .build()
                })?;
            ensure!(
                independent_mapping_identity.0 > 0
                    && independent_mapping_identity.0 != main_mapping_identity.0
                    && independent_mapping_identity.1 != main_mapping_identity.1
                    && independent_mapping_identity.2 != main_mapping_identity.2,
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "the shared-mapping target did not have an independent process root",
                }
            );
            let independent_allow_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::IndependentBenignMmapRead)?
                    .allowed,
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: "the independent-root benign mapping control was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                independent_allow_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::MmapRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign"),
                None,
            )?;
        }

        let benign_marker = observations.cursor();
        ensure!(
            fixture.read(&paths.benign)?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "the exact benign control did not remain readable",
            }
        );
        wait_for_reason(&reader, &observations, benign_marker, "EXACT_POLICY_ALLOW")?;

        let io_uring_secret_marker = observations.cursor();
        let io_uring_secret = fixture.run_prepared(HardClosedOperation::IoUringSecretRead)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            if protect {
                io_uring_secret.denied()
            } else {
                io_uring_secret.allowed
            },
            InvalidInputSnafu {
                path: &paths.secret,
                reason: format!(
                    "the exact io_uring secret-read result did not match the profile mode: {io_uring_secret:?}; observed {:?}",
                    observations
                        .recent_since(io_uring_secret_marker)
                        .iter()
                        .map(|event| {
                            (
                                (
                                    event.observed_boottime_ns,
                                    event.task_cookie,
                                    event.reason.as_str(),
                                    event.effect_family,
                                    event.operation,
                                    event.operation_argument,
                                    event.exact_object_key_id,
                                    event.composite_atom_id,
                                    event.kernel_result,
                                    event.configured_errno,
                                ),
                                (
                                    event.io_uring_ring_id.as_str(),
                                    event.io_uring_submission_sequence,
                                    event.io_uring_user_data,
                                    event.io_uring_file_cookie,
                                    event.io_uring_executor_pid_tgid,
                                    event.io_uring_byte_length,
                                    event.io_uring_request_flags,
                                    event.io_uring_opcode,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                ),
            }
        );
        wait_for_exact_io_uring_effect(
            &reader,
            &observations,
            io_uring_secret_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
        )?;
        let io_uring_benign_marker = observations.cursor();
        let io_uring_benign = fixture.run_prepared(HardClosedOperation::IoUringBenignRead)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            io_uring_benign.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: format!(
                    "the exact io_uring benign read did not complete with the expected byte: {io_uring_benign:?}; observed {:?}",
                    observations
                        .recent_since(io_uring_benign_marker)
                        .iter()
                        .map(|event| {
                            (
                                (
                                    event.observed_boottime_ns,
                                    event.task_cookie,
                                    event.reason.as_str(),
                                    event.effect_family,
                                    event.operation,
                                    event.operation_argument,
                                    event.exact_object_key_id,
                                    event.composite_atom_id,
                                    event.kernel_result,
                                    event.configured_errno,
                                ),
                                (
                                    event.io_uring_ring_id.as_str(),
                                    event.io_uring_submission_sequence,
                                    event.io_uring_user_data,
                                    event.io_uring_file_cookie,
                                    event.io_uring_executor_pid_tgid,
                                    event.io_uring_byte_length,
                                    event.io_uring_request_flags,
                                    event.io_uring_opcode,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                ),
            }
        );
        wait_for_exact_io_uring_effect(
            &reader,
            &observations,
            io_uring_benign_marker,
            "EXACT_POLICY_ALLOW",
            PathSelectorV1::kernel_handle_for_id("manual-benign"),
        )?;
        let io_uring_sqpoll_marker = observations.cursor();
        ensure!(
            fixture
                .run_prepared(HardClosedOperation::IoUringSqpoll)?
                .denied(),
            InvalidInputSnafu {
                path: Path::new("io_uring SQPOLL"),
                reason: "an SQPOLL ring was created for a managed task",
            }
        );
        wait_for_effect(
            &reader,
            &observations,
            io_uring_sqpoll_marker,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Privilege,
                KernelEffectOperationV1::IoUringSqpoll,
            ),
        )?;
        let io_uring_cleanup_deadline = Instant::now() + Duration::from_secs(5);
        let (
            io_uring_lifecycle_released,
            retained_io_uring_rings,
            retained_io_uring_requests,
            retained_io_uring_generation_ref,
        ) = loop {
            let ring_keys = host
                .map_keys("io_uring_ring_states")
                .context(InterceptorSnafu)?;
            let request_keys = host
                .map_keys("io_uring_request_states")
                .context(InterceptorSnafu)?;
            let async_ref = host
                .lookup_map(
                    "profile_generation_async_refs",
                    &PROFILE_GENERATION_REF_ID.to_ne_bytes(),
                )
                .context(InterceptorSnafu)?;
            let released = ring_keys.is_empty()
                && request_keys.is_empty()
                && async_ref
                    .as_deref()
                    .is_some_and(|bytes| bytes == 0_u64.to_ne_bytes());
            if released || Instant::now() >= io_uring_cleanup_deadline {
                break (released, ring_keys, request_keys, async_ref);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        ensure!(
            io_uring_lifecycle_released,
            InvalidInputSnafu {
                path: Path::new("io_uring lifecycle maps"),
                reason: format!(
                    "a completed io_uring request retained ring, request, or generation authority: rings={}, requests={}, generation_ref={retained_io_uring_generation_ref:?}",
                    retained_io_uring_rings.len(),
                    retained_io_uring_requests.len(),
                ),
            }
        );

        // Both fork children must inherit the active protected identity.
        fixture.prepare_labeled_targets()?;
        if protect {
            require_exact_process_control(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::Signal,
                KernelEffectOperationV1::Signal,
                "EXACT_POLICY_ALLOW",
                false,
            )?;
            require_exact_process_control(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::SignalUnmatched,
                KernelEffectOperationV1::Signal,
                "EXACT_POLICY_DENY",
                true,
            )?;
            require_exact_process_control(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::Ptrace,
                KernelEffectOperationV1::Ptrace,
                "EXACT_POLICY_DENY",
                true,
            )?;
        } else {
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::Signal,
                "UNSUPPORTED_OBJECT",
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Signal,
                ),
                "unmatched signal process control",
            )?;
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::Ptrace,
                "UNSUPPORTED_OBJECT",
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Ptrace,
                ),
                "unmatched ptrace process control",
            )?;
        }

        if protect {
            for (operation, label) in [
                (HardClosedOperation::Execve, "execve image"),
                (HardClosedOperation::Execveat, "execveat image"),
                (HardClosedOperation::Fexecve, "fexecve image"),
                (HardClosedOperation::ScriptExec, "script image"),
                (
                    HardClosedOperation::NonLeaderExec,
                    "non-leader-thread image",
                ),
            ] {
                let marker = require_hard_close(
                    &mut fixture,
                    &reader,
                    &observations,
                    operation,
                    "EXACT_POLICY_DENY",
                    (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
                    label,
                )?;
                wait_for_path_exec_effect(
                    &reader,
                    &observations,
                    marker,
                    "EXACT_POLICY_DENY",
                    KernelEffectOperationV1::Execute,
                )?;
            }
            let deleted_exec_marker = require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::DeletedExec,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
                "deleted image",
            )?;
            wait_for_unsupported_effect(
                &reader,
                &observations,
                deleted_exec_marker,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
            )?;
            let external_exec_marker = observations.cursor();
            let external_exec = fixture.run_prepared(HardClosedOperation::AllowedExec)?;
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            ensure!(
                external_exec.denied(),
                InvalidInputSnafu {
                    path: &paths.allowed_exec_target,
                    reason: format!(
                        "an action-level executable Allow admitted an external entry: {external_exec:?}; observed {:?}",
                        observations
                            .recent_since(external_exec_marker)
                            .iter()
                            .map(|event| (
                                event.reason.as_str(),
                                event.effect_family,
                                event.operation,
                                event.operation_argument,
                            ))
                            .collect::<Vec<_>>()
                    ),
                }
            );
            wait_for_path_exec_effect(
                &reader,
                &observations,
                external_exec_marker,
                "EXACT_POLICY_ALLOW",
                KernelEffectOperationV1::Execute,
            )?;
            wait_for_effect(
                &reader,
                &observations,
                external_exec_marker,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
            )?;

            let proc_marker = observations.cursor();
            ensure!(
                fixture.read(Path::new("/proc/self/environ"))?.denied(),
                InvalidInputSnafu {
                    path: Path::new("/proc/self/environ"),
                    reason: "the managed proc-object open returned a file descriptor or bytes",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                proc_marker,
                "UNRESOLVED_OBJECT",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
        } else {
            let exec_marker = observations.cursor();
            // The signed image decision must be observe-only. A later dynamic
            // loader or library can still fail hard as an unclassified image.
            let _physical_result = fixture.hard_closed(HardClosedOperation::Exec)?;
            wait_for_path_exec_effect(
                &reader,
                &observations,
                exec_marker,
                "WOULD_DENY",
                KernelEffectOperationV1::Execute,
            )?;
        }
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::AnonymousExec,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Exec,
                KernelEffectOperationV1::Mprotect,
            ),
            "anonymous executable memory",
        )?;
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::AnonymousExecutableMmap,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Exec,
                KernelEffectOperationV1::MmapExec,
            ),
            "anonymous executable mmap",
        )?;
        ensure!(
            fixture
                .run_prepared(HardClosedOperation::AnonymousReadMmap)?
                .allowed,
            InvalidInputSnafu {
                path: Path::new("anonymous read mmap"),
                reason: "the anonymous non-executable mmap control was denied",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::PkeyExecutableMprotect,
            "UNSUPPORTED_OBJECT",
            (
                KernelEffectFamilyV1::Exec,
                KernelEffectOperationV1::Mprotect,
            ),
            "pkey_mprotect executable memory",
        )?;
        ensure!(
            fixture
                .run_prepared(HardClosedOperation::PkeyReadMprotect)?
                .allowed,
            InvalidInputSnafu {
                path: Path::new("pkey_mprotect read control"),
                reason: "the pkey_mprotect non-executable control was denied",
            }
        );
        if protect {
            for (operation, family, kernel_operation, label) in [
                (
                    HardClosedOperation::SecretMmapWrite,
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::MmapWrite,
                    "shared writable file mapping",
                ),
                (
                    HardClosedOperation::SecretMmapExec,
                    KernelEffectFamilyV1::Exec,
                    KernelEffectOperationV1::MmapExec,
                    "file executable mapping",
                ),
                (
                    HardClosedOperation::SecretMprotectReadExec,
                    KernelEffectFamilyV1::Exec,
                    KernelEffectOperationV1::Mprotect,
                    "read-to-executable mprotect",
                ),
                (
                    HardClosedOperation::SecretMprotectWriteExec,
                    KernelEffectFamilyV1::Exec,
                    KernelEffectOperationV1::Mprotect,
                    "write-to-executable mprotect",
                ),
            ] {
                let marker = require_hard_close(
                    &mut fixture,
                    &reader,
                    &observations,
                    operation,
                    "EXACT_POLICY_DENY",
                    (family, kernel_operation),
                    label,
                )?;
                wait_for_exact_effect(
                    &reader,
                    &observations,
                    marker,
                    "EXACT_POLICY_DENY",
                    (family, kernel_operation),
                    PathSelectorV1::kernel_handle_for_id("manual-secret"),
                    None,
                )?;
            }
            let memfd_exec_marker = require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::MemfdExec,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
                "memfd execution",
            )?;
            wait_for_unsupported_effect(
                &reader,
                &observations,
                memfd_exec_marker,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
            )?;
            for (operation, label) in [
                (
                    HardClosedOperation::DeletedMprotectExec,
                    "deleted-file mprotect",
                ),
                (HardClosedOperation::MemfdMprotectExec, "memfd mprotect"),
            ] {
                let marker = require_hard_close(
                    &mut fixture,
                    &reader,
                    &observations,
                    operation,
                    "UNSUPPORTED_OBJECT",
                    (
                        KernelEffectFamilyV1::Exec,
                        KernelEffectOperationV1::Mprotect,
                    ),
                    label,
                )?;
                wait_for_unsupported_effect(
                    &reader,
                    &observations,
                    marker,
                    "UNSUPPORTED_OBJECT",
                    (
                        KernelEffectFamilyV1::Exec,
                        KernelEffectOperationV1::Mprotect,
                    ),
                )?;
            }
            let benign_mmap_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::BenignMmapRead)?
                    .allowed,
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: "the signed exact benign mapping control was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                benign_mmap_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::MmapRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign"),
                None,
            )?;
        }
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Create {
                path: create_target.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Create),
            "file creation",
        )?;
        ensure!(
            !create_target.exists(),
            InvalidInputSnafu {
                path: &create_target,
                reason: "denied creation left a filesystem object behind",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Setattr {
                path: setattr_target.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Setattr),
            "file attribute mutation",
        )?;
        ensure!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(&setattr_target)
                    .context(IoSnafu {
                        path: &setattr_target,
                    })?
                    .permissions()
            ) & 0o777
                == 0o600,
            InvalidInputSnafu {
                path: &setattr_target,
                reason: "denied chmod changed the file mode",
            }
        );
        let truncate_length = fs::metadata(&truncate_target)
            .context(IoSnafu {
                path: &truncate_target,
            })?
            .len();
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Truncate,
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Setattr),
            "file truncation",
        )?;
        ensure!(
            fs::metadata(&truncate_target)
                .context(IoSnafu {
                    path: &truncate_target,
                })?
                .len()
                == truncate_length,
            InvalidInputSnafu {
                path: &truncate_target,
                reason: "denied truncate changed the file length",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Unlink {
                path: unlink_target.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Unlink),
            "file unlink",
        )?;
        ensure!(
            unlink_target.exists(),
            InvalidInputSnafu {
                path: &unlink_target,
                reason: "denied unlink removed its target",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Link {
                source: mutation_source.clone(),
                target: link_target.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Link),
            "hard-link creation",
        )?;
        ensure!(
            !link_target.exists(),
            InvalidInputSnafu {
                path: &link_target,
                reason: "denied link created its target",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::Rename {
                source: mutation_source.clone(),
                target: rename_target.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Rename),
            "file rename",
        )?;
        ensure!(
            mutation_source.exists() && !rename_target.exists(),
            InvalidInputSnafu {
                path: &rename_target,
                reason: "denied rename changed the source or target",
            }
        );
        for (operation, effect, label) in [
            (
                HardClosedOperation::Ipc,
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
                "SysV IPC access",
            ),
            (
                HardClosedOperation::Namespace,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Capability,
                ),
                "namespace privilege",
            ),
            (
                HardClosedOperation::Bpf,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Bpf,
                ),
                "BPF map creation",
            ),
        ] {
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                operation,
                "UNSUPPORTED_OBJECT",
                effect,
                label,
            )?;
        }
        let unix_stream_marker = observations.cursor();
        let unix_stream_outcome = fixture.run_prepared(HardClosedOperation::UnixStream)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            unix_stream_outcome.allowed,
            InvalidInputSnafu {
                path: fixture_root.join("relationship.sock"),
                reason: format!(
                    "Unix-stream IPC did not produce the configured relationship classification: {unix_stream_outcome:?}; observed {:?}",
                    observations
                        .recent_since(unix_stream_marker)
                        .iter()
                        .map(|event| {
                            (
                                event.reason.as_str(),
                                event.effect_family,
                                event.operation,
                                event.operation_argument,
                            )
                        })
                        .collect::<Vec<_>>()
                ),
            }
        );
        if protect {
            wait_for_effect(
                &reader,
                &observations,
                unix_stream_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
            )?;
            let relationship_operations = observations
                .recent_since(unix_stream_marker)
                .into_iter()
                .filter(|event| event.reason == "EXACT_POLICY_ALLOW")
                .map(|event| event.operation_argument)
                .collect::<std::collections::BTreeSet<_>>();
            ensure!(
                relationship_operations
                    == [
                        IpcOperationV1::Connect as u32,
                        IpcOperationV1::Send as u32,
                        IpcOperationV1::Receive as u32,
                    ]
                    .into_iter()
                    .collect(),
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "the exact Unix-stream allow did not cover connect, send, and receive",
                }
            );

            let inherited_stream_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::InheritedUnixStreamSend)?
                    .denied(),
                InvalidInputSnafu {
                    path: Path::new("inherited Unix-stream endpoint"),
                    reason: "a fork child borrowed its parent's exact Unix-stream endpoint",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                inherited_stream_marker,
                "CORRUPT_IDENTITY_OR_GENERATION",
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
            )?;

            let passed_secret_descriptors = process_descriptor_set(fixture.pid())?;
            let passed_secret_acquisition_marker = observations.cursor();
            let passed_secret_acquisition = fixture.receive_passed_secret()?;
            let passed_secret_descriptors_after = process_descriptor_set(fixture.pid())?;
            ensure!(
                passed_secret_acquisition.payload_received
                    && passed_secret_acquisition.control_truncated
                    && passed_secret_acquisition.installed_descriptors == 0
                    && !passed_secret_acquisition.read_allowed
                    && passed_secret_descriptors_after == passed_secret_descriptors,
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: format!(
                        "denied SCM_RIGHTS acquisition installed a descriptor: {passed_secret_acquisition:?}"
                    ),
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                passed_secret_acquisition_marker,
                "EXACT_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;

            let passed_benign_descriptors = process_descriptor_set(fixture.pid())?;
            let passed_benign_acquisition_marker = observations.cursor();
            let passed_benign_acquisition = fixture.receive_passed_benign()?;
            let passed_benign_descriptors_after = process_descriptor_set(fixture.pid())?;
            ensure!(
                passed_benign_acquisition.payload_received
                    && !passed_benign_acquisition.control_truncated
                    && passed_benign_acquisition.installed_descriptors == 1
                    && passed_benign_acquisition.read_allowed
                    && passed_benign_descriptors
                        .difference(&passed_benign_descriptors_after)
                        .next()
                        .is_none()
                    && passed_benign_descriptors_after
                        .difference(&passed_benign_descriptors)
                        .count()
                        == 1,
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: format!(
                        "allowed SCM_RIGHTS acquisition did not install and read one descriptor: {passed_benign_acquisition:?}"
                    ),
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                passed_benign_acquisition_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;

            let stale_marker = observations.cursor();
            let stale_outcome = fixture.run_prepared(HardClosedOperation::UnixStreamStalePeer)?;
            ensure!(
                stale_outcome.denied(),
                InvalidInputSnafu {
                    path: Path::new("effect Unix-stream peer"),
                    reason: "a connected socket retained positive authority after its peer exited",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                stale_marker,
                "CORRUPT_IDENTITY_OR_GENERATION",
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
            )?;

            let unmatched_marker = observations.cursor();
            let unmatched_outcome =
                fixture.run_prepared(HardClosedOperation::UnixStreamUnmatched)?;
            ensure!(
                unmatched_outcome.denied(),
                InvalidInputSnafu {
                    path: Path::new("effect Unix-stream peer"),
                    reason: "an unmatched Unix-stream peer bypassed the configured denial",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                unmatched_marker,
                "EXACT_POLICY_DENY",
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
            )?;
        } else {
            wait_for_effect(
                &reader,
                &observations,
                unix_stream_marker,
                "WOULD_DENY",
                (
                    KernelEffectFamilyV1::Ipc,
                    KernelEffectOperationV1::IpcAccess,
                ),
            )?;
        }
        ensure!(
            !observations
                .recent_since(unix_stream_marker)
                .iter()
                .any(|event| {
                    event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::Create as u16)
                }),
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: "the abstract Unix-stream case reached the file-create path",
            }
        );
        if protect {
            let device_allow_marker = observations.cursor();
            let device_allow = fixture.run_prepared(HardClosedOperation::Ioctl)?;
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            ensure!(
                device_allow.allowed,
                InvalidInputSnafu {
                    path: Path::new("/dev/pts/ptmx"),
                    reason: format!(
                        "the exact PTMX ioctl did not succeed with kernel output: {device_allow:?}; observed {:?}",
                        observations
                            .recent_since(device_allow_marker)
                            .iter()
                            .map(|event| {
                                (
                                    (
                                        event.reason.as_str(),
                                        event.effect_family,
                                        event.operation,
                                        event.operation_argument,
                                    ),
                                    (
                                        event.mount_namespace_inode,
                                        event.mount_id_unique,
                                        event.filesystem_device,
                                        event.inode,
                                        event.inode_generation,
                                        event.exact_object_key_id,
                                        event.composite_atom_id,
                                    ),
                                    (event.active_role_id, event.process_state_vector_id),
                                )
                            })
                            .collect::<Vec<_>>()
                    ),
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                device_allow_marker,
                "EXACT_POLICY_ALLOW",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                PathSelectorV1::kernel_handle_for_id("manual-device-ptmx"),
                Some(QUALIFIED_TIOCGPTN_IOCTL),
            )?;
            let descriptors_before = process_descriptor_set(fixture.pid())?;
            let derived_peer_marker = require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::IoctlDerivedPeer,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                "PTMX derived-peer acquisition",
            )?;
            let descriptors_after = process_descriptor_set(fixture.pid())?;
            ensure!(
                descriptors_after == descriptors_before,
                InvalidInputSnafu {
                    path: Path::new("/dev/pts/ptmx"),
                    reason: "denied PTMX derived-peer acquisition installed a descriptor",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                derived_peer_marker,
                "UNSUPPORTED_OBJECT",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                PathSelectorV1::kernel_handle_for_id("manual-device-ptmx"),
                Some(QUALIFIED_TIOCGPTPEER_IOCTL),
            )?;
            let device_deny_marker = require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::IoctlUnsupported,
                "EXACT_POLICY_DENY",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                "exact denied device ioctl",
            )?;
            wait_for_exact_effect(
                &reader,
                &observations,
                device_deny_marker,
                "EXACT_POLICY_DENY",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                PathSelectorV1::kernel_handle_for_id("manual-device-zero"),
                Some(QUALIFIED_TIOCGPTN_IOCTL),
            )?;
        } else {
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                HardClosedOperation::Ioctl,
                "UNRESOLVED_OBJECT",
                (KernelEffectFamilyV1::Device, KernelEffectOperationV1::Ioctl),
                "unclassified device ioctl",
            )?;
        }
        let protected_link = pin_root.join("links/erebor_identity_file_open");
        ensure!(
            protected_link.exists(),
            InvalidInputSnafu {
                path: &protected_link,
                reason: "the self-protection fixture link is not pinned",
            }
        );
        require_hard_close(
            &mut fixture,
            &reader,
            &observations,
            HardClosedOperation::SelfProtect {
                path: protected_link.clone(),
            },
            "UNRESOLVED_OBJECT",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Unlink),
            "Mithril BPF-link removal",
        )?;
        ensure!(
            protected_link.exists(),
            InvalidInputSnafu {
                path: &protected_link,
                reason: "denied self-protection attack removed the BPF link pin",
            }
        );

        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        let original_marker = observations.cursor();
        let original = fixture.open(&paths.secret)?;
        if original.allowed == protect {
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            return InvalidInputSnafu {
                path: &paths.secret,
                reason: format!(
                    "exact file decision did not match protect={protect}; observed {:?}; expected file (mount_namespace={},mount_id={},device={},inode={},generation={},object={}); mount view dirty={}",
                    observations
                        .recent_since(original_marker)
                        .iter()
                        .map(|event| format!(
                            "{}(mount_namespace={},mount_id={},device={},inode={},generation={},object={},composite={})",
                            event.reason,
                            event.mount_namespace_inode,
                            event.mount_id_unique,
                            event.filesystem_device,
                            event.inode,
                            event.inode_generation,
                            event.exact_object_key_id,
                            event.composite_atom_id,
                        ))
                        .collect::<Vec<_>>(),
                    exact_object.mount_namespace_inode,
                    exact_object.mount_id_unique,
                    exact_object.filesystem_device,
                    exact_object.inode,
                    exact_object.inode_generation,
                    exact_object.exact_object_key_id,
                    mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?
                ),
            }
            .fail();
        }
        let exact_reason = if protect {
            "EXACT_POLICY_DENY"
        } else {
            "WOULD_DENY"
        };
        wait_for_effect(
            &reader,
            &observations,
            original_marker,
            exact_reason,
            (
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
            ),
        )?;
        let original_composite_atom_id = observations
            .recent_since(original_marker)
            .iter()
            .find(|event| {
                event.reason == exact_reason
                    && event.exact_object_key_id == PathSelectorV1::kernel_handle_for_id("manual-secret")
                    && event.composite_atom_id > 0
            })
            .map(|event| event.composite_atom_id)
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "the original exact-object result lacked its object and composite authority",
                }
                .build()
            })?;

        if protect {
            for branch in ["HF-006", "HF-008", "HF-009", "HF-010"] {
                let marker = observations.cursor();
                ensure!(
                    fixture.open(&paths.secret)?.denied(),
                    InvalidInputSnafu {
                        path: &paths.secret,
                        reason: format!(
                            "{branch} exact protected-file branch returned a file descriptor"
                        ),
                    }
                );
                wait_for_exact_effect(
                    &reader,
                    &observations,
                    marker,
                    "EXACT_POLICY_DENY",
                    (
                        KernelEffectFamilyV1::File,
                        KernelEffectOperationV1::OpenRead,
                    ),
                    PathSelectorV1::kernel_handle_for_id("manual-secret"),
                    None,
                )?;
            }
        }

        let symlink_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.symlink_alias)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.symlink_alias,
                reason: "symlink resolution changed the exact object decision",
            }
        );
        wait_for_exact_effect(
            &reader,
            &observations,
            symlink_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
            (
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
            ),
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            None,
        )?;

        if protect {
            let proc_fd_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::ProcFdOpen)?
                    .denied(),
                InvalidInputSnafu {
                    path: Path::new("/proc/self/fd"),
                    reason: "a proc-fd alias bypassed the exact object denial",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                proc_fd_marker,
                "EXACT_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-secret"),
                None,
            )?;

            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
            let passed_secret_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::PassedSecretRead)?
                    .denied(),
                InvalidInputSnafu {
                    path: &paths.secret,
                    reason: "an SCM_RIGHTS descriptor bypassed the current actor decision",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                passed_secret_marker,
                "EXACT_POLICY_DENY",
                (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
                PathSelectorV1::kernel_handle_for_id("manual-secret"),
                None,
            )?;

            let passed_benign_marker = observations.cursor();
            ensure!(
                fixture
                    .run_prepared(HardClosedOperation::PassedBenignRead)?
                    .allowed,
                InvalidInputSnafu {
                    path: &paths.benign,
                    reason: "the SCM_RIGHTS benign descriptor control was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                passed_benign_marker,
                "EXACT_POLICY_ALLOW",
                (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
                PathSelectorV1::kernel_handle_for_id("manual-benign"),
                None,
            )?;
        }

        let hard_link_marker = observations.cursor();
        let hard_link = fixture.open(&paths.hard_link)?;
        ensure!(
            hard_link.denied(),
            InvalidInputSnafu {
                path: &paths.hard_link,
                reason: "hard-link alias inherited the original path decision",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            hard_link_marker,
            "UNRESOLVED_OBJECT",
        )?;

        for (bind_alias, bind_alias_object) in [
            (&paths.bind_alias, &bind_alias_object),
            (&paths.second_bind_alias, &second_bind_alias_object),
        ] {
            let bind_marker = observations.cursor();
            let bind_alias_outcome = fixture.open(bind_alias)?;
            if bind_alias_outcome.allowed == protect {
                reader
                    .poll(Duration::from_millis(100))
                    .context(InterceptorSnafu)?;
            }
            ensure!(
                bind_alias_outcome.allowed != protect,
                InvalidInputSnafu {
                    path: bind_alias,
                    reason: format!(
                        "pre-existing bind alias did not preserve the exact policy result: {:?}",
                        observations
                            .recent_since(bind_marker)
                            .iter()
                            .map(|event| (
                                event.reason.as_str(),
                                event.active_role_id,
                                event.admitted_entry_rule_id,
                                event.exact_object_key_id,
                                event.composite_atom_id,
                                event.kernel_result,
                            ))
                            .collect::<Vec<_>>()
                    ),
                }
            );
            if protect {
                ensure!(
                    bind_alias_outcome.denied(),
                    InvalidInputSnafu {
                        path: bind_alias,
                        reason: "protected bind alias returned a file descriptor",
                    }
                );
            }
            wait_for_effect(
                &reader,
                &observations,
                bind_marker,
                exact_reason,
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            ensure!(
                observations
                    .recent_since(bind_marker)
                    .iter()
                    .any(|event| {
                        event.reason == exact_reason
                            && event.mount_id_unique == bind_alias_object.mount_id_unique
                            && event.filesystem_device == bind_alias_object.filesystem_device
                            && event.inode == bind_alias_object.inode
                            && event.inode_generation == bind_alias_object.inode_generation
                            && event.exact_object_key_id == PathSelectorV1::kernel_handle_for_id("manual-secret")
                            && event.composite_atom_id == original_composite_atom_id
                    }),
                InvalidInputSnafu {
                    path: Path::new("effect_observations"),
                    reason: "bind-alias evidence did not preserve the live alias identity and canonical exact authority",
                }
            );
        }

        for (operation, expected_effect, label) in [
            (
                HardClosedOperation::MoveMount,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Capability,
                ),
                "detached move_mount capability precondition",
            ),
            (
                HardClosedOperation::MountSetattr,
                (
                    KernelEffectFamilyV1::Privilege,
                    KernelEffectOperationV1::Capability,
                ),
                "mount_setattr capability precondition",
            ),
            (
                HardClosedOperation::MountPropagation,
                (KernelEffectFamilyV1::Mount, KernelEffectOperationV1::Mount),
                "mount propagation mutation",
            ),
        ] {
            require_hard_close(
                &mut fixture,
                &reader,
                &observations,
                operation,
                "UNSUPPORTED_OBJECT",
                expected_effect,
                label,
            )?;
        }

        let mount_marker = observations.cursor();
        let mount_race = fixture.mount_race(&paths.source, mount_race_target, 8)?;
        ensure!(
            mount_race.allowed == 0 && mount_race.denied == 8 && mount_race.other_errors == 0,
            InvalidInputSnafu {
                path: mount_race_target,
                reason: "one or more protected mount attempts escaped hard safety",
            }
        );
        wait_for_effect(
            &reader,
            &observations,
            mount_marker,
            "UNSUPPORTED_OBJECT",
            (KernelEffectFamilyV1::Mount, KernelEffectOperationV1::Mount),
        )?;
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        let reconciled_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.secret)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "failed protected mounts left the exact path permanently unavailable",
            }
        );
        wait_for_exact_effect(
            &reader,
            &observations,
            reconciled_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
            (
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
            ),
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            None,
        )?;

        let stale_proposal_key = exact_object.mount_namespace_inode.to_ne_bytes();
        let clean_view_bytes = host
            .lookup_map("mount_security_views", &stale_proposal_key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("mount_security_views"),
                    reason: "the exact mount view disappeared before the stale proposal test",
                }
                .build()
            })?;
        let clean_view =
            MountSecurityViewStateV1::try_read_from_bytes(&clean_view_bytes).map_err(|error| {
                InvalidInputSnafu {
                    path: Path::new("mount_security_views"),
                    reason: format!("mount security view has invalid ABI: {error}"),
                }
                .build()
            })?;
        let stale_proposal_bytes = host
            .lookup_map("mount_reconciliation_proposals", &stale_proposal_key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("mount_reconciliation_proposals"),
                    reason: "the clean mount view has no reconciliation proposal",
                }
                .build()
            })?;
        let stale_proposal = MountReconciliationProposalV1::try_read_from_bytes(
            &stale_proposal_bytes,
        )
        .map_err(|error| {
            InvalidInputSnafu {
                path: Path::new("mount_reconciliation_proposals"),
                reason: format!("mount reconciliation proposal has invalid ABI: {error}"),
            }
            .build()
        })?;
        ensure!(
            clean_view.state == MountTopologyStateV1::Clean
                && clean_view.pending_mutations == 0
                && stale_proposal.topology_generation == clean_view.topology_generation
                && stale_proposal.snapshot_digest_id == clean_view.snapshot_digest_id
                && stale_proposal.transition_version == clean_view.transition_version
                && stale_proposal.topology_generation != 0
                && stale_proposal.snapshot_digest_id != 0
                && stale_proposal.transition_version > stale_proposal.expected_transition_version,
            InvalidInputSnafu {
                path: Path::new("mount_reconciliation_proposals"),
                reason: "the clean mount view did not retain a usable proposal",
            }
        );

        external_mount_namespace.bind_mount(&paths.source, &paths.mount_target)?;
        ensure!(
            global_mount_view_is_dirty(&host)?
                && mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?,
            InvalidInputSnafu {
                path: &paths.mount_target,
                reason: "an external topology change did not dirty the exact mount view",
            }
        );
        host.update_map(
            "mount_reconciliation_proposals",
            &stale_proposal_key,
            stale_proposal.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("mount_reconciliation_proposals", &stale_proposal_key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(stale_proposal.as_bytes()),
            InvalidInputSnafu {
                path: Path::new("mount_reconciliation_proposals"),
                reason: "the stale mount proposal readback changed",
            }
        );
        ensure!(
            !host
                .apply_mount_reconciliation_proposal(exact_object.mount_namespace_inode)
                .context(InterceptorSnafu)?,
            InvalidInputSnafu {
                path: Path::new("mount_reconciliation_proposals"),
                reason: "a stale mount proposal committed after an external topology change",
            }
        );
        ensure!(
            global_mount_view_is_dirty(&host)?
                && mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?,
            InvalidInputSnafu {
                path: &paths.mount_target,
                reason: "a rejected stale proposal cleared the exact mount view",
            }
        );
        let stale_proposal_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.secret)?.denied(),
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "a stale mount proposal made the exact path readable",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            stale_proposal_marker,
            "UNRESOLVED_OBJECT",
        )?;
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        let current_proposal_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.secret)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "the current mount snapshot did not restore the exact policy result",
            }
        );
        wait_for_exact_effect(
            &reader,
            &observations,
            current_proposal_marker,
            exact_reason,
            (
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
            ),
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            None,
        )?;
        external_mount_namespace.unmount(&paths.mount_target)?;
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;

        external_mount_namespace.bind_mount(&paths.benign, &paths.secret)?;
        ensure!(
            mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?,
            InvalidInputSnafu {
                path: &paths.secret,
                reason:
                    "an external mount-namespace mutation did not mark the protected view DIRTY",
            }
        );
        let replacement_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.secret)?.denied(),
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "a replaced exact path was physically allowed while its topology was DIRTY",
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            replacement_marker,
            "UNRESOLVED_OBJECT",
        )?;
        ensure!(
            policy.reconcile_mount_views(&mut host).is_err(),
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "reconciliation accepted a different object mounted over the exact path",
            }
        );
        external_mount_namespace.unmount(&paths.secret)?;
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        let restored_marker = observations.cursor();
        ensure!(
            fixture.open(&paths.secret)?.allowed != protect,
            InvalidInputSnafu {
                path: &paths.secret,
                reason:
                    "the exact object did not recover after the hostile replacement was removed",
            }
        );
        wait_for_exact_effect(
            &reader,
            &observations,
            restored_marker,
            if protect {
                "EXACT_POLICY_DENY"
            } else {
                "WOULD_DENY"
            },
            (
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
            ),
            PathSelectorV1::kernel_handle_for_id("manual-secret"),
            None,
        )?;

        if protect {
            external_mount_namespace
                .bind_mount(&path_tree_root, &path_tree_postactivation_bind_target)?;
            ensure!(
                global_mount_view_is_dirty(&host)?
                    && mount_view_is_dirty(&host, exact_object.mount_namespace_inode)?,
                InvalidInputSnafu {
                    path: &path_tree_postactivation_bind_target,
                    reason: "a successful protected-tree bind did not dirty its mount view",
                }
            );
            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
            let path_tree_mount_marker = observations.cursor();
            let mounted_child = path_tree_postactivation_bind_target.join("pre-existing");
            ensure!(
                fixture.open(&mounted_child)?.denied(),
                InvalidInputSnafu {
                    path: &mounted_child,
                    reason: "a successful reconciled bind exposed a protected child",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                path_tree_mount_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            path_tree_postactivation_bind_alias_denied = true;

            let allowed_alias_marker = observations.cursor();
            ensure!(
                fixture.open(&allowed_bind_alias)?.allowed,
                InvalidInputSnafu {
                    path: &allowed_bind_alias,
                    reason: "the allowed bind alias was denied after mount reconciliation",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                allowed_alias_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
                None,
            )?;
            external_mount_namespace.unmount(&path_tree_postactivation_bind_target)?;
        }
        external_mount_namespace.unmount(&path_tree_preexisting_bind_target)?;
        external_mount_namespace.unmount(&allowed_bind_target)?;
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;

        if protect {
            external_mount_namespace
                .recursive_bind_mount(&path_tree_root, &path_tree_recursive_bind_target)?;
            external_mount_namespace
                .recursive_bind_mount(&allowed_bind_source, &allowed_recursive_bind_target)?;
            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;

            let protected_recursive_child = path_tree_recursive_bind_target.join("pre-existing");
            let protected_recursive_marker = observations.cursor();
            ensure!(
                fixture.open(&protected_recursive_child)?.denied(),
                InvalidInputSnafu {
                    path: &protected_recursive_child,
                    reason: "a successful recursive bind exposed a protected child",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                protected_recursive_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            path_tree_recursive_bind_alias_denied = true;

            let allowed_recursive_marker = observations.cursor();
            ensure!(
                fixture.open(&allowed_recursive_bind_alias)?.allowed,
                InvalidInputSnafu {
                    path: &allowed_recursive_bind_alias,
                    reason: "the allowed recursive bind alias was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                allowed_recursive_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
                None,
            )?;
            allowed_recursive_bind_alias_allowed = true;

            external_mount_namespace.unmount(&path_tree_recursive_bind_target)?;
            external_mount_namespace.unmount(&allowed_recursive_bind_target)?;
            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;

            external_mount_namespace.move_mount(&path_tree_root, &path_tree_move_mount_target)?;
            external_mount_namespace
                .move_mount(&allowed_bind_source, &allowed_move_mount_target)?;
            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;

            let protected_move_child = path_tree_move_mount_target.join("pre-existing");
            let protected_move_marker = observations.cursor();
            ensure!(
                fixture.open(&protected_move_child)?.denied(),
                InvalidInputSnafu {
                    path: &protected_move_child,
                    reason: "a successful move_mount attachment exposed a protected child",
                }
            );
            wait_for_effect(
                &reader,
                &observations,
                protected_move_marker,
                "PATH_TREE_POLICY_DENY",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
            )?;
            path_tree_move_mount_alias_denied = true;

            let allowed_move_marker = observations.cursor();
            ensure!(
                fixture.open(&allowed_move_mount_alias)?.allowed,
                InvalidInputSnafu {
                    path: &allowed_move_mount_alias,
                    reason: "the allowed move_mount alias was denied",
                }
            );
            wait_for_exact_effect(
                &reader,
                &observations,
                allowed_move_marker,
                "EXACT_POLICY_ALLOW",
                (
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                ),
                PathSelectorV1::kernel_handle_for_id("manual-benign-bind"),
                None,
            )?;
            allowed_move_mount_alias_allowed = true;

            external_mount_namespace.unmount(&path_tree_move_mount_target)?;
            external_mount_namespace.unmount(&allowed_move_mount_target)?;
            reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        }

        ensure!(
            fixture.propagation_peer_open()?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "the propagation-peer benign control was denied before mutation",
            }
        );
        external_mount_namespace
            .bind_mount(&paths.propagation_source, &paths.propagation_target)?;
        ensure!(
            fixture.propagation_peer_has_marker()?,
            InvalidInputSnafu {
                path: &paths.propagation_marker,
                reason: "the shared mount did not propagate into the peer namespace",
            }
        );
        ensure!(
            fixture.open(&paths.benign)?.denied() && fixture.propagation_peer_open()?.denied(),
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "one represented namespace authorized an exact open after propagation",
            }
        );
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        ensure!(
            fixture.open(&paths.benign)?.allowed && fixture.propagation_peer_open()?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "the propagated topology did not reconcile across both namespaces",
            }
        );
        external_mount_namespace.unmount(&paths.propagation_target)?;
        ensure!(
            !fixture.propagation_peer_has_marker()? && fixture.propagation_peer_open()?.denied(),
            InvalidInputSnafu {
                path: &paths.propagation_marker,
                reason: "propagated unmount did not invalidate the peer namespace",
            }
        );
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        ensure!(
            fixture.propagation_peer_open()?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "the peer exact decision did not recover after propagated unmount",
            }
        );

        external_mount_namespace.mount_setattr(&paths.mount_target, true)?;
        ensure!(
            global_mount_view_is_dirty(&host)?
                && fixture.open(&paths.benign)?.denied()
                && fixture.propagation_peer_open()?.denied(),
            InvalidInputSnafu {
                path: &paths.mount_target,
                reason: "mount_setattr did not invalidate every represented namespace",
            }
        );
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        ensure!(
            fixture.open(&paths.benign)?.allowed && fixture.propagation_peer_open()?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "mount_setattr topology did not reconcile",
            }
        );
        external_mount_namespace.mount_setattr(&paths.mount_target, false)?;
        ensure!(
            global_mount_view_is_dirty(&host)?,
            InvalidInputSnafu {
                path: &paths.mount_target,
                reason: "mount_setattr restore did not invalidate the global view",
            }
        );
        reconcile_mount_views_until_clean(&policy, &mut host, &mount_namespaces)?;
        ensure!(
            fixture.open(&paths.benign)?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "mount_setattr restore did not reconcile",
            }
        );

        policy = policy
            .reload_and_install_for_test_objects(
                &next_node_config,
                &mut host,
                node_boot_id,
                1,
                next_test_exact_objects,
            )
            .context(NodeSnafu)?;
        let active_generation = host
            .lookup_map(
                "active_profile_generations",
                Id128V1::new(0x1111_1111_1111_4111, 0x8111_1111_1111_1111).as_bytes(),
            )
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("active_profile_generations"),
                    reason: "profile generation 2 was not published",
                }
                .build()
            })?;
        let new_roots_generation_published_atomically =
            u64::from_ne_bytes(active_generation.try_into().unwrap_or_default())
                == NEXT_PROFILE_GENERATION_REF_ID;
        ensure!(
            new_roots_generation_published_atomically,
            InvalidInputSnafu {
                path: Path::new("active_profile_generations"),
                reason: "profile generation 2 did not become the one active new-root generation",
            }
        );
        let retiring = host
            .lookup_map(
                "profile_generation_descriptors",
                &PROFILE_GENERATION_REF_ID.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("profile_generation_descriptors"),
                    reason: "generation 1 was deleted while it still had task holders",
                }
                .build()
            })?;
        let retiring =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&retiring).map_err(|error| {
                InvalidInputSnafu {
                    path: Path::new("profile_generation_descriptors"),
                    reason: format!("generation 1 descriptor is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            retiring.state == PolicyGenerationStateV1::Retiring,
            InvalidInputSnafu {
                path: Path::new("profile_generation_descriptors"),
                reason: "generation 1 did not enter RETIRING while its tasks remained live",
            }
        );
        let retained_marker = observations.cursor();
        ensure!(
            fixture.read(&paths.benign)?.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "an existing task lost its pinned generation during activation",
            }
        );
        wait_for_exact_effect(
            &reader,
            &observations,
            retained_marker,
            "EXACT_POLICY_ALLOW",
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
            PathSelectorV1::kernel_handle_for_id("manual-benign"),
            None,
        )?;
        let existing_tasks_retained_old_generation = observations
            .recent_since(retained_marker)
            .iter()
            .any(|event| {
                event.reason == "EXACT_POLICY_ALLOW"
                    && event.profile_generation_ref_id == PROFILE_GENERATION_REF_ID
                    && event.exact_object_key_id
                        == PathSelectorV1::kernel_handle_for_id("manual-benign")
            });
        ensure!(
            existing_tasks_retained_old_generation,
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: "existing task evidence did not retain generation 1",
            }
        );

        let before_latency = sample_observation_health(&host, &observations)?;
        let observed_samples = fixture.open_samples(&paths.secret, measured_opens)?;
        let observed = observed_samples.batch;
        ensure!(
            observed.other_errors == 0
                && if protect {
                    observed.denied == measured_opens && observed.allowed == 0
                } else {
                    observed.denied == 0 && observed.allowed == measured_opens
                },
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "latency sample did not preserve the selected policy mode",
            }
        );
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let pre_saturation = sample_observation_health(&host, &observations)?;
        let latency_delta = health_delta(pre_saturation, before_latency);
        ensure!(
            latency_delta.lost == 0
                && latency_delta.attempted == latency_delta.suppressed + latency_delta.requested
                && latency_delta.requested == latency_delta.emitted,
            InvalidInputSnafu {
                path: Path::new("effect_observation_health"),
                reason: "bounded latency measurement lost effect observations",
            }
        );
        let emitted_source_sequences_monotonic = source_sequences_are_monotonic(&observations);
        ensure!(
            emitted_source_sequences_monotonic,
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: "compiled BPF emitted a zero or non-monotonic per-CPU source sequence",
            }
        );

        let saturation = fixture.open_many(&paths.secret, saturation_opens)?;
        ensure!(
            saturation.other_errors == 0
                && if protect {
                    saturation.denied == saturation_opens && saturation.allowed == 0
                } else {
                    saturation.denied == 0 && saturation.allowed == saturation_opens
                },
            InvalidInputSnafu {
                path: &paths.secret,
                reason: "ring saturation changed the selected policy result",
            }
        );
        let network = fixture.connect()?;
        ensure!(
            network.denied(),
            InvalidInputSnafu {
                path: Path::new("127.0.0.1:9"),
                reason: "ring saturation changed the unsupported-network hard denial",
            }
        );
        let benign_after_saturation = fixture.read(&paths.benign)?;
        ensure!(
            benign_after_saturation.allowed,
            InvalidInputSnafu {
                path: &paths.benign,
                reason: "ring saturation changed the exact benign allow decision",
            }
        );
        let saturated = sample_observation_health(&host, &observations)?;
        let saturation_delta = health_delta(saturated, pre_saturation);
        ensure!(
            saturation_delta.lost > 0
                && saturation_delta.attempted
                    == saturation_delta.suppressed + saturation_delta.requested
                && saturation_delta.requested
                    == saturation_delta.emitted + saturation_delta.lost,
            InvalidInputSnafu {
                path: Path::new("effect_observation_health"),
                reason: "ring saturation did not preserve exact attempted, requested, emitted, and lost accounting",
            }
        );
        let coverage = observations.coverage_snapshot().ok_or_else(|| {
            InvalidInputSnafu {
                path: Path::new("evidence-coverage-v1.json"),
                reason: "the durable effect fixture has no coverage snapshot",
            }
            .build()
        })?;
        let intervals = coverage.all_intervals();
        let wal_capacity_gapped = intervals.iter().any(|interval| {
            interval
                .gap_reasons
                .contains(&CoverageGapReasonV1::WalCapacity)
        });
        let ring_loss_gapped = intervals.iter().any(|interval| {
            interval
                .gap_reasons
                .contains(&CoverageGapReasonV1::RingLoss)
        });
        let negative_claim_blocked = !coverage.supports_negative_claim();
        let evidence_errors = observations.evidence_errors();
        let evidence_batch = observations.next_evidence_batch().ok_or_else(|| {
            InvalidInputSnafu {
                path: Path::new("evidence-wal-v2"),
                reason: "the durable effect fixture produced no replay batch",
            }
            .build()
        })?;
        let durable_evidence_batch_records = evidence_batch.record_count();
        let durable_evidence_batch_is_contiguous = evidence_batch
            .first_cursor
            .checked_add(durable_evidence_batch_records as u64)
            .and_then(|cursor| cursor.checked_sub(1))
            == Some(evidence_batch.last_cursor);
        ensure!(
            wal_capacity_gapped
                && ring_loss_gapped
                && negative_claim_blocked
                && evidence_errors > 0
                && durable_evidence_batch_records > 0
                && durable_evidence_batch_is_contiguous,
            InvalidInputSnafu {
                path: Path::new("durable effect evidence"),
                reason: "saturation did not preserve a contiguous replay batch and explicit coverage gaps",
            }
        );

        fixture.stop()?;
        policy.reconcile_mount_views(&mut host).context(NodeSnafu)?;
        let old_target = BindingActivationTargetKeyV1 {
            binding_id: Id128V1::new(0x9999_9999_9999_4999, 0x8999_9999_9999_9999),
            profile_generation_ref_id: PROFILE_GENERATION_REF_ID,
        };
        let old_generation_deleted_after_last_holder = host
            .lookup_map(
                "profile_generation_descriptors",
                &PROFILE_GENERATION_REF_ID.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .is_none()
            && host
                .lookup_map("binding_activation_targets", old_target.as_bytes())
                .context(InterceptorSnafu)?
                .is_none();
        ensure!(
            old_generation_deleted_after_last_holder,
            InvalidInputSnafu {
                path: Path::new("profile_generation_descriptors"),
                reason: "generation 1 survived after its last task holder exited",
            }
        );
        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        peer_cgroup_cleanup.cleanup()?;
        propagation_cgroup_cleanup.cleanup()?;
        cgroup_cleanup.cleanup()?;
        fixture_cleanup.cleanup()?;
        ensure!(
            !pin_root.exists()
                && !lease_path.exists()
                && !cgroup_path.exists()
                && !peer_cgroup_path.exists()
                && !propagation_cgroup_path.exists()
                && !fixture_root.exists(),
            InvalidInputSnafu {
                path: output_directory,
                reason: "the effect probe left a pin root, cgroup, or mount fixture behind",
            }
        );

        Ok(EffectPhysicalProbeBundleV1 {
            schema_version: 1,
            protect_mode: protect,
            protected_deployment_digest,
            local_enforcement_fixture_results: local_enforcement_fixture_results(protect),
            hf_static_effect_classification: hf_static_effect_classification(),
            managed_proc_read_hard_closed: protect,
            exact_open_observed: true,
            exact_open_denied_before_effect: protect,
            inherited_fd_read_denied: protect,
            file_mmap_denied: protect,
            writable_shared_mmap_denied: protect,
            independent_root_shared_mmap_denied: protect,
            independent_root_benign_mmap_allowed: protect,
            independent_root_shared_mmap_distinct_identity: protect,
            executable_mmap_denied: protect,
            file_mprotect_exec_denied: protect,
            benign_mmap_allowed: protect,
            benign_read_allowed: true,
            execve_denied: protect,
            execveat_denied: protect,
            fexecve_denied: protect,
            script_exec_denied: protect,
            deleted_exec_denied: protect,
            non_leader_exec_denied: protect,
            external_exec_allow_cannot_admit: protect,
            memfd_exec_failed_closed: protect,
            anonymous_exec_hard_closed: true,
            anonymous_executable_mmap_hard_closed: true,
            anonymous_read_mmap_allowed: true,
            pkey_executable_mprotect_hard_closed: true,
            pkey_read_mprotect_allowed: true,
            file_create_hard_closed: true,
            file_setattr_hard_closed: true,
            file_truncate_hard_closed: true,
            file_unlink_hard_closed: true,
            file_link_hard_closed: true,
            file_rename_hard_closed: true,
            sysv_ipc_access_hard_closed: true,
            unix_stream_relationship_allowed: protect,
            inherited_unix_stream_send_denied: protect,
            unix_stream_stale_peer_denied: protect,
            unix_stream_unmatched_denied: protect,
            ptrace_hard_closed: true,
            process_ptrace_exact_denied: protect,
            process_signal_zero_permission_allowed: protect,
            process_signal_unmatched_denied: protect,
            namespace_privilege_hard_closed: true,
            ptmx_ioctl_exact_allowed: protect,
            ptmx_derived_peer_hard_closed: protect,
            ptmx_derived_peer_installed_nothing: protect,
            zero_device_ioctl_exact_denied: protect,
            bpf_hard_closed: true,
            managed_link_pin_unlink_denied: true,
            bounded_exception_maximum_uses: if protect { 2 } else { 0 },
            bounded_exception_n_allows: protect,
            bounded_exception_n_plus_one_denied: protect,
            bounded_exception_expiry_denied: protect,
            bounded_exception_restart_preserved: protect,
            hard_link_alias_denied: true,
            symlink_alias_denied: protect,
            proc_fd_alias_denied: protect,
            passed_fd_read_denied: protect,
            passed_benign_fd_read_allowed: protect,
            passed_fd_acquisition_denied: protect,
            passed_fd_acquisition_installed_nothing: protect,
            passed_benign_fd_acquisition_allowed: protect,
            passed_benign_fd_acquisition_read_allowed: protect,
            io_uring_secret_read_observed: true,
            io_uring_secret_read_denied_before_effect: protect,
            io_uring_benign_read_allowed: true,
            io_uring_worker_request_attributed: true,
            io_uring_sqpoll_denied_before_ring: true,
            io_uring_lifecycle_released,
            bind_alias_canonicalized: true,
            path_tree_preexisting_child_denied: protect,
            path_tree_meta_depth_denied,
            path_tree_future_namespace_denied,
            path_tree_later_child_denied: protect,
            path_tree_replacement_child_denied: protect,
            path_tree_outside_control_allowed: protect,
            path_tree_preexisting_bind_alias_denied,
            path_tree_postactivation_bind_alias_denied,
            allowed_bind_alias_allowed,
            path_tree_recursive_bind_alias_denied,
            allowed_recursive_bind_alias_allowed,
            path_tree_move_mount_alias_denied,
            allowed_move_mount_alias_allowed,
            path_tree_mount_attack_failed_closed: path_tree_postactivation_bind_alias_denied,
            protected_mount_race_denied: true,
            mount_stale_proposal_failed_closed: true,
            mount_propagation_reached_peer: true,
            mount_propagation_all_views_failed_closed: true,
            mount_propagation_reconciled: true,
            mount_setattr_global_invalidation: true,
            mount_setattr_reconciled: true,
            external_mount_replacement_failed_closed: true,
            exact_object_restored_after_reconciliation: true,
            new_roots_generation_published_atomically,
            existing_tasks_retained_old_generation,
            old_generation_deleted_after_last_holder,
            baseline_average_open_ns: baseline.average_ns(),
            observed_average_open_ns: observed.average_ns(),
            baseline_open_latency: LatencyDistributionV1::from_samples(
                baseline_samples.raw_samples_ns,
            ),
            observed_open_latency: LatencyDistributionV1::from_samples(
                observed_samples.raw_samples_ns,
            ),
            measured_opens,
            saturation_opens,
            pre_saturation_health: pre_saturation.into(),
            saturated_health: saturated.into(),
            saturation_preserved_network_denial: true,
            saturation_preserved_benign_allow: true,
            emitted_source_sequences_monotonic,
            durable_evidence_batch_records,
            durable_evidence_batch_is_contiguous,
            wal_capacity_gapped,
            ring_loss_gapped,
            negative_claim_blocked,
            evidence_errors,
            pin_root_removed: true,
            lease_removed: true,
            cgroup_removed: true,
            fixture_root_removed: true,
        })
    }

    pub fn write_json<T: Serialize>(&self, output: &Path, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value).context(JsonSnafu { path: output })?;
        fs::write(output, bytes).context(IoSnafu { path: output })
    }
}

fn source_sequences_are_monotonic(observations: &EffectObservationStore) -> bool {
    let mut last_by_cpu = BTreeMap::new();
    let events = observations.recent();
    !events.is_empty()
        && events.iter().all(|event| {
            if event.source_sequence == 0 {
                return false;
            }
            let prior = last_by_cpu.insert(event.source_cpu_id, event.source_sequence);
            prior.is_none_or(|prior| event.source_sequence > prior)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use erebor_interceptor_abi::{
        EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
        EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
        QualificationResultV1,
    };
    use mithril_node::{
        EffectObservationStore, EvidenceIdV1, EvidenceWalLimits, ObservationCanonicalizer,
    };
    use zerocopy::IntoBytes as _;

    use super::{
        hf_static_effect_classification, local_enforcement_fixture_results,
        HfStaticEffectClassificationV1,
    };

    #[test]
    fn runtime_entry_process_control_is_durable_with_exact_target(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let observations = EffectObservationStore::durable(
            4,
            directory.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )?,
        )?;
        observations.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        for (source_sequence, task_cookie, target_task_cookie, operation, argument) in [
            (1, 0, 5, KernelEffectOperationV1::Ptrace, 9),
            (2, 0, 5, KernelEffectOperationV1::Signal, 15),
            (3, 160, 0, KernelEffectOperationV1::Signal, 0),
        ] {
            observations.record_bytes(
                EffectObservationV1 {
                    observed_boottime_ns: source_sequence,
                    source_sequence,
                    task_cookie,
                    target_task_cookie,
                    effect_family: KernelEffectFamilyV1::Privilege as u16,
                    operation: operation as u16,
                    operation_argument: argument,
                    reason: EffectObservationReasonV1::RuntimeEntryInfrastructure as u8,
                    physical_result: EffectPhysicalResultV1::UnknownAfterPreEffect as u8,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        }

        assert_eq!(observations.evidence_errors(), 0);
        let batch = observations
            .next_evidence_batch()
            .ok_or("durable process-control evidence is missing")?;
        let records = batch.decode_records()?;
        assert_eq!(records.len(), 3);
        assert!(records[..2]
            .iter()
            .all(|record| { record.task_cookie == 0 && record.target_task_cookie == Some(5) }));
        assert_eq!(records[0].operation_argument, Some(9));
        assert_eq!(records[1].operation_argument, Some(15));
        assert_eq!(records[2].task_cookie, 160);
        assert_eq!(records[2].target_task_cookie, None);
        assert_eq!(records[2].operation_argument, Some(0));
        Ok(())
    }

    #[test]
    fn static_effect_classification_covers_every_branch_without_physical_claims() {
        let matrix = hf_static_effect_classification();
        let events = matrix
            .iter()
            .map(|case| case.incident_event_id)
            .collect::<BTreeSet<_>>();
        let expected = (2..=12)
            .map(|number| format!("HF-{number:03}"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            events
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
            expected
        );

        for case in &matrix {
            match case.classification {
                HfStaticEffectClassificationV1::LocalPreventionProbe
                | HfStaticEffectClassificationV1::HardCloseProbe => {
                    assert!(case.declared_denial_before_effect);
                    assert!(case.declared_legitimate_control_succeeded);
                }
                HfStaticEffectClassificationV1::NoCoveredEffect
                | HfStaticEffectClassificationV1::OutsideAuthority
                | HfStaticEffectClassificationV1::DeferredNetwork
                | HfStaticEffectClassificationV1::Unsupported => {
                    assert!(!case.declared_denial_before_effect);
                }
            }
        }
        assert!(matrix.iter().any(|case| {
            case.incident_event_id == "HF-006"
                && case.branch_id == "pure-memory-packing"
                && case.classification == HfStaticEffectClassificationV1::NoCoveredEffect
        }));
        assert!(matrix.iter().any(|case| {
            case.incident_event_id == "HF-010"
                && case.branch_id == "pure-in-process-expression"
                && case.classification == HfStaticEffectClassificationV1::NoCoveredEffect
        }));
        assert!(matrix.iter().any(|case| {
            case.incident_event_id == "HF-005"
                && case.branch_id == "managed-staged-code"
                && case.classification == HfStaticEffectClassificationV1::Unsupported
        }));
        assert!(matrix.iter().any(|case| {
            case.incident_event_id == "HF-011"
                && case.branch_id == "projected-token-open-and-read"
                && case.classification == HfStaticEffectClassificationV1::Unsupported
        }));
    }

    #[test]
    fn local_enforcement_results_close_every_owned_fixture_exactly_once() {
        let protected = local_enforcement_fixture_results(true);
        let fixture_ids = protected
            .iter()
            .map(|record| record.fixture_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(protected.len(), 29);
        assert_eq!(fixture_ids.len(), protected.len());
        assert_eq!(
            protected
                .iter()
                .filter(|record| record.result == QualificationResultV1::Pass)
                .count(),
            15
        );
        assert_eq!(
            protected
                .iter()
                .filter(|record| record.result == QualificationResultV1::Unsupported)
                .count(),
            14
        );
        assert!(protected.iter().all(|record| {
            matches!(
                record.result,
                QualificationResultV1::Pass | QualificationResultV1::Unsupported
            ) && !record.reason_code.is_empty()
        }));
        assert!(fixture_ids.contains("FILE-PATH-TREE-DENY-001"));

        let observed = local_enforcement_fixture_results(false);
        assert_eq!(observed.len(), protected.len());
        assert_eq!(
            observed
                .iter()
                .filter(|record| record.result == QualificationResultV1::Degraded)
                .count(),
            15
        );
        assert_eq!(
            observed
                .iter()
                .filter(|record| record.result == QualificationResultV1::Unsupported)
                .count(),
            14
        );
    }
}
