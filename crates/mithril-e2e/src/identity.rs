mod clone3;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use erebor_interceptor::{
    bundled_bpf_sha256, Error as InterceptorError, KernelHost, KernelHostConfig, KernelHostOwner,
    KernelObjectLayoutV1, KernelObjectManifestV1, BUNDLED_BPF_OBJECT, REQUIRED_IDENTITY_PROGRAMS,
};
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, CreatedByEdgeV1, EntryLifetimeStateV1, EntrySecurityStateV1,
    ExecGuardStateV1, ExecutionSetBindingStateV1, Id128V1, IdentityRuntimeConfigV1,
    PendingExecStateV1, PendingExecV1, ProcessExecutionInstanceV1, ProcessExecutionStateV1,
    ProcessSecurityStateKindV1, ProcessSecurityStateV1, ProcessStateVectorStateV1,
    ProcessStateVectorV1, ReferenceTombstoneStateV1, TaskCoordinateStateV1, TaskCoordinateV1,
    TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use libbpf_rs::{MapCore as _, MapHandle, MapType};
use mithril_control::{
    encode_administrative_authorization_fixture, AdministrativeExecResolution,
    AdministrativeFileObject, ResolvedAdministrativeExecutable,
};
use mithril_node::{
    AuthorizationProofOwner, AuthorizationTargetV1, IssuerTrustV1, NativeIdentityInspector,
    NativeSecurityStateOwner, NativeTaskSnapshotV1, TrustBundleV1, WorkloadBindingConfig,
    WorkloadBindingOwner,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};
use zerocopy::{FromBytes as _, IntoBytes as _, KnownLayout, TryFromBytes};

use crate::closure::QualificationRegistry;
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu};
use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(30);
const KUBERNETES_CLEANUP_WAIT_LIMIT: Duration = Duration::from_secs(120);
const PROFILE_GENERATION_REF_ID: u64 = 7;
const PRESTART_REQUEST_DIRECTORY: &str = "/run/mithril-identity-prestart";

const REQUIRED_IDENTITY_MAPS: [&str; 74] = [
    "active_profile_generations",
    "approved_exec_arguments",
    "approved_exec_slots",
    "authority_domains",
    "binding_activation_targets",
    "canonical_mount_cache",
    "canonical_mount_cache_states",
    "exact_mount_events",
    "created_by_edges",
    "declared_entry_requests",
    "device_effect_decisions",
    "effect_decisions",
    "effect_defaults",
    "effect_observation_health",
    "effect_observations",
    "entry_admission_rules",
    "entry_states",
    "execution_set_bindings",
    "external_root_classifications",
    "exact_file_measurements",
    "exact_file_objects",
    "exact_inode_generation_allocator",
    "exact_inode_lifetime_generations",
    "task_effect_attempt_states",
    "exception_handle_bindings",
    "exception_runtime_states",
    "exception_use_receipts",
    "identity_config",
    "identity_health",
    "identity_scratch",
    "image_provenance",
    "ipc_relationship_decisions",
    "ipc_socket_states",
    "io_uring_execution_states",
    "io_uring_request_states",
    "io_uring_ring_states",
    "io_uring_setup_states",
    "kernel_real_parent_intervals",
    "pending_execs",
    "pending_exec_request_paths",
    "pending_administrative_matches",
    "mount_global_ambiguous_epoch",
    "mount_global_clean_epoch",
    "mount_global_mutation_epoch",
    "mount_global_pending_mutations",
    "mount_mutation_attempts",
    "mount_mutation_epochs",
    "mount_reconciliation_proposals",
    "mount_security_view_locks",
    "mount_security_views",
    "network_destination_decisions",
    "network_ipv4_destination_classes",
    "network_ipv6_destination_classes",
    "network_response_floors",
    "network_socket_states",
    "canonical_mount_roots",
    "path_graph_exact_transitions",
    "path_graph_terminals",
    "path_graph_wildcard_transitions",
    "path_tree_denials",
    "policy_activation_probe_requests",
    "process_execution_instances",
    "process_generation_migrations",
    "process_control_rules",
    "process_state_vectors",
    "process_states",
    "profile_generation_descriptors",
    "profile_generation_async_refs",
    "profile_generation_socket_refs",
    "profile_generation_task_refs",
    "runtime_entry_bootstrap_states",
    "task_coordinates",
    "task_labels",
    "task_reference_tombstones",
];

const IDENTITY_FIXTURES: [&str; 29] = [
    "AUTHORIZATION-REPLAY-004",
    "ENTRY-BINDING-GAP-001",
    "ENTRY-CONTAINERS-001",
    "ENTRY-EPHEMERAL-001",
    "ENTRY-EXEC-001",
    "ENTRY-EXEC-002",
    "ENTRY-EXTERNAL-AMBIGUITY-001",
    "ENTRY-LOSS-001",
    "ENTRY-MIGRATE-001",
    "ENTRY-NETPROBE-001",
    "ENTRY-POSTSTART-001",
    "ENTRY-POSTSTART-002",
    "ENTRY-PRESTOP-001",
    "ENTRY-PROBE-001",
    "ENTRY-PROBE-002",
    "ENTRY-PROBE-IMPERSONATION-003",
    "ENTRY-RESTART-001",
    "ENTRY-REUSE-001",
    "ENTRY-SLEEP-001",
    "ENTRY-START-001",
    "ENTRY-STOCK-HOOK-FAILURE-002",
    "EXEC-COMMIT-STATE-001",
    "ID-CGROUP-ESCAPE-001",
    "ID-CLONE-CGROUP-002",
    "ID-CREATOR-PARENT-007",
    "ID-MOVED-PARENT-FORK-004",
    "ID-MOVED-TASK-EXEC-005",
    "ID-TASK-COORD-FINALIZE-006",
    "NATIVE-STATE-REF-LIFETIME-001",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityVerificationBundleV1 {
    pub schema_version: u32,
    pub object_path: PathBuf,
    pub object_sha256: String,
    pub layout: KernelObjectLayoutV1,
    pub identity_fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub object_sha256: String,
    pub first_start: KernelObjectManifestV1,
    pub distinct_pin_root_owner_rejected: bool,
    pub binding_gap_reconciled_root: NativeTaskSnapshotV1,
    pub binding_gap_reconciliation_closed: bool,
    pub external_ambiguity_first_root: NativeTaskSnapshotV1,
    pub external_ambiguity_second_root: NativeTaskSnapshotV1,
    pub external_ambiguity_same_restricted_role: bool,
    pub cgroup_escape_unmoved_control: NativeTaskSnapshotV1,
    pub cgroup_escape_unmoved_first_effect_allowed: bool,
    pub cgroup_escape_root: NativeTaskSnapshotV1,
    pub cgroup_escape_placement_mismatch_detected: bool,
    pub cgroup_escape_first_effect_denied: bool,
    pub moved_parent_fork_denied: bool,
    pub moved_task_exec_denied: bool,
    pub pre_ponr_failed_exec_restored: bool,
    pub pre_ponr_failed_exec_before: NativeTaskSnapshotV1,
    pub pre_ponr_failed_exec_after_failure: NativeTaskSnapshotV1,
    pub pre_ponr_failed_exec_after_success: NativeTaskSnapshotV1,
    pub post_ponr_exec_fatal: bool,
    pub post_ponr_pending_state: u8,
    pub post_ponr_exec_guard_state: u8,
    pub post_ponr_task_coordinate_state: u8,
    pub authorization_retarget_rejected: bool,
    pub authorization_expired_rejected: bool,
    pub authorization_signature_mismatch_rejected: bool,
    pub authorization_same_owner_replay_rejected: bool,
    pub authorization_restart_replay_rejected: bool,
    pub authorization_reboot_replay_rejected: bool,
    pub authorization_fresh_exact_accepted: bool,
    pub authorization_fresh_after_reboot_accepted: bool,
    pub authorization_replay_wal_sha256: String,
    pub authorization_replay_wal_records: u64,
    pub authorization_replay_state_removed: bool,
    pub non_leader_thread_exec_committed: bool,
    pub non_leader_thread_exec_root: NativeTaskSnapshotV1,
    pub non_leader_thread_exec_after_exec: NativeTaskSnapshotV1,
    pub clone_into_cgroup_external_root: NativeTaskSnapshotV1,
    pub clone_into_cgroup_native_child: NativeTaskSnapshotV1,
    pub clone_into_cgroup_native_child_after_namespace_move: NativeTaskSnapshotV1,
    pub clone_into_cgroup_first_effect_root: NativeTaskSnapshotV1,
    pub clone_into_cgroup_first_effect_child: NativeTaskSnapshotV1,
    pub clone_into_cgroup_native_child_first_effect_allowed: bool,
    pub external_root: NativeTaskSnapshotV1,
    pub native_child_before_exec: NativeTaskSnapshotV1,
    pub native_child_after_exec: NativeTaskSnapshotV1,
    pub orphaned_native_parent: NativeTaskSnapshotV1,
    pub orphaned_native_child_before_parent_exit: NativeTaskSnapshotV1,
    pub orphaned_native_child_after_parent_exit: NativeTaskSnapshotV1,
    pub subreaper_native_parent: NativeTaskSnapshotV1,
    pub subreaper_intermediate_before_exit: NativeTaskSnapshotV1,
    pub subreaper_native_child_before_parent_exit: NativeTaskSnapshotV1,
    pub subreaper_native_child_after_parent_exit: NativeTaskSnapshotV1,
    pub namespace_init_parent: NativeTaskSnapshotV1,
    pub namespace_init_pid_in_own_namespace: u32,
    pub namespace_init_intermediate_before_exit: NativeTaskSnapshotV1,
    pub namespace_init_native_child_before_parent_exit: NativeTaskSnapshotV1,
    pub namespace_init_native_child_after_parent_exit: NativeTaskSnapshotV1,
    pub double_fork_outer_parent: NativeTaskSnapshotV1,
    pub double_fork_intermediate_before_exit: NativeTaskSnapshotV1,
    pub double_fork_native_child_before_intermediate_exit: NativeTaskSnapshotV1,
    pub double_fork_native_child_after_intermediate_exit: NativeTaskSnapshotV1,
    pub no_pidfd_thread_observed: bool,
    pub leader_first_worker_task_cookie: u64,
    pub leader_first_process_refs_after_leader_exit: u64,
    pub leader_first_entry_refs_after_leader_exit: u64,
    pub leader_first_profile_refs_after_leader_exit: u64,
    pub leader_first_root_tombstone_released: bool,
    pub leader_first_worker_tombstone_owned: bool,
    pub leader_first_process_refs_after_worker_exit: u64,
    pub leader_first_entry_refs_after_worker_exit: u64,
    pub leader_first_profile_refs_after_worker_exit: u64,
    pub leader_first_process_reclaimable: bool,
    pub leader_first_entry_draining: bool,
    pub leader_first_worker_tombstone_released: bool,
    pub reused_namespace_pid: u32,
    pub pid_reuse_first: NativeTaskSnapshotV1,
    pub pid_reuse_second: NativeTaskSnapshotV1,
    pub pid_reuse_fresh_identity: bool,
    pub reused_namespace_tid: u32,
    pub tid_reuse_first_task_cookie: u64,
    pub tid_reuse_second_task_cookie: u64,
    pub tid_reuse_first_host_tid: u32,
    pub tid_reuse_second_host_tid: u32,
    pub tid_reuse_fresh_identity: bool,
    pub cgroup_reuse_path: PathBuf,
    pub cgroup_reuse_first_root: NativeTaskSnapshotV1,
    pub cgroup_reuse_second_root: NativeTaskSnapshotV1,
    pub cgroup_reuse_first_root_id: u64,
    pub cgroup_reuse_second_root_id: u64,
    pub cgroup_reuse_first_binding_nonce: String,
    pub cgroup_reuse_second_binding_nonce: String,
    pub cgroup_reuse_first_live_interval_id: String,
    pub cgroup_reuse_second_live_interval_id: String,
    pub cgroup_reuse_fresh_identity: bool,
    pub profile_task_refs_after_exit: u64,
    pub recovered_start: KernelObjectManifestV1,
    pub map_ids_stable_across_restart: bool,
    pub live_manifest_mismatch_detected: bool,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub kubernetes_initial_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_direct_cri_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_kubectl_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_kubectl_tty_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_kubectl_copy_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_native_child_parent: Option<NativeTaskSnapshotV1>,
    pub kubernetes_native_child_control: Option<NativeTaskSnapshotV1>,
    pub kubernetes_lifecycle_sleep_no_task: Option<bool>,
    pub kubernetes_http_probe_no_task: Option<bool>,
    pub kubernetes_tcp_probe_no_task: Option<bool>,
    pub kubernetes_grpc_probe_no_task: Option<bool>,
    pub kubernetes_init_container_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_sidecar_container_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_application_container_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_containers_distinct_execution_sets: Option<bool>,
    pub kubernetes_ephemeral_target_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_ephemeral_container_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_ephemeral_shared_pid_namespace: Option<bool>,
    pub kubernetes_ephemeral_distinct_execution_set_and_profile: Option<bool>,
    pub kubernetes_startup_exec_probe_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_readiness_exec_probe_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_liveness_exec_probe_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_probe_native_parent: Option<NativeTaskSnapshotV1>,
    pub kubernetes_probe_native_child: Option<NativeTaskSnapshotV1>,
    pub kubernetes_probe_kubectl_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_probe_direct_cri_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_probe_identities_distinct: Option<bool>,
    pub kubernetes_prestop_application_before: Option<NativeTaskSnapshotV1>,
    pub kubernetes_prestop_application_during: Option<NativeTaskSnapshotV1>,
    pub kubernetes_prestop_exec_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_prestop_profile_refs_during: Option<u64>,
    pub kubernetes_prestop_profile_refs_after: Option<u64>,
    pub kubernetes_poststart_entrypoint_first_application: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_entrypoint_first_hook: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_hook_first_application: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_hook_first_hook: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_both_orders_observed: Option<bool>,
    pub kubernetes_poststart_repeat_application_before: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_repeat_application_after: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_first_hook: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_repeated_hook: Option<NativeTaskSnapshotV1>,
    pub kubernetes_poststart_repeat_fresh_identity: Option<bool>,
    pub kubernetes_stock_hook_timeout_seconds: Option<u64>,
    pub kubernetes_stock_hook_timeout_result: Option<String>,
    pub kubernetes_stock_hook_timeout_no_payload: Option<bool>,
    pub kubernetes_stock_hook_mismatch_result: Option<String>,
    pub kubernetes_stock_hook_mismatch_rejected: Option<bool>,
    pub kubernetes_stock_hook_mismatch_no_payload: Option<bool>,
    pub kubernetes_stock_hook_missing_field_result: Option<String>,
    pub kubernetes_stock_hook_missing_field_rejected: Option<bool>,
    pub kubernetes_stock_hook_missing_field_no_payload: Option<bool>,
    pub kubernetes_stock_hook_failure_fixture_removed: Option<bool>,
    pub kubernetes_loss_audit_absent_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_loss_bpf_recovered_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_loss_bpf_recovered_fresh_restricted: Option<bool>,
    pub kubernetes_loss_runtime_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_loss_runtime_identity_unhealthy: Option<bool>,
    pub kubernetes_restart_discovered_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_restart_bound_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_restart_runtime_recovered_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_restart_node_gap_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_restart_node_recovered_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_restart_node_observation_unavailable: Option<bool>,
    pub kubernetes_restart_identity_stable: Option<bool>,
    pub kubernetes_reuse_first_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_reuse_second_root: Option<NativeTaskSnapshotV1>,
    pub kubernetes_reuse_first_pod_uid: Option<String>,
    pub kubernetes_reuse_second_pod_uid: Option<String>,
    pub kubernetes_reuse_first_sandbox_id: Option<String>,
    pub kubernetes_reuse_second_sandbox_id: Option<String>,
    pub kubernetes_reuse_first_container_id: Option<String>,
    pub kubernetes_reuse_second_container_id: Option<String>,
    pub kubernetes_reuse_first_cgroup_path: Option<PathBuf>,
    pub kubernetes_reuse_second_cgroup_path: Option<PathBuf>,
    pub kubernetes_reuse_first_root_cgroup_id: Option<u64>,
    pub kubernetes_reuse_second_root_cgroup_id: Option<u64>,
    pub kubernetes_reuse_first_binding_nonce: Option<String>,
    pub kubernetes_reuse_second_binding_nonce: Option<String>,
    pub kubernetes_reuse_first_live_interval_id: Option<String>,
    pub kubernetes_reuse_second_live_interval_id: Option<String>,
    pub kubernetes_reuse_same_names: Option<bool>,
    pub kubernetes_reuse_fresh_full_identity: Option<bool>,
    pub kubernetes_reuse_fresh_binding_identity: Option<bool>,
    pub kubernetes_fixture_removed: bool,
}

pub struct IdentityTestRunner {
    repo_root: PathBuf,
}

impl IdentityTestRunner {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn verify(&self, output_directory: &Path) -> Result<IdentityVerificationBundleV1> {
        let object_path = self.materialize_object(output_directory)?;
        let object_sha256 = bundled_bpf_sha256();
        let config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            output_directory.join("inspect-owner.lock"),
            None,
            "offline-inspection",
            1,
        );
        let layout = KernelHostOwner::new(config)
            .inspect()
            .context(InterceptorSnafu)?;
        let maps = layout
            .maps
            .iter()
            .map(|map| map.name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            maps == BTreeSet::from(REQUIRED_IDENTITY_MAPS),
            InvalidInputSnafu {
                path: &object_path,
                reason: format!("identity object maps are {maps:?}"),
            }
        );
        for name in [
            "mount_security_views",
            "mount_security_view_locks",
            "mount_reconciliation_proposals",
            "mount_mutation_epochs",
        ] {
            ensure!(
                layout
                    .maps
                    .iter()
                    .find(|map| map.name == name)
                    .is_some_and(|map| map.key_size == size_of::<u32>() as u32),
                InvalidInputSnafu {
                    path: &object_path,
                    reason: format!("{name} is not keyed by mount namespace identity"),
                }
            );
        }
        let programs = layout
            .programs
            .iter()
            .map(|program| program.name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            programs == BTreeSet::from(REQUIRED_IDENTITY_PROGRAMS),
            InvalidInputSnafu {
                path: &object_path,
                reason: format!("identity object programs are {programs:?}"),
            }
        );
        let registry = QualificationRegistry::new(self.repo_root.join("spec")).verify()?;
        let registered = registry.fixture_ids.into_iter().collect::<BTreeSet<_>>();
        let fixtures = IDENTITY_FIXTURES
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        ensure!(
            fixtures.is_subset(&registered),
            InvalidInputSnafu {
                path: self.repo_root.join("spec/qualification/v1/fixtures.yaml"),
                reason: "the acceptance registry omits an identity fixture",
            }
        );
        Ok(IdentityVerificationBundleV1 {
            schema_version: 1,
            object_path,
            object_sha256,
            layout,
            identity_fixture_ids: fixtures.into_iter().collect(),
        })
    }

    pub fn physical_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        cgroup_path: &Path,
    ) -> Result<IdentityPhysicalProbeBundleV1> {
        ensure!(
            !pin_root.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the dedicated identity-test pin root must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let cgroup_cleanup = ProbeCgroup::create(cgroup_path)?;
        let cgroup_path = cgroup_cleanup.path().to_path_buf();
        let procs_path = cgroup_path.join("cgroup.procs");

        self.materialize_object(output_directory)?;
        let execfail_path = output_directory.join("execfail");
        let execfail_ready_path = output_directory.join("execfail-ready");
        let post_ponr_execfail_path = output_directory.join("post-ponr-execfail");
        let non_leader_thread_ready_path = output_directory.join("non-leader-thread-ready");
        let leader_first_ready_path = output_directory.join("leader-first-ready");
        let leader_first_release_path = output_directory.join("leader-first-release");
        let cgroup_escape_sentinel_path = output_directory.join("cgroup-escape-sentinel");
        let authorization_state_directory = output_directory.join("authorization-replay");
        ensure!(
            !execfail_path.exists()
                && !execfail_ready_path.exists()
                && !post_ponr_execfail_path.exists()
                && !non_leader_thread_ready_path.exists()
                && !leader_first_ready_path.exists()
                && !leader_first_release_path.exists()
                && !cgroup_escape_sentinel_path.exists()
                && !authorization_state_directory.exists(),
            InvalidInputSnafu {
                path: output_directory,
                reason: "identity exec probe files must not already exist",
            }
        );
        let execfail_cleanup = ProbeFile::new(&execfail_path);
        let execfail_ready_cleanup = ProbeFile::new(&execfail_ready_path);
        let post_ponr_execfail_cleanup = ProbeFile::new(&post_ponr_execfail_path);
        let non_leader_thread_ready_cleanup = ProbeFile::new(&non_leader_thread_ready_path);
        let leader_first_ready_cleanup = ProbeFile::new(&leader_first_ready_path);
        let leader_first_release_cleanup = ProbeFile::new(&leader_first_release_path);
        let cgroup_escape_sentinel_cleanup = ProbeFile::new(&cgroup_escape_sentinel_path);
        let authorization_state_cleanup = ProbeDirectory::new(&authorization_state_directory);
        self.materialize_execfail(&execfail_path)?;
        Self::materialize_post_ponr_execfail(&post_ponr_execfail_path)?;
        fs::write(
            &cgroup_escape_sentinel_path,
            b"identity cgroup escape sentinel\n",
        )
        .context(IoSnafu {
            path: &cgroup_escape_sentinel_path,
        })?;
        let object_sha256 = bundled_bpf_sha256();
        let (boot_id, node_boot_id) = boot_identity()?;
        let (authorization_replay_wal_sha256, authorization_replay_wal_records) =
            run_authorization_replay_fixture(&authorization_state_directory, node_boot_id)?;
        authorization_state_cleanup.cleanup()?;
        ensure!(
            !authorization_state_directory.exists(),
            InvalidInputSnafu {
                path: &authorization_state_directory,
                reason: "authorization replay fixture survived cleanup",
            }
        );
        let config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id.clone(),
            1,
        );
        let mut host = KernelHostOwner::new(config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let first_start = host.manifest().clone();
        let alternate_pin_root = pin_root.with_extension("alternate");
        let alternate_lease_path = lease_path.with_extension("alternate.lock");
        let distinct_pin_root_owner_rejected =
            match KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                &alternate_lease_path,
                Some(alternate_pin_root.clone()),
                boot_id.clone(),
                1,
            ))
            .start()
            {
                Err(InterceptorError::LeaseOwned { .. }) => true,
                Err(source) => return Err(crate::Error::from_interceptor(source)),
                Ok(alternate) => {
                    alternate.shutdown().context(InterceptorSnafu)?;
                    ProbeDirectory::new(&alternate_pin_root).cleanup()?;
                    ProbeFile::new(&alternate_lease_path).cleanup()?;
                    false
                }
            };
        ensure!(
            distinct_pin_root_owner_rejected,
            InvalidInputSnafu {
                path: &alternate_pin_root,
                reason: "a distinct Interceptor owner acquired the host lease",
            }
        );
        let mut binding_gap_fixture = NativeProcessFixture::start()?;
        fs::write(&procs_path, binding_gap_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let binding = test_binding(&cgroup_path);
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        let identity = NativeSecurityStateOwner::new(node_boot_id, 1);
        let binding_gap_reconciliation = identity.activate(&mut host).context(NodeSnafu)?;
        let inspector = NativeIdentityInspector::new(pin_root);
        let binding_gap_reconciled_root =
            self.wait_for("binding-gap reconciled root identity", &procs_path, || {
                inspector
                    .snapshot(binding_gap_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        ensure!(
            binding_gap_reconciled_root.creator_task_cookie.is_none()
                && binding_gap_reconciled_root.root_class.as_deref()
                    == Some("restored_or_unknown_root")
                && binding_gap_reconciled_root.installed_role_class.as_deref()
                    == Some("fail_closed_unknown")
                && binding_gap_reconciled_root.active_role_id == binding.external_role_id
                && binding_gap_reconciled_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8
                && binding_gap_reconciliation.allocation_failures == 0
                && binding_gap_reconciliation.coordinate_failures == 0
                && binding_gap_reconciliation.reconciliation_required == 0,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "a task present before binding did not reconcile to the fail-closed root",
            }
        );
        let binding_gap_root_id = fs::metadata(&cgroup_path)
            .context(IoSnafu { path: &cgroup_path })?
            .ino();
        let mut terminating_binding = required_abi_map::<ExecutionSetBindingStateV1>(
            &host,
            "execution_set_bindings",
            &binding_gap_root_id.to_ne_bytes(),
            "binding-gap execution-set binding",
        )?;
        terminating_binding.lifecycle_state = BindingLifecycleStateV1::Terminating;
        terminating_binding.transition_version += 1;
        host.update_map(
            "execution_set_bindings",
            &binding_gap_root_id.to_ne_bytes(),
            terminating_binding.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        identity
            .recover_tasks(&mut host, false)
            .context(NodeSnafu)?;

        // A terminal binding removes effect authority before its task exits.
        // Reconciliation must retain that coherent graph without reopening it.
        terminating_binding.lifecycle_state = BindingLifecycleStateV1::Active;
        terminating_binding.transition_version += 1;
        host.update_map(
            "execution_set_bindings",
            &binding_gap_root_id.to_ne_bytes(),
            terminating_binding.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        identity
            .recover_tasks(&mut host, false)
            .context(NodeSnafu)?;
        binding_gap_fixture.stop();

        let mut external_ambiguity_first = NativeProcessFixture::start()?;
        let mut external_ambiguity_second = NativeProcessFixture::start()?;
        fs::write(
            &procs_path,
            external_ambiguity_first.outer_pid().to_string(),
        )
        .context(IoSnafu { path: &procs_path })?;
        fs::write(
            &procs_path,
            external_ambiguity_second.outer_pid().to_string(),
        )
        .context(IoSnafu { path: &procs_path })?;
        let external_ambiguity_first_root = self.wait_for(
            "first concurrent external-root identity",
            &procs_path,
            || {
                inspector
                    .snapshot(external_ambiguity_first.outer_pid())
                    .context(NodeSnafu)
            },
        )?;
        let external_ambiguity_second_root = self.wait_for(
            "second concurrent external-root identity",
            &procs_path,
            || {
                inspector
                    .snapshot(external_ambiguity_second.outer_pid())
                    .context(NodeSnafu)
            },
        )?;
        let external_ambiguity_same_restricted_role = external_ambiguity_first_root.active_role_id
            == external_ambiguity_second_root.active_role_id;
        ensure!(
            external_ambiguity_first_root.creator_task_cookie.is_none()
                && external_ambiguity_second_root.creator_task_cookie.is_none()
                && external_ambiguity_first_root.task_cookie
                    != external_ambiguity_second_root.task_cookie
                && external_ambiguity_first_root.process_state_id
                    != external_ambiguity_second_root.process_state_id
                && external_ambiguity_first_root.root_class.as_deref() == Some("external_runtime_root")
                && external_ambiguity_second_root.root_class.as_deref() == Some("external_runtime_root")
                && external_ambiguity_first_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && external_ambiguity_second_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && external_ambiguity_same_restricted_role
                && external_ambiguity_first_root.active_role_id == binding.external_role_id
                && external_ambiguity_first_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8
                && external_ambiguity_second_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: format!(
                    "concurrent indistinguishable external roots did not remain separate restricted roots: first {external_ambiguity_first_root:?}; second {external_ambiguity_second_root:?}"
                ),
            }
        );
        external_ambiguity_first.stop();
        external_ambiguity_second.stop();

        let mut escape_fixture = CloneIntoCgroupFixture::start(&cgroup_path)?;
        let escape_root_before_move = self.wait_for(
            "cgroup escape root identity before movement",
            &procs_path,
            || {
                inspector
                    .snapshot(escape_fixture.root_pid())
                    .context(NodeSnafu)
            },
        )?;
        let health_before_escape = identity.health(&host).context(NodeSnafu)?;
        let parent_cgroup = cgroup_path
            .parent()
            .ok_or_else(|| invalid_state("identity-test cgroup has no parent"))?;
        let parent_procs_path = parent_cgroup.join("cgroup.procs");
        fs::write(&parent_procs_path, escape_fixture.root_pid().to_string()).context(IoSnafu {
            path: &parent_procs_path,
        })?;
        let cgroup_escape_root = self.wait_for(
            "cgroup escape fail-closed identity",
            &parent_procs_path,
            || {
                let snapshot = inspector
                    .snapshot(escape_fixture.root_pid())
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.coordinate_state == TaskCoordinateStateV1::FailClosedUnknown as u8
                }))
            },
        )?;
        let health_after_escape = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            escape_root_before_move.creator_task_cookie.is_none()
                && cgroup_escape_root.creator_task_cookie.is_none()
                && cgroup_escape_root.root_class.as_deref() == Some("external_runtime_root")
                && cgroup_escape_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && health_after_escape.placement_mismatches
                    > health_before_escape.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "moving a labeled root out of its cgroup did not fail closed",
            }
        );
        escape_fixture.release_root()?;
        self.wait_for(
            "moved-parent ordinary fork denial",
            &parent_procs_path,
            || escape_fixture.moved_parent_fork_denied(),
        )?;
        let health_after_moved_parent_fork = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            health_after_moved_parent_fork.placement_mismatches
                > health_after_escape.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "a moved labeled parent did not record its denied ordinary fork",
            }
        );
        escape_fixture.stop();

        let mut clone_fixture =
            CloneIntoCgroupFixture::start_with_mount_namespace_target(&cgroup_path)?;
        let clone_external_root = self.wait_for(
            "pre-wake CLONE_INTO_CGROUP external root identity",
            &procs_path,
            || {
                inspector
                    .snapshot(clone_fixture.root_pid())
                    .context(NodeSnafu)
            },
        )?;
        clone_fixture.release_root()?;
        let clone_child_pid =
            self.wait_for("CLONE_INTO_CGROUP native child", &procs_path, || {
                clone_fixture.child_pid()
            })?;
        let clone_native_child = self.wait_for(
            "CLONE_INTO_CGROUP native child identity",
            &procs_path,
            || inspector.snapshot(clone_child_pid).context(NodeSnafu),
        )?;
        ensure!(
            clone_external_root.creator_task_cookie.is_none()
                && clone_external_root.root_class.as_deref() == Some("external_runtime_root")
                && clone_external_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && clone_native_child.creator_task_cookie == Some(clone_external_root.task_cookie)
                && clone_native_child.real_parent_task_cookie == clone_external_root.task_cookie
                && clone_native_child.root_class.is_none()
                && clone_native_child.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "CLONE_INTO_CGROUP root or its native child has the wrong identity",
            }
        );
        let clone_child_mount_namespace = fs::read_link(format!("/proc/{clone_child_pid}/ns/mnt"))
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{clone_child_pid}/ns/mnt")),
            })?;
        let clone_target_mount_namespace = clone_fixture.target_mount_namespace()?;
        ensure!(
            clone_child_mount_namespace != clone_target_mount_namespace,
            InvalidInputSnafu {
                path: PathBuf::from(format!("/proc/{clone_child_pid}/ns/mnt")),
                reason: "native child already has the target mount namespace",
            }
        );
        clone_fixture.release_child_into_mount_namespace()?;
        let clone_native_child_after_namespace_move = self.wait_for(
            "CLONE_INTO_CGROUP native child mount-namespace entry",
            &procs_path,
            || {
                let snapshot = inspector.snapshot(clone_child_pid).context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie == clone_native_child.task_cookie
                        && snapshot.creator_task_cookie == clone_native_child.creator_task_cookie
                        && snapshot.real_parent_task_cookie
                            == clone_native_child.real_parent_task_cookie
                        && snapshot.process_state_id == clone_native_child.process_state_id
                        && snapshot.active_execution_id != clone_native_child.active_execution_id
                        && snapshot.image_provenance_id != clone_native_child.image_provenance_id
                        && snapshot.active_role_id == clone_native_child.active_role_id
                        && snapshot.root_class.is_none()
                        && snapshot.installed_role_class.is_none()
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            },
        )?;
        let clone_child_mount_namespace_after =
            fs::read_link(format!("/proc/{clone_child_pid}/ns/mnt")).context(IoSnafu {
                path: PathBuf::from(format!("/proc/{clone_child_pid}/ns/mnt")),
            })?;
        ensure!(
            clone_child_mount_namespace_after == clone_target_mount_namespace,
            InvalidInputSnafu {
                path: PathBuf::from(format!("/proc/{clone_child_pid}/ns/mnt")),
                reason: "native child did not enter the target mount namespace",
            }
        );
        clone_fixture.stop();

        let mut fixture = NativeProcessFixture::start()?;
        fs::write(&procs_path, fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let external_root = self.wait_for("external root identity", &procs_path, || {
            inspector.snapshot(fixture.outer_pid()).context(NodeSnafu)
        })?;

        let next_id_before_child = identity_next_id(&host)?;
        fixture.release_root()?;
        let native_pid = match self.wait_for("native child creation", &procs_path, || {
            fixture.native_child_pid()
        }) {
            Ok(pid) => pid,
            Err(source) => {
                let health = identity.health(&host).context(NodeSnafu)?;
                let next_id_after_child = identity_next_id(&host)?;
                return Err(invalid_state(format!(
                    "{source}; identity health {health:?}; child allocation advanced next_id by {}",
                    next_id_after_child.saturating_sub(next_id_before_child)
                )));
            }
        };
        fixture.open_native_pidfd(native_pid)?;
        let before_exec = self.wait_for("native child identity", &procs_path, || {
            inspector.snapshot(native_pid).context(NodeSnafu)
        })?;
        ensure!(
            external_root.creator_task_cookie.is_none()
                && external_root.root_class.as_deref() == Some("external_runtime_root")
                && external_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && external_root.active_role_id == binding.external_role_id
                && external_root.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                && before_exec.creator_task_cookie == Some(external_root.task_cookie)
                && before_exec.real_parent_task_cookie == external_root.task_cookie
                && before_exec.task_cookie != external_root.task_cookie
                && before_exec.active_role_id == external_root.active_role_id
                && before_exec.image_provenance_id == external_root.image_provenance_id
                && before_exec.image_candidate_count > 0
                && before_exec.process_execution_state == ProcessExecutionStateV1::Active as u8
                && before_exec.process_state_vector_state
                    == ProcessStateVectorStateV1::Active as u8
                && before_exec.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "external root or native child identity is incorrect",
            }
        );

        fixture.release_exec(native_pid)?;
        let after_exec = self.wait_for("native exec commit", &procs_path, || {
            let snapshot = inspector.snapshot(native_pid).context(NodeSnafu)?;
            Ok(snapshot.filter(|snapshot| {
                snapshot.active_execution_id != before_exec.active_execution_id
                    && snapshot.image_provenance_id != before_exec.image_provenance_id
                    && snapshot.image_candidate_count > 0
                    && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
            }))
        });
        let after_exec = match after_exec {
            Ok(snapshot) => snapshot,
            Err(source) => {
                let snapshot = inspector.snapshot(native_pid).context(NodeSnafu)?;
                let health = identity.health(&host).context(NodeSnafu)?;
                let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
                let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
                let comm = fs::read_to_string(&comm_path)
                    .unwrap_or_else(|error| format!("<unavailable: {error}>"));
                let status = fs::read_to_string(&status_path)
                    .unwrap_or_else(|error| format!("<unavailable: {error}>"));
                return Err(invalid_state(format!(
                    "{source}; live snapshot {snapshot:?}; identity health {health:?}; comm {}; status {}",
                    comm.trim(),
                    status.lines().next().unwrap_or("<empty>")
                )));
            }
        };
        fixture.stop();

        let mut non_leader_thread_fixture =
            NativeProcessFixture::start_with_non_leader_exec(&non_leader_thread_ready_path)?;
        let non_leader_thread_root_pid = non_leader_thread_fixture.outer_pid();
        fs::write(&procs_path, non_leader_thread_root_pid.to_string())
            .context(IoSnafu { path: &procs_path })?;
        let non_leader_thread_exec_root =
            self.wait_for("non-leader thread exec root identity", &procs_path, || {
                inspector
                    .snapshot(non_leader_thread_root_pid)
                    .context(NodeSnafu)
            })?;
        ensure!(
            non_leader_thread_exec_root.creator_task_cookie.is_none()
                && non_leader_thread_exec_root.root_class.as_deref()
                    == Some("external_runtime_root")
                && non_leader_thread_exec_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && non_leader_thread_exec_root.active_role_id == binding.external_role_id
                && non_leader_thread_exec_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "non-leader thread exec root has the wrong identity",
            }
        );
        let next_id_before_non_leader_thread = identity_next_id(&host)?;
        let expected_next_id_after_non_leader_thread = next_id_before_non_leader_thread
            .checked_add(2)
            .ok_or_else(|| {
                invalid_state("identity ID sequence overflowed for non-leader thread")
            })?;
        non_leader_thread_fixture.release_root()?;
        let non_leader_thread_tid = self.wait_for(
            "non-leader Python thread creation",
            &non_leader_thread_ready_path,
            || non_leader_thread_fixture.non_leader_thread_tid(&non_leader_thread_ready_path),
        )?;
        let non_leader_thread_path = PathBuf::from(format!(
            "/proc/{non_leader_thread_root_pid}/task/{non_leader_thread_tid}"
        ));
        let next_id_after_non_leader_thread = identity_next_id(&host)?;
        ensure!(
            non_leader_thread_tid != non_leader_thread_root_pid
                && non_leader_thread_path.is_dir()
                && next_id_after_non_leader_thread == expected_next_id_after_non_leader_thread,
            InvalidInputSnafu {
                path: &non_leader_thread_path,
                reason: format!(
                    "non-leader Python thread did not receive one exact task identity; expected next ID {expected_next_id_after_non_leader_thread}, got {next_id_after_non_leader_thread}"
                ),
            }
        );
        non_leader_thread_fixture.release_non_leader_exec()?;
        let non_leader_thread_exec_after_exec =
            self.wait_for("non-leader thread exec commit", &procs_path, || {
                let snapshot = inspector
                    .snapshot(non_leader_thread_root_pid)
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie == next_id_before_non_leader_thread
                        && snapshot.creator_task_cookie
                            == Some(non_leader_thread_exec_root.task_cookie)
                        && snapshot.process_state_id == non_leader_thread_exec_root.process_state_id
                        && snapshot.active_execution_id
                            != non_leader_thread_exec_root.active_execution_id
                        && snapshot.image_provenance_id
                            != non_leader_thread_exec_root.image_provenance_id
                        && snapshot.active_role_id == non_leader_thread_exec_root.active_role_id
                        && snapshot.root_class.is_none()
                        && snapshot.installed_role_class.is_none()
                        && snapshot.host_tid == non_leader_thread_root_pid
                        && snapshot.host_tgid == non_leader_thread_root_pid
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            })?;
        non_leader_thread_fixture.stop();
        non_leader_thread_ready_cleanup.cleanup()?;

        let mut failed_exec_fixture =
            NativeProcessFixture::start_with_failed_exec(&execfail_path, &execfail_ready_path)?;
        fs::write(&procs_path, failed_exec_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let failed_exec_parent =
            self.wait_for("pre-PONR failed-exec parent identity", &procs_path, || {
                inspector
                    .snapshot(failed_exec_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        failed_exec_fixture.release_root()?;
        let failed_exec_pid =
            self.wait_for("pre-PONR failed-exec child creation", &procs_path, || {
                failed_exec_fixture.native_child_pid()
            })?;
        failed_exec_fixture.open_native_pidfd(failed_exec_pid)?;
        failed_exec_fixture.wait_for_stopped_native_child(failed_exec_pid)?;
        let failed_exec_before =
            self.wait_for("pre-PONR failed-exec child identity", &procs_path, || {
                inspector.snapshot(failed_exec_pid).context(NodeSnafu)
            })?;
        let failed_exec_pending = host
            .lookup_map(
                "pending_execs",
                &failed_exec_before.task_cookie.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?;
        ensure!(
            failed_exec_parent.root_class.as_deref() == Some("external_runtime_root")
                && failed_exec_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && failed_exec_pending.is_none()
                && failed_exec_before.creator_task_cookie == Some(failed_exec_parent.task_cookie)
                && failed_exec_before.real_parent_task_cookie == failed_exec_parent.task_cookie
                && failed_exec_before.root_class.is_none()
                && failed_exec_before.installed_role_class.is_none()
                && failed_exec_before.process_execution_state
                    == ProcessExecutionStateV1::Active as u8
                && failed_exec_before.process_state_vector_state
                    == ProcessStateVectorStateV1::Active as u8
                && failed_exec_before.exec_guard_state == ExecGuardStateV1::None as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: format!(
                    "pre-PONR failed-exec child has the wrong initial identity; parent snapshot {failed_exec_parent:?}; child snapshot {failed_exec_before:?}; pending exec present {}",
                    failed_exec_pending.is_some()
                ),
            }
        );
        failed_exec_fixture.release_exec(failed_exec_pid)?;
        let failed_exec_after_failure = self.wait_for(
            "pre-PONR failed-exec restoration",
            &execfail_ready_path,
            || {
                if !execfail_ready_path.exists() {
                    return Ok(None);
                }
                let Some(snapshot) = inspector.snapshot(failed_exec_pid).context(NodeSnafu)? else {
                    return Ok(None);
                };
                let pending = host
                    .lookup_map("pending_execs", &snapshot.task_cookie.to_ne_bytes())
                    .context(InterceptorSnafu)?;
                Ok((pending.is_none()
                    && snapshot.task_cookie == failed_exec_before.task_cookie
                    && snapshot.creator_task_cookie == failed_exec_before.creator_task_cookie
                    && snapshot.real_parent_task_cookie
                        == failed_exec_before.real_parent_task_cookie
                    && snapshot.active_execution_id == failed_exec_before.active_execution_id
                    && snapshot.image_provenance_id == failed_exec_before.image_provenance_id
                    && snapshot.active_role_id == failed_exec_before.active_role_id
                    && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && snapshot.process_state_vector_state
                        == ProcessStateVectorStateV1::Active as u8
                    && snapshot.exec_guard_state == ExecGuardStateV1::None as u8)
                    .then_some(snapshot))
            },
        )?;
        failed_exec_fixture.release_exec(failed_exec_pid)?;
        let failed_exec_after_success = self.wait_for(
            "pre-PONR failed-exec later normal commit",
            &procs_path,
            || {
                let Some(snapshot) = inspector.snapshot(failed_exec_pid).context(NodeSnafu)? else {
                    return Ok(None);
                };
                let pending = host
                    .lookup_map("pending_execs", &snapshot.task_cookie.to_ne_bytes())
                    .context(InterceptorSnafu)?;
                Ok((pending.is_none()
                    && snapshot.task_cookie == failed_exec_after_failure.task_cookie
                    && snapshot.creator_task_cookie
                        == failed_exec_after_failure.creator_task_cookie
                    && snapshot.real_parent_task_cookie
                        == failed_exec_after_failure.real_parent_task_cookie
                    && snapshot.active_execution_id
                        != failed_exec_after_failure.active_execution_id
                    && snapshot.image_provenance_id
                        != failed_exec_after_failure.image_provenance_id
                    && snapshot.active_role_id == failed_exec_after_failure.active_role_id
                    && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && snapshot.process_state_vector_state
                        == ProcessStateVectorStateV1::Active as u8
                    && snapshot.exec_guard_state == ExecGuardStateV1::None as u8)
                    .then_some(snapshot))
            },
        )?;
        ensure!(
            failed_exec_after_success.root_class.is_none()
                && failed_exec_after_success.installed_role_class.is_none()
                && failed_exec_after_success.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "normal exec after the pre-PONR failure did not restore a runnable task",
            }
        );
        failed_exec_fixture.stop();
        execfail_ready_cleanup.cleanup()?;
        execfail_cleanup.cleanup()?;

        let mut post_ponr_fixture =
            NativeProcessFixture::start_with_post_ponr_exec(&post_ponr_execfail_path)?;
        fs::write(&procs_path, post_ponr_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let post_ponr_parent = self.wait_for("post-PONR parent identity", &procs_path, || {
            inspector
                .snapshot(post_ponr_fixture.outer_pid())
                .context(NodeSnafu)
        })?;
        post_ponr_fixture.release_root()?;
        let post_ponr_pid = self.wait_for("post-PONR native child", &procs_path, || {
            post_ponr_fixture.native_child_pid()
        })?;
        post_ponr_fixture.open_native_pidfd(post_ponr_pid)?;
        post_ponr_fixture.wait_for_stopped_native_child(post_ponr_pid)?;
        let post_ponr_before = self.wait_for("post-PONR child identity", &procs_path, || {
            inspector.snapshot(post_ponr_pid).context(NodeSnafu)
        })?;
        ensure!(
            post_ponr_parent.root_class.as_deref() == Some("external_runtime_root")
                && post_ponr_before.creator_task_cookie == Some(post_ponr_parent.task_cookie)
                && post_ponr_before.active_role_id == post_ponr_parent.active_role_id
                && post_ponr_before.exec_guard_state == ExecGuardStateV1::None as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "the post-PONR child did not start with the inherited restricted identity",
            }
        );
        let post_ponr_task_key = post_ponr_before.task_cookie.to_ne_bytes();
        let post_ponr_process_key = id_key(&post_ponr_before.process_state_id)?;
        post_ponr_fixture.release_exec(post_ponr_pid)?;
        post_ponr_fixture.wait_for_post_ponr_fatal(post_ponr_pid)?;
        let (
            post_ponr_pending,
            post_ponr_process,
            post_ponr_coordinate,
            post_ponr_tombstone,
            post_ponr_source_execution,
            post_ponr_target_execution,
        ) = self.wait_for("post-PONR fatal identity", &procs_path, || {
            let Some(pending) = optional_abi_map::<PendingExecV1>(
                &host,
                "pending_execs",
                &post_ponr_task_key,
                "post-PONR pending exec",
            )?
            else {
                return Ok(None);
            };
            let process = required_abi_map::<ProcessSecurityStateV1>(
                &host,
                "process_states",
                &post_ponr_process_key,
                "post-PONR process state",
            )?;
            let coordinate = required_abi_map::<TaskCoordinateV1>(
                &host,
                "task_coordinates",
                &post_ponr_before.task_cookie.to_ne_bytes(),
                "post-PONR task coordinate",
            )?;
            let tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                &host,
                "task_reference_tombstones",
                &post_ponr_before.task_cookie.to_ne_bytes(),
                "post-PONR task tombstone",
            )?;
            let source_execution = required_abi_map::<ProcessExecutionInstanceV1>(
                &host,
                "process_execution_instances",
                &id_bytes(pending.source_execution_id),
                "post-PONR source execution",
            )?;
            let target_execution = required_abi_map::<ProcessExecutionInstanceV1>(
                &host,
                "process_execution_instances",
                &id_bytes(pending.target_execution_id),
                "post-PONR target execution",
            )?;
            Ok((pending.state == PendingExecStateV1::PostPonrFatal
                && process.exec_guard_state == ExecGuardStateV1::OutcomeUnknown
                && process.state == ProcessSecurityStateKindV1::Reclaimable
                && process.live_thread_refs == 0
                && coordinate.state == TaskCoordinateStateV1::Exited
                && tombstone.task_free_observed == 1
                && tombstone.released_bits == TASK_REFERENCE_ALL_V1
                && tombstone.state == ReferenceTombstoneStateV1::Released
                && source_execution.state == ProcessExecutionStateV1::Complete
                && target_execution.state == ProcessExecutionStateV1::OutcomeUnknown)
                .then_some((
                    pending,
                    process,
                    coordinate,
                    tombstone,
                    source_execution,
                    target_execution,
                )))
        })?;
        ensure!(
            post_ponr_process.active_role_id == post_ponr_before.active_role_id
                && post_ponr_process.active_execution_id == post_ponr_pending.source_execution_id
                && post_ponr_pending.source_role_id == post_ponr_before.active_role_id
                && post_ponr_coordinate.task_cookie == post_ponr_before.task_cookie
                && post_ponr_tombstone.task_cookie == post_ponr_before.task_cookie
                && post_ponr_source_execution.process_execution_instance_id
                    == post_ponr_pending.source_execution_id
                && post_ponr_target_execution.process_execution_instance_id
                    == post_ponr_pending.target_execution_id,
            InvalidInputSnafu {
                path: &post_ponr_execfail_path,
                reason: "post-PONR failure restored or replaced the source restriction",
            }
        );
        post_ponr_fixture.stop();
        post_ponr_execfail_cleanup.cleanup()?;

        let mut moved_task_fixture = NativeProcessFixture::start()?;
        fs::write(&procs_path, moved_task_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let moved_task_parent =
            self.wait_for("moved-task exec parent identity", &procs_path, || {
                inspector
                    .snapshot(moved_task_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        moved_task_fixture.release_root()?;
        let moved_task_pid =
            self.wait_for("moved-task exec child creation", &procs_path, || {
                moved_task_fixture.native_child_pid()
            })?;
        moved_task_fixture.open_native_pidfd(moved_task_pid)?;
        let moved_task_before_move =
            self.wait_for("moved-task exec child identity", &procs_path, || {
                inspector.snapshot(moved_task_pid).context(NodeSnafu)
            })?;
        ensure!(
            moved_task_parent.root_class.as_deref() == Some("external_runtime_root")
                && moved_task_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && moved_task_before_move.creator_task_cookie
                    == Some(moved_task_parent.task_cookie)
                && moved_task_before_move.real_parent_task_cookie == moved_task_parent.task_cookie
                && moved_task_before_move.task_cookie != moved_task_parent.task_cookie
                && moved_task_before_move.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "moved-task exec child has the wrong pre-move identity",
            }
        );
        let health_before_moved_task = identity.health(&host).context(NodeSnafu)?;
        fs::write(&parent_procs_path, moved_task_pid.to_string()).context(IoSnafu {
            path: &parent_procs_path,
        })?;
        let moved_task_after_move = self.wait_for(
            "moved-task exec fail-closed identity",
            &parent_procs_path,
            || {
                let snapshot = inspector.snapshot(moved_task_pid).context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie == moved_task_before_move.task_cookie
                        && snapshot.creator_task_cookie
                            == moved_task_before_move.creator_task_cookie
                        && snapshot.real_parent_task_cookie
                            == moved_task_before_move.real_parent_task_cookie
                        && snapshot.coordinate_state
                            == TaskCoordinateStateV1::FailClosedUnknown as u8
                }))
            },
        )?;
        let health_after_moved_task_move = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            moved_task_after_move.root_class.is_none()
                && moved_task_after_move.installed_role_class.is_none()
                && health_after_moved_task_move.placement_mismatches
                    > health_before_moved_task.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "moving a labeled native child did not fail closed",
            }
        );
        moved_task_fixture.release_exec(moved_task_pid)?;
        moved_task_fixture.wait_for_native_exec_failure()?;
        let health_after_moved_task_exec = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            health_after_moved_task_exec.placement_mismatches
                > health_after_moved_task_move.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "a moved labeled native child did not record its denied exec",
            }
        );
        moved_task_fixture.stop();

        let mut orphan_fixture = NativeProcessFixture::start_orphaning()?;
        fs::write(&procs_path, orphan_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let orphaned_native_parent =
            self.wait_for("orphaned native parent identity", &procs_path, || {
                inspector
                    .snapshot(orphan_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        orphan_fixture.release_root()?;
        let orphaned_native_child_pid =
            self.wait_for("orphaned native child creation", &procs_path, || {
                orphan_fixture.native_child_pid()
            })?;
        orphan_fixture.open_native_pidfd(orphaned_native_child_pid)?;
        let orphaned_native_child_before_parent_exit =
            self.wait_for("orphaned native child identity", &procs_path, || {
                inspector
                    .snapshot(orphaned_native_child_pid)
                    .context(NodeSnafu)
            })?;
        ensure!(
            orphaned_native_parent.root_class.as_deref() == Some("external_runtime_root")
                && orphaned_native_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && orphaned_native_child_before_parent_exit.creator_task_cookie
                    == Some(orphaned_native_parent.task_cookie)
                && orphaned_native_child_before_parent_exit.real_parent_task_cookie
                    == orphaned_native_parent.task_cookie
                && orphaned_native_child_before_parent_exit
                    .root_class
                    .is_none()
                && orphaned_native_child_before_parent_exit
                    .installed_role_class
                    .is_none()
                && orphaned_native_child_before_parent_exit.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "orphaned native child has the wrong pre-exit identity",
            }
        );
        orphan_fixture.release_parent_exit()?;
        orphan_fixture.wait_for_parent_exit()?;
        orphan_fixture.release_exec(orphaned_native_child_pid)?;
        let orphaned_native_child_after_parent_exit = self.wait_for(
            "orphaned native child exec after parent exit",
            &procs_path,
            || {
                let snapshot = inspector
                    .snapshot(orphaned_native_child_pid)
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie == orphaned_native_child_before_parent_exit.task_cookie
                        && snapshot.creator_task_cookie == Some(orphaned_native_parent.task_cookie)
                        && snapshot.real_parent_task_cookie != orphaned_native_parent.task_cookie
                        && snapshot.real_parent_interval_sequence
                            > orphaned_native_child_before_parent_exit.real_parent_interval_sequence
                        && snapshot.active_execution_id
                            != orphaned_native_child_before_parent_exit.active_execution_id
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            },
        )?;
        ensure!(
            orphaned_native_child_after_parent_exit.root_class.is_none()
                && orphaned_native_child_after_parent_exit
                    .installed_role_class
                    .is_none()
                && orphaned_native_child_after_parent_exit.active_role_id
                    == orphaned_native_parent.active_role_id,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "orphaned native child lost its inherited restriction",
            }
        );
        orphan_fixture.stop();

        let mut subreaper_fixture = NativeProcessFixture::start_subreaper()?;
        fs::write(&procs_path, subreaper_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let subreaper_native_parent =
            self.wait_for("subreaper native parent identity", &procs_path, || {
                inspector
                    .snapshot(subreaper_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        subreaper_fixture.release_root()?;
        let subreaper_intermediate_pid =
            self.wait_for("subreaper intermediate creation", &procs_path, || {
                subreaper_fixture.intermediate_pid()
            })?;
        subreaper_fixture.open_intermediate_pidfd(subreaper_intermediate_pid)?;
        let subreaper_native_child_pid =
            self.wait_for("subreaper native child creation", &procs_path, || {
                subreaper_fixture.intermediate_native_child_pid(subreaper_intermediate_pid)
            })?;
        subreaper_fixture.open_native_pidfd(subreaper_native_child_pid)?;
        let subreaper_intermediate_before_exit =
            self.wait_for("subreaper intermediate identity", &procs_path, || {
                inspector
                    .snapshot(subreaper_intermediate_pid)
                    .context(NodeSnafu)
            })?;
        let subreaper_native_child_before_parent_exit =
            self.wait_for("subreaper native child identity", &procs_path, || {
                inspector
                    .snapshot(subreaper_native_child_pid)
                    .context(NodeSnafu)
            })?;
        ensure!(
            subreaper_native_parent.root_class.as_deref() == Some("external_runtime_root")
                && subreaper_native_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && subreaper_intermediate_before_exit.creator_task_cookie
                    == Some(subreaper_native_parent.task_cookie)
                && subreaper_intermediate_before_exit.real_parent_task_cookie
                    == subreaper_native_parent.task_cookie
                && subreaper_intermediate_before_exit.real_parent_host_tid
                    == subreaper_native_parent.host_tid
                && subreaper_intermediate_before_exit.real_parent_host_tgid
                    == subreaper_native_parent.host_tgid
                && subreaper_intermediate_before_exit.root_class.is_none()
                && subreaper_intermediate_before_exit
                    .installed_role_class
                    .is_none()
                && subreaper_native_child_before_parent_exit.creator_task_cookie
                    == Some(subreaper_intermediate_before_exit.task_cookie)
                && subreaper_native_child_before_parent_exit.real_parent_task_cookie
                    == subreaper_intermediate_before_exit.task_cookie
                && subreaper_native_child_before_parent_exit.real_parent_host_tid
                    == subreaper_intermediate_before_exit.host_tid
                && subreaper_native_child_before_parent_exit.real_parent_host_tgid
                    == subreaper_intermediate_before_exit.host_tgid
                && subreaper_native_child_before_parent_exit
                    .root_class
                    .is_none()
                && subreaper_native_child_before_parent_exit
                    .installed_role_class
                    .is_none()
                && subreaper_native_child_before_parent_exit.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "subreaper native child has the wrong pre-exit identity",
            }
        );
        subreaper_fixture.release_intermediate_exit()?;
        self.wait_for("subreaper intermediate exit", &procs_path, || {
            Ok(subreaper_fixture
                .intermediate_exited(subreaper_intermediate_pid)?
                .then_some(()))
        })?;
        subreaper_fixture.release_exec(subreaper_native_child_pid)?;
        let subreaper_native_child_after_parent_exit = self.wait_for(
            "subreaper native child exec after parent exit",
            &procs_path,
            || {
                let snapshot = inspector
                    .snapshot(subreaper_native_child_pid)
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie == subreaper_native_child_before_parent_exit.task_cookie
                        && snapshot.creator_task_cookie
                            == Some(subreaper_intermediate_before_exit.task_cookie)
                        && snapshot.real_parent_task_cookie == 0
                        && snapshot.real_parent_host_tid == subreaper_native_parent.host_tid
                        && snapshot.real_parent_host_tgid == subreaper_native_parent.host_tgid
                        && snapshot.real_parent_interval_sequence
                            > subreaper_native_child_before_parent_exit
                                .real_parent_interval_sequence
                        && snapshot.active_execution_id
                            != subreaper_native_child_before_parent_exit.active_execution_id
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            },
        )?;
        ensure!(
            subreaper_native_child_after_parent_exit
                .root_class
                .is_none()
                && subreaper_native_child_after_parent_exit
                    .installed_role_class
                    .is_none()
                && subreaper_native_child_after_parent_exit.active_role_id
                    == subreaper_native_parent.active_role_id,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "subreaper native child lost its inherited restriction",
            }
        );
        subreaper_fixture.stop();

        let mut namespace_init_fixture = NativeProcessFixture::start_namespace_init_reparenting()?;
        let namespace_init_parent_pid =
            self.wait_for("PID-namespace init creation", &procs_path, || {
                namespace_init_fixture.namespace_init_pid()
            })?;
        namespace_init_fixture.open_namespace_init_pidfd(namespace_init_parent_pid)?;
        fs::write(&procs_path, namespace_init_parent_pid.to_string())
            .context(IoSnafu { path: &procs_path })?;
        let namespace_init_pid_in_own_namespace = pid_in_own_namespace(namespace_init_parent_pid)?;
        ensure!(
            namespace_init_pid_in_own_namespace == 1,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "PID-namespace init did not have namespace PID 1",
            }
        );
        let namespace_init_parent =
            self.wait_for("PID-namespace init identity", &procs_path, || {
                inspector
                    .snapshot(namespace_init_parent_pid)
                    .context(NodeSnafu)
            })?;
        namespace_init_fixture.release_namespace_init()?;
        let namespace_init_intermediate_pid =
            self.wait_for("PID-namespace intermediate creation", &procs_path, || {
                namespace_init_fixture.namespace_init_intermediate_pid(namespace_init_parent_pid)
            })?;
        namespace_init_fixture.open_intermediate_pidfd(namespace_init_intermediate_pid)?;
        let namespace_init_intermediate_before_exit =
            self.wait_for("PID-namespace intermediate identity", &procs_path, || {
                inspector
                    .snapshot(namespace_init_intermediate_pid)
                    .context(NodeSnafu)
            })?;
        namespace_init_fixture.release_intermediate_start(namespace_init_intermediate_pid)?;
        let namespace_init_native_child_pid =
            self.wait_for("PID-namespace native child creation", &procs_path, || {
                namespace_init_fixture
                    .intermediate_native_child_pid(namespace_init_intermediate_pid)
            })?;
        namespace_init_fixture.open_native_pidfd(namespace_init_native_child_pid)?;
        let namespace_init_native_child_before_parent_exit =
            self.wait_for("PID-namespace native child identity", &procs_path, || {
                inspector
                    .snapshot(namespace_init_native_child_pid)
                    .context(NodeSnafu)
            })?;
        ensure!(
            namespace_init_parent.root_class.as_deref() == Some("external_runtime_root")
                && namespace_init_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && namespace_init_intermediate_before_exit.creator_task_cookie
                    == Some(namespace_init_parent.task_cookie)
                && namespace_init_intermediate_before_exit.real_parent_task_cookie
                    == namespace_init_parent.task_cookie
                && namespace_init_intermediate_before_exit.real_parent_host_tid
                    == namespace_init_parent.host_tid
                && namespace_init_intermediate_before_exit.real_parent_host_tgid
                    == namespace_init_parent.host_tgid
                && namespace_init_intermediate_before_exit.root_class.is_none()
                && namespace_init_intermediate_before_exit
                    .installed_role_class
                    .is_none()
                && namespace_init_native_child_before_parent_exit.creator_task_cookie
                    == Some(namespace_init_intermediate_before_exit.task_cookie)
                && namespace_init_native_child_before_parent_exit.real_parent_task_cookie
                    == namespace_init_intermediate_before_exit.task_cookie
                && namespace_init_native_child_before_parent_exit.real_parent_host_tid
                    == namespace_init_intermediate_before_exit.host_tid
                && namespace_init_native_child_before_parent_exit.real_parent_host_tgid
                    == namespace_init_intermediate_before_exit.host_tgid
                && namespace_init_native_child_before_parent_exit
                    .root_class
                    .is_none()
                && namespace_init_native_child_before_parent_exit
                    .installed_role_class
                    .is_none()
                && namespace_init_native_child_before_parent_exit.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "PID-namespace native child has the wrong pre-exit identity",
            }
        );
        namespace_init_fixture.release_intermediate_exit()?;
        self.wait_for("PID-namespace intermediate exit", &procs_path, || {
            Ok(namespace_init_fixture
                .intermediate_exited(namespace_init_intermediate_pid)?
                .then_some(()))
        })?;
        namespace_init_fixture.release_exec(namespace_init_native_child_pid)?;
        let namespace_init_native_child_after_parent_exit = self.wait_for(
            "PID-namespace native child exec after parent exit",
            &procs_path,
            || {
                let snapshot = inspector
                    .snapshot(namespace_init_native_child_pid)
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie
                        == namespace_init_native_child_before_parent_exit.task_cookie
                        && snapshot.creator_task_cookie
                            == Some(namespace_init_intermediate_before_exit.task_cookie)
                        && snapshot.real_parent_task_cookie == 0
                        && snapshot.real_parent_host_tid == namespace_init_parent.host_tid
                        && snapshot.real_parent_host_tgid == namespace_init_parent.host_tgid
                        && snapshot.real_parent_interval_sequence
                            > namespace_init_native_child_before_parent_exit
                                .real_parent_interval_sequence
                        && snapshot.active_execution_id
                            != namespace_init_native_child_before_parent_exit.active_execution_id
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            },
        )?;
        ensure!(
            namespace_init_native_child_after_parent_exit
                .root_class
                .is_none()
                && namespace_init_native_child_after_parent_exit
                    .installed_role_class
                    .is_none()
                && namespace_init_native_child_after_parent_exit.active_role_id
                    == namespace_init_parent.active_role_id,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "PID-namespace native child lost its inherited restriction",
            }
        );
        namespace_init_fixture.stop();

        let mut double_fork_fixture = NativeProcessFixture::start_double_forking()?;
        fs::write(&procs_path, double_fork_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let double_fork_outer_parent =
            self.wait_for("double-fork outer parent identity", &procs_path, || {
                inspector
                    .snapshot(double_fork_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        double_fork_fixture.release_root()?;
        let double_fork_intermediate_pid =
            self.wait_for("double-fork intermediate creation", &procs_path, || {
                double_fork_fixture.intermediate_pid()
            })?;
        double_fork_fixture.open_intermediate_pidfd(double_fork_intermediate_pid)?;
        let double_fork_native_child_pid =
            self.wait_for("double-fork native child creation", &procs_path, || {
                double_fork_fixture.intermediate_native_child_pid(double_fork_intermediate_pid)
            })?;
        double_fork_fixture.open_native_pidfd(double_fork_native_child_pid)?;
        let double_fork_intermediate_before_exit =
            self.wait_for("double-fork intermediate identity", &procs_path, || {
                inspector
                    .snapshot(double_fork_intermediate_pid)
                    .context(NodeSnafu)
            })?;
        let double_fork_native_child_before_intermediate_exit =
            self.wait_for("double-fork native child identity", &procs_path, || {
                inspector
                    .snapshot(double_fork_native_child_pid)
                    .context(NodeSnafu)
            })?;
        ensure!(
            double_fork_outer_parent.root_class.as_deref() == Some("external_runtime_root")
                && double_fork_outer_parent.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && double_fork_intermediate_before_exit.creator_task_cookie
                    == Some(double_fork_outer_parent.task_cookie)
                && double_fork_intermediate_before_exit.real_parent_task_cookie
                    == double_fork_outer_parent.task_cookie
                && double_fork_intermediate_before_exit.root_class.is_none()
                && double_fork_intermediate_before_exit
                    .installed_role_class
                    .is_none()
                && double_fork_native_child_before_intermediate_exit.creator_task_cookie
                    == Some(double_fork_intermediate_before_exit.task_cookie)
                && double_fork_native_child_before_intermediate_exit.real_parent_task_cookie
                    == double_fork_intermediate_before_exit.task_cookie
                && double_fork_native_child_before_intermediate_exit
                    .root_class
                    .is_none()
                && double_fork_native_child_before_intermediate_exit
                    .installed_role_class
                    .is_none()
                && double_fork_native_child_before_intermediate_exit.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "double-fork native identity is incorrect before intermediate exit",
            }
        );
        double_fork_fixture.release_intermediate_exit()?;
        self.wait_for("double-fork intermediate exit", &procs_path, || {
            Ok(double_fork_fixture
                .intermediate_exited(double_fork_intermediate_pid)?
                .then_some(()))
        })?;
        double_fork_fixture.release_exec(double_fork_native_child_pid)?;
        let double_fork_native_child_after_intermediate_exit = self.wait_for(
            "double-fork native child exec after intermediate exit",
            &procs_path,
            || {
                let snapshot = inspector
                    .snapshot(double_fork_native_child_pid)
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.task_cookie
                        == double_fork_native_child_before_intermediate_exit.task_cookie
                        && snapshot.creator_task_cookie
                            == Some(double_fork_intermediate_before_exit.task_cookie)
                        && snapshot.real_parent_task_cookie
                            != double_fork_intermediate_before_exit.task_cookie
                        && snapshot.real_parent_interval_sequence
                            > double_fork_native_child_before_intermediate_exit
                                .real_parent_interval_sequence
                        && snapshot.active_execution_id
                            != double_fork_native_child_before_intermediate_exit.active_execution_id
                        && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && snapshot.process_state_vector_state
                            == ProcessStateVectorStateV1::Active as u8
                        && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            },
        )?;
        ensure!(
            double_fork_native_child_after_intermediate_exit
                .root_class
                .is_none()
                && double_fork_native_child_after_intermediate_exit
                    .installed_role_class
                    .is_none()
                && double_fork_native_child_after_intermediate_exit.active_role_id
                    == double_fork_outer_parent.active_role_id,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "double-fork native child lost its inherited restriction",
            }
        );
        double_fork_fixture.stop();

        self.wait_for("native reference baseline", &procs_path, || {
            Ok((profile_task_refs(&host)? == 0).then_some(()))
        })
        .map_err(|source| {
            invalid_state(format!(
                "{source}; live cgroup tasks `{}`; profile refs {}",
                fs::read_to_string(&procs_path).unwrap_or_default().trim(),
                profile_task_refs(&host).unwrap_or(u64::MAX)
            ))
        })?;
        let mut leader_first_fixture = NativeProcessFixture::start_with_leader_first_exit(
            &leader_first_ready_path,
            &leader_first_release_path,
        )?;
        fs::write(&procs_path, leader_first_fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let leader_first_root = self.wait_for("leader-first root identity", &procs_path, || {
            inspector
                .snapshot(leader_first_fixture.outer_pid())
                .context(NodeSnafu)
        })?;
        let leader_first_process_key = id_key(&leader_first_root.process_state_id)?;
        let leader_first_process_before = required_abi_map::<ProcessSecurityStateV1>(
            &host,
            "process_states",
            &leader_first_process_key,
            "leader-first process state",
        )?;
        let leader_first_entry_key = id_bytes(leader_first_process_before.entry_instance_id);
        let next_id_before_worker = identity_next_id(&host)?;
        leader_first_fixture.release_root()?;
        let leader_first_worker_tid = self.wait_for(
            "leader-first worker thread",
            &leader_first_ready_path,
            || leader_first_fixture.reported_tid(&leader_first_ready_path),
        )?;
        let leader_first_worker_task_cookie = next_id_before_worker;
        let no_pidfd_thread_observed = {
            let raw = i32::try_from(leader_first_worker_tid).map_err(|error| {
                invalid_state(format!(
                    "worker TID {leader_first_worker_tid} is invalid: {error}"
                ))
            })?;
            let tid = Pid::from_raw(raw)
                .ok_or_else(|| invalid_state("worker TID zero cannot have a pidfd"))?;
            pidfd_open(tid, PidfdFlags::empty()).is_err()
        };
        let leader_first_worker_coordinate = required_abi_map::<TaskCoordinateV1>(
            &host,
            "task_coordinates",
            &leader_first_worker_task_cookie.to_ne_bytes(),
            "leader-first worker coordinate",
        )?;
        let leader_first_created_by = required_abi_map::<CreatedByEdgeV1>(
            &host,
            "created_by_edges",
            &leader_first_worker_task_cookie.to_ne_bytes(),
            "leader-first worker creator edge",
        )?;
        ensure!(
            no_pidfd_thread_observed
                && identity_next_id(&host)? == next_id_before_worker + 2
                && leader_first_worker_coordinate.task_cookie == leader_first_worker_task_cookie
                && leader_first_worker_coordinate.host_tid == leader_first_worker_tid
                && leader_first_worker_coordinate.host_tgid == leader_first_root.host_tgid
                && leader_first_worker_coordinate.process_state_id
                    == leader_first_process_before.process_state_id
                && leader_first_worker_coordinate.state == TaskCoordinateStateV1::Runnable
                && leader_first_created_by.child_task_cookie == leader_first_worker_task_cookie
                && leader_first_created_by.creator_task_cookie == leader_first_root.task_cookie,
            InvalidInputSnafu {
                path: &leader_first_ready_path,
                reason: "the non-leader thread did not receive one exact native identity",
            }
        );
        let (
            leader_first_process_refs_after_leader_exit,
            leader_first_entry_refs_after_leader_exit,
            leader_first_profile_refs_after_leader_exit,
            leader_first_root_tombstone_released,
            leader_first_worker_tombstone_owned,
        ) = self.wait_for("leader-first reference transition", &procs_path, || {
            let root_coordinate = required_abi_map::<TaskCoordinateV1>(
                &host,
                "task_coordinates",
                &leader_first_root.task_cookie.to_ne_bytes(),
                "leader-first root coordinate",
            )?;
            let process = required_abi_map::<ProcessSecurityStateV1>(
                &host,
                "process_states",
                &leader_first_process_key,
                "leader-first live process",
            )?;
            let entry = required_map_bytes(
                &host,
                "entry_states",
                &leader_first_entry_key,
                "leader-first live entry",
            )?;
            let entry_refs = read_u64(
                &entry,
                offset_of!(EntrySecurityStateV1, live_task_refs),
                "leader-first live entry references",
            )?;
            let root_tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                &host,
                "task_reference_tombstones",
                &leader_first_root.task_cookie.to_ne_bytes(),
                "leader-first root tombstone",
            )?;
            let worker_tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                &host,
                "task_reference_tombstones",
                &leader_first_worker_task_cookie.to_ne_bytes(),
                "leader-first worker tombstone",
            )?;
            let profile_refs = profile_task_refs(&host)?;
            let root_released = root_tombstone.task_free_observed == 1
                && root_tombstone.released_bits == TASK_REFERENCE_ALL_V1
                && root_tombstone.state == ReferenceTombstoneStateV1::Released;
            let worker_owned = worker_tombstone.task_free_observed == 0
                && worker_tombstone.released_bits == 0
                && worker_tombstone.state == ReferenceTombstoneStateV1::Owned;
            Ok((root_coordinate.state == TaskCoordinateStateV1::Exited
                && process.state == ProcessSecurityStateKindV1::Active
                && process.live_thread_refs == 1
                && process.active_role_id == leader_first_root.active_role_id
                && entry_refs == 1
                && profile_refs == 1
                && root_released
                && worker_owned)
                .then_some((
                    process.live_thread_refs,
                    entry_refs,
                    profile_refs,
                    root_released,
                    worker_owned,
                )))
        })?;
        fs::write(&leader_first_release_path, b"release\n").context(IoSnafu {
            path: &leader_first_release_path,
        })?;
        leader_first_fixture.wait_for_successful_exit()?;
        let (
            leader_first_process_refs_after_worker_exit,
            leader_first_entry_refs_after_worker_exit,
            leader_first_profile_refs_after_worker_exit,
            leader_first_process_reclaimable,
            leader_first_entry_draining,
            leader_first_worker_tombstone_released,
        ) = self.wait_for("leader-first final reference release", &procs_path, || {
            let worker_coordinate = required_abi_map::<TaskCoordinateV1>(
                &host,
                "task_coordinates",
                &leader_first_worker_task_cookie.to_ne_bytes(),
                "leader-first exited worker coordinate",
            )?;
            let process = required_abi_map::<ProcessSecurityStateV1>(
                &host,
                "process_states",
                &leader_first_process_key,
                "leader-first retired process",
            )?;
            let vector = required_abi_map::<ProcessStateVectorV1>(
                &host,
                "process_state_vectors",
                &leader_first_process_key,
                "leader-first retired process vector",
            )?;
            let execution = required_abi_map::<ProcessExecutionInstanceV1>(
                &host,
                "process_execution_instances",
                &id_bytes(process.active_execution_id),
                "leader-first completed execution",
            )?;
            let entry = required_map_bytes(
                &host,
                "entry_states",
                &leader_first_entry_key,
                "leader-first draining entry",
            )?;
            let entry_refs = read_u64(
                &entry,
                offset_of!(EntrySecurityStateV1, live_task_refs),
                "leader-first final entry references",
            )?;
            let entry_lifetime = read_u8(
                &entry,
                offset_of!(EntrySecurityStateV1, lifetime_state),
                "leader-first entry lifetime",
            )?;
            let worker_tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                &host,
                "task_reference_tombstones",
                &leader_first_worker_task_cookie.to_ne_bytes(),
                "leader-first released worker tombstone",
            )?;
            let profile_refs = profile_task_refs(&host)?;
            let process_reclaimable = process.state == ProcessSecurityStateKindV1::Reclaimable
                && process.live_thread_refs == 0
                && vector.state == ProcessStateVectorStateV1::Retiring
                && execution.state == ProcessExecutionStateV1::Complete;
            let entry_draining =
                entry_refs == 0 && entry_lifetime == EntryLifetimeStateV1::Draining as u8;
            let worker_released = worker_tombstone.task_free_observed == 1
                && worker_tombstone.released_bits == TASK_REFERENCE_ALL_V1
                && worker_tombstone.state == ReferenceTombstoneStateV1::Released;
            Ok((worker_coordinate.state == TaskCoordinateStateV1::Exited
                && process_reclaimable
                && entry_draining
                && profile_refs == 0
                && worker_released)
                .then_some((
                    process.live_thread_refs,
                    entry_refs,
                    profile_refs,
                    process_reclaimable,
                    entry_draining,
                    worker_released,
                )))
        })?;
        leader_first_fixture.stop();
        leader_first_ready_cleanup.cleanup()?;
        leader_first_release_cleanup.cleanup()?;

        let reuse_work = output_directory.join("pid-tid-reuse");
        ensure!(
            !reuse_work.exists(),
            InvalidInputSnafu {
                path: &reuse_work,
                reason: "the PID/TID reuse fixture directory must not already exist",
            }
        );
        fs::create_dir(&reuse_work).context(IoSnafu { path: &reuse_work })?;
        let reuse_cleanup = ProbeDirectory::new(&reuse_work);
        let mut reuse_fixture = NativeProcessFixture::start_pid_tid_reuse(&reuse_work)?;
        let reuse_namespace_init_pid =
            self.wait_for("PID/TID reuse namespace init", &reuse_work, || {
                reuse_fixture.namespace_init_pid()
            })?;
        reuse_fixture.open_namespace_init_pidfd(reuse_namespace_init_pid)?;
        fs::write(&procs_path, reuse_namespace_init_pid.to_string())
            .context(IoSnafu { path: &procs_path })?;
        let reuse_namespace_init = self.wait_for(
            "PID/TID reuse namespace-init external identity",
            &procs_path,
            || {
                inspector
                    .snapshot(reuse_namespace_init_pid)
                    .context(NodeSnafu)
            },
        )?;
        reuse_fixture.release_root()?;
        let reused_namespace_pid = self.wait_for(
            "first reusable namespace PID",
            &reuse_work.join("process-first"),
            || read_marker_pid(&reuse_work.join("process-first")),
        )?;
        let first_reused_host_pid =
            self.wait_for("first reusable host PID", &reuse_work, || {
                reuse_fixture.first_child_pid(reuse_namespace_init_pid)
            })?;
        let first_live_namespace_pid = pid_in_own_namespace(first_reused_host_pid)?;
        let pid_reuse_first = self.wait_for("first reused-PID identity", &procs_path, || {
            inspector.snapshot(first_reused_host_pid).context(NodeSnafu)
        })?;
        let pid_reuse_first_coordinate = required_abi_map::<TaskCoordinateV1>(
            &host,
            "task_coordinates",
            &pid_reuse_first.task_cookie.to_ne_bytes(),
            "first reused-PID coordinate",
        )?;
        fs::write(reuse_work.join("release-process-first"), b"release\n").context(IoSnafu {
            path: reuse_work.join("release-process-first"),
        })?;
        let second_namespace_pid = self.wait_for(
            "second reusable namespace PID",
            &reuse_work.join("process-second"),
            || read_marker_pid(&reuse_work.join("process-second")),
        )?;
        let second_reused_host_pid =
            self.wait_for("second reusable host PID", &reuse_work, || {
                reuse_fixture.first_child_pid(reuse_namespace_init_pid)
            })?;
        let second_live_namespace_pid = pid_in_own_namespace(second_reused_host_pid)?;
        let pid_reuse_second = self.wait_for("second reused-PID identity", &procs_path, || {
            inspector
                .snapshot(second_reused_host_pid)
                .context(NodeSnafu)
        })?;
        let pid_reuse_second_coordinate = required_abi_map::<TaskCoordinateV1>(
            &host,
            "task_coordinates",
            &pid_reuse_second.task_cookie.to_ne_bytes(),
            "second reused-PID coordinate",
        )?;
        let pid_reuse_fresh_identity = reused_namespace_pid == second_namespace_pid
            && first_reused_host_pid != second_reused_host_pid
            && pid_reuse_first.task_cookie != pid_reuse_second.task_cookie
            && pid_reuse_first.process_state_id != pid_reuse_second.process_state_id
            && pid_reuse_first.active_execution_id != pid_reuse_second.active_execution_id
            && pid_reuse_first.creator_task_cookie == Some(reuse_namespace_init.task_cookie)
            && pid_reuse_second.creator_task_cookie == Some(reuse_namespace_init.task_cookie)
            && pid_reuse_first_coordinate.pid_namespace_inode
                == pid_reuse_second_coordinate.pid_namespace_inode
            && pid_reuse_first_coordinate.task_start_boottime_ns
                != pid_reuse_second_coordinate.task_start_boottime_ns;
        ensure!(
            reuse_namespace_init.root_class.as_deref() == Some("external_runtime_root")
                && reuse_namespace_init.creator_task_cookie.is_none()
                && reused_namespace_pid > 1
                && first_live_namespace_pid == reused_namespace_pid
                && second_live_namespace_pid == reused_namespace_pid
                && pid_reuse_fresh_identity,
            InvalidInputSnafu {
                path: &reuse_work,
                reason: "reusing a namespace PID attached stale native identity",
            }
        );
        fs::write(reuse_work.join("release-process-second"), b"release\n").context(IoSnafu {
            path: reuse_work.join("release-process-second"),
        })?;
        self.wait_for(
            "process-reuse completion gate",
            &reuse_work.join("processes-done"),
            || Ok(reuse_work.join("processes-done").exists().then_some(())),
        )?;

        let next_id_before_first_reused_tid = identity_next_id(&host)?;
        fs::write(reuse_work.join("start-thread-first"), b"start\n").context(IoSnafu {
            path: reuse_work.join("start-thread-first"),
        })?;
        let reused_namespace_tid = self.wait_for(
            "first reusable namespace TID",
            &reuse_work.join("thread-first"),
            || read_marker_pid(&reuse_work.join("thread-first")),
        )?;
        let tid_reuse_first_host_tid = self.wait_for(
            "first reusable host TID",
            &reuse_work.join("thread-first"),
            || host_thread_for_namespace_tid(reuse_namespace_init_pid, reused_namespace_tid),
        )?;
        let tid_reuse_first_task_cookie = next_id_before_first_reused_tid;
        let tid_reuse_first_coordinate = required_abi_map::<TaskCoordinateV1>(
            &host,
            "task_coordinates",
            &tid_reuse_first_task_cookie.to_ne_bytes(),
            "first reused-TID coordinate",
        )?;
        let tid_reuse_first_edge = required_abi_map::<CreatedByEdgeV1>(
            &host,
            "created_by_edges",
            &tid_reuse_first_task_cookie.to_ne_bytes(),
            "first reused-TID creator edge",
        )?;
        ensure!(
            identity_next_id(&host)? == next_id_before_first_reused_tid + 2
                && tid_reuse_first_coordinate.host_tid == tid_reuse_first_host_tid
                && tid_reuse_first_coordinate.host_tgid == reuse_namespace_init.host_tgid
                && tid_reuse_first_coordinate.process_state_id
                    == id_value(&reuse_namespace_init.process_state_id)?
                && tid_reuse_first_edge.creator_task_cookie == reuse_namespace_init.task_cookie,
            InvalidInputSnafu {
                path: &reuse_work,
                reason: "the first reusable TID did not receive an exact thread identity",
            }
        );
        fs::write(reuse_work.join("release-thread-first"), b"release\n").context(IoSnafu {
            path: reuse_work.join("release-thread-first"),
        })?;
        self.wait_for(
            "first reusable TID exit",
            &reuse_work.join("thread-first-done"),
            || {
                if !reuse_work.join("thread-first-done").exists() {
                    return Ok(None);
                }
                let coordinate = required_abi_map::<TaskCoordinateV1>(
                    &host,
                    "task_coordinates",
                    &tid_reuse_first_task_cookie.to_ne_bytes(),
                    "exited first reused-TID coordinate",
                )?;
                Ok((coordinate.state == TaskCoordinateStateV1::Exited).then_some(()))
            },
        )?;
        let next_id_before_second_reused_tid = identity_next_id(&host)?;
        fs::write(reuse_work.join("start-thread-second"), b"start\n").context(IoSnafu {
            path: reuse_work.join("start-thread-second"),
        })?;
        let second_namespace_tid = self.wait_for(
            "second reusable namespace TID",
            &reuse_work.join("thread-second"),
            || read_marker_pid(&reuse_work.join("thread-second")),
        )?;
        let tid_reuse_second_host_tid = self.wait_for(
            "second reusable host TID",
            &reuse_work.join("thread-second"),
            || host_thread_for_namespace_tid(reuse_namespace_init_pid, second_namespace_tid),
        )?;
        let tid_reuse_second_task_cookie = next_id_before_second_reused_tid;
        let tid_reuse_second_coordinate = required_abi_map::<TaskCoordinateV1>(
            &host,
            "task_coordinates",
            &tid_reuse_second_task_cookie.to_ne_bytes(),
            "second reused-TID coordinate",
        )?;
        let tid_reuse_second_edge = required_abi_map::<CreatedByEdgeV1>(
            &host,
            "created_by_edges",
            &tid_reuse_second_task_cookie.to_ne_bytes(),
            "second reused-TID creator edge",
        )?;
        let tid_reuse_fresh_identity = reused_namespace_tid == second_namespace_tid
            && tid_reuse_first_host_tid != tid_reuse_second_host_tid
            && tid_reuse_first_task_cookie != tid_reuse_second_task_cookie
            && tid_reuse_first_coordinate.task_start_boottime_ns
                != tid_reuse_second_coordinate.task_start_boottime_ns
            && tid_reuse_first_coordinate.pid_namespace_inode
                == tid_reuse_second_coordinate.pid_namespace_inode
            && tid_reuse_second_edge.creator_task_cookie == reuse_namespace_init.task_cookie;
        ensure!(
            identity_next_id(&host)? == next_id_before_second_reused_tid + 2
                && tid_reuse_second_coordinate.host_tid == tid_reuse_second_host_tid
                && tid_reuse_second_coordinate.host_tgid == reuse_namespace_init.host_tgid
                && tid_reuse_fresh_identity,
            InvalidInputSnafu {
                path: &reuse_work,
                reason: "reusing a namespace TID attached stale native identity",
            }
        );
        fs::write(reuse_work.join("release-thread-second"), b"release\n").context(IoSnafu {
            path: reuse_work.join("release-thread-second"),
        })?;
        reuse_fixture.wait_for_successful_exit()?;
        self.wait_for("reused TID final release", &reuse_work, || {
            let tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                &host,
                "task_reference_tombstones",
                &tid_reuse_second_task_cookie.to_ne_bytes(),
                "second reused-TID tombstone",
            )?;
            Ok((tombstone.task_free_observed == 1
                && tombstone.released_bits == TASK_REFERENCE_ALL_V1
                && tombstone.state == ReferenceTombstoneStateV1::Released)
                .then_some(()))
        })?;
        reuse_fixture.stop();
        reuse_cleanup.cleanup()?;

        let mut cgroup_escape_control = CloneIntoCgroupFixture::start_with_root_first_effect(
            &cgroup_path,
            &cgroup_escape_sentinel_path,
        )?;
        let cgroup_escape_unmoved_control = self.wait_for(
            "cgroup escape unmoved control identity",
            &procs_path,
            || {
                inspector
                    .snapshot(cgroup_escape_control.root_pid())
                    .context(NodeSnafu)
            },
        )?;
        ensure!(
            cgroup_escape_unmoved_control.creator_task_cookie.is_none()
                && cgroup_escape_unmoved_control.root_class.as_deref()
                    == Some("external_runtime_root")
                && cgroup_escape_unmoved_control.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && cgroup_escape_unmoved_control.active_role_id == binding.external_role_id
                && cgroup_escape_unmoved_control.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "the unmoved cgroup-escape control did not have the restricted external identity",
            }
        );
        cgroup_escape_control.release_root()?;
        self.wait_for("unmoved-root first-effect success", &procs_path, || {
            cgroup_escape_control.root_first_effect_allowed()
        })?;
        cgroup_escape_control.stop();

        let mut cgroup_escape_fixture = CloneIntoCgroupFixture::start_with_root_first_effect(
            &cgroup_path,
            &cgroup_escape_sentinel_path,
        )?;
        let cgroup_escape_unmoved_root = self.wait_for(
            "cgroup escape root identity before movement",
            &procs_path,
            || {
                inspector
                    .snapshot(cgroup_escape_fixture.root_pid())
                    .context(NodeSnafu)
            },
        )?;
        let health_before_cgroup_escape = identity.health(&host).context(NodeSnafu)?;
        fs::write(
            &parent_procs_path,
            cgroup_escape_fixture.root_pid().to_string(),
        )
        .context(IoSnafu {
            path: &parent_procs_path,
        })?;
        let cgroup_escape_root = self.wait_for(
            "cgroup escape fail-closed identity",
            &parent_procs_path,
            || {
                let snapshot = inspector
                    .snapshot(cgroup_escape_fixture.root_pid())
                    .context(NodeSnafu)?;
                Ok(snapshot.filter(|snapshot| {
                    snapshot.coordinate_state == TaskCoordinateStateV1::FailClosedUnknown as u8
                }))
            },
        )?;
        let health_after_cgroup_escape = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            cgroup_escape_unmoved_root.creator_task_cookie.is_none()
                && cgroup_escape_unmoved_root.root_class.as_deref()
                    == Some("external_runtime_root")
                && cgroup_escape_unmoved_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && cgroup_escape_unmoved_root.active_role_id == binding.external_role_id
                && cgroup_escape_unmoved_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8
                && cgroup_escape_root.creator_task_cookie.is_none()
                && cgroup_escape_root.root_class.as_deref() == Some("external_runtime_root")
                && cgroup_escape_root.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && cgroup_escape_root.active_role_id == binding.external_role_id
                && health_after_cgroup_escape.placement_mismatches
                    > health_before_cgroup_escape.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "moving a labeled root out of its cgroup did not fail closed",
            }
        );
        cgroup_escape_fixture.release_root()?;
        self.wait_for("moved-root first-effect denial", &parent_procs_path, || {
            cgroup_escape_fixture.moved_root_first_effect_denied()
        })?;
        let health_after_cgroup_escape_effect = identity.health(&host).context(NodeSnafu)?;
        ensure!(
            health_after_cgroup_escape_effect.placement_mismatches
                > health_after_cgroup_escape.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "a moved labeled root did not record its denied first effect",
            }
        );
        cgroup_escape_fixture.stop();

        let mut clone_first_effect_fixture =
            CloneIntoCgroupFixture::start_with_native_child_first_effect(
                &cgroup_path,
                &cgroup_escape_sentinel_path,
            )?;
        let clone_into_cgroup_first_effect_root = self.wait_for(
            "CLONE_INTO_CGROUP first-effect root identity",
            &procs_path,
            || {
                inspector
                    .snapshot(clone_first_effect_fixture.root_pid())
                    .context(NodeSnafu)
            },
        )?;
        clone_first_effect_fixture.release_root()?;
        let clone_into_cgroup_first_effect_child_pid = self.wait_for(
            "CLONE_INTO_CGROUP first-effect native child",
            &procs_path,
            || clone_first_effect_fixture.child_pid(),
        )?;
        let clone_into_cgroup_first_effect_child = self.wait_for(
            "CLONE_INTO_CGROUP first-effect native child identity",
            &procs_path,
            || {
                inspector
                    .snapshot(clone_into_cgroup_first_effect_child_pid)
                    .context(NodeSnafu)
            },
        )?;
        ensure!(
            clone_into_cgroup_first_effect_root
                .creator_task_cookie
                .is_none()
                && clone_into_cgroup_first_effect_root.root_class.as_deref()
                    == Some("external_runtime_root")
                && clone_into_cgroup_first_effect_root
                    .installed_role_class
                    .as_deref()
                    == Some("runtime_external_restricted")
                && clone_into_cgroup_first_effect_root.active_role_id == binding.external_role_id
                && clone_into_cgroup_first_effect_root.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8
                && clone_into_cgroup_first_effect_child.creator_task_cookie
                    == Some(clone_into_cgroup_first_effect_root.task_cookie)
                && clone_into_cgroup_first_effect_child.real_parent_task_cookie
                    == clone_into_cgroup_first_effect_root.task_cookie
                && clone_into_cgroup_first_effect_child.root_class.is_none()
                && clone_into_cgroup_first_effect_child
                    .installed_role_class
                    .is_none()
                && clone_into_cgroup_first_effect_child.active_role_id
                    == clone_into_cgroup_first_effect_root.active_role_id
                && clone_into_cgroup_first_effect_child.coordinate_state
                    == TaskCoordinateStateV1::Runnable as u8
                && clone_into_cgroup_first_effect_child.process_execution_state
                    == ProcessExecutionStateV1::Active as u8
                && clone_into_cgroup_first_effect_child.process_state_vector_state
                    == ProcessStateVectorStateV1::Active as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason:
                    "CLONE_INTO_CGROUP first-effect root or native child has the wrong identity",
            }
        );
        clone_first_effect_fixture.release_child_first_effect()?;
        self.wait_for(
            "CLONE_INTO_CGROUP native-child first-effect success",
            &procs_path,
            || clone_first_effect_fixture.native_child_first_effect_allowed(),
        )?;
        clone_first_effect_fixture.stop();
        cgroup_escape_sentinel_cleanup.cleanup()?;

        let profile_task_refs_after_exit =
            self.wait_for("profile reference release", &procs_path, || {
                let refs = profile_task_refs(&host)?;
                Ok((refs == 0).then_some(refs))
            })?;
        let cgroup_reuse_first_root_id = fs::metadata(&cgroup_path)
            .context(IoSnafu { path: &cgroup_path })?
            .ino();
        let cgroup_reuse_first_binding = required_abi_map::<ExecutionSetBindingStateV1>(
            &host,
            "execution_set_bindings",
            &cgroup_reuse_first_root_id.to_ne_bytes(),
            "first cgroup lifetime binding",
        )?;

        let first_map_ids = map_ids(&first_start);
        host.shutdown().context(InterceptorSnafu)?;
        let retired_pin_root = pin_root.with_extension("retired");
        let retired_lease_path = lease_path.with_extension("retired.lock");
        let retired_pin_root_owner_rejected =
            match KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                &retired_lease_path,
                Some(retired_pin_root.clone()),
                boot_id.clone(),
                1,
            ))
            .start()
            {
                Err(InterceptorError::RetainedLsmLink { .. }) => true,
                Err(source) => {
                    if retired_pin_root.exists() {
                        ProbeDirectory::new(&retired_pin_root).cleanup()?;
                    }
                    ProbeFile::new(&retired_lease_path).cleanup()?;
                    return Err(crate::Error::from_interceptor(source));
                }
                Ok(retired) => {
                    retired.shutdown().context(InterceptorSnafu)?;
                    ProbeDirectory::new(&retired_pin_root).cleanup()?;
                    ProbeFile::new(&retired_lease_path).cleanup()?;
                    false
                }
            };
        ProbeFile::new(&retired_lease_path).cleanup()?;
        ensure!(
            retired_pin_root_owner_rejected && !retired_pin_root.exists(),
            InvalidInputSnafu {
                path: &retired_pin_root,
                reason: "a retained Interceptor owner allowed a distinct pin root",
            }
        );
        verify_recovery_rejects_displaced_map(&config, &first_start)?;
        let mut recovered = KernelHostOwner::new(config)
            .start()
            .context(InterceptorSnafu)?;
        let recovered_start = recovered.manifest().clone();
        let mut recovered_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        recovered_bindings
            .publish_all(&recovered, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut recovered)
            .context(NodeSnafu)?;
        let live_manifest_mismatch_detected = verify_live_manifest_negative_fixture(&recovered)?;
        let map_ids_stable_across_restart = first_map_ids == map_ids(&recovered_start);
        ensure!(
            map_ids_stable_across_restart,
            InvalidInputSnafu {
                path: pin_root,
                reason: "recovery did not reuse the complete pinned map generation",
            }
        );
        cgroup_cleanup.cleanup()?;
        ensure!(
            !cgroup_path.exists(),
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the first cgroup lifetime survived removal",
            }
        );
        let reused_cgroup_cleanup = ProbeCgroup::create(&cgroup_path)?;
        let reused_procs_path = reused_cgroup_cleanup.path().join("cgroup.procs");
        let mut reused_fixture = NativeProcessFixture::start()?;
        fs::write(&reused_procs_path, reused_fixture.outer_pid().to_string()).context(IoSnafu {
            path: &reused_procs_path,
        })?;
        let mut reused_binding = test_binding(reused_cgroup_cleanup.path());
        reused_binding.container_id = "c".repeat(64);
        reused_binding.pod_uid = "identity-pod-uid-reused".to_owned();
        reused_binding.sandbox_id = "identity-sandbox-reused".to_owned();
        reused_binding.container_generation = 2;

        let mut reused_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        reused_bindings
            .publish_all(&recovered, std::slice::from_ref(&reused_binding))
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut recovered)
            .context(NodeSnafu)?;
        let cgroup_reuse_second_root =
            self.wait_for("recreated cgroup root identity", &reused_procs_path, || {
                inspector
                    .snapshot(reused_fixture.outer_pid())
                    .context(NodeSnafu)
            })?;
        let cgroup_reuse_second_root_id = fs::metadata(reused_cgroup_cleanup.path())
            .context(IoSnafu {
                path: reused_cgroup_cleanup.path(),
            })?
            .ino();
        let cgroup_reuse_second_binding = required_abi_map::<ExecutionSetBindingStateV1>(
            &recovered,
            "execution_set_bindings",
            &cgroup_reuse_second_root_id.to_ne_bytes(),
            "second cgroup lifetime binding",
        )?;
        let cgroup_reuse_fresh_identity = cgroup_reuse_first_root_id != cgroup_reuse_second_root_id
            && cgroup_reuse_first_binding.binding_nonce
                != cgroup_reuse_second_binding.binding_nonce
            && cgroup_reuse_first_binding.root_cgroup_live_interval_id
                != cgroup_reuse_second_binding.root_cgroup_live_interval_id
            && binding_gap_reconciled_root.task_cookie != cgroup_reuse_second_root.task_cookie
            && binding_gap_reconciled_root.process_state_id
                != cgroup_reuse_second_root.process_state_id
            && binding_gap_reconciled_root.active_execution_id
                != cgroup_reuse_second_root.active_execution_id
            && cgroup_reuse_second_root.creator_task_cookie.is_none()
            && cgroup_reuse_second_root.root_class.as_deref() == Some("restored_or_unknown_root")
            && cgroup_reuse_second_root.installed_role_class.as_deref()
                == Some("fail_closed_unknown")
            && cgroup_reuse_second_root.active_role_id == reused_binding.external_role_id;
        ensure!(
            cgroup_reuse_fresh_identity,
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the recreated cgroup path reused an old lifetime identity",
            }
        );
        reused_fixture.stop();
        recovered.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        reused_cgroup_cleanup.cleanup()?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the identity-test pin root or lease survived cleanup",
            }
        );
        ensure!(
            !cgroup_path.exists(),
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the identity-test cgroup survived cleanup",
            }
        );
        Ok(IdentityPhysicalProbeBundleV1 {
            schema_version: 28,
            object_sha256,
            first_start,
            distinct_pin_root_owner_rejected,
            binding_gap_reconciled_root: binding_gap_reconciled_root.clone(),
            binding_gap_reconciliation_closed: true,
            external_ambiguity_first_root,
            external_ambiguity_second_root,
            external_ambiguity_same_restricted_role,
            cgroup_escape_unmoved_control,
            cgroup_escape_unmoved_first_effect_allowed: true,
            cgroup_escape_root,
            cgroup_escape_placement_mismatch_detected: true,
            cgroup_escape_first_effect_denied: true,
            moved_parent_fork_denied: true,
            moved_task_exec_denied: true,
            pre_ponr_failed_exec_restored: true,
            pre_ponr_failed_exec_before: failed_exec_before,
            pre_ponr_failed_exec_after_failure: failed_exec_after_failure,
            pre_ponr_failed_exec_after_success: failed_exec_after_success,
            post_ponr_exec_fatal: true,
            post_ponr_pending_state: post_ponr_pending.state as u8,
            post_ponr_exec_guard_state: post_ponr_process.exec_guard_state as u8,
            post_ponr_task_coordinate_state: post_ponr_coordinate.state as u8,
            authorization_retarget_rejected: true,
            authorization_expired_rejected: true,
            authorization_signature_mismatch_rejected: true,
            authorization_same_owner_replay_rejected: true,
            authorization_restart_replay_rejected: true,
            authorization_reboot_replay_rejected: true,
            authorization_fresh_exact_accepted: true,
            authorization_fresh_after_reboot_accepted: true,
            authorization_replay_wal_sha256,
            authorization_replay_wal_records,
            authorization_replay_state_removed: true,
            non_leader_thread_exec_committed: true,
            non_leader_thread_exec_root,
            non_leader_thread_exec_after_exec,
            clone_into_cgroup_external_root: clone_external_root,
            clone_into_cgroup_native_child: clone_native_child,
            clone_into_cgroup_native_child_after_namespace_move:
                clone_native_child_after_namespace_move,
            clone_into_cgroup_first_effect_root,
            clone_into_cgroup_first_effect_child,
            clone_into_cgroup_native_child_first_effect_allowed: true,
            external_root,
            native_child_before_exec: before_exec,
            native_child_after_exec: after_exec,
            orphaned_native_parent,
            orphaned_native_child_before_parent_exit,
            orphaned_native_child_after_parent_exit,
            subreaper_native_parent,
            subreaper_intermediate_before_exit,
            subreaper_native_child_before_parent_exit,
            subreaper_native_child_after_parent_exit,
            namespace_init_parent,
            namespace_init_pid_in_own_namespace,
            namespace_init_intermediate_before_exit,
            namespace_init_native_child_before_parent_exit,
            namespace_init_native_child_after_parent_exit,
            double_fork_outer_parent,
            double_fork_intermediate_before_exit,
            double_fork_native_child_before_intermediate_exit,
            double_fork_native_child_after_intermediate_exit,
            no_pidfd_thread_observed,
            leader_first_worker_task_cookie,
            leader_first_process_refs_after_leader_exit,
            leader_first_entry_refs_after_leader_exit,
            leader_first_profile_refs_after_leader_exit,
            leader_first_root_tombstone_released,
            leader_first_worker_tombstone_owned,
            leader_first_process_refs_after_worker_exit,
            leader_first_entry_refs_after_worker_exit,
            leader_first_profile_refs_after_worker_exit,
            leader_first_process_reclaimable,
            leader_first_entry_draining,
            leader_first_worker_tombstone_released,
            reused_namespace_pid,
            pid_reuse_first,
            pid_reuse_second,
            pid_reuse_fresh_identity,
            reused_namespace_tid,
            tid_reuse_first_task_cookie,
            tid_reuse_second_task_cookie,
            tid_reuse_first_host_tid,
            tid_reuse_second_host_tid,
            tid_reuse_fresh_identity,
            cgroup_reuse_path: cgroup_path.clone(),
            cgroup_reuse_first_root: binding_gap_reconciled_root.clone(),
            cgroup_reuse_second_root,
            cgroup_reuse_first_root_id,
            cgroup_reuse_second_root_id,
            cgroup_reuse_first_binding_nonce: id128_hex(cgroup_reuse_first_binding.binding_nonce),
            cgroup_reuse_second_binding_nonce: id128_hex(cgroup_reuse_second_binding.binding_nonce),
            cgroup_reuse_first_live_interval_id: id128_hex(
                cgroup_reuse_first_binding.root_cgroup_live_interval_id,
            ),
            cgroup_reuse_second_live_interval_id: id128_hex(
                cgroup_reuse_second_binding.root_cgroup_live_interval_id,
            ),
            cgroup_reuse_fresh_identity,
            profile_task_refs_after_exit,
            recovered_start,
            map_ids_stable_across_restart,
            live_manifest_mismatch_detected,
            pin_root_removed: true,
            lease_removed: true,
            cgroup_removed: true,
            kubernetes_initial_root: None,
            kubernetes_direct_cri_exec_root: None,
            kubernetes_kubectl_exec_root: None,
            kubernetes_kubectl_tty_exec_root: None,
            kubernetes_kubectl_copy_root: None,
            kubernetes_native_child_parent: None,
            kubernetes_native_child_control: None,
            kubernetes_lifecycle_sleep_no_task: None,
            kubernetes_http_probe_no_task: None,
            kubernetes_tcp_probe_no_task: None,
            kubernetes_grpc_probe_no_task: None,
            kubernetes_init_container_root: None,
            kubernetes_sidecar_container_root: None,
            kubernetes_application_container_root: None,
            kubernetes_containers_distinct_execution_sets: None,
            kubernetes_ephemeral_target_root: None,
            kubernetes_ephemeral_container_root: None,
            kubernetes_ephemeral_shared_pid_namespace: None,
            kubernetes_ephemeral_distinct_execution_set_and_profile: None,
            kubernetes_startup_exec_probe_root: None,
            kubernetes_readiness_exec_probe_root: None,
            kubernetes_liveness_exec_probe_root: None,
            kubernetes_probe_native_parent: None,
            kubernetes_probe_native_child: None,
            kubernetes_probe_kubectl_exec_root: None,
            kubernetes_probe_direct_cri_exec_root: None,
            kubernetes_probe_identities_distinct: None,
            kubernetes_prestop_application_before: None,
            kubernetes_prestop_application_during: None,
            kubernetes_prestop_exec_root: None,
            kubernetes_prestop_profile_refs_during: None,
            kubernetes_prestop_profile_refs_after: None,
            kubernetes_poststart_entrypoint_first_application: None,
            kubernetes_poststart_entrypoint_first_hook: None,
            kubernetes_poststart_hook_first_application: None,
            kubernetes_poststart_hook_first_hook: None,
            kubernetes_poststart_both_orders_observed: None,
            kubernetes_poststart_repeat_application_before: None,
            kubernetes_poststart_repeat_application_after: None,
            kubernetes_poststart_first_hook: None,
            kubernetes_poststart_repeated_hook: None,
            kubernetes_poststart_repeat_fresh_identity: None,
            kubernetes_stock_hook_timeout_seconds: None,
            kubernetes_stock_hook_timeout_result: None,
            kubernetes_stock_hook_timeout_no_payload: None,
            kubernetes_stock_hook_mismatch_result: None,
            kubernetes_stock_hook_mismatch_rejected: None,
            kubernetes_stock_hook_mismatch_no_payload: None,
            kubernetes_stock_hook_missing_field_result: None,
            kubernetes_stock_hook_missing_field_rejected: None,
            kubernetes_stock_hook_missing_field_no_payload: None,
            kubernetes_stock_hook_failure_fixture_removed: None,
            kubernetes_loss_audit_absent_root: None,
            kubernetes_loss_bpf_recovered_root: None,
            kubernetes_loss_bpf_recovered_fresh_restricted: None,
            kubernetes_loss_runtime_root: None,
            kubernetes_loss_runtime_identity_unhealthy: None,
            kubernetes_restart_discovered_root: None,
            kubernetes_restart_bound_root: None,
            kubernetes_restart_runtime_recovered_root: None,
            kubernetes_restart_node_gap_root: None,
            kubernetes_restart_node_recovered_root: None,
            kubernetes_restart_node_observation_unavailable: None,
            kubernetes_restart_identity_stable: None,
            kubernetes_reuse_first_root: None,
            kubernetes_reuse_second_root: None,
            kubernetes_reuse_first_pod_uid: None,
            kubernetes_reuse_second_pod_uid: None,
            kubernetes_reuse_first_sandbox_id: None,
            kubernetes_reuse_second_sandbox_id: None,
            kubernetes_reuse_first_container_id: None,
            kubernetes_reuse_second_container_id: None,
            kubernetes_reuse_first_cgroup_path: None,
            kubernetes_reuse_second_cgroup_path: None,
            kubernetes_reuse_first_root_cgroup_id: None,
            kubernetes_reuse_second_root_cgroup_id: None,
            kubernetes_reuse_first_binding_nonce: None,
            kubernetes_reuse_second_binding_nonce: None,
            kubernetes_reuse_first_live_interval_id: None,
            kubernetes_reuse_second_live_interval_id: None,
            kubernetes_reuse_same_names: None,
            kubernetes_reuse_fresh_full_identity: None,
            kubernetes_reuse_fresh_binding_identity: None,
            kubernetes_fixture_removed: false,
        })
    }

    pub fn physical_kubernetes_probe(
        &self,
        output_directory: &Path,
        previous_bundle_path: &Path,
        pin_root: &Path,
        lease_path: &Path,
    ) -> Result<IdentityPhysicalProbeBundleV1> {
        let bytes = fs::read(previous_bundle_path).context(IoSnafu {
            path: previous_bundle_path,
        })?;
        let mut bundle: IdentityPhysicalProbeBundleV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu {
                path: previous_bundle_path,
            })?;
        let entry_results_missing = bundle.kubernetes_initial_root.is_none()
            && bundle.kubernetes_direct_cri_exec_root.is_none()
            && bundle.kubernetes_kubectl_exec_root.is_none()
            && bundle.kubernetes_kubectl_tty_exec_root.is_none()
            && bundle.kubernetes_kubectl_copy_root.is_none()
            && bundle.kubernetes_native_child_parent.is_none()
            && bundle.kubernetes_native_child_control.is_none()
            && !bundle.kubernetes_fixture_removed;
        let entry_results_present = bundle.kubernetes_initial_root.is_some()
            && bundle.kubernetes_direct_cri_exec_root.is_some()
            && bundle.kubernetes_kubectl_exec_root.is_some()
            && bundle.kubernetes_kubectl_tty_exec_root.is_some()
            && bundle.kubernetes_kubectl_copy_root.is_some()
            && bundle.kubernetes_native_child_parent.is_some()
            && bundle.kubernetes_native_child_control.is_some()
            && bundle.kubernetes_fixture_removed;
        let network_results_missing = bundle.kubernetes_http_probe_no_task.is_none()
            && bundle.kubernetes_tcp_probe_no_task.is_none()
            && bundle.kubernetes_grpc_probe_no_task.is_none();
        let network_results_present = bundle.kubernetes_http_probe_no_task == Some(true)
            && bundle.kubernetes_tcp_probe_no_task == Some(true)
            && bundle.kubernetes_grpc_probe_no_task == Some(true);
        let container_results_missing = bundle.kubernetes_init_container_root.is_none()
            && bundle.kubernetes_sidecar_container_root.is_none()
            && bundle.kubernetes_application_container_root.is_none()
            && bundle
                .kubernetes_containers_distinct_execution_sets
                .is_none();
        let container_results_present = bundle.kubernetes_init_container_root.is_some()
            && bundle.kubernetes_sidecar_container_root.is_some()
            && bundle.kubernetes_application_container_root.is_some()
            && bundle.kubernetes_containers_distinct_execution_sets == Some(true);
        let ephemeral_results_missing = bundle.kubernetes_ephemeral_target_root.is_none()
            && bundle.kubernetes_ephemeral_container_root.is_none()
            && bundle.kubernetes_ephemeral_shared_pid_namespace.is_none()
            && bundle
                .kubernetes_ephemeral_distinct_execution_set_and_profile
                .is_none();
        let ephemeral_results_present = bundle.kubernetes_ephemeral_target_root.is_some()
            && bundle.kubernetes_ephemeral_container_root.is_some()
            && bundle.kubernetes_ephemeral_shared_pid_namespace == Some(true)
            && bundle.kubernetes_ephemeral_distinct_execution_set_and_profile == Some(true);
        let probe_results_missing = bundle.kubernetes_startup_exec_probe_root.is_none()
            && bundle.kubernetes_readiness_exec_probe_root.is_none()
            && bundle.kubernetes_liveness_exec_probe_root.is_none()
            && bundle.kubernetes_probe_native_parent.is_none()
            && bundle.kubernetes_probe_native_child.is_none()
            && bundle.kubernetes_probe_kubectl_exec_root.is_none()
            && bundle.kubernetes_probe_direct_cri_exec_root.is_none()
            && bundle.kubernetes_probe_identities_distinct.is_none();
        let probe_results_present = bundle.kubernetes_startup_exec_probe_root.is_some()
            && bundle.kubernetes_readiness_exec_probe_root.is_some()
            && bundle.kubernetes_liveness_exec_probe_root.is_some()
            && bundle.kubernetes_probe_native_parent.is_some()
            && bundle.kubernetes_probe_native_child.is_some()
            && bundle.kubernetes_probe_kubectl_exec_root.is_some()
            && bundle.kubernetes_probe_direct_cri_exec_root.is_some()
            && bundle.kubernetes_probe_identities_distinct == Some(true);
        let prestop_results_missing = bundle.kubernetes_prestop_application_before.is_none()
            && bundle.kubernetes_prestop_application_during.is_none()
            && bundle.kubernetes_prestop_exec_root.is_none()
            && bundle.kubernetes_prestop_profile_refs_during.is_none()
            && bundle.kubernetes_prestop_profile_refs_after.is_none();
        let prestop_results_present = bundle.kubernetes_prestop_application_before.is_some()
            && bundle.kubernetes_prestop_application_during.is_some()
            && bundle.kubernetes_prestop_exec_root.is_some()
            && bundle.kubernetes_prestop_profile_refs_during == Some(2)
            && bundle.kubernetes_prestop_profile_refs_after == Some(0);
        let poststart_results_missing = bundle
            .kubernetes_poststart_entrypoint_first_application
            .is_none()
            && bundle.kubernetes_poststart_entrypoint_first_hook.is_none()
            && bundle.kubernetes_poststart_hook_first_application.is_none()
            && bundle.kubernetes_poststart_hook_first_hook.is_none()
            && bundle.kubernetes_poststart_both_orders_observed.is_none()
            && bundle
                .kubernetes_poststart_repeat_application_before
                .is_none()
            && bundle
                .kubernetes_poststart_repeat_application_after
                .is_none()
            && bundle.kubernetes_poststart_first_hook.is_none()
            && bundle.kubernetes_poststart_repeated_hook.is_none()
            && bundle.kubernetes_poststart_repeat_fresh_identity.is_none();
        let poststart_results_present = bundle
            .kubernetes_poststart_entrypoint_first_application
            .is_some()
            && bundle.kubernetes_poststart_entrypoint_first_hook.is_some()
            && bundle.kubernetes_poststart_hook_first_application.is_some()
            && bundle.kubernetes_poststart_hook_first_hook.is_some()
            && bundle.kubernetes_poststart_both_orders_observed == Some(true)
            && bundle
                .kubernetes_poststart_repeat_application_before
                .is_some()
            && bundle
                .kubernetes_poststart_repeat_application_after
                .is_some()
            && bundle.kubernetes_poststart_first_hook.is_some()
            && bundle.kubernetes_poststart_repeated_hook.is_some()
            && bundle.kubernetes_poststart_repeat_fresh_identity == Some(true);
        let stock_hook_failure_results_missing =
            bundle.kubernetes_stock_hook_timeout_seconds.is_none()
                && bundle.kubernetes_stock_hook_timeout_result.is_none()
                && bundle.kubernetes_stock_hook_timeout_no_payload.is_none()
                && bundle.kubernetes_stock_hook_mismatch_result.is_none()
                && bundle.kubernetes_stock_hook_mismatch_rejected.is_none()
                && bundle.kubernetes_stock_hook_mismatch_no_payload.is_none()
                && bundle.kubernetes_stock_hook_missing_field_result.is_none()
                && bundle
                    .kubernetes_stock_hook_missing_field_rejected
                    .is_none()
                && bundle
                    .kubernetes_stock_hook_missing_field_no_payload
                    .is_none()
                && bundle
                    .kubernetes_stock_hook_failure_fixture_removed
                    .is_none();
        let stock_hook_failure_results_present = bundle
            .kubernetes_stock_hook_timeout_seconds
            .is_some_and(|seconds| seconds == 30)
            && bundle
                .kubernetes_stock_hook_timeout_result
                .as_deref()
                .is_some_and(|result| !result.is_empty())
            && bundle.kubernetes_stock_hook_timeout_no_payload == Some(true)
            && bundle
                .kubernetes_stock_hook_mismatch_result
                .as_deref()
                .is_some_and(|result| !result.is_empty())
            && bundle.kubernetes_stock_hook_mismatch_rejected == Some(true)
            && bundle.kubernetes_stock_hook_mismatch_no_payload == Some(true)
            && bundle
                .kubernetes_stock_hook_missing_field_result
                .as_deref()
                .is_some_and(|result| !result.is_empty())
            && bundle.kubernetes_stock_hook_missing_field_rejected == Some(true)
            && bundle.kubernetes_stock_hook_missing_field_no_payload == Some(true)
            && bundle.kubernetes_stock_hook_failure_fixture_removed == Some(true);
        let loss_results_missing = bundle.kubernetes_loss_audit_absent_root.is_none()
            && bundle.kubernetes_loss_bpf_recovered_root.is_none()
            && bundle
                .kubernetes_loss_bpf_recovered_fresh_restricted
                .is_none()
            && bundle.kubernetes_loss_runtime_root.is_none()
            && bundle.kubernetes_loss_runtime_identity_unhealthy.is_none();
        let loss_results_present = bundle.kubernetes_loss_audit_absent_root.is_some()
            && bundle.kubernetes_loss_bpf_recovered_root.is_some()
            && bundle.kubernetes_loss_bpf_recovered_fresh_restricted == Some(true)
            && bundle.kubernetes_loss_runtime_root.is_some()
            && bundle.kubernetes_loss_runtime_identity_unhealthy == Some(true);
        let restart_results_missing = bundle.kubernetes_restart_discovered_root.is_none()
            && bundle.kubernetes_restart_bound_root.is_none()
            && bundle.kubernetes_restart_runtime_recovered_root.is_none()
            && bundle.kubernetes_restart_node_gap_root.is_none()
            && bundle.kubernetes_restart_node_recovered_root.is_none()
            && bundle
                .kubernetes_restart_node_observation_unavailable
                .is_none()
            && bundle.kubernetes_restart_identity_stable.is_none();
        let restart_results_present = bundle.kubernetes_restart_discovered_root.is_some()
            && bundle.kubernetes_restart_bound_root.is_some()
            && bundle.kubernetes_restart_runtime_recovered_root.is_some()
            && bundle.kubernetes_restart_node_gap_root.is_some()
            && bundle.kubernetes_restart_node_recovered_root.is_some()
            && bundle.kubernetes_restart_node_observation_unavailable == Some(true)
            && bundle.kubernetes_restart_identity_stable == Some(true);
        let reuse_results_missing = bundle.kubernetes_reuse_first_root.is_none()
            && bundle.kubernetes_reuse_second_root.is_none()
            && bundle.kubernetes_reuse_first_pod_uid.is_none()
            && bundle.kubernetes_reuse_second_pod_uid.is_none()
            && bundle.kubernetes_reuse_first_sandbox_id.is_none()
            && bundle.kubernetes_reuse_second_sandbox_id.is_none()
            && bundle.kubernetes_reuse_first_container_id.is_none()
            && bundle.kubernetes_reuse_second_container_id.is_none()
            && bundle.kubernetes_reuse_first_cgroup_path.is_none()
            && bundle.kubernetes_reuse_second_cgroup_path.is_none()
            && bundle.kubernetes_reuse_first_root_cgroup_id.is_none()
            && bundle.kubernetes_reuse_second_root_cgroup_id.is_none()
            && bundle.kubernetes_reuse_first_binding_nonce.is_none()
            && bundle.kubernetes_reuse_second_binding_nonce.is_none()
            && bundle.kubernetes_reuse_first_live_interval_id.is_none()
            && bundle.kubernetes_reuse_second_live_interval_id.is_none()
            && bundle.kubernetes_reuse_same_names.is_none()
            && bundle.kubernetes_reuse_fresh_full_identity.is_none()
            && bundle.kubernetes_reuse_fresh_binding_identity.is_none();
        let reuse_results_present = bundle.kubernetes_reuse_first_root.is_some()
            && bundle.kubernetes_reuse_second_root.is_some()
            && bundle.kubernetes_reuse_first_pod_uid.is_some()
            && bundle.kubernetes_reuse_second_pod_uid.is_some()
            && bundle.kubernetes_reuse_first_sandbox_id.is_some()
            && bundle.kubernetes_reuse_second_sandbox_id.is_some()
            && bundle.kubernetes_reuse_first_container_id.is_some()
            && bundle.kubernetes_reuse_second_container_id.is_some()
            && bundle.kubernetes_reuse_first_cgroup_path.is_some()
            && bundle.kubernetes_reuse_second_cgroup_path.is_some()
            && bundle.kubernetes_reuse_first_root_cgroup_id.is_some()
            && bundle.kubernetes_reuse_second_root_cgroup_id.is_some()
            && bundle.kubernetes_reuse_first_binding_nonce.is_some()
            && bundle.kubernetes_reuse_second_binding_nonce.is_some()
            && bundle.kubernetes_reuse_first_live_interval_id.is_some()
            && bundle.kubernetes_reuse_second_live_interval_id.is_some()
            && bundle.kubernetes_reuse_same_names == Some(true)
            && bundle.kubernetes_reuse_fresh_full_identity == Some(true)
            && bundle.kubernetes_reuse_fresh_binding_identity == Some(true);
        let schema_compatible = bundle.schema_version == 28
            || (bundle.schema_version == 27 && stock_hook_failure_results_missing)
            || (bundle.schema_version == 26
                && reuse_results_missing
                && stock_hook_failure_results_missing)
            || (bundle.schema_version == 25
                && restart_results_missing
                && reuse_results_missing
                && stock_hook_failure_results_missing)
            || (bundle.schema_version == 24
                && loss_results_missing
                && restart_results_missing
                && reuse_results_missing
                && stock_hook_failure_results_missing);
        ensure!(
            schema_compatible
                && (entry_results_missing || entry_results_present)
                && matches!(bundle.kubernetes_lifecycle_sleep_no_task, None | Some(true))
                && (network_results_missing || network_results_present)
                && (container_results_missing || container_results_present)
                && (ephemeral_results_missing || ephemeral_results_present)
                && (probe_results_missing || probe_results_present)
                && (prestop_results_missing || prestop_results_present)
                && (poststart_results_missing || poststart_results_present)
                && (stock_hook_failure_results_missing || stock_hook_failure_results_present)
                && (loss_results_missing || loss_results_present)
                && (restart_results_missing || restart_results_present)
                && (reuse_results_missing || reuse_results_present),
            InvalidInputSnafu {
                path: previous_bundle_path,
                reason: "the prior identity bundle cannot accept the next Kubernetes result",
            }
        );
        bundle.schema_version = 28;
        if entry_results_missing {
            self.physical_kubernetes_exec_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if bundle.kubernetes_lifecycle_sleep_no_task.is_none() {
            bundle.kubernetes_lifecycle_sleep_no_task =
                Some(self.physical_kubernetes_lifecycle_sleep_probe(output_directory)?);
        }
        if network_results_missing {
            let (http, tcp, grpc) = self.physical_kubernetes_network_probe(output_directory)?;
            bundle.kubernetes_http_probe_no_task = Some(http);
            bundle.kubernetes_tcp_probe_no_task = Some(tcp);
            bundle.kubernetes_grpc_probe_no_task = Some(grpc);
        }
        if container_results_missing {
            self.physical_kubernetes_containers_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if ephemeral_results_missing {
            self.physical_kubernetes_ephemeral_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if probe_results_missing {
            self.physical_kubernetes_probe_impersonation(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if prestop_results_missing {
            self.physical_kubernetes_prestop_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if poststart_results_missing {
            self.physical_kubernetes_poststart_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        if stock_hook_failure_results_missing {
            self.physical_kubernetes_stock_hook_failure_probe(output_directory, &mut bundle)?;
        }
        if loss_results_missing || restart_results_missing || reuse_results_missing {
            self.physical_kubernetes_resilience_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        bundle.kubernetes_fixture_removed = true;
        Ok(bundle)
    }

    pub fn write_json<T: Serialize>(&self, output: &Path, value: &T) -> Result<()> {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        let bytes = serde_json::to_vec_pretty(value).context(JsonSnafu { path: output })?;
        fs::write(output, bytes).context(IoSnafu { path: output })
    }

    pub fn remove_task_label_for_fixture(&self, pin_root: &Path, host_pid: u32) -> Result<()> {
        let raw_pid = i32::try_from(host_pid)
            .map_err(|error| invalid_state(format!("host PID {host_pid} is invalid: {error}")))?;
        let pid = Pid::from_raw(raw_pid)
            .ok_or_else(|| invalid_state("host PID zero cannot identify a task"))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{host_pid}")),
            })?;
        let path = pin_root.join("maps/task_labels");
        let map = MapHandle::from_pinned_path(&path).map_err(|error| {
            invalid_state(format!("open task-label map for loss injection: {error}"))
        })?;
        let key = pidfd.as_raw_fd().to_ne_bytes();
        ensure!(
            map.lookup(&key, libbpf_rs::MapFlags::ANY)
                .map_err(|error| invalid_state(format!("read task label before loss: {error}")))?
                .is_some(),
            InvalidInputSnafu {
                path: &path,
                reason: "the task has no label to remove",
            }
        );
        map.delete(&key)
            .map_err(|error| invalid_state(format!("remove task label: {error}")))?;
        ensure!(
            map.lookup(&key, libbpf_rs::MapFlags::ANY)
                .map_err(|error| invalid_state(format!("read task label after loss: {error}")))?
                .is_none(),
            InvalidInputSnafu {
                path: &path,
                reason: "the task label survived loss injection",
            }
        );
        Ok(())
    }

    fn pinned_execution_set_binding(
        &self,
        pin_root: &Path,
        cgroup_path: &Path,
    ) -> Result<ExecutionSetBindingStateV1> {
        let root_cgroup_id = fs::metadata(cgroup_path)
            .context(IoSnafu { path: cgroup_path })?
            .ino();
        let map_path = pin_root.join("maps/execution_set_bindings");
        let map = MapHandle::from_pinned_path(&map_path).map_err(|error| {
            invalid_state(format!(
                "open execution-set binding map for reuse inspection: {error}"
            ))
        })?;
        let bytes = map
            .lookup(&root_cgroup_id.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .map_err(|error| invalid_state(format!("read reused cgroup binding: {error}")))?
            .ok_or_else(|| invalid_state("the reused cgroup has no execution-set binding"))?;
        ExecutionSetBindingStateV1::try_read_from_bytes(&bytes).map_err(|error| {
            invalid_state(format!(
                "the reused cgroup binding has an invalid ABI value: {error}"
            ))
        })
    }

    fn materialize_object(&self, output_directory: &Path) -> Result<PathBuf> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let path = output_directory.join("erebor-interceptor.bpf.o");
        fs::write(&path, BUNDLED_BPF_OBJECT).context(IoSnafu { path: &path })?;
        Ok(path)
    }

    fn materialize_execfail(&self, path: &Path) -> Result<()> {
        let source = Path::new("/bin/true");
        let mut bytes = fs::read(source).context(IoSnafu { path: source })?;
        let (linker_offset, linker) = [
            b"/lib64/ld-linux-x86-64.so.2\0".as_slice(),
            b"/lib/ld-linux-aarch64.so.1\0".as_slice(),
            b"/lib/ld-linux-armhf.so.3\0".as_slice(),
            b"/lib/ld-linux-riscv64-lp64d.so.1\0".as_slice(),
        ]
        .into_iter()
        .find_map(|linker| {
            bytes
                .windows(linker.len())
                .position(|candidate| candidate == linker)
                .map(|offset| (offset, linker))
        })
        .ok_or_else(|| invalid_state("/bin/true has no supported ELF interpreter"))?;
        let mut missing_linker = linker.to_vec();
        missing_linker[1] = b'z';
        bytes[linker_offset..linker_offset + linker.len()].copy_from_slice(&missing_linker);
        fs::write(path, bytes).context(IoSnafu { path })?;
        let mut permissions = fs::metadata(path).context(IoSnafu { path })?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).context(IoSnafu { path })
    }

    pub(crate) fn materialize_post_ponr_execfail(path: &Path) -> Result<()> {
        const PT_LOAD: u32 = 1;

        let source = Path::new("/bin/true");
        let mut bytes = fs::read(source).context(IoSnafu { path: source })?;
        ensure!(
            bytes.get(0..4) == Some(b"\x7fELF") && bytes.get(5) == Some(&1),
            InvalidInputSnafu {
                path: source,
                reason: "the post-PONR fixture requires a little-endian ELF",
            }
        );
        let (program_offset, entry_size, entry_count, filesz_offset, memsz_offset) =
            match bytes.get(4).copied() {
                Some(2) => (
                    read_u64_le(&bytes, 32, "ELF64 program-header offset")? as usize,
                    read_u16(&bytes, 54, "ELF64 program-header size")? as usize,
                    read_u16(&bytes, 56, "ELF64 program-header count")? as usize,
                    32,
                    40,
                ),
                Some(1) => (
                    read_u32(&bytes, 28, "ELF32 program-header offset")? as usize,
                    read_u16(&bytes, 42, "ELF32 program-header size")? as usize,
                    read_u16(&bytes, 44, "ELF32 program-header count")? as usize,
                    16,
                    20,
                ),
                class => {
                    return Err(invalid_state(format!(
                        "unsupported ELF class {class:?} for the post-PONR fixture"
                    )))
                }
            };
        let field_size = if bytes[4] == 2 { 8 } else { 4 };
        let mut patched = false;
        for index in 0..entry_count {
            let offset = program_offset
                .checked_add(index.saturating_mul(entry_size))
                .ok_or_else(|| invalid_state("ELF program-header offset overflowed"))?;
            if read_u32(&bytes, offset, "ELF program-header type")? != PT_LOAD {
                continue;
            }
            let filesz = read_uint(
                &bytes,
                offset + filesz_offset,
                field_size,
                "ELF PT_LOAD file size",
            )?;
            ensure!(
                filesz > 0,
                InvalidInputSnafu {
                    path: source,
                    reason: "the first ELF PT_LOAD segment has no file bytes",
                }
            );
            write_uint(
                &mut bytes,
                offset + memsz_offset,
                field_size,
                filesz - 1,
                "ELF PT_LOAD memory size",
            )?;
            patched = true;
            break;
        }
        ensure!(
            patched,
            InvalidInputSnafu {
                path: source,
                reason: "the source ELF has no PT_LOAD segment",
            }
        );
        fs::write(path, bytes).context(IoSnafu { path })?;
        let mut permissions = fs::metadata(path).context(IoSnafu { path })?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).context(IoSnafu { path })
    }

    fn wait_for<T, F>(&self, description: &str, path: &Path, inspect: F) -> Result<T>
    where
        F: FnMut() -> Result<Option<T>>,
    {
        self.wait_for_with_limit(description, path, WAIT_LIMIT, inspect)
    }

    fn wait_for_with_limit<T, F>(
        &self,
        description: &str,
        path: &Path,
        limit: Duration,
        mut inspect: F,
    ) -> Result<T>
    where
        F: FnMut() -> Result<Option<T>>,
    {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(value) = inspect()? {
                return Ok(value);
            }
            ensure!(
                Instant::now() < deadline,
                InvalidInputSnafu {
                    path,
                    reason: format!("timed out waiting for {description}"),
                }
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn physical_kubernetes_exec_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        const ENTRY_COMMAND: &str = "read identity_pid _ < /proc/self/stat; printf \"%s\\n\" \"$identity_pid\" > /var/lib/mithril/entry/pid; while [ ! -f /var/lib/mithril/entry/release ]; do sleep 0.1; done";
        const COPY_PAYLOAD: &[u8] = b"mithril kubectl copy fixture\n";
        const COPY_WRAPPER: &str = "#!/bin/sh\nread identity_pid _ < /proc/self/stat\nprintf '%s\\n' \"$identity_pid\" > /var/lib/mithril/entry/copy-pid\nwhile [ ! -f /var/lib/mithril/entry/copy-release ]; do sleep 0.1; done\nexec /bin/tar \"$@\"\n";
        const NATIVE_PARENT_COMMAND: &str = "/bin/sh -c \"$1\" & wait \"$!\"";

        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-entry");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes identity fixture directory must not already exist",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-{}", std::process::id());
        let fixture_root = work_directory.join("fixture");
        let marker_path = fixture_root.join("pid");
        let release_path = fixture_root.join("release");
        let copy_marker_path = fixture_root.join("copy-pid");
        let copy_release_path = fixture_root.join("copy-release");
        let copy_source_path = fixture_root.join("copy-source");
        let copy_destination_path = work_directory.join("copy-result");
        let copy_wrapper_path = fixture_root.join("tar");
        let manifest_path = work_directory.join("workload.yaml");
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes identity pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut host = None;
        let mut direct_cri_exec = None;
        let mut kubectl_exec = None;
        let mut kubectl_tty_exec = None;
        let mut kubectl_copy = None;
        let mut native_child_exec = None;

        let probe = (|| -> Result<_> {
            fs::create_dir(&fixture_root).context(IoSnafu {
                path: &fixture_root,
            })?;
            fs::write(&copy_source_path, COPY_PAYLOAD).context(IoSnafu {
                path: &copy_source_path,
            })?;
            fs::write(&copy_wrapper_path, COPY_WRAPPER).context(IoSnafu {
                path: &copy_wrapper_path,
            })?;
            let mut copy_wrapper_permissions = fs::metadata(&copy_wrapper_path)
                .context(IoSnafu {
                    path: &copy_wrapper_path,
                })?
                .permissions();
            copy_wrapper_permissions.set_mode(0o700);
            fs::set_permissions(&copy_wrapper_path, copy_wrapper_permissions).context(IoSnafu {
                path: &copy_wrapper_path,
            })?;
            let manifest_template_path = self
                .repo_root
                .join("crates/mithril-e2e/fixtures/identity/kubernetes-entry-workload-v1.yaml");
            let manifest = fs::read_to_string(&manifest_template_path)
                .context(IoSnafu {
                    path: &manifest_template_path,
                })?
                .replace("MITHRIL_IDENTITY_NAMESPACE", &namespace)
                .replace(
                    "MITHRIL_IDENTITY_FIXTURE_ROOT",
                    fixture_root.to_string_lossy().as_ref(),
                );
            ensure!(
                manifest.contains(ENTRY_COMMAND),
                InvalidInputSnafu {
                    path: &manifest_template_path,
                    reason:
                        "the Kubernetes startup command differs from the direct CRI fixture command",
                }
            );
            fs::write(&manifest_path, manifest).context(IoSnafu {
                path: &manifest_path,
            })?;

            self.kubernetes_output(
                &["kubectl", "create", "namespace", namespace.as_str()],
                "create Kubernetes fixture namespace",
            )?;
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create Kubernetes identity fixture Pod",
            )?;
            let container_ref =
                self.wait_for("Kubernetes identity fixture root", &manifest_path, || {
                    let container_ref = self.kubernetes_output(
                        &[
                            "kubectl",
                            "-n",
                            namespace.as_str(),
                            "get",
                            "pod",
                            "mithril-identity",
                            "-o",
                            "jsonpath={.status.containerStatuses[0].containerID}",
                        ],
                        "read the Kubernetes fixture container ID",
                    )?;
                    Ok((!container_ref.trim().is_empty()).then_some(container_ref))
                })?;
            let container_id = container_ref
                .trim()
                .strip_prefix("containerd://")
                .ok_or_else(|| {
                    invalid_state("Kubernetes did not return a containerd container ID")
                })?
                .to_owned();
            let container_inspect = self.kubernetes_output(
                &["crictl", "inspect", container_id.as_str()],
                "inspect the Kubernetes fixture container",
            )?;
            let container_inspect: serde_json::Value = serde_json::from_str(&container_inspect)
                .context(JsonSnafu {
                    path: &manifest_path,
                })?;
            let initial_pid = container_inspect
                .pointer("/info/pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or_else(|| invalid_state("CRI did not return a live fixture root PID"))?;
            let image_digest = container_inspect
                .pointer("/status/imageRef")
                .and_then(serde_json::Value::as_str)
                .filter(|digest| digest.contains("sha256:"))
                .ok_or_else(|| invalid_state("CRI did not return the fixture image digest"))?
                .to_owned();
            let container_generation = container_inspect
                .pointer("/status/createdAt")
                .ok_or_else(|| invalid_state("CRI did not return the fixture container generation"))
                .and_then(|created_at| self.kubernetes_container_generation(created_at))?;
            let pod_uid = self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "get",
                    "pod",
                    "mithril-identity",
                    "-o",
                    "jsonpath={.metadata.uid}",
                ],
                "read the Kubernetes fixture Pod UID",
            )?;
            let pod_uid = pod_uid.trim().to_owned();
            ensure!(
                !pod_uid.is_empty(),
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "Kubernetes did not return the fixture Pod UID",
                }
            );
            let sandbox = self.kubernetes_output(
                &["crictl", "ps", "--id", container_id.as_str(), "-o", "json"],
                "read the Kubernetes fixture sandbox ID",
            )?;
            let sandbox: serde_json::Value = serde_json::from_str(&sandbox).context(JsonSnafu {
                path: &manifest_path,
            })?;
            let sandbox_id = sandbox
                .pointer("/containers/0/podSandboxId")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| invalid_state("CRI did not return the fixture sandbox ID"))?
                .to_owned();
            let probe_namespace_pid =
                self.wait_for("Kubernetes startup probe start", &marker_path, || {
                    self.kubernetes_fixture_pid(&marker_path)
                })?;
            let initial_cgroup = self.kubernetes_cgroup_for_pid(initial_pid)?;
            let probe_host_pid =
                self.wait_for("Kubernetes startup probe host PID", &initial_cgroup, || {
                    self.kubernetes_host_pid(&initial_cgroup, probe_namespace_pid)
                })?;
            ensure!(
                probe_host_pid != initial_pid,
                InvalidInputSnafu {
                    path: &initial_cgroup,
                    reason: "the Kubernetes startup probe did not create a separate task",
                }
            );
            fs::write(&release_path, b"release\\n").context(IoSnafu {
                path: &release_path,
            })?;
            self.wait_for("Kubernetes startup probe release", &marker_path, || {
                Ok(self
                    .kubernetes_host_pid(&initial_cgroup, probe_namespace_pid)?
                    .is_none()
                    .then_some(()))
            })?;
            fs::remove_file(&release_path).context(IoSnafu {
                path: &release_path,
            })?;
            fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;

            let (boot_id, node_boot_id) = boot_identity()?;
            let mut identity_host = KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                lease_path,
                Some(pin_root.to_path_buf()),
                boot_id,
                1,
            ))
            .start()
            .context(InterceptorSnafu)?;
            let mut binding = test_binding(&initial_cgroup);
            binding.container_id.clone_from(&container_id);
            binding.namespace.clone_from(&namespace);
            binding.pod_uid = pod_uid;
            binding.sandbox_id = sandbox_id;
            binding.container_name = "runtime".to_owned();
            binding.image_digest = image_digest;
            binding.container_generation = container_generation;
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            bindings
                .publish_all(&identity_host, std::slice::from_ref(&binding))
                .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate(&mut identity_host)
                .context(NodeSnafu)?;
            host = Some(identity_host);
            let inspector = NativeIdentityInspector::new(pin_root);
            let initial_root =
                self.wait_for("Kubernetes initial-root reconciliation", pin_root, || {
                    inspector.snapshot(initial_pid).context(NodeSnafu)
                })?;
            ensure!(
                initial_root.creator_task_cookie.is_none()
                    && initial_root.root_class.as_deref() == Some("restored_or_unknown_root")
                    && initial_root.installed_role_class.as_deref() == Some("fail_closed_unknown"),
                InvalidInputSnafu {
                    path: &pin_root,
                    reason: "the pre-existing Kubernetes Pod root was not reconciled fail closed",
                }
            );

            direct_cri_exec = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "crictl",
                        "exec",
                        container_id.as_str(),
                        "/bin/sh",
                        "-c",
                        ENTRY_COMMAND,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let direct_cri_namespace_pid =
                self.wait_for("direct CRI exec start", &marker_path, || {
                    self.kubernetes_fixture_pid(&marker_path)
                })?;
            let direct_cri_host_pid =
                self.wait_for("direct CRI exec host PID", &initial_cgroup, || {
                    self.kubernetes_host_pid(&initial_cgroup, direct_cri_namespace_pid)
                })?;
            let direct_cri_exec_root =
                self.wait_for("direct CRI exec identity", pin_root, || {
                    inspector.snapshot(direct_cri_host_pid).context(NodeSnafu)
                })?;
            ensure!(
                direct_cri_exec_root.creator_task_cookie.is_none()
                    && direct_cri_exec_root.root_class.as_deref() == Some("external_runtime_root")
                    && direct_cri_exec_root.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && direct_cri_exec_root.active_role_id == binding.external_role_id,
                InvalidInputSnafu {
                    path: &pin_root,
                    reason: "direct CRI exec did not remain a restricted external root",
                }
            );
            fs::write(&release_path, b"release\\n").context(IoSnafu {
                path: &release_path,
            })?;
            let direct_cri_status = direct_cri_exec
                .as_mut()
                .ok_or_else(|| invalid_state("direct CRI exec process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("direct CRI exec"),
                })?;
            ensure!(
                direct_cri_status.success(),
                InvalidInputSnafu {
                    path: Path::new("direct CRI exec"),
                    reason: format!("direct CRI exec exited with {direct_cri_status}"),
                }
            );
            direct_cri_exec = None;
            fs::remove_file(&release_path).context(IoSnafu {
                path: &release_path,
            })?;
            fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;

            kubectl_exec = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "exec",
                        "mithril-identity",
                        "-c",
                        "runtime",
                        "--",
                        "/bin/sh",
                        "-c",
                        ENTRY_COMMAND,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let kubectl_namespace_pid =
                self.wait_for("kubectl exec start", &marker_path, || {
                    self.kubernetes_fixture_pid(&marker_path)
                })?;
            let kubectl_host_pid =
                self.wait_for("kubectl exec host PID", &initial_cgroup, || {
                    self.kubernetes_host_pid(&initial_cgroup, kubectl_namespace_pid)
                })?;
            let kubectl_exec_root = self.wait_for("kubectl exec identity", pin_root, || {
                inspector.snapshot(kubectl_host_pid).context(NodeSnafu)
            })?;
            ensure!(
                kubectl_exec_root.creator_task_cookie.is_none()
                    && kubectl_exec_root.root_class.as_deref() == Some("external_runtime_root")
                    && kubectl_exec_root.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && kubectl_exec_root.active_role_id == binding.external_role_id
                    && kubectl_exec_root.task_cookie != direct_cri_exec_root.task_cookie,
                InvalidInputSnafu {
                    path: &pin_root,
                    reason: "kubectl exec did not remain a separate restricted external root",
                }
            );
            fs::write(&release_path, b"release\\n").context(IoSnafu {
                path: &release_path,
            })?;
            let kubectl_status = kubectl_exec
                .as_mut()
                .ok_or_else(|| invalid_state("kubectl exec process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("kubectl exec"),
                })?;
            ensure!(
                kubectl_status.success(),
                InvalidInputSnafu {
                    path: Path::new("kubectl exec"),
                    reason: format!("kubectl exec exited with {kubectl_status}"),
                }
            );
            kubectl_exec = None;
            fs::remove_file(&release_path).context(IoSnafu {
                path: &release_path,
            })?;
            fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;

            let tty_command = format!(
                "/usr/local/bin/k3s kubectl -n {namespace} exec -i -t mithril-identity -c runtime -- /bin/sh -c '{ENTRY_COMMAND}'"
            );
            kubectl_tty_exec = Some(
                Command::new("/usr/bin/script")
                    .args(["-qfec", tty_command.as_str(), "/dev/null"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/bin/script"),
                    })?,
            );
            let tty_namespace_pid =
                self.wait_for("TTY kubectl exec start", &marker_path, || {
                    self.kubernetes_fixture_pid(&marker_path)
                })?;
            let tty_host_pid =
                self.wait_for("TTY kubectl exec host PID", &initial_cgroup, || {
                    self.kubernetes_host_pid(&initial_cgroup, tty_namespace_pid)
                })?;
            let kubectl_tty_exec_root =
                self.wait_for("TTY kubectl exec identity", pin_root, || {
                    inspector.snapshot(tty_host_pid).context(NodeSnafu)
                })?;
            ensure!(
                kubectl_tty_exec_root.creator_task_cookie.is_none()
                    && kubectl_tty_exec_root.root_class.as_deref() == Some("external_runtime_root")
                    && kubectl_tty_exec_root.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && kubectl_tty_exec_root.active_role_id == binding.external_role_id
                    && kubectl_tty_exec_root.task_cookie != direct_cri_exec_root.task_cookie
                    && kubectl_tty_exec_root.task_cookie != kubectl_exec_root.task_cookie,
                InvalidInputSnafu {
                    path: &pin_root,
                    reason: "TTY kubectl exec did not remain a separate restricted external root",
                }
            );
            fs::write(&release_path, b"release\n").context(IoSnafu {
                path: &release_path,
            })?;
            let tty_status = kubectl_tty_exec
                .as_mut()
                .ok_or_else(|| invalid_state("TTY kubectl exec process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("TTY kubectl exec"),
                })?;
            ensure!(
                tty_status.success(),
                InvalidInputSnafu {
                    path: Path::new("TTY kubectl exec"),
                    reason: format!("TTY kubectl exec exited with {tty_status}"),
                }
            );
            kubectl_tty_exec = None;
            fs::remove_file(&release_path).context(IoSnafu {
                path: &release_path,
            })?;
            fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;

            let copy_source = format!(
                "mithril-identity:/var/lib/mithril/entry/{}",
                copy_source_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid_state("kubectl copy source name is invalid"))?
            );
            kubectl_copy = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "cp",
                        copy_source.as_str(),
                        copy_destination_path.to_string_lossy().as_ref(),
                        "-c",
                        "runtime",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let copy_namespace_pid =
                self.wait_for("kubectl cp start", &copy_marker_path, || {
                    self.kubernetes_fixture_pid(&copy_marker_path)
                })?;
            let copy_host_pid = self.wait_for("kubectl cp host PID", &initial_cgroup, || {
                self.kubernetes_host_pid(&initial_cgroup, copy_namespace_pid)
            })?;
            let kubectl_copy_root = self.wait_for("kubectl cp identity", pin_root, || {
                inspector.snapshot(copy_host_pid).context(NodeSnafu)
            })?;
            ensure!(
                kubectl_copy_root.creator_task_cookie.is_none()
                    && kubectl_copy_root.root_class.as_deref() == Some("external_runtime_root")
                    && kubectl_copy_root.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && kubectl_copy_root.active_role_id == binding.external_role_id
                    && kubectl_copy_root.task_cookie != direct_cri_exec_root.task_cookie
                    && kubectl_copy_root.task_cookie != kubectl_exec_root.task_cookie
                    && kubectl_copy_root.task_cookie != kubectl_tty_exec_root.task_cookie,
                InvalidInputSnafu {
                    path: &pin_root,
                    reason: "kubectl cp did not remain a separate restricted external root",
                }
            );
            fs::write(&copy_release_path, b"release\n").context(IoSnafu {
                path: &copy_release_path,
            })?;
            let copy_status = kubectl_copy
                .as_mut()
                .ok_or_else(|| invalid_state("kubectl cp process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("kubectl cp"),
                })?;
            ensure!(
                copy_status.success(),
                InvalidInputSnafu {
                    path: Path::new("kubectl cp"),
                    reason: format!("kubectl cp exited with {copy_status}"),
                }
            );
            kubectl_copy = None;
            let copied = fs::read(&copy_destination_path).context(IoSnafu {
                path: &copy_destination_path,
            })?;
            ensure!(
                copied == COPY_PAYLOAD,
                InvalidInputSnafu {
                    path: &copy_destination_path,
                    reason: "kubectl cp did not copy the exact fixture bytes",
                }
            );
            fs::remove_file(&copy_release_path).context(IoSnafu {
                path: &copy_release_path,
            })?;
            fs::remove_file(&copy_marker_path).context(IoSnafu {
                path: &copy_marker_path,
            })?;

            native_child_exec = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "crictl",
                        "exec",
                        container_id.as_str(),
                        "/bin/sh",
                        "-c",
                        NATIVE_PARENT_COMMAND,
                        "mithril-native-parent",
                        ENTRY_COMMAND,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let native_child_namespace_pid =
                self.wait_for("native-child control start", &marker_path, || {
                    self.kubernetes_fixture_pid(&marker_path)
                })?;
            let native_child_host_pid =
                self.wait_for("native-child control host PID", &initial_cgroup, || {
                    self.kubernetes_host_pid(&initial_cgroup, native_child_namespace_pid)
                })?;
            let native_parent_host_pid = self.host_parent_pid(native_child_host_pid)?;
            let native_child_parent =
                self.wait_for("native-child parent identity", pin_root, || {
                    inspector
                        .snapshot(native_parent_host_pid)
                        .context(NodeSnafu)
                })?;
            let native_child_control =
                self.wait_for("native-child control identity", pin_root, || {
                    inspector.snapshot(native_child_host_pid).context(NodeSnafu)
                })?;
            ensure!(
                native_child_parent.creator_task_cookie.is_none()
                    && native_child_parent.root_class.as_deref() == Some("external_runtime_root")
                    && native_child_parent.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && native_child_parent.active_role_id == binding.external_role_id
                    && native_child_control.creator_task_cookie
                        == Some(native_child_parent.task_cookie)
                    && native_child_control.real_parent_task_cookie
                        == native_child_parent.task_cookie
                    && native_child_control.root_class.is_none()
                    && native_child_control.installed_role_class.is_none()
                    && native_child_control.active_role_id == native_child_parent.active_role_id,
                InvalidInputSnafu {
                    path: &pin_root,
                    reason:
                        "the identical native child did not keep native lineage and its parent role",
                }
            );
            fs::write(&release_path, b"release\n").context(IoSnafu {
                path: &release_path,
            })?;
            let native_status = native_child_exec
                .as_mut()
                .ok_or_else(|| invalid_state("native-child control process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("native-child control"),
                })?;
            ensure!(
                native_status.success(),
                InvalidInputSnafu {
                    path: Path::new("native-child control"),
                    reason: format!("native-child control exited with {native_status}"),
                }
            );
            native_child_exec = None;
            fs::remove_file(&release_path).context(IoSnafu {
                path: &release_path,
            })?;
            fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;

            Ok((
                initial_root,
                direct_cri_exec_root,
                kubectl_exec_root,
                kubectl_tty_exec_root,
                kubectl_copy_root,
                native_child_parent,
                native_child_control,
            ))
        })();

        Self::stop_fixture_process(&mut direct_cri_exec);
        Self::stop_fixture_process(&mut kubectl_exec);
        Self::stop_fixture_process(&mut kubectl_tty_exec);
        Self::stop_fixture_process(&mut kubectl_copy);
        Self::stop_fixture_process(&mut native_child_exec);
        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes identity fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let pin_cleanup = pin_cleanup.cleanup();
        let lease_cleanup = lease_cleanup.cleanup();
        let cleanup = work_cleanup.cleanup();
        let cleanup_result = host_cleanup
            .and(namespace_cleanup)
            .and(pin_cleanup)
            .and(lease_cleanup)
            .and(cleanup);
        if let Err(source) = probe {
            cleanup_result?;
            return Err(source);
        }
        cleanup_result?;
        let namespace_removed =
            !namespace_created || self.kubernetes_namespace_absent(&namespace)?;
        let pin_removed = !pin_root.exists() && !lease_path.exists();
        ensure!(
            namespace_removed && pin_removed && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes identity fixture left a namespace, Mithril pin, lease, or fixture directory",
            }
        );
        let (
            initial_root,
            direct_cri_exec_root,
            kubectl_exec_root,
            kubectl_tty_exec_root,
            kubectl_copy_root,
            native_child_parent,
            native_child_control,
        ) = probe?;
        bundle.kubernetes_initial_root = Some(initial_root);
        bundle.kubernetes_direct_cri_exec_root = Some(direct_cri_exec_root);
        bundle.kubernetes_kubectl_exec_root = Some(kubectl_exec_root);
        bundle.kubernetes_kubectl_tty_exec_root = Some(kubectl_tty_exec_root);
        bundle.kubernetes_kubectl_copy_root = Some(kubectl_copy_root);
        bundle.kubernetes_native_child_parent = Some(native_child_parent);
        bundle.kubernetes_native_child_control = Some(native_child_control);
        Ok(())
    }

    fn physical_kubernetes_lifecycle_sleep_probe(&self, output_directory: &Path) -> Result<bool> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-lifecycle-sleep");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes lifecycle-sleep fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-sleep-{}", std::process::id());
        let manifest_path = work_directory.join("workload.yaml");
        let template_path = self.repo_root.join(
            "crates/mithril-e2e/fixtures/identity/kubernetes-lifecycle-sleep-workload-v1.yaml",
        );
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest.replace("MITHRIL_IDENTITY_SLEEP_NAMESPACE", &namespace),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        let mut namespace_created = false;

        let probe = (|| -> Result<bool> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes lifecycle-sleep fixture",
            )?;

            let container_id = self.wait_for(
                "Kubernetes lifecycle-sleep container start",
                &manifest_path,
                || {
                    let inventory = self.kubernetes_output(
                        &["crictl", "ps", "-o", "json"],
                        "read the lifecycle-sleep CRI inventory",
                    )?;
                    let inventory: serde_json::Value =
                        serde_json::from_str(&inventory).context(JsonSnafu {
                            path: &manifest_path,
                        })?;
                    Ok(inventory
                        .get("containers")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|containers| {
                            containers.iter().find_map(|container| {
                                let matching_namespace = container
                                    .pointer("/labels/io.kubernetes.pod.namespace")
                                    .and_then(serde_json::Value::as_str)
                                    == Some(namespace.as_str());
                                let matching_name = container
                                    .pointer("/metadata/name")
                                    .and_then(serde_json::Value::as_str)
                                    == Some("runtime");
                                (matching_namespace && matching_name)
                                    .then(|| {
                                        container
                                            .get("id")
                                            .and_then(serde_json::Value::as_str)
                                            .map(str::to_owned)
                                    })
                                    .flatten()
                            })
                        }))
                },
            )?;
            let container = self.kubernetes_output(
                &["crictl", "inspect", container_id.as_str()],
                "inspect the lifecycle-sleep container",
            )?;
            let container: serde_json::Value =
                serde_json::from_str(&container).context(JsonSnafu {
                    path: &manifest_path,
                })?;
            let init_pid = container
                .pointer("/info/pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or_else(|| invalid_state("lifecycle-sleep CRI PID is invalid"))?;
            let cgroup = self.kubernetes_cgroup_for_pid(init_pid)?;
            let procs_path = cgroup.join("cgroup.procs");
            let tasks = fs::read_to_string(&procs_path)
                .context(IoSnafu { path: &procs_path })?
                .split_ascii_whitespace()
                .map(|pid| {
                    pid.parse::<u32>().map_err(|source| {
                        invalid_state(format!(
                            "lifecycle-sleep cgroup has invalid PID `{pid}`: {source}"
                        ))
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                tasks.len() == 1 && tasks.contains(&init_pid),
                InvalidInputSnafu {
                    path: &procs_path,
                    reason: format!(
                        "Kubernetes lifecycle sleep created an in-container task: {tasks:?}"
                    ),
                }
            );

            let pod = self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "get",
                    "pod",
                    "mithril-sleep",
                    "-o",
                    "json",
                ],
                "read the lifecycle-sleep Pod",
            )?;
            let pod: serde_json::Value = serde_json::from_str(&pod).context(JsonSnafu {
                path: &manifest_path,
            })?;
            let ready = pod
                .pointer("/status/conditions")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                            && condition.get("status").and_then(serde_json::Value::as_str)
                                == Some("True")
                    })
                });
            ensure!(
                !ready,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the lifecycle sleep completed before the no-task observation",
                }
            );
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-sleep",
                    "--timeout=120s",
                ],
                "wait for the Kubernetes lifecycle sleep to complete",
            )?;
            Ok(true)
        })();

        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes lifecycle-sleep fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup.and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)? && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes lifecycle-sleep fixture was not removed",
            }
        );
        probe
    }

    fn physical_kubernetes_containers_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-containers");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes containers fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let fixture_root = work_directory.join("fixture");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let namespace = format!("mithril-identity-containers-{}", std::process::id());
        let manifest_path = work_directory.join("workload.yaml");
        let template_path = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/identity/kubernetes-containers-workload-v1.yaml");
        let manifest = fs::read_to_string(&template_path)
            .context(IoSnafu {
                path: &template_path,
            })?
            .replace("MITHRIL_IDENTITY_CONTAINERS_NAMESPACE", &namespace)
            .replace(
                "MITHRIL_IDENTITY_CONTAINERS_FIXTURE_ROOT",
                fixture_root.to_string_lossy().as_ref(),
            );
        fs::write(&manifest_path, manifest).context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes containers pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut host = None;

        let probe = (|| -> Result<_> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes containers fixture",
            )?;

            let (init_binding, init_pid, init_sandbox) = self.kubernetes_container_binding(
                &namespace,
                "mithril-containers",
                "init",
                (
                    mithril_node::ContainerKindV1::Init,
                    "11111111-1111-4111-8111-111111111101",
                    "22222222-2222-4222-8222-222222222201",
                    "4cd90188-e814-45ec-899f-4e3c9bca3803",
                    PROFILE_GENERATION_REF_ID,
                ),
                &manifest_path,
            )?;
            let (sidecar_binding, sidecar_pid, sidecar_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-containers",
                    "sidecar",
                    (
                        mithril_node::ContainerKindV1::Sidecar,
                        "11111111-1111-4111-8111-111111111102",
                        "22222222-2222-4222-8222-222222222202",
                        "4cd90188-e814-45ec-899f-4e3c9bca3803",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            ensure!(
                init_sandbox == sidecar_sandbox
                    && init_binding.root_cgroup_path != sidecar_binding.root_cgroup_path,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the init and native sidecar did not share one Pod sandbox with separate cgroups",
                }
            );

            let (boot_id, node_boot_id) = boot_identity()?;
            let mut identity_host = KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                lease_path,
                Some(pin_root.to_path_buf()),
                boot_id,
                1,
            ))
            .start()
            .context(InterceptorSnafu)?;
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            bindings
                .publish_all(
                    &identity_host,
                    &[init_binding.clone(), sidecar_binding.clone()],
                )
                .context(NodeSnafu)?;
            let native = NativeSecurityStateOwner::new(node_boot_id, 1);
            native.activate(&mut identity_host).context(NodeSnafu)?;
            host = Some(identity_host);
            let inspector = NativeIdentityInspector::new(pin_root);
            let init_root =
                self.wait_for("Kubernetes init-container identity", pin_root, || {
                    inspector.snapshot(init_pid).context(NodeSnafu)
                })?;
            let sidecar_before =
                self.wait_for("Kubernetes native-sidecar identity", pin_root, || {
                    inspector.snapshot(sidecar_pid).context(NodeSnafu)
                })?;
            ensure!(
                init_root.creator_task_cookie.is_none()
                    && init_root.root_class.as_deref() == Some("restored_or_unknown_root")
                    && init_root.installed_role_class.as_deref() == Some("fail_closed_unknown")
                    && sidecar_before.creator_task_cookie.is_none()
                    && sidecar_before.root_class.as_deref()
                        == Some("restored_or_unknown_root")
                    && sidecar_before.installed_role_class.as_deref()
                        == Some("fail_closed_unknown")
                    && init_root.task_cookie != sidecar_before.task_cookie
                    && init_root.process_state_id != sidecar_before.process_state_id
                    && init_root.execution_set_id.is_some()
                    && sidecar_before.execution_set_id.is_some()
                    && init_root.execution_set_id != sidecar_before.execution_set_id,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the init and native sidecar did not have independent conservative roots and execution sets",
                }
            );

            fs::write(fixture_root.join("release-init"), b"release\n").context(IoSnafu {
                path: fixture_root.join("release-init"),
            })?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-containers",
                    "--timeout=180s",
                ],
                "wait for the Kubernetes application container",
            )?;

            let (application_binding, application_pid, application_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-containers",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111103",
                        "22222222-2222-4222-8222-222222222203",
                        "4cd90188-e814-45ec-899f-4e3c9bca3803",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            ensure!(
                application_sandbox == init_sandbox
                    && application_binding.root_cgroup_path != sidecar_binding.root_cgroup_path
                    && application_binding.root_cgroup_path != init_binding.root_cgroup_path,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the application did not share the Pod sandbox with its own cgroup",
                }
            );
            let identity_host = host.as_mut().ok_or_else(|| {
                invalid_state("the Kubernetes containers identity host is missing")
            })?;
            bindings
                .publish_all(identity_host, std::slice::from_ref(&application_binding))
                .context(NodeSnafu)?;
            native.activate(identity_host).context(NodeSnafu)?;
            let sidecar_root = self.wait_for(
                "stable Kubernetes native-sidecar identity",
                pin_root,
                || inspector.snapshot(sidecar_pid).context(NodeSnafu),
            )?;
            let application_root = self.wait_for(
                "Kubernetes application-container identity",
                pin_root,
                || inspector.snapshot(application_pid).context(NodeSnafu),
            )?;
            let distinct_execution_sets = init_root.execution_set_id.is_some()
                && sidecar_root.execution_set_id.is_some()
                && application_root.execution_set_id.is_some()
                && init_root.execution_set_id != sidecar_root.execution_set_id
                && init_root.execution_set_id != application_root.execution_set_id
                && sidecar_root.execution_set_id != application_root.execution_set_id;
            ensure!(
                sidecar_root == sidecar_before
                    && application_root.creator_task_cookie.is_none()
                    && application_root.root_class.as_deref()
                        == Some("restored_or_unknown_root")
                    && application_root.installed_role_class.as_deref()
                        == Some("fail_closed_unknown")
                    && init_root.task_cookie != application_root.task_cookie
                    && sidecar_root.task_cookie != application_root.task_cookie
                    && init_root.process_state_id != application_root.process_state_id
                    && sidecar_root.process_state_id != application_root.process_state_id
                    && distinct_execution_sets,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the init, native sidecar, and application did not keep independent roots and execution sets",
                }
            );
            Ok((
                init_root,
                sidecar_root,
                application_root,
                distinct_execution_sets,
            ))
        })();

        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes containers fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = host_cleanup
            .and(namespace_cleanup)
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes containers fixture was not removed",
            }
        );
        let (init_root, sidecar_root, application_root, distinct_execution_sets) = probe?;
        bundle.kubernetes_init_container_root = Some(init_root);
        bundle.kubernetes_sidecar_container_root = Some(sidecar_root);
        bundle.kubernetes_application_container_root = Some(application_root);
        bundle.kubernetes_containers_distinct_execution_sets = Some(distinct_execution_sets);
        Ok(())
    }

    fn physical_kubernetes_ephemeral_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        const EPHEMERAL_PATCH: &str = r#"{"spec":{"ephemeralContainers":[{"name":"debugger","image":"docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662","imagePullPolicy":"IfNotPresent","targetContainerName":"application","command":["/bin/sh","-c","exec sleep 3600"],"stdin":false,"tty":false}]}}"#;

        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-ephemeral");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes ephemeral fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-ephemeral-{}", std::process::id());
        let manifest_path = work_directory.join("workload.yaml");
        let template_path = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/identity/kubernetes-ephemeral-workload-v1.yaml");
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest.replace("MITHRIL_IDENTITY_EPHEMERAL_NAMESPACE", &namespace),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes ephemeral pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut host = None;

        let probe = (|| -> Result<_> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes ephemeral fixture",
            )?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-ephemeral",
                    "--timeout=180s",
                ],
                "wait for the Kubernetes ephemeral target",
            )?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "patch",
                    "pod",
                    "mithril-ephemeral",
                    "--subresource=ephemeralcontainers",
                    "--type=merge",
                    "-p",
                    EPHEMERAL_PATCH,
                ],
                "add the Kubernetes ephemeral container",
            )?;

            let (target_binding, target_pid, target_sandbox) = self.kubernetes_container_binding(
                &namespace,
                "mithril-ephemeral",
                "application",
                (
                    mithril_node::ContainerKindV1::Application,
                    "11111111-1111-4111-8111-111111111201",
                    "22222222-2222-4222-8222-222222222301",
                    "33333333-3333-4333-8333-333333333301",
                    PROFILE_GENERATION_REF_ID,
                ),
                &manifest_path,
            )?;
            let (ephemeral_binding, ephemeral_pid, ephemeral_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-ephemeral",
                    "debugger",
                    (
                        mithril_node::ContainerKindV1::Ephemeral,
                        "11111111-1111-4111-8111-111111111202",
                        "22222222-2222-4222-8222-222222222302",
                        "33333333-3333-4333-8333-333333333302",
                        PROFILE_GENERATION_REF_ID + 1,
                    ),
                    &manifest_path,
                )?;
            let target_pid_namespace = fs::metadata(format!("/proc/{target_pid}/ns/pid"))
                .context(IoSnafu {
                    path: PathBuf::from(format!("/proc/{target_pid}/ns/pid")),
                })?
                .ino();
            let ephemeral_pid_namespace = fs::metadata(format!("/proc/{ephemeral_pid}/ns/pid"))
                .context(IoSnafu {
                    path: PathBuf::from(format!("/proc/{ephemeral_pid}/ns/pid")),
                })?
                .ino();
            let shared_pid_namespace =
                target_pid_namespace != 0 && target_pid_namespace == ephemeral_pid_namespace;
            ensure!(
                target_sandbox == ephemeral_sandbox
                    && target_binding.root_cgroup_path != ephemeral_binding.root_cgroup_path
                    && shared_pid_namespace,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the ephemeral container did not target the application PID namespace from a separate container cgroup",
                }
            );

            let pod = self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "get",
                    "pod",
                    "mithril-ephemeral",
                    "-o",
                    "json",
                ],
                "read the Kubernetes ephemeral fixture Pod",
            )?;
            let pod: serde_json::Value = serde_json::from_str(&pod).context(JsonSnafu {
                path: &manifest_path,
            })?;
            let target_recorded = pod
                .pointer("/spec/ephemeralContainers")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|containers| {
                    containers.iter().any(|container| {
                        container.get("name").and_then(serde_json::Value::as_str)
                            == Some("debugger")
                            && container
                                .get("targetContainerName")
                                .and_then(serde_json::Value::as_str)
                                == Some("application")
                    })
                });
            ensure!(
                target_recorded,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "Kubernetes did not retain the exact ephemeral target",
                }
            );

            let (boot_id, node_boot_id) = boot_identity()?;
            let mut identity_host = KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                lease_path,
                Some(pin_root.to_path_buf()),
                boot_id,
                1,
            ))
            .start()
            .context(InterceptorSnafu)?;
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            bindings
                .publish_all(
                    &identity_host,
                    &[target_binding.clone(), ephemeral_binding.clone()],
                )
                .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate(&mut identity_host)
                .context(NodeSnafu)?;
            host = Some(identity_host);
            let inspector = NativeIdentityInspector::new(pin_root);
            let target_root =
                self.wait_for("Kubernetes ephemeral target identity", pin_root, || {
                    inspector.snapshot(target_pid).context(NodeSnafu)
                })?;
            let ephemeral_root =
                self.wait_for("Kubernetes ephemeral-container identity", pin_root, || {
                    inspector.snapshot(ephemeral_pid).context(NodeSnafu)
                })?;
            let distinct_execution_set_and_profile = target_root.execution_set_id.is_some()
                && ephemeral_root.execution_set_id.is_some()
                && target_root.execution_set_id != ephemeral_root.execution_set_id
                && target_root.profile_generation_ref_id
                    != ephemeral_root.profile_generation_ref_id;
            ensure!(
                target_root.creator_task_cookie.is_none()
                    && target_root.root_class.as_deref() == Some("restored_or_unknown_root")
                    && target_root.installed_role_class.as_deref() == Some("fail_closed_unknown")
                    && ephemeral_root.creator_task_cookie.is_none()
                    && ephemeral_root.root_class.as_deref() == Some("restored_or_unknown_root")
                    && ephemeral_root.installed_role_class.as_deref()
                        == Some("fail_closed_unknown")
                    && target_root.task_cookie != ephemeral_root.task_cookie
                    && target_root.process_state_id != ephemeral_root.process_state_id
                    && distinct_execution_set_and_profile,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the ephemeral container merged with the application identity tree",
                }
            );
            Ok((
                target_root,
                ephemeral_root,
                shared_pid_namespace,
                distinct_execution_set_and_profile,
            ))
        })();

        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes ephemeral fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = host_cleanup
            .and(namespace_cleanup)
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes ephemeral fixture was not removed",
            }
        );
        let (target_root, ephemeral_root, shared_pid_namespace, distinct_execution_set_and_profile) =
            probe?;
        bundle.kubernetes_ephemeral_target_root = Some(target_root);
        bundle.kubernetes_ephemeral_container_root = Some(ephemeral_root);
        bundle.kubernetes_ephemeral_shared_pid_namespace = Some(shared_pid_namespace);
        bundle.kubernetes_ephemeral_distinct_execution_set_and_profile =
            Some(distinct_execution_set_and_profile);
        Ok(())
    }

    fn physical_kubernetes_probe_impersonation(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        const PROBE_COMMAND: &str = "read identity_pid _ < /proc/self/stat; directory=/var/lib/mithril/probe; marker=\"$directory/$MITHRIL_PROBE_SLOT-$identity_pid.pid\"; fifo=\"$directory/$MITHRIL_PROBE_SLOT-release-$identity_pid\"; printf \"%s\\n\" \"$identity_pid\" > \"$marker\"; mkfifo \"$fifo\"; read -r identity_release < \"$fifo\"; rm -f \"$fifo\"";

        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-probe-impersonation");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes probe-impersonation fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-probes-{}", std::process::id());
        let fixture_root = work_directory.join("fixture");
        let native_start_path = fixture_root.join("native-start");
        let manifest_path = work_directory.join("workload.yaml");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let mkfifo = Command::new("/usr/bin/mkfifo")
            .arg(&native_start_path)
            .output()
            .context(IoSnafu {
                path: Path::new("/usr/bin/mkfifo"),
            })?;
        ensure!(
            mkfifo.status.success(),
            InvalidInputSnafu {
                path: &native_start_path,
                reason: format!(
                    "cannot create the native-start FIFO: {}",
                    String::from_utf8_lossy(&mkfifo.stderr).trim()
                ),
            }
        );
        let template_path = self.repo_root.join(
            "crates/mithril-e2e/fixtures/identity/kubernetes-probe-impersonation-workload-v1.yaml",
        );
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        ensure!(
            manifest.matches(PROBE_COMMAND).count() == 4,
            InvalidInputSnafu {
                path: &template_path,
                reason:
                    "the stock probes and independent entries do not use identical command bytes",
            }
        );
        fs::write(
            &manifest_path,
            manifest
                .replace("MITHRIL_IDENTITY_PROBE_NAMESPACE", &namespace)
                .replace(
                    "MITHRIL_IDENTITY_PROBE_FIXTURE_ROOT",
                    fixture_root.to_string_lossy().as_ref(),
                ),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes probe pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut host = None;
        let mut kubectl_exec = None;
        let mut direct_cri_exec = None;

        let probe = (|| -> Result<_> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes probe-impersonation fixture",
            )?;

            let (startup_binding, _startup_pid, startup_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-probe-impersonation",
                    "startup",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111301",
                        "22222222-2222-4222-8222-222222222401",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let (readiness_binding, _readiness_pid, readiness_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-probe-impersonation",
                    "readiness",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111302",
                        "22222222-2222-4222-8222-222222222402",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let (liveness_binding, _liveness_pid, liveness_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-probe-impersonation",
                    "liveness",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111303",
                        "22222222-2222-4222-8222-222222222403",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let (application_binding, application_pid, application_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-probe-impersonation",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111304",
                        "22222222-2222-4222-8222-222222222404",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            ensure!(
                startup_sandbox == readiness_sandbox
                    && startup_sandbox == liveness_sandbox
                    && startup_sandbox == application_sandbox,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the probe containers do not share one Pod sandbox",
                }
            );
            let startup_cgroup = startup_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the startup probe binding has no cgroup"))?;
            let readiness_cgroup = readiness_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the readiness probe binding has no cgroup"))?;
            let liveness_cgroup = liveness_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the liveness probe binding has no cgroup"))?;
            let application_cgroup = application_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the probe application binding has no cgroup"))?;

            let (boot_id, node_boot_id) = boot_identity()?;
            let mut identity_host = KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                lease_path,
                Some(pin_root.to_path_buf()),
                boot_id,
                1,
            ))
            .start()
            .context(InterceptorSnafu)?;
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            bindings
                .publish_all(
                    &identity_host,
                    &[
                        startup_binding.clone(),
                        readiness_binding.clone(),
                        liveness_binding.clone(),
                        application_binding.clone(),
                    ],
                )
                .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate(&mut identity_host)
                .context(NodeSnafu)?;
            host = Some(identity_host);
            let inspector = NativeIdentityInspector::new(pin_root);
            let application_parent =
                self.wait_for("Kubernetes probe application root", pin_root, || {
                    inspector.snapshot(application_pid).context(NodeSnafu)
                })?;
            ensure!(
                application_parent.creator_task_cookie.is_none()
                    && application_parent.root_class.as_deref() == Some("restored_or_unknown_root")
                    && application_parent.installed_role_class.as_deref()
                        == Some("fail_closed_unknown"),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the probe application root was not reconciled conservatively",
                }
            );

            self.kubernetes_release_fifo(&native_start_path)?;
            let native_namespace_pid =
                self.wait_for("probe-identical native child", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "application")?
                        .into_iter()
                        .next())
                })?;
            let native_host_pid = self.wait_for(
                "probe-identical native child host PID",
                application_cgroup,
                || self.kubernetes_host_pid(application_cgroup, native_namespace_pid),
            )?;

            kubectl_exec = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "exec",
                        "mithril-probe-impersonation",
                        "-c",
                        "application",
                        "--",
                        "/bin/sh",
                        "-c",
                        PROBE_COMMAND,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let kubectl_namespace_pid =
                self.wait_for("probe-identical kubectl exec", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "application")?
                        .into_iter()
                        .find(|pid| *pid != native_namespace_pid))
                })?;
            let kubectl_host_pid = self.wait_for(
                "probe-identical kubectl exec host PID",
                application_cgroup,
                || self.kubernetes_host_pid(application_cgroup, kubectl_namespace_pid),
            )?;

            direct_cri_exec = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "crictl",
                        "exec",
                        application_binding.container_id.as_str(),
                        "/bin/sh",
                        "-c",
                        PROBE_COMMAND,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let direct_cri_namespace_pid =
                self.wait_for("probe-identical direct CRI exec", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "application")?
                        .into_iter()
                        .find(|pid| *pid != native_namespace_pid && *pid != kubectl_namespace_pid))
                })?;
            let direct_cri_host_pid = self.wait_for(
                "probe-identical direct CRI exec host PID",
                application_cgroup,
                || self.kubernetes_host_pid(application_cgroup, direct_cri_namespace_pid),
            )?;

            let startup_namespace_pid =
                self.wait_for("stock startup exec probe", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "startup")?
                        .into_iter()
                        .next())
                })?;
            let readiness_namespace_pid =
                self.wait_for("stock readiness exec probe", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "readiness")?
                        .into_iter()
                        .next())
                })?;
            let liveness_namespace_pid =
                self.wait_for("stock liveness exec probe", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "liveness")?
                        .into_iter()
                        .next())
                })?;
            let startup_host_pid =
                self.wait_for("stock startup exec probe host PID", startup_cgroup, || {
                    self.kubernetes_host_pid(startup_cgroup, startup_namespace_pid)
                })?;
            let readiness_host_pid = self.wait_for(
                "stock readiness exec probe host PID",
                readiness_cgroup,
                || self.kubernetes_host_pid(readiness_cgroup, readiness_namespace_pid),
            )?;
            let liveness_host_pid = self.wait_for(
                "stock liveness exec probe host PID",
                liveness_cgroup,
                || self.kubernetes_host_pid(liveness_cgroup, liveness_namespace_pid),
            )?;

            ensure!(
                kubectl_exec
                    .as_mut()
                    .ok_or_else(|| invalid_state("kubectl exec process is missing"))?
                    .try_wait()
                    .context(IoSnafu {
                        path: Path::new("probe-identical kubectl exec"),
                    })?
                    .is_none()
                    && direct_cri_exec
                        .as_mut()
                        .ok_or_else(|| invalid_state("direct CRI exec process is missing"))?
                        .try_wait()
                        .context(IoSnafu {
                            path: Path::new("probe-identical direct CRI exec"),
                        })?
                        .is_none(),
                InvalidInputSnafu {
                    path: &fixture_root,
                    reason: "the independent entries did not overlap the stock exec probes",
                }
            );

            let startup_root = self.wait_for("stock startup probe identity", pin_root, || {
                inspector.snapshot(startup_host_pid).context(NodeSnafu)
            })?;
            let readiness_root =
                self.wait_for("stock readiness probe identity", pin_root, || {
                    inspector.snapshot(readiness_host_pid).context(NodeSnafu)
                })?;
            let liveness_root = self.wait_for("stock liveness probe identity", pin_root, || {
                inspector.snapshot(liveness_host_pid).context(NodeSnafu)
            })?;
            let native_child =
                self.wait_for("probe-identical native identity", pin_root, || {
                    inspector.snapshot(native_host_pid).context(NodeSnafu)
                })?;
            let kubectl_root =
                self.wait_for("probe-identical kubectl identity", pin_root, || {
                    inspector.snapshot(kubectl_host_pid).context(NodeSnafu)
                })?;
            let direct_cri_root =
                self.wait_for("probe-identical direct CRI identity", pin_root, || {
                    inspector.snapshot(direct_cri_host_pid).context(NodeSnafu)
                })?;
            let external_roots = [
                &startup_root,
                &readiness_root,
                &liveness_root,
                &kubectl_root,
                &direct_cri_root,
            ];
            ensure!(
                external_roots.iter().all(|root| {
                    root.creator_task_cookie.is_none()
                        && root.root_class.as_deref() == Some("external_runtime_root")
                        && root.installed_role_class.as_deref()
                            == Some("runtime_external_restricted")
                        && root.active_role_id == application_binding.external_role_id
                }),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: format!(
                        "an independent identical-byte entry was not restricted: startup={:?}/{:?}/{}, readiness={:?}/{:?}/{}, liveness={:?}/{:?}/{}, kubectl={:?}/{:?}/{}, cri={:?}/{:?}/{}",
                        startup_root.root_class,
                        startup_root.installed_role_class,
                        startup_root.active_role_id,
                        readiness_root.root_class,
                        readiness_root.installed_role_class,
                        readiness_root.active_role_id,
                        liveness_root.root_class,
                        liveness_root.installed_role_class,
                        liveness_root.active_role_id,
                        kubectl_root.root_class,
                        kubectl_root.installed_role_class,
                        kubectl_root.active_role_id,
                        direct_cri_root.root_class,
                        direct_cri_root.installed_role_class,
                        direct_cri_root.active_role_id,
                    ),
                }
            );
            ensure!(
                native_child.creator_task_cookie == Some(application_parent.task_cookie)
                    && native_child.real_parent_task_cookie == application_parent.task_cookie
                    && native_child.root_class.is_none()
                    && native_child.installed_role_class.is_none()
                    && native_child.active_role_id == application_parent.active_role_id,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: format!(
                        "the identical native child lost application lineage: parent={}, creator={:?}, real_parent={}, root={:?}, role_class={:?}, role={}",
                        application_parent.task_cookie,
                        native_child.creator_task_cookie,
                        native_child.real_parent_task_cookie,
                        native_child.root_class,
                        native_child.installed_role_class,
                        native_child.active_role_id,
                    ),
                }
            );
            let snapshots = [
                &application_parent,
                &startup_root,
                &readiness_root,
                &liveness_root,
                &native_child,
                &kubectl_root,
                &direct_cri_root,
            ];
            let distinct_identities = snapshots
                .iter()
                .map(|snapshot| snapshot.task_cookie)
                .collect::<BTreeSet<_>>()
                .len()
                == snapshots.len()
                && snapshots
                    .iter()
                    .map(|snapshot| snapshot.process_state_id.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == snapshots.len();
            ensure!(
                distinct_identities,
                InvalidInputSnafu {
                    path: pin_root,
                    reason:
                        "concurrent probe and runtime entries reused a task or process identity",
                }
            );

            for (slot, namespace_pid) in [
                ("startup", startup_namespace_pid),
                ("readiness", readiness_namespace_pid),
                ("liveness", liveness_namespace_pid),
                ("application", native_namespace_pid),
                ("application", kubectl_namespace_pid),
                ("application", direct_cri_namespace_pid),
            ] {
                self.kubernetes_release_fifo(
                    &fixture_root.join(format!("{slot}-release-{namespace_pid}")),
                )?;
            }
            for (process, description) in [
                (&mut kubectl_exec, "probe-identical kubectl exec"),
                (&mut direct_cri_exec, "probe-identical direct CRI exec"),
            ] {
                let status = process
                    .as_mut()
                    .ok_or_else(|| invalid_state(format!("{description} process is missing")))?
                    .wait()
                    .context(IoSnafu {
                        path: Path::new(description),
                    })?;
                ensure!(
                    status.success(),
                    InvalidInputSnafu {
                        path: Path::new(description),
                        reason: format!("{description} exited with {status}"),
                    }
                );
                *process = None;
            }

            Ok((
                startup_root,
                readiness_root,
                liveness_root,
                application_parent,
                native_child,
                kubectl_root,
                direct_cri_root,
                distinct_identities,
            ))
        })();

        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes probe-impersonation fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        Self::stop_fixture_process(&mut kubectl_exec);
        Self::stop_fixture_process(&mut direct_cri_exec);
        let cleanup = host_cleanup
            .and(namespace_cleanup)
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes probe-impersonation fixture was not removed",
            }
        );
        let (
            startup_root,
            readiness_root,
            liveness_root,
            application_parent,
            native_child,
            kubectl_root,
            direct_cri_root,
            distinct_identities,
        ) = probe?;
        bundle.kubernetes_startup_exec_probe_root = Some(startup_root);
        bundle.kubernetes_readiness_exec_probe_root = Some(readiness_root);
        bundle.kubernetes_liveness_exec_probe_root = Some(liveness_root);
        bundle.kubernetes_probe_native_parent = Some(application_parent);
        bundle.kubernetes_probe_native_child = Some(native_child);
        bundle.kubernetes_probe_kubectl_exec_root = Some(kubectl_root);
        bundle.kubernetes_probe_direct_cri_exec_root = Some(direct_cri_root);
        bundle.kubernetes_probe_identities_distinct = Some(distinct_identities);
        Ok(())
    }

    fn physical_kubernetes_prestop_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-prestop");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes PreStop fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-prestop-{}", std::process::id());
        let fixture_root = work_directory.join("fixture");
        let manifest_path = work_directory.join("workload.yaml");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let template_path = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/identity/kubernetes-prestop-workload-v1.yaml");
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest
                .replace("MITHRIL_IDENTITY_PRESTOP_NAMESPACE", &namespace)
                .replace(
                    "MITHRIL_IDENTITY_PRESTOP_FIXTURE_ROOT",
                    fixture_root.to_string_lossy().as_ref(),
                ),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes PreStop pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut host = None;
        let mut pod_delete = None;
        let mut prestop_namespace_pid = None;

        let probe = (|| -> Result<_> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes PreStop fixture",
            )?;
            let (binding, application_pid, _) = self.kubernetes_container_binding(
                &namespace,
                "mithril-prestop",
                "application",
                (
                    mithril_node::ContainerKindV1::Application,
                    "11111111-1111-4111-8111-111111111401",
                    "22222222-2222-4222-8222-222222222501",
                    "33333333-3333-4333-8333-333333333333",
                    PROFILE_GENERATION_REF_ID,
                ),
                &manifest_path,
            )?;
            let application_cgroup = binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the PreStop application binding has no cgroup"))?;

            let (boot_id, node_boot_id) = boot_identity()?;
            let mut identity_host = KernelHostOwner::new(KernelHostConfig::identity(
                "/sys/kernel/btf/vmlinux",
                lease_path,
                Some(pin_root.to_path_buf()),
                boot_id,
                1,
            ))
            .start()
            .context(InterceptorSnafu)?;
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            bindings
                .publish_all(&identity_host, std::slice::from_ref(&binding))
                .context(NodeSnafu)?;
            NativeSecurityStateOwner::new(node_boot_id, 1)
                .activate(&mut identity_host)
                .context(NodeSnafu)?;
            host = Some(identity_host);
            let inspector = NativeIdentityInspector::new(pin_root);
            let application_before =
                self.wait_for("PreStop application identity", pin_root, || {
                    inspector.snapshot(application_pid).context(NodeSnafu)
                })?;
            ensure!(
                application_before.creator_task_cookie.is_none()
                    && application_before.root_class.as_deref() == Some("restored_or_unknown_root")
                    && application_before.installed_role_class.as_deref()
                        == Some("fail_closed_unknown")
                    && application_before.active_role_id == binding.external_role_id
                    && profile_task_refs(
                        host.as_ref()
                            .ok_or_else(|| invalid_state("the PreStop identity host is missing"))?,
                    )? == 1,
                InvalidInputSnafu {
                    path: pin_root,
                    reason:
                        "the PreStop application did not retain one conservative root reference",
                }
            );

            pod_delete = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "delete",
                        "pod",
                        "mithril-prestop",
                        "--wait=true",
                        "--timeout=90s",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let namespace_pid = self.wait_for("Kubernetes PreStop exec", &fixture_root, || {
                Ok(self
                    .kubernetes_fixture_slot_pids(&fixture_root, "prestop")?
                    .into_iter()
                    .next())
            })?;
            prestop_namespace_pid = Some(namespace_pid);
            let prestop_host_pid = self.wait_for(
                "Kubernetes PreStop exec host PID",
                application_cgroup,
                || self.kubernetes_host_pid(application_cgroup, namespace_pid),
            )?;
            ensure!(
                prestop_host_pid != application_pid,
                InvalidInputSnafu {
                    path: application_cgroup,
                    reason: "the Kubernetes PreStop hook did not create a separate task",
                }
            );
            let application_during =
                self.wait_for("application identity during PreStop", pin_root, || {
                    inspector.snapshot(application_pid).context(NodeSnafu)
                })?;
            let prestop_root = self.wait_for("PreStop exec identity", pin_root, || {
                inspector.snapshot(prestop_host_pid).context(NodeSnafu)
            })?;
            let refs_during = profile_task_refs(
                host.as_ref()
                    .ok_or_else(|| invalid_state("the PreStop identity host is missing"))?,
            )?;
            ensure!(
                application_during == application_before,
                InvalidInputSnafu {
                    path: pin_root,
                    reason:
                        "Pod termination changed the application identity before PreStop completed",
                }
            );
            ensure!(
                prestop_root.creator_task_cookie.is_none()
                    && prestop_root.root_class.as_deref() == Some("external_runtime_root")
                    && prestop_root.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && prestop_root.active_role_id == binding.external_role_id
                    && prestop_root.task_cookie != application_before.task_cookie
                    && prestop_root.process_state_id != application_before.process_state_id
                    && refs_during == 2,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: format!(
                        "PreStop did not retain the application reference and add one restricted external root: application {application_during:?}; PreStop {prestop_root:?}; profile references {refs_during}"
                    ),
                }
            );

            self.kubernetes_release_fifo(
                &fixture_root.join(format!("prestop-release-{namespace_pid}")),
            )?;
            let delete_status = pod_delete
                .as_mut()
                .ok_or_else(|| invalid_state("the Kubernetes Pod delete process is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("Kubernetes Pod delete"),
                })?;
            ensure!(
                delete_status.success(),
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: format!("Kubernetes Pod delete exited with {delete_status}"),
                }
            );
            pod_delete = None;
            let refs_after =
                self.wait_for("PreStop profile reference release", pin_root, || {
                    let refs =
                        profile_task_refs(host.as_ref().ok_or_else(|| {
                            invalid_state("the PreStop identity host is missing")
                        })?)?;
                    Ok((refs == 0).then_some(refs))
                })?;
            Ok((
                application_before,
                application_during,
                prestop_root,
                refs_during,
                refs_after,
            ))
        })();

        if let Some(namespace_pid) = prestop_namespace_pid {
            let release_path = fixture_root.join(format!("prestop-release-{namespace_pid}"));
            if release_path.exists() {
                let _ = self.kubernetes_release_fifo(&release_path);
            }
        }
        Self::stop_fixture_process(&mut pod_delete);
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes PreStop fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup
            .and(host_cleanup)
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes PreStop fixture was not removed",
            }
        );
        let (application_before, application_during, prestop_root, refs_during, refs_after) =
            probe?;
        bundle.kubernetes_prestop_application_before = Some(application_before);
        bundle.kubernetes_prestop_application_during = Some(application_during);
        bundle.kubernetes_prestop_exec_root = Some(prestop_root);
        bundle.kubernetes_prestop_profile_refs_during = Some(refs_during);
        bundle.kubernetes_prestop_profile_refs_after = Some(refs_after);
        Ok(())
    }

    fn physical_kubernetes_poststart_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-poststart");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes PostStart fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-poststart-{}", std::process::id());
        let fixture_root = work_directory.join("fixture");
        let manifest_path = work_directory.join("workload.yaml");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let template_path = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/identity/kubernetes-poststart-workload-v1.yaml");
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest
                .replace("MITHRIL_IDENTITY_POSTSTART_NAMESPACE", &namespace)
                .replace(
                    "MITHRIL_IDENTITY_POSTSTART_FIXTURE_ROOT",
                    fixture_root.to_string_lossy().as_ref(),
                ),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes PostStart pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let request_directory = Path::new(PRESTART_REQUEST_DIRECTORY);
        ensure!(
            !request_directory.exists(),
            InvalidInputSnafu {
                path: request_directory,
                reason: "the PostStart prestart request directory must not already exist",
            }
        );
        fs::create_dir(request_directory).context(IoSnafu {
            path: request_directory,
        })?;
        fs::set_permissions(request_directory, fs::Permissions::from_mode(0o700)).context(
            IoSnafu {
                path: request_directory,
            },
        )?;
        let request_cleanup = ProbeDirectory::new(request_directory);
        let mut namespace_created = false;
        let mut host = None;
        let mut repeated_poststart = None;

        let probe = (|| -> Result<_> {
            let (boot_id, node_boot_id) = boot_identity()?;
            host = Some(
                KernelHostOwner::new(KernelHostConfig::identity(
                    "/sys/kernel/btf/vmlinux",
                    lease_path,
                    Some(pin_root.to_path_buf()),
                    boot_id,
                    1,
                ))
                .start()
                .context(InterceptorSnafu)?,
            );
            let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes PostStart fixture",
            )?;
            let (entrypoint_first_binding, entrypoint_first_init_pid, entrypoint_first_request) =
                self.kubernetes_prestart_binding(
                    request_directory,
                    &namespace,
                    "mithril-poststart-entrypoint-first",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111501",
                        "22222222-2222-4222-8222-222222222601",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let (hook_first_binding, hook_first_init_pid, hook_first_request) = self
                .kubernetes_prestart_binding(
                    request_directory,
                    &namespace,
                    "mithril-poststart-hook-first",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111502",
                        "22222222-2222-4222-8222-222222222602",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let (repeat_binding, repeat_init_pid, repeat_request) = self
                .kubernetes_prestart_binding(
                    request_directory,
                    &namespace,
                    "mithril-poststart-repeat",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111503",
                        "22222222-2222-4222-8222-222222222603",
                        "33333333-3333-4333-8333-333333333333",
                        PROFILE_GENERATION_REF_ID,
                    ),
                    &manifest_path,
                )?;
            let held_initial_pids = [
                entrypoint_first_init_pid,
                hook_first_init_pid,
                repeat_init_pid,
            ];
            for pid in held_initial_pids {
                self.stop_host_pid(pid)?;
            }
            bindings
                .publish_held_initial_roots(
                    host.as_ref()
                        .ok_or_else(|| invalid_state("the PostStart identity host is missing"))?,
                    &[
                        (entrypoint_first_binding.clone(), entrypoint_first_init_pid),
                        (hook_first_binding.clone(), hook_first_init_pid),
                        (repeat_binding.clone(), repeat_init_pid),
                    ],
                )
                .context(NodeSnafu)?;
            let identity = NativeSecurityStateOwner::new(node_boot_id, 1);
            identity
                .activate_held_initial_admission(
                    host.as_mut()
                        .ok_or_else(|| invalid_state("the PostStart identity host is missing"))?,
                    false,
                )
                .context(NodeSnafu)?;
            let held_inspector = NativeIdentityInspector::new(pin_root);
            for pid in held_initial_pids {
                ensure!(
                    held_inspector.snapshot(pid).context(NodeSnafu)?.is_none(),
                    InvalidInputSnafu {
                        path: pin_root,
                        reason: "a stopped held task gained identity before reconciliation",
                    }
                );
            }
            let held_reconciliation = identity
                .activate_prepared_runtime_roots(
                    host.as_mut()
                        .ok_or_else(|| invalid_state("the PostStart identity host is missing"))?,
                    false,
                )
                .context(NodeSnafu)?;
            ensure!(
                held_reconciliation == Default::default(),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: format!(
                        "held initial tasks failed prepared reconciliation: {held_reconciliation:?}"
                    ),
                }
            );
            for (pid, binding) in [
                (entrypoint_first_init_pid, &entrypoint_first_binding),
                (hook_first_init_pid, &hook_first_binding),
                (repeat_init_pid, &repeat_binding),
            ] {
                let root = held_inspector
                    .snapshot(pid)
                    .context(NodeSnafu)?
                    .ok_or_else(|| invalid_state("a held initial task has no native identity"))?;
                let runtime = root.runtime_binding.as_ref().ok_or_else(|| {
                    invalid_state("a held initial task has no exact runtime binding")
                })?;
                ensure!(
                    root.creator_task_cookie.is_none()
                        && root.root_class.as_deref() == Some("initial_container_root")
                        && root.installed_role_class.as_deref() == Some("initial_role")
                        && root.active_role_id == binding.initial_role_id
                        && runtime.prepared_container_state == "prepared"
                        && runtime.prepared_container_entry_instance_id == root.entry_instance_id
                        && runtime.prepared_container_initial_host_tgid == pid,
                    InvalidInputSnafu {
                        path: pin_root,
                        reason: "iterator reconciliation did not preserve the exact prepared root",
                    }
                );
            }
            for pid in held_initial_pids {
                self.continue_host_pid(pid)?;
            }
            for request in [
                &entrypoint_first_request,
                &hook_first_request,
                &repeat_request,
            ] {
                self.release_prestart(request)?;
            }
            let entrypoint_first_pid =
                self.wait_for("entrypoint-first application", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "entrypoint-first")?
                        .into_iter()
                        .next())
                })?;
            let entrypoint_first_hook_pid =
                self.wait_for("entrypoint-first PostStart hook", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "poststart-entrypoint-first")?
                        .into_iter()
                        .next())
                })?;
            let hook_first_pid = self.wait_for("hook-first application", &fixture_root, || {
                Ok(self
                    .kubernetes_fixture_slot_pids(&fixture_root, "entrypoint-hook-first")?
                    .into_iter()
                    .next())
            })?;
            let hook_first_hook_pid =
                self.wait_for("hook-first PostStart hook", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "poststart-hook-first")?
                        .into_iter()
                        .next())
                })?;
            let repeat_first_hook_pid =
                self.wait_for("restart PostStart hook", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "poststart-repeat")?
                        .into_iter()
                        .next())
                })?;
            let entrypoint_first_order =
                self.wait_for("entrypoint-first order record", &fixture_root, || {
                    self.kubernetes_fixture_order(&fixture_root, "entrypoint-first")
                })?;
            let entrypoint_first_hook_order =
                self.wait_for("entrypoint-first hook order record", &fixture_root, || {
                    self.kubernetes_fixture_order(&fixture_root, "poststart-entrypoint-first")
                })?;
            let hook_first_order =
                self.wait_for("hook-first order record", &fixture_root, || {
                    self.kubernetes_fixture_order(&fixture_root, "entrypoint-hook-first")
                })?;
            let hook_first_hook_order =
                self.wait_for("hook-first hook order record", &fixture_root, || {
                    self.kubernetes_fixture_order(&fixture_root, "poststart-hook-first")
                })?;
            let both_orders_observed = entrypoint_first_order < entrypoint_first_hook_order
                && hook_first_hook_order < hook_first_order;
            ensure!(
                both_orders_observed,
                InvalidInputSnafu {
                    path: &fixture_root,
                    reason: format!(
                        "Kubernetes PostStart orders are wrong: entrypoint-first={entrypoint_first_order}/{entrypoint_first_hook_order}, hook-first={hook_first_hook_order}/{hook_first_order}"
                    ),
                }
            );

            let entrypoint_first_cgroup = entrypoint_first_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the entrypoint-first binding has no cgroup"))?;
            let hook_first_cgroup = hook_first_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the hook-first binding has no cgroup"))?;
            let repeat_cgroup = repeat_binding
                .root_cgroup_path
                .as_deref()
                .ok_or_else(|| invalid_state("the restart PostStart binding has no cgroup"))?;
            let entrypoint_first_host_pid =
                self.wait_for("entrypoint-first host PID", entrypoint_first_cgroup, || {
                    self.kubernetes_host_pid(entrypoint_first_cgroup, entrypoint_first_pid)
                })?;
            let entrypoint_first_hook_host_pid = self.wait_for(
                "entrypoint-first PostStart host PID",
                entrypoint_first_cgroup,
                || self.kubernetes_host_pid(entrypoint_first_cgroup, entrypoint_first_hook_pid),
            )?;
            let hook_first_host_pid =
                self.wait_for("hook-first host PID", hook_first_cgroup, || {
                    self.kubernetes_host_pid(hook_first_cgroup, hook_first_pid)
                })?;
            let hook_first_hook_host_pid =
                self.wait_for("hook-first PostStart host PID", hook_first_cgroup, || {
                    self.kubernetes_host_pid(hook_first_cgroup, hook_first_hook_pid)
                })?;
            let repeat_first_hook_host_pid =
                self.wait_for("restart PostStart first host PID", repeat_cgroup, || {
                    self.kubernetes_host_pid(repeat_cgroup, repeat_first_hook_pid)
                })?;

            let inspector = NativeIdentityInspector::new(pin_root);
            let entrypoint_first_application =
                self.wait_for("entrypoint-first application identity", pin_root, || {
                    inspector
                        .snapshot(entrypoint_first_host_pid)
                        .context(NodeSnafu)
                })?;
            let entrypoint_first_hook =
                self.wait_for("entrypoint-first PostStart identity", pin_root, || {
                    inspector
                        .snapshot(entrypoint_first_hook_host_pid)
                        .context(NodeSnafu)
                })?;
            let hook_first_application =
                self.wait_for("hook-first application identity", pin_root, || {
                    inspector.snapshot(hook_first_host_pid).context(NodeSnafu)
                })?;
            let hook_first_hook =
                self.wait_for("hook-first PostStart identity", pin_root, || {
                    inspector
                        .snapshot(hook_first_hook_host_pid)
                        .context(NodeSnafu)
                })?;
            let repeat_application_before =
                self.wait_for("restart application identity", pin_root, || {
                    inspector.snapshot(repeat_init_pid).context(NodeSnafu)
                })?;
            let first_hook = self.wait_for("restart first PostStart identity", pin_root, || {
                inspector
                    .snapshot(repeat_first_hook_host_pid)
                    .context(NodeSnafu)
            })?;
            let roots = [
                &entrypoint_first_application,
                &entrypoint_first_hook,
                &hook_first_application,
                &hook_first_hook,
                &repeat_application_before,
                &first_hook,
            ];
            ensure!(
                [
                    (&entrypoint_first_application, &entrypoint_first_binding),
                    (&hook_first_application, &hook_first_binding),
                    (&repeat_application_before, &repeat_binding),
                ]
                .into_iter()
                .all(|(root, binding)| {
                    root.creator_task_cookie.is_none()
                        && root.root_class.as_deref() == Some("initial_container_root")
                        && root.installed_role_class.as_deref() == Some("initial_role")
                        && root.active_role_id == binding.initial_role_id
                })
                    && [
                        (&entrypoint_first_hook, &entrypoint_first_binding),
                        (&hook_first_hook, &hook_first_binding),
                        (&first_hook, &repeat_binding),
                    ]
                    .into_iter()
                    .all(|(root, binding)| {
                        root.creator_task_cookie.is_none()
                            && root.root_class.as_deref() == Some("external_runtime_root")
                            && root.installed_role_class.as_deref()
                                == Some("runtime_external_restricted")
                            && root.active_role_id == binding.external_role_id
                    })
                    && roots
                        .iter()
                        .map(|root| root.task_cookie)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == roots.len()
                    && roots
                        .iter()
                        .map(|root| root.process_state_id.as_str())
                        .collect::<BTreeSet<_>>()
                        .len()
                        == roots.len(),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "prestart admission did not keep application and PostStart roots distinct with exact roles",
                }
            );

            for (slot, namespace_pid) in [
                ("entrypoint-first", entrypoint_first_pid),
                ("poststart-entrypoint-first", entrypoint_first_hook_pid),
                ("entrypoint-hook-first", hook_first_pid),
                ("poststart-hook-first", hook_first_hook_pid),
            ] {
                self.kubernetes_release_fifo(
                    &fixture_root.join(format!("{slot}-release-{namespace_pid}")),
                )?;
            }
            for pod in [
                "mithril-poststart-entrypoint-first",
                "mithril-poststart-hook-first",
            ] {
                self.kubernetes_output(
                    &[
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "wait",
                        "--for=condition=Ready",
                        &format!("pod/{pod}"),
                        "--timeout=60s",
                    ],
                    "wait for the ordered PostStart fixture Pod",
                )?;
            }

            let kill = Command::new("/usr/bin/systemctl")
                .args(["kill", "--kill-who=main", "--signal=SIGKILL", "k3s"])
                .output()
                .context(IoSnafu {
                    path: Path::new("/usr/bin/systemctl"),
                })?;
            ensure!(
                kill.status.success(),
                InvalidInputSnafu {
                    path: Path::new("/usr/bin/systemctl"),
                    reason: format!(
                        "Kubernetes node service kill failed: {}",
                        String::from_utf8_lossy(&kill.stderr).trim()
                    ),
                }
            );
            let start = Command::new("/usr/bin/systemctl")
                .args(["start", "k3s"])
                .output()
                .context(IoSnafu {
                    path: Path::new("/usr/bin/systemctl"),
                })?;
            ensure!(
                start.status.success(),
                InvalidInputSnafu {
                    path: Path::new("/usr/bin/systemctl"),
                    reason: format!(
                        "Kubernetes node service start failed: {}",
                        String::from_utf8_lossy(&start.stderr).trim()
                    ),
                }
            );
            let repeat_command =
                self.wait_for("Kubernetes API after restart", &manifest_path, || {
                    let program = Path::new("/usr/local/bin/k3s");
                    let output = Command::new(program)
                        .args([
                            "kubectl",
                            "-n",
                            namespace.as_str(),
                            "get",
                            "pod",
                            "mithril-poststart-repeat",
                            "-o",
                            "json",
                        ])
                        .output()
                        .context(IoSnafu { path: program })?;
                    if !output.status.success() {
                        return Ok(None);
                    }
                    let pod: serde_json::Value =
                        serde_json::from_slice(&output.stdout).context(JsonSnafu {
                            path: &manifest_path,
                        })?;
                    let command = pod
                        .pointer("/spec/containers/0/lifecycle/postStart/exec/command")
                        .and_then(serde_json::Value::as_array)
                        .filter(|command| !command.is_empty())
                        .ok_or_else(|| {
                            invalid_state("the live PostStart fixture Pod has no exec-hook command")
                        })?
                        .iter()
                        .map(|argument| {
                            argument.as_str().map(str::to_owned).ok_or_else(|| {
                                invalid_state(
                                    "the live PostStart fixture command has a non-string argument",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(Some(command))
                })?;
            repeated_poststart = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "crictl",
                        "exec",
                        "--sync",
                        repeat_binding.container_id.as_str(),
                    ])
                    .args(&repeat_command)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let repeat_second_hook_pid =
                self.wait_for("repeated PostStart hook", &fixture_root, || {
                    Ok(self
                        .kubernetes_fixture_slot_pids(&fixture_root, "poststart-repeat")?
                        .into_iter()
                        .find(|pid| *pid != repeat_first_hook_pid))
                })?;
            let repeat_second_hook_host_pid =
                self.wait_for("repeated PostStart host PID", repeat_cgroup, || {
                    self.kubernetes_host_pid(repeat_cgroup, repeat_second_hook_pid)
                })?;
            ensure!(
                self.kubernetes_host_pid(repeat_cgroup, repeat_first_hook_pid)?
                    == Some(repeat_first_hook_host_pid),
                InvalidInputSnafu {
                    path: repeat_cgroup,
                    reason: "the first in-flight PostStart task did not survive kubelet restart",
                }
            );
            let repeated_hook = self.wait_for("repeated PostStart identity", pin_root, || {
                inspector
                    .snapshot(repeat_second_hook_host_pid)
                    .context(NodeSnafu)
            })?;
            let repeat_application_after = self.wait_for(
                "application identity after kubelet restart",
                pin_root,
                || inspector.snapshot(repeat_init_pid).context(NodeSnafu),
            )?;
            let repeat_fresh_identity = repeated_hook.task_cookie != first_hook.task_cookie
                && repeated_hook.process_state_id != first_hook.process_state_id;
            ensure!(
                repeat_application_after == repeat_application_before
                    && repeat_fresh_identity
                    && repeated_hook.creator_task_cookie.is_none()
                    && repeated_hook.root_class.as_deref() == Some("external_runtime_root")
                    && repeated_hook.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && repeated_hook.active_role_id == repeat_binding.external_role_id,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the repeated PostStart task reused identity or lost its restricted external class",
                }
            );
            for namespace_pid in [repeat_first_hook_pid, repeat_second_hook_pid] {
                self.kubernetes_release_fifo(
                    &fixture_root.join(format!("poststart-repeat-release-{namespace_pid}")),
                )?;
            }
            let repeat_status = repeated_poststart
                .take()
                .ok_or_else(|| invalid_state("the repeated PostStart delivery is missing"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("/usr/local/bin/k3s"),
                })?;
            ensure!(
                repeat_status.success(),
                InvalidInputSnafu {
                    path: Path::new("/usr/local/bin/k3s"),
                    reason: format!(
                        "the repeated PostStart CRI delivery failed with {repeat_status}"
                    ),
                }
            );
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-poststart-repeat",
                    "--timeout=60s",
                ],
                "wait for the repeated PostStart fixture Pod",
            )?;

            Ok((
                entrypoint_first_application,
                entrypoint_first_hook,
                hook_first_application,
                hook_first_hook,
                both_orders_observed,
                repeat_application_before,
                repeat_application_after,
                first_hook,
                repeated_hook,
                repeat_fresh_identity,
            ))
        })();

        Self::stop_fixture_process(&mut repeated_poststart);
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes PostStart fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let runtime_class_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "runtimeclass",
                    "mithril",
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=60s",
                ],
                "remove the Mithril prestart RuntimeClass",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let host_cleanup = if let Some(host) = host.take() {
            host.shutdown().context(InterceptorSnafu)
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup
            .and(runtime_class_cleanup)
            .and(host_cleanup)
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(request_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !request_directory.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes PostStart fixture was not removed",
            }
        );
        let (
            entrypoint_first_application,
            entrypoint_first_hook,
            hook_first_application,
            hook_first_hook,
            both_orders_observed,
            repeat_application_before,
            repeat_application_after,
            first_hook,
            repeated_hook,
            repeat_fresh_identity,
        ) = probe?;
        bundle.kubernetes_poststart_entrypoint_first_application =
            Some(entrypoint_first_application);
        bundle.kubernetes_poststart_entrypoint_first_hook = Some(entrypoint_first_hook);
        bundle.kubernetes_poststart_hook_first_application = Some(hook_first_application);
        bundle.kubernetes_poststart_hook_first_hook = Some(hook_first_hook);
        bundle.kubernetes_poststart_both_orders_observed = Some(both_orders_observed);
        bundle.kubernetes_poststart_repeat_application_before = Some(repeat_application_before);
        bundle.kubernetes_poststart_repeat_application_after = Some(repeat_application_after);
        bundle.kubernetes_poststart_first_hook = Some(first_hook);
        bundle.kubernetes_poststart_repeated_hook = Some(repeated_hook);
        bundle.kubernetes_poststart_repeat_fresh_identity = Some(repeat_fresh_identity);
        Ok(())
    }

    fn physical_kubernetes_stock_hook_failure_probe(
        &self,
        output_directory: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        const HOOK_TIMEOUT_SECONDS: u64 = 30;

        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-stock-hook-failure");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes stock-hook failure fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let fixture_root = work_directory.join("fixture");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let request_directory = Path::new(PRESTART_REQUEST_DIRECTORY);
        ensure!(
            !request_directory.exists(),
            InvalidInputSnafu {
                path: request_directory,
                reason: "the stock-hook failure request directory must not already exist",
            }
        );
        fs::create_dir(request_directory).context(IoSnafu {
            path: request_directory,
        })?;
        fs::set_permissions(request_directory, fs::Permissions::from_mode(0o700)).context(
            IoSnafu {
                path: request_directory,
            },
        )?;
        let request_cleanup = ProbeDirectory::new(request_directory);
        let namespace = format!("mithril-identity-stock-hook-{}", std::process::id());
        let template_path = self.repo_root.join(
            "crates/mithril-e2e/fixtures/identity/kubernetes-stock-hook-failure-workload-v1.yaml",
        );
        let template = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        let mut namespace_created = false;
        let mut runtime_class_created = false;

        let probe = (|| -> Result<_> {
            let mut timeout_result = None;
            let mut timeout_no_payload = false;
            let mut mismatch_result = None;
            let mut mismatch_rejected = false;
            let mut mismatch_no_payload = false;
            let mut missing_field_result = None;
            let mut missing_field_rejected = false;
            let mut missing_field_no_payload = false;

            for (index, case) in ["timeout", "mismatch", "missing-field"]
                .into_iter()
                .enumerate()
            {
                let pod_name = format!("mithril-stock-hook-{case}");
                let manifest_path = work_directory.join(format!("{case}.yaml"));
                fs::write(
                    &manifest_path,
                    template
                        .replace("MITHRIL_IDENTITY_STOCK_HOOK_NAMESPACE", &namespace)
                        .replace("MITHRIL_IDENTITY_STOCK_HOOK_CASE", case)
                        .replace(
                            "MITHRIL_IDENTITY_STOCK_HOOK_FIXTURE_ROOT",
                            fixture_root.to_string_lossy().as_ref(),
                        ),
                )
                .context(IoSnafu {
                    path: &manifest_path,
                })?;
                namespace_created = true;
                runtime_class_created = true;
                self.kubernetes_output(
                    &[
                        "kubectl",
                        "apply",
                        "-f",
                        manifest_path.to_string_lossy().as_ref(),
                    ],
                    &format!("create the Kubernetes stock-hook {case} fixture"),
                )?;
                let request_path = self.kubernetes_prestart_request_path(
                    request_directory,
                    &namespace,
                    &pod_name,
                    "application",
                )?;
                let container_id = request_path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .filter(|value| {
                        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .ok_or_else(|| invalid_state("stock-hook request has no full container ID"))?
                    .to_owned();
                let binding_id = format!("11111111-1111-4111-8111-11111111170{index}");
                let execution_set_id = format!("22222222-2222-4222-8222-22222222280{index}");
                let identity = (
                    mithril_node::ContainerKindV1::Application,
                    binding_id.as_str(),
                    execution_set_id.as_str(),
                    "33333333-3333-4333-8333-333333333333",
                    PROFILE_GENERATION_REF_ID,
                );

                let expected_hook_message = match case {
                    "timeout" => {
                        let (_, _, validated_request) = self.kubernetes_prestart_binding(
                            request_directory,
                            &namespace,
                            &pod_name,
                            "application",
                            identity,
                            &manifest_path,
                        )?;
                        ensure!(
                            validated_request == request_path,
                            InvalidInputSnafu {
                                path: &request_path,
                                reason: "timeout validation selected another prestart request",
                            }
                        );
                        format!("Mithril prestart admission timed out for {container_id}")
                    }
                    "mismatch" => {
                        let mut request: serde_json::Value =
                            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                                path: &request_path,
                            })?)
                            .context(JsonSnafu {
                                path: &request_path,
                            })?;
                        let state_id = request
                            .pointer_mut("/state/id")
                            .ok_or_else(|| invalid_state("prestart request has no state ID"))?;
                        *state_id = serde_json::Value::String("0".repeat(64));
                        fs::write(
                            &request_path,
                            serde_json::to_vec(&request).context(JsonSnafu {
                                path: &request_path,
                            })?,
                        )
                        .context(IoSnafu {
                            path: &request_path,
                        })?;
                        mismatch_rejected = self
                            .kubernetes_prestart_binding(
                                request_directory,
                                &namespace,
                                &pod_name,
                                "application",
                                identity,
                                &manifest_path,
                            )
                            .is_err_and(|error| {
                                error.to_string().contains(
                                    "prestart OCI state does not match the sole live cgroup PID",
                                )
                            });
                        ensure!(
                            mismatch_rejected,
                            InvalidInputSnafu {
                                path: &request_path,
                                reason: "mismatched prestart identity did not reject",
                            }
                        );
                        self.reject_prestart(&request_path)?;
                        format!("Mithril rejected prestart admission for {container_id}")
                    }
                    "missing-field" => {
                        let mut request: serde_json::Value =
                            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                                path: &request_path,
                            })?)
                            .context(JsonSnafu {
                                path: &request_path,
                            })?;
                        let removed = request
                            .pointer_mut("/annotations")
                            .and_then(serde_json::Value::as_object_mut)
                            .and_then(|annotations| {
                                annotations.remove("io.kubernetes.cri.sandbox-uid")
                            });
                        ensure!(
                            removed.is_some(),
                            InvalidInputSnafu {
                                path: &request_path,
                                reason: "prestart request has no Pod UID to remove",
                            }
                        );
                        fs::write(
                            &request_path,
                            serde_json::to_vec(&request).context(JsonSnafu {
                                path: &request_path,
                            })?,
                        )
                        .context(IoSnafu {
                            path: &request_path,
                        })?;
                        missing_field_rejected = self
                            .kubernetes_prestart_binding(
                                request_directory,
                                &namespace,
                                &pod_name,
                                "application",
                                identity,
                                &manifest_path,
                            )
                            .is_err_and(|error| {
                                error
                                    .to_string()
                                    .contains("prestart request has no Pod UID")
                            });
                        ensure!(
                            missing_field_rejected,
                            InvalidInputSnafu {
                                path: &request_path,
                                reason: "missing prestart Pod UID did not reject",
                            }
                        );
                        self.reject_prestart(&request_path)?;
                        format!("Mithril rejected prestart admission for {container_id}")
                    }
                    _ => unreachable!(),
                };

                let runtime_result = self.kubernetes_stock_hook_failure_result(
                    &namespace,
                    &pod_name,
                    &expected_hook_message,
                    &manifest_path,
                )?;
                let marker_path = fixture_root.join(format!("{case}.started"));
                let no_payload = !marker_path.exists();
                ensure!(
                    no_payload,
                    InvalidInputSnafu {
                        path: &marker_path,
                        reason: format!("the stock-hook {case} payload started"),
                    }
                );
                self.kubernetes_output(
                    &[
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "delete",
                        "pod",
                        pod_name.as_str(),
                        "--wait=false",
                    ],
                    &format!("begin removal of the stock-hook {case} Pod"),
                )?;
                self.settle_prestart_requests(request_directory)?;
                self.kubernetes_output(
                    &[
                        "kubectl",
                        "-n",
                        namespace.as_str(),
                        "wait",
                        "--for=delete",
                        &format!("pod/{pod_name}"),
                        "--timeout=120s",
                    ],
                    &format!("finish removal of the stock-hook {case} Pod"),
                )?;
                self.wait_for_with_limit(
                    &format!("stock-hook {case} CRI container removal"),
                    &manifest_path,
                    KUBERNETES_CLEANUP_WAIT_LIMIT,
                    || {
                        let listed = self.kubernetes_output(
                            &[
                                "crictl",
                                "ps",
                                "-a",
                                "--id",
                                container_id.as_str(),
                                "-o",
                                "json",
                            ],
                            "read the failed stock-hook container record",
                        )?;
                        let listed: serde_json::Value =
                            serde_json::from_str(&listed).context(JsonSnafu {
                                path: &manifest_path,
                            })?;
                        Ok(listed
                            .get("containers")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(Vec::is_empty)
                            .then_some(()))
                    },
                )?;

                match case {
                    "timeout" => {
                        timeout_result = Some(runtime_result);
                        timeout_no_payload = no_payload;
                    }
                    "mismatch" => {
                        mismatch_result = Some(runtime_result);
                        mismatch_no_payload = no_payload;
                    }
                    "missing-field" => {
                        missing_field_result = Some(runtime_result);
                        missing_field_no_payload = no_payload;
                    }
                    _ => unreachable!(),
                }
            }

            Ok((
                timeout_result
                    .ok_or_else(|| invalid_state("stock-hook timeout result is missing"))?,
                timeout_no_payload,
                mismatch_result
                    .ok_or_else(|| invalid_state("stock-hook mismatch result is missing"))?,
                mismatch_rejected,
                mismatch_no_payload,
                missing_field_result
                    .ok_or_else(|| invalid_state("stock-hook missing-field result is missing"))?,
                missing_field_rejected,
                missing_field_no_payload,
            ))
        })();

        let _ = self.settle_prestart_requests(request_directory);
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes stock-hook failure fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let runtime_class_cleanup = if runtime_class_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "runtimeclass",
                    "mithril",
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=60s",
                ],
                "remove the Kubernetes stock-hook failure RuntimeClass",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup
            .and(runtime_class_cleanup)
            .and(request_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !request_directory.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes stock-hook failure fixture was not removed",
            }
        );
        let (
            timeout_result,
            timeout_no_payload,
            mismatch_result,
            mismatch_rejected,
            mismatch_no_payload,
            missing_field_result,
            missing_field_rejected,
            missing_field_no_payload,
        ) = probe?;
        bundle.kubernetes_stock_hook_timeout_seconds = Some(HOOK_TIMEOUT_SECONDS);
        bundle.kubernetes_stock_hook_timeout_result = Some(timeout_result);
        bundle.kubernetes_stock_hook_timeout_no_payload = Some(timeout_no_payload);
        bundle.kubernetes_stock_hook_mismatch_result = Some(mismatch_result);
        bundle.kubernetes_stock_hook_mismatch_rejected = Some(mismatch_rejected);
        bundle.kubernetes_stock_hook_mismatch_no_payload = Some(mismatch_no_payload);
        bundle.kubernetes_stock_hook_missing_field_result = Some(missing_field_result);
        bundle.kubernetes_stock_hook_missing_field_rejected = Some(missing_field_rejected);
        bundle.kubernetes_stock_hook_missing_field_no_payload = Some(missing_field_no_payload);
        bundle.kubernetes_stock_hook_failure_fixture_removed = Some(true);
        Ok(())
    }

    fn physical_kubernetes_resilience_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        bundle: &mut IdentityPhysicalProbeBundleV1,
    ) -> Result<()> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-entry-loss");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes entry-loss fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-loss-{}", std::process::id());
        let fixture_root = work_directory.join("fixture");
        let manifest_path = work_directory.join("workload.yaml");
        let config_path = work_directory.join("node.json");
        let state_directory = work_directory.join("state");
        let observation_socket = work_directory.join("observation.sock");
        let marker_path = fixture_root.join("loss.pid");
        let node_log_path = work_directory.join("mithril-node.log");
        fs::create_dir(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let template_path = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/identity/kubernetes-resilience-workload-v1.yaml");
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest
                .replace("MITHRIL_IDENTITY_RESILIENCE_NAMESPACE", &namespace)
                .replace(
                    "MITHRIL_IDENTITY_RESILIENCE_FIXTURE_ROOT",
                    fixture_root.to_string_lossy().as_ref(),
                ),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        ensure!(
            !pin_root.exists() && !lease_path.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Kubernetes entry-loss pin root and lease must not already exist",
            }
        );
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);
        let mut namespace_created = false;
        let mut k3s_stopped = false;
        let mut node = None;
        let mut external = None;

        let probe = (|| -> Result<_> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes entry-loss fixture",
            )?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-resilience",
                    "--timeout=180s",
                ],
                "wait for the Kubernetes entry-loss Pod",
            )?;
            let (mut binding, init_pid, _sandbox) = self.kubernetes_container_binding(
                &namespace,
                "mithril-resilience",
                "application",
                (
                    mithril_node::ContainerKindV1::Application,
                    "11111111-1111-4111-8111-111111111701",
                    "22222222-2222-4222-8222-222222222701",
                    "33333333-3333-4333-8333-333333333701",
                    7,
                ),
                &manifest_path,
            )?;
            let container_id = binding.container_id.clone();
            let cgroup = self.kubernetes_cgroup_for_pid(init_pid)?;
            binding.root_cgroup_path = None;
            binding.arm_initial_root = false;

            let source_config_path = self
                .repo_root
                .join("crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json");
            let mut config: serde_json::Value =
                serde_json::from_slice(&fs::read(&source_config_path).context(IoSnafu {
                    path: &source_config_path,
                })?)
                .context(JsonSnafu {
                    path: &source_config_path,
                })?;
            config["state_directory"] =
                serde_json::Value::String(state_directory.to_string_lossy().into_owned());
            config["interceptor"]["pin_root"] =
                serde_json::Value::String(pin_root.to_string_lossy().into_owned());
            config["interceptor"]["lease_path"] =
                serde_json::Value::String(lease_path.to_string_lossy().into_owned());
            config["runtime_observation"] = serde_json::json!({
                "socket_path": observation_socket.to_string_lossy(),
                "allowed_uid": 0,
                "cgroup_scope": "/"
            });
            let binding_config = config
                .pointer_mut("/workload_bindings/0")
                .ok_or_else(|| invalid_state("the node template has no workload binding"))?;
            binding_config["binding_id"] = binding.binding_id.clone().into();
            binding_config["execution_set_id"] = binding.execution_set_id.clone().into();
            binding_config["protected_scope_id"] = binding.protected_scope_id.clone().into();
            binding_config["workload_selector_id"] = binding.workload_selector_id.clone().into();
            binding_config["profile_id"] = binding.profile_id.clone().into();
            binding_config["container_id"] = binding.container_id.clone().into();
            binding_config["namespace"] = binding.namespace.clone().into();
            binding_config["pod_uid"] = binding.pod_uid.clone().into();
            binding_config["sandbox_id"] = binding.sandbox_id.clone().into();
            binding_config["container_name"] = binding.container_name.clone().into();
            binding_config["image_digest"] = binding.image_digest.clone().into();
            binding_config["container_generation"] = binding.container_generation.into();
            binding_config["lifecycle_generation"] = binding.lifecycle_generation.into();
            binding_config["active_profile_generation_ref_id"] =
                binding.active_profile_generation_ref_id.into();
            binding_config["initial_role_id"] = binding.initial_role_id.into();
            binding_config["external_role_id"] = binding.external_role_id.into();
            fs::write(
                &config_path,
                serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
            )
            .context(IoSnafu { path: &config_path })?;

            let current_executable = std::env::current_exe().context(IoSnafu {
                path: Path::new("current Mithril identity-test executable"),
            })?;
            let binary_directory = current_executable
                .parent()
                .ok_or_else(|| invalid_state("the identity-test executable has no parent"))?;
            let node_binary = binary_directory.join("mithril-node");
            let inspect_binary = binary_directory.join("mithril-inspect");
            ensure!(
                node_binary.is_file() && inspect_binary.is_file(),
                InvalidInputSnafu {
                    path: binary_directory,
                    reason: "the entry-loss fixture requires sibling node and inspector binaries",
                }
            );
            let node_log = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&node_log_path)
                .context(IoSnafu {
                    path: &node_log_path,
                })?;
            node = Some(
                Command::new(&node_binary)
                    .args(["--config", config_path.to_string_lossy().as_ref()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(node_log))
                    .spawn()
                    .context(IoSnafu { path: &node_binary })?,
            );
            self.wait_for("Kubernetes entry-loss node", pin_root, || {
                if node
                    .as_mut()
                    .is_some_and(|child| child.try_wait().ok().flatten().is_some())
                {
                    return Err(invalid_state(format!(
                        "the entry-loss node exited: {}",
                        fs::read_to_string(&node_log_path).unwrap_or_default()
                    )));
                }
                Ok((pin_root.join("links/erebor_sched_process_exit").exists()
                    && observation_socket.exists())
                .then_some(()))
            })?;
            let initial_capability = self.wait_for(
                "healthy entry-loss identity capability",
                &observation_socket,
                || {
                    let output = Command::new(&inspect_binary)
                        .args([
                            "effects",
                            "--socket-path",
                            observation_socket.to_string_lossy().as_ref(),
                            "--cgroup-scope",
                            "/",
                        ])
                        .output()
                        .context(IoSnafu {
                            path: &inspect_binary,
                        })?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok((output.status.success()
                        && stdout.contains("capability=EXACT_NATIVE_IDENTITY state=SUPPORTED"))
                    .then_some(true))
                },
            )?;
            ensure!(
                initial_capability,
                InvalidInputSnafu {
                    path: &observation_socket,
                    reason: "the entry-loss node did not start with healthy identity coverage",
                }
            );
            let inspector = NativeIdentityInspector::new(pin_root);
            let discovered_root =
                self.wait_for("Kubernetes resilience discovery identity", pin_root, || {
                    inspector.snapshot(init_pid).context(NodeSnafu)
                })?;
            ensure!(
                discovered_root.creator_task_cookie.is_none()
                    && discovered_root.root_class.as_deref() == Some("restored_or_unknown_root")
                    && discovered_root.installed_role_class.as_deref()
                        == Some("fail_closed_unknown"),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the node did not conservatively discover the pre-existing Pod root",
                }
            );

            external = Some(
                Command::new("/usr/local/bin/k3s")
                    .args([
                        "crictl",
                        "exec",
                        container_id.as_str(),
                        "/bin/sh",
                        "-c",
                        "read identity_pid _ < /proc/self/stat; printf '%s\n' \"$identity_pid\" > /var/lib/mithril/resilience/loss.pid; kill -STOP \"$identity_pid\"; read identity_hostname < /etc/hostname; kill -STOP \"$identity_pid\"",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?,
            );
            let namespace_pid = self.wait_for("entry-loss CRI task", &marker_path, || {
                self.kubernetes_fixture_pid(&marker_path)
            })?;
            let host_pid = self.wait_for("entry-loss CRI host PID", &cgroup, || {
                self.kubernetes_host_pid(&cgroup, namespace_pid)
            })?;
            self.wait_for_stopped_host_pid(host_pid, "entry-loss CRI task")?;
            let audit_absent = self.wait_for("entry-loss direct CRI identity", pin_root, || {
                inspector.snapshot(host_pid).context(NodeSnafu)
            })?;
            ensure!(
                audit_absent.creator_task_cookie.is_none()
                    && audit_absent.root_class.as_deref() == Some("external_runtime_root")
                    && audit_absent.installed_role_class.as_deref()
                        == Some("runtime_external_restricted")
                    && audit_absent.active_role_id == binding.external_role_id,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "direct CRI entry without Kubernetes audit metadata was not restricted",
                }
            );

            self.remove_task_label_for_fixture(pin_root, host_pid)?;
            ensure!(
                inspector.snapshot(host_pid).context(NodeSnafu)?.is_none(),
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the BPF entry label survived the independent loss injection",
                }
            );
            self.continue_host_pid(host_pid)?;
            let bpf_recovered = self.wait_for("entry-loss BPF recovery", pin_root, || {
                let snapshot = inspector.snapshot(host_pid).context(NodeSnafu)?;
                let stopped = fs::read_to_string(format!("/proc/{host_pid}/status"))
                    .is_ok_and(|status| status.lines().any(|line| line.starts_with("State:\tT")));
                Ok(stopped.then_some(snapshot).flatten())
            })?;
            let bpf_recovered_fresh_restricted = bpf_recovered.task_cookie
                != audit_absent.task_cookie
                && bpf_recovered.process_state_id != audit_absent.process_state_id
                && bpf_recovered.creator_task_cookie.is_none()
                && bpf_recovered.root_class.as_deref() == Some("external_runtime_root")
                && bpf_recovered.installed_role_class.as_deref()
                    == Some("runtime_external_restricted")
                && bpf_recovered.active_role_id == binding.external_role_id;
            ensure!(
                bpf_recovered_fresh_restricted,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: format!(
                        "the first effect after BPF entry loss did not install a fresh restricted root: before={audit_absent:?}; after={bpf_recovered:?}",
                    ),
                }
            );

            self.set_k3s_service("stop")?;
            k3s_stopped = true;
            let runtime_identity_unhealthy = self.wait_for(
                "entry-loss runtime coverage transition",
                &observation_socket,
                || {
                    let output = Command::new(&inspect_binary)
                        .args([
                            "effects",
                            "--socket-path",
                            observation_socket.to_string_lossy().as_ref(),
                            "--cgroup-scope",
                            "/",
                        ])
                        .output()
                        .context(IoSnafu {
                            path: &inspect_binary,
                        })?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok((output.status.success()
                        && stdout.contains(
                            "capability=EXACT_NATIVE_IDENTITY state=UNHEALTHY reason=LIVE_IDENTITY_RECONCILIATION_FAILED",
                        ))
                    .then_some(true))
                },
            )?;
            let runtime_root = self.wait_for(
                "entry-loss task after runtime loss",
                Path::new("/proc"),
                || inspector.snapshot(host_pid).context(NodeSnafu),
            )?;
            ensure!(
                runtime_identity_unhealthy && runtime_root == bpf_recovered,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "runtime loss changed task identity or did not close identity coverage",
                }
            );

            self.set_k3s_service("start")?;
            k3s_stopped = false;
            self.wait_for_k3s_ready()?;
            let runtime_recovered = self.wait_for(
                "healthy identity capability after Kubernetes service restart",
                &observation_socket,
                || {
                    let output = Command::new(&inspect_binary)
                        .args([
                            "effects",
                            "--socket-path",
                            observation_socket.to_string_lossy().as_ref(),
                            "--cgroup-scope",
                            "/",
                        ])
                        .output()
                        .context(IoSnafu {
                            path: &inspect_binary,
                        })?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok((output.status.success()
                        && stdout.contains("capability=EXACT_NATIVE_IDENTITY state=SUPPORTED"))
                    .then(|| inspector.snapshot(host_pid).context(NodeSnafu))
                    .transpose()?
                    .flatten())
                },
            )?;
            ensure!(
                runtime_recovered == bpf_recovered,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the Kubernetes service restart changed the live task identity",
                }
            );

            Self::stop_node_process(&mut node)?;
            let observation = Command::new(&inspect_binary)
                .args([
                    "effects",
                    "--socket-path",
                    observation_socket.to_string_lossy().as_ref(),
                    "--cgroup-scope",
                    "/",
                ])
                .output()
                .context(IoSnafu {
                    path: &inspect_binary,
                })?;
            let node_observation_unavailable = !observation.status.success();
            let node_gap_root = inspector
                .snapshot(host_pid)
                .context(NodeSnafu)?
                .ok_or_else(|| {
                    invalid_state(
                        "the live task lost its pinned identity during the node restart gap",
                    )
                })?;
            ensure!(
                node_observation_unavailable && node_gap_root == bpf_recovered,
                InvalidInputSnafu {
                    path: pin_root,
                    reason:
                        "the node restart gap was not explicit or changed the live task identity",
                }
            );

            let node_log = fs::OpenOptions::new()
                .append(true)
                .open(&node_log_path)
                .context(IoSnafu {
                    path: &node_log_path,
                })?;
            node = Some(
                Command::new(&node_binary)
                    .args(["--config", config_path.to_string_lossy().as_ref()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(node_log))
                    .spawn()
                    .context(IoSnafu { path: &node_binary })?,
            );
            let node_recovered = self.wait_for(
                "healthy identity capability after node restart",
                &observation_socket,
                || {
                    if node
                        .as_mut()
                        .is_some_and(|child| child.try_wait().ok().flatten().is_some())
                    {
                        return Err(invalid_state(format!(
                            "the recovered resilience node exited: {}",
                            fs::read_to_string(&node_log_path).unwrap_or_default()
                        )));
                    }
                    let output = Command::new(&inspect_binary)
                        .args([
                            "effects",
                            "--socket-path",
                            observation_socket.to_string_lossy().as_ref(),
                            "--cgroup-scope",
                            "/",
                        ])
                        .output()
                        .context(IoSnafu {
                            path: &inspect_binary,
                        })?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok((output.status.success()
                        && stdout.contains("capability=EXACT_NATIVE_IDENTITY state=SUPPORTED"))
                    .then(|| inspector.snapshot(host_pid).context(NodeSnafu))
                    .transpose()?
                    .flatten())
                },
            )?;
            let restart_identity_stable = runtime_recovered == bpf_recovered
                && node_gap_root == bpf_recovered
                && node_recovered == bpf_recovered;
            ensure!(
                restart_identity_stable,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the recovered node reused a different task, process, or role identity",
                }
            );
            let first_reuse_binding = self.pinned_execution_set_binding(pin_root, &cgroup)?;
            self.continue_host_pid(host_pid)?;
            let external_status = external
                .as_mut()
                .ok_or_else(|| invalid_state("the resilience CRI task disappeared"))?
                .wait()
                .context(IoSnafu {
                    path: Path::new("Kubernetes resilience CRI task"),
                })?;
            external = None;
            ensure!(
                external_status.success(),
                InvalidInputSnafu {
                    path: &marker_path,
                    reason: "the resilience CRI task failed after its final release",
                }
            );

            Self::stop_node_process(&mut node)?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "delete",
                    "pod",
                    "mithril-resilience",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the first Kubernetes reuse Pod lifetime",
            )?;
            self.wait_for("first Kubernetes reuse cgroup removal", &cgroup, || {
                Ok((!cgroup.exists()).then_some(()))
            })?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "recreate the Kubernetes reuse Pod with the same names",
            )?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-resilience",
                    "--timeout=180s",
                ],
                "wait for the recreated Kubernetes reuse Pod",
            )?;
            let (mut second_binding, second_init_pid, _second_sandbox) = self
                .kubernetes_container_binding(
                    &namespace,
                    "mithril-resilience",
                    "application",
                    (
                        mithril_node::ContainerKindV1::Application,
                        "11111111-1111-4111-8111-111111111701",
                        "22222222-2222-4222-8222-222222222701",
                        "33333333-3333-4333-8333-333333333701",
                        7,
                    ),
                    &manifest_path,
                )?;
            let second_cgroup = self.kubernetes_cgroup_for_pid(second_init_pid)?;
            second_binding.root_cgroup_path = None;
            second_binding.arm_initial_root = false;
            let binding_config = config
                .pointer_mut("/workload_bindings/0")
                .ok_or_else(|| invalid_state("the node template has no workload binding"))?;
            binding_config["binding_id"] = second_binding.binding_id.clone().into();
            binding_config["execution_set_id"] = second_binding.execution_set_id.clone().into();
            binding_config["protected_scope_id"] = second_binding.protected_scope_id.clone().into();
            binding_config["workload_selector_id"] =
                second_binding.workload_selector_id.clone().into();
            binding_config["profile_id"] = second_binding.profile_id.clone().into();
            binding_config["container_id"] = second_binding.container_id.clone().into();
            binding_config["namespace"] = second_binding.namespace.clone().into();
            binding_config["pod_uid"] = second_binding.pod_uid.clone().into();
            binding_config["sandbox_id"] = second_binding.sandbox_id.clone().into();
            binding_config["container_name"] = second_binding.container_name.clone().into();
            binding_config["image_digest"] = second_binding.image_digest.clone().into();
            binding_config["container_generation"] = second_binding.container_generation.into();
            binding_config["lifecycle_generation"] = second_binding.lifecycle_generation.into();
            binding_config["active_profile_generation_ref_id"] =
                second_binding.active_profile_generation_ref_id.into();
            binding_config["initial_role_id"] = second_binding.initial_role_id.into();
            binding_config["external_role_id"] = second_binding.external_role_id.into();
            fs::write(
                &config_path,
                serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
            )
            .context(IoSnafu { path: &config_path })?;

            let node_log = fs::OpenOptions::new()
                .append(true)
                .open(&node_log_path)
                .context(IoSnafu {
                    path: &node_log_path,
                })?;
            node = Some(
                Command::new(&node_binary)
                    .args(["--config", config_path.to_string_lossy().as_ref()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(node_log))
                    .spawn()
                    .context(IoSnafu { path: &node_binary })?,
            );
            let second_root = self.wait_for(
                "recreated Kubernetes Pod root identity",
                &observation_socket,
                || {
                    if node
                        .as_mut()
                        .is_some_and(|child| child.try_wait().ok().flatten().is_some())
                    {
                        return Err(invalid_state(format!(
                            "the Kubernetes reuse node exited: {}",
                            fs::read_to_string(&node_log_path).unwrap_or_default()
                        )));
                    }
                    let output = Command::new(&inspect_binary)
                        .args([
                            "effects",
                            "--socket-path",
                            observation_socket.to_string_lossy().as_ref(),
                            "--cgroup-scope",
                            "/",
                        ])
                        .output()
                        .context(IoSnafu {
                            path: &inspect_binary,
                        })?;
                    let healthy = output.status.success()
                        && String::from_utf8_lossy(&output.stdout)
                            .contains("capability=EXACT_NATIVE_IDENTITY state=SUPPORTED");
                    Ok(healthy
                        .then(|| inspector.snapshot(second_init_pid).context(NodeSnafu))
                        .transpose()?
                        .flatten())
                },
            )?;
            let second_reuse_binding =
                self.pinned_execution_set_binding(pin_root, &second_cgroup)?;
            let same_names = binding.namespace == second_binding.namespace
                && binding.container_name == second_binding.container_name;
            let fresh_full_identity = binding.pod_uid != second_binding.pod_uid
                && binding.sandbox_id != second_binding.sandbox_id
                && binding.container_id != second_binding.container_id
                && binding.container_generation != second_binding.container_generation;
            let fresh_binding_identity = first_reuse_binding.root_cgroup_id
                != second_reuse_binding.root_cgroup_id
                && first_reuse_binding.binding_nonce != second_reuse_binding.binding_nonce
                && first_reuse_binding.root_cgroup_live_interval_id
                    != second_reuse_binding.root_cgroup_live_interval_id
                && discovered_root.task_cookie != second_root.task_cookie
                && discovered_root.process_state_id != second_root.process_state_id
                && discovered_root.active_execution_id != second_root.active_execution_id
                && second_root.creator_task_cookie.is_none()
                && second_root.root_class.as_deref() == Some("restored_or_unknown_root")
                && second_root.installed_role_class.as_deref() == Some("fail_closed_unknown")
                && second_root.active_role_id == second_binding.external_role_id;
            ensure!(
                same_names && fresh_full_identity && fresh_binding_identity,
                InvalidInputSnafu {
                    path: &manifest_path,
                    reason: "the recreated Pod or container reused an old full or binding identity",
                }
            );
            Ok((
                audit_absent,
                bpf_recovered,
                bpf_recovered_fresh_restricted,
                runtime_root,
                runtime_identity_unhealthy,
                discovered_root.clone(),
                runtime_recovered,
                node_gap_root,
                node_recovered,
                node_observation_unavailable,
                restart_identity_stable,
                discovered_root,
                second_root,
                binding.pod_uid.clone(),
                second_binding.pod_uid.clone(),
                binding.sandbox_id.clone(),
                second_binding.sandbox_id.clone(),
                binding.container_id.clone(),
                second_binding.container_id.clone(),
                cgroup.clone(),
                second_cgroup,
                first_reuse_binding,
                second_reuse_binding,
                same_names,
                fresh_full_identity,
                fresh_binding_identity,
            ))
        })();

        if k3s_stopped {
            let _result = self.set_k3s_service("start");
            let _result = self.wait_for_k3s_ready();
        }
        Self::stop_fixture_process(&mut external);
        Self::stop_fixture_process(&mut node);
        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes entry-loss fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup
            .and(pin_cleanup.cleanup())
            .and(lease_cleanup.cleanup())
            .and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)?
                && !pin_root.exists()
                && !lease_path.exists()
                && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes entry-loss fixture was not removed",
            }
        );
        let (
            audit_absent,
            bpf_recovered,
            bpf_recovered_fresh_restricted,
            runtime_root,
            runtime_identity_unhealthy,
            discovered_root,
            runtime_recovered,
            node_gap_root,
            node_recovered,
            node_observation_unavailable,
            restart_identity_stable,
            reuse_first_root,
            reuse_second_root,
            reuse_first_pod_uid,
            reuse_second_pod_uid,
            reuse_first_sandbox_id,
            reuse_second_sandbox_id,
            reuse_first_container_id,
            reuse_second_container_id,
            reuse_first_cgroup_path,
            reuse_second_cgroup_path,
            reuse_first_binding,
            reuse_second_binding,
            reuse_same_names,
            reuse_fresh_full_identity,
            reuse_fresh_binding_identity,
        ) = probe?;
        bundle.kubernetes_loss_audit_absent_root = Some(audit_absent);
        bundle.kubernetes_loss_bpf_recovered_root = Some(bpf_recovered.clone());
        bundle.kubernetes_loss_bpf_recovered_fresh_restricted =
            Some(bpf_recovered_fresh_restricted);
        bundle.kubernetes_loss_runtime_root = Some(runtime_root);
        bundle.kubernetes_loss_runtime_identity_unhealthy = Some(runtime_identity_unhealthy);
        bundle.kubernetes_restart_discovered_root = Some(discovered_root);
        bundle.kubernetes_restart_bound_root = Some(bpf_recovered);
        bundle.kubernetes_restart_runtime_recovered_root = Some(runtime_recovered);
        bundle.kubernetes_restart_node_gap_root = Some(node_gap_root);
        bundle.kubernetes_restart_node_recovered_root = Some(node_recovered);
        bundle.kubernetes_restart_node_observation_unavailable = Some(node_observation_unavailable);
        bundle.kubernetes_restart_identity_stable = Some(restart_identity_stable);
        bundle.kubernetes_reuse_first_root = Some(reuse_first_root);
        bundle.kubernetes_reuse_second_root = Some(reuse_second_root);
        bundle.kubernetes_reuse_first_pod_uid = Some(reuse_first_pod_uid);
        bundle.kubernetes_reuse_second_pod_uid = Some(reuse_second_pod_uid);
        bundle.kubernetes_reuse_first_sandbox_id = Some(reuse_first_sandbox_id);
        bundle.kubernetes_reuse_second_sandbox_id = Some(reuse_second_sandbox_id);
        bundle.kubernetes_reuse_first_container_id = Some(reuse_first_container_id);
        bundle.kubernetes_reuse_second_container_id = Some(reuse_second_container_id);
        bundle.kubernetes_reuse_first_cgroup_path = Some(reuse_first_cgroup_path);
        bundle.kubernetes_reuse_second_cgroup_path = Some(reuse_second_cgroup_path);
        bundle.kubernetes_reuse_first_root_cgroup_id = Some(reuse_first_binding.root_cgroup_id);
        bundle.kubernetes_reuse_second_root_cgroup_id = Some(reuse_second_binding.root_cgroup_id);
        bundle.kubernetes_reuse_first_binding_nonce =
            Some(id128_hex(reuse_first_binding.binding_nonce));
        bundle.kubernetes_reuse_second_binding_nonce =
            Some(id128_hex(reuse_second_binding.binding_nonce));
        bundle.kubernetes_reuse_first_live_interval_id =
            Some(id128_hex(reuse_first_binding.root_cgroup_live_interval_id));
        bundle.kubernetes_reuse_second_live_interval_id =
            Some(id128_hex(reuse_second_binding.root_cgroup_live_interval_id));
        bundle.kubernetes_reuse_same_names = Some(reuse_same_names);
        bundle.kubernetes_reuse_fresh_full_identity = Some(reuse_fresh_full_identity);
        bundle.kubernetes_reuse_fresh_binding_identity = Some(reuse_fresh_binding_identity);
        Ok(())
    }

    fn kubernetes_container_binding(
        &self,
        namespace: &str,
        pod_name: &str,
        container_name: &str,
        identity: (mithril_node::ContainerKindV1, &str, &str, &str, u64),
        manifest_path: &Path,
    ) -> Result<(WorkloadBindingConfig, u32, String)> {
        let (container_kind, binding_id, execution_set_id, profile_id, profile_ref_id) = identity;
        let container_id = self.wait_for(
            &format!("Kubernetes `{container_name}` container start"),
            manifest_path,
            || {
                let pod = self.kubernetes_output(
                    &[
                        "kubectl", "-n", namespace, "get", "pod", pod_name, "-o", "json",
                    ],
                    "read the Kubernetes containers fixture Pod",
                )?;
                let pod: serde_json::Value = serde_json::from_str(&pod).context(JsonSnafu {
                    path: manifest_path,
                })?;
                let status = [
                    "initContainerStatuses",
                    "containerStatuses",
                    "ephemeralContainerStatuses",
                ]
                .into_iter()
                .filter_map(|field| {
                    pod.pointer(&format!("/status/{field}"))
                        .and_then(serde_json::Value::as_array)
                })
                .flatten()
                .find(|status| {
                    status.get("name").and_then(serde_json::Value::as_str) == Some(container_name)
                        && status.pointer("/state/running").is_some()
                });
                Ok(status
                    .and_then(|status| status.get("containerID"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| id.strip_prefix("containerd://"))
                    .map(str::to_owned))
            },
        )?;
        let container = self.kubernetes_output(
            &["crictl", "inspect", container_id.as_str()],
            "inspect the Kubernetes containers fixture container",
        )?;
        let container: serde_json::Value = serde_json::from_str(&container).context(JsonSnafu {
            path: manifest_path,
        })?;
        let init_pid = container
            .pointer("/info/pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| {
                invalid_state(format!(
                    "the `{container_name}` Kubernetes container PID is invalid"
                ))
            })?;
        let image_digest = container
            .pointer("/status/imageRef")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| digest.contains("sha256:"))
            .ok_or_else(|| {
                invalid_state(format!(
                    "the `{container_name}` Kubernetes container has no image digest"
                ))
            })?
            .to_owned();
        let container_generation = container
            .pointer("/status/createdAt")
            .ok_or_else(|| {
                invalid_state(format!(
                    "the `{container_name}` Kubernetes container has no generation"
                ))
            })
            .and_then(|created_at| self.kubernetes_container_generation(created_at))?;
        let pod_uid = self.kubernetes_output(
            &[
                "kubectl",
                "-n",
                namespace,
                "get",
                "pod",
                pod_name,
                "-o",
                "jsonpath={.metadata.uid}",
            ],
            "read the Kubernetes containers fixture Pod UID",
        )?;
        let sandbox = self.kubernetes_output(
            &["crictl", "ps", "--id", container_id.as_str(), "-o", "json"],
            "read the Kubernetes containers fixture sandbox",
        )?;
        let sandbox: serde_json::Value = serde_json::from_str(&sandbox).context(JsonSnafu {
            path: manifest_path,
        })?;
        let sandbox_id = sandbox
            .pointer("/containers/0/podSandboxId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                invalid_state(format!(
                    "the `{container_name}` Kubernetes container has no sandbox"
                ))
            })?
            .to_owned();
        let root_cgroup_path = self.kubernetes_cgroup_for_pid(init_pid)?;
        let mut binding = test_binding(&root_cgroup_path);
        binding.binding_id = binding_id.to_owned();
        binding.execution_set_id = execution_set_id.to_owned();
        binding.profile_id = profile_id.to_owned();
        binding.active_profile_generation_ref_id = profile_ref_id;
        binding.container_id = container_id;
        binding.namespace = namespace.to_owned();
        binding.pod_uid = pod_uid.trim().to_owned();
        binding.sandbox_id = sandbox_id.clone();
        binding.container_name = container_name.to_owned();
        binding.image_digest = image_digest;
        binding.container_kind = container_kind;
        binding.container_generation = container_generation;
        Ok((binding, init_pid, sandbox_id))
    }

    fn kubernetes_prestart_binding(
        &self,
        request_directory: &Path,
        namespace: &str,
        pod_name: &str,
        container_name: &str,
        identity: (mithril_node::ContainerKindV1, &str, &str, &str, u64),
        manifest_path: &Path,
    ) -> Result<(WorkloadBindingConfig, u32, PathBuf)> {
        let request_path = self.kubernetes_prestart_request_path(
            request_directory,
            namespace,
            pod_name,
            container_name,
        )?;
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                path: &request_path,
            })?)
            .context(JsonSnafu {
                path: &request_path,
            })?;
        let pid = request
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| invalid_state("prestart request has no valid OCI state PID"))?;
        let container_id = request_path
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| invalid_state("prestart request has no full container ID"))?;
        let state_id = request
            .pointer("/state/id")
            .and_then(serde_json::Value::as_str);
        let state_pid = request
            .pointer("/state/pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok());
        let cgroup = request
            .get("cgroup")
            .and_then(serde_json::Value::as_str)
            .filter(|path| {
                path.starts_with('/')
                    && path != &"/"
                    && !path.split('/').any(|part| matches!(part, "." | ".."))
            })
            .ok_or_else(|| invalid_state("prestart request has no clean cgroup path"))?;
        let root_cgroup_path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        let live_cgroup = self.kubernetes_cgroup_for_pid(pid)?;
        let procs_path = root_cgroup_path.join("cgroup.procs");
        let live_pids = fs::read_to_string(&procs_path)
            .context(IoSnafu { path: &procs_path })?
            .split_ascii_whitespace()
            .map(|value| value.parse::<u32>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| {
                invalid_state(format!("prestart cgroup has an invalid PID: {error}"))
            })?;
        ensure!(
            request.get("stage").and_then(serde_json::Value::as_str) == Some("prestart")
                && state_id == Some(container_id)
                && state_pid == Some(pid)
                && live_pids.as_slice() == [pid]
                && fs::canonicalize(&root_cgroup_path).context(IoSnafu {
                    path: &root_cgroup_path,
                })? == fs::canonicalize(&live_cgroup).context(IoSnafu { path: &live_cgroup })?,
            InvalidInputSnafu {
                path: &request_path,
                reason: "prestart OCI state does not match the sole live cgroup PID",
            }
        );

        let container = self.kubernetes_output(
            &["crictl", "inspect", container_id],
            "inspect the held prestart container",
        )?;
        let container: serde_json::Value = serde_json::from_str(&container).context(JsonSnafu {
            path: manifest_path,
        })?;
        let runtime_cgroups_path = container
            .pointer("/info/runtimeSpec/linux/cgroupsPath")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid_state("held prestart container has no cgroup path"))?;
        let image_digest = container
            .pointer("/status/imageRef")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| digest.contains("sha256:"))
            .ok_or_else(|| invalid_state("held prestart container has no image digest"))?
            .to_owned();
        let container_generation = container
            .pointer("/status/createdAt")
            .ok_or_else(|| invalid_state("held prestart container has no generation"))
            .and_then(|created_at| self.kubernetes_container_generation(created_at))?;
        let annotation = |name: &str| {
            request
                .pointer(&format!("/annotations/{name}"))
                .and_then(serde_json::Value::as_str)
        };
        let pod_uid = annotation("io.kubernetes.cri.sandbox-uid")
            .ok_or_else(|| invalid_state("prestart request has no Pod UID"))?;
        let sandbox_id = annotation("io.kubernetes.cri.sandbox-id")
            .ok_or_else(|| invalid_state("prestart request has no sandbox ID"))?;
        let listed = self.kubernetes_output(
            &["crictl", "ps", "-a", "--id", container_id, "-o", "json"],
            "read the held prestart container record",
        )?;
        let listed: serde_json::Value = serde_json::from_str(&listed).context(JsonSnafu {
            path: manifest_path,
        })?;
        ensure!(
            container
                .pointer("/status/id")
                .and_then(serde_json::Value::as_str)
                == Some(container_id)
                && container
                    .pointer("/status/state")
                    .and_then(serde_json::Value::as_str)
                    == Some("CONTAINER_CREATED")
                && container
                    .pointer("/info/pid")
                    .and_then(serde_json::Value::as_u64)
                    == Some(0)
                && runtime_cgroups_path.contains(container_id)
                && annotation("io.kubernetes.cri.container-type") == Some("container")
                && annotation("io.kubernetes.cri.sandbox-namespace") == Some(namespace)
                && annotation("io.kubernetes.cri.sandbox-name") == Some(pod_name)
                && annotation("io.kubernetes.cri.container-name") == Some(container_name)
                && listed
                    .pointer("/containers/0/podSandboxId")
                    .and_then(serde_json::Value::as_str)
                    == Some(sandbox_id)
                && listed
                    .pointer("/containers/0/labels/io.kubernetes.pod.uid")
                    .and_then(serde_json::Value::as_str)
                    == Some(pod_uid),
            InvalidInputSnafu {
                path: &request_path,
                reason: "prestart fields do not match the Created CRI container",
            }
        );

        let (container_kind, binding_id, execution_set_id, profile_id, profile_ref_id) = identity;
        let mut binding = test_binding(&root_cgroup_path);
        binding.binding_id = binding_id.to_owned();
        binding.execution_set_id = execution_set_id.to_owned();
        binding.profile_id = profile_id.to_owned();
        binding.active_profile_generation_ref_id = profile_ref_id;
        binding.container_id = container_id.to_owned();
        binding.namespace = namespace.to_owned();
        binding.pod_uid = pod_uid.to_owned();
        binding.sandbox_id = sandbox_id.to_owned();
        binding.container_name = container_name.to_owned();
        binding.image_digest = image_digest;
        binding.container_kind = container_kind;
        binding.container_generation = container_generation;
        binding.arm_initial_root = true;
        Ok((binding, pid, request_path))
    }

    fn kubernetes_prestart_request_path(
        &self,
        request_directory: &Path,
        namespace: &str,
        pod_name: &str,
        container_name: &str,
    ) -> Result<PathBuf> {
        self.wait_for(
            &format!("Kubernetes `{pod_name}` prestart request"),
            request_directory,
            || {
                let mut matching = Vec::new();
                for entry in fs::read_dir(request_directory).context(IoSnafu {
                    path: request_directory,
                })? {
                    let path = entry
                        .context(IoSnafu {
                            path: request_directory,
                        })?
                        .path();
                    if path.extension().and_then(|value| value.to_str()) != Some("json") {
                        continue;
                    }
                    let request: serde_json::Value =
                        serde_json::from_slice(&fs::read(&path).context(IoSnafu { path: &path })?)
                            .context(JsonSnafu { path: &path })?;
                    if request
                        .pointer("/annotations/io.kubernetes.cri.sandbox-namespace")
                        .and_then(serde_json::Value::as_str)
                        == Some(namespace)
                        && request
                            .pointer("/annotations/io.kubernetes.cri.sandbox-name")
                            .and_then(serde_json::Value::as_str)
                            == Some(pod_name)
                        && request
                            .pointer("/annotations/io.kubernetes.cri.container-name")
                            .and_then(serde_json::Value::as_str)
                            == Some(container_name)
                    {
                        matching.push(path);
                    }
                }
                ensure!(
                    matching.len() <= 1,
                    InvalidInputSnafu {
                        path: request_directory,
                        reason: format!(
                            "more than one prestart request matched `{pod_name}/{container_name}`"
                        ),
                    }
                );
                Ok(matching.pop())
            },
        )
    }

    fn release_prestart(&self, request_path: &Path) -> Result<()> {
        let request: serde_json::Value = serde_json::from_slice(
            &fs::read(request_path).context(IoSnafu { path: request_path })?,
        )
        .context(JsonSnafu { path: request_path })?;
        let pid = request
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| invalid_state("prestart request has no valid release PID"))?;
        let release_path = request_path.with_extension("release");
        fs::write(&release_path, format!("accepted:{pid}\n")).context(IoSnafu {
            path: &release_path,
        })?;
        self.wait_for("prestart request release", request_path, || {
            Ok((!request_path.exists() && !release_path.exists()).then_some(()))
        })
    }

    fn reject_prestart(&self, request_path: &Path) -> Result<()> {
        let release_path = request_path.with_extension("release");
        fs::write(&release_path, b"rejected\n").context(IoSnafu {
            path: &release_path,
        })?;
        self.wait_for("prestart request rejection", request_path, || {
            Ok((!request_path.exists() && !release_path.exists()).then_some(()))
        })
    }

    fn settle_prestart_requests(&self, request_directory: &Path) -> Result<()> {
        if !request_directory.exists() {
            return Ok(());
        }
        let mut requests = Vec::new();
        for entry in fs::read_dir(request_directory).context(IoSnafu {
            path: request_directory,
        })? {
            let path = entry
                .context(IoSnafu {
                    path: request_directory,
                })?
                .path();
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                let release_path = path.with_extension("release");
                fs::write(&release_path, b"rejected\n").context(IoSnafu {
                    path: &release_path,
                })?;
                requests.push((path, release_path));
            }
        }
        thread::sleep(Duration::from_millis(500));
        for (request_path, release_path) in requests {
            for path in [&request_path, &release_path] {
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => return Err(source).context(IoSnafu { path }),
                }
            }
        }
        Ok(())
    }

    fn kubernetes_stock_hook_failure_result(
        &self,
        namespace: &str,
        pod_name: &str,
        expected_hook_message: &str,
        manifest_path: &Path,
    ) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let pod = self.kubernetes_output(
                &[
                    "kubectl", "-n", namespace, "get", "pod", pod_name, "-o", "json",
                ],
                "read the Kubernetes stock-hook failure Pod",
            )?;
            let pod: serde_json::Value = serde_json::from_str(&pod).context(JsonSnafu {
                path: manifest_path,
            })?;
            if let Some(waiting) = pod
                .pointer("/status/containerStatuses/0/state/waiting")
                .and_then(serde_json::Value::as_object)
            {
                let reason = waiting
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("UNKNOWN");
                let message = waiting
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if message.contains(expected_hook_message) {
                    return Ok(format!("{reason}: {message}"));
                }
            }

            let events = self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace,
                    "get",
                    "events",
                    "--field-selector",
                    &format!("involvedObject.name={pod_name}"),
                    "-o",
                    "json",
                ],
                "read the Kubernetes stock-hook failure events",
            )?;
            let events: serde_json::Value = serde_json::from_str(&events).context(JsonSnafu {
                path: manifest_path,
            })?;
            if let Some(result) = events
                .get("items")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|event| {
                    let message = event.get("message")?.as_str()?;
                    message.contains(expected_hook_message).then(|| {
                        let reason = event
                            .get("reason")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("UNKNOWN");
                        format!("{reason}: {message}")
                    })
                })
                .next()
            {
                return Ok(result);
            }

            let journal_program = Path::new("/usr/bin/journalctl");
            let journal = Command::new(journal_program)
                .args([
                    "-u",
                    "k3s",
                    "--since",
                    "2 minutes ago",
                    "--no-pager",
                    "-o",
                    "cat",
                ])
                .output()
                .context(IoSnafu {
                    path: journal_program,
                })?;
            ensure!(
                journal.status.success(),
                InvalidInputSnafu {
                    path: journal_program,
                    reason: format!(
                        "read the Kubernetes stock-hook journal failed with {}: {}",
                        journal.status,
                        String::from_utf8_lossy(&journal.stderr).trim()
                    ),
                }
            );
            if let Some(line) = String::from_utf8_lossy(&journal.stdout)
                .lines()
                .find(|line| line.contains(expected_hook_message))
            {
                return Ok(format!("K3S_JOURNAL: {line}"));
            }

            ensure!(
                Instant::now() < deadline,
                InvalidInputSnafu {
                    path: manifest_path,
                    reason: format!(
                        "timed out waiting for stock-hook result `{expected_hook_message}`"
                    ),
                }
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn physical_kubernetes_network_probe(
        &self,
        output_directory: &Path,
    ) -> Result<(bool, bool, bool)> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let work_directory = output_directory.join("kubernetes-network-probes");
        ensure!(
            !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes network-probe fixture directory already exists",
            }
        );
        fs::create_dir(&work_directory).context(IoSnafu {
            path: &work_directory,
        })?;
        let work_cleanup = ProbeDirectory::new(&work_directory);
        let namespace = format!("mithril-identity-network-{}", std::process::id());
        let manifest_path = work_directory.join("workload.yaml");
        let template_path = self.repo_root.join(
            "crates/mithril-e2e/fixtures/identity/kubernetes-network-probes-workload-v1.yaml",
        );
        let manifest = fs::read_to_string(&template_path).context(IoSnafu {
            path: &template_path,
        })?;
        fs::write(
            &manifest_path,
            manifest.replace("MITHRIL_IDENTITY_NETWORK_PROBE_NAMESPACE", &namespace),
        )
        .context(IoSnafu {
            path: &manifest_path,
        })?;
        let mut namespace_created = false;

        let probe = (|| -> Result<(bool, bool, bool)> {
            namespace_created = true;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "apply",
                    "-f",
                    manifest_path.to_string_lossy().as_ref(),
                ],
                "create the Kubernetes network-probe fixture",
            )?;
            self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "wait",
                    "--for=condition=Ready",
                    "pod/mithril-network-probes",
                    "--timeout=180s",
                ],
                "wait for the Kubernetes network probes",
            )?;

            let pod = self.kubernetes_output(
                &[
                    "kubectl",
                    "-n",
                    namespace.as_str(),
                    "get",
                    "pod",
                    "mithril-network-probes",
                    "-o",
                    "json",
                ],
                "read the Kubernetes network-probe Pod",
            )?;
            let pod: serde_json::Value = serde_json::from_str(&pod).context(JsonSnafu {
                path: &manifest_path,
            })?;
            let statuses = pod
                .pointer("/status/containerStatuses")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| invalid_state("network-probe Pod has no container statuses"))?;
            for name in ["http", "tcp", "grpc"] {
                let status = statuses
                    .iter()
                    .find(|status| {
                        status.get("name").and_then(serde_json::Value::as_str) == Some(name)
                    })
                    .ok_or_else(|| {
                        invalid_state(format!(
                            "network-probe Pod has no `{name}` container status"
                        ))
                    })?;
                ensure!(
                    status.get("ready").and_then(serde_json::Value::as_bool) == Some(true)
                        && status
                            .get("restartCount")
                            .and_then(serde_json::Value::as_u64)
                            == Some(0),
                    InvalidInputSnafu {
                        path: &manifest_path,
                        reason: format!(
                            "the `{name}` network probe did not pass without a restart"
                        ),
                    }
                );
            }

            let http = self.kubernetes_network_probe_container_no_task(
                &namespace,
                "http",
                &manifest_path,
            )?;
            let tcp =
                self.kubernetes_network_probe_container_no_task(&namespace, "tcp", &manifest_path)?;
            let grpc = self.kubernetes_network_probe_container_no_task(
                &namespace,
                "grpc",
                &manifest_path,
            )?;
            Ok((http, tcp, grpc))
        })();

        let namespace_cleanup = if namespace_created {
            self.kubernetes_output(
                &[
                    "kubectl",
                    "delete",
                    "namespace",
                    namespace.as_str(),
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=120s",
                ],
                "remove the Kubernetes network-probe fixture namespace",
            )
            .map(|_| ())
        } else {
            Ok(())
        };
        let cleanup = namespace_cleanup.and(work_cleanup.cleanup());
        if let Err(source) = probe {
            cleanup?;
            return Err(source);
        }
        cleanup?;
        ensure!(
            self.kubernetes_namespace_absent(&namespace)? && !work_directory.exists(),
            InvalidInputSnafu {
                path: &work_directory,
                reason: "the Kubernetes network-probe fixture was not removed",
            }
        );
        probe
    }

    fn kubernetes_network_probe_container_no_task(
        &self,
        namespace: &str,
        container_name: &str,
        manifest_path: &Path,
    ) -> Result<bool> {
        let container_id = self.wait_for(
            "Kubernetes network-probe container start",
            manifest_path,
            || {
                let inventory = self.kubernetes_output(
                    &["crictl", "ps", "-o", "json"],
                    "read the network-probe CRI inventory",
                )?;
                let inventory: serde_json::Value =
                    serde_json::from_str(&inventory).context(JsonSnafu {
                        path: manifest_path,
                    })?;
                Ok(inventory
                    .get("containers")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|containers| {
                        containers.iter().find_map(|container| {
                            let matching_namespace = container
                                .pointer("/labels/io.kubernetes.pod.namespace")
                                .and_then(serde_json::Value::as_str)
                                == Some(namespace);
                            let matching_name = container
                                .pointer("/metadata/name")
                                .and_then(serde_json::Value::as_str)
                                == Some(container_name);
                            (matching_namespace && matching_name)
                                .then(|| {
                                    container
                                        .get("id")
                                        .and_then(serde_json::Value::as_str)
                                        .map(str::to_owned)
                                })
                                .flatten()
                        })
                    }))
            },
        )?;
        let container = self.kubernetes_output(
            &["crictl", "inspect", container_id.as_str()],
            "inspect the network-probe container",
        )?;
        let container: serde_json::Value = serde_json::from_str(&container).context(JsonSnafu {
            path: manifest_path,
        })?;
        let init_pid = container
            .pointer("/info/pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| {
                invalid_state(format!(
                    "the `{container_name}` network-probe CRI PID is invalid"
                ))
            })?;
        let cgroup = self.kubernetes_cgroup_for_pid(init_pid)?;
        let procs_path = cgroup.join("cgroup.procs");
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let tasks = fs::read_to_string(&procs_path)
                .context(IoSnafu { path: &procs_path })?
                .split_ascii_whitespace()
                .map(|pid| {
                    pid.parse::<u32>().map_err(|source| {
                        invalid_state(format!(
                            "the `{container_name}` network-probe cgroup has invalid PID `{pid}`: {source}"
                        ))
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                tasks.len() == 1 && tasks.contains(&init_pid),
                InvalidInputSnafu {
                    path: &procs_path,
                    reason: format!(
                        "the `{container_name}` network probe created an in-container task: {tasks:?}"
                    ),
                }
            );
            if Instant::now() >= deadline {
                return Ok(true);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kubernetes_output(&self, arguments: &[&str], description: &str) -> Result<String> {
        let program = Path::new("/usr/local/bin/k3s");
        let output = Command::new(program)
            .args(arguments)
            .output()
            .context(IoSnafu { path: program })?;
        ensure!(
            output.status.success(),
            InvalidInputSnafu {
                path: program,
                reason: format!(
                    "{description} failed with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim(),
                ),
            }
        );
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn set_k3s_service(&self, action: &str) -> Result<()> {
        ensure!(
            matches!(action, "start" | "stop"),
            InvalidInputSnafu {
                path: Path::new("/usr/bin/systemctl"),
                reason: format!("unsupported K3s service action `{action}`"),
            }
        );
        let program = Path::new("/usr/bin/systemctl");
        let output = Command::new(program)
            .args([action, "k3s"])
            .output()
            .context(IoSnafu { path: program })?;
        ensure!(
            output.status.success(),
            InvalidInputSnafu {
                path: program,
                reason: format!(
                    "K3s service {action} failed with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim(),
                ),
            }
        );
        Ok(())
    }

    fn continue_host_pid(&self, host_pid: u32) -> Result<()> {
        let raw_pid = i32::try_from(host_pid)
            .map_err(|error| invalid_state(format!("host PID {host_pid} is invalid: {error}")))?;
        let pid = Pid::from_raw(raw_pid)
            .ok_or_else(|| invalid_state("host PID zero cannot identify a task"))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{host_pid}")),
            })?;
        pidfd_send_signal(&pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("continue host PID {host_pid}: {error}")))
    }

    fn stop_host_pid(&self, host_pid: u32) -> Result<()> {
        let raw_pid = i32::try_from(host_pid)
            .map_err(|error| invalid_state(format!("host PID {host_pid} is invalid: {error}")))?;
        let pid = Pid::from_raw(raw_pid)
            .ok_or_else(|| invalid_state("host PID zero cannot identify a task"))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{host_pid}")),
            })?;
        pidfd_send_signal(&pidfd, Signal::STOP)
            .map_err(|error| invalid_state(format!("stop host PID {host_pid}: {error}")))
    }

    fn stop_node_process(child: &mut Option<Child>) -> Result<()> {
        let Some(mut child) = child.take() else {
            return Ok(());
        };
        if child
            .try_wait()
            .context(IoSnafu {
                path: Path::new("mithril-node child"),
            })?
            .is_some()
        {
            return Err(invalid_state(
                "mithril-node exited before the restart boundary",
            ));
        }
        let raw_pid = i32::try_from(child.id()).map_err(|error| {
            invalid_state(format!(
                "mithril-node PID {} is invalid: {error}",
                child.id()
            ))
        })?;
        let pid = Pid::from_raw(raw_pid)
            .ok_or_else(|| invalid_state("mithril-node PID zero cannot identify a process"))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: Path::new("mithril-node child"),
            })?;
        pidfd_send_signal(&pidfd, Signal::INT)
            .map_err(|error| invalid_state(format!("stop mithril-node for restart: {error}")))?;
        for _attempt in 0..50 {
            if child
                .try_wait()
                .context(IoSnafu {
                    path: Path::new("mithril-node child"),
                })?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        child.kill().context(IoSnafu {
            path: Path::new("mithril-node child"),
        })?;
        child.wait().context(IoSnafu {
            path: Path::new("mithril-node child"),
        })?;
        Ok(())
    }

    fn wait_for_stopped_host_pid(&self, host_pid: u32, name: &str) -> Result<()> {
        let status_path = PathBuf::from(format!("/proc/{host_pid}/status"));
        self.wait_for(name, &status_path, || {
            let status =
                fs::read_to_string(&status_path).context(IoSnafu { path: &status_path })?;
            Ok(status
                .lines()
                .any(|line| line.starts_with("State:\tT"))
                .then_some(()))
        })
    }

    fn wait_for_k3s_ready(&self) -> Result<()> {
        self.wait_for(
            "Kubernetes node readiness",
            Path::new("/usr/local/bin/k3s"),
            || {
                let output = Command::new("/usr/local/bin/k3s")
                    .args([
                        "kubectl",
                        "wait",
                        "--for=condition=Ready",
                        "node",
                        "--all",
                        "--timeout=5s",
                    ])
                    .output()
                    .context(IoSnafu {
                        path: Path::new("/usr/local/bin/k3s"),
                    })?;
                Ok(output.status.success().then_some(()))
            },
        )
    }

    fn kubernetes_namespace_absent(&self, namespace: &str) -> Result<bool> {
        let program = Path::new("/usr/local/bin/k3s");
        let output = Command::new(program)
            .args(["kubectl", "get", "namespace", namespace])
            .output()
            .context(IoSnafu { path: program })?;
        if output.status.success() {
            return Ok(false);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            stderr.contains("NotFound") || stderr.contains("not found"),
            InvalidInputSnafu {
                path: program,
                reason: format!(
                    "cannot verify removal of Kubernetes namespace {namespace}: {}",
                    stderr.trim()
                ),
            }
        );
        Ok(true)
    }

    fn kubernetes_fixture_pid(&self, path: &Path) -> Result<Option<u32>> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path }),
        };
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let pid = text.parse::<u32>().map_err(|source| {
            invalid_state(format!(
                "Kubernetes fixture wrote an invalid namespace PID `{}`: {source}",
                text
            ))
        })?;
        Ok((pid > 0).then_some(pid))
    }

    fn kubernetes_fixture_slot_pids(&self, directory: &Path, slot: &str) -> Result<Vec<u32>> {
        let mut pids = BTreeSet::new();
        for entry in fs::read_dir(directory).context(IoSnafu { path: directory })? {
            let entry = entry.context(IoSnafu { path: directory })?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(name_pid) = file_name
                .strip_prefix(&format!("{slot}-"))
                .and_then(|name| name.strip_suffix(".pid"))
            else {
                continue;
            };
            let path = entry.path();
            let text = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let pid = text.parse::<u32>().map_err(|source| {
                invalid_state(format!(
                    "Kubernetes fixture wrote an invalid `{slot}` namespace PID `{}`: {source}",
                    text
                ))
            })?;
            ensure!(
                pid > 0 && name_pid == pid.to_string(),
                InvalidInputSnafu {
                    path: &path,
                    reason: "the Kubernetes fixture PID marker name and value differ",
                }
            );
            pids.insert(pid);
        }
        Ok(pids.into_iter().collect())
    }

    fn kubernetes_fixture_order(&self, directory: &Path, slot: &str) -> Result<Option<f64>> {
        let path = directory.join(format!("{slot}.order"));
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let order = text.parse::<f64>().map_err(|source| {
            invalid_state(format!(
                "Kubernetes fixture wrote an invalid `{slot}` order `{text}`: {source}"
            ))
        })?;
        ensure!(
            order.is_finite() && order > 0.0,
            InvalidInputSnafu {
                path: &path,
                reason: "the Kubernetes fixture order must be a positive finite value",
            }
        );
        Ok(Some(order))
    }

    fn kubernetes_release_fifo(&self, path: &Path) -> Result<()> {
        self.wait_for("Kubernetes fixture FIFO reader", path, || {
            let mut release = match fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
            {
                Ok(release) => release,
                Err(source)
                    if source.kind() == std::io::ErrorKind::NotFound
                        || source.raw_os_error() == Some(libc::ENXIO) =>
                {
                    return Ok(None)
                }
                Err(source) => return Err(source).context(IoSnafu { path }),
            };
            release.write_all(b"release\n").context(IoSnafu { path })?;
            Ok(Some(()))
        })
    }

    fn kubernetes_container_generation(&self, created_at: &serde_json::Value) -> Result<u64> {
        if let Some(generation) = created_at.as_u64().filter(|generation| *generation > 0) {
            return Ok(generation);
        }
        let created_at = created_at
            .as_str()
            .filter(|created_at| !created_at.is_empty())
            .ok_or_else(|| {
                invalid_state("CRI returned an invalid fixture container creation time")
            })?;
        let output = Command::new("date")
            .args(["--utc", "--date", created_at, "+%s%N"])
            .output()
            .context(IoSnafu {
                path: Path::new("date"),
            })?;
        ensure!(
            output.status.success(),
            InvalidInputSnafu {
                path: Path::new("date"),
                reason: format!(
                    "cannot convert the CRI container creation time `{created_at}`: {}",
                    String::from_utf8_lossy(&output.stderr).trim(),
                ),
            }
        );
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or_else(|| invalid_state("CRI container generation is invalid"))
    }

    fn kubernetes_cgroup_for_pid(&self, pid: u32) -> Result<PathBuf> {
        let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
        let cgroup = fs::read_to_string(&proc_path).context(IoSnafu { path: &proc_path })?;
        let cgroup_path = cgroup
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .map(|path| PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')))
            .ok_or_else(|| {
                invalid_state(format!("Kubernetes root PID {pid} has no unified cgroup"))
            })?;
        ensure!(
            cgroup_path.is_dir(),
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "Kubernetes root cgroup does not exist",
            }
        );
        Ok(cgroup_path)
    }

    fn kubernetes_host_pid(&self, cgroup: &Path, namespace_pid: u32) -> Result<Option<u32>> {
        let procs_path = cgroup.join("cgroup.procs");
        let procs = fs::read_to_string(&procs_path).context(IoSnafu { path: &procs_path })?;
        for process in procs.split_ascii_whitespace() {
            let Ok(host_pid) = process.parse::<u32>() else {
                continue;
            };
            let status_path = PathBuf::from(format!("/proc/{host_pid}/status"));
            let status = match fs::read_to_string(&status_path) {
                Ok(status) => status,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(source).context(IoSnafu { path: &status_path }),
            };
            let mapped_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .and_then(|line| line.split_ascii_whitespace().last())
                .and_then(|pid| pid.parse::<u32>().ok());
            if mapped_pid == Some(namespace_pid) {
                return Ok(Some(host_pid));
            }
        }
        Ok(None)
    }

    fn host_parent_pid(&self, host_pid: u32) -> Result<u32> {
        let status_path = PathBuf::from(format!("/proc/{host_pid}/status"));
        let status = fs::read_to_string(&status_path).context(IoSnafu { path: &status_path })?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:")?.split_ascii_whitespace().next())
            .and_then(|parent| parent.parse::<u32>().ok())
            .filter(|parent| *parent > 0)
            .ok_or_else(|| invalid_state(format!("host PID {host_pid} has no live parent PID")))
    }

    fn stop_fixture_process(child: &mut Option<Child>) {
        if let Some(mut child) = child.take() {
            let _result = child.kill();
            let _result = child.wait();
        }
    }
}

struct NativeProcessFixture {
    outer: Child,
    stdin: Option<ChildStdin>,
    stderr: Option<ChildStderr>,
    native_pid: Option<u32>,
    native_pidfd: Option<OwnedFd>,
    intermediate_pidfd: Option<OwnedFd>,
    namespace_init_pidfd: Option<OwnedFd>,
    parent_exit_mode: bool,
}

impl NativeProcessFixture {
    fn start() -> Result<Self> {
        Self::start_with_parent_exit(false)
    }

    fn start_orphaning() -> Result<Self> {
        Self::start_with_parent_exit(true)
    }

    fn start_subreaper() -> Result<Self> {
        let mut command = Command::new("python3");
        command.args([
            "-c",
            r#"import ctypes
import os
import signal
import sys

sys.stdin.readline()
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "set child subreaper")
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    os.waitpid(child, 0)
    os._exit(0)
os.waitpid(middle, 0)
os.waitpid(-1, 0)
"#,
        ]);
        Self::start_command(&mut command, false, Path::new("python3"))
    }

    fn start_namespace_init_reparenting() -> Result<Self> {
        let mut command = Command::new("/usr/bin/unshare");
        command.args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "python3",
            "-c",
            r#"import os
import signal
import sys

sys.stdin.readline()
middle = os.fork()
if middle == 0:
    os.kill(os.getpid(), signal.SIGSTOP)
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    os.waitpid(child, 0)
    os._exit(0)
os.waitpid(middle, 0)
os.waitpid(-1, 0)
"#,
        ]);
        Self::start_command(&mut command, false, Path::new("/usr/bin/unshare"))
    }

    fn start_pid_tid_reuse(work: &Path) -> Result<Self> {
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args([
                "--pid",
                "--fork",
                "--mount-proc",
                "python3",
                "-c",
                r#"import os
import sys
import threading
import time

work = sys.argv[1]
sys.stdin.readline()

def path(name):
    return os.path.join(work, name)

def mark(name, value="ready"):
    temporary = f"{path(name)}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{value}\n")
    os.replace(temporary, path(name))

def wait_for(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)

def process(name, release):
    mark(name, os.getpid())
    wait_for(release)
    os._exit(0)

first = os.fork()
if first == 0:
    process("process-first", "release-process-first")
os.waitpid(first, 0)
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(first - 1))
second = os.fork()
if second == 0:
    process("process-second", "release-process-second")
os.waitpid(second, 0)
mark("processes-done")

thread_ids = []
def worker(name, release):
    thread_ids.append(threading.get_native_id())
    mark(name, thread_ids[-1])
    wait_for(release)

wait_for("start-thread-first")
first_thread = threading.Thread(
    target=worker, args=("thread-first", "release-thread-first"))
first_thread.start()
first_thread.join()
mark("thread-first-done")
wait_for("start-thread-second")
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(thread_ids[0] - 1))
second_thread = threading.Thread(
    target=worker, args=("thread-second", "release-thread-second"))
second_thread.start()
second_thread.join()
mark("complete")
"#,
            ])
            .arg(work);
        Self::start_command(&mut command, false, Path::new("/usr/bin/unshare"))
    }

    fn start_double_forking() -> Result<Self> {
        Self::start_with_script(
            "read _; ( ( read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300 ) & wait ) & middle_pid=$!; wait \"$middle_pid\"; exec /bin/sleep 300",
            false,
        )
    }

    fn start_with_parent_exit(parent_exit_mode: bool) -> Result<Self> {
        let parent_wait = if parent_exit_mode {
            "read _"
        } else {
            "wait \"$!\""
        };
        let script = format!(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300) & {parent_wait}"
        );
        Self::start_with_script(&script, parent_exit_mode)
    }

    fn start_with_script(script: &str, parent_exit_mode: bool) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        Self::start_command(&mut command, parent_exit_mode, Path::new("/bin/sh"))
    }

    fn start_with_failed_exec(execfail: &Path, ready: &Path) -> Result<Self> {
        let mut command = Command::new("/bin/bash");
        command
            .args([
                "-c",
                "read _; /bin/bash -c 'read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; shopt -s execfail; exec \"$0\"; : > \"$1\"; kill -STOP \"$child_pid\"; exec /bin/sleep 300' \"$0\" \"$1\" & wait \"$!\"",
            ])
            .arg(execfail)
            .arg(ready);
        Self::start_command(&mut command, false, Path::new("/bin/bash"))
    }

    fn start_with_post_ponr_exec(execfail: &Path) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec \"$0\") & wait \"$!\"",
            ])
            .arg(execfail);
        Self::start_command(&mut command, false, Path::new("/bin/sh"))
    }

    fn start_with_leader_first_exit(ready: &Path, release: &Path) -> Result<Self> {
        let mut command = Command::new("python3");
        command
            .args([
                "-c",
                r#"import ctypes
import os
import sys
import threading
import time

ready = sys.argv[1]
release = sys.argv[2]
sys.stdin.readline()

def worker():
    temporary = f"{ready}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    os.replace(temporary, ready)
    while not os.path.exists(release):
        time.sleep(0.01)

thread = threading.Thread(target=worker)
thread.start()
while not os.path.exists(ready):
    time.sleep(0.01)
libc = ctypes.CDLL(None, use_errno=True)
libc.pthread_exit.argtypes = [ctypes.c_void_p]
libc.pthread_exit.restype = None
libc.pthread_exit(None)
raise RuntimeError("pthread_exit returned")
"#,
            ])
            .arg(ready)
            .arg(release);
        Self::start_command(&mut command, false, Path::new("python3"))
    }

    fn start_with_non_leader_exec(ready: &Path) -> Result<Self> {
        let mut command = Command::new("python3");
        command
            .args([
                "-c",
                r#"import os
import sys
import threading

ready = sys.argv[1]
release = threading.Event()
sys.stdin.readline()

def execute():
    with open(ready, "x", encoding="ascii") as output:
        output.write(f"{threading.get_native_id()}\n")
    release.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

thread = threading.Thread(target=execute)
thread.start()
sys.stdin.readline()
release.set()
thread.join()
"#,
            ])
            .arg(ready);
        Self::start_command(&mut command, false, Path::new("python3"))
    }

    #[cfg(test)]
    fn start_with_concurrent_thread_exec(ready: &Path) -> Result<Self> {
        let mut command = Command::new("python3");
        command
            .args([
                "-c",
                r#"import os
import sys
import threading

ready = sys.argv[1]
sys.stdin.readline()
release = threading.Event()
started = threading.Barrier(3)
racing = threading.Barrier(2)
thread_ids = []
thread_ids_lock = threading.Lock()

def execute():
    with thread_ids_lock:
        thread_ids.append(threading.get_native_id())
    started.wait()
    release.wait()
    racing.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

first = threading.Thread(target=execute)
second = threading.Thread(target=execute)
first.start()
second.start()
started.wait()
temporary = f"{ready}.tmp"
with open(temporary, "x", encoding="ascii") as output:
    output.write("\n".join(str(thread_id) for thread_id in thread_ids))
    output.write("\n")
os.replace(temporary, ready)
sys.stdin.readline()
release.set()
first.join()
second.join()
"#,
            ])
            .arg(ready);
        Self::start_command(&mut command, false, Path::new("python3"))
    }

    fn start_command(command: &mut Command, parent_exit_mode: bool, path: &Path) -> Result<Self> {
        let mut outer = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu { path })?;
        let stdin = outer
            .stdin
            .take()
            .ok_or_else(|| invalid_state("test shell has no stdin pipe"))?;
        let stderr = outer
            .stderr
            .take()
            .ok_or_else(|| invalid_state("test shell has no stderr pipe"))?;
        Ok(Self {
            outer,
            stdin: Some(stdin),
            stderr: Some(stderr),
            native_pid: None,
            native_pidfd: None,
            intermediate_pidfd: None,
            namespace_init_pidfd: None,
            parent_exit_mode,
        })
    }

    fn outer_pid(&self) -> u32 {
        self.outer.id()
    }

    fn open_native_pidfd(&mut self, pid: u32) -> Result<()> {
        self.native_pid = Some(pid);
        self.native_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    fn open_intermediate_pidfd(&mut self, pid: u32) -> Result<()> {
        self.intermediate_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    fn open_namespace_init_pidfd(&mut self, pid: u32) -> Result<()> {
        self.namespace_init_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    fn release_root(&mut self) -> Result<()> {
        self.write_stdin(b"root\n")
    }

    fn release_namespace_init(&mut self) -> Result<()> {
        self.write_stdin(b"namespace-init\n")
    }

    fn release_non_leader_exec(&mut self) -> Result<()> {
        self.write_stdin(b"exec\n")
    }

    #[cfg(test)]
    fn release_concurrent_thread_exec(&mut self) -> Result<()> {
        self.write_stdin(b"exec\n")
    }

    fn release_exec(&mut self, native_pid: u32) -> Result<()> {
        self.wait_for_stopped_native_child(native_pid)?;
        let pidfd = self
            .native_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("native child has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release native child exec: {error}")))
    }

    fn wait_for_stopped_native_child(&mut self, native_pid: u32) -> Result<()> {
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        let deadline = Instant::now() + WAIT_LIMIT;
        loop {
            let status = match fs::read_to_string(&status_path) {
                Ok(status) => status,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    let outer = self.outer.try_wait().context(IoSnafu {
                        path: Path::new("identity test shell"),
                    })?;
                    let stderr = if outer.is_some() {
                        self.stdin.take();
                        let mut stderr = String::new();
                        if let Some(mut pipe) = self.stderr.take() {
                            pipe.read_to_string(&mut stderr).context(IoSnafu {
                                path: Path::new("identity test shell stderr"),
                            })?;
                        }
                        format!("; outer {outer:?}; stderr {}", stderr.trim())
                    } else {
                        String::from("; outer still running")
                    };
                    return Err(invalid_state(format!(
                        "native child {native_pid} exited before it stopped for exec release{stderr}"
                    )));
                }
                Err(source) => return Err(source).context(IoSnafu { path: &status_path }),
            };
            if status.lines().any(|line| line.starts_with("State:\tT")) {
                break;
            }
            if Instant::now() >= deadline {
                let state = status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .unwrap_or("State: <missing>");
                return Err(invalid_state(format!(
                    "native child {native_pid} did not stop before exec release; last {state}"
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn wait_for_native_exec_failure(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.outer.try_wait().context(IoSnafu {
                path: Path::new("identity test shell"),
            })? {
                self.stdin.take();
                ensure!(
                    !status.success(),
                    InvalidInputSnafu {
                        path: Path::new("identity test shell"),
                        reason: format!("native child exec unexpectedly completed with {status}"),
                    }
                );
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                InvalidInputSnafu {
                    path: Path::new("identity test shell"),
                    reason: "native child exec did not fail before the short deadline",
                }
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_post_ponr_fatal(&mut self, native_pid: u32) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{native_pid}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.outer.try_wait().context(IoSnafu {
                path: Path::new("post-PONR identity fixture"),
            })? {
                self.stdin.take();
                ensure!(
                    !status.success() && !path.exists(),
                    InvalidInputSnafu {
                        path: &path,
                        reason: format!(
                            "post-PONR exec did not terminate its task; outer status {status}"
                        ),
                    }
                );
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                InvalidInputSnafu {
                    path: &path,
                    reason: "post-PONR exec failure did not terminate before the short deadline",
                }
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_successful_exit(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.outer.try_wait().context(IoSnafu {
                path: Path::new("leader-first identity fixture"),
            })? {
                self.stdin.take();
                ensure!(
                    status.success(),
                    InvalidInputSnafu {
                        path: Path::new("leader-first identity fixture"),
                        reason: format!("leader-first fixture exited with {status}"),
                    }
                );
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                InvalidInputSnafu {
                    path: Path::new("leader-first identity fixture"),
                    reason: "leader-first worker did not exit before the short deadline",
                }
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_parent_exit(&mut self) -> Result<()> {
        ensure!(
            self.parent_exit_mode,
            InvalidInputSnafu {
                path: Path::new("identity test shell"),
                reason: "native fixture does not have a parent-exit release",
            }
        );
        self.write_stdin(b"parent-exit\n")
    }

    fn release_intermediate_exit(&mut self) -> Result<()> {
        let pidfd = self
            .intermediate_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("double-fork intermediate has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::TERM)
            .map_err(|error| invalid_state(format!("release intermediate exit: {error}")))
    }

    fn release_intermediate_start(&mut self, intermediate_pid: u32) -> Result<()> {
        self.wait_for_stopped_native_child(intermediate_pid)?;
        let pidfd = self
            .intermediate_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("PID-namespace intermediate has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release intermediate start: {error}")))
    }

    fn intermediate_exited(&self, intermediate_pid: u32) -> Result<bool> {
        let path = PathBuf::from(format!("/proc/{intermediate_pid}/status"));
        match fs::read_to_string(&path) {
            Ok(status) => Ok(status.lines().any(|line| line.starts_with("State:\tZ"))),
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(libc::ESRCH) =>
            {
                Ok(true)
            }
            Err(source) => Err(source).context(IoSnafu { path: &path }),
        }
    }

    fn wait_for_parent_exit(&mut self) -> Result<()> {
        let status = self.outer.wait().context(IoSnafu {
            path: Path::new("identity test shell"),
        })?;
        ensure!(
            status.success(),
            InvalidInputSnafu {
                path: Path::new("identity test shell"),
                reason: format!("native parent exited with {status}"),
            }
        );
        self.stdin.take();
        Ok(())
    }

    fn write_stdin(&mut self, bytes: &[u8]) -> Result<()> {
        self.stdin
            .as_mut()
            .ok_or_else(|| invalid_state("test shell stdin is closed"))?
            .write_all(bytes)
            .context(IoSnafu {
                path: Path::new("test shell stdin"),
            })
    }

    fn native_child_pid(&mut self) -> Result<Option<u32>> {
        if let Some(status) = self.outer.try_wait().context(IoSnafu {
            path: Path::new("identity test shell"),
        })? {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("identity test shell stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "identity test shell exited before creating its child ({status}): {}",
                stderr.trim()
            )));
        }
        self.first_child_pid(self.outer.id())
    }

    fn non_leader_thread_tid(&mut self, ready: &Path) -> Result<Option<u32>> {
        if let Some(status) = self.outer.try_wait().context(IoSnafu {
            path: Path::new("non-leader thread fixture"),
        })? {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("non-leader thread fixture stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "non-leader thread fixture exited before it reported its TID ({status}): {}",
                stderr.trim()
            )));
        }
        let text = match fs::read_to_string(ready) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: ready }),
        };
        if text.trim().is_empty() {
            return Ok(None);
        }
        let tid = text.trim().parse::<u32>().map_err(|source| {
            invalid_state(format!(
                "non-leader thread fixture wrote an invalid TID `{}`: {source}",
                text.trim()
            ))
        })?;
        Ok(Some(tid))
    }

    fn reported_tid(&mut self, ready: &Path) -> Result<Option<u32>> {
        self.non_leader_thread_tid(ready)
    }

    #[cfg(test)]
    fn concurrent_thread_tids(&mut self, ready: &Path) -> Result<Option<[u32; 2]>> {
        if let Some(status) = self.outer.try_wait().context(IoSnafu {
            path: Path::new("concurrent thread fixture"),
        })? {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("concurrent thread fixture stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "concurrent thread fixture exited before it reported its TIDs ({status}): {}",
                stderr.trim()
            )));
        }
        let text = match fs::read_to_string(ready) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: ready }),
        };
        let mut tids = text
            .split_ascii_whitespace()
            .map(|value| {
                value.parse::<u32>().map_err(|source| {
                    invalid_state(format!(
                        "concurrent thread fixture wrote an invalid TID `{value}`: {source}"
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            tids.len() == 2,
            InvalidInputSnafu {
                path: ready,
                reason: format!(
                    "concurrent thread fixture must report two distinct TIDs, got {}",
                    tids.len()
                ),
            }
        );
        let first = tids
            .pop_first()
            .ok_or_else(|| invalid_state("first concurrent thread TID is missing"))?;
        let second = tids
            .pop_first()
            .ok_or_else(|| invalid_state("second concurrent thread TID is missing"))?;
        Ok(Some([first, second]))
    }

    fn intermediate_pid(&mut self) -> Result<Option<u32>> {
        self.native_child_pid()
    }

    fn intermediate_native_child_pid(&self, intermediate_pid: u32) -> Result<Option<u32>> {
        self.first_child_pid(intermediate_pid)
    }

    fn namespace_init_pid(&mut self) -> Result<Option<u32>> {
        self.native_child_pid()
    }

    fn namespace_init_intermediate_pid(&self, namespace_init_pid: u32) -> Result<Option<u32>> {
        self.first_child_pid(namespace_init_pid)
    }

    fn first_child_pid(&self, pid: u32) -> Result<Option<u32>> {
        let path = PathBuf::from(format!("/proc/{pid}/task/{pid}/children"));
        let children = match fs::read_to_string(&path) {
            Ok(children) => children,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };
        children
            .split_ascii_whitespace()
            .next()
            .map(|value| {
                value.parse().map_err(|error| {
                    invalid_state(format!("invalid native child PID `{value}`: {error}"))
                })
            })
            .transpose()
    }

    fn stop(&mut self) {
        if let Some(pidfd) = &self.native_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        if let Some(pidfd) = &self.intermediate_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        if let Some(pidfd) = &self.namespace_init_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        let _result = self.outer.kill();
        let _result = self.outer.wait();
        self.stdin.take();
    }
}

impl Drop for NativeProcessFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn test_binding(cgroup_path: &Path) -> WorkloadBindingConfig {
    WorkloadBindingConfig {
        binding_id: "4cd90188-e814-45ec-899f-4e3c9bca3801".to_owned(),
        scheduled_binding_authority_id: None,
        scheduled_target_digest: None,
        execution_set_id: "4cd90188-e814-45ec-899f-4e3c9bca3802".to_owned(),
        protected_scope_id: "4cd90188-e814-45ec-899f-4e3c9bca3804".to_owned(),
        workload_selector_id: "worker".to_owned(),
        profile_id: "4cd90188-e814-45ec-899f-4e3c9bca3803".to_owned(),
        container_id: "b".repeat(64),
        namespace: "default".to_owned(),
        cluster_uid: String::new(),
        namespace_uid: String::new(),
        controller_uid: String::new(),
        service_account_uid: String::new(),
        pod_labels: BTreeMap::new(),
        pod_uid: "identity-pod-uid".to_owned(),
        sandbox_id: "identity-sandbox".to_owned(),
        container_name: "worker".to_owned(),
        image_digest: "sha256:identity-fixture-image".to_owned(),
        container_kind: mithril_node::ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: Some(cgroup_path.to_path_buf()),
        lifecycle_generation: 1,
        active_profile_generation_ref_id: PROFILE_GENERATION_REF_ID,
        initial_role_id: 10,
        external_role_id: 11,
        arm_initial_root: false,
    }
}

fn profile_task_refs(host: &KernelHost) -> Result<u64> {
    let value = host
        .lookup_map(
            "profile_generation_task_refs",
            &PROFILE_GENERATION_REF_ID.to_ne_bytes(),
        )
        .context(InterceptorSnafu)?
        .ok_or_else(|| invalid_state("profile-generation reference state is missing"))?;
    read_u64(&value, 0, "profile-generation task references")
}

fn identity_next_id(host: &KernelHost) -> Result<u64> {
    let value = host
        .lookup_map("identity_config", &0_u32.to_ne_bytes())
        .context(InterceptorSnafu)?
        .ok_or_else(|| invalid_state("identity runtime configuration is missing"))?;
    IdentityRuntimeConfigV1::read_from_bytes(&value)
        .map(|config| config.next_id)
        .map_err(|error| {
            invalid_state(format!(
                "identity runtime configuration is invalid: {error}"
            ))
        })
}

fn map_ids(manifest: &KernelObjectManifestV1) -> BTreeMap<&str, u32> {
    manifest
        .maps
        .iter()
        .map(|map| (map.name.as_str(), map.id))
        .collect()
}

fn verify_recovery_rejects_displaced_map(
    config: &KernelHostConfig,
    manifest: &KernelObjectManifestV1,
) -> Result<()> {
    let record = manifest
        .maps
        .iter()
        .find(|map| map.name == "active_profile_generations")
        .ok_or_else(|| invalid_state("live manifest has no active-profile map"))?;
    ensure!(
        record.map_type == "Hash",
        InvalidInputSnafu {
            path: Path::new(&record.name),
            reason: "active-profile map is not a hash map",
        }
    );
    let pin = record
        .pin_path
        .as_deref()
        .ok_or_else(|| invalid_state("active-profile map has no pin path"))?;
    let displaced = pin
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid_state("active-profile map pin has no pin root"))?
        .join("recovery-original-active-profile-generations");
    ensure!(
        !displaced.exists(),
        InvalidInputSnafu {
            path: &displaced,
            reason: "recovery negative-fixture path already exists",
        }
    );
    fs::rename(pin, &displaced).context(IoSnafu { path: pin })?;

    let attempt = (|| {
        let options = libbpf_rs::libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let mut replacement = MapHandle::create(
            MapType::Hash,
            Some("recovery_map"),
            record.key_size,
            record.value_size,
            record.max_entries,
            &options,
        )
        .map_err(|error| invalid_state(format!("create same-layout replacement map: {error}")))?;
        replacement
            .pin(pin)
            .map_err(|error| invalid_state(format!("pin same-layout replacement map: {error}")))?;
        match KernelHostOwner::new(config.clone()).start() {
            Ok(host) => {
                host.shutdown().context(InterceptorSnafu)?;
                Ok(false)
            }
            Err(error) => Ok(error.to_string().contains("recovered maps")),
        }
    })();
    let remove = match fs::remove_file(pin) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source).context(IoSnafu { path: pin }),
    };
    let restore = fs::rename(&displaced, pin).context(IoSnafu { path: &displaced });
    let rejected = attempt?;
    remove?;
    restore?;
    ensure!(
        rejected,
        InvalidInputSnafu {
            path: pin,
            reason: "recovery accepted retained programs that use a displaced map",
        }
    );
    Ok(())
}

fn verify_live_manifest_negative_fixture(host: &KernelHost) -> Result<bool> {
    host.verify_live_manifest().context(InterceptorSnafu)?;
    let pin = host
        .manifest()
        .links
        .first()
        .and_then(|link| link.pin_path.as_ref())
        .ok_or_else(|| invalid_state("live manifest has no pinned link"))?;
    fs::remove_file(pin).context(IoSnafu { path: pin })?;
    let mismatch_detected = host.verify_live_manifest().is_err();
    ensure!(
        mismatch_detected,
        InvalidInputSnafu {
            path: pin,
            reason: "live manifest accepted a missing pinned link",
        }
    );
    Ok(true)
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let raw = i32::try_from(pid)
        .map_err(|error| invalid_state(format!("PID {pid} is out of range: {error}")))?;
    let pid = Pid::from_raw(raw).ok_or_else(|| invalid_state("PID zero cannot have a pidfd"))?;
    pidfd_open(pid, PidfdFlags::empty())
        .map_err(|error| invalid_state(format!("pidfd_open({raw}) failed: {error}")))
}

fn pid_in_own_namespace(host_pid: u32) -> Result<u32> {
    let path = PathBuf::from(format!("/proc/{host_pid}/status"));
    let status = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .and_then(|line| line.split_ascii_whitespace().last())
        .ok_or_else(|| invalid_state(format!("host PID {host_pid} has no NSpid record")))?
        .parse::<u32>()
        .map_err(|error| {
            invalid_state(format!("host PID {host_pid} has an invalid NSpid: {error}"))
        })
}

fn read_u64(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))?;
    Ok(u64::from_ne_bytes(value))
}

fn read_u8(bytes: &[u8], offset: usize, name: &str) -> Result<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))
}

fn read_u16(bytes: &[u8], offset: usize, name: &str) -> Result<u16> {
    let value = bytes
        .get(offset..offset + size_of::<u16>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize, name: &str) -> Result<u32> {
    let value = bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))?;
    Ok(u64::from_le_bytes(value))
}

fn read_uint(bytes: &[u8], offset: usize, size: usize, name: &str) -> Result<u64> {
    match size {
        4 => read_u32(bytes, offset, name).map(u64::from),
        8 => read_u64_le(bytes, offset, name),
        _ => Err(invalid_state(format!("{name} has unsupported size {size}"))),
    }
}

fn write_uint(bytes: &mut [u8], offset: usize, size: usize, value: u64, name: &str) -> Result<()> {
    let encoded = match size {
        4 => u32::try_from(value)
            .map_err(|error| invalid_state(format!("{name} does not fit ELF32: {error}")))?
            .to_le_bytes()
            .to_vec(),
        8 => value.to_le_bytes().to_vec(),
        _ => return Err(invalid_state(format!("{name} has unsupported size {size}"))),
    };
    let target = bytes
        .get_mut(offset..offset + size)
        .ok_or_else(|| invalid_state(format!("{name} is truncated")))?;
    target.copy_from_slice(&encoded);
    Ok(())
}

fn run_authorization_replay_fixture(
    state_directory: &Path,
    node_boot_id: Id128V1,
) -> Result<(String, u64)> {
    let now_utc_ns = 1_000_000_000_000_i64;
    let expires_at_utc_ns = now_utc_ns + 60_000_000_000;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let (envelope, body_sha256) = encode_fixture_signed_authorization(
        &signing_key,
        6,
        fixture_authorization_id(1),
        fixture_authorization_id(7),
        now_utc_ns,
        expires_at_utc_ns,
    )?;
    let trust = TrustBundleV1 {
        trust_domain_id: fixture_authorization_id(3),
        bundle_generation: 1,
        maximum_clock_skew_ns: 0,
        replay_window_size: 4096,
        issuers: vec![IssuerTrustV1 {
            issuer_id: fixture_authorization_id(4),
            key_id: b"operator-key".to_vec(),
            public_key: signing_key.verifying_key().to_bytes(),
            sequence_epoch: 5,
            valid_from_utc_ns: now_utc_ns - 1,
            valid_until_utc_ns: now_utc_ns + 120_000_000_000,
            revoked_at_utc_ns: None,
            allowed_intent_kinds: vec![8],
            allowed_tenant_ids: vec![fixture_authorization_id(2)],
        }],
    };
    let target = AuthorizationTargetV1 {
        tenant_id: fixture_authorization_id(2),
        trust_domain_id: fixture_authorization_id(3),
        issuer_id: fixture_authorization_id(4),
        intent_kind: 8,
        body_sha256,
    };
    let mut owner = AuthorizationProofOwner::load(
        state_directory,
        fixture_authorization_id(32),
        node_boot_id,
        trust.clone(),
    )
    .context(NodeSnafu)?;

    let retargeted = AuthorizationTargetV1 {
        body_sha256: [0x55; 32],
        ..target
    };
    ensure!(
        owner
            .verify_and_accept(&envelope, retargeted, now_utc_ns, 100)
            .is_err_and(|error| error.to_string().contains("exact target does not match")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization retarget did not reject before replay-state mutation",
        }
    );
    ensure!(
        owner
            .verify_and_accept(&envelope, target, expires_at_utc_ns + 1, 100)
            .is_err_and(|error| error
                .to_string()
                .contains("outside its trusted time interval")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "expired authorization did not reject before replay-state mutation",
        }
    );
    let mut signature_mismatch = envelope.clone();
    let last = signature_mismatch
        .last_mut()
        .ok_or_else(|| invalid_state("signed authorization fixture is empty"))?;
    *last ^= 1;
    ensure!(
        owner
            .verify_and_accept(&signature_mismatch, target, now_utc_ns, 100)
            .is_err_and(|error| error.to_string().contains("Ed25519 verification failed")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization signature mismatch did not reject",
        }
    );

    let fresh = owner
        .verify_and_accept(&envelope, target, now_utc_ns, 100)
        .context(NodeSnafu)?;
    ensure!(
        fresh.proof_id == fixture_authorization_id(1)
            && fresh.claim_slot_id == fixture_authorization_id(7)
            && fresh.sequence_epoch == 5
            && fresh.sequence == 6
            && fresh.body_sha256 == body_sha256,
        InvalidInputSnafu {
            path: state_directory,
            reason: "fresh authorization did not retain its exact signed identity",
        }
    );
    ensure!(
        owner
            .verify_and_accept(&envelope, target, now_utc_ns, 100)
            .is_err_and(|error| error.to_string().contains("replay WAL repeats identity")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "same-owner authorization replay did not reject",
        }
    );
    let (sequence_replay_envelope, sequence_replay_body_sha256) =
        encode_fixture_signed_authorization(
            &signing_key,
            6,
            fixture_authorization_id(10),
            fixture_authorization_id(11),
            now_utc_ns,
            expires_at_utc_ns,
        )?;
    ensure!(
        sequence_replay_body_sha256 == body_sha256,
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization sequence-replay control changed its exact target",
        }
    );
    drop(owner);

    let mut restarted = AuthorizationProofOwner::load(
        state_directory,
        fixture_authorization_id(32),
        node_boot_id,
        trust.clone(),
    )
    .context(NodeSnafu)?;
    ensure!(
        restarted
            .verify_and_accept(&sequence_replay_envelope, target, now_utc_ns, 100)
            .is_err_and(|error| error.to_string().contains("replay window")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization replay succeeded after owner restart",
        }
    );
    drop(restarted);

    let reboot_low = node_boot_id
        .low
        .checked_add(1)
        .unwrap_or_else(|| node_boot_id.low.saturating_sub(1));
    let reboot_boot_id = Id128V1::new(node_boot_id.high, reboot_low);
    ensure!(
        !reboot_boot_id.is_zero() && reboot_boot_id != node_boot_id,
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization reboot fixture did not create a distinct boot identity",
        }
    );
    let mut rebooted = AuthorizationProofOwner::load(
        state_directory,
        fixture_authorization_id(32),
        reboot_boot_id,
        trust,
    )
    .context(NodeSnafu)?;
    ensure!(
        rebooted
            .verify_and_accept(&envelope, target, now_utc_ns, 100)
            .is_err_and(|error| error.to_string().contains("replay WAL repeats identity")),
        InvalidInputSnafu {
            path: state_directory,
            reason: "authorization replay succeeded after boot identity changed",
        }
    );

    let (fresh_after_reboot_envelope, fresh_after_reboot_body_sha256) =
        encode_fixture_signed_authorization(
            &signing_key,
            7,
            fixture_authorization_id(8),
            fixture_authorization_id(9),
            now_utc_ns,
            expires_at_utc_ns,
        )?;
    ensure!(
        fresh_after_reboot_body_sha256 == body_sha256,
        InvalidInputSnafu {
            path: state_directory,
            reason: "fresh reboot authorization changed its exact target",
        }
    );
    let fresh_after_reboot = rebooted
        .verify_and_accept(&fresh_after_reboot_envelope, target, now_utc_ns, 100)
        .context(NodeSnafu)?;
    ensure!(
        fresh_after_reboot.proof_id == fixture_authorization_id(8)
            && fresh_after_reboot.claim_slot_id == fixture_authorization_id(9)
            && fresh_after_reboot.sequence == 7,
        InvalidInputSnafu {
            path: state_directory,
            reason: "fresh exact authorization failed after boot identity changed",
        }
    );
    drop(rebooted);

    let wal_path = state_directory.join("authorization-replay-v1.jsonl");
    let wal = fs::read(&wal_path).context(IoSnafu { path: &wal_path })?;
    let wal_records = u64::try_from(
        wal.split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
            .count(),
    )
    .map_err(|error| invalid_state(format!("authorization WAL record count overflow: {error}")))?;
    ensure!(
        wal.ends_with(b"\n") && wal_records == 5,
        InvalidInputSnafu {
            path: &wal_path,
            reason: format!("authorization replay WAL has {wal_records} records instead of 5"),
        }
    );
    Ok((crate::digest::DigestV1::of(wal).to_hex(), wal_records))
}

fn fixture_authorization_id(value: u64) -> Id128V1 {
    Id128V1::new(1, value)
}

fn fixture_portable_id(value: Id128V1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.high.to_be_bytes());
    bytes.extend_from_slice(&value.low.to_be_bytes());
    bytes
}

fn fixture_administrative_resolution() -> AdministrativeExecResolution {
    AdministrativeExecResolution {
        request_id: fixture_portable_id(fixture_authorization_id(19)),
        resolved: true,
        reason_code: "resolved".to_owned(),
        target_node_id: fixture_portable_id(fixture_authorization_id(32)),
        namespace: b"default".to_vec(),
        pod_uid: b"pod-uid".to_vec(),
        container_name: b"worker".to_vec(),
        full_container_id: vec![b'c'; 32],
        container_generation: 1,
        argv: vec![b"bash".to_vec()],
        stream_flags: 2,
        approved_role_id: "admin.exec".to_owned(),
        profile_id: fixture_portable_id(fixture_authorization_id(31)),
        profile_owner_generation: 1,
        profile_artifact_sha256: vec![9; 32],
        resolved_executable: Some(ResolvedAdministrativeExecutable {
            requested_name: b"bash".to_vec(),
            resolution_mode: 3,
            resolved_display_path: b"/usr/bin/bash".to_vec(),
            container_working_directory: b"/workspace".to_vec(),
            effective_path_entries: vec![b"/usr/local/bin".to_vec(), b"/usr/bin".to_vec()],
            target_mount_namespace_id: fixture_portable_id(fixture_authorization_id(30)),
            target_mount_topology_generation: 1,
            executable_object: Some(AdministrativeFileObject {
                mount_namespace_id: fixture_portable_id(fixture_authorization_id(30)),
                mount_topology_generation: 1,
                mount_id: 42,
                filesystem_instance_id: fixture_portable_id(fixture_authorization_id(33)),
                inode: 100,
                inode_generation: 2,
                exact_live_object_id: fixture_portable_id(fixture_authorization_id(34)),
                object_kind: 1,
                backing_identity: fixture_portable_id(fixture_authorization_id(35)),
                live_interval_id: fixture_portable_id(fixture_authorization_id(36)),
            }),
        }),
    }
}

fn encode_fixture_signed_authorization(
    signing_key: &SigningKey,
    sequence: u64,
    proof_id: Id128V1,
    claim_slot_id: Id128V1,
    issued_at_utc_ns: i64,
    expires_at_utc_ns: i64,
) -> Result<(Vec<u8>, [u8; 32])> {
    encode_administrative_authorization_fixture(
        signing_key,
        b"operator-key",
        fixture_authorization_id(2),
        fixture_authorization_id(22),
        fixture_authorization_id(3),
        fixture_authorization_id(4),
        5,
        sequence,
        proof_id,
        claim_slot_id,
        issued_at_utc_ns,
        expires_at_utc_ns,
        fixture_authorization_id(20),
        fixture_authorization_id(21),
        &fixture_administrative_resolution(),
    )
    .map_err(|error| invalid_state(format!("encode authorization fixture: {error}")))
}
fn id_key(value: &str) -> Result<[u8; 16]> {
    id_value(value).map(id_bytes)
}

fn id_value(value: &str) -> Result<Id128V1> {
    ensure!(
        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        InvalidInputSnafu {
            path: Path::new("native identity ID"),
            reason: format!("`{value}` is not a 128-bit identity"),
        }
    );
    let high = u64::from_str_radix(&value[..16], 16)
        .map_err(|error| invalid_state(format!("parse identity high word: {error}")))?;
    let low = u64::from_str_radix(&value[16..], 16)
        .map_err(|error| invalid_state(format!("parse identity low word: {error}")))?;
    Ok(Id128V1::new(high, low))
}

fn id_bytes(value: Id128V1) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.high.to_ne_bytes());
    bytes[8..].copy_from_slice(&value.low.to_ne_bytes());
    bytes
}

fn required_map_bytes(host: &KernelHost, map: &str, key: &[u8], name: &str) -> Result<Vec<u8>> {
    host.lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| invalid_state(format!("{name} is missing")))
}

fn optional_abi_map<T>(host: &KernelHost, map: &str, key: &[u8], name: &str) -> Result<Option<T>>
where
    T: KnownLayout + TryFromBytes,
{
    host.lookup_map(map, key)
        .context(InterceptorSnafu)?
        .map(|bytes| {
            T::try_read_from_bytes(&bytes)
                .map_err(|error| invalid_state(format!("{name} has an invalid value: {error}")))
        })
        .transpose()
}

fn required_abi_map<T>(host: &KernelHost, map: &str, key: &[u8], name: &str) -> Result<T>
where
    T: KnownLayout + TryFromBytes,
{
    optional_abi_map(host, map, key, name)?
        .ok_or_else(|| invalid_state(format!("{name} is missing")))
}

fn read_marker_pid(path: &Path) -> Result<Option<u32>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context(IoSnafu { path }),
    };
    let pid = text.trim().parse::<u32>().map_err(|error| {
        invalid_state(format!(
            "PID marker `{}` has an invalid value: {error}",
            path.display()
        ))
    })?;
    ensure!(
        pid > 0,
        InvalidInputSnafu {
            path,
            reason: "PID marker contains PID zero",
        }
    );
    Ok(Some(pid))
}

fn id128_hex(value: Id128V1) -> String {
    format!("{:016x}{:016x}", value.high, value.low)
}

fn host_thread_for_namespace_tid(host_tgid: u32, namespace_tid: u32) -> Result<Option<u32>> {
    let task_path = PathBuf::from(format!("/proc/{host_tgid}/task"));
    let entries = match fs::read_dir(&task_path) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source).context(IoSnafu { path: &task_path }),
    };
    for entry in entries {
        let entry = entry.context(IoSnafu { path: &task_path })?;
        let Some(host_tid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if host_tid != host_tgid && pid_in_own_namespace(host_tid)? == namespace_tid {
            return Ok(Some(host_tid));
        }
    }
    Ok(None)
}

fn invalid_state(reason: impl Into<String>) -> crate::Error {
    InvalidInputSnafu {
        path: Path::new("live identity state"),
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::PathBuf;
    use std::process::Command;

    use super::{
        IdentityTestRunner, NativeProcessFixture, IDENTITY_FIXTURES, REQUIRED_IDENTITY_MAPS,
    };

    #[test]
    fn production_object_and_identity_fixture_allocation_are_exact() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create identity test directory: {error}"))
        })?;
        let bundle = IdentityTestRunner::new(root).verify(temporary.path())?;
        assert_eq!(bundle.schema_version, 1);
        assert_eq!(bundle.layout.maps.len(), REQUIRED_IDENTITY_MAPS.len());
        assert_eq!(bundle.identity_fixture_ids.len(), IDENTITY_FIXTURES.len());
        Ok(())
    }

    #[test]
    fn authorization_replay_fixture_persists_exact_rejections_and_fresh_control(
    ) -> crate::Result<()> {
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create authorization fixture directory: {error}"))
        })?;
        let state = temporary.path().join("authorization-replay");
        let (wal_sha256, wal_records) =
            super::run_authorization_replay_fixture(&state, super::fixture_authorization_id(90))?;
        assert_eq!(wal_sha256.len(), 64);
        assert_eq!(wal_records, 5);
        Ok(())
    }

    #[test]
    fn native_process_fixture_waits_for_stopped_child_before_exec() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start()?;
        fixture.release_root()?;
        let children_path =
            PathBuf::from(format!("/proc/{0}/task/{0}/children", fixture.outer_pid()));
        let native_pid = runner.wait_for("native child creation", &children_path, || {
            fixture.native_child_pid()
        })?;
        fixture.open_native_pidfd(native_pid)?;
        fixture.release_exec(native_pid)?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("native child exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn post_ponr_fixture_terminates_the_exec_process() -> crate::Result<()> {
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create post-PONR test directory: {error}"))
        })?;
        let executable = temporary.path().join("post-ponr-execfail");
        IdentityTestRunner::materialize_post_ponr_execfail(&executable)?;
        let status = Command::new(&executable)
            .status()
            .map_err(|error| super::invalid_state(format!("execute post-PONR fixture: {error}")))?;
        assert!(!status.success());
        assert!(status.signal().is_some());
        Ok(())
    }

    #[test]
    fn leader_first_fixture_keeps_the_worker_until_release() -> crate::Result<()> {
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create leader-first test directory: {error}"))
        })?;
        let ready = temporary.path().join("ready");
        let release = temporary.path().join("release");
        let mut fixture = NativeProcessFixture::start_with_leader_first_exit(&ready, &release)?;
        fixture.release_root()?;
        let runner = IdentityTestRunner::new(".");
        let tid = runner.wait_for("leader-first unit worker", &ready, || {
            fixture.reported_tid(&ready)
        })?;
        assert_ne!(tid, fixture.outer_pid());
        fs::write(&release, b"release\n").map_err(|error| {
            super::invalid_state(format!("release leader-first unit worker: {error}"))
        })?;
        fixture.wait_for_successful_exit()?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_executes_after_subreaper_reparenting() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start_subreaper()?;
        let outer_pid = fixture.outer_pid();
        fixture.release_root()?;
        let children_path = PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
        let intermediate_pid =
            runner.wait_for("subreaper intermediate creation", &children_path, || {
                fixture.intermediate_pid()
            })?;
        fixture.open_intermediate_pidfd(intermediate_pid)?;
        let native_pid =
            runner.wait_for("subreaper native child creation", &children_path, || {
                fixture.intermediate_native_child_pid(intermediate_pid)
            })?;
        fixture.open_native_pidfd(native_pid)?;
        fixture.release_intermediate_exit()?;
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        runner.wait_for("subreaper native child adoption", &status_path, || {
            let status = fs::read_to_string(&status_path).map_err(|error| {
                super::invalid_state(format!("read {}: {error}", status_path.display()))
            })?;
            let parent_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:")?.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok());
            Ok(parent_pid.filter(|parent_pid| *parent_pid == outer_pid))
        })?;
        fixture.release_exec(native_pid)?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("subreaper native child exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_executes_after_namespace_init_reparenting() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start_namespace_init_reparenting()?;
        let outer_pid = fixture.outer_pid();
        let outer_children = PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
        let namespace_init_pid =
            runner.wait_for("PID-namespace init creation", &outer_children, || {
                fixture.namespace_init_pid()
            })?;
        fixture.open_namespace_init_pidfd(namespace_init_pid)?;
        assert_eq!(super::pid_in_own_namespace(namespace_init_pid)?, 1);
        fixture.release_namespace_init()?;
        let namespace_init_children = PathBuf::from(format!(
            "/proc/{namespace_init_pid}/task/{namespace_init_pid}/children"
        ));
        let intermediate_pid = runner.wait_for(
            "PID-namespace intermediate creation",
            &namespace_init_children,
            || fixture.namespace_init_intermediate_pid(namespace_init_pid),
        )?;
        fixture.open_intermediate_pidfd(intermediate_pid)?;
        fixture.release_intermediate_start(intermediate_pid)?;
        let native_pid = runner.wait_for(
            "PID-namespace native child creation",
            &namespace_init_children,
            || fixture.intermediate_native_child_pid(intermediate_pid),
        )?;
        fixture.open_native_pidfd(native_pid)?;
        fixture.release_intermediate_exit()?;
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        runner.wait_for("PID-namespace native child adoption", &status_path, || {
            let status = fs::read_to_string(&status_path).map_err(|error| {
                super::invalid_state(format!("read {}: {error}", status_path.display()))
            })?;
            let parent_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:")?.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok());
            Ok(parent_pid.filter(|parent_pid| *parent_pid == namespace_init_pid))
        })?;
        fixture.release_exec(native_pid)?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("PID-namespace native child exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_executes_non_leader_thread() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create non-leader thread test directory: {error}"))
        })?;
        let ready = temporary.path().join("non-leader-thread-ready");
        let mut fixture = NativeProcessFixture::start_with_non_leader_exec(&ready)?;
        let outer_pid = fixture.outer_pid();
        fs::write(&ready, b"")
            .map_err(|error| super::invalid_state(format!("write {}: {error}", ready.display())))?;
        assert_eq!(fixture.non_leader_thread_tid(&ready)?, None);
        fs::remove_file(&ready).map_err(|error| {
            super::invalid_state(format!("remove {}: {error}", ready.display()))
        })?;

        fixture.release_root()?;
        let thread_tid = runner.wait_for("non-leader Python thread creation", &ready, || {
            fixture.non_leader_thread_tid(&ready)
        })?;
        assert_ne!(thread_tid, outer_pid);
        assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{thread_tid}")).is_dir());

        fixture.release_non_leader_exec()?;
        let comm_path = PathBuf::from(format!("/proc/{outer_pid}/comm"));
        runner.wait_for("non-leader Python thread exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_races_two_thread_execs() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create concurrent thread test directory: {error}"))
        })?;
        let ready = temporary.path().join("concurrent-thread-ready");
        let mut fixture = NativeProcessFixture::start_with_concurrent_thread_exec(&ready)?;
        let outer_pid = fixture.outer_pid();

        fixture.release_root()?;
        let [first_thread_tid, second_thread_tid] =
            runner.wait_for("concurrent Python thread creation", &ready, || {
                fixture.concurrent_thread_tids(&ready)
            })?;
        assert_ne!(first_thread_tid, outer_pid);
        assert_ne!(second_thread_tid, outer_pid);
        assert_ne!(first_thread_tid, second_thread_tid);
        assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{first_thread_tid}")).is_dir());
        assert!(PathBuf::from(format!("/proc/{outer_pid}/task/{second_thread_tid}")).is_dir());

        fixture.release_concurrent_thread_exec()?;
        let comm_path = PathBuf::from(format!("/proc/{outer_pid}/comm"));
        runner.wait_for("concurrent Python thread exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_reports_failed_exec() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start_with_script(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /missing-native-exec) & wait \"$!\"",
            false,
        )?;
        fixture.release_root()?;
        let children_path =
            PathBuf::from(format!("/proc/{0}/task/{0}/children", fixture.outer_pid()));
        let native_pid = runner.wait_for("failed native child creation", &children_path, || {
            fixture.native_child_pid()
        })?;
        fixture.open_native_pidfd(native_pid)?;
        fixture.release_exec(native_pid)?;
        fixture.wait_for_native_exec_failure()
    }

    #[test]
    fn native_process_fixture_recovers_from_bash_execfail() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create exec-failure test directory: {error}"))
        })?;
        let execfail = temporary.path().join("execfail");
        let ready = temporary.path().join("execfail-ready");
        runner.materialize_execfail(&execfail)?;

        let mut fixture = NativeProcessFixture::start_with_failed_exec(&execfail, &ready)?;
        fixture.release_root()?;
        let children_path =
            PathBuf::from(format!("/proc/{0}/task/{0}/children", fixture.outer_pid()));
        let native_pid = runner.wait_for("Bash execfail child creation", &children_path, || {
            fixture.native_child_pid()
        })?;
        fixture.open_native_pidfd(native_pid)?;
        fixture.release_exec(native_pid)?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("Bash execfail recovery", &ready, || {
            if !ready.exists() {
                fixture.native_child_pid()?;
                return Ok(None);
            }
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "bash").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        fixture.release_exec(native_pid)?;
        runner.wait_for("Bash execfail later normal exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_reparents_a_stopped_child_before_exec() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start_orphaning()?;
        let outer_pid = fixture.outer_pid();
        fixture.release_root()?;
        let children_path = PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
        let native_pid =
            runner.wait_for("orphaned native child creation", &children_path, || {
                fixture.native_child_pid()
            })?;
        fixture.open_native_pidfd(native_pid)?;
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        let status = fs::read_to_string(&status_path).map_err(|error| {
            super::invalid_state(format!("read {}: {error}", status_path.display()))
        })?;
        assert!(status.lines().any(|line| line.starts_with("State:\tT")));

        fixture.release_parent_exit()?;
        fixture.wait_for_parent_exit()?;
        assert!(!PathBuf::from(format!("/proc/{outer_pid}")).exists());
        runner.wait_for("native child reparenting", &status_path, || {
            let status = fs::read_to_string(&status_path).map_err(|error| {
                super::invalid_state(format!("read {}: {error}", status_path.display()))
            })?;
            let parent_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:")?.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok());
            Ok(parent_pid.filter(|parent_pid| *parent_pid != outer_pid))
        })?;

        fixture.release_exec(native_pid)?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("orphaned native child exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }

    #[test]
    fn native_process_fixture_reparents_double_fork_child_before_exec() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start_double_forking()?;
        let outer_pid = fixture.outer_pid();
        fixture.release_root()?;
        let outer_children_path =
            PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
        let intermediate_pid = runner.wait_for(
            "double-fork intermediate creation",
            &outer_children_path,
            || fixture.intermediate_pid(),
        )?;
        fixture.open_intermediate_pidfd(intermediate_pid)?;
        let intermediate_children_path = PathBuf::from(format!(
            "/proc/{intermediate_pid}/task/{intermediate_pid}/children"
        ));
        let native_pid = runner.wait_for(
            "double-fork native child creation",
            &intermediate_children_path,
            || fixture.intermediate_native_child_pid(intermediate_pid),
        )?;
        fixture.open_native_pidfd(native_pid)?;
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        let status = fs::read_to_string(&status_path).map_err(|error| {
            super::invalid_state(format!("read {}: {error}", status_path.display()))
        })?;
        assert!(status.lines().any(|line| line.starts_with("State:\tT")));
        assert!(status
            .lines()
            .any(|line| line == format!("PPid:\t{intermediate_pid}")));

        fixture.release_intermediate_exit()?;
        runner.wait_for(
            "double-fork intermediate exit",
            &intermediate_children_path,
            || {
                fixture
                    .intermediate_exited(intermediate_pid)
                    .map(|exited| exited.then_some(()))
            },
        )?;
        assert!(PathBuf::from(format!("/proc/{outer_pid}")).exists());
        fixture.release_exec(native_pid)?;
        runner.wait_for("double-fork native child reparenting", &status_path, || {
            let status = fs::read_to_string(&status_path).map_err(|error| {
                super::invalid_state(format!("read {}: {error}", status_path.display()))
            })?;
            let parent_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:")?.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok());
            Ok(parent_pid.filter(|parent_pid| *parent_pid != intermediate_pid))
        })?;
        let comm_path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        runner.wait_for("double-fork native child exec", &comm_path, || {
            fs::read_to_string(&comm_path)
                .map(|name| (name.trim() == "sleep").then_some(()))
                .map_err(|error| {
                    super::invalid_state(format!("read {}: {error}", comm_path.display()))
                })
        })?;
        Ok(())
    }
}
