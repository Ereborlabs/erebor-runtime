mod clone3;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor::{
    bundled_bpf_sha256, Error as InterceptorError, KernelHost, KernelHostConfig, KernelHostOwner,
    KernelObjectLayoutV1, KernelObjectManifestV1, BUNDLED_BPF_OBJECT, REQUIRED_IDENTITY_PROGRAMS,
};
use erebor_interceptor_abi::{
    ExecGuardStateV1, IdentityRuntimeConfigV1, ProcessExecutionStateV1, ProcessStateVectorStateV1,
    TaskCoordinateStateV1,
};
use libbpf_rs::{MapHandle, MapType};
use mithril_node::{
    NativeIdentityInspector, NativeSecurityStateOwner, NativeTaskSnapshotV1, WorkloadBindingConfig,
    WorkloadBindingOwner,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};
use zerocopy::FromBytes as _;

use crate::closure::ArchitectureClosure;
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu};
use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::physical::{boot_identity, ProbeCgroup, ProbeDirectory, ProbeFile};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(30);
const PROFILE_GENERATION_REF_ID: u64 = 7;

const REQUIRED_IDENTITY_MAPS: [&str; 55] = [
    "active_profile_generations",
    "approved_exec_arguments",
    "approved_exec_slots",
    "authority_domains",
    "binding_activation_targets",
    "created_by_edges",
    "device_effect_decisions",
    "effect_decisions",
    "effect_defaults",
    "effect_observation_health",
    "effect_observations",
    "entry_states",
    "execution_set_bindings",
    "external_root_classifications",
    "exact_file_objects",
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
    "pending_administrative_matches",
    "mount_global_clean_epoch",
    "mount_global_mutation_epoch",
    "mount_global_pending_mutations",
    "mount_mutation_attempts",
    "mount_mutation_epochs",
    "mount_reconciliation_proposals",
    "mount_security_view_locks",
    "mount_security_views",
    "canonical_mount_roots",
    "path_graph_exact_transitions",
    "path_graph_terminals",
    "path_graph_wildcard_transitions",
    "policy_activation_probe_requests",
    "process_execution_instances",
    "process_control_rules",
    "process_state_vectors",
    "process_states",
    "profile_generation_descriptors",
    "profile_generation_async_refs",
    "profile_generation_task_refs",
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
        let closure = ArchitectureClosure::new(self.repo_root.join("spec")).verify()?;
        let fixtures = closure
            .fixtures
            .into_iter()
            .filter(|fixture| fixture.owning_phase == 2)
            .map(|fixture| fixture.fixture_id)
            .collect::<BTreeSet<_>>();
        ensure!(
            fixtures == IDENTITY_FIXTURES.into_iter().map(str::to_owned).collect(),
            InvalidInputSnafu {
                path: self.repo_root.join("spec/qualification/v1/fixtures.yaml"),
                reason: "identity fixture allocation differs from the acceptance registry",
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
        let non_leader_thread_ready_path = output_directory.join("non-leader-thread-ready");
        let cgroup_escape_sentinel_path = output_directory.join("cgroup-escape-sentinel");
        ensure!(
            !execfail_path.exists()
                && !execfail_ready_path.exists()
                && !non_leader_thread_ready_path.exists()
                && !cgroup_escape_sentinel_path.exists(),
            InvalidInputSnafu {
                path: output_directory,
                reason: "identity exec probe files must not already exist",
            }
        );
        let execfail_cleanup = ProbeFile::new(&execfail_path);
        let execfail_ready_cleanup = ProbeFile::new(&execfail_ready_path);
        let non_leader_thread_ready_cleanup = ProbeFile::new(&non_leader_thread_ready_path);
        let cgroup_escape_sentinel_cleanup = ProbeFile::new(&cgroup_escape_sentinel_path);
        self.materialize_execfail(&execfail_path)?;
        fs::write(
            &cgroup_escape_sentinel_path,
            b"identity cgroup escape sentinel\n",
        )
        .context(IoSnafu {
            path: &cgroup_escape_sentinel_path,
        })?;
        let object_sha256 = bundled_bpf_sha256();
        let (boot_id, node_boot_id) = boot_identity()?;
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
                reason: "concurrent indistinguishable external roots did not remain separate restricted roots",
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
        namespace_init_fixture.release_intermediate_start()?;
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
            .publish_all(&recovered, &[binding])
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
        recovered.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        cgroup_cleanup.cleanup()?;
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
            schema_version: 16,
            object_sha256,
            first_start,
            distinct_pin_root_owner_rejected,
            binding_gap_reconciled_root,
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
        ensure!(
            matches!(bundle.schema_version, 15 | 16)
                && (entry_results_missing || entry_results_present)
                && bundle.kubernetes_lifecycle_sleep_no_task.is_none(),
            InvalidInputSnafu {
                path: previous_bundle_path,
                reason: "the prior identity bundle cannot accept one Kubernetes result",
            }
        );
        bundle.schema_version = 16;
        if entry_results_missing {
            self.physical_kubernetes_exec_probe(
                output_directory,
                pin_root,
                lease_path,
                &mut bundle,
            )?;
        }
        bundle.kubernetes_lifecycle_sleep_no_task =
            Some(self.physical_kubernetes_lifecycle_sleep_probe(output_directory)?);
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

    fn wait_for<T, F>(&self, description: &str, path: &Path, mut inspect: F) -> Result<T>
    where
        F: FnMut() -> Result<Option<T>>,
    {
        let deadline = Instant::now() + WAIT_LIMIT;
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
        os.execv("/bin/sleep", ["/bin/sleep", "30"])
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

os.kill(os.getpid(), signal.SIGSTOP)
middle = os.fork()
if middle == 0:
    os.kill(os.getpid(), signal.SIGSTOP)
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "30"])
    os.waitpid(child, 0)
    os._exit(0)
os.waitpid(middle, 0)
os.waitpid(-1, 0)
"#,
        ]);
        Self::start_command(&mut command, false, Path::new("/usr/bin/unshare"))
    }

    fn start_double_forking() -> Result<Self> {
        Self::start_with_script(
            "read _; ( ( read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 30 ) & wait ) & middle_pid=$!; wait \"$middle_pid\"; exec /bin/sleep 30",
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
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 30) & {parent_wait}"
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
                "read _; /bin/bash -c 'read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; shopt -s execfail; exec \"$0\"; : > \"$1\"; kill -STOP \"$child_pid\"; exec /bin/sleep 30' \"$0\" \"$1\" & wait \"$!\"",
            ])
            .arg(execfail)
            .arg(ready);
        Self::start_command(&mut command, false, Path::new("/bin/bash"))
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
    os.execv("/bin/sleep", ["/bin/sleep", "30"])

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
    os.execv("/bin/sleep", ["/bin/sleep", "30"])

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

    fn release_namespace_init(&self) -> Result<()> {
        let pidfd = self
            .namespace_init_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("PID-namespace init has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release PID-namespace init: {error}")))
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

    fn release_intermediate_start(&self) -> Result<()> {
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
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(true),
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
        execution_set_id: "4cd90188-e814-45ec-899f-4e3c9bca3802".to_owned(),
        protected_scope_id: "4cd90188-e814-45ec-899f-4e3c9bca3804".to_owned(),
        workload_selector_id: "worker".to_owned(),
        profile_id: "4cd90188-e814-45ec-899f-4e3c9bca3803".to_owned(),
        container_id: "b".repeat(64),
        namespace: "default".to_owned(),
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
    use std::path::PathBuf;

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
        fixture.release_intermediate_start()?;
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
