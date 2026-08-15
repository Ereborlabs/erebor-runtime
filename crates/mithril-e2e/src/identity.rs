mod clone3;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::mem::size_of;
use std::os::fd::OwnedFd;
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
use serde::Serialize;
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

const IDENTITY_FIXTURES: [&str; 33] = [
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
    "EXEC-CONCURRENT-002",
    "ID-CGROUP-ESCAPE-001",
    "ID-CLONE-CGROUP-002",
    "ID-CLONE-CGROUP-FAIL-003",
    "ID-CREATOR-PARENT-007",
    "ID-MOVED-PARENT-FORK-004",
    "ID-MOVED-TASK-EXEC-005",
    "ID-TASK-COORD-FINALIZE-006",
    "NATIVE-STATE-REF-LIFETIME-001",
    "STATE-FORK-IPC-002",
    "STATE-THREAD-RACE-001",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityVerificationBundleV1 {
    pub schema_version: u32,
    pub object_path: PathBuf,
    pub object_sha256: String,
    pub layout: KernelObjectLayoutV1,
    pub identity_fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub object_sha256: String,
    pub first_start: KernelObjectManifestV1,
    pub distinct_pin_root_owner_rejected: bool,
    pub cgroup_escape_root: NativeTaskSnapshotV1,
    pub cgroup_escape_placement_mismatch_detected: bool,
    pub clone_into_cgroup_external_root: NativeTaskSnapshotV1,
    pub clone_into_cgroup_native_child: NativeTaskSnapshotV1,
    pub external_root: NativeTaskSnapshotV1,
    pub native_child_before_exec: NativeTaskSnapshotV1,
    pub native_child_after_exec: NativeTaskSnapshotV1,
    pub orphaned_native_parent: NativeTaskSnapshotV1,
    pub orphaned_native_child_before_parent_exit: NativeTaskSnapshotV1,
    pub orphaned_native_child_after_parent_exit: NativeTaskSnapshotV1,
    pub profile_task_refs_after_exit: u64,
    pub recovered_start: KernelObjectManifestV1,
    pub map_ids_stable_across_restart: bool,
    pub live_manifest_mismatch_detected: bool,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
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
        let binding = test_binding(&cgroup_path);
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        let identity = NativeSecurityStateOwner::new(node_boot_id, 1);
        identity.activate(&mut host).context(NodeSnafu)?;
        let inspector = NativeIdentityInspector::new(pin_root);

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
                && cgroup_escape_root.root_class == Some("external_runtime_root")
                && cgroup_escape_root.installed_role_class == Some("runtime_external_restricted")
                && health_after_escape.placement_mismatches
                    > health_before_escape.placement_mismatches,
            InvalidInputSnafu {
                path: &parent_procs_path,
                reason: "moving a labeled root out of its cgroup did not fail closed",
            }
        );
        escape_fixture.stop();

        let mut clone_fixture = CloneIntoCgroupFixture::start(&cgroup_path)?;
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
                && clone_external_root.root_class == Some("external_runtime_root")
                && clone_external_root.installed_role_class == Some("runtime_external_restricted")
                && clone_native_child.creator_task_cookie == Some(clone_external_root.task_cookie)
                && clone_native_child.real_parent_task_cookie == clone_external_root.task_cookie
                && clone_native_child.root_class.is_none()
                && clone_native_child.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "CLONE_INTO_CGROUP root or its native child has the wrong identity",
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
            before_exec.creator_task_cookie == Some(external_root.task_cookie)
                && before_exec.real_parent_task_cookie == external_root.task_cookie
                && before_exec.task_cookie != external_root.task_cookie
                && before_exec.image_provenance_id == external_root.image_provenance_id
                && before_exec.image_candidate_count > 0
                && before_exec.process_execution_state == ProcessExecutionStateV1::Active as u8
                && before_exec.process_state_vector_state
                    == ProcessStateVectorStateV1::Active as u8
                && before_exec.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: &procs_path,
                reason: "native child creator, cookie, or pre-wake coordinate is incorrect",
            }
        );

        fixture.release_exec()?;
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
            orphaned_native_parent.root_class == Some("external_runtime_root")
                && orphaned_native_parent.installed_role_class
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
        orphan_fixture.release_exec()?;
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
            schema_version: 2,
            object_sha256,
            first_start,
            distinct_pin_root_owner_rejected,
            cgroup_escape_root,
            cgroup_escape_placement_mismatch_detected: true,
            clone_into_cgroup_external_root: clone_external_root,
            clone_into_cgroup_native_child: clone_native_child,
            external_root,
            native_child_before_exec: before_exec,
            native_child_after_exec: after_exec,
            orphaned_native_parent,
            orphaned_native_child_before_parent_exit,
            orphaned_native_child_after_parent_exit,
            profile_task_refs_after_exit,
            recovered_start,
            map_ids_stable_across_restart,
            live_manifest_mismatch_detected,
            pin_root_removed: true,
            lease_removed: true,
            cgroup_removed: true,
        })
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
}

struct NativeProcessFixture {
    outer: Child,
    stdin: Option<ChildStdin>,
    stderr: Option<ChildStderr>,
    native_pidfd: Option<OwnedFd>,
    parent_exit_mode: bool,
}

impl NativeProcessFixture {
    fn start() -> Result<Self> {
        Self::start_with_parent_exit(false)
    }

    fn start_orphaning() -> Result<Self> {
        Self::start_with_parent_exit(true)
    }

    fn start_with_parent_exit(parent_exit_mode: bool) -> Result<Self> {
        let parent_wait = if parent_exit_mode { "read _" } else { "wait" };
        let script = format!(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 30) & {parent_wait}"
        );
        let mut outer = Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu {
                path: Path::new("/bin/sh"),
            })?;
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
            native_pidfd: None,
            parent_exit_mode,
        })
    }

    fn outer_pid(&self) -> u32 {
        self.outer.id()
    }

    fn open_native_pidfd(&mut self, pid: u32) -> Result<()> {
        self.native_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    fn release_root(&mut self) -> Result<()> {
        self.write_stdin(b"root\n")
    }

    fn release_exec(&mut self) -> Result<()> {
        let pidfd = self
            .native_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("native child has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release native child exec: {error}")))
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
        let pid = self.outer.id();
        let path = PathBuf::from(format!("/proc/{pid}/task/{pid}/children"));
        let children = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
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
            let _result = pidfd_send_signal(pidfd, Signal::TERM);
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
    fn native_process_fixture_pauses_its_child_before_exec() -> crate::Result<()> {
        let runner = IdentityTestRunner::new(".");
        let mut fixture = NativeProcessFixture::start()?;
        fixture.release_root()?;
        let children_path =
            PathBuf::from(format!("/proc/{0}/task/{0}/children", fixture.outer_pid()));
        let native_pid = runner.wait_for("native child creation", &children_path, || {
            fixture.native_child_pid()
        })?;
        fixture.open_native_pidfd(native_pid)?;
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        let status = fs::read_to_string(&status_path).map_err(|error| {
            super::invalid_state(format!("read {}: {error}", status_path.display()))
        })?;
        assert!(status.lines().any(|line| line.starts_with("State:\tT")));

        fixture.release_exec()?;
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

        fixture.release_exec()?;
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
}
