use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor::{
    bundled_bpf_sha256, KernelHost, KernelHostConfig, KernelHostOwner, KernelObjectLayoutV1,
    KernelObjectManifestV1, BUNDLED_BPF_OBJECT, REQUIRED_IDENTITY_PROGRAMS,
};
use erebor_interceptor_abi::{
    ExecGuardStateV1, Id128V1, ProcessExecutionStateV1, ProcessStateVectorStateV1,
    TaskCoordinateStateV1,
};
use mithril_node::{
    NativeIdentityInspector, NativeSecurityStateOwner, NativeTaskSnapshotV1, WorkloadBindingConfig,
    WorkloadBindingOwner,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::closure::ArchitectureClosure;
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(5);
const PROFILE_GENERATION_REF_ID: u64 = 7;

const REQUIRED_IDENTITY_MAPS: [&str; 20] = [
    "approved_exec_slots",
    "authority_domains",
    "created_by_edges",
    "entry_states",
    "execution_set_bindings",
    "external_root_classifications",
    "identity_config",
    "identity_health",
    "identity_scratch",
    "image_provenance",
    "kernel_real_parent_intervals",
    "pending_execs",
    "pending_administrative_matches",
    "process_execution_instances",
    "process_state_vectors",
    "process_states",
    "profile_generation_task_refs",
    "task_coordinates",
    "task_labels",
    "task_reference_tombstones",
];

const PHASE2_FIXTURES: [&str; 33] = [
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
    pub phase2_fixture_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityPhysicalProbeBundleV1 {
    pub schema_version: u32,
    pub object_sha256: String,
    pub first_start: KernelObjectManifestV1,
    pub external_root: NativeTaskSnapshotV1,
    pub native_child_before_exec: NativeTaskSnapshotV1,
    pub native_child_after_exec: NativeTaskSnapshotV1,
    pub profile_task_refs_after_exit: u64,
    pub recovered_start: KernelObjectManifestV1,
    pub map_ids_stable_across_restart: bool,
    pub pin_root_removed: bool,
    pub cgroup_removed: bool,
}

pub struct IdentityTestRunner {
    repo_root: PathBuf,
}

struct ProbePinRoot {
    path: PathBuf,
    cleaned: bool,
}

impl ProbePinRoot {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbePinRoot {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::remove_dir_all(&self.path);
        }
    }
}

struct ProbeCgroup {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeCgroup {
    fn create(path: &Path) -> Result<Self> {
        ensure!(
            !path.exists(),
            InvalidInputSnafu {
                path,
                reason: "the dedicated identity-test cgroup must not already exist",
            }
        );
        fs::create_dir(path).context(IoSnafu { path })?;
        let path = fs::canonicalize(path).context(IoSnafu { path })?;
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeCgroup {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::write(self.path.join("cgroup.kill"), b"1");
            let _result = fs::remove_dir(&self.path);
        }
    }
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
            fixtures == PHASE2_FIXTURES.into_iter().map(str::to_owned).collect(),
            InvalidInputSnafu {
                path: self.repo_root.join("spec/qualification/v1/fixtures.yaml"),
                reason: "Phase 2 fixture allocation differs from the phase plan",
            }
        );
        Ok(IdentityVerificationBundleV1 {
            schema_version: 1,
            object_path,
            object_sha256,
            layout,
            phase2_fixture_ids: fixtures.into_iter().collect(),
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
        let pin_cleanup = ProbePinRoot::new(pin_root);
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
            boot_id,
            1,
        );
        let mut host = KernelHostOwner::new(config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let first_start = host.manifest().clone();
        let binding = test_binding(&cgroup_path);
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_all(&host, std::slice::from_ref(&binding))
            .context(NodeSnafu)?;
        NativeSecurityStateOwner::new(node_boot_id, 1)
            .activate(&mut host)
            .context(NodeSnafu)?;
        let inspector = NativeIdentityInspector::new(pin_root);

        let mut fixture = NativeProcessFixture::start()?;
        fs::write(&procs_path, fixture.outer_pid().to_string())
            .context(IoSnafu { path: &procs_path })?;
        let external_root = self.wait_for("external root identity", &procs_path, || {
            inspector.snapshot(fixture.outer_pid()).context(NodeSnafu)
        })?;

        fixture.release_root()?;
        let native_pid = self.wait_for("native child creation", &procs_path, || {
            fixture.native_child_pid()
        })?;
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
        })?;
        fixture.stop();
        let profile_task_refs_after_exit =
            self.wait_for("profile reference release", &procs_path, || {
                let refs = profile_task_refs(&host)?;
                Ok((refs == 0).then_some(refs))
            })?;

        let first_map_ids = map_ids(&first_start);
        host.shutdown().context(InterceptorSnafu)?;
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
        cgroup_cleanup.cleanup()?;
        ensure!(
            !pin_root.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the identity-test pin root survived cleanup",
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
            schema_version: 1,
            object_sha256,
            first_start,
            external_root,
            native_child_before_exec: before_exec,
            native_child_after_exec: after_exec,
            profile_task_refs_after_exit,
            recovered_start,
            map_ids_stable_across_restart,
            pin_root_removed: true,
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
    native_pidfd: Option<OwnedFd>,
}

impl NativeProcessFixture {
    fn start() -> Result<Self> {
        let mut outer = Command::new("/bin/sh")
            .args([
                "-c",
                "read _; /bin/sh -c 'read _; exec /bin/sleep 30' & wait",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(IoSnafu {
                path: Path::new("/bin/sh"),
            })?;
        let stdin = outer
            .stdin
            .take()
            .ok_or_else(|| invalid_state("test shell has no stdin pipe"))?;
        Ok(Self {
            outer,
            stdin: Some(stdin),
            native_pidfd: None,
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
        self.write_stdin(b"exec\n")
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
        if self
            .outer
            .try_wait()
            .context(IoSnafu {
                path: Path::new("identity test shell"),
            })?
            .is_some()
        {
            return Err(invalid_state(
                "identity test shell exited before creating its child",
            ));
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
        profile_id: "4cd90188-e814-45ec-899f-4e3c9bca3803".to_owned(),
        container_id: "b".repeat(64),
        pod_uid: "phase2-pod-uid".to_owned(),
        sandbox_id: "phase2-sandbox".to_owned(),
        container_name: "worker".to_owned(),
        image_digest: "sha256:phase2-image".to_owned(),
        container_kind: mithril_node::ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: cgroup_path.to_path_buf(),
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

fn map_ids(manifest: &KernelObjectManifestV1) -> BTreeMap<&str, u32> {
    manifest
        .maps
        .iter()
        .map(|map| (map.name.as_str(), map.id))
        .collect()
}

fn boot_identity() -> Result<(String, Id128V1)> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let text = fs::read_to_string(path).context(IoSnafu { path })?;
    let uuid = uuid::Uuid::parse_str(text.trim())
        .map_err(|error| invalid_state(format!("kernel boot ID is invalid: {error}")))?;
    let value = uuid.as_u128();
    Ok((
        uuid.simple().to_string(),
        Id128V1::new((value >> 64) as u64, value as u64),
    ))
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
    use std::path::PathBuf;

    use super::{IdentityTestRunner, PHASE2_FIXTURES, REQUIRED_IDENTITY_MAPS};

    #[test]
    fn production_object_and_phase2_fixture_allocation_are_exact() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary = tempfile::tempdir().map_err(|error| {
            super::invalid_state(format!("create identity test directory: {error}"))
        })?;
        let bundle = IdentityTestRunner::new(root).verify(temporary.path())?;
        assert_eq!(bundle.schema_version, 1);
        assert_eq!(bundle.layout.maps.len(), REQUIRED_IDENTITY_MAPS.len());
        assert_eq!(bundle.phase2_fixture_ids.len(), PHASE2_FIXTURES.len());
        Ok(())
    }
}
