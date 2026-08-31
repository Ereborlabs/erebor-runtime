use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor::{KernelHost, KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExecGuardStateV1, Id128V1, KernelEffectFamilyV1,
    KernelEffectOperationV1, PendingExecStateV1, PendingExecV1, ProcessSecurityStateV1,
    TaskCoordinateStateV1,
};
use mithril_control::{
    lower_kubernetes_policy, policy_custom_resource, EffectFamilyV1, PathTreeDenyFloorV1,
    PolicyDispositionV1, WorkloadProtectionPolicySpec,
};
use mithril_node::{
    EffectObservationStore, NativeIdentityInspector, NativeSecurityStateOwner,
    NativeTaskSnapshotV1, NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use super::support::{
    effect_binding_with_identity, effect_node_config, wait_for_application_default_effect,
    wait_for_path_exec_effect, wait_for_reason, ExternalMountNamespace,
};
use super::{
    sign_generation_artifact, EffectTestRunner, NEXT_PROFILE_GENERATION_REF_ID,
    PROFILE_GENERATION_REF_ID,
};
use crate::error::{
    CommandSnafu, InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::identity::IdentityTestRunner;
use crate::physical::{boot_identity, ProbeDirectory, ProbeFile};
use crate::{DigestV1, Result};

const WAIT_LIMIT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuncEntryRoleRuntimeProbeV1 {
    pub schema_version: u32,
    pub runc_version: String,
    pub initial_host_pid: u32,
    pub prepared_state_before_exec: String,
    pub prepared_state_after_exec: String,
    pub prepared_runtime_effect_observed: bool,
    pub application_entry_allow_observed: bool,
    pub application_default_file_allow_observed: bool,
    pub application_descendant_default_exec_role_preserved: bool,
    pub held_runtime_admission_reconciled: bool,
    pub application_exec_transition_event_driven: bool,
    pub preexisting_child_bind_path_tree_denied: bool,
    pub path_tree_control_allowed: bool,
    pub application_admitted_entry_rule_id: u32,
    pub independent_entries: Vec<RuncEntryRoleProbeV1>,
    pub independent_entry_roles_are_distinct: bool,
    pub reusable_entry_reinvocation_isolated: bool,
    pub runtime_entry_infrastructure_observed: bool,
    pub live_replacement_preserved_running_application: bool,
    pub live_replacement_entries_use_new_generation: bool,
    pub node_owner_restart_preserved_running_application: bool,
    pub kernel_upgrade_preserved_map_ids: bool,
    pub kernel_upgrade_preserved_link_pins: bool,
    pub kernel_upgrade_replaced_changed_programs: bool,
    pub post_ponr_terminal_evidence_observed: bool,
    pub post_ponr_terminal_evidence_preserved: bool,
    pub inactive_generation_retired: bool,
    pub external_entry_denied: bool,
    pub external_cgroup_entering_process_stays_closed: bool,
    pub entry_executable_exact_objects_enforced: bool,
    pub dynamic_loader_paths: Vec<String>,
    pub dynamic_loader_paths_absent_from_policy: bool,
    pub container_exit_success: bool,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub fixture_root_removed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuncEntryRoleProbeV1 {
    pub name: String,
    pub declaration_name: String,
    pub host_pid: u32,
    pub task_cookie: u64,
    pub process_state_id: String,
    pub active_execution_id: String,
    pub profile_generation_ref_id: u64,
    pub active_role_id: u32,
    pub admitted_entry_rule_id: u32,
    pub exact_executable_object_enforced: bool,
    pub own_policy_deny_observed: bool,
    pub application_policy_not_inherited: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuncRetainedRuntimeGateProbeV1 {
    pub schema_version: u32,
    pub runc_version: String,
    pub hostile_container_denied: bool,
    pub hostile_process_never_started: bool,
    pub hostile_decision_logged: bool,
    pub exact_recovery_allowed: bool,
    pub exact_recovery_process_started: bool,
    pub exact_recovery_decision_logged: bool,
    pub changed_recovery_denied: bool,
    pub changed_recovery_process_never_started: bool,
    pub unavailable_decision_logged: bool,
    pub host_stock_spec_generated: bool,
    pub fixture_root_removed: bool,
}

struct RuncPolicyFixture {
    artifact_path: PathBuf,
    replacement_artifact_path: PathBuf,
    profile_id: String,
    protected_scope_id: String,
    execution_set_id: String,
    workload_selector_id: String,
    initial_role_id: u32,
    external_role_id: u32,
    role_ids: BTreeMap<String, u32>,
}

struct RuncContainer {
    child: Option<Child>,
    runc_path: PathBuf,
    state_root: PathBuf,
    container_id: String,
    cgroup_path: PathBuf,
}

struct RetainedRuntimeGateRuncFixture {
    fixture_root: PathBuf,
    bundle: PathBuf,
    marker_directory: PathBuf,
    manifest: PathBuf,
    runc_path: PathBuf,
    hook_path: PathBuf,
    k3s_path: PathBuf,
    output_directory: PathBuf,
    recovery_args: Vec<String>,
    stock_config: serde_json::Value,
}

struct RetainedRuntimeGateCaseResult {
    success: bool,
    stdout: String,
    stderr: String,
}

impl RetainedRuntimeGateRuncFixture {
    fn create(
        output_directory: &Path,
        runc_path: &Path,
        hook_path: &Path,
        k3s_path: &Path,
        nsenter_path: &Path,
    ) -> Result<Self> {
        let fixture_root = output_directory.join("runc-retained-runtime-gate-fixture");
        ensure!(
            !fixture_root.exists(),
            InvalidInputSnafu {
                path: &fixture_root,
                reason: "the direct runc retained-gate fixture must start absent",
            }
        );
        let bundle = fixture_root.join("bundle");
        let rootfs = bundle.join("rootfs");
        let marker_directory = fixture_root.join("markers");
        fs::create_dir_all(rootfs.join("bin")).context(IoSnafu { path: &rootfs })?;
        fs::create_dir(&marker_directory).context(IoSnafu {
            path: &marker_directory,
        })?;
        Self::copy_executable(&rootfs, Path::new("/bin/sh"), Path::new("/bin/sh"))?;
        Self::copy_executable(&rootfs, nsenter_path, nsenter_path)?;
        run_checked(
            Command::new(runc_path).args(["spec", "--bundle", bundle.to_string_lossy().as_ref()]),
            runc_path,
        )?;
        let config_path = bundle.join("config.json");
        let stock_config = serde_json::from_slice(
            &fs::read(&config_path).context(IoSnafu { path: &config_path })?,
        )
        .context(JsonSnafu { path: &config_path })?;

        let shell = rootfs.join("bin/sh");
        let shell_digest = format!(
            "{:x}",
            Sha256::digest(fs::read(&shell).context(IoSnafu { path: &shell })?)
        );
        let mut recovery_args = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf RECOVERY_ALLOWED >/result/recovery".to_owned(),
        ];
        recovery_args.extend((0..35).map(|index| format!("recovery-argument-{index}")));
        let manifest = fixture_root.join("mithril-recovery.json");
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "entries": [{
                    "executable": "/bin/sh",
                    "executableSha256": shell_digest,
                    "args": recovery_args,
                    "requiredMounts": [{
                        "source": marker_directory,
                        "destination": "/result",
                        "readOnly": false
                    }]
                }]
            }))
            .context(JsonSnafu { path: &manifest })?,
        )
        .context(IoSnafu { path: &manifest })?;

        Ok(Self {
            fixture_root,
            bundle,
            marker_directory,
            manifest,
            runc_path: runc_path.to_path_buf(),
            hook_path: hook_path.to_path_buf(),
            k3s_path: k3s_path.to_path_buf(),
            output_directory: output_directory.to_path_buf(),
            recovery_args,
            stock_config,
        })
    }

    fn copy_executable(rootfs: &Path, source: &Path, destination: &Path) -> Result<()> {
        let destination = destination.strip_prefix("/").map_err(|error| {
            InvalidInputSnafu {
                path: destination,
                reason: format!("rootfs executable path is not absolute: {error}"),
            }
            .build()
        })?;
        let destination = rootfs.join(destination);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        fs::copy(source, &destination).context(IoSnafu { path: source })?;
        let output = Command::new("ldd").arg(source).output().context(IoSnafu {
            path: Path::new("ldd"),
        })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "ldd".to_owned(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        for dependency in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(ldd_dependency_path)
        {
            let source = Path::new(&dependency);
            let relative = source.strip_prefix("/").map_err(|error| {
                InvalidInputSnafu {
                    path: source,
                    reason: format!("dynamic-loader path is not absolute: {error}"),
                }
                .build()
            })?;
            let target = rootfs.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
            }
            fs::copy(source, &target).context(IoSnafu { path: source })?;
        }
        Ok(())
    }

    fn run_hostile(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let mut config = self.stock_config("hostile")?;
        config["process"]["args"] = json!([
            "/bin/sh",
            "-c",
            "read line </host/etc/shadow; printf HOSTILE_RAN >/result/hostile"
        ]);
        self.add_bind_mount(&mut config, Path::new("/"), Path::new("/host"), false)?;
        self.run_case("hostile", config)
    }

    fn run_exact_recovery(&self) -> Result<RetainedRuntimeGateCaseResult> {
        self.run_case("exact-recovery", self.exact_recovery_config()?)
    }

    fn run_changed_recovery(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let mut config = self.stock_config("changed-recovery")?;
        config["process"]["args"] = json!([
            "/bin/sh",
            "-c",
            "printf CHANGED_RECOVERY_RAN >/result/changed-recovery"
        ]);
        self.run_case("changed-recovery", config)
    }

    fn run_host_stock_spec(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let mut config = self.stock_config("host-stock-spec")?;
        // nsenter needs SYS_PTRACE to open the target namespace and SYS_ADMIN
        // plus SYS_CHROOT to join its mount namespace.
        config["process"]["capabilities"] = json!({
            "bounding": ["CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE"],
            "effective": ["CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE"],
            "permitted": ["CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE"]
        });
        config
            .as_object_mut()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: self.bundle.join("config.json"),
                    reason: "the generated runc spec is not an object",
                }
                .build()
            })?
            .remove("hooks");
        config["process"]["args"] = json!([
            "/usr/bin/nsenter",
            "--target",
            "1",
            "--mount",
            "--",
            self.k3s_path,
            "ctr",
            "oci",
            "spec"
        ]);
        self.run_case("host-stock-spec", config)
    }

    fn stock_config(&self, case: &str) -> Result<serde_json::Value> {
        let config_path = self.bundle.join("config.json");
        let mut config = self.stock_config.clone();
        config["process"]["terminal"] = json!(false);
        config["process"]["cwd"] = json!("/");
        config["process"]["env"] = json!(["PATH=/bin"]);
        config["process"]["noNewPrivileges"] = json!(false);
        config["process"]["capabilities"] = json!({
            "bounding": ["CAP_SYS_ADMIN"],
            "effective": ["CAP_SYS_ADMIN"],
            "permitted": ["CAP_SYS_ADMIN"]
        });
        config["root"]["path"] = json!("rootfs");
        config["root"]["readonly"] = json!(false);
        config["linux"]["cgroupsPath"] =
            json!(format!("/mithril-runc-gate-{}-{case}", std::process::id()));
        let namespaces = config["linux"]["namespaces"]
            .as_array_mut()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &config_path,
                    reason: "the generated runc spec has no namespace array",
                }
                .build()
            })?;
        let pid_namespace = namespaces
            .iter_mut()
            .find(|namespace| namespace["type"] == "pid")
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &config_path,
                    reason: "the generated runc spec has no PID namespace",
                }
                .build()
            })?;
        pid_namespace["path"] = json!("/proc/1/ns/pid");
        config["annotations"] = json!({
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.container-id": format!("{:064x}", Sha256::digest(case.as_bytes()))
        });
        config["hooks"] = json!({
            "createRuntime": [{
                "path": self.hook_path,
                "args": [
                    "mithril-oci-hook", "run", "--stage", "stage-runtime-facts",
                    "--socket", self.fixture_root.join("absent-runtime-admission.sock"),
                    "--recovery-manifest", self.manifest,
                    "--timeout-ms", "100"
                ],
                "env": ["RUST_LOG=debug"],
                "timeout": 2
            }]
        });
        self.add_bind_mount(
            &mut config,
            &self.marker_directory,
            Path::new("/result"),
            false,
        )?;
        Ok(config)
    }

    fn exact_recovery_config(&self) -> Result<serde_json::Value> {
        let mut config = self.stock_config("exact-recovery")?;
        config["process"]["args"] = json!(self.recovery_args);
        Ok(config)
    }

    fn exact_recovery_log(&self) -> Result<String> {
        let config_path = self.bundle.join("config.json");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&self.exact_recovery_config()?)
                .context(JsonSnafu { path: &config_path })?,
        )
        .context(IoSnafu { path: &config_path })?;
        let state = serde_json::to_vec(&json!({
            "id": format!("{:064x}", Sha256::digest(b"exact-recovery-log")),
            "pid": 1,
            "bundle": self.bundle,
            "annotations": {}
        }))
        .context(JsonSnafu { path: &config_path })?;
        let mut child = Command::new(&self.hook_path)
            .args([
                "run",
                "--stage",
                "stage-runtime-facts",
                "--socket",
                self.fixture_root
                    .join("absent-runtime-admission.sock")
                    .to_string_lossy()
                    .as_ref(),
                "--recovery-manifest",
                self.manifest.to_string_lossy().as_ref(),
                "--timeout-ms",
                "100",
            ])
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu {
                path: &self.hook_path,
            })?;
        child
            .stdin
            .take()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &self.hook_path,
                    reason: "the direct hook log probe has no stdin",
                }
                .build()
            })?
            .write_all(&state)
            .context(IoSnafu {
                path: &self.hook_path,
            })?;
        let output = child.wait_with_output().context(IoSnafu {
            path: &self.hook_path,
        })?;
        ensure!(
            output.status.success() && output.stdout.is_empty(),
            CommandSnafu {
                program: self.hook_path.display().to_string(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        Ok(String::from_utf8_lossy(&output.stderr).into_owned())
    }

    fn add_bind_mount(
        &self,
        config: &mut serde_json::Value,
        source: &Path,
        destination: &Path,
        read_only: bool,
    ) -> Result<()> {
        let config_path = self.bundle.join("config.json");
        let mounts = config["mounts"].as_array_mut().ok_or_else(|| {
            InvalidInputSnafu {
                path: &config_path,
                reason: "the generated runc spec has no mount array",
            }
            .build()
        })?;
        mounts.push(json!({
            "destination": destination,
            "type": "bind",
            "source": source,
            "options": if read_only { vec!["rbind", "ro"] } else { vec!["rbind", "rw"] }
        }));
        Ok(())
    }

    fn run_case(
        &self,
        case: &str,
        config: serde_json::Value,
    ) -> Result<RetainedRuntimeGateCaseResult> {
        let config_path = self.bundle.join("config.json");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
        )
        .context(IoSnafu { path: &config_path })?;
        let container_id = format!("{:064x}", Sha256::digest(case.as_bytes()));
        let state_root = self.fixture_root.join("runc-state");
        fs::create_dir_all(&state_root).context(IoSnafu { path: &state_root })?;
        let output = Command::new(&self.runc_path)
            .args(["--root", state_root.to_string_lossy().as_ref()])
            .args(["run", "--bundle", self.bundle.to_string_lossy().as_ref()])
            .arg(&container_id)
            .output()
            .context(IoSnafu {
                path: &self.runc_path,
            })?;
        let _cleanup = Command::new(&self.runc_path)
            .args(["--root", state_root.to_string_lossy().as_ref()])
            .args(["delete", "--force", &container_id])
            .output();
        let stdout_path = self
            .output_directory
            .join(format!("runc-gate-{case}.stdout"));
        let stderr_path = self
            .output_directory
            .join(format!("runc-gate-{case}.stderr"));
        fs::write(&stdout_path, &output.stdout).context(IoSnafu { path: &stdout_path })?;
        fs::write(&stderr_path, &output.stderr).context(IoSnafu { path: &stderr_path })?;
        Ok(RetainedRuntimeGateCaseResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn marker_exists(&self, name: &str) -> bool {
        self.marker_directory.join(name).is_file()
    }

    fn cleanup(&self) -> Result<()> {
        if self.fixture_root.exists() {
            fs::remove_dir_all(&self.fixture_root).context(IoSnafu {
                path: &self.fixture_root,
            })?;
        }
        Ok(())
    }
}

impl Drop for RetainedRuntimeGateRuncFixture {
    fn drop(&mut self) {
        let _result = self.cleanup();
    }
}

impl RuncContainer {
    fn set_frozen(&self, frozen: bool) -> Result<()> {
        let freeze_path = self.cgroup_path.join("cgroup.freeze");
        let events_path = self.cgroup_path.join("cgroup.events");
        fs::write(&freeze_path, if frozen { b"1" } else { b"0" })
            .context(IoSnafu { path: &freeze_path })?;
        let expected = format!("frozen {}", u8::from(frozen));
        let deadline = Instant::now() + WAIT_LIMIT;
        while Instant::now() < deadline {
            let events =
                fs::read_to_string(&events_path).context(IoSnafu { path: &events_path })?;
            if events.lines().any(|line| line == expected) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        InvalidInputSnafu {
            path: &events_path,
            reason: format!("the direct runc cgroup did not reach `{expected}`"),
        }
        .fail()
    }

    fn process_state_key(process_state_id: &str, evidence_path: &Path) -> Result<[u8; 16]> {
        ensure!(
            process_state_id.len() == 32
                && process_state_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            InvalidInputSnafu {
                path: evidence_path,
                reason: format!("`{process_state_id}` is not a process-state identity"),
            }
        );
        let high = u64::from_str_radix(&process_state_id[..16], 16).map_err(|error| {
            InvalidInputSnafu {
                path: evidence_path,
                reason: format!("process-state identity has an invalid high word: {error}"),
            }
            .build()
        })?;
        let low = u64::from_str_radix(&process_state_id[16..], 16).map_err(|error| {
            InvalidInputSnafu {
                path: evidence_path,
                reason: format!("process-state identity has an invalid low word: {error}"),
            }
            .build()
        })?;
        let id = Id128V1::new(high, low);
        let mut key = [0_u8; 16];
        key[..8].copy_from_slice(&id.high.to_ne_bytes());
        key[8..].copy_from_slice(&id.low.to_ne_bytes());
        Ok(key)
    }

    fn verify_exec_transition_event_path(
        &self,
        host: &mut KernelHost,
        identity: &NativeSecurityStateOwner,
        inspector: &NativeIdentityInspector,
        application: &NativeTaskSnapshotV1,
        evidence_path: &Path,
    ) -> Result<bool> {
        let process_key = Self::process_state_key(&application.process_state_id, evidence_path)?;
        let process_bytes = host
            .lookup_map("process_states", &process_key)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: evidence_path,
                    reason: "the application process state disappeared before reconciliation"
                        .to_owned(),
                }
                .build()
            })?;
        let stable_process =
            ProcessSecurityStateV1::try_read_from_bytes(&process_bytes).map_err(|error| {
                InvalidInputSnafu {
                    path: evidence_path,
                    reason: format!("the application process state has invalid ABI: {error}"),
                }
                .build()
            })?;
        let before = identity.health(host).context(NodeSnafu)?;
        let mut commit_pending = stable_process;
        commit_pending.exec_guard_state = ExecGuardStateV1::CommitPending;
        self.set_frozen(true)?;
        let transition_health = (|| {
            host.update_map("process_states", &process_key, commit_pending.as_bytes())
                .context(InterceptorSnafu)?;
            identity.verify(host, true).context(NodeSnafu)
        })();
        let restore = host
            .update_map("process_states", &process_key, stable_process.as_bytes())
            .context(InterceptorSnafu);
        let resume = self.set_frozen(false);
        restore?;
        resume?;
        let transition_health = transition_health?;
        let settled_health = identity.verify(host, true).context(NodeSnafu)?;
        let settled_application = inspector
            .snapshot(application.host_tid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: evidence_path,
                    reason: "the application identity disappeared after reconciliation".to_owned(),
                }
                .build()
            })?;
        let preserved = transition_health == before
            && settled_health == before
            && settled_application.coordinate_state == TaskCoordinateStateV1::Runnable as u8;
        ensure!(
            preserved,
            InvalidInputSnafu {
                path: evidence_path,
                reason: format!(
                    "an event-driven identity check changed application health: before={before:?}, transition={transition_health:?}, settled={settled_health:?}, application={settled_application:?}"
                ),
            }
        );
        Ok(true)
    }

    fn prepare_preexisting_child_bind(&self, host_pid: u32, rootfs: &Path) -> Result<()> {
        let source = rootfs.join("mnt/data/models");
        let target = rootfs.join("backup/models");
        let mount_namespace = ExternalMountNamespace::acquire(host_pid)?;
        mount_namespace.create_dir_all(&source)?;
        mount_namespace.create_dir_all(&target)?;
        mount_namespace.create_file(&source.join("secret"))?;
        mount_namespace.bind_mount(&source, &target)?;
        ensure!(
            mount_namespace
                .read_file(&target.join("secret"))?
                .is_empty(),
            InvalidInputSnafu {
                path: &target,
                reason:
                    "the direct runc child-directory bind is not readable before policy activation",
            }
        );
        Ok(())
    }

    fn record_mountinfo(&self, host_pid: u32, output_directory: &Path) -> Result<()> {
        let source = PathBuf::from(format!("/proc/{host_pid}/mountinfo"));
        fs::copy(
            &source,
            output_directory.join("runc-entry-role-mountinfo.txt"),
        )
        .context(IoSnafu { path: &source })?;
        Ok(())
    }

    fn spawn_exec(
        &self,
        executable: &str,
        arguments: &[&str],
        pid_path: &Path,
        stdout_path: &Path,
        stderr_path: &Path,
    ) -> Result<Child> {
        let stdout = fs::File::create(stdout_path).context(IoSnafu { path: stdout_path })?;
        let stderr = fs::File::create(stderr_path).context(IoSnafu { path: stderr_path })?;
        Command::new(&self.runc_path)
            .args(["--root", self.state_root.to_string_lossy().as_ref()])
            .args(["exec", "--pid-file", pid_path.to_string_lossy().as_ref()])
            .arg(&self.container_id)
            .arg(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .context(IoSnafu {
                path: &self.runc_path,
            })
    }

    fn cleanup(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            if child
                .try_wait()
                .context(IoSnafu {
                    path: Path::new("runc child"),
                })?
                .is_none()
            {
                child.kill().context(IoSnafu {
                    path: Path::new("runc child"),
                })?;
                child.wait().context(IoSnafu {
                    path: Path::new("runc child"),
                })?;
            }
        }
        let output = Command::new(&self.runc_path)
            .args(["--root", self.state_root.to_string_lossy().as_ref()])
            .args(["delete", "--force", &self.container_id])
            .output()
            .context(IoSnafu {
                path: &self.runc_path,
            })?;
        ensure!(
            output.status.success()
                || String::from_utf8_lossy(&output.stderr).contains("does not exist"),
            CommandSnafu {
                program: self.runc_path.display().to_string(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        if self.cgroup_path.exists() {
            fs::write(self.cgroup_path.join("cgroup.kill"), b"1").context(IoSnafu {
                path: &self.cgroup_path,
            })?;
            remove_cgroup(&self.cgroup_path)?;
        }
        Ok(())
    }
}

impl Drop for RuncContainer {
    fn drop(&mut self) {
        let _result = self.cleanup();
    }
}

impl EffectTestRunner {
    pub fn runc_retained_runtime_gate_probe(
        &self,
        output_directory: &Path,
        runc_path: &Path,
        hook_path: &Path,
        k3s_path: &Path,
        nsenter_path: &Path,
    ) -> Result<RuncRetainedRuntimeGateProbeV1> {
        for path in [runc_path, hook_path, k3s_path, nsenter_path] {
            ensure!(
                path.is_absolute() && path.is_file(),
                InvalidInputSnafu {
                    path,
                    reason: "the direct runc retained-gate input must be an existing absolute file",
                }
            );
        }
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let fixture = RetainedRuntimeGateRuncFixture::create(
            output_directory,
            runc_path,
            hook_path,
            k3s_path,
            nsenter_path,
        )?;
        let hostile = fixture.run_hostile()?;
        let recovery = fixture.run_exact_recovery()?;
        let changed = fixture.run_changed_recovery()?;
        let host_stock_spec = fixture.run_host_stock_spec()?;
        let recovery_log = fixture.exact_recovery_log()?;
        let host_stock_spec_generated = host_stock_spec.success
            && serde_json::from_str::<serde_json::Value>(&host_stock_spec.stdout)
                .ok()
                .and_then(|spec| spec.get("ociVersion").cloned())
                .is_some();

        let result = RuncRetainedRuntimeGateProbeV1 {
            schema_version: 1,
            runc_version: command_text(Command::new(runc_path).arg("--version"), runc_path)?,
            hostile_container_denied: !hostile.success,
            hostile_process_never_started: !fixture.marker_exists("hostile"),
            hostile_decision_logged: hostile.stderr.contains("decision=DENY_HOSTILE"),
            exact_recovery_allowed: recovery.success,
            exact_recovery_process_started: fixture.marker_exists("recovery"),
            exact_recovery_decision_logged: recovery_log.contains("decision=ALLOW_EXACT_RECOVERY"),
            changed_recovery_denied: !changed.success,
            changed_recovery_process_never_started: !fixture.marker_exists("changed-recovery"),
            unavailable_decision_logged: changed.stderr.contains("decision=DENY_NODE_UNAVAILABLE"),
            host_stock_spec_generated,
            fixture_root_removed: false,
        };
        ensure!(
            result.hostile_container_denied
                && result.hostile_process_never_started
                && result.hostile_decision_logged
                && result.exact_recovery_allowed
                && result.exact_recovery_process_started
                && result.exact_recovery_decision_logged
                && result.changed_recovery_denied
                && result.changed_recovery_process_never_started
                && result.unavailable_decision_logged
                && result.host_stock_spec_generated,
            InvalidInputSnafu {
                path: output_directory,
                reason: "the direct runc retained-gate oracle failed; inspect its case logs",
            }
        );
        fixture.cleanup()?;
        Ok(RuncRetainedRuntimeGateProbeV1 {
            fixture_root_removed: !fixture.fixture_root.exists(),
            ..result
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn runc_entry_role_runtime_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        runc_path: &Path,
        workload_path: &Path,
        prestart_hook: &Path,
        retained_bpf_object: &Path,
    ) -> Result<RuncEntryRoleRuntimeProbeV1> {
        for path in [pin_root, lease_path] {
            ensure!(
                !path.exists(),
                InvalidInputSnafu {
                    path,
                    reason: "the direct runc probe requires fresh Mithril ownership",
                }
            );
        }
        for path in [runc_path, workload_path, prestart_hook, retained_bpf_object] {
            ensure!(
                path.is_absolute() && path.exists(),
                InvalidInputSnafu {
                    path,
                    reason: "the direct runc probe input must be an existing absolute path",
                }
            );
        }

        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let fixture_root = output_directory.join("runc-entry-role-fixture");
        ensure!(
            !fixture_root.exists(),
            InvalidInputSnafu {
                path: &fixture_root,
                reason: "the direct runc fixture must start from an absent directory",
            }
        );
        fs::create_dir_all(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;
        let pin_cleanup = ProbeDirectory::new(pin_root);
        let lease_cleanup = ProbeFile::new(lease_path);

        let bundle = fixture_root.join("bundle");
        let rootfs = bundle.join("rootfs");
        let request_directory = fixture_root.join("prestart-requests");
        let state_root = fixture_root.join("runc-state");
        // Keep the runtime streams outside the disposable bundle so a failed probe is diagnosable.
        let stdout_path = output_directory.join("runc-entry-role.stdout");
        let stderr_path = output_directory.join("runc-entry-role.stderr");
        fs::create_dir_all(rootfs.join("bin")).context(IoSnafu { path: &rootfs })?;
        fs::create_dir(&request_directory).context(IoSnafu {
            path: &request_directory,
        })?;
        fs::set_permissions(&request_directory, fs::Permissions::from_mode(0o700)).context(
            IoSnafu {
                path: &request_directory,
            },
        )?;
        fs::create_dir(&state_root).context(IoSnafu { path: &state_root })?;
        let dynamic_loader_paths = prepare_entry_role_root(&rootfs, workload_path)?;

        run_checked(
            Command::new(runc_path).args(["spec", "--bundle", bundle.to_string_lossy().as_ref()]),
            runc_path,
        )?;
        let config_path = bundle.join("config.json");
        let mut config: serde_json::Value = serde_json::from_slice(
            &fs::read(&config_path).context(IoSnafu { path: &config_path })?,
        )
        .context(JsonSnafu { path: &config_path })?;
        let container_id = format!("{:x}", Sha256::digest(fixture_root.as_os_str().as_bytes()));
        let cgroup_name = format!("mithril-direct-runc-{}", std::process::id());
        let cgroup_path = PathBuf::from("/sys/fs/cgroup").join(&cgroup_name);
        ensure!(
            !cgroup_path.exists(),
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the direct runc cgroup already exists",
            }
        );
        config["process"]["terminal"] = json!(false);
        config["process"]["cwd"] = json!("/");
        config["process"]["env"] = json!(["PATH=/bin"]);
        config["process"]["args"] = json!([
            "/bin/sh",
            "-c",
            "true 2>/dev/null </run/mithril-entry-roles/application.denied || true; if true 2>/dev/null </backup/models/secret; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/path-tree.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/path-tree.result; fi; if true </run/mithril-entry-roles/control.allowed; then echo CONTROL_ALLOWED >/run/mithril-entry-roles/path-tree-control.result; else echo CONTROL_DENIED >/run/mithril-entry-roles/path-tree-control.result; fi; while [ ! -e /run/mithril-entry-roles/release ]; do /bin/sleep 1; done"
        ]);
        config["root"]["path"] = json!("rootfs");
        config["root"]["readonly"] = json!(false);
        config["linux"]["cgroupsPath"] = json!(format!("/{cgroup_name}"));
        config["annotations"] = json!({
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.container-id": container_id,
        });
        config["hooks"]["prestart"] = json!([{
            "path": prestart_hook,
            "args": [prestart_hook, "prestart", request_directory],
            "timeout": 30,
        }]);
        config["mounts"]
            .as_array_mut()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &config_path,
                    reason: "the generated runc spec has no mount array",
                }
                .build()
            })?
            .push(json!({
                "destination": "/mnt/data",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "mode=0755"]
            }));
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
        )
        .context(IoSnafu { path: &config_path })?;

        let policy = self.build_runc_artifact(&fixture_root, &dynamic_loader_paths)?;
        let runc_version = command_text(Command::new(runc_path).arg("--version"), runc_path)?;
        let stdout = fs::File::create(&stdout_path).context(IoSnafu { path: &stdout_path })?;
        let stderr = fs::File::create(&stderr_path).context(IoSnafu { path: &stderr_path })?;
        let child = Command::new(runc_path)
            .args(["--root", state_root.to_string_lossy().as_ref()])
            .args(["run", "--bundle", bundle.to_string_lossy().as_ref()])
            .arg(&container_id)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .context(IoSnafu { path: runc_path })?;
        let mut container = RuncContainer {
            child: Some(child),
            runc_path: runc_path.to_path_buf(),
            state_root: state_root.clone(),
            container_id: container_id.clone(),
            cgroup_path: cgroup_path.clone(),
        };

        let request_path = request_directory.join(format!("{container_id}.json"));
        wait_for_path(&request_path, true, "the direct runc prestart request")?;
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                path: &request_path,
            })?)
            .context(JsonSnafu {
                path: &request_path,
            })?;
        fs::copy(
            &request_path,
            output_directory.join("runc-entry-role-request.json"),
        )
        .context(IoSnafu {
            path: &request_path,
        })?;
        let initial_pid = request
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &request_path,
                    reason: "the direct runc prestart request has no valid PID",
                }
                .build()
            })?;
        let process_root = PathBuf::from(format!("/proc/{initial_pid}/root"));
        let root_target = fs::read_link(&process_root)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let work_state = fs::read_dir(process_root.join("work"))
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        fs::write(
            output_directory.join("runc-entry-role-root.txt"),
            format!("root={root_target}\nwork={work_state}\n"),
        )
        .context(IoSnafu {
            path: output_directory,
        })?;
        let observed_cgroup = request
            .get("cgroup")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &request_path,
                    reason: "the direct runc prestart request has no cgroup",
                }
                .build()
            })?;
        ensure!(
            observed_cgroup == format!("/{cgroup_name}"),
            InvalidInputSnafu {
                path: &request_path,
                reason: format!("direct runc used unexpected cgroup `{observed_cgroup}`"),
            }
        );
        container.prepare_preexisting_child_bind(initial_pid, &rootfs)?;
        signal_process(initial_pid, Signal::STOP)?;

        let (boot_id, node_boot_id) = boot_identity()?;
        let retained_bpf_sha256 = DigestV1::of(fs::read(retained_bpf_object).context(IoSnafu {
            path: retained_bpf_object,
        })?)
        .to_hex();
        let mut host = KernelHostOwner::new(KernelHostConfig::retained_identity_qualification(
            retained_bpf_object,
            retained_bpf_sha256,
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            &boot_id,
            1,
        ))
        .start()
        .context(InterceptorSnafu)?;
        let retained_manifest = host.manifest().clone();
        let mut binding = effect_binding_with_identity(
            &cgroup_path,
            "99999999-9999-4999-8999-999999999996",
            'f',
            "direct-runc",
            true,
        );
        binding.profile_id = policy.profile_id.clone();
        binding.protected_scope_id = policy.protected_scope_id.clone();
        binding.execution_set_id = policy.execution_set_id.clone();
        binding.workload_selector_id = policy.workload_selector_id.clone();
        binding.cluster_uid = "10000000-0000-4000-8000-000000000002".to_owned();
        binding.namespace_uid = "10000000-0000-4000-8000-000000000003".to_owned();
        binding.pod_labels = [(
            "app.kubernetes.io/name".to_owned(),
            "direct-runc".to_owned(),
        )]
        .into_iter()
        .collect();
        binding.image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        binding.initial_role_id = policy.initial_role_id;
        binding.external_role_id = policy.external_role_id;
        let mut bindings = WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        bindings
            .publish_held_initial_roots(&host, &[(binding.clone(), initial_pid)])
            .context(NodeSnafu)?;
        let policy_fixture = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/mithril-policy");
        let node_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            policy.artifact_path.clone(),
            vec![binding.clone()],
        );
        let mut policy_owner = NodePolicyGenerationOwner::load_and_install_for_bindings(
            &node_config,
            &mut host,
            &bindings,
            node_boot_id,
            1,
        )
        .context(NodeSnafu)?;
        let staged_entry_rules = host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?
            .into_iter()
            .map(|key| {
                host.lookup_map("entry_admission_rules", &key)
                    .context(InterceptorSnafu)?
                    .and_then(|value| EntryAdmissionRuleV1::try_read_from_bytes(&value).ok())
                    .ok_or_else(|| {
                        InvalidInputSnafu {
                            path: pin_root,
                            reason: "the prepared application entry rule has invalid ABI",
                        }
                        .build()
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            staged_entry_rules.len() == 7
                && staged_entry_rules
                    .iter()
                    .any(|rule| rule.target_role_id == policy.initial_role_id)
                && staged_entry_rules
                    .iter()
                    .all(|rule| rule.exact_object_key_id == 0),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "prepared application entry staging is invalid: {staged_entry_rules:?}"
                ),
            }
        );
        let identity = NativeSecurityStateOwner::new(node_boot_id, 1);
        identity
            .activate_held_initial_admission(&mut host, true)
            .context(NodeSnafu)?;
        let reconciliation = identity
            .activate_prepared_runtime_roots(&mut host, true)
            .context(NodeSnafu)?;
        ensure!(
            reconciliation == Default::default(),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "the held direct runc task failed prepared reconciliation: {reconciliation:?}"
                ),
            }
        );
        let inspector = NativeIdentityInspector::new(pin_root);
        let prepared = inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the held direct runc task has no prepared identity",
                }
                .build()
            })?;
        let prepared_state_before_exec = prepared
            .runtime_binding
            .as_ref()
            .map(|binding| binding.prepared_container_state.clone())
            .unwrap_or_default();
        ensure!(
            prepared_state_before_exec == "prepared",
            InvalidInputSnafu {
                path: pin_root,
                reason: "the held direct runc task is not in PREPARED state",
            }
        );
        let observations = EffectObservationStore::default();
        let sink = observations.clone();
        let reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let marker = observations.cursor();

        signal_process(initial_pid, Signal::CONT)?;
        fs::write(
            request_directory.join(format!("{container_id}.release")),
            format!("accepted:{initial_pid}"),
        )
        .context(IoSnafu {
            path: &request_directory,
        })?;
        wait_for_runtime_active(
            &reader,
            &observations,
            marker,
            &inspector,
            initial_pid,
            output_directory,
        )?;
        container.record_mountinfo(initial_pid, output_directory)?;
        wait_for_reason(&reader, &observations, marker, "PATH_TREE_POLICY_DENY")?;
        let path_tree_result = rootfs.join("run/mithril-entry-roles/path-tree.result");
        let path_tree_control_result =
            rootfs.join("run/mithril-entry-roles/path-tree-control.result");
        wait_for_path(&path_tree_result, true, "the path-tree denial result")?;
        wait_for_path(
            &path_tree_control_result,
            true,
            "the path-tree allowed-control result",
        )?;
        ensure!(
            fs::read_to_string(&path_tree_result)
                .context(IoSnafu {
                    path: &path_tree_result,
                })?
                .trim()
                == "PATH_TREE_DENIED"
                && fs::read_to_string(&path_tree_control_result)
                    .context(IoSnafu {
                        path: &path_tree_control_result,
                    })?
                    .trim()
                    == "CONTROL_ALLOWED",
            InvalidInputSnafu {
                path: &path_tree_result,
                reason: "the direct runc path-tree negative and allowed control did not both pass",
            }
        );
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let active = inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the direct runc task lost identity after its first exec",
                }
                .build()
            })?;
        let prepared_state_after_exec = active
            .runtime_binding
            .as_ref()
            .map(|binding| binding.prepared_container_state.clone())
            .unwrap_or_default();
        ensure!(
            prepared_state_after_exec == "active"
                && active.profile_generation_ref_id == PROFILE_GENERATION_REF_ID,
            InvalidInputSnafu {
                path: pin_root,
                reason: "the first configured executable did not activate normal policy",
            }
        );
        let application_exec_transition_event_driven = container
            .verify_exec_transition_event_path(
                &mut host, &identity, &inspector, &active, pin_root,
            )?;
        policy_owner
            .reconcile_cri_exact_bindings(&node_config, &mut host, &bindings)
            .context(NodeSnafu)?;
        let entry_admission_proofs = host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?
            .into_iter()
            .map(|key| {
                let value = host
                    .lookup_map("entry_admission_rules", &key)
                    .context(InterceptorSnafu)?
                    .ok_or_else(|| {
                        InvalidInputSnafu {
                            path: pin_root,
                            reason: "an entry admission rule disappeared before readback",
                        }
                        .build()
                    })?;
                EntryAdmissionRuleV1::try_read_from_bytes(&value).map_err(|error| {
                    InvalidInputSnafu {
                        path: pin_root,
                        reason: format!("an entry admission rule has invalid ABI: {error}"),
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let exact_entry_rule_ids = entry_admission_proofs
            .iter()
            .map(|rule| rule.admitted_entry_rule_id)
            .collect::<BTreeSet<_>>();
        let termination_role_id = policy.role_ids["termination-failure"];
        let ordinary_entry_proofs = entry_admission_proofs
            .iter()
            .filter(|rule| rule.target_role_id != termination_role_id)
            .collect::<Vec<_>>();
        let terminal_entry_proofs = entry_admission_proofs
            .iter()
            .filter(|rule| rule.target_role_id == termination_role_id)
            .collect::<Vec<_>>();
        ensure!(
            entry_admission_proofs.len() == 7
                && exact_entry_rule_ids.len() == 7
                && entry_admission_proofs.iter().all(|rule| {
                    rule.exact_object_key_id > 0
                        && rule.executable_object.profile_generation_ref_id
                            == PROFILE_GENERATION_REF_ID
                        && rule.executable_object.mount_id_unique > 0
                        && rule.executable_object.inode > 0
                        && rule.executable_object.inode_generation > 0
                })
                && ordinary_entry_proofs.len() == 6
                && ordinary_entry_proofs[1..].iter().all(|rule| {
                    rule.executable_object == ordinary_entry_proofs[0].executable_object
                })
                && terminal_entry_proofs.len() == 1
                && terminal_entry_proofs[0].executable_object
                    != ordinary_entry_proofs[0].executable_object,
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "entry admission did not retain six BusyBox entries and one terminal-exec fixture: {entry_admission_proofs:?}"
                ),
            }
        );

        wait_for_reason(
            &reader,
            &observations,
            marker,
            "PREPARED_RUNTIME_INFRASTRUCTURE",
        )?;
        wait_for_path_exec_effect(
            &reader,
            &observations,
            marker,
            "EXACT_POLICY_ALLOW",
            KernelEffectOperationV1::Execute,
        )?;
        let application_entry_exact_object_enforced =
            exact_entry_rule_ids.contains(&active.admitted_entry_rule_id);
        ensure!(
            application_entry_exact_object_enforced,
            InvalidInputSnafu {
                path: pin_root,
                reason: "the application entry did not commit its exact-object admission proof",
            }
        );
        wait_for_application_default_effect(
            &reader,
            &observations,
            marker,
            (KernelEffectFamilyV1::File, KernelEffectOperationV1::Read),
        )?;
        wait_for_application_default_effect(
            &reader,
            &observations,
            marker,
            (KernelEffectFamilyV1::Exec, KernelEffectOperationV1::Execute),
        )?;
        let application_descendant_default_exec_role_preserved =
            observations.recent_since(marker).iter().any(|event| {
                event.reason == "APPLICATION_DEFAULT_ALLOW"
                    && event.effect_family == u32::from(KernelEffectFamilyV1::Exec as u16)
                    && event.operation == u32::from(KernelEffectOperationV1::Execute as u16)
                    && event.task_cookie != active.task_cookie
                    && event.active_role_id == active.active_role_id
                    && event.admitted_entry_rule_id == active.admitted_entry_rule_id
                    && event.composite_atom_id == 0
                    && event.exact_object_key_id == 0
            });
        ensure!(
            application_descendant_default_exec_role_preserved,
            InvalidInputSnafu {
                path: pin_root,
                reason:
                    "an application descendant did not retain its application role and admission ID",
            }
        );

        ensure!(
            active.active_role_id == policy.initial_role_id && active.admitted_entry_rule_id > 0,
            InvalidInputSnafu {
                path: pin_root,
                reason: "the application entry did not install its declared role and admission ID",
            }
        );

        let mut replacement_binding = binding.clone();
        replacement_binding.active_profile_generation_ref_id = NEXT_PROFILE_GENERATION_REF_ID;
        let replacement_config = effect_node_config(
            &fixture_root,
            pin_root,
            lease_path,
            &policy_fixture,
            policy.replacement_artifact_path.clone(),
            vec![replacement_binding.clone()],
        );
        policy_owner = NodePolicyGenerationOwner::load_and_install_for_bindings(
            &replacement_config,
            &mut host,
            &bindings,
            node_boot_id,
            1,
        )
        .context(NodeSnafu)?;
        bindings
            .adopt_activated_profiles(&host, &replacement_config.workload_bindings)
            .context(NodeSnafu)?;
        policy_owner
            .reconcile_cri_exact_bindings(&replacement_config, &mut host, &bindings)
            .context(NodeSnafu)?;
        let active_after_replacement = inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the running application lost identity during policy replacement",
                }
                .build()
            })?;
        let live_replacement_preserved_running_application =
            active_after_replacement.profile_generation_ref_id == PROFILE_GENERATION_REF_ID
                && active_after_replacement.task_cookie == active.task_cookie
                && active_after_replacement.active_role_id == active.active_role_id
                && active_after_replacement.admitted_entry_rule_id == active.admitted_entry_rule_id;
        ensure!(
            live_replacement_preserved_running_application,
            InvalidInputSnafu {
                path: pin_root,
                reason: "policy replacement changed the running application identity",
            }
        );
        let replacement_entry_rules = host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?
            .into_iter()
            .map(|key| {
                let parsed_key =
                    EntryAdmissionRuleKeyV1::try_read_from_bytes(&key).map_err(|error| {
                        InvalidInputSnafu {
                            path: pin_root,
                            reason: format!(
                                "a replacement entry admission key has invalid ABI: {error}"
                            ),
                        }
                        .build()
                    })?;
                let value = host
                    .lookup_map("entry_admission_rules", &key)
                    .context(InterceptorSnafu)?
                    .ok_or_else(|| {
                        InvalidInputSnafu {
                            path: pin_root,
                            reason:
                                "a replacement entry admission rule disappeared before readback",
                        }
                        .build()
                    })?;
                let rule = EntryAdmissionRuleV1::try_read_from_bytes(&value).map_err(|error| {
                    InvalidInputSnafu {
                        path: pin_root,
                        reason: format!(
                            "a replacement entry admission rule has invalid ABI: {error}"
                        ),
                    }
                    .build()
                })?;
                Ok((parsed_key, rule))
            })
            .collect::<Result<Vec<_>>>()?;
        let replacement_exact_entry_rule_ids = replacement_entry_rules
            .iter()
            .filter(|(_, rule)| {
                rule.executable_object.profile_generation_ref_id == NEXT_PROFILE_GENERATION_REF_ID
            })
            .map(|(_, rule)| rule.admitted_entry_rule_id)
            .collect::<BTreeSet<_>>();
        let replacement_terminal_entry_rule_ids = replacement_entry_rules
            .iter()
            .filter(|(_, rule)| {
                rule.executable_object.profile_generation_ref_id == NEXT_PROFILE_GENERATION_REF_ID
                    && rule.target_role_id == termination_role_id
            })
            .map(|(_, rule)| rule.admitted_entry_rule_id)
            .collect::<BTreeSet<_>>();
        ensure!(
            replacement_exact_entry_rule_ids.len() == 7
                && replacement_terminal_entry_rule_ids.len() == 1,
            InvalidInputSnafu {
                path: pin_root,
                reason: "policy replacement did not install seven exact declared entries",
            }
        );

        drop(policy_owner);
        drop(bindings);
        drop(reader);
        host.shutdown().context(InterceptorSnafu)?;
        let mut host = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        ))
        .start()
        .context(InterceptorSnafu)?;
        let upgraded_manifest = host.manifest();
        let kernel_upgrade_preserved_map_ids = retained_manifest
            .maps
            .iter()
            .map(|map| (&map.name, map.id))
            .eq(upgraded_manifest.maps.iter().map(|map| (&map.name, map.id)));
        let kernel_upgrade_preserved_link_pins = retained_manifest
            .links
            .iter()
            .map(|link| (&link.program, &link.pin_path))
            .eq(upgraded_manifest
                .links
                .iter()
                .map(|link| (&link.program, &link.pin_path)));
        let kernel_upgrade_replaced_changed_programs = retained_manifest
            .links
            .iter()
            .zip(&upgraded_manifest.links)
            .any(|(retained, upgraded)| {
                retained.program == upgraded.program
                    && retained.program_tag != upgraded.program_tag
                    && retained.program_id != upgraded.program_id
            });
        ensure!(
            kernel_upgrade_preserved_map_ids
                && kernel_upgrade_preserved_link_pins
                && kernel_upgrade_replaced_changed_programs,
            InvalidInputSnafu {
                path: pin_root,
                reason: "the kernel-host upgrade did not preserve maps and link pins while replacing changed programs",
            }
        );
        let sink = observations.clone();
        let reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let mut restarted_bindings =
            WorkloadBindingOwner::system(node_boot_id, 1).context(NodeSnafu)?;
        restarted_bindings
            .publish_held_initial_roots(&host, &[(replacement_binding.clone(), initial_pid)])
            .context(NodeSnafu)?;
        restarted_bindings
            .adopt_activated_profiles(&host, &replacement_config.workload_bindings)
            .context(NodeSnafu)?;
        let mut restarted_policy_owner = NodePolicyGenerationOwner::load_and_install_for_bindings(
            &replacement_config,
            &mut host,
            &restarted_bindings,
            node_boot_id,
            1,
        )
        .context(NodeSnafu)?;
        restarted_policy_owner
            .reconcile_cri_exact_bindings(&replacement_config, &mut host, &restarted_bindings)
            .context(NodeSnafu)?;
        let restarted_identity = NativeSecurityStateOwner::new(node_boot_id, 1);
        let restart_reconciliation = restarted_identity
            .activate_initial_with_effect_policy(&mut host, true)
            .context(NodeSnafu)?;
        ensure!(
            restart_reconciliation == Default::default(),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "node-owner restart recorded an identity failure: {restart_reconciliation:?}"
                ),
            }
        );
        let active_after_node_owner_restart = inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
            InvalidInputSnafu {
                path: pin_root,
                reason: "node-owner restart lost the running application identity",
            }
            .build()
        })?;
        let node_owner_restart_preserved_running_application =
            active_after_node_owner_restart == active_after_replacement;
        ensure!(
            node_owner_restart_preserved_running_application,
            InvalidInputSnafu {
                path: pin_root,
                reason: "node-owner restart changed the running application identity",
            }
        );
        let mut independent_entries = Vec::new();
        for (name, declaration_name, executable) in [
            ("poststart", "poststart", "/bin/cp"),
            ("poststart-repeat", "poststart", "/bin/cp"),
            ("prestop", "prestop", "/bin/dd"),
            ("startup", "startup", "/bin/cat"),
            ("readiness", "readiness", "/bin/grep"),
            ("liveness", "liveness", "/bin/wc"),
        ] {
            let entry_marker = observations.cursor();
            let pid_path = fixture_root.join(format!("{name}.pid"));
            let entry_stdout = output_directory.join(format!("runc-entry-{name}.stdout"));
            let entry_stderr = output_directory.join(format!("runc-entry-{name}.stderr"));
            let command = format!(
                "true 2>/dev/null </run/mithril-entry-roles/{declaration_name}.denied || true; true </run/mithril-entry-roles/application.denied && /bin/sleep 2"
            );
            let mut child = container.spawn_exec(
                executable,
                &["-c", command.as_str()],
                &pid_path,
                &entry_stdout,
                &entry_stderr,
            )?;
            let host_pid = if let Some(host_pid) = wait_for_pid_file(&pid_path, &mut child)? {
                host_pid
            } else {
                reader
                    .poll(Duration::from_millis(100))
                    .context(InterceptorSnafu)?;
                ensure!(
                    false,
                    InvalidInputSnafu {
                        path: &entry_stderr,
                        reason: format!(
                            "entry `{name}` exited before publishing its host PID: stderr={}, effects={:?}",
                            fs::read_to_string(&entry_stderr).unwrap_or_default().trim(),
                            recent_effect_summary(&observations, entry_marker)
                        ),
                    }
                );
                unreachable!()
            };
            let snapshot = wait_for_task_snapshot(
                &inspector,
                host_pid,
                &mut child,
                &reader,
                &observations,
                entry_marker,
                &entry_stderr,
            )?;
            let status = wait_for_child(&mut child)?;
            reader
                .poll(Duration::from_millis(100))
                .context(InterceptorSnafu)?;
            let expected_role_id = policy.role_ids[declaration_name];
            let own_policy_deny_observed = wait_for_entry_policy_deny(
                &reader,
                &observations,
                entry_marker,
                expected_role_id,
                snapshot.admitted_entry_rule_id,
            )?;
            let exact_executable_object_enforced =
                replacement_exact_entry_rule_ids.contains(&snapshot.admitted_entry_rule_id);
            ensure!(
                status.success()
                    && snapshot.profile_generation_ref_id == NEXT_PROFILE_GENERATION_REF_ID
                    && snapshot.active_role_id == expected_role_id
                    && snapshot.admitted_entry_rule_id > 0
                    && exact_executable_object_enforced
                    && own_policy_deny_observed,
                InvalidInputSnafu {
                    path: &entry_stderr,
                    reason: format!(
                        "entry `{name}` did not keep its independent role: status={status}, snapshot={snapshot:?}, stderr={}",
                        fs::read_to_string(&entry_stderr).unwrap_or_default().trim()
                    ),
                }
            );
            independent_entries.push(RuncEntryRoleProbeV1 {
                name: name.to_owned(),
                declaration_name: declaration_name.to_owned(),
                host_pid,
                task_cookie: snapshot.task_cookie,
                process_state_id: snapshot.process_state_id,
                active_execution_id: snapshot.active_execution_id,
                profile_generation_ref_id: snapshot.profile_generation_ref_id,
                active_role_id: snapshot.active_role_id,
                admitted_entry_rule_id: snapshot.admitted_entry_rule_id,
                exact_executable_object_enforced,
                own_policy_deny_observed,
                application_policy_not_inherited: true,
            });
        }
        let role_ids = independent_entries
            .iter()
            .map(|entry| entry.active_role_id)
            .chain(std::iter::once(active.active_role_id))
            .collect::<BTreeSet<_>>();
        let admitted_ids = independent_entries
            .iter()
            .map(|entry| entry.admitted_entry_rule_id)
            .chain(std::iter::once(active.admitted_entry_rule_id))
            .collect::<BTreeSet<_>>();
        let independent_entry_roles_are_distinct = role_ids.len() == 6 && admitted_ids.len() == 6;
        ensure!(
            independent_entry_roles_are_distinct,
            InvalidInputSnafu {
                path: pin_root,
                reason: "application and additional entries did not install six distinct roles and admission IDs",
            }
        );
        let entry_executable_exact_objects_enforced = application_entry_exact_object_enforced
            && independent_entries
                .iter()
                .all(|entry| entry.exact_executable_object_enforced);
        let live_replacement_entries_use_new_generation = independent_entries
            .iter()
            .all(|entry| entry.profile_generation_ref_id == NEXT_PROFILE_GENERATION_REF_ID);
        let poststart = &independent_entries[0];
        let repeated_poststart = &independent_entries[1];
        let reusable_entry_reinvocation_isolated = poststart.declaration_name
            == repeated_poststart.declaration_name
            && poststart.active_role_id == repeated_poststart.active_role_id
            && poststart.admitted_entry_rule_id == repeated_poststart.admitted_entry_rule_id
            && poststart.host_pid != repeated_poststart.host_pid
            && poststart.task_cookie != repeated_poststart.task_cookie
            && poststart.process_state_id != repeated_poststart.process_state_id
            && poststart.active_execution_id != repeated_poststart.active_execution_id;
        ensure!(
            reusable_entry_reinvocation_isolated,
            InvalidInputSnafu {
                path: pin_root,
                reason: "a reusable declared entry did not create an independent invocation",
            }
        );
        let runtime_entry_infrastructure_observed = observations
            .recent_since(marker)
            .iter()
            .any(|event| event.reason == "RUNTIME_ENTRY_INFRASTRUCTURE");
        ensure!(
            runtime_entry_infrastructure_observed,
            InvalidInputSnafu {
                path: pin_root,
                reason: "declared entries did not record runtime entry infrastructure",
            }
        );

        let post_ponr_pid_path = fixture_root.join("post-ponr-terminal.pid");
        let post_ponr_stdout = output_directory.join("runc-entry-post-ponr.stdout");
        let post_ponr_stderr = output_directory.join("runc-entry-post-ponr.stderr");
        let mut post_ponr_child = container.spawn_exec(
            "/bin/post-ponr-execfail",
            &[],
            &post_ponr_pid_path,
            &post_ponr_stdout,
            &post_ponr_stderr,
        )?;
        let post_ponr_status = wait_for_child(&mut post_ponr_child)?;
        let post_ponr_pending = wait_for_post_ponr_terminal_exec(
            &host,
            NEXT_PROFILE_GENERATION_REF_ID,
            &post_ponr_stderr,
        )?;
        let post_ponr_terminal_evidence_observed = !post_ponr_status.success()
            && replacement_terminal_entry_rule_ids
                .contains(&post_ponr_pending.admitted_entry_rule_id);
        ensure!(
            post_ponr_terminal_evidence_observed,
            InvalidInputSnafu {
                path: &post_ponr_stderr,
                reason: format!(
                    "the declared terminal exec did not leave post-PONR evidence: status={post_ponr_status}, pending={post_ponr_pending:?}, stderr={}",
                    fs::read_to_string(&post_ponr_stderr)
                        .unwrap_or_default()
                        .trim()
                ),
            }
        );

        let external_marker = observations.cursor();
        let external_pid_path = fixture_root.join("external.pid");
        let external_stdout = output_directory.join("runc-entry-external.stdout");
        let external_stderr = output_directory.join("runc-entry-external.stderr");
        let mut external_child = container.spawn_exec(
            "/bin/sleep",
            &["5"],
            &external_pid_path,
            &external_stdout,
            &external_stderr,
        )?;
        let external_pid = wait_for_pid_file(&external_pid_path, &mut external_child)?;
        let external_snapshot = external_pid.and_then(|pid| inspector.snapshot(pid).ok().flatten());
        let external_status = wait_for_child(&mut external_child)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        ensure!(
            !external_status.success(),
            InvalidInputSnafu {
                path: runc_path,
                reason: format!(
                    "an undeclared external entry entered the protected container: snapshot={external_snapshot:?}, stderr={}, effects={:?}",
                    fs::read_to_string(&external_stderr).unwrap_or_default().trim(),
                    recent_effect_summary(&observations, external_marker)
                ),
            }
        );
        wait_for_reason(
            &reader,
            &observations,
            external_marker,
            "UNSUPPORTED_OBJECT",
        )?;
        let external_entry_denied =
            observations
                .recent_since(external_marker)
                .iter()
                .any(|event| {
                    event.reason == "UNSUPPORTED_OBJECT"
                        && event.effect_family == u32::from(KernelEffectFamilyV1::Exec as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::Execute as u16)
                        && event.active_role_id == binding.external_role_id
                        && event.admitted_entry_rule_id == 0
                        && event.kernel_result == -13
                });
        ensure!(
            external_entry_denied,
            InvalidInputSnafu {
                path: runc_path,
                reason: format!(
                    "the undeclared external entry did not produce a fail-closed effect: {:?}",
                    observations
                        .recent_since(external_marker)
                        .iter()
                        .filter(|event| event.kernel_result != 0)
                        .map(|event| (
                            event.reason.as_str(),
                            event.effect_family,
                            event.operation,
                            event.active_role_id,
                            event.admitted_entry_rule_id,
                            event.kernel_result,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );

        let cgroup_entry_marker = observations.cursor();
        let cgroup_entry_stderr = output_directory.join("cgroup-entry.stderr");
        let mut cgroup_entry = Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 1; exec /bin/true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(&cgroup_entry_stderr).context(IoSnafu {
                    path: &cgroup_entry_stderr,
                })?,
            ))
            .spawn()
            .context(IoSnafu {
                path: Path::new("/bin/sh"),
            })?;
        let cgroup_entry_pid = cgroup_entry.id();
        fs::write(
            cgroup_path.join("cgroup.procs"),
            cgroup_entry_pid.to_string(),
        )
        .context(IoSnafu {
            path: cgroup_path.join("cgroup.procs"),
        })?;
        let cgroup_entry_snapshot = inspector
            .snapshot(cgroup_entry_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &cgroup_path,
                    reason: "the external cgroup entrant has no Mithril identity",
                }
                .build()
            })?;
        ensure!(
            cgroup_entry_snapshot.active_role_id == binding.external_role_id
                && cgroup_entry_snapshot.admitted_entry_rule_id == 0
                && cgroup_entry_snapshot.installed_role_class.as_deref()
                    == Some("runtime_external_restricted"),
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: format!(
                    "the external cgroup entrant received an admitted role: {cgroup_entry_snapshot:?}"
                ),
            }
        );
        let cgroup_entry_status = wait_for_child(&mut cgroup_entry)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let external_cgroup_entering_process_stays_closed = !cgroup_entry_status.success()
            && observations
                .recent_since(cgroup_entry_marker)
                .iter()
                .any(|event| {
                    event.task_cookie == cgroup_entry_snapshot.task_cookie
                        && event.active_role_id == binding.external_role_id
                        && event.admitted_entry_rule_id == 0
                        && event.kernel_result == -13
                });
        ensure!(
            external_cgroup_entering_process_stays_closed,
            InvalidInputSnafu {
                path: &cgroup_entry_stderr,
                reason: format!(
                    "the external cgroup entrant did not fail closed: status={cgroup_entry_status}, stderr={}, effects={:?}",
                    fs::read_to_string(&cgroup_entry_stderr)
                        .unwrap_or_default()
                        .trim(),
                    observations
                        .recent_since(cgroup_entry_marker)
                        .iter()
                        .filter(|event| event.task_cookie == cgroup_entry_snapshot.task_cookie)
                        .map(|event| (
                            event.reason.as_str(),
                            event.effect_family,
                            event.operation,
                            event.active_role_id,
                            event.admitted_entry_rule_id,
                            event.kernel_result,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
        fs::write(rootfs.join("run/mithril-entry-roles/release"), b"release\n")
            .context(IoSnafu { path: &rootfs })?;

        let status = wait_for_child(container.child.as_mut().ok_or_else(|| {
            InvalidInputSnafu {
                path: runc_path,
                reason: "the direct runc child disappeared",
            }
            .build()
        })?)?;
        ensure!(
            status.success(),
            CommandSnafu {
                program: runc_path.display().to_string(),
                reason: format!(
                    "container status {status}; stderr=`{}`; observations={:?}",
                    fs::read_to_string(&stderr_path).unwrap_or_default().trim(),
                    observations
                        .recent_since(marker)
                        .iter()
                        .map(|event| (
                            event.reason.as_str(),
                            event.effect_family,
                            event.operation,
                            event.exact_object_key_id,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
        container.cleanup()?;
        drop(restarted_policy_owner);
        restarted_bindings
            .retire_profile_bindings_for_test(
                &host,
                &policy.profile_id,
                NEXT_PROFILE_GENERATION_REF_ID,
            )
            .context(NodeSnafu)?;
        let retirement_deadline = Instant::now() + WAIT_LIMIT;
        let inactive_generation_retired = loop {
            if NodePolicyGenerationOwner::retire_profile_generation_for_test(
                &host,
                &policy.profile_id,
                NEXT_PROFILE_GENERATION_REF_ID,
                node_boot_id,
                1,
            )
            .context(NodeSnafu)?
            {
                break true;
            }
            ensure!(
                Instant::now() < retirement_deadline,
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "terminal exec evidence blocked inactive policy-generation retirement",
                }
            );
            thread::sleep(Duration::from_millis(25));
        };
        let post_ponr_terminal_evidence_preserved = host
            .lookup_map(
                "pending_execs",
                &post_ponr_pending.task_cookie.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .and_then(|value| PendingExecV1::try_read_from_bytes(&value).ok())
            .is_some_and(|pending| {
                pending == post_ponr_pending && pending.state == PendingExecStateV1::PostPonrFatal
            });
        ensure!(
            post_ponr_terminal_evidence_preserved,
            InvalidInputSnafu {
                path: pin_root,
                reason: "policy retirement removed the terminal exec evidence row",
            }
        );
        restarted_bindings
            .finalize_retired_profile_bindings_for_test(
                &host,
                &policy.profile_id,
                NEXT_PROFILE_GENERATION_REF_ID,
            )
            .context(NodeSnafu)?;
        ensure!(
            NodePolicyGenerationOwner::profile_generation_is_absent_for_test(
                &host,
                &policy.profile_id,
                NEXT_PROFILE_GENERATION_REF_ID,
            )
            .context(NodeSnafu)?,
            InvalidInputSnafu {
                path: pin_root,
                reason: "inactive policy generation lacks exact kernel absence proof",
            }
        );
        drop(reader);
        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        let cgroup_removed = !cgroup_path.exists();
        ensure!(
            cgroup_removed,
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the direct runc cgroup survived container deletion",
            }
        );
        fs::remove_dir_all(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;

        Ok(RuncEntryRoleRuntimeProbeV1 {
            schema_version: 15,
            runc_version: runc_version.lines().next().unwrap_or_default().to_owned(),
            initial_host_pid: initial_pid,
            prepared_state_before_exec,
            prepared_state_after_exec,
            prepared_runtime_effect_observed: true,
            application_entry_allow_observed: true,
            application_default_file_allow_observed: true,
            application_descendant_default_exec_role_preserved,
            held_runtime_admission_reconciled: true,
            application_exec_transition_event_driven,
            preexisting_child_bind_path_tree_denied: true,
            path_tree_control_allowed: true,
            application_admitted_entry_rule_id: active.admitted_entry_rule_id,
            independent_entries,
            independent_entry_roles_are_distinct,
            reusable_entry_reinvocation_isolated,
            runtime_entry_infrastructure_observed,
            live_replacement_preserved_running_application,
            live_replacement_entries_use_new_generation,
            node_owner_restart_preserved_running_application,
            kernel_upgrade_preserved_map_ids,
            kernel_upgrade_preserved_link_pins,
            kernel_upgrade_replaced_changed_programs,
            post_ponr_terminal_evidence_observed,
            post_ponr_terminal_evidence_preserved,
            inactive_generation_retired,
            external_entry_denied,
            external_cgroup_entering_process_stays_closed,
            entry_executable_exact_objects_enforced,
            dynamic_loader_paths,
            dynamic_loader_paths_absent_from_policy: true,
            container_exit_success: true,
            pin_root_removed: !pin_root.exists(),
            lease_removed: !lease_path.exists(),
            cgroup_removed,
            fixture_root_removed: !fixture_root.exists(),
        })
    }

    fn build_runc_artifact(
        &self,
        fixture_root: &Path,
        dynamic_loader_paths: &[String],
    ) -> Result<RuncPolicyFixture> {
        let policy_fixture = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/mithril-policy");
        let policy_source = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/convergence/direct-entry-roles-v1.yaml");
        let spec = WorkloadProtectionPolicySpec::parse(
            &policy_source,
            &fs::read(&policy_source).context(IoSnafu {
                path: &policy_source,
            })?,
        )
        .context(PolicySnafu)?;
        let mut resource =
            policy_custom_resource("direct-entry-roles", "default", spec).context(PolicySnafu)?;
        resource.metadata.uid = Some("30000000-0000-4000-8000-000000000001".to_owned());
        resource.metadata.generation = Some(1);
        let mut document = lower_kubernetes_policy(
            &resource,
            "10000000-0000-4000-8000-000000000001",
            "10000000-0000-4000-8000-000000000002",
            "10000000-0000-4000-8000-000000000003",
        )
        .context(PolicySnafu)?;
        document.path_tree_deny_floors.push(PathTreeDenyFloorV1 {
            schema_version: 1,
            rule_id: "deny-model-tree".to_owned(),
            canonical_path: "/mnt/data".to_owned(),
            recursive: true,
            effect_families: vec![EffectFamilyV1::File],
            operation_ids: vec!["OPEN_READ".to_owned()],
            requested_disposition: PolicyDispositionV1::Deny,
            exception_ids: Vec::new(),
        });
        ensure!(
            dynamic_loader_paths.iter().all(|dependency| {
                document
                    .path_selectors
                    .iter()
                    .all(|selector| selector.path_expression() != dependency)
            }),
            InvalidInputSnafu {
                path: &policy_source,
                reason: "the direct runc policy must not list dynamic runtime dependencies",
            }
        );
        let role_ids = document
            .roles
            .iter()
            .map(|role| role.role_id.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(index, role)| (role.to_owned(), index as u32 + 1))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            document
                .path_selectors
                .iter()
                .all(|selector| !selector.requires_exact_object()),
            InvalidInputSnafu {
                path: &policy_source,
                reason: "the direct runc policy must keep action selectors path-based",
            }
        );
        let profile_id = document.metadata.profile_id.clone();
        let protected_scope_id = document.protected_universe.protected_scope_ids[0].clone();
        let execution_set_id = document.protected_universe.execution_set_ids[0].clone();
        let artifact_path = sign_generation_artifact(
            document.clone(),
            &policy_fixture.join("observe-profile-seal-request.json"),
            &policy_fixture.join("test-signing-key.hex"),
            fixture_root,
            1,
        )?;
        let replacement_artifact_path = sign_generation_artifact(
            document,
            &policy_fixture.join("observe-profile-seal-request.json"),
            &policy_fixture.join("test-signing-key.hex"),
            fixture_root,
            2,
        )?;
        Ok(RuncPolicyFixture {
            artifact_path,
            replacement_artifact_path,
            profile_id,
            protected_scope_id,
            execution_set_id,
            workload_selector_id: "container-0".to_owned(),
            initial_role_id: role_ids["application"],
            external_role_id: role_ids["runtime-external"],
            role_ids,
        })
    }
}

fn prepare_entry_role_root(rootfs: &Path, workload_path: &Path) -> Result<Vec<String>> {
    let executables = [
        (Path::new("/bin/sh"), rootfs.join("bin/sh")),
        (workload_path, rootfs.join("bin/sleep")),
    ];
    let mut dependencies = BTreeSet::new();
    for (source, destination) in &executables {
        fs::copy(source, destination).context(IoSnafu { path: source })?;
        let output = Command::new("ldd").arg(source).output().context(IoSnafu {
            path: Path::new("ldd"),
        })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "ldd".to_owned(),
                reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
        );
        dependencies.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(ldd_dependency_path),
        );
    }
    ensure!(
        !dependencies.is_empty(),
        InvalidInputSnafu {
            path: workload_path,
            reason: "the direct runc entry-role workload must use a dynamic loader",
        }
    );
    for entry in ["cp", "dd", "cat", "grep", "wc"] {
        let destination = rootfs.join("bin").join(entry);
        fs::hard_link(rootfs.join("bin/sh"), &destination)
            .context(IoSnafu { path: &destination })?;
    }
    IdentityTestRunner::materialize_post_ponr_execfail(&rootfs.join("bin/post-ponr-execfail"))?;
    let role_directory = rootfs.join("run/mithril-entry-roles");
    fs::create_dir_all(&role_directory).context(IoSnafu {
        path: &role_directory,
    })?;
    for role in [
        "application",
        "poststart",
        "prestop",
        "startup",
        "readiness",
        "liveness",
    ] {
        let path = role_directory.join(format!("{role}.denied"));
        fs::write(&path, format!("{role}\n")).context(IoSnafu { path: &path })?;
    }
    fs::write(role_directory.join("control.allowed"), b"allowed\n").context(IoSnafu {
        path: role_directory.join("control.allowed"),
    })?;
    fs::create_dir_all(rootfs.join("backup/models")).context(IoSnafu {
        path: rootfs.join("backup/models"),
    })?;
    for dependency in &dependencies {
        let source = Path::new(dependency);
        let relative = source.strip_prefix("/").map_err(|error| {
            InvalidInputSnafu {
                path: source,
                reason: format!("dynamic-loader path is not absolute: {error}"),
            }
            .build()
        })?;
        let destination = rootfs.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        }
        fs::copy(source, &destination).context(IoSnafu { path: source })?;
    }
    Ok(dependencies.into_iter().collect())
}

fn ldd_dependency_path(line: &str) -> Option<String> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let candidate = match fields.as_slice() {
        [_, "=>", path, ..] => *path,
        [path, ..] => *path,
        [] => return None,
    };
    candidate.starts_with('/').then(|| candidate.to_owned())
}

fn run_checked(command: &mut Command, program: &Path) -> Result<()> {
    let output = command.output().context(IoSnafu { path: program })?;
    ensure!(
        output.status.success(),
        CommandSnafu {
            program: program.display().to_string(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
    );
    Ok(())
}

fn command_text(command: &mut Command, program: &Path) -> Result<String> {
    let output = command.output().context(IoSnafu { path: program })?;
    ensure!(
        output.status.success(),
        CommandSnafu {
            program: program.display().to_string(),
            reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn signal_process(host_pid: u32, signal: Signal) -> Result<()> {
    let raw_pid = i32::try_from(host_pid).map_err(|error| {
        InvalidInputSnafu {
            path: PathBuf::from(format!("/proc/{host_pid}")),
            reason: format!("host PID is invalid: {error}"),
        }
        .build()
    })?;
    let pid = Pid::from_raw(raw_pid).ok_or_else(|| {
        InvalidInputSnafu {
            path: PathBuf::from(format!("/proc/{host_pid}")),
            reason: "host PID zero cannot identify a task",
        }
        .build()
    })?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: PathBuf::from(format!("/proc/{host_pid}")),
        })?;
    pidfd_send_signal(&pidfd, signal).map_err(|error| {
        InvalidInputSnafu {
            path: PathBuf::from(format!("/proc/{host_pid}")),
            reason: format!("send {signal:?} to held task: {error}"),
        }
        .build()
    })
}

fn wait_for_path(path: &Path, exists: bool, name: &str) -> Result<()> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if path.exists() == exists {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path,
                reason: format!("timed out waiting for {name}"),
            }
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_post_ponr_terminal_exec(
    host: &KernelHost,
    profile_generation_ref_id: u64,
    diagnostic_path: &Path,
) -> Result<PendingExecV1> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        for key in host.map_keys("pending_execs").context(InterceptorSnafu)? {
            let Some(value) = host
                .lookup_map("pending_execs", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let pending = PendingExecV1::try_read_from_bytes(&value).map_err(|error| {
                InvalidInputSnafu {
                    path: diagnostic_path,
                    reason: format!("a pending exec has invalid ABI: {error}"),
                }
                .build()
            })?;
            if pending.source_profile_generation_ref_id == profile_generation_ref_id
                && pending.state == PendingExecStateV1::PostPonrFatal
            {
                return Ok(pending);
            }
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: diagnostic_path,
                reason: "timed out waiting for terminal post-PONR exec evidence",
            }
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn recent_effect_summary(observations: &EffectObservationStore, marker: u64) -> Vec<String> {
    observations
        .recent_since(marker)
        .iter()
        .rev()
        .take(16)
        .map(|event| {
            format!(
                "reason={} family={} operation={} generation={} binding={} role={} vector={} admission={} atom={} object={} file=({},{},{},{},{}) result={}",
                event.reason,
                event.effect_family,
                event.operation,
                event.profile_generation_ref_id,
                event.binding_id,
                event.active_role_id,
                event.process_state_vector_id,
                event.admitted_entry_rule_id,
                event.composite_atom_id,
                event.exact_object_key_id,
                event.mount_namespace_inode,
                event.mount_id_unique,
                event.filesystem_device,
                event.inode,
                event.inode_generation,
                event.kernel_result,
            )
        })
        .collect()
}

fn wait_for_pid_file(path: &Path, child: &mut Child) -> Result<Option<u32>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            if let Ok(pid) = value.trim().parse::<u32>() {
                if pid > 0 {
                    return Ok(Some(pid));
                }
            }
        }
        if child
            .try_wait()
            .context(IoSnafu {
                path: Path::new("runc exec child"),
            })?
            .is_some()
        {
            return Ok(None);
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path,
                reason: "timed out waiting for an entry host PID",
            }
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_task_snapshot(
    inspector: &NativeIdentityInspector,
    host_pid: u32,
    child: &mut Child,
    reader: &erebor_interceptor::EffectObservationReader,
    observations: &EffectObservationStore,
    marker: u64,
    stderr: &Path,
) -> Result<NativeTaskSnapshotV1> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        reader
            .poll(Duration::from_millis(25))
            .context(InterceptorSnafu)?;
        if let Some(status) = child.try_wait().context(IoSnafu {
            path: Path::new("runc exec child"),
        })? {
            ensure!(
                false,
                InvalidInputSnafu {
                    path: stderr,
                    reason: format!(
                        "entry PID {host_pid} exited before its admitted snapshot: status={status}, stderr={}, effects={:?}",
                        fs::read_to_string(stderr).unwrap_or_default().trim(),
                        recent_effect_summary(observations, marker)
                    ),
                }
            );
        }
        if let Some(snapshot) = inspector.snapshot(host_pid).context(NodeSnafu)? {
            if snapshot.admitted_entry_rule_id > 0 {
                return Ok(snapshot);
            }
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: stderr,
                reason: format!("timed out waiting for admitted entry PID {host_pid}"),
            }
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_entry_policy_deny(
    reader: &erebor_interceptor::EffectObservationReader,
    observations: &EffectObservationStore,
    marker: u64,
    active_role_id: u32,
    admitted_entry_rule_id: u32,
) -> Result<bool> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        reader
            .poll(Duration::from_millis(50))
            .context(InterceptorSnafu)?;
        if observations.recent_since(marker).iter().any(|event| {
            event.reason == "EXACT_POLICY_DENY"
                && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                && event.operation == u32::from(KernelEffectOperationV1::OpenRead as u16)
                && event.active_role_id == active_role_id
                && event.admitted_entry_rule_id == admitted_entry_rule_id
                && event.kernel_result == -13
        }) {
            return Ok(true);
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("effect_observations"),
                reason: "timed out waiting for the admitted entry policy denial",
            }
        );
    }
}

fn wait_for_runtime_active(
    reader: &erebor_interceptor::EffectObservationReader,
    observations: &EffectObservationStore,
    marker: u64,
    inspector: &NativeIdentityInspector,
    initial_pid: u32,
    output_directory: &Path,
) -> Result<()> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        reader
            .poll(Duration::from_millis(50))
            .context(InterceptorSnafu)?;
        if inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .and_then(|snapshot| snapshot.runtime_binding)
            .is_some_and(|binding| binding.prepared_container_state == "active")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let process = ["status", "wchan", "stack"]
                .into_iter()
                .map(|name| {
                    let path = PathBuf::from(format!("/proc/{initial_pid}/{name}"));
                    let value = fs::read_to_string(&path)
                        .unwrap_or_else(|error| format!("unavailable: {error}"));
                    format!("[{name}]\n{value}")
                })
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(
                output_directory.join("runc-entry-role-process.txt"),
                process,
            )
            .context(IoSnafu {
                path: output_directory,
            })?;
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("prepared_container_state"),
                reason: format!(
                    "direct runc did not activate normal policy; observations={:?}",
                    observations
                        .recent_since(marker)
                        .iter()
                        .map(|event| (
                            event.reason.as_str(),
                            event.effect_family,
                            event.operation,
                            event.exact_object_key_id,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
    }
}

fn wait_for_child(child: &mut Child) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(status) = child.try_wait().context(IoSnafu {
            path: Path::new("runc child"),
        })? {
            return Ok(status);
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("runc child"),
                reason: "direct runc did not exit after the workload release",
            }
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn remove_cgroup(path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error)
                if Instant::now() < deadline
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::EBUSY) | Some(libc::ENOTEMPTY)
                    ) =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            Err(source) => return Err(source).context(IoSnafu { path }),
        }
    }
}
