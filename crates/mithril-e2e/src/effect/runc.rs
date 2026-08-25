use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::KernelEffectOperationV1;
use mithril_control::{EntryKindV1, PathSelectorV1, PolicyDocumentV1, RuleMatchV1};
use mithril_node::{
    EffectObservationStore, NativeIdentityInspector, NativeSecurityStateOwner,
    NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use super::support::{
    effect_binding_with_identity, effect_node_config, wait_for_path_exec_effect, wait_for_reason,
};
use super::{sign_generation_artifact, EffectTestRunner, PROFILE_GENERATION_REF_ID};
use crate::error::{
    CommandSnafu, InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeDirectory, ProbeFile};
use crate::Result;

const WAIT_LIMIT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuncPreparedProbeV1 {
    pub schema_version: u32,
    pub runc_version: String,
    pub initial_host_pid: u32,
    pub prepared_state_before_exec: String,
    pub prepared_state_after_exec: String,
    pub prepared_runtime_effect_observed: bool,
    pub path_exec_allow_observed: bool,
    pub executable_observation_has_no_exact_object: bool,
    pub container_exit_success: bool,
    pub pin_root_removed: bool,
    pub lease_removed: bool,
    pub cgroup_removed: bool,
    pub fixture_root_removed: bool,
}

struct RuncContainer {
    child: Option<Child>,
    runc_path: PathBuf,
    state_root: PathBuf,
    container_id: String,
    cgroup_path: PathBuf,
}

impl RuncContainer {
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
    #[allow(clippy::too_many_arguments)]
    pub fn runc_prepared_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        runc_path: &Path,
        busybox_path: &Path,
        prestart_hook: &Path,
    ) -> Result<RuncPreparedProbeV1> {
        for path in [pin_root, lease_path] {
            ensure!(
                !path.exists(),
                InvalidInputSnafu {
                    path,
                    reason: "the direct runc probe requires fresh Mithril ownership",
                }
            );
        }
        for path in [runc_path, busybox_path, prestart_hook] {
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
        let fixture_root = output_directory.join("runc-prepared-fixture");
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
        let stdout_path = output_directory.join("runc-prepared.stdout");
        let stderr_path = output_directory.join("runc-prepared.stderr");
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
        fs::copy(busybox_path, rootfs.join("bin/busybox"))
            .context(IoSnafu { path: busybox_path })?;
        symlink("busybox", rootfs.join("bin/sleep")).context(IoSnafu {
            path: &rootfs.join("bin/sleep"),
        })?;

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
        config["process"]["args"] = json!(["/bin/sleep", "3"]);
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
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
        )
        .context(IoSnafu { path: &config_path })?;

        let artifact = self.build_runc_artifact(&fixture_root)?;
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
        wait_for_path(&request_path, true, "the stock runc prestart request")?;
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                path: &request_path,
            })?)
            .context(JsonSnafu {
                path: &request_path,
            })?;
        fs::copy(
            &request_path,
            output_directory.join("runc-prepared-request.json"),
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
                    reason: "the stock runc prestart request has no valid PID",
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
            output_directory.join("runc-prepared-root.txt"),
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
                    reason: "the stock runc prestart request has no cgroup",
                }
                .build()
            })?;
        ensure!(
            observed_cgroup == format!("/{cgroup_name}"),
            InvalidInputSnafu {
                path: &request_path,
                reason: format!("stock runc used unexpected cgroup `{observed_cgroup}`"),
            }
        );
        signal_process(initial_pid, Signal::STOP)?;

        let (boot_id, node_boot_id) = boot_identity()?;
        let mut host = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id,
            1,
        ))
        .start()
        .context(InterceptorSnafu)?;
        let binding = effect_binding_with_identity(
            &cgroup_path,
            "99999999-9999-4999-8999-999999999996",
            'f',
            "direct-runc",
            true,
        );
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
            artifact,
            vec![binding],
        );
        let _policy =
            NodePolicyGenerationOwner::load_and_install(&node_config, &mut host, node_boot_id, 1)
                .context(NodeSnafu)?;
        let identity = NativeSecurityStateOwner::new(node_boot_id, 1);
        identity
            .activate_held_initial_admission(&mut host, true)
            .context(NodeSnafu)?;
        let reconciliation = identity.reconcile(&mut host, true).context(NodeSnafu)?;
        ensure!(
            reconciliation == Default::default(),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "the held stock runc task failed prepared reconciliation: {reconciliation:?}"
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
                    reason: "the held stock runc task has no prepared identity",
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
                reason: "the held stock runc task is not in PREPARED state",
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
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let active = inspector
            .snapshot(initial_pid)
            .context(NodeSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: pin_root,
                    reason: "the stock runc task lost identity after its first exec",
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

        let status = wait_for_child(container.child.as_mut().ok_or_else(|| {
            InvalidInputSnafu {
                path: runc_path,
                reason: "the stock runc child disappeared",
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
        drop(reader);
        host.shutdown().context(InterceptorSnafu)?;
        pin_cleanup.cleanup()?;
        lease_cleanup.cleanup()?;
        let cgroup_removed = !cgroup_path.exists();
        ensure!(
            cgroup_removed,
            InvalidInputSnafu {
                path: &cgroup_path,
                reason: "the stock runc cgroup survived container deletion",
            }
        );
        fs::remove_dir_all(&fixture_root).context(IoSnafu {
            path: &fixture_root,
        })?;

        Ok(RuncPreparedProbeV1 {
            schema_version: 1,
            runc_version: runc_version.lines().next().unwrap_or_default().to_owned(),
            initial_host_pid: initial_pid,
            prepared_state_before_exec,
            prepared_state_after_exec,
            prepared_runtime_effect_observed: true,
            path_exec_allow_observed: true,
            executable_observation_has_no_exact_object: true,
            container_exit_success: true,
            pin_root_removed: !pin_root.exists(),
            lease_removed: !lease_path.exists(),
            cgroup_removed,
            fixture_root_removed: !fixture_root.exists(),
        })
    }

    fn build_runc_artifact(&self, fixture_root: &Path) -> Result<PathBuf> {
        let policy_fixture = self
            .repo_root
            .join("crates/mithril-e2e/fixtures/mithril-policy");
        let policy_source = policy_fixture.join("protect-policy-v1.yaml");
        let mut document = PolicyDocumentV1::parse(
            &policy_source,
            &fs::read(&policy_source).context(IoSnafu {
                path: &policy_source,
            })?,
        )
        .context(PolicySnafu)?;
        document.path_selectors = vec![
            PathSelectorV1::path("manual-exec-allowed", "/bin/busybox", "MANUAL_EXEC_ALLOWED"),
            PathSelectorV1::exact(
                "manual-device-ptmx",
                "/dev/pts/ptmx",
                "MANUAL_DEVICE_ALLOWED",
            )
            .with_device_class("PTMX_DEVICE"),
            PathSelectorV1::exact("manual-device-zero", "/dev/zero", "MANUAL_DEVICE_DENIED")
                .with_device_class("ZERO_DEVICE"),
        ];
        let mut prepared_exec_rule = document
            .rules
            .iter()
            .find(|rule| rule.rule_id == "allow-manual-exec-allowed")
            .cloned()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: &policy_source,
                    reason: "the direct runc fixture has no executable allow rule",
                }
                .build()
            })?;
        prepared_exec_rule.rule_id = "allow-prepared-container-exec".to_owned();
        let RuleMatchV1::LocalPreEffect(exec_match) = &mut prepared_exec_rule.rule_match else {
            return InvalidInputSnafu {
                path: &policy_source,
                reason: "the direct runc executable allow rule is not a local effect rule",
            }
            .fail();
        };
        // The first application exec is evaluated against the prepared
        // container entry. A runtime-external rule cannot authorize it.
        exec_match.subject.entry_kind_ids = vec![EntryKindV1::ContainerStart];
        exec_match.subject.role_ids = vec!["converter".to_owned()];
        document.rules.push(prepared_exec_rule);
        sign_generation_artifact(
            document,
            &policy_fixture.join("observe-profile-seal-request.json"),
            &policy_fixture.join("test-signing-key.hex"),
            fixture_root,
            1,
        )
    }
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
            fs::write(output_directory.join("runc-prepared-process.txt"), process).context(
                IoSnafu {
                    path: output_directory,
                },
            )?;
        }
        ensure!(
            Instant::now() < deadline,
            InvalidInputSnafu {
                path: Path::new("prepared_container_state"),
                reason: format!(
                    "stock runc did not activate normal policy; observations={:?}",
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
                reason: "stock runc did not exit after the workload release",
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
