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
    CanonicalMountRootKeyV1, CanonicalMountRootV1, EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1,
    ExecGuardStateV1, Id128V1, KernelEffectFamilyV1, KernelEffectOperationV1, PendingExecStateV1,
    PendingExecV1, ProcessSecurityStateV1, TaskCoordinateStateV1,
};
use erebor_runtime_ipc::v1::MithrilEffectObservation;
use mithril_control::{
    lower_kubernetes_policy, policy_custom_resource, WorkloadProtectionPolicySpec,
};
use mithril_node::{
    EffectObservationStore, NativeIdentityInspector, NativeSecurityStateOwner,
    NativeTaskSnapshotV1, NodePolicyGenerationOwner, WorkloadBindingOwner,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use super::support::{
    effect_binding_with_identity, effect_node_config, wait_for_application_default_effect,
    wait_for_reason, ExternalMountNamespace,
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
    pub kubernetes_subpath_alias_path_tree_denied: bool,
    pub newer_kubernetes_subpath_alias_path_tree_denied: bool,
    pub container_bind_mount_succeeded: bool,
    pub container_bind_alias_path_tree_denied: bool,
    pub single_wildcard_path_tree_denied: bool,
    pub recursive_wildcard_path_tree_denied: bool,
    pub other_role_path_tree_allowed: bool,
    pub path_tree_control_allowed: bool,
    pub application_admitted_entry_rule_id: u32,
    pub independent_entries: Vec<RuncEntryRoleProbeV1>,
    pub independent_entry_roles_are_distinct: bool,
    pub reusable_entry_reinvocation_isolated: bool,
    pub runtime_entry_infrastructure_observed: bool,
    pub live_replacement_preserved_running_application: bool,
    pub live_replacement_entries_use_new_generation: bool,
    pub node_owner_restart_preserved_running_application: bool,
    pub prestop_retained_during_runtime_inventory_omission: bool,
    pub retained_mount_views_survived_source_exit: bool,
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
    pub cri_sandbox_allowed: bool,
    pub cri_sandbox_process_started: bool,
    pub cri_sandbox_decision_logged: bool,
    pub forged_cri_sandbox_denied: bool,
    pub forged_cri_sandbox_process_never_started: bool,
    pub forged_cri_sandbox_decision_logged: bool,
    pub exact_recovery_allowed: bool,
    pub exact_recovery_process_started: bool,
    pub exact_recovery_decision_logged: bool,
    pub exact_installer_allowed: bool,
    pub exact_installer_process_started: bool,
    pub changed_installer_allowed: bool,
    pub changed_installer_process_started: bool,
    pub changed_installer_decision_logged: bool,
    pub forged_installer_denied: bool,
    pub forged_installer_process_never_started: bool,
    pub forged_installer_decision_logged: bool,
    pub changed_recovery_binary_denied: bool,
    pub changed_recovery_binary_process_never_started: bool,
    pub changed_recovery_binary_decision_logged: bool,
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
    installer_args: Vec<String>,
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
        let pause = rootfs.join("pause");
        fs::write(&pause, b"#!/bin/sh\nprintf CRI_SANDBOX_ALLOWED\n")
            .context(IoSnafu { path: &pause })?;
        fs::set_permissions(&pause, fs::Permissions::from_mode(0o755))
            .context(IoSnafu { path: &pause })?;
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
        let installer = rootfs.join("usr/local/bin/mithril-oci-hook");
        fs::create_dir_all(installer.parent().ok_or_else(|| {
            InvalidInputSnafu {
                path: &installer,
                reason: "the installer fixture path has no parent",
            }
            .build()
        })?)
        .context(IoSnafu { path: &installer })?;
        fs::write(
            &installer,
            b"#!/bin/sh\nprintf INSTALLER_ALLOWED >/result/installer\n",
        )
        .context(IoSnafu { path: &installer })?;
        fs::set_permissions(&installer, fs::Permissions::from_mode(0o755))
            .context(IoSnafu { path: &installer })?;
        let installer_digest = format!(
            "{:x}",
            Sha256::digest(fs::read(&installer).context(IoSnafu { path: &installer })?)
        );
        let host_hook_directory = fixture_root.join("host-hook");
        let host_containerd_directory = fixture_root.join("host-containerd");
        fs::create_dir(&host_hook_directory).context(IoSnafu {
            path: &host_hook_directory,
        })?;
        fs::create_dir(&host_containerd_directory).context(IoSnafu {
            path: &host_containerd_directory,
        })?;
        let mut recovery_args = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf RECOVERY_ALLOWED >/result/recovery".to_owned(),
        ];
        recovery_args.extend((0..35).map(|index| format!("recovery-argument-{index}")));
        let installer_args = vec![
            "/usr/local/bin/mithril-oci-hook".to_owned(),
            "install".to_owned(),
            "--owner".to_owned(),
            "mithril-system/mithril".to_owned(),
            "--hook-host-directory".to_owned(),
            "/usr/libexec/oci/hooks.d".to_owned(),
            "--containerd-host-directory".to_owned(),
            "/var/lib/rancher/k3s/agent/etc/containerd".to_owned(),
            "--k3s-host-path".to_owned(),
            "/usr/local/bin/k3s".to_owned(),
            "--socket".to_owned(),
            "/run/mithril/runtime-admission.sock".to_owned(),
        ];
        let manifest = fixture_root.join("mithril-recovery.json");
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "entries": [
                    {
                        "executable": "/bin/sh",
                        "executableSha256": shell_digest,
                        "args": recovery_args,
                        "requiredMounts": [
                            {
                                "source": marker_directory,
                                "destination": "/result",
                                "readOnly": false
                            },
                            {
                                "source": host_hook_directory,
                                "destination": "/host-hook-bin",
                                "readOnly": false
                            },
                            {
                                "source": host_containerd_directory,
                                "destination": "/host-containerd",
                                "readOnly": false
                            }
                        ]
                    },
                    {
                        "executable": "/usr/local/bin/mithril-oci-hook",
                        "executableSha256": installer_digest,
                        "args": installer_args,
                        "requiredMounts": [
                            {
                                "source": host_hook_directory,
                                "destination": "/host-hook-bin",
                                "readOnly": false
                            },
                            {
                                "source": host_containerd_directory,
                                "destination": "/host-containerd",
                                "readOnly": false
                            },
                            {
                                "source": k3s_path,
                                "destination": "/host-k3s",
                                "readOnly": true
                            }
                        ]
                    }
                ]
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
            installer_args,
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

    fn run_cri_sandbox(&self) -> Result<RetainedRuntimeGateCaseResult> {
        self.run_case("cri-sandbox", self.cri_sandbox_config()?)
    }

    fn run_forged_cri_sandbox(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let mut config = self.cri_sandbox_config()?;
        config["process"]["args"] = json!([
            "/bin/sh",
            "-c",
            "printf FORGED_SANDBOX_RAN >/result/forged-cri-sandbox"
        ]);
        self.add_bind_mount(
            &mut config,
            &self.marker_directory,
            Path::new("/result"),
            false,
        )?;
        self.run_case("forged-cri-sandbox", config)
    }

    fn run_exact_recovery(&self) -> Result<RetainedRuntimeGateCaseResult> {
        self.run_case("exact-recovery", self.exact_recovery_config()?)
    }

    fn run_exact_installer(&self) -> Result<RetainedRuntimeGateCaseResult> {
        self.run_case("exact-installer", self.installer_config(false)?)
    }

    fn run_changed_installer(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let executable = self.bundle.join("rootfs/usr/local/bin/mithril-oci-hook");
        let original = fs::read(&executable).context(IoSnafu { path: &executable })?;
        fs::OpenOptions::new()
            .append(true)
            .open(&executable)
            .and_then(|mut file| file.write_all(b"# upgraded Mithril installer\n"))
            .context(IoSnafu { path: &executable })?;
        let marker = self.marker_directory.join("installer");
        if marker.exists() {
            fs::remove_file(&marker).context(IoSnafu { path: &marker })?;
        }
        let result = self.run_case("changed-installer", self.installer_config(true)?);
        fs::write(&executable, original).context(IoSnafu { path: &executable })?;
        result
    }

    fn run_forged_installer(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let mut config = self.installer_config(true)?;
        config["process"]["args"][3] = json!("attacker/other");
        let marker = self.marker_directory.join("installer");
        if marker.exists() {
            fs::remove_file(&marker).context(IoSnafu { path: &marker })?;
        }
        self.run_case("forged-installer", config)
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

    fn run_changed_recovery_binary(&self) -> Result<RetainedRuntimeGateCaseResult> {
        let executable = self.bundle.join("rootfs/bin/sh");
        let original = fs::read(&executable).context(IoSnafu { path: &executable })?;
        fs::OpenOptions::new()
            .append(true)
            .open(&executable)
            .and_then(|mut file| file.write_all(&[0]))
            .context(IoSnafu { path: &executable })?;
        let marker = self.marker_directory.join("recovery");
        if marker.exists() {
            fs::remove_file(&marker).context(IoSnafu { path: &marker })?;
        }
        let result = self.run_case("changed-recovery-binary", self.exact_recovery_config()?);
        fs::write(&executable, original).context(IoSnafu { path: &executable })?;
        result
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
        self.add_bind_mount(
            &mut config,
            &self.fixture_root.join("host-hook"),
            Path::new("/host-hook-bin"),
            false,
        )?;
        self.add_bind_mount(
            &mut config,
            &self.fixture_root.join("host-containerd"),
            Path::new("/host-containerd"),
            false,
        )?;
        Ok(config)
    }

    fn cri_sandbox_config(&self) -> Result<serde_json::Value> {
        let mut config = self.stock_config("cri-sandbox")?;
        config["process"]["args"] = json!(["/pause"]);
        config["process"]["noNewPrivileges"] = json!(true);
        config["process"]["capabilities"] = json!({
            "bounding": ["CAP_CHOWN", "CAP_NET_RAW"],
            "effective": ["CAP_CHOWN", "CAP_NET_RAW"],
            "permitted": ["CAP_CHOWN", "CAP_NET_RAW"]
        });
        config["root"]["readonly"] = json!(true);
        config["annotations"] = json!({
            "io.kubernetes.cri.container-type": "sandbox",
            "io.kubernetes.cri.podsandbox.image-name": "registry.k8s.io/pause:3.10",
            "io.kubernetes.cri.sandbox-id": format!(
                "{:064x}",
                Sha256::digest(b"cri-sandbox")
            )
        });
        config["mounts"]
            .as_array_mut()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: self.bundle.join("config.json"),
                    reason: "the generated runc spec has no mount array",
                }
                .build()
            })?
            .retain(|mount| mount["destination"] != "/result");
        Ok(config)
    }

    fn installer_config(&self, upgraded: bool) -> Result<serde_json::Value> {
        let mut config = self.stock_config(if upgraded {
            "changed-installer"
        } else {
            "exact-installer"
        })?;
        config["process"]["args"] = if upgraded {
            json!([
                "/usr/local/bin/mithril-oci-hook",
                "install",
                "--owner",
                "mithril-system/mithril",
                "--hook-host-directory",
                "/usr/libexec/oci/hooks.d",
                "--containerd-host-directory",
                "/var/lib/rancher/k3s/agent/etc/containerd",
                "--containerd-drop-in-directory",
                "config-v3.toml.d",
                "--runtime-cli-host-path",
                "/usr/local/bin/k3s",
                "--runtime-cli-arg",
                "ctr",
                "--runtime-cli-arg",
                "oci",
                "--runtime-cli-arg",
                "spec",
                "--runtime-service",
                "k3s",
                "--runtime-service",
                "k3s-agent",
                "--socket",
                "/run/mithril/runtime-admission.sock",
                "--decommission-state-directory",
                "/var/lib/mithril"
            ])
        } else {
            json!(self.installer_args)
        };
        self.add_bind_mount(
            &mut config,
            &self.fixture_root.join("host-hook"),
            Path::new("/host-hook-bin"),
            false,
        )?;
        self.add_bind_mount(
            &mut config,
            &self.fixture_root.join("host-containerd"),
            Path::new("/host-containerd"),
            false,
        )?;
        self.add_bind_mount(
            &mut config,
            &self.k3s_path,
            if upgraded {
                Path::new("/host-runtime-cli")
            } else {
                Path::new("/host-k3s")
            },
            true,
        )?;
        Ok(config)
    }

    fn exact_recovery_log(&self) -> Result<String> {
        self.decision_log(self.exact_recovery_config()?, b"exact-recovery-log")
    }

    fn cri_sandbox_log(&self) -> Result<String> {
        self.decision_log(self.cri_sandbox_config()?, b"cri-sandbox-log")
    }

    fn changed_installer_log(&self) -> Result<String> {
        self.decision_log(self.installer_config(true)?, b"changed-installer-log")
    }

    fn decision_log(&self, config: serde_json::Value, identity: &[u8]) -> Result<String> {
        let config_path = self.bundle.join("config.json");
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).context(JsonSnafu { path: &config_path })?,
        )
        .context(IoSnafu { path: &config_path })?;
        let state = serde_json::to_vec(&json!({
            "id": format!("{:064x}", Sha256::digest(identity)),
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

    fn prepare_path_tree_aliases(&self, host_pid: u32, rootfs: &Path) -> Result<()> {
        let source_root = rootfs.join("home/secret");
        let source_file = source_root.join("models/secret");
        let kubernetes_alias = rootfs.join("home/kubelet-attack/secret");
        let newer_kubernetes_alias = rootfs.join("home/kubelet-attack-newer/secret");
        let container_alias = rootfs.join("home/attack");
        let single_wildcard_file = rootfs.join("home/alice/secrets/secret");
        let recursive_wildcard_file = rootfs.join("srv/team/blue/secrets/secret");
        let mount_namespace = ExternalMountNamespace::acquire(host_pid)?;
        mount_namespace.create_dir_all(&container_alias)?;
        ensure!(
            mount_namespace.read_file(&source_file)?.is_empty()
                && mount_namespace.read_file(&kubernetes_alias)?.is_empty()
                && mount_namespace
                    .read_file(&newer_kubernetes_alias)?
                    .is_empty()
                && mount_namespace.read_file(&single_wildcard_file)?.is_empty()
                && mount_namespace
                    .read_file(&recursive_wildcard_file)?
                    .is_empty(),
            InvalidInputSnafu {
                path: &source_root,
                reason:
                    "the direct runc path-tree aliases are not readable before policy activation",
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
        let cri_sandbox = fixture.run_cri_sandbox()?;
        let forged_cri_sandbox = fixture.run_forged_cri_sandbox()?;
        let recovery = fixture.run_exact_recovery()?;
        let exact_recovery_process_started = fixture.marker_exists("recovery");
        let installer = fixture.run_exact_installer()?;
        let exact_installer_process_started = fixture.marker_exists("installer");
        let changed_installer = fixture.run_changed_installer()?;
        let changed_installer_process_started = fixture.marker_exists("installer");
        let forged_installer = fixture.run_forged_installer()?;
        let changed_binary = fixture.run_changed_recovery_binary()?;
        let changed = fixture.run_changed_recovery()?;
        let host_stock_spec = fixture.run_host_stock_spec()?;
        let cri_sandbox_log = fixture.cri_sandbox_log()?;
        let recovery_log = fixture.exact_recovery_log()?;
        let installer_log = fixture.changed_installer_log()?;
        let host_stock_spec_generated = host_stock_spec.success
            && serde_json::from_str::<serde_json::Value>(&host_stock_spec.stdout)
                .ok()
                .and_then(|spec| spec.get("ociVersion").cloned())
                .is_some();

        let result = RuncRetainedRuntimeGateProbeV1 {
            schema_version: 3,
            runc_version: command_text(Command::new(runc_path).arg("--version"), runc_path)?,
            hostile_container_denied: !hostile.success,
            hostile_process_never_started: !fixture.marker_exists("hostile"),
            hostile_decision_logged: hostile.stderr.contains("decision=DENY_HOSTILE"),
            cri_sandbox_allowed: cri_sandbox.success,
            cri_sandbox_process_started: cri_sandbox.stdout.trim() == "CRI_SANDBOX_ALLOWED",
            cri_sandbox_decision_logged: cri_sandbox_log.contains("decision=ALLOW_CRI_SANDBOX"),
            forged_cri_sandbox_denied: !forged_cri_sandbox.success,
            forged_cri_sandbox_process_never_started: !fixture.marker_exists("forged-cri-sandbox"),
            forged_cri_sandbox_decision_logged: forged_cri_sandbox
                .stderr
                .contains("decision=DENY_NODE_UNAVAILABLE"),
            exact_recovery_allowed: recovery.success,
            exact_recovery_process_started,
            exact_recovery_decision_logged: recovery_log.contains("decision=ALLOW_EXACT_RECOVERY"),
            exact_installer_allowed: installer.success,
            exact_installer_process_started,
            changed_installer_allowed: changed_installer.success,
            changed_installer_process_started,
            changed_installer_decision_logged: installer_log
                .contains("decision=ALLOW_MITHRIL_INSTALLER"),
            forged_installer_denied: !forged_installer.success,
            forged_installer_process_never_started: !fixture.marker_exists("installer"),
            forged_installer_decision_logged: forged_installer
                .stderr
                .contains("decision=DENY_NODE_UNAVAILABLE"),
            changed_recovery_binary_denied: !changed_binary.success,
            changed_recovery_binary_process_never_started: !fixture.marker_exists("recovery"),
            changed_recovery_binary_decision_logged: changed_binary
                .stderr
                .contains("decision=DENY_NODE_UNAVAILABLE"),
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
                && result.cri_sandbox_allowed
                && result.cri_sandbox_process_started
                && result.cri_sandbox_decision_logged
                && result.forged_cri_sandbox_denied
                && result.forged_cri_sandbox_process_never_started
                && result.forged_cri_sandbox_decision_logged
                && result.exact_recovery_allowed
                && result.exact_recovery_process_started
                && result.exact_recovery_decision_logged
                && result.exact_installer_allowed
                && result.exact_installer_process_started
                && result.changed_installer_allowed
                && result.changed_installer_process_started
                && result.changed_installer_decision_logged
                && result.forged_installer_denied
                && result.forged_installer_process_never_started
                && result.forged_installer_decision_logged
                && result.changed_recovery_binary_denied
                && result.changed_recovery_binary_process_never_started
                && result.changed_recovery_binary_decision_logged
                && result.changed_recovery_denied
                && result.changed_recovery_process_never_started
                && result.unavailable_decision_logged
                && result.host_stock_spec_generated,
            InvalidInputSnafu {
                path: output_directory,
                reason: format!(
                    "the direct runc retained-gate oracle failed: hostile={:?}; cri_sandbox={:?}; forged_cri_sandbox={:?}; recovery={:?}; exact_installer={:?}; changed_installer={:?}; forged_installer={:?}; changed_recovery_binary={:?}; changed_recovery={:?}; stock_spec={:?}",
                    hostile.stderr.trim(),
                    cri_sandbox.stderr.trim(),
                    forged_cri_sandbox.stderr.trim(),
                    recovery.stderr.trim(),
                    installer.stderr.trim(),
                    changed_installer.stderr.trim(),
                    forged_installer.stderr.trim(),
                    changed_binary.stderr.trim(),
                    changed.stderr.trim(),
                    host_stock_spec.stderr.trim(),
                ),
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
        for path in [runc_path, workload_path, retained_bpf_object] {
            ensure!(
                path.is_absolute() && path.exists(),
                InvalidInputSnafu {
                    path,
                    reason: "the direct runc probe input must be an existing absolute path",
                }
            );
        }
        let oci_stage_hook = std::env::current_exe().context(IoSnafu {
            path: Path::new("the current Mithril effect-test executable"),
        })?;

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
        let role_directory = fixture_root.join("runtime-markers");
        let request_directory = fixture_root.join("prestart-requests");
        let state_root = fixture_root.join("runc-state");
        // Keep the runtime streams outside the disposable bundle so a failed probe is diagnosable.
        let stdout_path = output_directory.join("runc-entry-role.stdout");
        let stderr_path = output_directory.join("runc-entry-role.stderr");
        fs::create_dir_all(rootfs.join("bin")).context(IoSnafu { path: &rootfs })?;
        let path_tree_source = fixture_root.join("path-tree");
        let path_tree_models = path_tree_source.join("models");
        fs::create_dir_all(&path_tree_models).context(IoSnafu {
            path: &path_tree_source,
        })?;
        fs::File::create(path_tree_models.join("secret")).context(IoSnafu {
            path: &path_tree_source,
        })?;
        fs::File::create(path_tree_source.join("secret")).context(IoSnafu {
            path: &path_tree_source,
        })?;
        fs::create_dir(&request_directory).context(IoSnafu {
            path: &request_directory,
        })?;
        fs::set_permissions(&request_directory, fs::Permissions::from_mode(0o700)).context(
            IoSnafu {
                path: &request_directory,
            },
        )?;
        fs::create_dir(&state_root).context(IoSnafu { path: &state_root })?;
        let dynamic_loader_paths =
            prepare_entry_role_root(&rootfs, workload_path, &role_directory)?;

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
        config["process"]["noNewPrivileges"] = json!(false);
        config["process"]["capabilities"] = json!({
            "bounding": ["CAP_SYS_ADMIN"],
            "effective": ["CAP_SYS_ADMIN"],
            "permitted": ["CAP_SYS_ADMIN"]
        });
        config["process"]["args"] = json!([
            "/bin/sh",
            "-c",
            concat!(
                "echo CONTAINER_ROOT_READY >/run/mithril-entry-roles/container-root-ready; while [ ! -e /run/mithril-entry-roles/effects-ready ]; do /bin/sleep 1; done; ",
                "true 2>/dev/null </run/mithril-entry-roles/application.denied || true; ",
                "if /bin/mount --bind /home/secret /home/attack 2>/run/mithril-entry-roles/container-bind-mount.stderr; then mithril_mount_result=MOUNT_READY; else mithril_mount_result=MOUNT_FAILED; fi; ",
                "echo \"$mithril_mount_result\" >/run/mithril-entry-roles/container-bind-mount.result; ",
                "if /bin/cat /home/kubelet-attack/secret >/dev/null 2>&1; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/kubernetes-subpath.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/kubernetes-subpath.result; fi; ",
                "if /bin/cat /home/kubelet-attack-newer/secret >/dev/null 2>&1; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/kubernetes-subpath-newer.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/kubernetes-subpath-newer.result; fi; ",
                "if /bin/cat /home/attack/models/secret >/dev/null 2>&1; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/container-bind.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/container-bind.result; fi; ",
                "if /bin/cat /home/alice/secrets/secret >/dev/null 2>&1; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/single-wildcard.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/single-wildcard.result; fi; ",
                "if /bin/cat /srv/team/blue/secrets/secret >/dev/null 2>&1; then echo PATH_TREE_ALLOWED >/run/mithril-entry-roles/recursive-wildcard.result; else echo PATH_TREE_DENIED >/run/mithril-entry-roles/recursive-wildcard.result; fi; ",
                "if /bin/cat /run/mithril-entry-roles/control.allowed >/dev/null 2>&1; then echo CONTROL_ALLOWED >/run/mithril-entry-roles/path-tree-control.result; else echo CONTROL_DENIED >/run/mithril-entry-roles/path-tree-control.result; fi; ",
                "while [ ! -e /run/mithril-entry-roles/release ]; do /bin/sleep 1; done"
            )
        ]);
        config["root"]["path"] = json!("rootfs");
        config["root"]["readonly"] = json!(false);
        config["linux"]["cgroupsPath"] = json!(format!("/{cgroup_name}"));
        config["annotations"] = json!({
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.container-id": container_id,
        });
        config["hooks"]["createRuntime"] = json!([{
            "path": oci_stage_hook,
            "args": [
                oci_stage_hook,
                "oci-stage-fixture",
                "--stage", "createRuntime",
                "--request-directory", request_directory
            ],
            "timeout": 30,
        }]);
        config["hooks"]["createContainer"] = json!([{
            "path": oci_stage_hook,
            "args": [
                oci_stage_hook,
                "oci-stage-fixture",
                "--stage", "createContainer",
                "--request-directory", request_directory
            ],
            "timeout": 30,
        }]);
        let mounts = config["mounts"].as_array_mut().ok_or_else(|| {
            InvalidInputSnafu {
                path: &config_path,
                reason: "the generated runc spec has no mount array",
            }
            .build()
        })?;
        mounts.push(json!({
            "destination": "/run/mithril-entry-roles",
            "type": "bind",
            "source": role_directory,
            "options": ["rbind", "rprivate", "rw"]
        }));
        for (destination, source) in [
            ("/home/kubelet-attack", path_tree_models.as_path()),
            ("/home/secret", path_tree_source.as_path()),
            ("/home/kubelet-attack-newer", path_tree_models.as_path()),
            ("/home/alice/secrets", path_tree_source.as_path()),
            ("/srv/team/blue/secrets", path_tree_source.as_path()),
        ] {
            mounts.push(json!({
                "destination": destination,
                "type": "bind",
                "source": source,
                "options": ["rbind", "rprivate", "ro"]
            }));
        }
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

        let request_path = request_directory.join(format!("{container_id}.createRuntime.json"));
        wait_for_path(&request_path, true, "the direct runc createRuntime request")?;
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).context(IoSnafu {
                path: &request_path,
            })?)
            .context(JsonSnafu {
                path: &request_path,
            })?;
        fs::copy(
            &request_path,
            output_directory.join("runc-entry-role-create-runtime-request.json"),
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
                    reason: "the direct runc createRuntime request has no valid PID",
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
                    reason: "the direct runc createRuntime request has no cgroup",
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
        let read_entry_rules = |host: &KernelHost| {
            host.map_keys("entry_admission_rules")
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
                .collect::<Result<Vec<_>>>()
        };
        let provisional_entry_rules = read_entry_rules(&host)?;
        ensure!(
            provisional_entry_rules.len() == 7
                && provisional_entry_rules
                    .iter()
                    .any(|rule| rule.target_role_id == policy.initial_role_id)
                && provisional_entry_rules
                    .iter()
                    .all(|rule| rule.exact_object_key_id == 0),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "provisional application entry staging is invalid: {provisional_entry_rules:?}"
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
        let physical_effect_capture = EffectObservationStore::new(65_536);
        let sink = observations.clone();
        let capture = physical_effect_capture.clone();
        let reader = host
            .effect_observation_reader(move |bytes| {
                sink.record_bytes(bytes);
                capture.record_bytes(bytes);
                0
            })
            .context(InterceptorSnafu)?;
        let marker = observations.cursor();
        fs::write(
            request_directory.join(format!("{container_id}.createRuntime.release")),
            format!("accepted:{initial_pid}"),
        )
        .context(IoSnafu {
            path: &request_directory,
        })?;
        let create_container_request =
            request_directory.join(format!("{container_id}.createContainer.json"));
        wait_for_path(
            &create_container_request,
            true,
            "the direct runc createContainer request",
        )?;
        fs::copy(
            &create_container_request,
            output_directory.join("runc-entry-role-create-container-request.json"),
        )
        .context(IoSnafu {
            path: &create_container_request,
        })?;
        container.prepare_path_tree_aliases(initial_pid, &rootfs)?;
        container.record_mountinfo(initial_pid, output_directory)?;
        policy_owner
            .reconcile_cri_exact_bindings_for_oci_entries_for_test(
                &node_config,
                &mut host,
                &bindings,
                &binding.binding_id,
                initial_pid,
                &bundle,
            )
            .context(NodeSnafu)?;
        fs::write(
            output_directory.join("runc-entry-role-canonical-mount-roots.txt"),
            canonical_mount_route_summary(&host)?,
        )
        .context(IoSnafu {
            path: output_directory,
        })?;
        let staged_entry_rules = read_entry_rules(&host)?;
        ensure!(
            staged_entry_rules.len() == 7
                && staged_entry_rules
                    .iter()
                    .any(|rule| rule.target_role_id == policy.initial_role_id)
                && staged_entry_rules
                    .iter()
                    .all(|rule| rule.exact_object_key_id != 0),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "prepared application entry staging is invalid: {staged_entry_rules:?}"
                ),
            }
        );
        fs::write(
            request_directory.join(format!("{container_id}.createContainer.release")),
            b"accepted",
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
        wait_for_reason(
            &reader,
            &observations,
            marker,
            "PREPARED_RUNTIME_INFRASTRUCTURE",
        )?;
        let container_root_ready = role_directory.join("container-root-ready");
        wait_for_path(
            &container_root_ready,
            true,
            "the live container-root readiness marker",
        )?;
        let overlap_marker = observations.cursor();
        let poststart_overlap_pid = fixture_root.join("poststart-overlap.pid");
        let poststart_overlap_stdout = output_directory.join("poststart-overlap.stdout");
        let poststart_overlap_stderr = output_directory.join("poststart-overlap.stderr");
        let mut poststart_overlap = container.spawn_exec(
            "/bin/cp",
            &[
                "/run/mithril-entry-roles/control.allowed",
                "/run/mithril-entry-roles/poststart-overlap.fifo",
                "/run/mithril-entry-roles/poststart-overlap-output",
            ],
            &poststart_overlap_pid,
            &poststart_overlap_stdout,
            &poststart_overlap_stderr,
        )?;
        let poststart_overlap_host_pid =
            wait_for_pid_file(&poststart_overlap_pid, &mut poststart_overlap)?.ok_or_else(
                || {
                    InvalidInputSnafu {
                        path: &poststart_overlap_stderr,
                        reason: "the overlapping PostStart entry exited before publishing its PID",
                    }
                    .build()
                },
            )?;
        wait_for_task_snapshot(
            &inspector,
            poststart_overlap_host_pid,
            &mut poststart_overlap,
            &reader,
            &observations,
            overlap_marker,
            &poststart_overlap_stderr,
        )?;
        let startup_overlap_pid = fixture_root.join("startup-overlap.pid");
        let startup_overlap_stdout = output_directory.join("startup-overlap.stdout");
        let startup_overlap_stderr = output_directory.join("startup-overlap.stderr");
        let mut startup_overlap = container.spawn_exec(
            "/bin/cat",
            &[
                "/run/mithril-entry-roles/control.allowed",
                "/home/alice/secrets/models/secret",
                "/run/mithril-entry-roles/startup-overlap.fifo",
            ],
            &startup_overlap_pid,
            &startup_overlap_stdout,
            &startup_overlap_stderr,
        )?;
        let startup_overlap_host_pid =
            wait_for_pid_file(&startup_overlap_pid, &mut startup_overlap)?.ok_or_else(|| {
                InvalidInputSnafu {
                    path: &startup_overlap_stderr,
                    reason: "the overlapping StartupProbe entry exited before publishing its PID",
                }
                .build()
            })?;
        wait_for_task_snapshot(
            &inspector,
            startup_overlap_host_pid,
            &mut startup_overlap,
            &reader,
            &observations,
            overlap_marker,
            &startup_overlap_stderr,
        )?;
        let mount_change_sequence = observations.mount_change_sequence();
        fs::write(role_directory.join("effects-ready"), b"ready\n").context(IoSnafu {
            path: &role_directory,
        })?;
        let mount_event_deadline = Instant::now() + WAIT_LIMIT;
        while observations.mount_change_sequence() <= mount_change_sequence
            && Instant::now() < mount_event_deadline
        {
            reader
                .poll(Duration::from_millis(10))
                .context(InterceptorSnafu)?;
        }
        ensure!(
            observations.mount_change_sequence() > mount_change_sequence,
            InvalidInputSnafu {
                path: &rootfs,
                reason: "the successful container bind mount did not publish a mount event",
            }
        );
        let path_tree_control_result = role_directory.join("path-tree-control.result");
        wait_for_path(
            &path_tree_control_result,
            true,
            "the application control result after the mount change",
        )?;
        let path_tree_control = fs::read_to_string(&path_tree_control_result).context(IoSnafu {
            path: &path_tree_control_result,
        })?;
        ensure!(
            path_tree_control.trim() == "CONTROL_ALLOWED",
            InvalidInputSnafu {
                path: &path_tree_control_result,
                reason: format!(
                    "the synchronous BPF mount rebuild denied the application control read: effects={:?}",
                    recent_effect_summary(&observations, marker),
                ),
            }
        );
        fs::write(role_directory.join("poststart-overlap.fifo"), b"release\n").context(
            IoSnafu {
                path: &role_directory,
            },
        )?;
        fs::write(role_directory.join("startup-overlap.fifo"), b"release\n").context(IoSnafu {
            path: &role_directory,
        })?;
        ensure!(
            wait_for_child(&mut poststart_overlap)?.success()
                && wait_for_child(&mut startup_overlap)?.success(),
            InvalidInputSnafu {
                path: &role_directory,
                reason: "an overlapping Kubernetes entry failed",
            }
        );
        let concurrent_entry_marker = observations.cursor();
        let concurrent_pid_path = fixture_root.join("poststart-during-mount-reconciliation.pid");
        let concurrent_stdout =
            output_directory.join("runc-entry-poststart-during-mount-reconciliation.stdout");
        let concurrent_stderr =
            output_directory.join("runc-entry-poststart-during-mount-reconciliation.stderr");
        let concurrent_output = role_directory.join("poststart-during-mount-reconciliation-output");
        let concurrent_result = concurrent_output.join("control.allowed");
        let concurrent_release = role_directory.join("poststart-overlap.fifo");
        let mut concurrent_poststart = container.spawn_exec(
            "/bin/cp",
            &[
                "/run/mithril-entry-roles/control.allowed",
                "/run/mithril-entry-roles/poststart.denied",
                "/run/mithril-entry-roles/poststart-overlap.fifo",
                "/run/mithril-entry-roles/poststart-during-mount-reconciliation-output",
            ],
            &concurrent_pid_path,
            &concurrent_stdout,
            &concurrent_stderr,
        )?;
        let concurrent_host_pid = wait_for_pid_file(
            &concurrent_pid_path,
            &mut concurrent_poststart,
        )?
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: &concurrent_stderr,
                reason: format!(
                    "the declared PostStart entry exited while the mount view was dirty: stderr={}, effects={:?}",
                    fs::read_to_string(&concurrent_stderr)
                        .unwrap_or_default()
                        .trim(),
                    recent_effect_summary(&observations, concurrent_entry_marker),
                ),
            }
            .build()
        })?;
        let concurrent_result_deadline = Instant::now() + WAIT_LIMIT;
        while !concurrent_result.exists() {
            if let Some(status) = concurrent_poststart.try_wait().context(IoSnafu {
                path: &concurrent_stderr,
            })? {
                ensure!(
                    false,
                    InvalidInputSnafu {
                        path: &concurrent_stderr,
                        reason: format!(
                            "the declared PostStart entry exited before its control read after the mount change: status={status}, stderr={}, effects={:?}",
                            fs::read_to_string(&concurrent_stderr)
                                .unwrap_or_default()
                                .trim(),
                            recent_effect_summary(&observations, concurrent_entry_marker),
                        ),
                    }
                );
            }
            ensure!(
                Instant::now() < concurrent_result_deadline,
                InvalidInputSnafu {
                    path: &concurrent_result,
                    reason: "the declared PostStart control read did not complete after the mount change",
                }
            );
            reader
                .poll(Duration::from_millis(5))
                .context(InterceptorSnafu)?;
        }
        let concurrent_control_result = fs::read_to_string(&concurrent_result)
            .context(IoSnafu {
                path: &concurrent_result,
            })?
            .trim()
            .to_owned();
        ensure!(
            concurrent_control_result == "allowed",
            InvalidInputSnafu {
                path: &concurrent_result,
                reason: format!(
                    "the declared PostStart control read was denied while the mount view was dirty: effects={:?}",
                    recent_effect_summary(&observations, concurrent_entry_marker),
                ),
            }
        );
        let concurrent_snapshot = wait_for_task_snapshot(
            &inspector,
            concurrent_host_pid,
            &mut concurrent_poststart,
            &reader,
            &observations,
            concurrent_entry_marker,
            &concurrent_stderr,
        )?;
        fs::write(&concurrent_release, b"release\n").context(IoSnafu {
            path: &concurrent_release,
        })?;
        let concurrent_status = wait_for_child(&mut concurrent_poststart)?;
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let concurrent_role_id = policy.role_ids["poststart"];
        let concurrent_policy_deny = wait_for_entry_policy_deny(
            &reader,
            &observations,
            concurrent_entry_marker,
            concurrent_role_id,
            concurrent_snapshot.admitted_entry_rule_id,
        )?;
        ensure!(
            concurrent_status.code() == Some(1)
                && concurrent_snapshot.profile_generation_ref_id == PROFILE_GENERATION_REF_ID
                && concurrent_snapshot.active_role_id == concurrent_role_id
                && concurrent_snapshot.admitted_entry_rule_id > 0
                && concurrent_policy_deny,
            InvalidInputSnafu {
                path: &concurrent_stderr,
                reason: format!(
                    "the declared PostStart entry did not survive the mount change: status={concurrent_status}, snapshot={concurrent_snapshot:?}, stderr={}",
                    fs::read_to_string(&concurrent_stderr)
                        .unwrap_or_default()
                        .trim(),
                ),
            }
        );
        wait_for_reason(&reader, &observations, marker, "PATH_TREE_POLICY_DENY")?;
        let kubernetes_subpath_result = role_directory.join("kubernetes-subpath.result");
        let newer_kubernetes_subpath_result =
            role_directory.join("kubernetes-subpath-newer.result");
        let container_bind_mount_result = role_directory.join("container-bind-mount.result");
        let container_bind_result = role_directory.join("container-bind.result");
        let single_wildcard_result = role_directory.join("single-wildcard.result");
        let recursive_wildcard_result = role_directory.join("recursive-wildcard.result");
        for (result, description) in [
            (
                &container_bind_mount_result,
                "the in-container bind-mount result",
            ),
            (
                &kubernetes_subpath_result,
                "the older Kubernetes subPath denial result",
            ),
            (
                &newer_kubernetes_subpath_result,
                "the newer Kubernetes subPath denial result",
            ),
            (
                &container_bind_result,
                "the in-container bind denial result",
            ),
            (&single_wildcard_result, "the single-wildcard denial result"),
            (
                &recursive_wildcard_result,
                "the recursive-wildcard denial result",
            ),
        ] {
            wait_for_path(result, true, description)?;
        }
        wait_for_path(
            &path_tree_control_result,
            true,
            "the path-tree allowed-control result",
        )?;
        let kubernetes_subpath =
            fs::read_to_string(&kubernetes_subpath_result).context(IoSnafu {
                path: &kubernetes_subpath_result,
            })?;
        let newer_kubernetes_subpath = fs::read_to_string(&newer_kubernetes_subpath_result)
            .context(IoSnafu {
                path: &newer_kubernetes_subpath_result,
            })?;
        let container_bind_mount =
            fs::read_to_string(&container_bind_mount_result).context(IoSnafu {
                path: &container_bind_mount_result,
            })?;
        let container_bind_mount_stderr =
            fs::read_to_string(role_directory.join("container-bind-mount.stderr"))
                .unwrap_or_default();
        let container_bind = fs::read_to_string(&container_bind_result).context(IoSnafu {
            path: &container_bind_result,
        })?;
        let single_wildcard = fs::read_to_string(&single_wildcard_result).context(IoSnafu {
            path: &single_wildcard_result,
        })?;
        let recursive_wildcard =
            fs::read_to_string(&recursive_wildcard_result).context(IoSnafu {
                path: &recursive_wildcard_result,
            })?;
        let path_tree_control = fs::read_to_string(&path_tree_control_result).context(IoSnafu {
            path: &path_tree_control_result,
        })?;
        ensure!(
            container_bind_mount.trim() == "MOUNT_READY"
                && kubernetes_subpath.trim() == "PATH_TREE_DENIED"
                && newer_kubernetes_subpath.trim() == "PATH_TREE_DENIED"
                && container_bind.trim() == "PATH_TREE_DENIED"
                && single_wildcard.trim() == "PATH_TREE_DENIED"
                && recursive_wildcard.trim() == "PATH_TREE_DENIED"
                && path_tree_control.trim() == "CONTROL_ALLOWED",
            InvalidInputSnafu {
                path: &kubernetes_subpath_result,
                reason: format!(
                    "the direct runc path-tree results differ: container_bind_mount={container_bind_mount:?}, mount_stderr={container_bind_mount_stderr:?}, older_kubernetes_subpath={kubernetes_subpath:?}, newer_kubernetes_subpath={newer_kubernetes_subpath:?}, container_bind={container_bind:?}, single_wildcard={single_wildcard:?}, recursive_wildcard={recursive_wildcard:?}, control={path_tree_control:?}, relevant_effects={:?}",
                    observations
                        .recent_since(marker)
                        .iter()
                        .filter(|event| {
                            event.effect_family
                                == u32::from(KernelEffectFamilyV1::File as u16)
                                || event.effect_family
                                    == u32::from(KernelEffectFamilyV1::Privilege as u16)
                                || event.effect_family
                                    == u32::from(KernelEffectFamilyV1::Mount as u16)
                        })
                        .map(|event| (
                            event.reason.as_str(),
                            event.effect_family,
                            event.operation,
                            event.operation_argument,
                            event.physical_result.as_str(),
                            event.configured_errno,
                            event.kernel_result,
                            event.composite_atom_id,
                        ))
                        .collect::<Vec<_>>()
                ),
            }
        );
        reader
            .poll(Duration::from_millis(100))
            .context(InterceptorSnafu)?;
        let effect_window_churn_marker = observations.cursor();
        let effect_window_churn_pid = fixture_root.join("effect-window-churn.pid");
        let effect_window_churn_stdout = output_directory.join("effect-window-churn.stdout");
        let effect_window_churn_stderr = output_directory.join("effect-window-churn.stderr");
        let effect_window_churn_arguments = vec!["/run/mithril-entry-roles/control.allowed"; 1_200];
        let mut effect_window_churn = container.spawn_exec(
            "/bin/cat",
            &effect_window_churn_arguments,
            &effect_window_churn_pid,
            &effect_window_churn_stdout,
            &effect_window_churn_stderr,
        )?;
        let effect_window_churn_status = wait_for_child(&mut effect_window_churn)?;
        let effect_window_churn_deadline = Instant::now() + WAIT_LIMIT;
        while observations
            .cursor()
            .saturating_sub(effect_window_churn_marker)
            < 1_024
            && Instant::now() < effect_window_churn_deadline
        {
            reader
                .poll(Duration::from_millis(25))
                .context(InterceptorSnafu)?;
        }
        ensure!(
            effect_window_churn_status.success()
                && observations
                    .cursor()
                    .saturating_sub(effect_window_churn_marker)
                    >= 1_024,
            InvalidInputSnafu {
                path: &effect_window_churn_stderr,
                reason: format!(
                    "the direct runc fixture did not fill the Node-sized recent effect window: status={effect_window_churn_status}, observed={}",
                    observations
                        .cursor()
                        .saturating_sub(effect_window_churn_marker)
                ),
            }
        );
        let recent_path_tree_effect_count = observations
            .recent_since(marker)
            .iter()
            .map(physical_effect_line)
            .filter(|line| physical_path_tree_effect_line_matches(line, policy.initial_role_id))
            .count();
        let captured_path_tree_effect_count = physical_effect_capture
            .recent_since(marker)
            .iter()
            .map(physical_effect_line)
            .filter(|line| physical_path_tree_effect_line_matches(line, policy.initial_role_id))
            .count();
        ensure!(
            recent_path_tree_effect_count == 0 && captured_path_tree_effect_count >= 5,
            InvalidInputSnafu {
                path: &kubernetes_subpath_result,
                reason: format!(
                    "the direct runc pre-effect capture did not preserve five physical path-tree denials after recent-window eviction: recent={recent_path_tree_effect_count}, captured={captured_path_tree_effect_count}"
                ),
            }
        );
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
        ensure!(
            restarted_policy_owner
                .reconcile_policy_lifecycle(&mut host)
                .context(NodeSnafu)?,
            InvalidInputSnafu {
                path: pin_root,
                reason: "node-owner restart did not reconcile policy lifecycle state",
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
        let mut other_role_path_tree_allowed = false;
        let mut prestop_retained_during_runtime_inventory_omission = false;
        let application_control_host = role_directory.join("application.denied");
        for (name, declaration_name, executable) in [
            ("poststart", "poststart", "/bin/cp"),
            ("poststart-repeat", "poststart", "/bin/cp"),
            ("prestop", "prestop", "/bin/dd"),
            ("startup", "startup", "/bin/cat"),
            ("readiness", "readiness", "/bin/grep"),
            ("liveness", "liveness", "/bin/wc"),
        ] {
            if name == "prestop" {
                let runtime_inventory_absence_proves_retirement = restarted_bindings
                    .runtime_inventory_absence_proves_retirement_for_test(
                        &replacement_binding.binding_id,
                    )
                    .context(NodeSnafu)?;
                if runtime_inventory_absence_proves_retirement {
                    restarted_bindings
                        .retire_binding_id_for_test(&host, &replacement_binding.binding_id)
                        .context(NodeSnafu)?;
                } else {
                    prestop_retained_during_runtime_inventory_omission = true;
                }
            }
            let entry_marker = observations.cursor();
            let entry_mount_sequence = observations.mount_change_sequence();
            let pid_path = fixture_root.join(format!("{name}.pid"));
            let entry_stdout = output_directory.join(format!("runc-entry-{name}.stdout"));
            let entry_stderr = output_directory.join(format!("runc-entry-{name}.stderr"));
            let control_output_name = format!("{name}-control-output");
            let control_output_host = role_directory.join(&control_output_name);
            if executable == "/bin/cp" {
                fs::create_dir(&control_output_host).context(IoSnafu {
                    path: &control_output_host,
                })?;
            }
            let control_output = format!("/run/mithril-entry-roles/{control_output_name}");
            let application_control = "/run/mithril-entry-roles/application.denied";
            let control_arguments = match executable {
                "/bin/cp" => vec![application_control.to_owned(), control_output.clone()],
                "/bin/dd" => vec![
                    format!("if={application_control}"),
                    format!("of={control_output}"),
                ],
                "/bin/cat" => vec![
                    "/home/alice/secrets/secret".to_owned(),
                    application_control.to_owned(),
                ],
                "/bin/grep" => vec!["application".to_owned(), application_control.to_owned()],
                "/bin/wc" => vec![application_control.to_owned()],
                _ => unreachable!("the entry fixture has one of five BusyBox applets"),
            };
            let control_argument_refs = control_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let mut child = container.spawn_exec(
                executable,
                &control_argument_refs,
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
                            "entry `{name}` exited before publishing its host PID: stderr={}, mount_sequence={entry_mount_sequence}->{}, effects={:?}",
                            fs::read_to_string(&entry_stderr).unwrap_or_default().trim(),
                            observations.mount_change_sequence(),
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
            )
            .map_err(|error| {
                InvalidInputSnafu {
                    path: &entry_stderr,
                    reason: format!(
                        "entry `{name}` mount sequence changed from {entry_mount_sequence} to {} while admission failed: {error}",
                        observations.mount_change_sequence(),
                    ),
                }
                .build()
            })?;
            fs::write(&application_control_host, b"application\n").context(IoSnafu {
                path: &application_control_host,
            })?;
            let status = wait_for_child(&mut child)?;
            if name == "startup" {
                other_role_path_tree_allowed = status.success();
            }
            let deny_pid_path = fixture_root.join(format!("{name}-deny.pid"));
            let deny_stdout = output_directory.join(format!("runc-entry-{name}-deny.stdout"));
            let deny_stderr = output_directory.join(format!("runc-entry-{name}-deny.stderr"));
            let denied_path = format!("/run/mithril-entry-roles/{declaration_name}.denied");
            let deny_output = format!("/run/mithril-entry-roles/{name}-deny-output");
            let deny_arguments = match executable {
                "/bin/cp" => vec![denied_path.clone(), deny_output.clone()],
                "/bin/dd" => vec![format!("if={denied_path}"), format!("of={deny_output}")],
                "/bin/cat" => vec![denied_path.clone()],
                "/bin/grep" => vec!["denied".to_owned(), denied_path.clone()],
                "/bin/wc" => vec![denied_path.clone()],
                _ => unreachable!("the entry fixture has one of five BusyBox applets"),
            };
            let deny_argument_refs = deny_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let mut denied_child = container.spawn_exec(
                executable,
                &deny_argument_refs,
                &deny_pid_path,
                &deny_stdout,
                &deny_stderr,
            )?;
            let denied_status = wait_for_child(&mut denied_child)?;
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
                    && !denied_status.success()
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
        ensure!(
            other_role_path_tree_allowed,
            InvalidInputSnafu {
                path: &role_directory,
                reason: "the application path-tree denial affected the startup role",
            }
        );
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
        fs::write(role_directory.join("release"), b"release\n").context(IoSnafu {
            path: &role_directory,
        })?;

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
        let initial_proc = PathBuf::from(format!("/proc/{initial_pid}"));
        wait_for_path(
            &initial_proc,
            false,
            "the direct runc initial process to exit",
        )?;
        let retained_mount_views_survived_source_exit = restarted_policy_owner
            .retained_mount_views_are_readable_for_test()
            .context(NodeSnafu)?;
        ensure!(
            retained_mount_views_survived_source_exit,
            InvalidInputSnafu {
                path: &initial_proc,
                reason: "a retained mount view depended on its exited source process",
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
            schema_version: 22,
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
            kubernetes_subpath_alias_path_tree_denied: true,
            newer_kubernetes_subpath_alias_path_tree_denied: true,
            container_bind_mount_succeeded: true,
            container_bind_alias_path_tree_denied: true,
            single_wildcard_path_tree_denied: true,
            recursive_wildcard_path_tree_denied: true,
            other_role_path_tree_allowed,
            path_tree_control_allowed: true,
            application_admitted_entry_rule_id: active.admitted_entry_rule_id,
            independent_entries,
            independent_entry_roles_are_distinct,
            reusable_entry_reinvocation_isolated,
            runtime_entry_infrastructure_observed,
            live_replacement_preserved_running_application,
            live_replacement_entries_use_new_generation,
            node_owner_restart_preserved_running_application,
            prestop_retained_during_runtime_inventory_omission,
            retained_mount_views_survived_source_exit,
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
        let document = lower_kubernetes_policy(
            &resource,
            "10000000-0000-4000-8000-000000000001",
            "10000000-0000-4000-8000-000000000002",
            "10000000-0000-4000-8000-000000000003",
        )
        .context(PolicySnafu)?;
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

fn prepare_entry_role_root(
    rootfs: &Path,
    workload_path: &Path,
    role_directory: &Path,
) -> Result<Vec<String>> {
    let executable = rootfs.join("bin/busybox");
    fs::copy(workload_path, &executable).context(IoSnafu {
        path: workload_path,
    })?;
    let mut dependencies = BTreeSet::new();
    for executable in [workload_path, Path::new("/bin/true")] {
        let output = Command::new("ldd")
            .arg(executable)
            .output()
            .context(IoSnafu {
                path: Path::new("ldd"),
            })?;
        if output.status.success() {
            dependencies.extend(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter_map(ldd_dependency_path),
            );
        } else {
            ensure!(
                String::from_utf8_lossy(&output.stderr).contains("not a dynamic executable"),
                CommandSnafu {
                    program: "ldd".to_owned(),
                    reason: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                }
            );
        }
    }
    for entry in ["sh", "mount", "sleep", "cp", "dd", "cat", "grep", "wc"] {
        let destination = rootfs.join("bin").join(entry);
        std::os::unix::fs::symlink("busybox", &destination)
            .context(IoSnafu { path: &destination })?;
    }
    IdentityTestRunner::materialize_post_ponr_execfail(&rootfs.join("bin/post-ponr-execfail"))?;
    fs::create_dir_all(rootfs.join("run/mithril-entry-roles")).context(IoSnafu { path: rootfs })?;
    fs::create_dir(role_directory).context(IoSnafu {
        path: role_directory,
    })?;
    fs::create_dir(role_directory.join("poststart-overlap-output")).context(IoSnafu {
        path: role_directory,
    })?;
    fs::create_dir(role_directory.join("poststart-during-mount-reconciliation-output")).context(
        IoSnafu {
            path: role_directory,
        },
    )?;
    for name in ["poststart-overlap.fifo", "startup-overlap.fifo"] {
        let path = role_directory.join(name);
        run_checked(
            Command::new("/usr/bin/mkfifo").arg(&path),
            Path::new("/usr/bin/mkfifo"),
        )?;
    }
    let application_denied = role_directory.join("application.denied");
    run_checked(
        Command::new("/usr/bin/mkfifo").arg(&application_denied),
        Path::new("/usr/bin/mkfifo"),
    )?;
    for role in ["poststart", "prestop", "startup", "readiness", "liveness"] {
        let path = role_directory.join(format!("{role}.denied"));
        fs::write(&path, format!("{role}\n")).context(IoSnafu { path: &path })?;
    }
    fs::write(role_directory.join("control.allowed"), b"allowed\n").context(IoSnafu {
        path: role_directory.join("control.allowed"),
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

fn physical_effect_line(event: &MithrilEffectObservation) -> String {
    format!(
        "active_role_id={} family={} operation={} reason={} exact_object_key_id={} kernel_result={}",
        event.active_role_id,
        event.effect_family,
        event.operation,
        event.reason,
        event.exact_object_key_id,
        event.kernel_result,
    )
}

fn physical_path_tree_effect_line_matches(line: &str, active_role_id: u32) -> bool {
    let mut observed_role = None;
    let mut family = None;
    let mut operation = None;
    let mut reason = None;
    let mut exact_object_key_id = None;
    let mut kernel_result = None;
    for field in line.split_whitespace() {
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        match name {
            "active_role_id" => observed_role = value.parse::<u32>().ok(),
            "family" => family = value.parse::<u32>().ok(),
            "operation" => operation = value.parse::<u32>().ok(),
            "reason" => reason = Some(value),
            "exact_object_key_id" => exact_object_key_id = value.parse::<u64>().ok(),
            "kernel_result" => kernel_result = value.parse::<i32>().ok(),
            _ => {}
        }
    }
    observed_role == Some(active_role_id)
        && family == Some(u32::from(KernelEffectFamilyV1::File as u16))
        && operation == Some(u32::from(KernelEffectOperationV1::OpenRead as u16))
        && reason == Some("PATH_TREE_POLICY_DENY")
        && exact_object_key_id == Some(0)
        && kernel_result == Some(-13)
}

fn canonical_mount_route_summary(host: &KernelHost) -> Result<String> {
    let mut rows = Vec::new();
    for key_bytes in host
        .map_keys("canonical_mount_roots")
        .context(InterceptorSnafu)?
    {
        let key = CanonicalMountRootKeyV1::try_read_from_bytes(&key_bytes).map_err(|error| {
            InvalidInputSnafu {
                path: Path::new("canonical_mount_roots"),
                reason: format!("a route key has invalid ABI: {error}"),
            }
            .build()
        })?;
        let value_bytes = host
            .lookup_map("canonical_mount_roots", &key_bytes)
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: Path::new("canonical_mount_roots"),
                    reason: "a listed route has no value".to_owned(),
                }
                .build()
            })?;
        let value = CanonicalMountRootV1::try_read_from_bytes(&value_bytes).map_err(|error| {
            InvalidInputSnafu {
                path: Path::new("canonical_mount_roots"),
                reason: format!("a route value has invalid ABI: {error}"),
            }
            .build()
        })?;
        let count = usize::try_from(value.graph_prefix_state_count)
            .unwrap_or(usize::MAX)
            .min(value.graph_prefix_state_ids.len());
        rows.push(format!(
            "generation={} namespace={} binding={:?} device={} inode={} selected_mount={} states={:?}",
            key.topology_generation,
            key.mount_namespace_inode,
            key.binding_id,
            key.filesystem_device,
            key.root_inode,
            value.selected_mount_id_unique,
            &value.graph_prefix_state_ids[..count],
        ));
    }
    rows.sort();
    Ok(format!("{}\n", rows.join("\n")))
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
