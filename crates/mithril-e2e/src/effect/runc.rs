use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor::{KernelHostConfig, KernelHostOwner};
use erebor_interceptor_abi::{
    EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use mithril_control::{
    lower_kubernetes_policy, policy_custom_resource, WorkloadProtectionPolicySpec,
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
use zerocopy::TryFromBytes as _;

use super::support::{
    effect_binding_with_identity, effect_node_config, wait_for_application_default_effect,
    wait_for_path_exec_effect, wait_for_reason,
};
use super::{
    sign_generation_artifact, EffectTestRunner, NEXT_PROFILE_GENERATION_REF_ID,
    PROFILE_GENERATION_REF_ID,
};
use crate::error::{
    CommandSnafu, InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, NodeSnafu, PolicySnafu,
};
use crate::physical::{boot_identity, ProbeDirectory, ProbeFile};
use crate::Result;

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
    pub application_admitted_entry_rule_id: u32,
    pub independent_entries: Vec<RuncEntryRoleProbeV1>,
    pub independent_entry_roles_are_distinct: bool,
    pub reusable_entry_reinvocation_isolated: bool,
    pub runtime_entry_infrastructure_observed: bool,
    pub live_replacement_preserved_running_application: bool,
    pub live_replacement_entries_use_new_generation: bool,
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

impl RuncContainer {
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
    #[allow(clippy::too_many_arguments)]
    pub fn runc_entry_role_runtime_probe(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
        runc_path: &Path,
        workload_path: &Path,
        prestart_hook: &Path,
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
        for path in [runc_path, workload_path, prestart_hook] {
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
            "true 2>/dev/null </run/mithril-entry-roles/application.denied || true; while [ ! -e /run/mithril-entry-roles/release ]; do /bin/sleep 1; done"
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
            staged_entry_rules.len() == 6
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
        let reconciliation = identity.reconcile(&mut host, true).context(NodeSnafu)?;
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
        ensure!(
            entry_admission_proofs.len() == 6
                && exact_entry_rule_ids.len() == 6
                && entry_admission_proofs.iter().all(|rule| {
                    rule.exact_object_key_id > 0
                        && rule.executable_object.profile_generation_ref_id
                            == PROFILE_GENERATION_REF_ID
                        && rule.executable_object.mount_id_unique > 0
                        && rule.executable_object.inode > 0
                        && rule.executable_object.inode_generation > 0
                })
                && entry_admission_proofs[1..].iter().all(|rule| {
                    rule.executable_object == entry_admission_proofs[0].executable_object
                }),
            InvalidInputSnafu {
                path: pin_root,
                reason: format!(
                    "entry admission did not retain six calls over one proven BusyBox object: {entry_admission_proofs:?}"
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
            vec![replacement_binding],
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
        ensure!(
            replacement_exact_entry_rule_ids.len() == 6,
            InvalidInputSnafu {
                path: pin_root,
                reason: "policy replacement did not install six exact declared entries",
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
            schema_version: 9,
            runc_version: runc_version.lines().next().unwrap_or_default().to_owned(),
            initial_host_pid: initial_pid,
            prepared_state_before_exec,
            prepared_state_after_exec,
            prepared_runtime_effect_observed: true,
            application_entry_allow_observed: true,
            application_default_file_allow_observed: true,
            application_descendant_default_exec_role_preserved,
            application_admitted_entry_rule_id: active.admitted_entry_rule_id,
            independent_entries,
            independent_entry_roles_are_distinct,
            reusable_entry_reinvocation_isolated,
            runtime_entry_infrastructure_observed,
            live_replacement_preserved_running_application,
            live_replacement_entries_use_new_generation,
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
