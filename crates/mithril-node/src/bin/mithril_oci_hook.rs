use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use erebor_telemetry::{error, init_stderr_logging};
use mithril_node::{
    NodeDecommissionOwner, OciBaseSpecOwner, RetainedRuntimeDecisionV1, RetainedRuntimeGate,
    RuntimeAdmissionClient, RuntimeAdmissionOperationV1, RuntimeAdmissionRequestV1,
    RuntimeControlRecoveryMountInputV1, RuntimeIntegrationInstallV1, RuntimeIntegrationOwner,
    RuntimeRecoveryMountInputV1, PROFILE_ID_ANNOTATION,
};
use serde::Deserialize;

const MAXIMUM_OCI_DOCUMENT_BYTES: u64 = 1_048_576;

#[derive(Parser)]
#[command(about = "Own Mithril's retained OCI runtime gate")]
struct Cli {
    #[command(subcommand)]
    command: CommandV1,
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "the one-shot CLI parses one command and does not retain this enum"
)]
enum CommandV1 {
    Run(RunArgsV1),
    BuildBaseSpec(BuildBaseSpecArgsV1),
    Install(InstallArgsV1),
}

#[derive(Args)]
struct RunArgsV1 {
    #[arg(long, value_enum)]
    stage: HookStageV1,
    #[arg(long, default_value = "/run/mithril/runtime-admission.sock")]
    socket: PathBuf,
    #[arg(long)]
    recovery_manifest: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
}

#[derive(Args)]
struct BuildBaseSpecArgsV1 {
    #[arg(long)]
    hook_path: PathBuf,
    #[arg(long)]
    recovery_manifest: PathBuf,
    #[arg(long, default_value = "/run/mithril/runtime-admission.sock")]
    socket: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 11)]
    runtime_timeout_seconds: u64,
    #[arg(long, default_value = "info")]
    log_filter: String,
}

#[derive(Args)]
struct InstallArgsV1 {
    #[arg(long)]
    owner: String,
    #[arg(long, default_value = "/usr/local/bin/mithril-oci-hook")]
    hook_source: PathBuf,
    #[arg(long, default_value = "/host-hook-bin")]
    hook_mount_directory: PathBuf,
    #[arg(long)]
    hook_host_directory: PathBuf,
    #[arg(long, default_value = "/host-containerd")]
    containerd_mount_directory: PathBuf,
    #[arg(long)]
    containerd_host_directory: PathBuf,
    #[arg(long, default_value = "conf.d")]
    containerd_drop_in_directory: String,
    #[arg(long, default_value = "/host-runtime-cli")]
    runtime_cli_mount_path: PathBuf,
    #[arg(long)]
    runtime_cli_host_path: PathBuf,
    #[arg(long)]
    runtime_cli_arg: Vec<String>,
    #[arg(long)]
    runtime_service: Vec<String>,
    #[arg(long)]
    node_read_only_mount: Vec<String>,
    #[arg(long)]
    node_read_write_mount: Vec<String>,
    #[arg(long, default_value_t = 65_532)]
    control_uid: u32,
    #[arg(long, default_value_t = 65_532)]
    control_gid: u32,
    #[arg(long)]
    control_read_only_mount: Vec<PathBuf>,
    #[arg(long)]
    control_read_write_mount: Vec<PathBuf>,
    #[arg(long, default_value = "/run/mithril/runtime-admission.sock")]
    socket: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 11)]
    runtime_timeout_seconds: u64,
    #[arg(long, default_value = "info")]
    log_filter: String,
    #[arg(long)]
    decommission_state_directory: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HookStageV1 {
    StageRuntimeFacts,
    PrepareContainer,
    PrepareDeclaredEntries,
}

#[derive(Deserialize)]
struct OciStateV1 {
    id: String,
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    bundle: PathBuf,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

struct OciHookOwner;

impl OciHookOwner {
    async fn execute(
        command: CommandV1,
        process_args: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            CommandV1::Run(args) => Self::run_hook(args).await,
            CommandV1::BuildBaseSpec(args) => Self::build_base_spec(args),
            CommandV1::Install(args) => Self::install(args, process_args),
        }
    }

    fn install(
        args: InstallArgsV1,
        process_args: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(directory) = &args.decommission_state_directory {
            if !Self::clean_absolute(directory) {
                return Err(invalid_data("decommission state directory is not absolute").into());
            }
            if NodeDecommissionOwner::durable_completion(directory)? {
                erebor_telemetry::info!(
                    "kept a completed node decommission free of runtime integration",
                    decision = %"DECOMMISSION_REINSTALL_SKIPPED"
                );
                return Ok(());
            }
        }
        let mut node_mounts = Vec::new();
        for value in &args.node_read_only_mount {
            node_mounts.push(Self::parse_mount(value, true)?);
        }
        for value in &args.node_read_write_mount {
            node_mounts.push(Self::parse_mount(value, false)?);
        }
        let control_mounts = args
            .control_read_only_mount
            .iter()
            .map(|destination| RuntimeControlRecoveryMountInputV1 {
                destination: destination.clone(),
                read_only: true,
            })
            .chain(args.control_read_write_mount.iter().map(|destination| {
                RuntimeControlRecoveryMountInputV1 {
                    destination: destination.clone(),
                    read_only: false,
                }
            }))
            .collect();
        let owner = RuntimeIntegrationOwner::new(RuntimeIntegrationInstallV1 {
            owner: args.owner,
            hook_source: args.hook_source,
            hook_mount_directory: args.hook_mount_directory,
            hook_host_directory: args.hook_host_directory,
            containerd_mount_directory: args.containerd_mount_directory,
            containerd_host_directory: args.containerd_host_directory,
            containerd_drop_in_directory: args.containerd_drop_in_directory,
            runtime_cli_mount_path: args.runtime_cli_mount_path,
            runtime_cli_host_path: args.runtime_cli_host_path,
            runtime_cli_args: args.runtime_cli_arg,
            runtime_services: args.runtime_service,
            installer_executable: PathBuf::from("/usr/local/bin/mithril-oci-hook"),
            installer_args: process_args,
            node_mounts,
            control_uid: args.control_uid,
            control_gid: args.control_gid,
            control_mounts,
            socket: args.socket,
            timeout_ms: args.timeout_ms,
            runtime_timeout_seconds: args.runtime_timeout_seconds,
            log_filter: args.log_filter,
        })?;
        let result = owner.install()?;
        erebor_telemetry::info!(
            "installed retained containerd runtime integration",
            decision = %"RUNTIME_INTEGRATION_INSTALLED",
            restart_required = %result.restart_required,
            base_spec = %result.base_spec_host_path.display()
        );
        if result.restart_required {
            let service = owner.restart()?;
            erebor_telemetry::info!(
                "restarted the container runtime for retained integration",
                decision = %"RUNTIME_INTEGRATION_RESTARTED",
                service = %service
            );
        }
        owner.read_back()?;
        erebor_telemetry::info!(
            "read back retained containerd runtime integration",
            decision = %"RUNTIME_INTEGRATION_VERIFIED"
        );
        Ok(())
    }

    fn parse_mount(value: &str, read_only: bool) -> io::Result<RuntimeRecoveryMountInputV1> {
        let (source, destination) = value
            .split_once('=')
            .ok_or_else(|| invalid_data("recovery mount must use source=destination"))?;
        if source.is_empty() || destination.is_empty() {
            return Err(invalid_data("recovery mount has an empty path"));
        }
        Ok(RuntimeRecoveryMountInputV1 {
            source: PathBuf::from(source),
            destination: PathBuf::from(destination),
            read_only,
        })
    }

    async fn run_hook(args: RunArgsV1) -> Result<(), Box<dyn std::error::Error>> {
        Self::validate_run_args(&args)?;
        let state: OciStateV1 = serde_json::from_slice(&Self::read_stdin()?)?;
        if !(32..=128).contains(&state.id.len()) || !state.bundle.is_absolute() {
            return Err(invalid_data("OCI state has no valid container identity or bundle").into());
        }

        let client = RuntimeAdmissionClient::new(
            args.socket.clone(),
            Duration::from_millis(args.timeout_ms),
        )?;
        if args.stage == HookStageV1::StageRuntimeFacts {
            let gate = RetainedRuntimeGate::open(&args.recovery_manifest)?;
            match gate.decide(&state.bundle, &state.annotations, false)? {
                RetainedRuntimeDecisionV1::DenyHostile => {
                    erebor_telemetry::info!(
                        "retained runtime gate denied the incident container",
                        decision = %"DENY_HOSTILE",
                        container_id = %state.id
                    );
                    return Err(invalid_data("retained gate denied the hostile OCI shape").into());
                }
                RetainedRuntimeDecisionV1::AdmitProtected => {
                    erebor_telemetry::debug!(
                        "routing protected container to node admission",
                        decision = %"ROUTE_PROTECTED_TO_NODE",
                        container_id = %state.id
                    );
                    return Self::submit(args.stage, state, &args.cgroup_root, &client).await;
                }
                RetainedRuntimeDecisionV1::AllowInstaller => {
                    erebor_telemetry::info!(
                        "retained runtime gate allowed a Mithril installer during node recovery",
                        decision = %"ALLOW_MITHRIL_INSTALLER",
                        container_id = %state.id
                    );
                    return Ok(());
                }
                RetainedRuntimeDecisionV1::AllowRecovery => {
                    erebor_telemetry::info!(
                        "retained runtime gate allowed exact Mithril recovery",
                        decision = %"ALLOW_EXACT_RECOVERY",
                        container_id = %state.id
                    );
                    return Ok(());
                }
                RetainedRuntimeDecisionV1::AllowSandbox => {
                    erebor_telemetry::info!(
                        "retained runtime gate allowed a CRI Pod sandbox during node recovery",
                        decision = %"ALLOW_CRI_SANDBOX",
                        container_id = %state.id
                    );
                    return Ok(());
                }
                RetainedRuntimeDecisionV1::DenyUnavailable => {
                    if client.available().await {
                        erebor_telemetry::debug!(
                            "retained runtime gate allowed an unprotected container",
                            decision = %"ALLOW_HEALTHY_UNPROTECTED",
                            container_id = %state.id
                        );
                        return Ok(());
                    }
                    erebor_telemetry::info!(
                        "retained runtime gate denied a container while node admission was unavailable",
                        decision = %"DENY_NODE_UNAVAILABLE",
                        container_id = %state.id
                    );
                    return Err(invalid_data(
                        "retained gate denied a non-recovery start while node admission was unavailable",
                    )
                    .into());
                }
                RetainedRuntimeDecisionV1::AllowHealthy => {
                    unreachable!(
                        "the preliminary retained-gate decision uses an unavailable endpoint"
                    )
                }
            }
        }

        if state
            .annotations
            .get(PROFILE_ID_ANNOTATION)
            .is_some_and(|profile| !profile.is_empty())
        {
            return Self::submit(args.stage, state, &args.cgroup_root, &client).await;
        }
        Ok(())
    }

    async fn submit(
        stage: HookStageV1,
        state: OciStateV1,
        cgroup_root: &Path,
        client: &RuntimeAdmissionClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let container_id = state.id.clone();
        let request = Self::request_for_stage(stage, state, cgroup_root)?;
        let response = match client.submit(&request).await {
            Ok(response) => response,
            Err(error) => {
                erebor_telemetry::info!(
                    "retained runtime gate could not reach node admission",
                    decision = %"DENY_NODE_UNAVAILABLE",
                    container_id = %container_id
                );
                return Err(error.into());
            }
        };
        if !response.allowed {
            erebor_telemetry::info!(
                "node admission denied the container",
                decision = %"DENY_NODE_ADMISSION",
                container_id = %container_id,
                reason_code = %response.reason_code
            );
            return Err(invalid_data(&format!(
                "Mithril runtime admission denied the container: {}",
                response.reason_code
            ))
            .into());
        }
        Ok(())
    }

    fn build_base_spec(args: BuildBaseSpecArgsV1) -> Result<(), Box<dyn std::error::Error>> {
        Self::validate_base_spec_args(&args)?;
        let spec = OciBaseSpecOwner::build(
            &Self::read_stdin()?,
            &args.hook_path,
            &args.recovery_manifest,
            &args.socket,
            args.timeout_ms,
            args.runtime_timeout_seconds,
            &args.log_filter,
        )?;
        io::stdout().lock().write_all(&spec)?;
        io::stdout().lock().write_all(b"\n")?;
        Ok(())
    }

    fn validate_run_args(args: &RunArgsV1) -> io::Result<()> {
        if !Self::clean_absolute(&args.socket)
            || !Self::clean_absolute(&args.recovery_manifest)
            || args.cgroup_root != Path::new("/sys/fs/cgroup")
            || !(100..=30_000).contains(&args.timeout_ms)
        {
            return Err(invalid_data("OCI hook arguments are not safe and bounded"));
        }
        Ok(())
    }

    fn validate_base_spec_args(args: &BuildBaseSpecArgsV1) -> io::Result<()> {
        if !Self::clean_absolute(&args.hook_path)
            || !Self::clean_absolute(&args.recovery_manifest)
            || !Self::clean_absolute(&args.socket)
            || !(100..=30_000).contains(&args.timeout_ms)
            || args.runtime_timeout_seconds * 1_000 <= args.timeout_ms
            || args.runtime_timeout_seconds > 30
            || args.log_filter.is_empty()
            || args.log_filter.len() > 1_024
            || args.log_filter.contains(['\r', '\n'])
        {
            return Err(invalid_data(
                "OCI base-spec arguments are not safe and bounded",
            ));
        }
        Ok(())
    }

    fn clean_absolute(path: &Path) -> bool {
        path.is_absolute()
            && path.as_os_str().as_encoded_bytes().len() <= 4_096
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
    }

    fn read_stdin() -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        io::stdin()
            .take(MAXIMUM_OCI_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_OCI_DOCUMENT_BYTES as usize {
            return Err(invalid_data("OCI document exceeds its byte limit"));
        }
        Ok(bytes)
    }

    fn request_for_stage(
        stage: HookStageV1,
        state: OciStateV1,
        cgroup_root: &Path,
    ) -> io::Result<RuntimeAdmissionRequestV1> {
        let cgroup_path = match stage {
            HookStageV1::StageRuntimeFacts => {
                if state.pid == 0 {
                    return Err(invalid_data("OCI hook has no initial process"));
                }
                Some(Self::process_cgroup_path(state.pid, cgroup_root)?)
            }
            HookStageV1::PrepareContainer | HookStageV1::PrepareDeclaredEntries => None,
        };
        Self::request_with_cgroup(stage, state, cgroup_path)
    }

    fn request_with_cgroup(
        stage: HookStageV1,
        state: OciStateV1,
        cgroup_path: Option<PathBuf>,
    ) -> io::Result<RuntimeAdmissionRequestV1> {
        let (operation, initial_pid, cgroup_path, oci_bundle) = match stage {
            HookStageV1::StageRuntimeFacts => (
                RuntimeAdmissionOperationV1::StageRuntimeFacts,
                None,
                cgroup_path,
                None,
            ),
            HookStageV1::PrepareContainer => {
                if state.pid == 0 {
                    return Err(invalid_data("OCI runtime admission has no initial process"));
                }
                // The second ordered hook keeps the task held until exact map readback succeeds.
                (
                    RuntimeAdmissionOperationV1::PrepareContainer,
                    Some(state.pid),
                    None,
                    None,
                )
            }
            HookStageV1::PrepareDeclaredEntries => (
                RuntimeAdmissionOperationV1::PrepareDeclaredEntries,
                None,
                None,
                Some(state.bundle),
            ),
        };
        Ok(RuntimeAdmissionRequestV1 {
            operation,
            container_id: state.id,
            initial_pid,
            cgroup_path,
            oci_bundle,
            annotations: state.annotations,
        })
    }

    fn process_cgroup_path(pid: u32, root: &Path) -> io::Result<PathBuf> {
        let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
        let cgroups = std::fs::read_to_string(&proc_path)?;
        let relative = Self::unified_cgroup(&cgroups)
            .ok_or_else(|| invalid_data("OCI initial process has no unified cgroup"))?;
        let relative = relative
            .strip_prefix('/')
            .ok_or_else(|| invalid_data("OCI initial process cgroup is not absolute"))?;
        if relative.is_empty()
            || Path::new(relative).components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid_data("OCI initial process cgroup is not clean"));
        }
        // Canonicalization binds the runtime fact to the fixed cgroup2 hierarchy.
        std::fs::canonicalize(root.join(relative))
    }

    fn unified_cgroup(cgroups: &str) -> Option<&str> {
        cgroups
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .filter(|path| !path.is_empty())
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = init_stderr_logging() {
        eprintln!("Mithril OCI hook logging initialization failed: {error}");
        std::process::exit(1);
    }
    let process_args = std::env::args().collect();
    if let Err(error) = OciHookOwner::execute(Cli::parse().command, process_args).await {
        error!(%error; "Mithril OCI hook stopped with an error");
        std::process::exit(1);
    }
}

fn invalid_data(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mithril_node::RuntimeAdmissionOperationV1;

    use super::{HookStageV1, OciHookOwner, OciStateV1};

    #[test]
    fn unified_cgroup_parser_rejects_legacy_or_empty_entries() {
        assert_eq!(
            OciHookOwner::unified_cgroup("5:cpu:/legacy\n0::/kubepods/pod-a/container-a\n"),
            Some("/kubepods/pod-a/container-a")
        );
        assert_eq!(OciHookOwner::unified_cgroup("5:cpu:/legacy\n"), None);
        assert_eq!(OciHookOwner::unified_cgroup("0::\n"), None);
    }

    #[test]
    fn stock_oci_state_fields_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let state: OciStateV1 = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "a".repeat(64),
            "status": "creating",
            "pid": 42,
            "bundle": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/container-a",
            "annotations": {}
        }))?;
        assert_eq!(state.pid, 42);
        Ok(())
    }

    #[test]
    fn ordered_requests_preserve_stage_ownership() -> Result<(), Box<dyn std::error::Error>> {
        let state = || {
            serde_json::from_value(serde_json::json!({
                "id": "a".repeat(64),
                "pid": 42,
                "bundle": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/container-a",
                "annotations": {}
            }))
        };
        let staged = OciHookOwner::request_with_cgroup(
            HookStageV1::StageRuntimeFacts,
            state()?,
            Some(Path::new("/sys/fs/cgroup/kubepods/pod-a/container-a").to_path_buf()),
        )?;
        assert_eq!(
            staged.operation,
            RuntimeAdmissionOperationV1::StageRuntimeFacts
        );
        assert!(staged.initial_pid.is_none());
        assert!(staged.cgroup_path.is_some());

        let prepared =
            OciHookOwner::request_with_cgroup(HookStageV1::PrepareContainer, state()?, None)?;
        assert_eq!(
            prepared.operation,
            RuntimeAdmissionOperationV1::PrepareContainer
        );
        assert_eq!(prepared.initial_pid, Some(42));

        let entries =
            OciHookOwner::request_with_cgroup(HookStageV1::PrepareDeclaredEntries, state()?, None)?;
        assert_eq!(
            entries.operation,
            RuntimeAdmissionOperationV1::PrepareDeclaredEntries
        );
        assert_eq!(
            entries.oci_bundle.as_deref(),
            Some(Path::new(
                "/run/containerd/io.containerd.runtime.v2.task/k8s.io/container-a"
            ))
        );
        Ok(())
    }
}
