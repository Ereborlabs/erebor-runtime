use std::collections::BTreeMap;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use mithril_node::{
    RuntimeAdmissionClient, RuntimeAdmissionOperationV1, RuntimeAdmissionRequestV1,
};
use serde::Deserialize;

const MAXIMUM_OCI_STATE_BYTES: u64 = 1_048_576;

#[derive(Parser)]
#[command(about = "Run one ordered OCI runtime-fact or container-preparation step")]
struct Cli {
    #[arg(long, value_enum)]
    stage: HookStageV1,
    #[arg(long, default_value = "/run/mithril/runtime-admission.sock")]
    socket: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HookStageV1 {
    StageRuntimeFacts,
    PrepareContainer,
}

#[derive(Deserialize)]
struct OciStateV1 {
    id: String,
    #[serde(default)]
    pid: u32,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if !cli.socket.is_absolute()
        || cli.cgroup_root != Path::new("/sys/fs/cgroup")
        || !(100..=30_000).contains(&cli.timeout_ms)
    {
        return Err(invalid_data("OCI hook arguments are not safe and bounded").into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAXIMUM_OCI_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_OCI_STATE_BYTES as usize {
        return Err(invalid_data("OCI state exceeds its byte limit").into());
    }
    let state: OciStateV1 = serde_json::from_slice(&bytes)?;
    if !(32..=128).contains(&state.id.len()) {
        return Err(invalid_data("OCI state has no valid container identity").into());
    }
    let request = request_for_stage(cli.stage, state, &cli.cgroup_root)?;
    let client = RuntimeAdmissionClient::new(cli.socket, Duration::from_millis(cli.timeout_ms))?;
    let response = client.submit(&request).await?;
    if !response.allowed {
        return Err(invalid_data(&format!(
            "Mithril runtime admission denied the container: {}",
            response.reason_code
        ))
        .into());
    }
    Ok(())
}

fn request_for_stage(
    stage: HookStageV1,
    state: OciStateV1,
    cgroup_root: &Path,
) -> io::Result<RuntimeAdmissionRequestV1> {
    if state.pid == 0 {
        return Err(invalid_data("OCI hook has no initial process"));
    }
    let cgroup_path = process_cgroup_path(state.pid, cgroup_root)?;
    request_with_cgroup(stage, state, cgroup_path)
}

fn request_with_cgroup(
    stage: HookStageV1,
    state: OciStateV1,
    cgroup_path: PathBuf,
) -> io::Result<RuntimeAdmissionRequestV1> {
    let (operation, initial_pid, cgroup_path) = match stage {
        HookStageV1::StageRuntimeFacts => (
            RuntimeAdmissionOperationV1::StageRuntimeFacts,
            None,
            Some(cgroup_path),
        ),
        HookStageV1::PrepareContainer => {
            if state.pid == 0 {
                return Err(invalid_data("OCI runtime admission has no initial process"));
            }
            // The second ordered hook keeps the task held until exact map readback succeeds.
            (
                RuntimeAdmissionOperationV1::PrepareContainer,
                Some(state.pid),
                Some(cgroup_path),
            )
        }
    };
    Ok(RuntimeAdmissionRequestV1 {
        operation,
        container_id: state.id,
        initial_pid,
        cgroup_path,
        annotations: state.annotations,
    })
}

fn process_cgroup_path(pid: u32, root: &Path) -> io::Result<PathBuf> {
    let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let cgroups = std::fs::read_to_string(&proc_path)?;
    let relative = unified_cgroup(&cgroups)
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
    // Canonicalize against the fixed cgroup2 root before sending the path to the node.
    std::fs::canonicalize(root.join(relative))
}

fn unified_cgroup(cgroups: &str) -> Option<&str> {
    cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| !path.is_empty())
}

fn invalid_data(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mithril_node::RuntimeAdmissionOperationV1;

    use super::{request_with_cgroup, unified_cgroup, HookStageV1, OciStateV1};

    #[test]
    fn unified_cgroup_parser_rejects_legacy_or_empty_entries() {
        assert_eq!(
            unified_cgroup("5:cpu:/legacy\n0::/kubepods/pod-a/container-a\n"),
            Some("/kubepods/pod-a/container-a")
        );
        assert_eq!(unified_cgroup("5:cpu:/legacy\n"), None);
        assert_eq!(unified_cgroup("0::\n"), None);
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
    fn first_hook_stages_cgroup_without_preparing_the_container(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state: OciStateV1 = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "a".repeat(64),
            "status": "creating",
            "pid": 42,
            "bundle": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/container-a",
            "annotations": {}
        }))?;
        let request = request_with_cgroup(
            HookStageV1::StageRuntimeFacts,
            state,
            Path::new("/sys/fs/cgroup/kubepods/pod-a/container-a").to_path_buf(),
        )?;
        assert_eq!(
            request.operation,
            RuntimeAdmissionOperationV1::StageRuntimeFacts
        );
        assert_eq!(request.initial_pid, None);
        assert!(request.cgroup_path.is_some());
        Ok(())
    }

    #[test]
    fn second_hook_carries_the_exact_held_initial_task() -> Result<(), Box<dyn std::error::Error>> {
        let state: OciStateV1 = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "id": "a".repeat(64),
            "status": "creating",
            "pid": 42,
            "bundle": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/container-a",
            "annotations": {}
        }))?;
        let request = request_with_cgroup(
            HookStageV1::PrepareContainer,
            state,
            Path::new("/sys/fs/cgroup/kubepods/pod-a/container-a").to_path_buf(),
        )?;
        assert_eq!(
            request.operation,
            RuntimeAdmissionOperationV1::PrepareContainer
        );
        assert_eq!(request.initial_pid, Some(42));
        assert!(request.cgroup_path.is_some());
        Ok(())
    }
}
