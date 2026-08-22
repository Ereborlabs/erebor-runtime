use std::collections::BTreeMap;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use mithril_node::{submit_runtime_admission, RuntimeAdmissionRequestV1};
use serde::Deserialize;

const MAXIMUM_OCI_STATE_BYTES: u64 = 1_048_576;

#[derive(Parser)]
#[command(about = "Hold one OCI prestart until Mithril activates its exact binding")]
struct Cli {
    #[arg(long, default_value = "/run/mithril/runtime-admission.sock")]
    socket: PathBuf,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
}

#[derive(Deserialize)]
struct OciStateV1 {
    id: String,
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
    if state.pid == 0 || !(32..=128).contains(&state.id.len()) {
        return Err(invalid_data("OCI state has no valid container identity").into());
    }
    let cgroup_path = process_cgroup_path(state.pid, &cli.cgroup_root)?;
    let response = submit_runtime_admission(
        &cli.socket,
        &RuntimeAdmissionRequestV1 {
            container_id: state.id,
            initial_pid: state.pid,
            cgroup_path,
            annotations: state.annotations,
        },
        Duration::from_millis(cli.timeout_ms),
    )
    .await?;
    if !response.allowed {
        return Err(invalid_data(&format!(
            "Mithril runtime admission denied the container: {}",
            response.reason_code
        ))
        .into());
    }
    Ok(())
}

fn process_cgroup_path(pid: u32, root: &Path) -> io::Result<PathBuf> {
    let proc_path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let cgroups = std::fs::read_to_string(&proc_path)?;
    let relative = unified_cgroup(&cgroups)
        .ok_or_else(|| invalid_data("OCI initial process has no unified cgroup"))?;
    let relative = relative
        .strip_prefix('/')
        .ok_or_else(|| invalid_data("OCI initial process cgroup is not absolute"))?;
    if Path::new(relative).components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(invalid_data("OCI initial process cgroup is not clean"));
    }
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
    use super::{unified_cgroup, OciStateV1};

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
}
