use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use super::overlay_multivolume_support::LifecycleFixture;

pub(super) fn run(
    binary: &Path,
    cwd: &Path,
    args: &[impl AsRef<std::ffi::OsStr>],
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(binary).current_dir(cwd).args(args).output()?;
    if !output.status.success() {
        return Err(command_error("erebor command", output).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

pub(super) fn run_failure(
    binary: &Path,
    cwd: &Path,
    args: &[impl AsRef<std::ffi::OsStr>],
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(binary).current_dir(cwd).args(args).output()?;
    if output.status.success() {
        return Err(std::io::Error::other(format!(
            "erebor command unexpectedly succeeded: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

pub(super) fn erebor_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(binary) = std::env::var_os("CARGO_BIN_EXE_erebor") {
        return Ok(PathBuf::from(binary));
    }
    let workspace = workspace_root();
    let candidate = workspace
        .join("target/debug")
        .join(format!("erebor{}", std::env::consts::EXE_SUFFIX));
    let output = Command::new("cargo")
        .args(["build", "-p", "erebor-runtime-cli", "--bin", "erebor"])
        .current_dir(&workspace)
        .output()?;
    if !output.status.success() {
        return Err(command_error("cargo build erebor", output).into());
    }
    Ok(candidate)
}

pub(super) fn transaction_args<const N: usize>(
    registry: &Path,
    session_id: &str,
    tail: [&str; N],
) -> Vec<String> {
    let mut args = vec![
        String::from("filesystem"),
        String::from("transactions"),
        String::from(tail[0]),
        String::from("--registry"),
        registry.display().to_string(),
        String::from("--session"),
        session_id.to_owned(),
    ];
    args.extend(tail.into_iter().skip(1).map(ToOwned::to_owned));
    args
}

pub(super) fn retention_args<const N: usize>(
    registry: &Path,
    session_id: &str,
    tail: [&str; N],
) -> Vec<String> {
    let mut args = vec![
        String::from("filesystem"),
        String::from("retention"),
        String::from(tail[0]),
        String::from("--registry"),
        registry.display().to_string(),
        String::from("--session"),
        session_id.to_owned(),
    ];
    args.extend(tail.into_iter().skip(1).map(ToOwned::to_owned));
    args
}

pub(super) fn config_source(
    fixture: &LifecycleFixture,
    policy_path: &Path,
    diagnostic_name: &str,
    shell_command: &str,
) -> String {
    format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [{{ "name": "{}", "command": ["sh", "-lc", "{}"] }}],
            "runner": {{ "kind": "linux_host" }},
            "interception": {{
              "enabled": true,
              "backend": "linux_ptrace",
              "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
            }}
          }},
          "surfaces": {{
            "terminal": {{ "enabled": true }},
            "filesystem": {{
              "enabled": true,
              "backend": {{ "kind": "linux_ostree_overlay" }},
              "volumes": [
                {{ "id": "project", "host_path": "{}", "session_path": "{}", "mode": "writable" }},
                {{ "id": "cache", "host_path": "{}", "session_path": "{}", "mode": "writable" }}
              ],
              "revert": {{
                "promote_on_session_finish": true,
                "retain_layers": true,
                "preimage_size_limit_bytes": 104857600
              }}
            }}
          }}
        }}"#,
        policy_path.display(),
        fixture.workspace.display(),
        diagnostic_name,
        json_escape(shell_command),
        fixture.host_project.display(),
        fixture.session_project.display(),
        fixture.host_cache.display(),
        fixture.session_cache.display(),
    )
}

fn command_error(operation: &str, output: Output) -> std::io::Error {
    std::io::Error::other(format!(
        "{operation} failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
