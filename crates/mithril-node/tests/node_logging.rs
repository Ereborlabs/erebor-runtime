use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn invalid_config_exits_with_one_formatted_owner_error() -> TestResult {
    let directory = TempDir::new()?;
    let config = directory.path().join("node.json");
    fs::write(&config, b"{}")?;

    let output = Command::new(env!("CARGO_BIN_EXE_mithril-node"))
        .args([
            "--config",
            config.to_str().ok_or("config path is not UTF-8")?,
        ])
        .env("RUST_LOG", "info")
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!stderr.contains('\u{1b}'), "{stderr}");
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("Mithril Node stopped with an error"))
            .count(),
        1
    );
    assert!(stderr.contains(" ERROR mithril_node:"), "{stderr}");
    assert!(stderr.contains("Mithril node JSON"), "{stderr}");
    Ok(())
}

#[test]
fn invalid_filter_fails_before_node_startup() -> TestResult {
    let directory = TempDir::new()?;
    let config = directory.path().join("node.json");
    fs::write(&config, b"{}")?;

    let output = Command::new(env!("CARGO_BIN_EXE_mithril-node"))
        .args([
            "--config",
            config.to_str().ok_or("config path is not UTF-8")?,
        ])
        .env("RUST_LOG", "[")
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr
            .contains("Mithril Node logging initialization failed: the RUST_LOG filter is invalid"),
        "{stderr}"
    );
    assert!(!stderr.contains("starting Mithril Node"), "{stderr}");
    Ok(())
}

#[test]
fn oci_hook_uses_the_default_filter_when_rust_log_is_absent() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_mithril-oci-hook"))
        .arg("--help")
        .env_remove("RUST_LOG")
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8(output.stdout)?.contains("Own Mithril's retained OCI runtime gate"));
    Ok(())
}

#[test]
fn oci_hook_failure_uses_the_shared_format_without_stdout() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_mithril-oci-hook"))
        .args([
            "run",
            "--stage",
            "prepare-container",
            "--recovery-manifest",
            "/tmp/mithril-recovery.json",
            "--timeout-ms",
            "1",
        ])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!stderr.contains('\u{1b}'), "{stderr}");
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("Mithril OCI hook stopped with an error"))
            .count(),
        1
    );
    assert!(stderr.contains(" ERROR mithril_oci_hook:"), "{stderr}");
    assert!(
        stderr.contains("OCI hook arguments are not safe and bounded"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn retained_hostile_denial_logs_its_decision_code() -> TestResult {
    let directory = TempDir::new()?;
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(&bundle)?;
    fs::write(
        bundle.join("config.json"),
        serde_json::to_vec(&serde_json::json!({
            "process": {
                "args": ["/bin/sh", "-c", "cat /host/etc/shadow"],
                "capabilities": {"effective": ["CAP_SYS_ADMIN"]}
            },
            "root": {"path": "rootfs"},
            "mounts": [{"destination": "/host", "source": "/", "type": "bind", "options": ["rbind", "rw"]}],
            "linux": {"namespaces": [{"type": "mount"}, {"type": "network"}]}
        }))?,
    )?;
    let manifest = directory.path().join("recovery.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": [{
                "executable": "/usr/local/bin/mithril-node",
                "args": ["/usr/local/bin/mithril-node"],
                "requiredMounts": [{"source": "/state", "destination": "/state", "readOnly": false}]
            }]
        }))?,
    )?;
    let state = serde_json::to_vec(&serde_json::json!({
        "id": "a".repeat(64),
        "pid": 1,
        "bundle": bundle,
        "annotations": {}
    }))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_mithril-oci-hook"))
        .args([
            "run",
            "--stage",
            "stage-runtime-facts",
            "--recovery-manifest",
            manifest.to_str().ok_or("manifest path is not UTF-8")?,
            "--timeout-ms",
            "100",
        ])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("hook stdin is unavailable")?
        .write_all(&state)?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("decision=DENY_HOSTILE"), "{stderr}");
    assert!(stderr.contains(&"a".repeat(64)), "{stderr}");
    Ok(())
}

#[test]
fn unavailable_node_admission_logs_its_decision_code() -> TestResult {
    let directory = TempDir::new()?;
    let bundle = directory.path().join("bundle");
    fs::create_dir_all(&bundle)?;
    let manifest = directory.path().join("recovery.json");
    fs::write(&manifest, b"not-read-after-the-first-hook")?;
    let state = serde_json::to_vec(&serde_json::json!({
        "id": "b".repeat(64),
        "pid": 1,
        "bundle": bundle,
        "annotations": {"mithril.erebor.dev/profile-id": "profile"}
    }))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_mithril-oci-hook"))
        .args([
            "run",
            "--stage",
            "prepare-declared-entries",
            "--socket",
            directory
                .path()
                .join("absent.sock")
                .to_str()
                .ok_or("socket path is not UTF-8")?,
            "--recovery-manifest",
            manifest.to_str().ok_or("manifest path is not UTF-8")?,
            "--timeout-ms",
            "100",
        ])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("hook stdin is unavailable")?
        .write_all(&state)?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("decision=DENY_NODE_UNAVAILABLE"),
        "{stderr}"
    );
    assert!(stderr.contains(&"b".repeat(64)), "{stderr}");
    Ok(())
}
