use std::fs;
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
    let stderr = String::from_utf8(output.stderr)?;
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
fn oci_hook_failure_uses_the_shared_format_without_stdout() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_mithril-oci-hook"))
        .args(["--stage", "prepare-container", "--timeout-ms", "1"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
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
