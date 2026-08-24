use std::fs;
use std::process::Command;

use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn invalid_store_exits_with_one_formatted_owner_error() -> TestResult {
    let directory = TempDir::new()?;
    let store = directory.path().join("store");
    fs::create_dir_all(store.join("commits"))?;
    fs::write(store.join("commits/00000000000000000001.json"), b"{}")?;
    let config = control_config(&directory, &store)?;

    let output = Command::new(env!("CARGO_BIN_EXE_mithril-control"))
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
            .filter(|line| line.contains("Mithril Control stopped with an error"))
            .count(),
        1
    );
    assert!(stderr.contains(" ERROR mithril_control:"), "{stderr}");
    assert!(stderr.contains("Mithril Control JSON"), "{stderr}");
    Ok(())
}

#[test]
fn invalid_filter_fails_before_control_startup() -> TestResult {
    let directory = TempDir::new()?;
    let store = directory.path().join("store");
    let config = control_config(&directory, &store)?;

    let output = Command::new(env!("CARGO_BIN_EXE_mithril-control"))
        .args([
            "--config",
            config.to_str().ok_or("config path is not UTF-8")?,
        ])
        .env("RUST_LOG", "[")
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains(
            "Mithril Control logging initialization failed: the RUST_LOG filter is invalid"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("starting Mithril Control"), "{stderr}");
    Ok(())
}

fn control_config(directory: &TempDir, store: &std::path::Path) -> TestResultWithPath {
    let config = directory.path().join("control.json");
    let certificate = directory.path().join("control.pem");
    let private_key = directory.path().join("control-key.pem");
    let node_ca = directory.path().join("node-ca.pem");
    let source = serde_json::json!({
        "listen": "127.0.0.1:0",
        "tls": {
            "certificate_path": certificate,
            "private_key_path": private_key,
            "node_ca_path": node_ca
        },
        "allowed_nodes": [{
            "node_id": "node-a",
            "certificate_sha256": "a".repeat(64),
            "tenant_id": "00000000-0000-0001-0000-000000000002"
        }],
        "trust": {
            "generation": 1,
            "bundle_digest": "b".repeat(64),
            "policy_issuer_sequence_epoch": 0,
            "policy_signers": []
        },
        "administrative_exec": null,
        "evidence_directory": store,
        "control_store_directory": store,
        "kubernetes_policy": null,
        "kubernetes_nodes": null,
        "kubernetes_admission": null
    });
    fs::write(&config, serde_json::to_vec(&source)?)?;
    Ok(config)
}

type TestResultWithPath = Result<std::path::PathBuf, Box<dyn std::error::Error>>;
