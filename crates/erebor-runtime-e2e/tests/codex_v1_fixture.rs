use std::{
    io::Write,
    process::{Command, Stdio},
};

use serde_json::Value;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn fixture_builds_a_pinned_package_contract_without_vendor_state() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let config = root.path().join("erebord.json");
    let trust_root = root.path().join("trusted-fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_codex-v1-fixture"))
        .args([
            "configure",
            "--config",
            config.to_str().ok_or("non-UTF-8 test config path")?,
            "--trust-root",
            trust_root.to_str().ok_or("non-UTF-8 test trust root")?,
            "--socket-group-gid",
            "1",
            "--owner-uid",
            "1000",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "fixture configuration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let configuration: Value = serde_json::from_slice(&std::fs::read(config)?)?;
    assert_eq!(configuration["linux_runner"]["containment"], "direct");
    let package = &configuration["root_curated_codex_packages"][0]["package"];
    let definition = &configuration["root_curated_codex_packages"][0]["definition"];
    assert_eq!(package["name"], "codex-v1-fixture");
    assert_eq!(package["adapter_id"], "codex-v1");
    assert_eq!(definition["release_id"], "codex-v1-fixture");
    assert_eq!(definition["entrypoints"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        definition["hook_contract"]["event_schemas"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
    assert_eq!(
        definition["child_delegation"]["bridge_path"],
        "/run/erebor/codex/erebor-child-delegation"
    );
    assert_eq!(
        definition["child_delegation"]["child_profile"]["entrypoint"],
        "codex"
    );
    assert_eq!(
        definition["child_delegation"]["child_profile"]["frozen_context_modes"],
        serde_json::json!(["all"])
    );
    assert!(trust_root.join("codex-v1-fixture").is_file());
    assert!(
        String::from_utf8(output.stdout)?.contains("package_reference=codex-v1-fixture@sha256:")
    );
    Ok(())
}

#[test]
fn fixture_app_server_is_bounded_jsonl_and_exits_at_eof() -> TestResult<()> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-v1-fixture"))
        .args(["app-server", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or("fixture App Server stdin is missing")?
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")?;
    let output = child.wait_with_output()?;

    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["turnId"], "fixture-turn");
    Ok(())
}
