use std::{
    io::Write,
    process::{Command, Stdio},
};

use erebor_runtime_policy::LocalPolicy;
use serde_json::Value;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn fixture_builds_a_pinned_package_contract_without_vendor_state() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let config = root.path().join("erebord.json");
    let trust_root = root.path().join("trusted-fixture");
    let runtime_file_probe = root.path().join("runtime-file-probe");
    std::fs::write(&runtime_file_probe, b"runtime-static-file-probe")?;
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
            "--runtime-file-probe",
            runtime_file_probe
                .to_str()
                .ok_or("non-UTF-8 Runtime file probe path")?,
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
        definition["hook_contract"]["events"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
    assert!(definition.get("child_delegation").is_none());
    let curated_packages = configuration["root_curated_codex_packages"]
        .as_array()
        .ok_or("root-curated Codex packages are not an array")?;
    assert_eq!(curated_packages.len(), 4);
    for (name, mode, target) in [
        (
            "runtime-file-open-probe",
            "open",
            "/tmp/erebor-runtime-file-open-target",
        ),
        (
            "runtime-file-read-probe",
            "read",
            "/tmp/erebor-runtime-file-read-target",
        ),
        (
            "runtime-file-mutation-probe",
            "mutation",
            "/tmp/erebor-runtime-file-mutation-target",
        ),
    ] {
        let package = curated_packages
            .iter()
            .find(|package| package["package"]["name"] == name)
            .ok_or("Runtime file probe package is absent")?;
        assert_eq!(package["definition"]["release_id"], name);
        assert_eq!(package["definition"]["entrypoints"][0]["name"], "codex");
        assert_eq!(
            package["definition"]["entrypoints"][0]["argv_suffix"],
            serde_json::json!([mode, target])
        );
        assert_eq!(
            package["definition"]["executable_sha256"]
                .as_str()
                .map(str::len),
            Some(64)
        );
    }
    assert!(trust_root.join("codex-v1-fixture").is_file());
    let fixture_policy = trust_root.join("fixture-baseline");
    assert_eq!(
        std::fs::read_to_string(fixture_policy.join("policy.toml"))?,
        "name = \"fixture-baseline\"\n"
    );
    let rules: Value = serde_json::from_slice(&std::fs::read(
        fixture_policy.join("rules").join("terminal.json"),
    )?)?;
    assert_eq!(rules["rules"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        rules["rules"][0]["mediation"]["replacement_surface"],
        "browser_cdp"
    );
    let runtime_policy_root = trust_root.join("runtime-interceptor-policies");
    for (name, denied_rule) in [
        ("runtime-allow-all", None),
        ("runtime-deny-exec", Some("runtime-process-exec")),
        ("runtime-deny-file-open", Some("runtime-file-open")),
        ("runtime-deny-file-read", Some("runtime-file-read")),
        ("runtime-deny-file-mutation", Some("runtime-file-mutation")),
        (
            "runtime-deny-socket-connect",
            Some("runtime-socket-connect"),
        ),
        ("runtime-dynamic-reject", Some("runtime-dynamic-exec")),
    ] {
        let package = runtime_policy_root.join(name);
        assert_eq!(
            std::fs::read_to_string(package.join("policy.toml"))?,
            format!("name = \"{name}\"\n")
        );
        let effect_bytes = std::fs::read(package.join("rules").join("effects.json"))?;
        let effect_source = std::str::from_utf8(&effect_bytes)?;
        LocalPolicy::from_json_str(effect_source)?;
        let effects: Value = serde_json::from_slice(&effect_bytes)?;
        let rules = effects["rules"]
            .as_array()
            .ok_or("runtime fixture rules are not an array")?;
        assert_eq!(
            rules.len(),
            if name == "runtime-dynamic-reject" {
                6
            } else {
                5
            }
        );
        if let Some(rule_id) = denied_rule {
            assert!(rules
                .iter()
                .any(|rule| { rule["id"] == rule_id && rule["decision"] == "deny" }));
        } else {
            assert!(rules.iter().all(|rule| rule["decision"] == "allow"));
        }
    }
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("package_name=codex-v1-fixture"));
    assert!(stdout.contains(&format!("fixture_policy_path={}", fixture_policy.display())));
    assert!(stdout.contains(&format!(
        "runtime_policy_root={}",
        runtime_policy_root.display()
    )));
    assert!(stdout.contains("runtime_file_open_package=runtime-file-open-probe"));
    assert!(stdout.contains("runtime_file_open_target=/tmp/erebor-runtime-file-open-target"));
    assert!(stdout.contains("runtime_file_read_package=runtime-file-read-probe"));
    assert!(stdout.contains("runtime_file_read_target=/tmp/erebor-runtime-file-read-target"));
    assert!(stdout.contains("runtime_file_mutation_package=runtime-file-mutation-probe"));
    assert!(
        stdout.contains("runtime_file_mutation_target=/tmp/erebor-runtime-file-mutation-target")
    );
    Ok(())
}

#[test]
fn fixture_rejects_invalid_delegation_context_requests_before_hook_execution() -> TestResult<()> {
    for request in [
        r#"{"jsonrpc":"2.0","id":1,"method":"fixture/delegate","params":{"frozen_context_mode":"all","last_turns":1}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"fixture/delegate","params":{"frozen_context_mode":"last_turns","last_turns":0}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"fixture/delegate","params":{"frozen_context_mode":"last_turns","last_turns":9}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"fixture/delegate","params":{"frozen_context_mode":"unknown","last_turns":0}}"#,
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-v1-fixture"))
            .args(["app-server", "--stdio"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        writeln!(
            child
                .stdin
                .as_mut()
                .ok_or("fixture App Server stdin is missing")?,
            "{request}"
        )?;
        let output = child.wait_with_output()?;
        assert!(
            !output.status.success(),
            "fixture accepted invalid delegation request: {request}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("fixture/delegate"));
    }
    Ok(())
}

#[test]
fn fixture_rejects_invalid_context_controls_before_hook_execution() -> TestResult<()> {
    for request in [
        r#"{"jsonrpc":"2.0","id":1,"method":"fixture/control","params":{"action":"unknown"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"fixture/control","params":{"action":"follow_up","target_thread_id":"child","target_turn_id":"turn"}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"fixture/control","params":{"action":"interrupt","target_thread_id":"bad scope","target_turn_id":"turn"}}"#,
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-v1-fixture"))
            .args(["app-server", "--stdio"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        writeln!(
            child
                .stdin
                .as_mut()
                .ok_or("fixture App Server stdin is missing")?,
            "{request}"
        )?;
        let output = child.wait_with_output()?;
        assert!(
            !output.status.success(),
            "fixture accepted invalid context control: {request}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("fixture/control"));
    }
    Ok(())
}

#[test]
fn fixture_rejects_cross_session_hook_without_a_target_before_hook_execution() -> TestResult<()> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-v1-fixture"))
        .args(["app-server", "--stdio"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    writeln!(
        child
            .stdin
            .as_mut()
            .ok_or("fixture App Server stdin is missing")?,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"fixture/hook-cross-session\",\"params\":{{}}}}"
    )?;
    let output = child.wait_with_output()?;
    assert!(
        !output.status.success(),
        "fixture accepted cross-session hook without a target"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("fixture/hook-cross-session"));
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
