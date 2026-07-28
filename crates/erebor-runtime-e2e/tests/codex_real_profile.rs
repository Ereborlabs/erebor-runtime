use std::{error::Error, fs, process::Command};

use serde_json::Value;
use tempfile::tempdir;

#[test]
fn real_codex_profile_uses_exact_managed_targets_and_intrinsic_guardrail(
) -> Result<(), Box<dyn Error>> {
    let temporary = tempdir()?;
    let configuration = temporary.path().join("etc/erebord.json");
    let trust_root = temporary.path().join("trusted-codex-profile");
    let output = Command::new(env!("CARGO_BIN_EXE_erebor-codex-real-profile"))
        .arg("--config")
        .arg(&configuration)
        .arg("--trust-root")
        .arg(&trust_root)
        .args(["--socket-group-gid", "1234"])
        .args(["--owner-uid", "1000"])
        .args(["--codex-executable", env!("CARGO_BIN_EXE_codex-v1-fixture")])
        .args([
            "--managed-hook",
            env!("CARGO_BIN_EXE_codex-linux-v1-test-hook"),
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "profile configurator failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    assert!(String::from_utf8_lossy(&output.stdout).contains("package_name=codex-cli-0-145-0"));

    let configuration: Value = serde_json::from_slice(&fs::read(configuration)?)?;
    let package = &configuration["root_curated_codex_packages"][0];
    assert_eq!(package["package"]["name"], "codex-cli-0-145-0");
    assert_eq!(
        package["definition"]["managed_artifacts"]["requirements_path"],
        "/etc/codex/requirements.toml"
    );
    assert_eq!(
        package["definition"]["managed_artifacts"]["managed_hook_path"],
        "/usr/lib/erebor/codex-hooks/erebor-codex-hook"
    );
    assert_eq!(
        package["definition"]["managed_artifacts"]["shell_startup_path"],
        "/usr/lib/erebor/codex-hooks/shell-startup"
    );
    assert_eq!(package["definition"]["hook_contract"]["shell"], "bash");
    assert!(package["definition"].get("source_view").is_none());
    assert_eq!(
        package["definition"]["hook_contract"]["exec_history"],
        serde_json::json!([
            { "kind": "installed_executable" },
            { "kind": "absolute_path", "path": "/usr/bin/bash" },
            { "kind": "managed_hook" }
        ])
    );
    assert_eq!(
        package["definition"]["hook_contract"]["events"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
    assert!(package["definition"]["hook_contract"]
        .get("event_schemas")
        .is_none());

    let policy =
        fs::read_to_string(trust_root.join("codex-runtime-guardrail/rules/filesystem.json"))?;
    assert!(policy.contains("deny-governed-marker-write"));
    assert!(policy.contains("deny-governed-marker-mutation"));
    assert!(policy.contains("allow-filesystem-open"));
    assert!(policy.contains("allow-filesystem-read"));
    assert!(policy.contains("allow-filesystem-write"));
    assert!(policy.contains("allow-filesystem-mutation"));
    assert!(!policy.contains("browser_cdp"));

    let terminal =
        fs::read_to_string(trust_root.join("codex-runtime-guardrail/rules/terminal.json"))?;
    assert!(terminal.contains("allow-codex-terminal-processes"));
    assert!(!terminal.contains("mediate"));

    let requirements = fs::read_to_string(trust_root.join("requirements.toml"))?;
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "Stop",
    ] {
        assert!(requirements.contains(&format!("[[hooks.{event}]]")));
    }
    Ok(())
}
