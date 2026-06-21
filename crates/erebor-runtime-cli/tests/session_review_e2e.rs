#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{self, Command},
        time::{SystemTime, UNIX_EPOCH},
    };

    use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_e2e::E2eError;
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{run_session_diagnostic, SessionExecutionError};
    use serde_json::Value;

    #[test]
    fn session_review_commands_render_governed_process_audit() -> Result<(), E2eError> {
        let test_dir = test_dir("session-review")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config_path = test_dir.join("session-config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "policies": ["{}"],
                  "audit": {{ "jsonl": "{}" }},
                  "session": {{
                    "enabled": true,
                    "actor": {{ "id": "test-agent", "kind": "agent" }},
                    "diagnostics": [
                      {{
                        "name": "raw-cdp",
                        "command": ["sh", "--remote-debugging-port=9222"]
                      }}
                    ],
                    "runner": {{ "kind": "linux_host" }}
                  }},
                  "surfaces": {{
                    "terminal": {{
                      "enabled": true,
                      "process_guard": {{ "enabled": true }}
                    }}
                  }}
                }}"#,
                policy_path.display(),
                audit_path.display()
            ),
        )
        .map_err(E2eError::io)?;
        let config =
            RuntimeConfig::from_json_str(&fs::read_to_string(&config_path).map_err(E2eError::io)?)
                .map_err(|error| E2eError::external("parse runtime config", error))?;
        let session_id = "session-review-e2e";
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new(session_id),
            "raw-cdp",
        )
        .map_err(|error| E2eError::external("build session plan", error))?;

        let error = run_session_diagnostic(&config, &plan);
        assert!(
            matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
            "expected governed diagnostic denial, got {error:?}"
        );

        let list = run_cli([
            "session",
            "ls",
            "--audit",
            audit_path.to_string_lossy().as_ref(),
        ])?;
        let show = run_cli([
            "session",
            "show",
            session_id,
            "--audit",
            audit_path.to_string_lossy().as_ref(),
            "--policy",
            policy_path.to_string_lossy().as_ref(),
            "--config",
            config_path.to_string_lossy().as_ref(),
        ])?;
        let describe = run_cli([
            "session",
            "describe",
            session_id,
            "--audit",
            audit_path.to_string_lossy().as_ref(),
            "--policy",
            policy_path.to_string_lossy().as_ref(),
            "--config",
            config_path.to_string_lossy().as_ref(),
        ])?;
        let describe_json = run_cli([
            "session",
            "describe",
            session_id,
            "--audit",
            audit_path.to_string_lossy().as_ref(),
            "--policy",
            policy_path.to_string_lossy().as_ref(),
            "--config",
            config_path.to_string_lossy().as_ref(),
            "--format",
            "json",
        ])?;
        let review: Value = serde_json::from_str(&describe_json).map_err(E2eError::json)?;

        assert!(list.contains(session_id));
        assert!(list.contains("terminal"));
        assert!(show.contains("test-agent"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
        assert!(describe.contains("Denied Event"));
        assert!(describe.contains("process_exec"));
        assert!(describe.contains("linux_ptrace_process_guard"));
        assert!(describe.contains("exec_denied_before_child_gained_authority"));
        assert!(describe.contains("Raw payload sha256:"));
        assert_eq!(
            review
                .pointer("/summary/session_id")
                .and_then(Value::as_str),
            Some(session_id)
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/rule_id")
                .and_then(Value::as_str),
            Some("deny-raw-cdp")
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/controlled_path_backend")
                .and_then(Value::as_str),
            Some("linux_ptrace_process_guard")
        );
        assert_eq!(
            review
                .pointer("/important_decisions/0/final_effect")
                .and_then(Value::as_str),
            Some("exec_denied_before_child_gained_authority")
        );
        let raw_payload_sha256 = review
            .pointer("/important_decisions/0/raw_payload_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(raw_payload_sha256.len(), 64);

        fs::remove_dir_all(test_dir).map_err(E2eError::io)?;
        Ok(())
    }

    fn run_cli<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<String, E2eError> {
        let output = Command::new(env!("CARGO_BIN_EXE_erebor-runtime"))
            .args(args)
            .output()
            .map_err(E2eError::io)?;
        if !output.status.success() {
            return Err(E2eError::external(
                "erebor-runtime command",
                std::io::Error::other(format!(
                    "status={} stdout={} stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn write_policy(test_dir: &Path) -> Result<PathBuf, E2eError> {
        let policy_path = test_dir.join("policy.json");
        fs::write(
            &policy_path,
            r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP process launch is denied"
                }
              ]
            }
            "#,
        )
        .map_err(E2eError::io)?;
        Ok(policy_path)
    }

    fn test_dir(name: &str) -> Result<PathBuf, E2eError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| E2eError::external("system clock", error))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-cli-{name}-{nanos}-{}",
            process::id()
        ));
        fs::create_dir_all(&path).map_err(E2eError::io)?;
        Ok(path)
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn session_review_e2e_is_host_specific() {
    eprintln!("skipping session review e2e on non-x86_64 Linux host");
}
