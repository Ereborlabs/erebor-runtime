#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{self, Command, Output},
        time::{SystemTime, UNIX_EPOCH},
    };

    use erebor_runtime_e2e::E2eError;
    use serde_json::Value;

    #[test]
    fn session_review_commands_render_governed_process_audit() -> Result<(), E2eError> {
        let erebor_runtime = build_erebor_runtime_binary()?;
        let test_dir = test_dir("session-review")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config_path = write_config(&test_dir, &policy_path, &audit_path)?;

        let diagnostic = run_cli_expect_failure(
            &erebor_runtime,
            [
                "session",
                "diagnose",
                "--runner",
                "linux-host",
                "--config",
                config_path.to_string_lossy().as_ref(),
                "raw-cdp",
            ],
        )?;
        assert!(
            diagnostic.contains("guarded session diagnostic failed"),
            "expected governed diagnostic denial, got {diagnostic}"
        );

        let session_id = session_id_from_audit(&audit_path)?;
        let list = run_cli(
            &erebor_runtime,
            [
                "session",
                "ls",
                "--audit",
                audit_path.to_string_lossy().as_ref(),
            ],
        )?;
        let show = run_cli(
            &erebor_runtime,
            [
                "session",
                "show",
                session_id.as_str(),
                "--audit",
                audit_path.to_string_lossy().as_ref(),
                "--policy",
                policy_path.to_string_lossy().as_ref(),
                "--config",
                config_path.to_string_lossy().as_ref(),
            ],
        )?;
        let describe = run_cli(
            &erebor_runtime,
            [
                "session",
                "describe",
                session_id.as_str(),
                "--audit",
                audit_path.to_string_lossy().as_ref(),
                "--policy",
                policy_path.to_string_lossy().as_ref(),
                "--config",
                config_path.to_string_lossy().as_ref(),
            ],
        )?;
        let describe_json = run_cli(
            &erebor_runtime,
            [
                "session",
                "describe",
                session_id.as_str(),
                "--audit",
                audit_path.to_string_lossy().as_ref(),
                "--policy",
                policy_path.to_string_lossy().as_ref(),
                "--config",
                config_path.to_string_lossy().as_ref(),
                "--format",
                "json",
            ],
        )?;
        let review: Value = serde_json::from_str(&describe_json).map_err(E2eError::json)?;

        assert!(list.contains(session_id.as_str()));
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
            Some(session_id.as_str())
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

    fn build_erebor_runtime_binary() -> Result<PathBuf, E2eError> {
        if let Some(binary) = std::env::var_os("CARGO_BIN_EXE_erebor-runtime") {
            return Ok(PathBuf::from(binary));
        }

        let workspace_root = workspace_root()?;
        let output = Command::new("cargo")
            .args([
                "build",
                "-p",
                "erebor-runtime-cli",
                "--bin",
                "erebor-runtime",
            ])
            .current_dir(&workspace_root)
            .output()
            .map_err(E2eError::io)?;
        if !output.status.success() {
            return Err(command_error("cargo build erebor-runtime", output));
        }

        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace_root.join("target"));
        let binary = target_dir
            .join("debug")
            .join(format!("erebor-runtime{}", std::env::consts::EXE_SUFFIX));
        if binary.exists() {
            Ok(binary)
        } else {
            Err(E2eError::external(
                "locate erebor-runtime binary",
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("expected binary at {}", binary.display()),
                ),
            ))
        }
    }

    fn run_cli<'a>(
        binary: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        let output = Command::new(binary)
            .args(args)
            .output()
            .map_err(E2eError::io)?;
        if !output.status.success() {
            return Err(command_error("erebor-runtime command", output));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_cli_expect_failure<'a>(
        binary: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        let output = Command::new(binary)
            .args(args)
            .output()
            .map_err(E2eError::io)?;
        if output.status.success() {
            return Err(E2eError::external(
                "erebor-runtime command expected failure",
                std::io::Error::other(format!(
                    "command unexpectedly succeeded: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )),
            ));
        }
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    fn command_error(operation: &str, output: Output) -> E2eError {
        E2eError::external(
            operation,
            std::io::Error::other(format!(
                "status={} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
        )
    }

    fn session_id_from_audit(audit_path: &Path) -> Result<String, E2eError> {
        let source = fs::read_to_string(audit_path).map_err(E2eError::io)?;
        for line in source.lines().filter(|line| !line.trim().is_empty()) {
            let record = serde_json::from_str::<Value>(line).map_err(E2eError::json)?;
            if let Some(session_id) = record.pointer("/event/session_id").and_then(Value::as_str) {
                return Ok(session_id.to_owned());
            }
        }
        Err(E2eError::external(
            "read session id from audit",
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no session id in {}", audit_path.display()),
            ),
        ))
    }

    fn write_config(
        test_dir: &Path,
        policy_path: &Path,
        audit_path: &Path,
    ) -> Result<PathBuf, E2eError> {
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
        Ok(config_path)
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
            "erebor-runtime-e2e-{name}-{nanos}-{}",
            process::id()
        ));
        fs::create_dir_all(&path).map_err(E2eError::io)?;
        Ok(path)
    }

    fn workspace_root() -> Result<PathBuf, E2eError> {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                E2eError::external(
                    "resolve workspace root",
                    std::io::Error::other("e2e crate is not under workspace crates directory"),
                )
            })
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn session_review_e2e_is_host_specific() {
    eprintln!("skipping session review e2e on non-x86_64 Linux host");
}
