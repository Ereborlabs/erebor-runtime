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
        let config_path = write_config(&test_dir, &policy_path)?;

        let diagnostic = run_cli_expect_failure_in(
            &erebor_runtime,
            &test_dir,
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

        let registry_record = single_registry_record(&test_dir)?;
        let session_id = json_string(&registry_record, "/session_id")?.to_owned();
        let audit_path = PathBuf::from(json_string(&registry_record, "/audit_path")?);
        let policy_artifact_path =
            PathBuf::from(json_string(&registry_record, "/policy_artifact_paths/0")?);
        let config_artifact_path =
            PathBuf::from(json_string(&registry_record, "/config_artifact_path")?);
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
                policy_artifact_path.to_string_lossy().as_ref(),
                "--config",
                config_artifact_path.to_string_lossy().as_ref(),
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
                policy_artifact_path.to_string_lossy().as_ref(),
                "--config",
                config_artifact_path.to_string_lossy().as_ref(),
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
                policy_artifact_path.to_string_lossy().as_ref(),
                "--config",
                config_artifact_path.to_string_lossy().as_ref(),
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

    #[test]
    fn session_run_creates_registry_and_review_commands_read_it() -> Result<(), E2eError> {
        let erebor_runtime = build_erebor_runtime_binary()?;
        let test_dir = test_dir("session-registry")?;
        let policy_path = write_policy(&test_dir)?;
        let config_path = write_registry_config(&test_dir, &policy_path)?;

        let run = run_cli_expect_failure_in(
            &erebor_runtime,
            &test_dir,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config_path.to_string_lossy().as_ref(),
                "sh",
                "--remote-debugging-port=9222",
            ],
        )?;
        assert!(
            run.contains("session runner `linux-host` exited unsuccessfully"),
            "expected governed run denial, got {run}"
        );

        let registry_record = single_registry_record(&test_dir)?;
        let session_id = json_string(&registry_record, "/session_id")?;
        let registry_path = test_dir.join(".erebor/sessions");
        assert!(registry_path.join(session_id).join("session.json").exists());
        assert_eq!(json_string(&registry_record, "/status")?, "failed");
        assert!(registry_record
            .pointer("/ended_at_unix_ms")
            .and_then(Value::as_u64)
            .is_some());
        assert!(Path::new(json_string(&registry_record, "/audit_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/config_artifact_path")?).exists());
        assert!(Path::new(json_string(&registry_record, "/policy_artifact_paths/0")?).exists());

        let list = run_cli_in(&erebor_runtime, &test_dir, ["session", "ls"])?;
        let show = run_cli_in(&erebor_runtime, &test_dir, ["session", "show", session_id])?;
        let describe_json = run_cli_in(
            &erebor_runtime,
            &test_dir,
            ["session", "describe", session_id, "--format", "json"],
        )?;
        let review: Value = serde_json::from_str(&describe_json).map_err(E2eError::json)?;

        assert!(list.contains(session_id));
        assert!(list.contains("failed"));
        assert!(list.contains("terminal"));
        assert!(show.contains("test-agent"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
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

    fn run_cli_in<'a>(
        binary: &Path,
        cwd: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        let output = Command::new(binary)
            .current_dir(cwd)
            .args(args)
            .output()
            .map_err(E2eError::io)?;
        if !output.status.success() {
            return Err(command_error("erebor-runtime command", output));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_cli_expect_failure_in<'a>(
        binary: &Path,
        cwd: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        let output = Command::new(binary)
            .current_dir(cwd)
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

    fn write_config(test_dir: &Path, policy_path: &Path) -> Result<PathBuf, E2eError> {
        let config_path = test_dir.join("session-config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "policies": ["{}"],
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
            ),
        )
        .map_err(E2eError::io)?;
        Ok(config_path)
    }

    fn write_registry_config(test_dir: &Path, policy_path: &Path) -> Result<PathBuf, E2eError> {
        let config_path = test_dir.join("session-config.json");
        fs::write(
            &config_path,
            format!(
                r#"{{
                  "policies": ["{}"],
                  "session": {{
                    "enabled": true,
                    "actor": {{ "id": "test-agent", "kind": "agent" }},
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

    fn single_registry_record(test_dir: &Path) -> Result<Value, E2eError> {
        let registry = test_dir.join(".erebor/sessions");
        let mut records = Vec::new();
        for entry in fs::read_dir(&registry).map_err(E2eError::io)? {
            let path = entry.map_err(E2eError::io)?.path().join("session.json");
            if path.exists() {
                let source = fs::read_to_string(&path).map_err(E2eError::io)?;
                records.push(serde_json::from_str::<Value>(&source).map_err(E2eError::json)?);
            }
        }
        if records.len() == 1 {
            Ok(records.remove(0))
        } else {
            Err(E2eError::external(
                "read registry record",
                std::io::Error::other(format!(
                    "expected exactly one registry record under {}, got {}",
                    registry.display(),
                    records.len()
                )),
            ))
        }
    }

    fn json_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, E2eError> {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                E2eError::external(
                    "read JSON string",
                    std::io::Error::other(format!("missing string field at {pointer}")),
                )
            })
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
