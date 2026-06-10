#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{
        fs,
        path::Path,
        process::{self, Command, Stdio},
    };

    use erebor_runtime_core::{RuntimeConfig, SessionAdoptPlan, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{
        adopt_session_plan_capture, run_session_diagnostic, SessionExecutionError,
    };

    #[test]
    fn linux_host_runner_relaunches_diagnostic_through_process_guard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = test_dir("relaunch")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "audit": {{ "jsonl": "{}" }},
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "diagnostics": [
                  {{
                    "name": "metadata",
                    "command": [
                      "sh",
                      "-lc",
                      "echo guard=$EREBOR_PROCESS_GUARD runner=$EREBOR_SESSION_RUNNER actor=$EREBOR_ACTOR_ID"
                    ]
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
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host"),
            "metadata",
        )?;

        let outcome = run_session_diagnostic(&config, &plan)?;

        assert!(outcome.stdout().contains("guard=linux-ptrace"));
        assert!(outcome.stdout().contains("runner=linux-host"));
        assert!(outcome.stdout().contains("actor=openclaw"));
        assert!(audit_path.exists());

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn linux_host_runner_can_disable_process_guard_at_runtime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = test_dir("unguarded")?;
        let policy_path = write_policy(&test_dir)?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "diagnostics": [
                  {{
                    "name": "metadata",
                    "command": [
                      "sh",
                      "-lc",
                      "echo terminal_guard=$EREBOR_TERMINAL_PROCESS_GUARD process_guard=${{EREBOR_PROCESS_GUARD:-unset}}"
                    ]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true,
                  "process_guard": {{ "enabled": false }}
                }}
              }}
            }}"#,
            policy_path.display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-unguarded"),
            "metadata",
        )?;

        let outcome = run_session_diagnostic(&config, &plan)?;

        assert!(outcome.stdout().contains("terminal_guard=disabled"));
        assert!(outcome.stdout().contains("process_guard=unset"));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn linux_host_runner_adopts_existing_process_when_ptrace_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !can_adopt_sibling_process() {
            eprintln!("skipping Linux host adoption test because host ptrace policy blocks sibling attachment");
            return Ok(());
        }

        let test_dir = test_dir("adopt")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "audit": {{ "jsonl": "{}" }},
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
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
        ))?;
        let mut child = Command::new("sh")
            .arg("-lc")
            .arg("sleep 1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let plan = SessionAdoptPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-adopt"),
            child.id() as i32,
        )?;

        let outcome = adopt_session_plan_capture(&config, &plan);
        if outcome.is_err() {
            let _result = child.kill();
            let _result = child.wait();
        }
        let outcome = outcome?;
        let _result = child.wait();

        assert!(outcome
            .stderr()
            .contains("erebor linux process guard capability: mode=adopt"));
        assert!(outcome.stderr().contains("ptrace=enabled"));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn linux_host_runner_denies_risky_exec_before_command_runs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = test_dir("deny")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "audit": {{ "jsonl": "{}" }},
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
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
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-deny"),
            "raw-cdp",
        )?;

        let error = match run_session_diagnostic(&config, &plan) {
            Ok(outcome) => {
                return Err(format!(
                    "diagnostic should fail, but stdout was `{}` and stderr was `{}`",
                    outcome.stdout(),
                    outcome.stderr()
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(error, SessionExecutionError::DiagnosticFailed { .. }),
            "expected denied diagnostic failure, got {error:?}"
        );
        assert!(audit_path.exists());
        let audit = fs::read_to_string(&audit_path)?;
        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    #[test]
    fn linux_host_runner_fails_closed_for_verification_required_exec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = test_dir("require-approval")?;
        let policy_path = write_policy(&test_dir)?;
        let audit_path = test_dir.join("audit.jsonl");
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "audit": {{ "jsonl": "{}" }},
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "diagnostics": [
                  {{
                    "name": "git-push",
                    "command": ["sh", "-lc", "git push origin main"]
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
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-verify"),
            "git-push",
        )?;

        let error = match run_session_diagnostic(&config, &plan) {
            Ok(outcome) => {
                return Err(format!(
                    "diagnostic should fail closed, but stdout was `{}` and stderr was `{}`",
                    outcome.stdout(),
                    outcome.stderr()
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(error, SessionExecutionError::DiagnosticFailed { .. }),
            "expected verification-required diagnostic failure, got {error:?}"
        );
        let audit = fs::read_to_string(&audit_path)?;
        assert!(audit.contains("\"policy_decision\":{\"type\":\"require_approval\""));
        assert!(audit.contains("\"final_decision\":{\"type\":\"deny\""));
        assert!(audit.contains("verify-git-push"));

        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let path =
            std::env::temp_dir().join(format!("erebor-linux-host-runner-{name}-{}", process::id()));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn write_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
        let policy_path = test_dir.join("policy.json");
        fs::write(
            &policy_path,
            r#"
            {
              "rules": [
                {
                  "id": "verify-git-push",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "git push"
                  },
                  "decision": "require_approval",
                  "reason": "git push needs operator verification"
                },
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
        )?;
        Ok(policy_path)
    }

    fn can_adopt_sibling_process() -> bool {
        fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .map(|value| value.trim() == "0")
            .unwrap_or(true)
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn linux_host_runner_tests_are_host_specific() {
    eprintln!("skipping Linux host runner tests on non-x86_64 Linux host");
}
