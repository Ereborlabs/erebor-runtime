#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{fs, path::Path, process};

    use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{run_session_diagnostic, SessionExecutionError};

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
                "terminal": {{ "enabled": true }}
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
                "terminal": {{ "enabled": true }}
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
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "payload_contains": "remote-debugging-port"
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
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn linux_host_runner_tests_are_host_specific() {
    eprintln!("skipping Linux host runner tests on non-x86_64 Linux host");
}
