#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_host {
    use std::{
        fs,
        path::Path,
        process::{self, Command, Stdio},
    };

    use erebor_runtime_core::{RuntimeConfig, SessionAdoptPlan, SessionRunPlan, SessionRunnerKind};
    use erebor_runtime_events::SessionId;
    use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

    #[test]
    fn linux_host_runner_relaunches_diagnostic_through_process_guard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("relaunch")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
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
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host"),
            "metadata",
        )?;

        let outcome = SessionExecutionService::run_diagnostic(&config, &plan)?;

        assert!(outcome.stdout().contains("guard=linux-ptrace"));
        assert!(outcome.stdout().contains("runner=linux-host"));
        assert!(outcome.stdout().contains("actor=openclaw"));
        assert!(fixture.session_audit_path("session-linux-host").exists());

        Ok(())
    }

    #[test]
    fn linux_host_runner_suppresses_default_debug_sleep_audit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("sleep-audit-filter")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
                "diagnostics": [
                  {{
                    "name": "sleep",
                    "command": ["sleep", "0"]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-sleep-filter"),
            "sleep",
        )?;

        let outcome = SessionExecutionService::run_diagnostic(&config, &plan)?;

        assert!(outcome.stdout().is_empty());
        let audit_path = fixture.session_audit_path("session-linux-host-sleep-filter");
        if audit_path.exists() {
            let audit = fs::read_to_string(&audit_path)?;
            assert!(!audit.contains("\"/usr/bin/sleep\""));
            assert!(!audit.contains("\"sleep\",\"0\""));
        }

        Ok(())
    }

    #[test]
    fn linux_host_runner_can_disable_process_guard_at_runtime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("unguarded")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
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
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-unguarded"),
            "metadata",
        )?;

        let outcome = SessionExecutionService::run_diagnostic(&config, &plan)?;

        assert!(outcome.stdout().contains("terminal_guard=disabled"));
        assert!(outcome.stdout().contains("process_guard=unset"));

        Ok(())
    }

    #[test]
    fn linux_host_runner_adopts_existing_process_when_ptrace_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !can_adopt_sibling_process() {
            eprintln!("skipping Linux host adoption test because host ptrace policy blocks sibling attachment");
            return Ok(());
        }

        let fixture = LinuxHostRunnerFixture::new("adopt")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
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

        let outcome = SessionExecutionService::adopt_plan_capture(&config, &plan);
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

        Ok(())
    }

    #[test]
    fn linux_host_runner_denies_risky_exec_before_command_runs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("deny")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
                "diagnostics": [
                  {{
                    "name": "raw-cdp",
                    "command": ["sh", "--remote-debugging-port=9222"]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-deny"),
            "raw-cdp",
        )?;

        let error = match SessionExecutionService::run_diagnostic(&config, &plan) {
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
        let audit_path = fixture.session_audit_path("session-linux-host-deny");
        assert!(audit_path.exists());
        let audit = fs::read_to_string(&audit_path)?;
        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));

        Ok(())
    }

    #[test]
    fn linux_host_runner_lifecycle_allows_safe_exec_and_denies_raw_cdp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("lifecycle")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
                "diagnostics": [
                  {{
                    "name": "allowed",
                    "command": [
                      "sh",
                      "-lc",
                      "echo erebor-lifecycle-allowed guard=$EREBOR_PROCESS_GUARD"
                    ]
                  }},
                  {{
                    "name": "raw-cdp",
                    "command": ["sh", "--remote-debugging-port=9222"]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;

        let allowed_plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-lifecycle-allow"),
            "allowed",
        )?;
        let allowed = SessionExecutionService::run_diagnostic(&config, &allowed_plan)?;

        assert!(allowed.stdout().contains("erebor-lifecycle-allowed"));
        assert!(allowed.stdout().contains("guard=linux-ptrace"));

        let denied_plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-lifecycle-deny"),
            "raw-cdp",
        )?;
        let error = SessionExecutionService::run_diagnostic(&config, &denied_plan);

        assert!(
            matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
            "expected raw CDP lifecycle diagnostic to fail closed, got {error:?}"
        );
        let audit =
            fs::read_to_string(fixture.session_audit_path("session-linux-host-lifecycle-deny"))?;
        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));
        assert!(audit.contains("raw CDP process launch is denied"));

        Ok(())
    }

    #[test]
    fn linux_host_runner_denies_shell_spawned_child_exec() -> Result<(), Box<dyn std::error::Error>>
    {
        let command_json = r#"[
          "sh",
          "-lc",
          "b=s; c=h; r=remote; d=debugging; p=port; \"$b$c\" \"--$r-$d-$p=9222\""
        ]"#;

        let audit = LinuxHostRunnerFixture::run_denied_process_diagnostic(
            "shell-child-deny",
            "raw-cdp-shell-child",
            command_json,
            "session-linux-host-shell-child-deny",
        )?;

        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));
        Ok(())
    }

    #[test]
    fn linux_host_runner_denies_pipeline_spawned_child_exec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let command_json = r#"[
          "sh",
          "-lc",
          "printf 'hello\n' | \"$0\" \"$@\"",
          "sh",
          "--remote-debugging-port=9222"
        ]"#;

        let audit = LinuxHostRunnerFixture::run_denied_process_diagnostic(
            "pipeline-child-deny",
            "raw-cdp-pipeline-child",
            command_json,
            "session-linux-host-pipeline-child-deny",
        )?;

        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));
        Ok(())
    }

    #[test]
    fn linux_host_runner_denies_python_subprocess_child_exec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if Command::new("python3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping Python subprocess guard test because python3 is unavailable");
            return Ok(());
        }

        let command_json = r#"[
          "python3",
          "-c",
          "import subprocess; subprocess.run(['sh', '--remote-debugging-port=9222'], check=True)"
        ]"#;

        let audit = LinuxHostRunnerFixture::run_denied_process_diagnostic(
            "python-child-deny",
            "raw-cdp-python-child",
            command_json,
            "session-linux-host-python-child-deny",
        )?;

        assert!(audit.contains("\"type\":\"deny\""));
        assert!(audit.contains("deny-raw-cdp"));
        Ok(())
    }

    #[test]
    fn linux_host_runner_fails_closed_for_verification_required_exec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = LinuxHostRunnerFixture::new("require-approval")?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "workspace": "{}",
                "diagnostics": [
                  {{
                    "name": "git-push",
                    "command": ["sh", "-lc", "git push origin main"]
                  }}
                ],
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            fixture.policy_path().display(),
            fixture.test_dir().display()
        ))?;
        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-linux-host-verify"),
            "git-push",
        )?;

        let error = match SessionExecutionService::run_diagnostic(&config, &plan) {
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
        let audit = fs::read_to_string(fixture.session_audit_path("session-linux-host-verify"))?;
        assert!(audit.contains("\"policy_decision\":{\"type\":\"require_approval\""));
        assert!(audit.contains("\"final_decision\":{\"type\":\"deny\""));
        assert!(audit.contains("verify-git-push"));

        Ok(())
    }

    struct LinuxHostRunnerFixture {
        test_dir: std::path::PathBuf,
        policy_path: std::path::PathBuf,
    }

    impl LinuxHostRunnerFixture {
        fn new(name: &str) -> Result<Self, std::io::Error> {
            let test_dir = std::env::temp_dir()
                .join(format!("erebor-linux-host-runner-{name}-{}", process::id()));
            let _result = fs::remove_dir_all(&test_dir);
            fs::create_dir_all(&test_dir)?;
            let policy_path = test_dir.join("policy.json");
            fs::write(&policy_path, Self::policy_source())?;
            Ok(Self {
                test_dir,
                policy_path,
            })
        }

        fn test_dir(&self) -> &Path {
            &self.test_dir
        }

        fn policy_path(&self) -> &Path {
            &self.policy_path
        }

        fn session_audit_path(&self, session_id: &str) -> std::path::PathBuf {
            self.registry_path().join(session_id).join("audit.jsonl")
        }

        fn run_denied_process_diagnostic(
            test_name: &str,
            diagnostic_name: &str,
            command_json: &str,
            session_id: &str,
        ) -> Result<String, Box<dyn std::error::Error>> {
            let fixture = Self::new(test_name)?;
            let config = RuntimeConfig::from_json_str(&format!(
                r#"{{
                  "policies": ["{}"],
                  "session": {{
                    "enabled": true,
                    "actor": {{ "id": "openclaw" }},
                    "workspace": "{}",
                    "diagnostics": [
                      {{
                        "name": "{}",
                        "command": {}
                      }}
                    ],
                    "runner": {{ "kind": "linux_host" }},
                    "interception": {{ "enabled": true }}
                  }},
                  "surfaces": {{
                    "terminal": {{
                      "enabled": true
                    }}
                  }}
                }}"#,
                fixture.policy_path().display(),
                fixture.test_dir().display(),
                diagnostic_name,
                command_json
            ))?;
            let plan = SessionRunPlan::from_diagnostic(
                &config,
                SessionRunnerKind::LinuxHost,
                SessionId::new(session_id),
                diagnostic_name,
            )?;

            let error = SessionExecutionService::run_diagnostic(&config, &plan);

            assert!(
                matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
                "expected denied diagnostic failure, got {error:?}"
            );
            Ok(fs::read_to_string(fixture.session_audit_path(session_id))?)
        }

        fn registry_path(&self) -> std::path::PathBuf {
            self.test_dir.join(".erebor/sessions")
        }

        fn policy_source() -> &'static str {
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
                "#
        }
    }

    impl Drop for LinuxHostRunnerFixture {
        fn drop(&mut self) {
            let _result = fs::remove_dir_all(&self.test_dir);
        }
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
