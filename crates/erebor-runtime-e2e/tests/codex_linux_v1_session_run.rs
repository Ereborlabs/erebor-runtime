#[allow(dead_code)]
#[path = "support/cli.rs"]
mod cli;
#[path = "support/codex_linux_v1/artifact.rs"]
mod managed_artifact;
#[path = "support/codex_linux_v1/mock_responses.rs"]
mod mock_responses;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        path::{Path, PathBuf},
        process::{Child, ChildStdin, ChildStdout, Command, Stdio},
        thread,
        time::Duration,
    };

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::{
        cli::{E2eWorkspace, EreborCliFixture},
        managed_artifact::{CodexLinuxV1RequirementsArtifact, V1_HOOK_EVENTS},
        mock_responses::{write_codex_mock_responses_config, CodexMockResponsesServer},
    };

    #[test]
    fn managed_hook_uses_the_guarded_session_run_channel() -> Result<(), Box<dyn std::error::Error>>
    {
        if !managed_projection_anchors_exist() {
            eprintln!(
                "skipping managed Codex session fixture: root-managed projection anchors are not installed"
            );
            return Ok(());
        }
        let workspace = E2eWorkspace::create("codex-managed-hook-session-run")?;
        let root = workspace.path();
        let trust = root.join("trust");
        let hooks = trust.join("hooks");
        fs::create_dir_all(&hooks)?;
        let requirements = trust.join("requirements.toml");
        let startup = hooks.join("shell-startup");
        let hook = hooks.join("erebor-codex-hook");
        fs::write(&requirements, "allow_managed_hooks_only = true\n")?;
        fs::write(&startup, "# managed startup\n")?;
        fs::copy(
            Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-test-hook")),
            &hook,
        )?;
        let marker = root.join("hook-result.json");
        let policy = root.join("policy.json");
        fs::write(&policy, r#"{ "rules": [] }"#)?;
        let driver = Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-session-driver"));
        let requirements_hash = hash(&requirements)?;
        let hook_hash = hash(&hook)?;
        let startup_hash = hash(&startup)?;
        let config = root.join("runtime.json");
        fs::write(
            &config,
            format!(
                r#"{{
          "policies":["{}"],
          "session":{{"enabled":true,"runner":{{"kind":"linux_host"}},"interception":{{"enabled":true}}}},
          "surfaces":{{
            "terminal":{{"enabled":true,"process_mediation":{{"enabled":true,"handlers":[{{
              "id":"unused-browser-handler","kind":"managed_browser_cdp",
              "match":{{"executables":["never-invoked-by-this-fixture"]}}
            }}]}}}},
            "browser_cdp":{{"enabled":true}},
            "filesystem":{{"enabled":true}}
          }},
          "codex":{{"enabled":true,"profiles":[{{
            "id":"fixture","runner":"linux_host","executable":"{}","deployment":"local_cooperative","profile_sha256":"{}",
            "trust_root":"{}","requirements_source":"{}","requirements_sha256":"{}",
            "managed_hook_source":"{}","managed_hook_sha256":"{}","managed_hook_path":"/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            "shell_startup_source":"{}","shell_startup_sha256":"{}","shell_startup_path":"/usr/lib/erebor/codex-hooks/shell-startup",
            "hook_shell":"direct",
            "hook_exec_history":["{}","/usr/lib/erebor/codex-hooks/erebor-codex-hook"],
            "event_schemas":[{{"event":"session_start","sha256":"{}"}}]
          }}]}}
        }}"#,
                policy.display(),
                driver.display(),
                "a".repeat(64),
                trust.display(),
                requirements.display(),
                requirements_hash,
                hook.display(),
                hook_hash,
                startup.display(),
                startup_hash,
                driver.display(),
                "b".repeat(64)
            ),
        )?;
        let result = EreborCliFixture::build()?.run_in(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                driver.to_str().ok_or("driver path")?,
                marker.to_str().ok_or("marker path")?,
            ],
        );
        if let Err(error) = result {
            let diagnostic = fs::read_to_string(marker.with_extension("diagnostic"))
                .unwrap_or_else(|_error| String::from("no driver diagnostic was written"));
            return Err(
                format!("managed hook session run failed: {error}; driver: {diagnostic}").into(),
            );
        }
        assert_eq!(fs::read(&marker)?, br#"{"continue":true}"#);

        let replaced_stdout_marker = root.join("replaced-stdout-result.json");
        let _failure = EreborCliFixture::build()?.run_expect_failure_in_env(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                driver.to_str().ok_or("driver path")?,
                replaced_stdout_marker.to_str().ok_or("marker path")?,
            ],
            [(
                String::from("EREBOR_CODEX_LINUX_V1_REPLACE_STDOUT"),
                std::ffi::OsString::from("1"),
            )],
        )?;
        let diagnostic = fs::read_to_string(replaced_stdout_marker.with_extension("diagnostic"))?;
        assert!(
            diagnostic.contains("peer identity did not match"),
            "replaced stdout did not fail through the broker: {diagnostic}"
        );
        Ok(())
    }

    #[test]
    fn pinned_app_server_session_start_uses_the_authenticated_hook_channel(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !managed_projection_anchors_exist() {
            eprintln!(
                "skipping pinned Codex App Server fixture: root-managed projection anchors are not installed"
            );
            return Ok(());
        }
        let Some(codex) = std::env::var_os("EREBOR_CODEX_LINUX_V1_CLI") else {
            eprintln!(
                "skipping pinned Codex App Server fixture: EREBOR_CODEX_LINUX_V1_CLI is not set"
            );
            return Ok(());
        };
        let codex = PathBuf::from(codex);
        if !codex.is_file() {
            return Err(format!(
                "EREBOR_CODEX_LINUX_V1_CLI is not a regular file: {}",
                codex.display()
            )
            .into());
        }

        let workspace = E2eWorkspace::create("codex-managed-app-server-session-run")?;
        let root = workspace.path();
        let artifact = CodexLinuxV1RequirementsArtifact::create(
            root,
            Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-test-hook")),
        )?;
        artifact.assert_complete()?;
        let startup = artifact.hook_directory().join(".zshenv");
        let managed_startup_marker = root.join("managed-zsh-startup");
        fs::write(
            &startup,
            format!(
                "print -r -- managed > {}\n",
                managed_startup_marker.display()
            ),
        )?;
        let hook = artifact.hook_directory().join("erebor-codex-hook");
        let policy = root.join("policy.json");
        fs::write(&policy, r#"{ "rules": [] }"#)?;
        let config = root.join("runtime.json");
        fs::write(
            &config,
            format!(
                r#"{{
          "policies":["{}"],
          "session":{{"enabled":true,"runner":{{"kind":"linux_host"}},"interception":{{"enabled":true}}}},
          "surfaces":{{
            "terminal":{{"enabled":true,"process_mediation":{{"enabled":true,"handlers":[{{
              "id":"unused-browser-handler","kind":"managed_browser_cdp",
              "match":{{"executables":["never-invoked-by-this-fixture"]}}
            }}]}}}},
            "browser_cdp":{{"enabled":true}},
            "filesystem":{{"enabled":true}}
          }},
          "codex":{{"enabled":true,"profiles":[{{
            "id":"pinned-app-server","runner":"linux_host","executable":"{}","deployment":"local_cooperative","profile_sha256":"{}",
            "trust_root":"{}","requirements_source":"{}","requirements_sha256":"{}",
            "managed_hook_source":"{}","managed_hook_sha256":"{}","managed_hook_path":"/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            "shell_startup_source":"{}","shell_startup_sha256":"{}","shell_startup_path":"/usr/lib/erebor/codex-hooks/.zshenv",
            "hook_shell":"zsh",
            "hook_exec_history":["{}","/usr/bin/zsh","/usr/lib/erebor/codex-hooks/erebor-codex-hook"],
            "event_schemas":[{}]
          }}]}}
        }}"#,
                policy.display(),
                codex.display(),
                "a".repeat(64),
                root.display(),
                artifact.requirements_path().display(),
                artifact.requirements_sha256(),
                hook.display(),
                artifact.hook_sha256(),
                startup.display(),
                hash(&startup)?,
                codex.display(),
                event_schemas()
            ),
        )?;
        let codex_home = root.join("codex-home");
        let untrusted_home = root.join("untrusted-home");
        let app_workspace = root.join("workspace");
        let hook_log = root.join("hook-events.jsonl");
        let hook_environment = root.join("hook-environment.log");
        let untrusted_startup_marker = root.join("untrusted-zsh-startup");
        fs::create_dir_all(&codex_home)?;
        fs::create_dir_all(&untrusted_home)?;
        fs::create_dir_all(&app_workspace)?;
        fs::write(
            untrusted_home.join(".zshenv"),
            format!(
                "print -r -- untrusted > {}\n",
                untrusted_startup_marker.display()
            ),
        )?;
        let mock_responses = CodexMockResponsesServer::start()?;
        write_codex_mock_responses_config(&codex_home, mock_responses.uri())?;

        let fixture = EreborCliFixture::build()?;
        let mut command = fixture.command_in(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                codex.to_str().ok_or("Codex path")?,
                "app-server",
                "--stdio",
            ],
        );
        command
            .env("CODEX_HOME", &codex_home)
            .env("EREBOR_CODEX_LINUX_V1_HOOK_LOG", &hook_log)
            .env("EREBOR_CODEX_LINUX_V1_HOOK_ENV_MARKER", &hook_environment)
            .env("HOME", &untrusted_home);
        let mut app_server = SessionRunAppServer::start(command)?;
        app_server.initialize()?;
        let requirements = app_server.request(2, "configRequirements/read", None)?;
        assert_eq!(
            requirements
                .pointer("/requirements/hooks/managedDir")
                .and_then(Value::as_str),
            Some("/usr/lib/erebor/codex-hooks")
        );
        let thread = app_server.request(
            3,
            "thread/start",
            Some(json!({"cwd": app_workspace, "ephemeral": true})),
        )?;
        let thread_id = thread
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .ok_or("thread/start omitted thread.id")?;
        app_server.request(
            4,
            "turn/start",
            Some(json!({
                "threadId": thread_id,
                "input": [{"type": "text", "text": "Phase 1 managed session probe."}]
            })),
        )?;
        assert_hook_events_in_order(
            &hook_log,
            ["SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"],
        )?;
        assert_eq!(fs::read_to_string(managed_startup_marker)?, "managed\n");
        assert!(
            !untrusted_startup_marker.exists(),
            "untrusted $HOME/.zshenv was executed"
        );
        assert_hook_environment_contains(&hook_environment, "ZDOTDIR=/usr/lib/erebor/codex-hooks")?;
        Ok(())
    }

    fn hash(path: &Path) -> Result<String, std::io::Error> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
    }

    fn managed_projection_anchors_exist() -> bool {
        Path::new("/etc/codex/requirements.toml").is_file()
            && Path::new("/usr/lib/erebor/codex-hooks").is_dir()
            && Path::new("/run/erebor").is_dir()
    }

    fn event_schemas() -> String {
        V1_HOOK_EVENTS
            .iter()
            .map(|event| {
                format!(
                    r#"{{"event":"{}","sha256":"{}"}}"#,
                    event_schema_name(event),
                    "b".repeat(64)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn event_schema_name(event: &str) -> &'static str {
        match event {
            "SessionStart" => "session_start",
            "UserPromptSubmit" => "user_prompt_submit",
            "PreToolUse" => "pre_tool_use",
            "PermissionRequest" => "permission_request",
            "PostToolUse" => "post_tool_use",
            "SubagentStart" => "subagent_start",
            "SubagentStop" => "subagent_stop",
            "Stop" => "stop",
            _ => unreachable!("the test requirements artifact has a fixed event inventory"),
        }
    }

    fn assert_hook_events_in_order(
        hook_log: &Path,
        expected_events: impl IntoIterator<Item = &'static str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected_events = expected_events.into_iter().collect::<Vec<_>>();
        let mut observed_events = Vec::new();
        for _attempt in 0..40 {
            if let Ok(source) = fs::read_to_string(hook_log) {
                observed_events = source
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter_map(|value| {
                        value
                            .get("hook_event_name")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .collect::<Vec<_>>();
                if expected_events
                    .iter()
                    .copied()
                    .eq(observed_events.iter().map(String::as_str))
                {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(125));
        }
        Err(format!(
            "managed hook events did not converge: expected={expected_events:?} observed={observed_events:?}"
        )
        .into())
    }

    fn assert_hook_environment_contains(
        hook_environment: &Path,
        expected: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for _attempt in 0..40 {
            if fs::read_to_string(hook_environment)
                .is_ok_and(|environment| environment.lines().any(|line| line == expected))
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(125));
        }
        let observed = fs::read_to_string(hook_environment)
            .unwrap_or_else(|_error| String::from("<no hook environment marker>"));
        Err(format!("managed hook did not receive `{expected}`: observed={observed:?}").into())
    }

    struct SessionRunAppServer {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
    }

    impl SessionRunAppServer {
        fn start(mut command: Command) -> Result<Self, Box<dyn std::error::Error>> {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let stdin = child.stdin.take().ok_or("session run omitted stdin")?;
            let stdout = child.stdout.take().ok_or("session run omitted stdout")?;
            Ok(Self {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            })
        }

        fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            self.request(
                1,
                "initialize",
                Some(json!({
                    "clientInfo": {
                        "name": "erebor-runtime-phase-1",
                        "title": "Erebor Runtime Phase 1",
                        "version": "1"
                    },
                    "capabilities": {"experimentalApi": true}
                })),
            )?;
            self.write_json(&json!({"method": "initialized"}))
        }

        fn request(
            &mut self,
            id: u64,
            method: &str,
            params: Option<Value>,
        ) -> Result<Value, Box<dyn std::error::Error>> {
            let mut request = json!({"id": id, "method": method});
            if let Some(params) = params {
                request["params"] = params;
            }
            self.write_json(&request)?;
            for _attempt in 0..128 {
                let mut line = String::new();
                if self.stdout.read_line(&mut line)? == 0 {
                    return Err(format!(
                        "session-run Codex App Server closed stdout while waiting for `{method}`"
                    )
                    .into());
                }
                let response: Value = serde_json::from_str(&line)?;
                if response.get("id") != Some(&json!(id)) {
                    continue;
                }
                if let Some(error) = response.get("error") {
                    return Err(format!("Codex App Server rejected `{method}`: {error}").into());
                }
                return response
                    .get("result")
                    .cloned()
                    .ok_or_else(|| format!("Codex App Server omitted `{method}` result").into());
            }
            Err(format!("Codex App Server emitted too many messages for `{method}`").into())
        }

        fn write_json(&mut self, message: &Value) -> Result<(), Box<dyn std::error::Error>> {
            serde_json::to_writer(&mut self.stdin, message)?;
            self.stdin.write_all(b"\n")?;
            self.stdin.flush()?;
            Ok(())
        }
    }

    impl Drop for SessionRunAppServer {
        fn drop(&mut self) {
            let _result = self.child.kill();
            let _result = self.child.wait();
        }
    }
}
