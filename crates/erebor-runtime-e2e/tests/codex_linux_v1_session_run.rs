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

    use erebor_runtime_session::CodexNativeHookEvent;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::{
        cli::{E2eWorkspace, EreborCliFixture},
        managed_artifact::CodexLinuxV1RequirementsArtifact,
        mock_responses::{write_codex_mock_responses_config, CodexMockResponsesServer},
    };

    const REQUIRE_SESSION_RUN_ENV: &str = "EREBOR_REQUIRE_CODEX_LINUX_V1_SESSION_RUN";

    #[test]
    fn managed_hook_uses_the_guarded_session_run_channel() -> Result<(), Box<dyn std::error::Error>>
    {
        if !required_session_run() {
            eprintln!(
                "skipping managed Codex session fixture; set {REQUIRE_SESSION_RUN_ENV}=1 on the Linux namespace fixture"
            );
            return Ok(());
        }
        require_managed_projection_anchors()?;
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
        let driver_hash = hash(driver)?;
        let session_start_schema = schema_sha256(br#"{"hook_event_name":"session_start"}"#)?;
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
            "id":"fixture","runner":"linux_host","executable":"{}","executable_sha256":"{}","deployment":"local_cooperative",
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
                driver_hash,
                trust.display(),
                requirements.display(),
                requirements_hash,
                hook.display(),
                hook_hash,
                startup.display(),
                startup_hash,
                driver.display(),
                session_start_schema
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

        let late_replaced_stdout_marker = root.join("late-replaced-stdout-result.json");
        let mut late_replacement = EreborCliFixture::build()?.command_in(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                driver.to_str().ok_or("driver path")?,
                late_replaced_stdout_marker.to_str().ok_or("marker path")?,
            ],
        );
        let late_replacement_output = late_replacement
            .env("EREBOR_CODEX_LINUX_V1_REPLACE_STDOUT_AFTER_BROKER", "1")
            .output()?;
        if !late_replacement_output.status.success() {
            return Err(format!(
                "managed hook did not preserve its original stdout after broker authentication: {}",
                String::from_utf8_lossy(&late_replacement_output.stderr)
            )
            .into());
        }
        assert_eq!(
            fs::read(&late_replaced_stdout_marker)?,
            br#"{"continue":true}"#
        );
        Ok(())
    }

    #[test]
    fn pinned_app_server_session_start_uses_the_authenticated_hook_channel(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !required_session_run() {
            eprintln!(
                "skipping pinned Codex App Server fixture; set {REQUIRE_SESSION_RUN_ENV}=1 with EREBOR_CODEX_LINUX_V1_CLI"
            );
            return Ok(());
        }
        require_managed_projection_anchors()?;
        let codex = PathBuf::from(
            std::env::var_os("EREBOR_CODEX_LINUX_V1_CLI")
                .ok_or("EREBOR_CODEX_LINUX_V1_CLI is required by the live Phase 1 fixture")?,
        );
        if !codex.is_file() {
            return Err(format!(
                "EREBOR_CODEX_LINUX_V1_CLI is not a regular file: {}",
                codex.display()
            )
            .into());
        }

        let workspace = E2eWorkspace::create("codex-managed-app-server-session-run")?;
        let root = workspace.path();
        let managed_hook = production_managed_hook()?;
        let artifact = CodexLinuxV1RequirementsArtifact::create(root, &managed_hook)?;
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
        let codex_hash = hash(&codex)?;
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
            "id":"pinned-app-server","runner":"linux_host","executable":"{}","executable_sha256":"{}","deployment":"local_cooperative",
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
                codex_hash,
                root.display(),
                artifact.requirements_path().display(),
                artifact.requirements_sha256(),
                hook.display(),
                artifact.hook_sha256(),
                startup.display(),
                hash(&startup)?,
                codex.display(),
                event_schemas()?
            ),
        )?;
        let codex_home = root.join("codex-home");
        let untrusted_home = root.join("untrusted-home");
        let app_workspace = root.join("workspace");
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
        assert_file_contains(&managed_startup_marker, "managed\n")?;
        assert!(
            !untrusted_startup_marker.exists(),
            "untrusted $HOME/.zshenv was executed"
        );
        Ok(())
    }

    fn hash(path: &Path) -> Result<String, std::io::Error> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
    }

    fn production_managed_hook() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("e2e crate is not under the workspace crates directory")?;
        let output = Command::new("cargo")
            .args([
                "build",
                "-p",
                "erebor-runtime-session",
                "--bin",
                "erebor-codex-hook",
            ])
            .current_dir(workspace)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "cargo build erebor-codex-hook failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let target_directory = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace.join("target"));
        let hook = target_directory
            .join("debug")
            .join(format!("erebor-codex-hook{}", std::env::consts::EXE_SUFFIX));
        if !hook.is_file() {
            return Err(format!(
                "cargo build erebor-codex-hook did not produce a regular binary at {}",
                hook.display()
            )
            .into());
        }
        Ok(hook)
    }

    fn schema_sha256(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        Ok(CodexNativeHookEvent::parse(input)?
            .schema_sha256()
            .to_owned())
    }

    fn required_session_run() -> bool {
        std::env::var_os(REQUIRE_SESSION_RUN_ENV).is_some_and(|value| value == "1")
    }

    fn require_managed_projection_anchors() -> Result<(), Box<dyn std::error::Error>> {
        for path in [
            "/etc/codex/requirements.toml",
            "/usr/lib/erebor/codex-hooks",
            "/run/erebor",
        ] {
            if !Path::new(path).exists() {
                return Err(format!(
                    "{REQUIRE_SESSION_RUN_ENV}=1 requires the root-managed session projection anchor `{path}`"
                )
                .into());
            }
        }
        Ok(())
    }

    fn event_schemas() -> Result<String, Box<dyn std::error::Error>> {
        [
            ("SessionStart", br#"{"session_id":"id","transcript_path":null,"cwd":"cwd","hook_event_name":"SessionStart","model":"model","permission_mode":"mode","source":"source"}"#.as_slice()),
            ("UserPromptSubmit", br#"{"session_id":"id","turn_id":"id","transcript_path":null,"cwd":"cwd","hook_event_name":"UserPromptSubmit","model":"model","permission_mode":"mode","prompt":"prompt"}"#.as_slice()),
            ("PreToolUse", br#"{"session_id":"id","turn_id":"id","transcript_path":null,"cwd":"cwd","hook_event_name":"PreToolUse","model":"model","permission_mode":"mode","tool_name":"Bash","tool_input":{"command":"command"},"tool_use_id":"id"}"#.as_slice()),
            ("Stop", br#"{"session_id":"id","turn_id":"id","transcript_path":null,"cwd":"cwd","hook_event_name":"Stop","model":"model","permission_mode":"mode","stop_hook_active":false,"last_assistant_message":"message"}"#.as_slice()),
        ]
        .into_iter()
        .map(|(event, payload)| {
            Ok(format!(
                r#"{{"event":"{}","sha256":"{}"}}"#,
                event_schema_name(event),
                schema_sha256(payload)?
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()
        .map(|schemas| schemas.join(","))
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

    fn assert_file_contains(path: &Path, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
        for _attempt in 0..40 {
            if fs::read_to_string(path).is_ok_and(|source| source.contains(expected)) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(125));
        }
        let observed =
            fs::read_to_string(path).unwrap_or_else(|_error| String::from("<missing file>"));
        Err(format!(
            "managed hook did not write `{expected}` to {}: observed={observed:?}",
            path.display()
        )
        .into())
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
