#[allow(dead_code)]
#[path = "support/cli.rs"]
mod cli;
#[path = "support/codex_linux_v1/mock_responses.rs"]
mod mock_responses;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{
        collections::BTreeSet,
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    };

    use erebor_runtime_audit::read_audit_records;
    use erebor_runtime_context::{ContextRepository, ContextTreeEntryKind};
    use erebor_runtime_core::SessionRegistry;
    use erebor_runtime_session::CodexNativeHookEvent;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::{
        cli::{E2eWorkspace, EreborCliFixture},
        mock_responses::{
            write_codex_mock_responses_config_with_sandbox, CodexMockResponsesServer,
        },
    };

    const REQUIRE_SESSION_RUN_ENV: &str = "EREBOR_REQUIRE_CODEX_LINUX_V1_SESSION_RUN";
    const STRICT_PROFILE_ROOT_ENV: &str = "EREBOR_CODEX_LINUX_V1_STRICT_PROFILE_ROOT";

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
        let pre_tool_use_schema = schema_sha256(
            br#"{"hook_event_name":"PreToolUse","session_id":"thread","turn_id":"turn","tool_use_id":"tool","tool_name":"Bash","tool_input":{"command":"command"}}"#,
        )?;
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
            "event_schemas":[{{"event":"session_start","sha256":"{}"}},{{"event":"pre_tool_use","sha256":"{}"}}]
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
                session_start_schema,
                pre_tool_use_schema
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

        let unleased_effect_marker = root.join("unleased-effect-result.json");
        let mut unleased_effect = EreborCliFixture::build()?.command_in(
            root,
            [
                "session",
                "run",
                "--runner",
                "linux-host",
                "--config",
                config.to_str().ok_or("config path")?,
                driver.to_str().ok_or("driver path")?,
                unleased_effect_marker.to_str().ok_or("marker path")?,
            ],
        );
        let unleased_effect_output = unleased_effect
            .env("EREBOR_CODEX_LINUX_V1_ASSERT_UNLEASED_EFFECT", "1")
            .output()?;
        if !unleased_effect_output.status.success() {
            return Err(format!(
                "unleased Codex effect fixture failed: {}",
                String::from_utf8_lossy(&unleased_effect_output.stderr)
            )
            .into());
        }
        assert_eq!(fs::read(&unleased_effect_marker)?, br#"{"continue":true}"#);
        assert_eq!(
            fs::read_to_string(unleased_effect_marker.with_extension("diagnostic"))?,
            "unleased-effect-denied"
        );

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
    fn brokered_app_server_prompt_ingress_uses_the_authenticated_hook_channel(
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !required_session_run() {
            eprintln!(
                "skipping pinned Codex App Server fixture; set {REQUIRE_SESSION_RUN_ENV}=1 and {STRICT_PROFILE_ROOT_ENV}=/absolute/root-owned-profile"
            );
            return Ok(());
        }
        require_managed_projection_anchors()?;
        let strict_profile = StrictCodexProfile::from_environment()?;
        strict_profile.assert_complete()?;
        let codex = strict_profile.executable();

        let workspace = E2eWorkspace::create("codex-managed-app-server-session-run")?;
        let root = workspace.path();
        let policy = root.join("policy.json");
        fs::write(&policy, r#"{ "rules": [] }"#)?;
        let codex_hash = hash(codex)?;
        let config = root.join("runtime.json");
        fs::write(
            &config,
            format!(
                r#"{{
          "policies":["{}"],
          "session":{{"enabled":true,"runner":{{"kind":"linux_host"}},"interception":{{"enabled":true,"operations":["process_exec","file_mutation"]}}}},
          "surfaces":{{
            "terminal":{{"enabled":true,"process_mediation":{{"enabled":true,"handlers":[{{
              "id":"unused-browser-handler","kind":"managed_browser_cdp",
              "match":{{"executables":["never-invoked-by-this-fixture"]}}
            }}]}}}},
            "browser_cdp":{{"enabled":true}},
            "filesystem":{{"enabled":true}}
          }},
          "codex":{{"enabled":true,"profiles":[{{
            "id":"pinned-app-server","runner":"linux_host","executable":"{}","executable_sha256":"{}","deployment":"fleet_managed",
            "trust_root":"{}","requirements_source":"{}","requirements_sha256":"{}",
            "managed_hook_source":"{}","managed_hook_sha256":"{}","managed_hook_path":"/usr/lib/erebor/codex-hooks/erebor-codex-hook",
            "shell_startup_source":"{}","shell_startup_sha256":"{}","shell_startup_path":"/usr/lib/erebor/codex-hooks/.zshenv",
            "hook_shell":"zsh",
            "hook_exec_history":["{}","/usr/bin/zsh","/usr/lib/erebor/codex-hooks/erebor-codex-hook"],
            "event_schemas":[{}],
            "app_server_transport":{{"enabled":true}}
          }}]}}
        }}"#,
                policy.display(),
                codex.display(),
                codex_hash,
                strict_profile.root().display(),
                strict_profile.requirements_path().display(),
                hash(strict_profile.requirements_path())?,
                strict_profile.managed_hook_path().display(),
                hash(strict_profile.managed_hook_path())?,
                strict_profile.shell_startup_path().display(),
                hash(strict_profile.shell_startup_path())?,
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
        let physical_effect_marker = app_workspace.join("phase-3-physical-effect");
        let tool_command = format!("/usr/bin/touch {}", physical_effect_marker.display());
        let mock_responses = CodexMockResponsesServer::start_with_tool_command(&tool_command)?;
        write_codex_mock_responses_config_with_sandbox(
            &codex_home,
            mock_responses.uri(),
            "workspace-write",
        )?;

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
        app_server.assert_completed_hook_events_and_turn(&[
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "Stop",
        ])?;
        assert!(
            physical_effect_marker.exists(),
            "the pinned Codex tool command did not create its physical-effect marker"
        );
        app_server.assert_physical_effect_order(root, &tool_command, &physical_effect_marker)?;
        app_server.assert_brokered_prompt_context(root, "Phase 1 managed session probe.")?;
        app_server.assert_broker_denied(
            5,
            "thread/shellCommand",
            Some(json!({"command":"printf should-not-reach-codex"})),
        )?;
        app_server.assert_broker_denied(6, "thread/inject_items", Some(json!({})))?;
        app_server.assert_broker_denied(7, "thread/realtime/appendText", Some(json!({})))?;
        assert!(
            !untrusted_startup_marker.exists(),
            "untrusted $HOME/.zshenv was executed"
        );
        Ok(())
    }

    struct StrictCodexProfile {
        root: PathBuf,
        executable: PathBuf,
        requirements: PathBuf,
        managed_hook: PathBuf,
        shell_startup: PathBuf,
    }

    impl StrictCodexProfile {
        fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
            let root = PathBuf::from(
                std::env::var_os(STRICT_PROFILE_ROOT_ENV).ok_or_else(|| {
                    format!(
                        "{STRICT_PROFILE_ROOT_ENV} must name the root-owned, hash-pinned Codex profile"
                    )
                })?,
            );
            if !root.is_absolute() {
                return Err(format!(
                    "{STRICT_PROFILE_ROOT_ENV} must be an absolute path: {}",
                    root.display()
                )
                .into());
            }
            let profile = Self {
                executable: root.join("bin/codex"),
                requirements: root.join("requirements.toml"),
                managed_hook: root.join("hooks/erebor-codex-hook"),
                shell_startup: root.join("hooks/.zshenv"),
                root,
            };
            for path in [
                profile.root.as_path(),
                profile.executable.as_path(),
                profile.requirements.as_path(),
                profile.managed_hook.as_path(),
                profile.shell_startup.as_path(),
            ] {
                Self::assert_root_owned(path)?;
            }
            Ok(profile)
        }

        fn assert_complete(&self) -> Result<(), Box<dyn std::error::Error>> {
            let requirements = fs::read_to_string(&self.requirements)?;
            for expected in [
                "allow_managed_hooks_only = true",
                "allow_remote_control = false",
                "managed_dir = \"/usr/lib/erebor/codex-hooks\"",
                "[[hooks.SessionStart]]",
                "[[hooks.UserPromptSubmit]]",
                "[[hooks.PreToolUse]]",
                "[[hooks.PermissionRequest]]",
                "[[hooks.PostToolUse]]",
                "[[hooks.SubagentStart]]",
                "[[hooks.SubagentStop]]",
                "[[hooks.Stop]]",
            ] {
                if !requirements.contains(expected) {
                    return Err(format!(
                        "strict Codex requirements artifact {} is missing `{expected}`",
                        self.requirements.display()
                    )
                    .into());
                }
            }
            Ok(())
        }

        fn assert_root_owned(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(format!(
                    "strict Codex profile artifact is not root-owned and non-user-writable: {}",
                    path.display()
                )
                .into());
            }
            Ok(())
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn executable(&self) -> &Path {
            &self.executable
        }

        fn requirements_path(&self) -> &Path {
            &self.requirements
        }

        fn managed_hook_path(&self) -> &Path {
            &self.managed_hook
        }

        fn shell_startup_path(&self) -> &Path {
            &self.shell_startup
        }
    }

    fn hash(path: &Path) -> Result<String, std::io::Error> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
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
        let schemas = [
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
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(schemas.join(","))
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

    struct SessionRunAppServer {
        child: Child,
        session_id: String,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
        notifications: Vec<Value>,
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
                session_id: format!("session-{}", child.id()),
                child,
                stdin,
                stdout: BufReader::new(stdout),
                notifications: Vec::new(),
            })
        }

        fn assert_brokered_prompt_context(
            &self,
            root: &Path,
            prompt: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let registry = SessionRegistry::new(root.join(".erebor/sessions"));
            let repository = registry
                .open_context_repository(&self.session_id)?
                .ok_or("brokered App Server session omitted its context repository")?;
            let scope = repository
                .scope_refs()?
                .into_iter()
                .find(|scope| scope.as_str().contains("/scope/codex-app-server-"))
                .ok_or("brokered App Server prompt did not create a context scope")?;
            let head = repository.scope_head(&scope)?;
            let tree = repository.read_commit(head)?.tree();
            let blobs = context_blobs(&repository, tree)?;
            let prompt_context = blobs
                .iter()
                .filter_map(|blob| serde_json::from_slice::<Value>(blob).ok())
                .find(|context| {
                    context.get("source") == Some(&json!("brokered_app_server_transport"))
                        && context
                            .get("original_request_jsonl")
                            .and_then(Value::as_str)
                            .is_some_and(|original| original.contains(prompt))
                })
                .ok_or("brokered App Server prompt context did not retain the original request")?;
            assert_eq!(
                prompt_context
                    .pointer("/hook_reconciliation/status")
                    .and_then(Value::as_str),
                Some("exact"),
                "the live UserPromptSubmit hook did not exactly reconcile to the brokered turn"
            );
            assert_eq!(
                prompt_context
                    .pointer("/hook_reconciliation/authenticated_user_prompt_submit_count")
                    .and_then(Value::as_u64),
                Some(1)
            );
            let pre_tool_context = blobs
                .iter()
                .filter_map(|blob| serde_json::from_slice::<Value>(blob).ok())
                .find(|context| {
                    context.get("source") == Some(&json!("authenticated_codex_hook_broker"))
                        && context.get("event_kind") == Some(&json!("pre-tool-use"))
                })
                .ok_or("live PreToolUse hook did not create a Context DAG record")?;
            assert_eq!(
                pre_tool_context
                    .pointer("/context_binding/status")
                    .and_then(Value::as_str),
                Some("exact")
            );
            assert_eq!(
                pre_tool_context
                    .pointer("/context_binding/scope_ref")
                    .and_then(Value::as_str),
                Some(scope.as_str())
            );
            Ok(())
        }

        fn assert_physical_effect_order(
            &self,
            root: &Path,
            command: &str,
            mutation_path: &Path,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let registry = SessionRegistry::new(root.join(".erebor/sessions"));
            let record = registry.load_session(&self.session_id)?;
            let records = read_audit_records(record.audit_path())?;
            let fact_index = |fact: &str| {
                records.iter().position(|record| {
                    record
                        .event
                        .payload
                        .pointer("/fact")
                        .and_then(Value::as_str)
                        == Some(fact)
                })
            };
            let pre_tool = fact_index("pre-tool-use-authenticated")
                .ok_or("live tool run omitted its PreToolUse lease fact")?;
            let hook_exit = fact_index("guarded-hook-exit-success")
                .ok_or("live tool run omitted its guarded hook-exit success fact")?;
            let command_effect = records
                .iter()
                .position(|record| {
                    record
                        .event
                        .payload
                        .pointer("/fact")
                        .and_then(Value::as_str)
                        == Some("physical-effect")
                        && record
                            .event
                            .payload
                            .pointer("/detail/allowed")
                            .and_then(Value::as_bool)
                            == Some(true)
                        && record
                            .event
                            .payload
                            .pointer("/detail/operation")
                            .and_then(Value::as_str)
                            == Some("process_exec")
                        && record
                            .event
                            .payload
                            .pointer("/detail/argv")
                            .and_then(Value::as_array)
                            .and_then(|argv| argv.last())
                            .and_then(Value::as_str)
                            == Some(command)
                })
                .ok_or("live tool command did not receive an allowed process lease decision")?;
            let mutation_path = mutation_path.display().to_string();
            let mutation_effect = records
                .iter()
                .position(|record| {
                    record
                        .event
                        .payload
                        .pointer("/fact")
                        .and_then(Value::as_str)
                        == Some("physical-effect")
                        && record
                            .event
                            .payload
                            .pointer("/detail/allowed")
                            .and_then(Value::as_bool)
                            == Some(true)
                        && record
                            .event
                            .payload
                            .pointer("/detail/operation")
                            .and_then(Value::as_str)
                            == Some("file_mutation")
                        && record
                            .event
                            .payload
                            .pointer("/detail/file/path")
                            .and_then(Value::as_str)
                            == Some(mutation_path.as_str())
                })
                .ok_or("live tool mutation did not receive an allowed file lease decision")?;
            assert!(
                pre_tool < hook_exit && hook_exit < command_effect && command_effect < mutation_effect,
                "unexpected live hook/physical-effect order: pre_tool={pre_tool}, hook_exit={hook_exit}, command={command_effect}, mutation={mutation_effect}"
            );
            Ok(())
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
                    self.notifications.push(response);
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

        fn assert_broker_denied(
            &mut self,
            id: u64,
            method: &str,
            params: Option<Value>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut request = json!({"id": id, "method": method});
            if let Some(params) = params {
                request["params"] = params;
            }
            self.write_json(&request)?;
            for _attempt in 0..128 {
                let mut line = String::new();
                if self.stdout.read_line(&mut line)? == 0 {
                    return Err(format!(
                        "session-run Codex App Server closed stdout while waiting for broker denial of `{method}`"
                    )
                    .into());
                }
                let response: Value = serde_json::from_str(&line)?;
                if response.get("id") != Some(&json!(id)) {
                    self.notifications.push(response);
                    continue;
                }
                assert_eq!(
                    response.pointer("/error/code").and_then(Value::as_i64),
                    Some(-32003),
                    "sensitive App Server method `{method}` reached Codex instead of Erebor's broker"
                );
                assert!(
                    response
                        .pointer("/error/message")
                        .and_then(Value::as_str)
                        .is_some_and(|message| message.contains("Erebor denied")),
                    "sensitive App Server method `{method}` did not receive Erebor's broker denial"
                );
                return Ok(());
            }
            Err(
                format!("App Server emitted too many messages before broker denial of `{method}`")
                    .into(),
            )
        }

        fn assert_completed_hook_events_and_turn(
            &mut self,
            expected_events: &[&str],
        ) -> Result<(), Box<dyn std::error::Error>> {
            let expected_events = expected_events.iter().copied().collect::<BTreeSet<_>>();
            let mut completed_events = BTreeSet::new();
            let mut observed_notifications = Vec::new();

            for _attempt in 0..512 {
                let notification = self.next_notification()?;
                let method = notification
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("<non-notification>");
                observed_notifications.push(method.to_owned());
                match Some(method) {
                    Some("hook/completed") => {
                        let event = notification
                            .pointer("/params/run/eventName")
                            .and_then(Value::as_str)
                            .ok_or("hook/completed omitted params.run.eventName")?;
                        let event = match event {
                            "sessionStart" | "SessionStart" => "SessionStart",
                            "userPromptSubmit" | "UserPromptSubmit" => "UserPromptSubmit",
                            "preToolUse" | "PreToolUse" => "PreToolUse",
                            "permissionRequest" | "PermissionRequest" => "PermissionRequest",
                            "postToolUse" | "PostToolUse" => "PostToolUse",
                            "subagentStart" | "SubagentStart" => "SubagentStart",
                            "subagentStop" | "SubagentStop" => "SubagentStop",
                            "stop" | "Stop" => "Stop",
                            other => other,
                        };
                        if !expected_events.contains(event) {
                            return Err(format!(
                                "managed AppServer emitted unsupported hook `{event}` outside the selected narrow profile; observed notifications: {observed_notifications:?}"
                            )
                            .into());
                        }
                        assert_eq!(
                            notification
                                .pointer("/params/run/status")
                                .and_then(Value::as_str),
                            Some("completed"),
                            "managed hook `{event}` did not complete successfully"
                        );
                        completed_events.insert(event.to_owned());
                    }
                    Some("turn/completed") => {
                        assert_eq!(
                            notification
                                .pointer("/params/turn/status")
                                .and_then(Value::as_str),
                            Some("completed"),
                            "managed AppServer turn did not complete successfully"
                        );
                        let expected_events = expected_events
                            .iter()
                            .map(|event| (*event).to_owned())
                            .collect::<BTreeSet<_>>();
                        assert_eq!(
                            completed_events, expected_events,
                            "the managed AppServer turn did not complete every expected hook; observed notifications: {observed_notifications:?}"
                        );
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err("managed AppServer emitted too many messages before turn/completed".into())
        }

        fn next_notification(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
            if !self.notifications.is_empty() {
                return Ok(self.notifications.remove(0));
            }
            loop {
                let mut line = String::new();
                if self.stdout.read_line(&mut line)? == 0 {
                    return Err(
                        "session-run Codex AppServer closed stdout before turn/completed".into(),
                    );
                }
                let message: Value = serde_json::from_str(&line)?;
                if message.get("method").is_some() {
                    return Ok(message);
                }
            }
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

    fn context_blobs(
        repository: &ContextRepository,
        tree: erebor_runtime_context::ContextObjectId,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut blobs = Vec::new();
        for entry in repository.read_tree(tree)?.entries() {
            match entry.kind() {
                ContextTreeEntryKind::Blob => {
                    blobs.push(repository.read_object(entry.object())?.bytes().to_vec());
                }
                ContextTreeEntryKind::Tree => {
                    blobs.extend(context_blobs(repository, entry.object())?);
                }
                ContextTreeEntryKind::Commit => {}
            }
        }
        Ok(blobs)
    }
}
