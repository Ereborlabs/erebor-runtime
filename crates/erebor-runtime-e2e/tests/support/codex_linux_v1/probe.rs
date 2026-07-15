use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use erebor_runtime_session::CodexNativeHookEvent;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::linux_user_mount_namespace::LinuxUserMountNamespace;

use super::{
    artifact::V1_HOOK_EVENTS, write_codex_mock_responses_config, CodexLinuxV1RequirementsArtifact,
    CodexMockResponsesServer,
};

const CODEX_BINARY_ENV: &str = "EREBOR_CODEX_LINUX_V1_CLI";
const CODEX_PROFILE_ENV: &str = "EREBOR_CODEX_LINUX_V1_PROFILE";
const HOOK_LOG_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_LOG";
const REQUIRE_PROBE_ENV: &str = "EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE";
const MANAGED_HOOK_DIRECTORY: &str = "/usr/lib/erebor/codex-hooks";
const MANAGED_HOOK_PATH: &str = "/usr/lib/erebor/codex-hooks/erebor-codex-hook";

pub(crate) struct CodexLinuxV1ProfileProbe;

impl CodexLinuxV1ProfileProbe {
    pub(crate) fn run_if_required(hook_binary: &Path) -> TestResult<()> {
        if !required_mode() {
            eprintln!(
                "skipping Codex Linux V1 live probe; set {REQUIRE_PROBE_ENV}=1 with {CODEX_PROFILE_ENV} and {CODEX_BINARY_ENV} on a privileged fixture"
            );
            return Ok(());
        }

        let profile = required_environment(CODEX_PROFILE_ENV)?;
        let codex = PathBuf::from(required_environment(CODEX_BINARY_ENV)?);
        if !codex.is_file() {
            return Err(test_error(format!(
                "{CODEX_BINARY_ENV} must name a regular executable: {}",
                codex.display()
            )));
        }
        if !hook_binary.is_file() {
            return Err(test_error(format!(
                "Phase 0 test hook binary is unavailable: {}",
                hook_binary.display()
            )));
        }

        LinuxUserMountNamespace::ensure_available()?;
        let fixture = fixture_directory()?;
        let artifact = CodexLinuxV1RequirementsArtifact::create(fixture.path(), hook_binary)?;
        artifact.assert_complete()?;

        let codex_version = command_output(&codex, ["--version"])?;
        let codex_sha256 = sha256_file(&codex)?;
        let host_requirements = Self::read_host_requirements(&codex, fixture.path())?;
        Self::assert_host_view_is_ordinary(&host_requirements)?;
        Self::assert_namespace_projection(&codex, fixture.path(), &artifact)?;

        eprintln!(
            "Codex Linux V1 profile probe passed mechanics: profile={} executable={} version={} executable_sha256={} requirements_sha256={} hook_sha256={} architecture={}",
            profile.to_string_lossy(),
            codex.display(),
            codex_version.trim(),
            codex_sha256,
            artifact.requirements_sha256(),
            artifact.hook_sha256(),
            std::env::consts::ARCH,
        );
        Ok(())
    }

    fn read_host_requirements(codex: &Path, root: &Path) -> TestResult<Value> {
        let codex_home = root.join("ordinary-host-codex-home");
        fs::create_dir_all(&codex_home)?;
        let mut command = Command::new(codex);
        command.args(["app-server", "--stdio"]);
        let ordinary_hook_log = root.join("ordinary-host-hook-log");
        let mut app_server = CodexAppServer::start(command, &codex_home, &ordinary_hook_log)?;
        app_server.initialize()?;
        app_server.request(2, "configRequirements/read", None)
    }

    fn assert_host_view_is_ordinary(requirements: &Value) -> TestResult<()> {
        let managed_dir = requirements
            .pointer("/requirements/hooks/managedDir")
            .and_then(Value::as_str);
        if managed_dir == Some(MANAGED_HOOK_DIRECTORY) {
            return Err(test_error(
                "ordinary host Codex view unexpectedly exposes the Phase 0 managed-hook directory",
            ));
        }
        Ok(())
    }

    fn assert_namespace_projection(
        codex: &Path,
        root: &Path,
        artifact: &CodexLinuxV1RequirementsArtifact,
    ) -> TestResult<()> {
        let codex_home = root.join("session-codex-home");
        let workspace = root.join("workspace");
        let hook_log = root.join("hook-events.jsonl");
        fs::create_dir_all(&codex_home)?;
        fs::create_dir_all(&workspace)?;
        let _mock_responses_server = CodexMockResponsesServer::start()?;
        write_codex_mock_responses_config(&codex_home, _mock_responses_server.uri())?;
        let script = MountNamespaceScript::write(root)?;

        let mut command = LinuxUserMountNamespace::command(script.path());
        command
            .arg(artifact.requirements_path())
            .arg(artifact.hook_directory())
            .arg(root.join("namespace-etc"))
            .arg(root.join("namespace-usr-lib-upper"))
            .arg(root.join("namespace-usr-lib-work"))
            .arg(codex)
            .arg("app-server")
            .arg("--stdio");
        let mut app_server = CodexAppServer::start(command, &codex_home, &hook_log)?;
        app_server.initialize()?;

        let requirements = app_server.request(2, "configRequirements/read", None)?;
        assert_projected_requirements(&requirements)?;

        let hooks = app_server.request(3, "hooks/list", Some(json!({"cwds": [workspace]})))?;
        assert_projected_hooks(&hooks)?;
        let thread = app_server.request(
            4,
            "thread/start",
            Some(json!({"cwd": workspace, "ephemeral": true})),
        )?;
        let thread_id = thread
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("thread/start omitted thread.id"))?;
        app_server.request(
            5,
            "turn/start",
            Some(json!({
                "threadId": thread_id,
                "input": [{"type": "text", "text": "Phase 0 lifecycle probe."}]
            })),
        )?;
        assert_hook_events_in_order(
            &hook_log,
            &[
                "SessionStart",
                "UserPromptSubmit",
                "PreToolUse",
                "PostToolUse",
                "Stop",
            ],
        )
    }
}

struct MountNamespaceScript {
    path: PathBuf,
}

impl MountNamespaceScript {
    fn write(root: &Path) -> TestResult<Self> {
        let path = root.join("mount-codex-profile.sh");
        fs::write(
            &path,
            r#"#!/bin/sh
set -eu

requirements_path="$1"
hook_directory="$2"
namespace_etc="$3"
namespace_usr_lib_upper="$4"
namespace_usr_lib_work="$5"
shift 5

mkdir -p "$namespace_etc/codex" "$namespace_usr_lib_upper" "$namespace_usr_lib_work"
touch "$namespace_etc/codex/requirements.toml"
mount --bind "$namespace_etc" /etc
mount -t overlay overlay -o "lowerdir=/usr/lib,upperdir=$namespace_usr_lib_upper,workdir=$namespace_usr_lib_work" /usr/lib
mkdir -p /usr/lib/erebor/codex-hooks
mount --bind "$requirements_path" /etc/codex/requirements.toml
mount -o remount,bind,ro /etc/codex/requirements.toml
mount --bind "$hook_directory" /usr/lib/erebor/codex-hooks
mount -o remount,bind,ro /usr/lib/erebor/codex-hooks

if printf invalid >/etc/codex/requirements.toml 2>/dev/null; then
  echo "requirements projection remained writable" >&2
  exit 90
fi
if printf invalid >/usr/lib/erebor/codex-hooks/unexpected 2>/dev/null; then
  echo "managed hook projection remained writable" >&2
  exit 91
fi

exec "$@"
"#,
        )?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

struct CodexAppServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    notifications: Vec<Value>,
}

impl CodexAppServer {
    fn start(mut command: Command, codex_home: &Path, hook_log: &Path) -> TestResult<Self> {
        let mut child = command
            .env("CODEX_HOME", codex_home)
            .env(HOOK_LOG_ENV, hook_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| test_error("Codex App Server did not provide stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| test_error("Codex App Server did not provide stdout"))?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            notifications: Vec::new(),
        })
    }

    fn initialize(&mut self) -> TestResult<()> {
        self.request(
            1,
            "initialize",
            Some(json!({
                "clientInfo": {
                    "name": "erebor-runtime-phase-0",
                    "title": "Erebor Runtime Phase 0",
                    "version": "1"
                },
                "capabilities": {"experimentalApi": true}
            })),
        )?;
        self.notify("initialized", None)
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> TestResult<()> {
        let mut notification = json!({"method": method});
        if let Some(params) = params {
            notification["params"] = params;
        }
        self.write_json(&notification)
    }

    fn request(&mut self, id: u64, method: &str, params: Option<Value>) -> TestResult<Value> {
        let mut request = json!({"id": id, "method": method});
        if let Some(params) = params {
            request["params"] = params;
        }
        self.write_json(&request)?;

        for _ in 0..128 {
            let mut line = String::new();
            if self.stdout.read_line(&mut line)? == 0 {
                return Err(test_error(format!(
                    "Codex App Server closed stdout while waiting for `{method}`"
                )));
            }
            let response: Value = serde_json::from_str(&line)?;
            if response.get("id") != Some(&json!(id)) {
                self.notifications.push(response);
                continue;
            }
            if let Some(error) = response.get("error") {
                return Err(test_error(format!(
                    "Codex App Server rejected `{method}`: {error}"
                )));
            }
            return response
                .get("result")
                .cloned()
                .ok_or_else(|| test_error(format!("Codex App Server omitted `{method}` result")));
        }

        Err(test_error(format!(
            "Codex App Server emitted too many messages while waiting for `{method}`"
        )))
    }

    fn write_json(&mut self, message: &Value) -> TestResult<()> {
        serde_json::to_writer(&mut self.stdin, message)?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }
}

impl Drop for CodexAppServer {
    fn drop(&mut self) {
        let _result = self.child.kill();
        let _result = self.child.wait();
    }
}

fn assert_projected_requirements(response: &Value) -> TestResult<()> {
    let requirements = response
        .get("requirements")
        .ok_or_else(|| test_error("configRequirements/read omitted requirements"))?;
    assert_eq!(
        requirements
            .get("allowManagedHooksOnly")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        requirements
            .get("allowRemoteControl")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        requirements
            .pointer("/featureRequirements/hooks")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        requirements
            .pointer("/hooks/managedDir")
            .and_then(Value::as_str),
        Some(MANAGED_HOOK_DIRECTORY)
    );
    for event in V1_HOOK_EVENTS {
        let hooks = requirements
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)
            .ok_or_else(|| test_error(format!("missing managed {event} hook")))?;
        assert_eq!(hooks.len(), 1, "expected one managed {event} hook group");
        let handler = hooks[0]
            .get("hooks")
            .and_then(Value::as_array)
            .and_then(|handlers| handlers.first())
            .ok_or_else(|| test_error(format!("missing managed {event} handler")))?;
        assert_eq!(handler.get("type").and_then(Value::as_str), Some("command"));
        assert_eq!(
            handler.get("command").and_then(Value::as_str),
            Some(MANAGED_HOOK_PATH)
        );
        assert_eq!(handler.get("timeoutSec").and_then(Value::as_u64), Some(10));
    }
    Ok(())
}

fn assert_projected_hooks(response: &Value) -> TestResult<()> {
    let hooks = response
        .pointer("/data/0/hooks")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("hooks/list did not return one workspace result"))?;
    assert_eq!(hooks.len(), V1_HOOK_EVENTS.len());
    for hook in hooks {
        assert_eq!(hook.get("isManaged").and_then(Value::as_bool), Some(true));
        assert_eq!(
            hook.get("command").and_then(Value::as_str),
            Some(MANAGED_HOOK_PATH)
        );
    }
    Ok(())
}

fn assert_hook_events_in_order(log_path: &Path, expected_events: &[&str]) -> TestResult<()> {
    for _ in 0..40 {
        if let Ok(source) = fs::read_to_string(log_path) {
            let observed_events = source
                .lines()
                .filter(|line| !line.is_empty())
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter_map(|payload| {
                    payload
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
                let schema_fingerprints = source
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(|line| {
                        let event =
                            CodexNativeHookEvent::parse(line.as_bytes()).map_err(test_error)?;
                        Ok((event.kind(), event.schema_sha256().to_owned()))
                    })
                    .collect::<TestResult<Vec<_>>>()?;
                eprintln!(
                    "Codex managed hook event order: {observed_events:?}; structural schema fingerprints: {schema_fingerprints:?}"
                );
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(125));
    }
    Err(test_error(format!(
        "managed hook event order did not converge to {expected_events:?}"
    )))
}

fn required_mode() -> bool {
    std::env::var(REQUIRE_PROBE_ENV).as_deref() == Ok("1")
}

fn required_environment(name: &str) -> TestResult<OsString> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| test_error(format!("{name} is required in Phase 0 required mode")))
}

fn command_output(
    command: &Path,
    args: impl IntoIterator<Item = &'static str>,
) -> TestResult<String> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        return Err(test_error(format!(
            "{} failed: status={} stderr={}",
            command.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn sha256_file(path: &Path) -> TestResult<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn fixture_directory() -> TestResult<tempfile::TempDir> {
    let parent = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .map_or_else(|| PathBuf::from("target"), |root| root.join("target"))
        });
    fs::create_dir_all(&parent)?;
    Ok(tempfile::Builder::new()
        .prefix("erebor-codex-linux-v1-")
        .tempdir_in(parent)?)
}

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
