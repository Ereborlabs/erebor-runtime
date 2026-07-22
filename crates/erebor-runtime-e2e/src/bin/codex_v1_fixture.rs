//! Deterministic Phase 4 Codex adapter fixture.
//!
//! This is intentionally not a Codex replacement.  It only exercises Erebor's
//! certified entrypoint, TTY, JSONL, managed-hook, and package-admission
//! contracts without vendor authentication or mutable user state.

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    io::{self, BufRead, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use erebor_runtime_core::AgentAdapterDescriptor;
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, CodexArtifact, CodexEntrypoint, CodexHookContract,
    CodexHookEventName, CodexHookEventSchema, CodexHookExec, CodexHookShell, CodexManagedArtifacts,
    CodexPackageDefinition, CodexSupportedPlatform, ContentDigest, InstallationRecord,
    PolicyPackageRevision, PolicySetRevision,
};
use erebor_runtime_session::{CodexHookClient, CodexHookResultOutput, CodexNativeHookEvent};
use serde_json::{json, Value};

const FIXTURE_NAME: &str = "codex-v1-fixture";
const MANAGED_HOOK_PATH: &str = "/run/erebor/codex/erebor-codex-hook";
const REQUIREMENTS_PATH: &str = "/run/erebor/codex/requirements.toml";
const SHELL_STARTUP_PATH: &str = "/run/erebor/codex/shell-startup";
const SESSION_START_EVENT: &[u8] = br#"{"hook_event_name":"SessionStart"}"#;

type FixtureResult<T> = Result<T, Box<dyn Error>>;

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => run_tty(),
        [command, rest @ ..] if command == "configure" => configure(rest),
        [command, option] if command == "app-server" && option == "--stdio" => run_app_server(),
        [command] if command == "managed-hook" => run_managed_hook(HookMode::Normal),
        [command] if command == "managed-hook-replay" => run_managed_hook(HookMode::Replay),
        [command] if command == "managed-hook-wrong-peer" => run_managed_hook(HookMode::WrongPeer),
        [command] if command == "managed-hook-wrong-session" => {
            run_managed_hook(HookMode::WrongSession)
        }
        [command] if command == "hook-client-only" => run_hook_client_only(),
        _ => Err(format!(
            "unsupported deterministic Codex fixture invocation: {}",
            arguments.join(" ")
        )
        .into()),
    }
}

fn run_tty() -> FixtureResult<()> {
    println!("fixture-tty=ready");
    println!(
        "fixture-daemon-socket={}",
        if Path::new("/run/erebor/daemon.sock").exists() {
            "present"
        } else {
            "absent"
        }
    );
    invoke_managed_hook("managed-hook")?;
    println!("fixture-hook=accepted");
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    println!("fixture-tty-input={}", line.trim_end());
    Ok(())
}

fn run_app_server() -> FixtureResult<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let request: Value = serde_json::from_str(&line)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or("fixture App Server request omitted method")?;
        if method == "fixture/malformed-output" {
            writeln!(stdout, "this is intentionally not JSON-RPC")?;
            stdout.flush()?;
            continue;
        }
        if method == "fixture/wait" {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let result = match method {
            "fixture/hook" => {
                invoke_managed_hook("managed-hook")?;
                "accepted"
            }
            "fixture/hook-replay" => {
                invoke_managed_hook("managed-hook-replay")?;
                "replay-rejected"
            }
            "fixture/hook-wrong-peer" => {
                invoke_managed_hook("managed-hook-wrong-peer")?;
                "wrong-peer-rejected"
            }
            "fixture/hook-wrong-session" => {
                invoke_managed_hook("managed-hook-wrong-session")?;
                "wrong-session-rejected"
            }
            "$/cancelRequest" => "cancelled",
            _ => "ok",
        };
        if let Some(id) = request.get("id") {
            writeln!(
                stdout,
                "{}",
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"fixture": result, "turnId": "fixture-turn"},
                }))?
            )?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum HookMode {
    Normal,
    Replay,
    WrongPeer,
    WrongSession,
}

fn run_managed_hook(mode: HookMode) -> FixtureResult<()> {
    let mut output = CodexHookResultOutput::capture()?;
    let mut input = Vec::new();
    io::stdin().take(32 * 1024).read_to_end(&mut input)?;
    let event = CodexNativeHookEvent::parse(&input)?;
    match mode {
        HookMode::Normal => submit_hook(&event, input)?,
        HookMode::Replay => {
            submit_hook(&event, input.clone())?;
            if submit_hook(&event, input).is_ok() {
                return Err("a consumed managed-hook ticket was accepted twice".into());
            }
        }
        HookMode::WrongPeer => {
            let status = Command::new(env::current_exe()?)
                .arg("hook-client-only")
                .status()?;
            if status.success() {
                return Err("a managed-hook ticket accepted a different process peer".into());
            }
        }
        HookMode::WrongSession => {
            let status = Command::new(env::current_exe()?)
                .arg("hook-client-only")
                .env("EREBOR_SESSION_ID", "fixture-wrong-session")
                .status()?;
            if status.success() {
                return Err("a managed-hook ticket accepted a different session".into());
            }
        }
    }
    output.write_result(br#"{"continue":true}"#)?;
    Ok(())
}

fn run_hook_client_only() -> FixtureResult<()> {
    let event = CodexNativeHookEvent::parse(SESSION_START_EVENT)?;
    submit_hook(&event, SESSION_START_EVENT.to_vec())
}

fn submit_hook(event: &CodexNativeHookEvent, native_event_json: Vec<u8>) -> FixtureResult<()> {
    CodexHookClient::default().submit(erebor_runtime_ipc::v1::HookEvent {
        event: event.kind() as i32,
        schema_sha256: event.schema_sha256().to_owned(),
        native_event_json,
    })?;
    Ok(())
}

fn invoke_managed_hook(mode: &str) -> FixtureResult<()> {
    let mut child = Command::new(MANAGED_HOOK_PATH)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or("managed-hook fixture did not expose stdin")?
        .write_all(SESSION_START_EVENT)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "managed hook `{mode}` failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(())
}

fn configure(arguments: &[String]) -> FixtureResult<()> {
    let options = ConfigureOptions::parse(arguments)?;
    fs::create_dir_all(&options.trust_root)?;
    let fixture = options.trust_root.join(FIXTURE_NAME);
    fs::copy(env::current_exe()?, &fixture)?;
    fs::write(
        options.trust_root.join("requirements.toml"),
        fixture_requirements(),
    )?;
    fs::write(options.trust_root.join("shell-startup"), "#!/bin/sh\n")?;
    for path in [
        &fixture,
        &options.trust_root.join("requirements.toml"),
        &options.trust_root.join("shell-startup"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }

    let definition = package_definition(&options.trust_root, &fixture)?;
    let package = package_manifest(&definition)?;
    let root_policy = root_policy()?;
    let root_policy_digest = root_policy.canonical_digest()?;
    let root_admissions = options
        .owner_uids
        .iter()
        .map(|owner_uid| root_admission(*owner_uid, &root_policy))
        .collect::<FixtureResult<Vec<_>>>()?;
    let package_digest = package.canonical_digest()?;
    let configuration = json!({
        "socket_group_gid": options.socket_group_gid,
        "root_curated_admissions": root_admissions,
        "root_curated_codex_packages": [{
            "package": package,
            "definition": definition,
            "trust_root": options.trust_root,
        }],
    });
    if let Some(parent) = options.config.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.config, serde_json::to_vec_pretty(&configuration)?)?;
    fs::set_permissions(&options.config, fs::Permissions::from_mode(0o640))?;
    println!(
        "package_reference={FIXTURE_NAME}@sha256:{}",
        package_digest.as_str()
    );
    println!("root_policy_digest={}", root_policy_digest.as_str());
    Ok(())
}

struct ConfigureOptions {
    config: PathBuf,
    trust_root: PathBuf,
    socket_group_gid: u32,
    owner_uids: Vec<u32>,
}

impl ConfigureOptions {
    fn parse(arguments: &[String]) -> FixtureResult<Self> {
        let mut config = None;
        let mut trust_root = None;
        let mut socket_group_gid = None;
        let mut owner_uids = Vec::new();
        let mut index = 0;
        while let Some(option) = arguments.get(index) {
            let value = arguments
                .get(index.saturating_add(1))
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option.as_str() {
                "--config" => config = Some(PathBuf::from(value)),
                "--trust-root" => trust_root = Some(PathBuf::from(value)),
                "--socket-group-gid" => socket_group_gid = Some(value.parse()?),
                "--owner-uid" => owner_uids.push(value.parse()?),
                _ => return Err(format!("unknown configure option `{option}`").into()),
            }
            index += 2;
        }
        Ok(Self {
            config: config.ok_or("--config is required")?,
            trust_root: trust_root.ok_or("--trust-root is required")?,
            socket_group_gid: socket_group_gid.ok_or("--socket-group-gid is required")?,
            owner_uids,
        })
    }
}

fn package_definition(trust_root: &Path, fixture: &Path) -> FixtureResult<CodexPackageDefinition> {
    let requirements = trust_root.join("requirements.toml");
    let shell_startup = trust_root.join("shell-startup");
    let fixture_digest = digest_file(fixture)?;
    let managed_artifacts = CodexManagedArtifacts::new(
        artifact(&requirements)?,
        PathBuf::from(REQUIREMENTS_PATH),
        CodexArtifact::new(fixture.to_path_buf(), fixture_digest.clone())?,
        PathBuf::from(MANAGED_HOOK_PATH),
        artifact(&shell_startup)?,
        PathBuf::from(SHELL_STARTUP_PATH),
        None,
        None,
    )?;
    let event_schemas = [
        (CodexHookEventName::SessionStart, "SessionStart"),
        (CodexHookEventName::UserPromptSubmit, "UserPromptSubmit"),
        (CodexHookEventName::PreToolUse, "PreToolUse"),
        (CodexHookEventName::PermissionRequest, "PermissionRequest"),
        (CodexHookEventName::PostToolUse, "PostToolUse"),
        (CodexHookEventName::SubagentStart, "SubagentStart"),
        (CodexHookEventName::SubagentStop, "SubagentStop"),
        (CodexHookEventName::Stop, "Stop"),
    ]
    .into_iter()
    .map(|(event, name)| {
        let native = format!(r#"{{"hook_event_name":"{name}"}}"#);
        let digest = CodexNativeHookEvent::parse(native.as_bytes())?
            .schema_sha256()
            .to_owned();
        Ok(CodexHookEventSchema::new(
            event,
            ContentDigest::new(digest)?,
        )?)
    })
    .collect::<FixtureResult<Vec<_>>>()?;
    CodexPackageDefinition::new(
        FIXTURE_NAME,
        fixture_digest,
        CodexSupportedPlatform::LinuxX86_64,
        vec![
            CodexEntrypoint::new("codex", Vec::new(), false)?,
            CodexEntrypoint::new(
                "codex-app-server",
                vec![String::from("app-server"), String::from("--stdio")],
                true,
            )?,
        ],
        managed_artifacts,
        CodexHookContract::new(
            CodexHookShell::Direct,
            vec![
                CodexHookExec::InstalledExecutable,
                CodexHookExec::ManagedHook,
            ],
            event_schemas,
            None,
        )?,
    )
    .map_err(Into::into)
}

fn package_manifest(definition: &CodexPackageDefinition) -> FixtureResult<AgentPackageManifest> {
    let descriptor = AgentAdapterDescriptor::codex_v1()?;
    let requirements = definition
        .managed_artifacts()
        .requirements_source()
        .sha256()
        .clone();
    let hook = definition
        .managed_artifacts()
        .managed_hook_source()
        .sha256()
        .clone();
    let startup = definition
        .managed_artifacts()
        .shell_startup_source()
        .sha256()
        .clone();
    AgentPackageManifest::with_adapter_and_config(
        FIXTURE_NAME,
        descriptor.id(),
        env!("CARGO_PKG_VERSION"),
        vec![String::from("codex"), String::from("codex-app-server")],
        ContentDigest::new(descriptor.sha256()?)?,
        definition.canonical_digest()?,
        vec![requirements, hook, startup],
    )
    .map_err(Into::into)
}

fn root_admission(owner_uid: u32, policy: &PolicyPackageRevision) -> FixtureResult<Value> {
    let descriptor = AgentAdapterDescriptor::generic_process_v1()?;
    let package = AgentPackageManifest::with_adapter_and_config(
        "fixture-policy-root",
        descriptor.id(),
        env!("CARGO_PKG_VERSION"),
        vec![String::from("<argv>")],
        ContentDigest::new(descriptor.sha256()?)?,
        ContentDigest::from_canonical_bytes(b"fixture-policy-root-config"),
        Vec::new(),
    )?;
    let policy_digest = policy.canonical_digest()?;
    let installation = InstallationRecord::new(owner_uid, package.canonical_digest()?, 0);
    let policy_set = PolicySetRevision::new(policy_digest, Vec::new(), None)?;
    Ok(json!({
        "package": package,
        "installation": installation,
        "policy_set": policy_set,
        "policies": [policy],
    }))
}

fn root_policy() -> FixtureResult<PolicyPackageRevision> {
    PolicyPackageRevision::new(
        "fixture-host-minimum",
        b"name = \"fixture-host-minimum\"\n".to_vec(),
        BTreeMap::from([(
            String::from("terminal.json"),
            br#"{"rules":[{"id":"fixture-allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
        )]),
        BTreeMap::new(),
        BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
        b"# Deterministic Phase 4 fixture host minimum\n".to_vec(),
    )
    .map_err(Into::into)
}

fn artifact(path: &Path) -> FixtureResult<CodexArtifact> {
    Ok(CodexArtifact::new(path.to_path_buf(), digest_file(path)?)?)
}

fn digest_file(path: &Path) -> FixtureResult<ContentDigest> {
    Ok(ContentDigest::from_canonical_bytes(&fs::read(path)?))
}

fn fixture_requirements() -> &'static str {
    "allow_managed_hooks_only = true\nallow_remote_control = false\n"
}
