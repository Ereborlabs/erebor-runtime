//! Deterministic Codex adapter fixture.
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
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
};

use erebor_runtime_core::AgentAdapterDescriptor;
use erebor_runtime_ipc::{
    v1::{
        Envelope, EnvelopeServiceFamily, HookHello, HookHelloAck, KIND_HOOK_HELLO,
        KIND_HOOK_HELLO_ACK, PROTOCOL_VERSION,
    },
    SyncFrameCodec,
};
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, CodexArtifact, CodexEntrypoint, CodexHookContract,
    CodexHookEventName, CodexHookEventSchema, CodexHookExec, CodexHookShell, CodexManagedArtifacts,
    CodexPackageDefinition, CodexSupportedPlatform, ContentDigest, InstallationRecord,
    PolicyPackageRevision, PolicySetRevision,
};
use erebor_runtime_session::{
    CodexHookClient, CodexHookResultOutput, CodexHookService, CodexNativeHookEvent,
};
use rustix::termios::tcgetwinsize;
use serde_json::{json, Value};
use tokio::signal::unix::{signal, SignalKind};

const FIXTURE_NAME: &str = "codex-v1-fixture";
const MANAGED_HOOK_PATH: &str = "/run/erebor/codex/erebor-codex-hook";
const REQUIREMENTS_PATH: &str = "/run/erebor/codex/requirements.toml";
const SHELL_STARTUP_PATH: &str = "/run/erebor/codex/shell-startup";
const SESSION_START_EVENT: &[u8] = br#"{"hook_event_name":"SessionStart"}"#;
const TERMINAL_TURN_EVENT: &[u8] = br#"{"hook_event_name":"UserPromptSubmit","session_id":"fixture-thread","turn_id":"fixture-turn"}"#;
// The managed package pins one structural schema per native hook kind. Keep
// every fixture PreToolUse event structurally identical while its tool name
// and values select the bounded command or logical-fork capability.
const DELEGATION_EVENT: &[u8] = br#"{"hook_event_name":"PreToolUse","session_id":"fixture-thread","turn_id":"fixture-turn","tool_use_id":"fixture-delegation-1","tool_name":"erebor_delegate","tool_input":{"command":"","erebor_operation_key":"","child_thread_id":"fixture-child-thread","child_turn_id":"fixture-child-turn","frozen_context_mode":"all","last_turns":0,"erebor_context_action":"","target_thread_id":"","target_turn_id":"","follow_up_text":""}}"#;
const DELIVERY_EVENT: &[u8] = br#"{"hook_event_name":"PostToolUse","session_id":"fixture-thread","turn_id":"fixture-turn","tool_use_id":"fixture-delivery-1","tool_response":{"status":"ok"},"erebor_delivery":{"emit":true,"sequence":1,"kind":"result","mode":"queue","selected_text":"fixture result","operation_key":""}}"#;
const HOOK_MODE_ENV: &str = "EREBOR_FIXTURE_HOOK_MODE";
const CROSS_SESSION_ENV: &str = "EREBOR_FIXTURE_CROSS_SESSION_ID";
const MAX_FIXTURE_DELEGATION_LAST_TURNS: u64 = 8;

type FixtureResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct FixtureTurn {
    thread_id: String,
    turn_id: String,
}

impl FixtureTurn {
    fn root() -> Self {
        Self {
            thread_id: String::from("fixture-thread"),
            turn_id: String::from("fixture-turn"),
        }
    }

    fn terminal_event(&self) -> FixtureResult<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": self.thread_id,
            "turn_id": self.turn_id,
        }))?)
    }
}

/// The fixture's deterministic collaboration scheduler. This is deliberately
/// local fixture state: switching focus selects an already daemon-admitted
/// native thread/turn binding; it neither asks the daemon to create a scope
/// nor turns a thread into another Erebor session.
struct FixtureTurns {
    active: FixtureTurn,
    known: BTreeMap<(String, String), FixtureTurn>,
    interrupted: BTreeMap<(String, String), ()>,
}

impl FixtureTurns {
    fn new() -> Self {
        let root = FixtureTurn::root();
        let mut known = BTreeMap::new();
        known.insert((root.thread_id.clone(), root.turn_id.clone()), root.clone());
        Self {
            active: root,
            known,
            interrupted: BTreeMap::new(),
        }
    }

    fn active(&self) -> &FixtureTurn {
        &self.active
    }

    fn delegate(&mut self, request: &Value) -> FixtureResult<()> {
        let child = delegated_turn(request)?;
        let key = (child.thread_id.clone(), child.turn_id.clone());
        if self.known.contains_key(&key) {
            return Err("fixture/delegate cannot reuse a native child thread/turn".into());
        }
        self.known.insert(key, child.clone());
        self.active = child;
        Ok(())
    }

    fn switch(&mut self, request: &Value) -> FixtureResult<()> {
        let params = fixture_params(request, "fixture/switch")?;
        let thread_id = params
            .get("thread_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("fixture/switch requires a non-empty thread_id")?;
        let turn_id = params
            .get("turn_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("fixture/switch requires a non-empty turn_id")?;
        self.activate((thread_id.to_owned(), turn_id.to_owned()))
    }

    fn activate(&mut self, key: (String, String)) -> FixtureResult<()> {
        if self.interrupted.contains_key(&key) {
            return Err("fixture/switch cannot enter an interrupted thread/turn".into());
        }
        self.active = self
            .known
            .get(&key)
            .cloned()
            .ok_or("fixture/switch may select only a previously delegated thread/turn")?;
        Ok(())
    }

    fn follow_up(&mut self, request: &Value) -> FixtureResult<()> {
        self.activate(control_target(request)?)
    }

    fn interrupt(&mut self, request: &Value) -> FixtureResult<FixtureTurn> {
        let key = control_target(request)?;
        let target = self
            .known
            .get(&key)
            .cloned()
            .ok_or("fixture/control interruption target is not a known thread/turn")?;
        self.interrupted.insert(key, ());
        Ok(target)
    }
}

#[derive(Default)]
struct FixtureToolUseIds {
    next_command: u64,
}

/// The fixture records a real terminal-window signal separately from the
/// terminal-size read. The privileged probe needs both facts: the PTY geometry
/// changed and the foreground workload received Linux's normal notification.
struct TerminalWindowSignals {
    received: mpsc::Receiver<()>,
}

impl TerminalWindowSignals {
    fn start() -> FixtureResult<Self> {
        let (received_sender, received) = mpsc::channel();
        let (ready_sender, ready) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _result = ready_sender.send(Err(error.to_string()));
                    return;
                }
            };
            let signals = {
                let _entered = runtime.enter();
                signal(SignalKind::window_change())
            };
            let mut signals = match signals {
                Ok(signals) => signals,
                Err(error) => {
                    let _result = ready_sender.send(Err(error.to_string()));
                    return;
                }
            };
            if ready_sender.send(Ok(())).is_err() {
                return;
            }
            runtime.block_on(async move {
                while signals.recv().await.is_some() {
                    if received_sender.send(()).is_err() {
                        break;
                    }
                }
            });
        });
        match ready
            .recv()
            .map_err(|_error| io::Error::other("fixture SIGWINCH monitor did not initialize"))?
        {
            Ok(()) => Ok(Self { received }),
            Err(reason) => Err(io::Error::other(reason).into()),
        }
    }

    fn take_received(&self) -> bool {
        let mut received = false;
        while self.received.try_recv().is_ok() {
            received = true;
        }
        received
    }
}

#[derive(Clone, Copy)]
enum FixtureOutput {
    Tty,
    AppServer,
}

impl FixtureOutput {
    fn line(self, line: &str) -> FixtureResult<()> {
        match self {
            Self::Tty => println!("{line}"),
            Self::AppServer => {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&json!({
                        "jsonrpc": "2.0",
                        "method": "fixture/event",
                        "params": {"line": line},
                    }))?
                )?;
                stdout.flush()?;
            }
        }
        Ok(())
    }
}

impl FixtureToolUseIds {
    fn command_request(&mut self, request: &Value) -> FixtureResult<Value> {
        let mut request = request.clone();
        let params = request
            .pointer_mut("/params")
            .and_then(Value::as_object_mut)
            .ok_or("fixture/command params must be an object")?;
        if params.contains_key("tool_use_id") {
            return Ok(request);
        }
        self.next_command = self
            .next_command
            .checked_add(1)
            .ok_or("fixture command tool use ID sequence overflowed")?;
        params.insert(
            String::from("tool_use_id"),
            Value::String(format!("fixture-command-{}", self.next_command)),
        );
        Ok(request)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] if env::var_os(HOOK_MODE_ENV).is_some() => {
            run_managed_hook(HookMode::from_environment()?)
        }
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
    let mut turns = FixtureTurns::new();
    let mut tool_uses = FixtureToolUseIds::default();
    let window_signals = TerminalWindowSignals::start()?;
    println!("fixture-tty=ready");
    report_terminal_size()?;
    println!(
        "fixture-daemon-socket={}",
        if Path::new("/run/erebor/daemon.sock").exists() {
            "present"
        } else {
            "absent"
        }
    );
    let hook_result = invoke_managed_hook(HookMode::Normal)?;
    println!("fixture-hook=accepted");
    if let Some(context) = hook_result
        .pointer("/hookSpecificOutput/additionalContext")
        .and_then(Value::as_str)
    {
        println!("fixture-frozen-context={context}");
    }
    for line in io::stdin().lock().lines() {
        let line = line?;
        println!("fixture-tty-input={line}");
        if let Some(params) = line.strip_prefix("fixture/deliver ") {
            let event = delivery_event(
                &json!({"params": serde_json::from_str::<Value>(params)?}),
                turns.active(),
            )?;
            invoke_managed_hook_event(HookMode::Normal, &event)?;
            println!("fixture-delivery=accepted");
        }
        if let Some(params) = line.strip_prefix("fixture/delegate ") {
            let request = json!({"params": serde_json::from_str::<Value>(params)?});
            let event = delegation_event(&request, turns.active())?;
            invoke_managed_hook_event(HookMode::Normal, &event)?;
            turns.delegate(&request)?;
            println!("fixture-delegation=accepted");
        }
        if let Some(params) = line.strip_prefix("fixture/switch ") {
            let request = json!({"params": serde_json::from_str::<Value>(params)?});
            turns.switch(&request)?;
            println!("fixture-switch=accepted");
        }
        if let Some(params) = line.strip_prefix("fixture/control ") {
            let request = json!({"params": serde_json::from_str::<Value>(params)?});
            let result = invoke_fixture_control(&request, turns.active())?;
            apply_fixture_control(&mut turns, &request, &result)?;
            println!("fixture-control={}", control_action(&request)?);
        }
        if let Some(params) = line.strip_prefix("fixture/command ") {
            let request = json!({"params": serde_json::from_str::<Value>(params)?});
            let output = run_guarded_command(&request, turns.active(), &mut tool_uses)?;
            println!("fixture-command-output={output}");
            println!("fixture-command=completed");
        }
        if line == "fixture/start-q" {
            start_long_operation(turns.active(), FixtureOutput::Tty)?;
        }
        if line == "fixture/turn" {
            invoke_managed_hook_event(HookMode::Normal, &turns.active().terminal_event()?)?;
            println!("fixture-turn=accepted");
        }
        if line == "terminal-size" {
            report_terminal_size()?;
            println!(
                "fixture-tty-sigwinch={}",
                if window_signals.take_received() {
                    "received"
                } else {
                    "not-observed"
                }
            );
        }
        if line == "exit" {
            break;
        }
    }
    Ok(())
}

fn report_terminal_size() -> FixtureResult<()> {
    let terminal = tcgetwinsize(io::stdin())?;
    println!(
        "fixture-tty-size=rows={} columns={}",
        terminal.ws_row, terminal.ws_col
    );
    Ok(())
}

fn run_app_server() -> FixtureResult<()> {
    let stdin = io::stdin();
    let mut tool_uses = FixtureToolUseIds::default();
    let mut turns = FixtureTurns::new();
    for line in stdin.lock().lines() {
        let line = line?;
        let request: Value = serde_json::from_str(&line)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or("fixture App Server request omitted method")?;
        if method == "fixture/malformed-output" {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "this is intentionally not JSON-RPC")?;
            stdout.flush()?;
            continue;
        }
        if method == "fixture/wait" {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let mut result = match method {
            "fixture/hook" => {
                invoke_managed_hook(HookMode::Normal)?;
                json!({"fixture": "accepted"})
            }
            "fixture/hook-replay" => {
                invoke_managed_hook(HookMode::Replay)?;
                json!({"fixture": "replay-rejected"})
            }
            "fixture/hook-wrong-peer" => {
                invoke_managed_hook(HookMode::WrongPeer)?;
                json!({"fixture": "wrong-peer-rejected"})
            }
            "fixture/hook-wrong-session" => {
                invoke_managed_hook(HookMode::WrongSession)?;
                json!({"fixture": "wrong-session-rejected"})
            }
            "fixture/hook-cross-session" => {
                let target_session_id = fixture_params(&request, "fixture/hook-cross-session")?
                    .get("target_session_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 128)
                    .ok_or("fixture/hook-cross-session requires a bounded target_session_id")?;
                invoke_managed_hook_cross_session(target_session_id)?;
                json!({"fixture": "cross-session-rejected"})
            }
            "fixture/delegate" => {
                let event = delegation_event(&request, turns.active())?;
                invoke_managed_hook_event(HookMode::Normal, &event)?;
                turns.delegate(&request)?;
                json!({"fixture": "delegated"})
            }
            "fixture/deliver" => {
                let event = delivery_event(&request, turns.active())?;
                invoke_managed_hook_event(HookMode::Normal, &event)?;
                json!({"fixture": "delivered"})
            }
            "fixture/switch" => {
                turns.switch(&request)?;
                json!({"fixture": "switched"})
            }
            "fixture/control" => {
                let result = invoke_fixture_control(&request, turns.active())?;
                apply_fixture_control(&mut turns, &request, &result)?;
                json!({"fixture": "control", "control": result})
            }
            "fixture/command" => {
                let output = run_guarded_command(&request, turns.active(), &mut tool_uses)?;
                json!({"fixture": "command-completed", "output": output})
            }
            "fixture/start-q" => {
                start_long_operation(turns.active(), FixtureOutput::AppServer)?;
                json!({"fixture": "operation-started"})
            }
            "$/cancelRequest" => json!({"fixture": "cancelled"}),
            _ => json!({"fixture": "ok"}),
        };
        if let Value::Object(object) = &mut result {
            object.insert(
                String::from("turnId"),
                Value::String(turns.active().turn_id.clone()),
            );
        }
        if let Some(id) = request.get("id") {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(
                stdout,
                "{}",
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                }))?
            )?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn run_guarded_command(
    request: &Value,
    turn: &FixtureTurn,
    tool_uses: &mut FixtureToolUseIds,
) -> FixtureResult<String> {
    let request = tool_uses.command_request(request)?;
    let event = command_event(&request, turn)?;
    let params = fixture_params(&request, "fixture/command")?;
    let command = params
        .get("command")
        .and_then(Value::as_str)
        .ok_or("fixture/command requires a command")?;
    let tool_use_id = params
        .get("tool_use_id")
        .and_then(Value::as_str)
        .unwrap_or("fixture-command-1");
    invoke_managed_hook_event(HookMode::Normal, &event)?;
    let output = Command::new("/bin/sh").args(["-c", command]).output()?;
    if !output.status.success() {
        return Err(format!("fixture command failed with {}", output.status).into());
    }
    let rendered = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    invoke_managed_hook_event(HookMode::Normal, &post_tool_event(tool_use_id, None, turn)?)?;
    Ok(rendered)
}

fn start_long_operation(turn: &FixtureTurn, output: FixtureOutput) -> FixtureResult<()> {
    const OPERATION_KEY: &str = "fixture-q";
    const TOOL_USE_ID: &str = "fixture-q-command-1";
    const COMMAND: &str = "printf 'q-partial\\n'; sleep 3; printf 'q-final\\n'";

    let request = json!({
        "params": {
            "command": COMMAND,
            "tool_use_id": TOOL_USE_ID,
            "operation_key": OPERATION_KEY,
        },
    });
    invoke_managed_hook_event(HookMode::Normal, &command_event(&request, turn)?)?;
    let mut child = Command::new("/bin/sh")
        .args(["-c", COMMAND])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or("fixture long operation did not expose stdout")?;
    let turn = turn.clone();
    output.line("fixture-operation=q-started")?;
    std::thread::spawn(move || {
        let result = (|| -> FixtureResult<()> {
            for (index, line) in io::BufReader::new(stdout).lines().enumerate() {
                let text = line?;
                let sequence = u64::try_from(index.saturating_add(1))?;
                let event = delivery_event(
                    &json!({
                        "params": {
                            "sequence": sequence,
                            "kind": "result",
                            "mode": "queue",
                            "selected_text": text,
                            "operation_key": OPERATION_KEY,
                            "tool_use_id": TOOL_USE_ID,
                        },
                    }),
                    &turn,
                )?;
                invoke_managed_hook_event(HookMode::Normal, &event)?;
                output.line(&format!("fixture-operation=q-delivery-{sequence}"))?;
            }
            if !child.wait()?.success() {
                return Err("fixture long operation failed".into());
            }
            output.line("fixture-operation=q-complete")?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("fixture long operation failed: {error}");
        }
    });
    Ok(())
}

#[derive(Clone, Copy)]
enum HookMode {
    Normal,
    Replay,
    WrongPeer,
    WrongSession,
    CrossSession,
}

impl HookMode {
    fn from_environment() -> FixtureResult<Self> {
        match env::var(HOOK_MODE_ENV).as_deref() {
            Ok("normal") => Ok(Self::Normal),
            Ok("replay") => Ok(Self::Replay),
            Ok("wrong-peer") => Ok(Self::WrongPeer),
            Ok("wrong-session") => Ok(Self::WrongSession),
            Ok("cross-session") => Ok(Self::CrossSession),
            Ok(value) => Err(format!("unsupported fixture hook mode `{value}`").into()),
            Err(_error) => Err("managed hook invocation omitted its fixture mode".into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Replay => "replay",
            Self::WrongPeer => "wrong-peer",
            Self::WrongSession => "wrong-session",
            Self::CrossSession => "cross-session",
        }
    }
}

fn run_managed_hook(mode: HookMode) -> FixtureResult<()> {
    let mut output = CodexHookResultOutput::capture()?;
    let mut input = Vec::new();
    io::stdin().take(32 * 1024).read_to_end(&mut input)?;
    let event = CodexNativeHookEvent::parse(&input)?;
    let result = match mode {
        HookMode::Normal => submit_hook(&event, input)?,
        HookMode::Replay => {
            let first = submit_hook(&event, input.clone())?;
            if submit_hook(&event, input).is_ok() {
                return Err("a consumed managed-hook ticket was accepted twice".into());
            }
            first
        }
        HookMode::WrongPeer => {
            let status = Command::new(env::current_exe()?)
                .arg("hook-client-only")
                .status()?;
            if status.success() {
                return Err("a managed-hook ticket accepted a different process peer".into());
            }
            submit_hook(&event, input)?
        }
        HookMode::WrongSession => {
            let status = Command::new(env::current_exe()?)
                .arg("hook-client-only")
                .env("EREBOR_SESSION_ID", "fixture-wrong-session")
                .status()?;
            if status.success() {
                return Err("a managed-hook ticket accepted a different session".into());
            }
            submit_hook(&event, input)?
        }
        HookMode::CrossSession => {
            let target_session_id = env::var(CROSS_SESSION_ENV)
                .map_err(|_error| "cross-session hook omitted its target session")?;
            if hook_hello_is_accepted(&target_session_id)? {
                return Err(
                    "a managed hook's guard-issued authority routed to another same-UID session"
                        .into(),
                );
            }
            // The protocol deliberately never sends a ticket value: the
            // listener derives the guard-issued authority from this process's
            // kernel peer. A cross-session hello must not consume it. This
            // succeeding submission proves the authority remained valid only
            // for this hook's own registration.
            submit_hook(&event, input)?
        }
    };
    output.write_result(&result.result_json)?;
    Ok(())
}

fn run_hook_client_only() -> FixtureResult<()> {
    let event = CodexNativeHookEvent::parse(SESSION_START_EVENT)?;
    submit_hook(&event, SESSION_START_EVENT.to_vec()).map(|_result| ())
}

fn submit_hook(
    event: &CodexNativeHookEvent,
    native_event_json: Vec<u8>,
) -> FixtureResult<erebor_runtime_ipc::v1::HookResult> {
    Ok(
        CodexHookClient::default().submit(erebor_runtime_ipc::v1::HookEvent {
            event: event.kind() as i32,
            schema_sha256: event.schema_sha256().to_owned(),
            native_event_json,
        })?,
    )
}

fn invoke_managed_hook(mode: HookMode) -> FixtureResult<Value> {
    invoke_managed_hook_event(mode, SESSION_START_EVENT)
}

fn invoke_managed_hook_event(mode: HookMode, event: &[u8]) -> FixtureResult<Value> {
    invoke_managed_hook_with_environment(mode, event, None)
}

fn invoke_managed_hook_cross_session(target_session_id: &str) -> FixtureResult<Value> {
    invoke_managed_hook_with_environment(
        HookMode::CrossSession,
        SESSION_START_EVENT,
        Some((CROSS_SESSION_ENV, target_session_id)),
    )
}

fn invoke_managed_hook_with_environment(
    mode: HookMode,
    event: &[u8],
    environment: Option<(&str, &str)>,
) -> FixtureResult<Value> {
    let mut command = Command::new(MANAGED_HOOK_PATH);
    command
        .env(HOOK_MODE_ENV, mode.name())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("starting managed hook `{}`: {error}", mode.name()))?;
    child
        .stdin
        .as_mut()
        .ok_or("managed-hook fixture did not expose stdin")?
        .write_all(event)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "managed hook `{}` failed: stdout={} stderr={}",
            mode.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn hook_hello_is_accepted(session_id: &str) -> FixtureResult<bool> {
    let mut stream = UnixStream::connect(CodexHookService::session_endpoint())?;
    let hello = HookHello {
        protocol_version: PROTOCOL_VERSION,
        // The real managed-hook protocol intentionally carries no ticket
        // string. The adapter receives the ticket-derived authority from the
        // guarded process's kernel peer instead.
        ticket_id: String::new(),
        session_id: session_id.to_owned(),
    };
    let request = Envelope::wrap_message(1, 0, KIND_HOOK_HELLO, &hello)?;
    SyncFrameCodec::write_frame(&mut stream, &request.into_frame()?)?;
    let frame = SyncFrameCodec::read_frame(&mut stream)?;
    let response: Envelope = frame.decode_payload()?;
    response.validate_headers(EnvelopeServiceFamily::Hook)?;
    let acknowledgement: HookHelloAck = response.decode_typed_payload(KIND_HOOK_HELLO_ACK)?;
    Ok(acknowledgement.accepted)
}

fn delegation_event(request: &Value, turn: &FixtureTurn) -> FixtureResult<Vec<u8>> {
    let params = match request.get("params") {
        None | Some(Value::Null) => None,
        Some(Value::Object(params)) => Some(params),
        Some(_) => return Err("fixture/delegate params must be an object".into()),
    };
    let mode = params
        .and_then(|params| params.get("frozen_context_mode"))
        .and_then(Value::as_str)
        .unwrap_or("all");
    let last_turns = params
        .and_then(|params| params.get("last_turns"))
        .map_or(Ok(0), |value| {
            value
                .as_u64()
                .ok_or("fixture/delegate last_turns must be an unsigned integer")
        })?;
    let valid = match mode {
        "none" | "all" => last_turns == 0,
        "last_turns" => (1..=MAX_FIXTURE_DELEGATION_LAST_TURNS).contains(&last_turns),
        _ => false,
    };
    if !valid {
        return Err(
            "fixture/delegate must request none/all with zero turns or bounded last_turns".into(),
        );
    }
    let tool_use_id = params.and_then(|params| params.get("tool_use_id")).map_or(
        Ok("fixture-delegation-1"),
        |value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or("fixture/delegate tool_use_id must be a bounded non-empty string")
        },
    )?;
    let child_thread_id = params
        .and_then(|params| params.get("child_thread_id"))
        .map_or(Ok("fixture-child-thread"), |value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
                .ok_or("fixture/delegate child_thread_id must be a bounded identifier")
        })?;
    let child_turn_id = params
        .and_then(|params| params.get("child_turn_id"))
        .map_or(Ok("fixture-child-turn"), |value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
                .ok_or("fixture/delegate child_turn_id must be a bounded identifier")
        })?;
    Ok(serde_json::to_vec(&json!({
        "hook_event_name": "PreToolUse",
        "session_id": turn.thread_id,
        "turn_id": turn.turn_id,
        "tool_use_id": tool_use_id,
        "tool_name": "erebor_delegate",
        "tool_input": {
            "command": "",
            "erebor_operation_key": "",
            "child_thread_id": child_thread_id,
            "child_turn_id": child_turn_id,
            "frozen_context_mode": mode,
            "last_turns": last_turns,
            "erebor_context_action": "",
            "target_thread_id": "",
            "target_turn_id": "",
            "follow_up_text": "",
        },
    }))?)
}

fn invoke_fixture_control(request: &Value, turn: &FixtureTurn) -> FixtureResult<Value> {
    let action = control_action(request)?;
    let result = invoke_managed_hook_event(HookMode::Normal, &control_event(request, turn)?)?;
    if result
        .pointer("/erebor_context_control/action")
        .and_then(Value::as_str)
        != Some(action)
    {
        return Err("managed hook did not return the authorized context control action".into());
    }
    Ok(result)
}

fn apply_fixture_control(
    turns: &mut FixtureTurns,
    request: &Value,
    result: &Value,
) -> FixtureResult<()> {
    let action = control_action(request)?;
    if result
        .pointer("/erebor_context_control/action")
        .and_then(Value::as_str)
        != Some(action)
    {
        return Err("fixture control result action does not match its request".into());
    }
    match action {
        "list_agents" => {
            let agents = result
                .pointer("/erebor_context_control/agents")
                .and_then(Value::as_array)
                .ok_or("fixture list_agents result omitted its authorized agent list")?;
            if agents.iter().any(|agent| {
                agent.get("thread_id").and_then(Value::as_str).is_none()
                    || agent.get("turn_id").and_then(Value::as_str).is_none()
            }) {
                return Err("fixture list_agents result contains an invalid agent identity".into());
            }
            Ok(())
        }
        "follow_up" => turns.follow_up(request),
        "interrupt" => {
            let target = turns.interrupt(request)?;
            let cancellation = delivery_event(
                &json!({
                    "params": {
                        "sequence": 1,
                        "kind": "cancelled",
                        "mode": "queue",
                        "selected_text": "interrupted by parent context control",
                    },
                }),
                &target,
            )?;
            invoke_managed_hook_event(HookMode::Normal, &cancellation)?;
            Ok(())
        }
        _ => Err("fixture control action is not supported".into()),
    }
}

fn control_action(request: &Value) -> FixtureResult<&str> {
    fixture_params(request, "fixture/control")?
        .get("action")
        .and_then(Value::as_str)
        .filter(|action| matches!(*action, "list_agents" | "follow_up" | "interrupt"))
        .ok_or("fixture/control action must be list_agents, follow_up, or interrupt".into())
}

fn control_target(request: &Value) -> FixtureResult<(String, String)> {
    let params = fixture_params(request, "fixture/control")?;
    let thread_id = params
        .get("target_thread_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or("fixture/control target_thread_id must be a bounded identifier")?;
    let turn_id = params
        .get("target_turn_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or("fixture/control target_turn_id must be a bounded identifier")?;
    Ok((thread_id.to_owned(), turn_id.to_owned()))
}

fn control_event(request: &Value, turn: &FixtureTurn) -> FixtureResult<Vec<u8>> {
    let params = fixture_params(request, "fixture/control")?;
    let action = control_action(request)?;
    let (target_thread_id, target_turn_id, follow_up_text) = match action {
        "list_agents" => (String::new(), String::new(), String::new()),
        "follow_up" => {
            let (thread_id, turn_id) = control_target(request)?;
            let text = params
                .get("follow_up_text")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 4 * 1024)
                .ok_or("fixture/control follow_up_text must be bounded and non-empty")?;
            (thread_id, turn_id, text.to_owned())
        }
        "interrupt" => {
            let (thread_id, turn_id) = control_target(request)?;
            (thread_id, turn_id, String::new())
        }
        _ => return Err("fixture/control action is not supported".into()),
    };
    let tool_use_id = params
        .get("tool_use_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("fixture-context-control-1");
    Ok(serde_json::to_vec(&json!({
        "hook_event_name": "PreToolUse",
        "session_id": turn.thread_id,
        "turn_id": turn.turn_id,
        "tool_use_id": tool_use_id,
        "tool_name": "erebor_context_control",
        "tool_input": {
            "command": "",
            "erebor_operation_key": "",
            "child_thread_id": "",
            "child_turn_id": "",
            "frozen_context_mode": "none",
            "last_turns": 0,
            "erebor_context_action": action,
            "target_thread_id": target_thread_id,
            "target_turn_id": target_turn_id,
            "follow_up_text": follow_up_text,
        },
    }))?)
}

fn delegated_turn(request: &Value) -> FixtureResult<FixtureTurn> {
    let params = fixture_params(request, "fixture/delegate")?;
    let thread_id = params
        .get("child_thread_id")
        .and_then(Value::as_str)
        .unwrap_or("fixture-child-thread");
    let turn_id = params
        .get("child_turn_id")
        .and_then(Value::as_str)
        .unwrap_or("fixture-child-turn");
    Ok(FixtureTurn {
        thread_id: thread_id.to_owned(),
        turn_id: turn_id.to_owned(),
    })
}

fn fixture_params<'a>(
    request: &'a Value,
    method: &str,
) -> FixtureResult<&'a serde_json::Map<String, Value>> {
    match request.get("params") {
        Some(Value::Object(params)) => Ok(params),
        _ => Err(format!("{method} params must be an object").into()),
    }
}

fn command_event(request: &Value, turn: &FixtureTurn) -> FixtureResult<Vec<u8>> {
    let params = fixture_params(request, "fixture/command")?;
    let command = params
        .get("command")
        .and_then(Value::as_str)
        .filter(|command| !command.is_empty() && command.len() <= 4 * 1024)
        .ok_or("fixture/command must contain a bounded non-empty command")?;
    let tool_use_id = params
        .get("tool_use_id")
        .map_or(Ok("fixture-command-1"), |value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or("fixture/command tool_use_id must be a bounded non-empty string")
        })?;
    let operation_key = match params.get("operation_key") {
        None => None,
        Some(Value::String(key))
            if !key.is_empty()
                && key.len() <= 128
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) =>
        {
            Some(key.as_str())
        }
        Some(_) => return Err("fixture/command operation_key is not supported".into()),
    };
    let input = json!({
        "command": command,
        "erebor_operation_key": operation_key.unwrap_or(""),
        "child_thread_id": "",
        "child_turn_id": "",
        "frozen_context_mode": "none",
        "last_turns": 0,
        "erebor_context_action": "",
        "target_thread_id": "",
        "target_turn_id": "",
        "follow_up_text": "",
    });
    Ok(serde_json::to_vec(&json!({
        "hook_event_name": "PreToolUse",
        "session_id": turn.thread_id,
        "turn_id": turn.turn_id,
        "tool_use_id": tool_use_id,
        "tool_name": "bash",
        "tool_input": input,
    }))?)
}

fn post_tool_event(
    tool_use_id: &str,
    delivery: Option<serde_json::Map<String, Value>>,
    turn: &FixtureTurn,
) -> FixtureResult<Vec<u8>> {
    let mut canonical_delivery = json!({
        "emit": false,
        "sequence": 0,
        "kind": "",
        "mode": "",
        "selected_text": "",
        "operation_key": "",
    });
    if let Some(delivery) = delivery {
        let Value::Object(canonical_delivery) = &mut canonical_delivery else {
            unreachable!("fixture delivery schema must remain an object");
        };
        canonical_delivery.insert(String::from("emit"), Value::Bool(true));
        canonical_delivery.extend(delivery);
    }
    let event = json!({
        "hook_event_name": "PostToolUse",
        "session_id": turn.thread_id,
        "turn_id": turn.turn_id,
        "tool_use_id": tool_use_id,
        "tool_response": {"status": "ok"},
        "erebor_delivery": canonical_delivery,
    });
    Ok(serde_json::to_vec(&event)?)
}

fn delivery_event(request: &Value, turn: &FixtureTurn) -> FixtureResult<Vec<u8>> {
    let params = match request.get("params") {
        None | Some(Value::Null) => None,
        Some(Value::Object(params)) => Some(params),
        Some(_) => return Err("fixture/deliver params must be an object".into()),
    };
    let sequence = params
        .and_then(|params| params.get("sequence"))
        .map_or(Ok(1), |value| {
            value
                .as_u64()
                .ok_or("fixture/deliver sequence must be unsigned")
        })?;
    let kind = params
        .and_then(|params| params.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("result");
    let mode = params
        .and_then(|params| params.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("queue");
    let selected_text = params
        .and_then(|params| params.get("selected_text"))
        .and_then(Value::as_str)
        .unwrap_or("fixture result");
    let operation_key = match params.and_then(|params| params.get("operation_key")) {
        None => None,
        Some(Value::String(key)) if !key.is_empty() => Some(key.as_str()),
        Some(_) => return Err("fixture/deliver operation_key must be a non-empty string".into()),
    };
    let tool_use_id = match params.and_then(|params| params.get("tool_use_id")) {
        None => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
        Some(_) => return Err("fixture/deliver tool_use_id must be a non-empty string".into()),
    };
    if operation_key.is_some() != tool_use_id.is_some() {
        return Err(
            "fixture/deliver operation_key and tool_use_id must be supplied together".into(),
        );
    }
    let mut delivery = serde_json::Map::from_iter([
        (String::from("sequence"), Value::from(sequence)),
        (String::from("kind"), Value::from(kind)),
        (String::from("mode"), Value::from(mode)),
        (String::from("selected_text"), Value::from(selected_text)),
        (String::from("operation_key"), Value::String(String::new())),
    ]);
    if let Some(operation_key) = operation_key {
        delivery.insert(
            String::from("operation_key"),
            Value::String(operation_key.to_owned()),
        );
    }
    post_tool_event(
        tool_use_id.unwrap_or("fixture-delivery-1"),
        Some(delivery),
        turn,
    )
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
    let root_admissions = options
        .owner_uids
        .iter()
        .map(|owner_uid| root_admission(*owner_uid, &root_policy))
        .collect::<FixtureResult<Vec<_>>>()?;
    let configuration = json!({
        "socket_group_gid": options.socket_group_gid,
        "linux_runner": {
            "containment": options.linux_runner_containment,
            "controller_path": options.linux_runner_controller,
            "process_guard_path": options.linux_process_guard,
            "descriptor_broker_path": options.descriptor_broker,
            "systemd_run_path": options.systemd_run,
        },
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
    println!("package_name={FIXTURE_NAME}");
    println!("root_policy_name={}", root_policy.manifest().name());
    Ok(())
}

struct ConfigureOptions {
    config: PathBuf,
    trust_root: PathBuf,
    socket_group_gid: u32,
    owner_uids: Vec<u32>,
    linux_runner_containment: String,
    linux_runner_controller: Option<PathBuf>,
    linux_process_guard: Option<PathBuf>,
    descriptor_broker: Option<PathBuf>,
    systemd_run: Option<PathBuf>,
}

impl ConfigureOptions {
    fn parse(arguments: &[String]) -> FixtureResult<Self> {
        let mut config = None;
        let mut trust_root = None;
        let mut socket_group_gid = None;
        let mut owner_uids = Vec::new();
        let mut linux_runner_containment = String::from("direct");
        let mut linux_runner_controller = None;
        let mut linux_process_guard = None;
        let mut descriptor_broker = None;
        let mut systemd_run = None;
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
                "--linux-runner-containment" => {
                    if !matches!(value.as_str(), "direct" | "systemd") {
                        return Err(format!(
                            "--linux-runner-containment must be `direct` or `systemd`, got `{value}`"
                        )
                        .into());
                    }
                    linux_runner_containment = value.clone();
                }
                "--linux-runner-controller" => {
                    linux_runner_controller = Some(absolute_option_path(option, value)?);
                }
                "--linux-process-guard" => {
                    linux_process_guard = Some(absolute_option_path(option, value)?);
                }
                "--descriptor-broker" => {
                    descriptor_broker = Some(absolute_option_path(option, value)?);
                }
                "--systemd-run" => systemd_run = Some(absolute_option_path(option, value)?),
                _ => return Err(format!("unknown configure option `{option}`").into()),
            }
            index += 2;
        }
        Ok(Self {
            config: config.ok_or("--config is required")?,
            trust_root: trust_root.ok_or("--trust-root is required")?,
            socket_group_gid: socket_group_gid.ok_or("--socket-group-gid is required")?,
            owner_uids,
            linux_runner_containment,
            linux_runner_controller,
            linux_process_guard,
            descriptor_broker,
            systemd_run,
        })
    }
}

fn absolute_option_path(option: &str, value: &str) -> FixtureResult<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{option} must name an absolute path, got `{value}`").into())
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
        let native = if event == CodexHookEventName::UserPromptSubmit {
            TERMINAL_TURN_EVENT.to_vec()
        } else if event == CodexHookEventName::PreToolUse {
            DELEGATION_EVENT.to_vec()
        } else if event == CodexHookEventName::PostToolUse {
            DELIVERY_EVENT.to_vec()
        } else {
            format!(r#"{{"hook_event_name":"{name}"}}"#).into_bytes()
        };
        let digest = CodexNativeHookEvent::parse(&native)?
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
        fixture_digest.clone(),
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
        b"# Deterministic Codex fixture host minimum\n".to_vec(),
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

#[cfg(test)]
mod tests {
    use super::{
        command_event, delegation_event, delivery_event, post_tool_event, CodexNativeHookEvent,
        FixtureToolUseIds, FixtureTurn, FixtureTurns, DELEGATION_EVENT, DELIVERY_EVENT,
    };

    #[test]
    fn fixture_command_and_delegation_hooks_share_the_pinned_pre_tool_schema(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let delegation = delegation_event(
            &serde_json::json!({
                "params": {
                    "child_thread_id": "fixture-b",
                    "child_turn_id": "turn-1",
                    "frozen_context_mode": "all",
                    "last_turns": 0,
                },
            }),
            &FixtureTurn::root(),
        )?;
        let command = command_event(
            &serde_json::json!({
                "params": {
                    "command": "ls",
                    "tool_use_id": "fixture-command-test"
                },
            }),
            &FixtureTurn::root(),
        )?;
        assert_eq!(
            CodexNativeHookEvent::parse(DELEGATION_EVENT)?.schema_sha256(),
            CodexNativeHookEvent::parse(&delegation)?.schema_sha256(),
        );
        assert_eq!(
            CodexNativeHookEvent::parse(DELEGATION_EVENT)?.schema_sha256(),
            CodexNativeHookEvent::parse(&command)?.schema_sha256(),
        );
        Ok(())
    }

    #[test]
    fn fixture_allocates_a_unique_native_tool_use_for_each_default_command(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = serde_json::json!({"params": {"command": "ls"}});
        let mut tool_uses = FixtureToolUseIds::default();
        let first = tool_uses.command_request(&request)?;
        let second = tool_uses.command_request(&request)?;
        let first = serde_json::from_slice::<serde_json::Value>(&command_event(
            &first,
            &FixtureTurn::root(),
        )?)?;
        let second = serde_json::from_slice::<serde_json::Value>(&command_event(
            &second,
            &FixtureTurn::root(),
        )?)?;
        assert_eq!(
            first
                .pointer("/tool_use_id")
                .and_then(serde_json::Value::as_str),
            Some("fixture-command-1")
        );
        assert_eq!(
            second
                .pointer("/tool_use_id")
                .and_then(serde_json::Value::as_str),
            Some("fixture-command-2")
        );
        Ok(())
    }

    #[test]
    fn fixture_switches_only_to_its_previously_delegated_thread_turn(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut turns = FixtureTurns::new();
        let child = serde_json::json!({
            "params": {
                "child_thread_id": "fixture-b",
                "child_turn_id": "turn-1",
                "frozen_context_mode": "all",
                "last_turns": 0,
            },
        });
        turns.delegate(&child)?;
        assert_eq!(turns.active().thread_id, "fixture-b");

        turns.switch(&serde_json::json!({
            "params": {"thread_id": "fixture-thread", "turn_id": "fixture-turn"},
        }))?;
        assert_eq!(turns.active().thread_id, "fixture-thread");

        assert!(turns
            .switch(&serde_json::json!({
                "params": {"thread_id": "fixture-c", "turn_id": "turn-1"},
            }))
            .is_err());
        Ok(())
    }

    #[test]
    fn fixture_operation_and_non_delivery_hooks_share_the_pinned_post_tool_schema(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let delivery = delivery_event(
            &serde_json::json!({
                "params": {
                    "sequence": 1,
                    "kind": "result",
                    "mode": "queue",
                    "selected_text": "partial",
                    "operation_key": "fixture-q",
                    "tool_use_id": "fixture-operation-test",
                },
            }),
            &FixtureTurn::root(),
        )?;
        let no_delivery = post_tool_event("fixture-command-test", None, &FixtureTurn::root())?;
        let expected = CodexNativeHookEvent::parse(DELIVERY_EVENT)?
            .schema_sha256()
            .to_owned();
        assert_eq!(
            CodexNativeHookEvent::parse(&delivery)?.schema_sha256(),
            expected
        );
        assert_eq!(
            CodexNativeHookEvent::parse(&no_delivery)?.schema_sha256(),
            expected
        );
        Ok(())
    }
}
