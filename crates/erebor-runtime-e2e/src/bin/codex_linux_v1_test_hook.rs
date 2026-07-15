use std::{
    env,
    fs::OpenOptions,
    io::{self, Read, Write},
    process::ExitCode,
};

use erebor_runtime_ipc::v1::{HookEvent, HookEventKind};
use erebor_runtime_session::CodexHookClient;
use rustix::stdio::dup2_stdout;

const HOOK_LOG_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_LOG";
const HOOK_ENV_MARKER_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_ENV_MARKER";
const REPLACE_STDOUT_ENV: &str = "EREBOR_CODEX_LINUX_V1_REPLACE_STDOUT";
const MAX_INPUT_BYTES: u64 = 64 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("erebor Codex Linux V1 test hook failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook input exceeds the Phase 0 test bound",
        ));
    }

    if env::var_os(REPLACE_STDOUT_ENV).is_some() {
        let replacement = std::fs::File::open("/dev/null")?;
        dup2_stdout(replacement).map_err(io::Error::from)?;
    }

    if env::var_os("EREBOR_CODEX_HOOK_BROKER").is_some() {
        let result = CodexHookClient::default()
            .submit(HookEvent {
                event: event_kind(&input) as i32,
                schema_sha256: String::new(),
                native_event_json: input.clone(),
            })
            .map_err(io::Error::other)?;
        append_hook_log_if_configured(&input)?;
        append_hook_environment_marker_if_configured()?;
        return io::stdout().write_all(&result.result_json);
    }
    let log_path = env::var_os(HOOK_LOG_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{HOOK_LOG_ENV} is required"),
        )
    })?;

    append_hook_log(&log_path, &input)?;

    io::stdout().write_all(br#"{"continue":true}"#)
}

fn append_hook_environment_marker_if_configured() -> io::Result<()> {
    let Some(marker_path) = env::var_os(HOOK_ENV_MARKER_ENV) else {
        return Ok(());
    };
    let mut marker = OpenOptions::new()
        .create(true)
        .append(true)
        .open(marker_path)?;
    let zdotdir = env::var("ZDOTDIR").unwrap_or_else(|_error| String::from("<unset>"));
    writeln!(marker, "ZDOTDIR={zdotdir}")
}

fn append_hook_log_if_configured(input: &[u8]) -> io::Result<()> {
    let Some(log_path) = env::var_os(HOOK_LOG_ENV) else {
        return Ok(());
    };
    append_hook_log(&log_path, input)
}

fn append_hook_log(log_path: impl AsRef<std::path::Path>, input: &[u8]) -> io::Result<()> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    log.write_all(input)?;
    log.write_all(b"\n")
}

fn event_kind(input: &[u8]) -> HookEventKind {
    match serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .and_then(|value| value.get("hook_event_name")?.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("session_start" | "SessionStart") => HookEventKind::SessionStart,
        Some("user_prompt_submit" | "UserPromptSubmit") => HookEventKind::UserPromptSubmit,
        Some("pre_tool_use" | "PreToolUse") => HookEventKind::PreToolUse,
        Some("permission_request" | "PermissionRequest") => HookEventKind::PermissionRequest,
        Some("post_tool_use" | "PostToolUse") => HookEventKind::PostToolUse,
        Some("subagent_start" | "SubagentStart") => HookEventKind::SubagentStart,
        Some("subagent_stop" | "SubagentStop") => HookEventKind::SubagentStop,
        Some("stop" | "Stop") => HookEventKind::Stop,
        _ => HookEventKind::Unspecified,
    }
}
