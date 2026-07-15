use std::{
    env,
    fs::OpenOptions,
    io::{self, Read, Write},
    process::ExitCode,
};

use erebor_runtime_ipc::v1::{HookEvent, HookEventKind};
use erebor_runtime_session::CodexHookClient;

const HOOK_LOG_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_LOG";
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

    if env::var_os("EREBOR_CODEX_HOOK_BROKER").is_some() {
        let result = CodexHookClient::default()
            .submit(HookEvent {
                event: event_kind(&input) as i32,
                schema_sha256: String::new(),
                native_event_json: input,
            })
            .map_err(io::Error::other)?;
        return io::stdout().write_all(&result.result_json);
    }
    let log_path = env::var_os(HOOK_LOG_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{HOOK_LOG_ENV} is required"),
        )
    })?;

    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    log.write_all(&input)?;
    log.write_all(b"\n")?;

    io::stdout().write_all(br#"{"continue":true}"#)
}

fn event_kind(input: &[u8]) -> HookEventKind {
    match serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .and_then(|value| value.get("hook_event_name")?.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("session_start") => HookEventKind::SessionStart,
        _ => HookEventKind::Unspecified,
    }
}
