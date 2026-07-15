use std::{
    env,
    fs::OpenOptions,
    io::{self, Read, Write},
    process::ExitCode,
};

use erebor_runtime_ipc::v1::HookEvent;
use erebor_runtime_session::{CodexHookClient, CodexHookResultOutput, CodexNativeHookEvent};
use rustix::stdio::dup2_stdout;

const HOOK_LOG_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_LOG";
const HOOK_ENV_MARKER_ENV: &str = "EREBOR_CODEX_LINUX_V1_HOOK_ENV_MARKER";
const REPLACE_STDOUT_ENV: &str = "EREBOR_CODEX_LINUX_V1_REPLACE_STDOUT";
const REPLACE_STDOUT_AFTER_BROKER_ENV: &str = "EREBOR_CODEX_LINUX_V1_REPLACE_STDOUT_AFTER_BROKER";
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
    let mut original_stdout = CodexHookResultOutput::capture().map_err(io::Error::other)?;
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
        let event = CodexNativeHookEvent::parse(&input).map_err(io::Error::other)?;
        let result = CodexHookClient::default()
            .submit(HookEvent {
                event: event.kind() as i32,
                schema_sha256: event.schema_sha256().to_owned(),
                native_event_json: input.clone(),
            })
            .map_err(io::Error::other)?;
        if env::var_os(REPLACE_STDOUT_AFTER_BROKER_ENV).is_some() {
            let replacement = std::fs::File::open("/dev/null")?;
            dup2_stdout(replacement).map_err(io::Error::from)?;
        }
        append_hook_log_if_configured(&input)?;
        append_hook_environment_marker_if_configured()?;
        return original_stdout
            .write_result(&result.result_json)
            .map_err(io::Error::other);
    }
    let log_path = env::var_os(HOOK_LOG_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{HOOK_LOG_ENV} is required"),
        )
    })?;

    append_hook_log(&log_path, &input)?;

    original_stdout
        .write_result(br#"{"continue":true}"#)
        .map_err(io::Error::other)
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
