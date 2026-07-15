use std::{
    env,
    fs::OpenOptions,
    io::{self, Read, Write},
    process::ExitCode,
};

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
    let log_path = env::var_os(HOOK_LOG_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{HOOK_LOG_ENV} is required"),
        )
    })?;
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

    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    log.write_all(&input)?;
    log.write_all(b"\n")?;

    io::stdout().write_all(br#"{"continue":true}"#)
}
