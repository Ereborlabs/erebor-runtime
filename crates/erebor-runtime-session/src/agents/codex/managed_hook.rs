use std::{
    io::{self, Read},
    process::ExitCode,
};

use erebor_runtime_ipc::v1::HookEvent;
use erebor_runtime_session::{CodexHookClient, CodexHookResultOutput, CodexNativeHookEvent};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("erebor managed Codex hook: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut original_stdout = CodexHookResultOutput::capture()?;
    let mut native_event_json = Vec::new();
    io::stdin()
        .lock()
        .take((CodexHookClient::MAX_NATIVE_EVENT_BYTES + 1) as u64)
        .read_to_end(&mut native_event_json)
        .map_err(|error| format!("failed to read native hook input: {error}"))?;
    if native_event_json.len() > CodexHookClient::MAX_NATIVE_EVENT_BYTES {
        return Err(format!(
            "native hook input exceeds {} bytes",
            CodexHookClient::MAX_NATIVE_EVENT_BYTES
        ));
    }
    let event = CodexNativeHookEvent::parse(&native_event_json)?;
    let result = CodexHookClient::default()
        .submit(HookEvent {
            event: event.kind() as i32,
            schema_sha256: event.schema_sha256().to_owned(),
            native_event_json,
        })
        .map_err(|error| error.to_string())?;
    original_stdout.write_result(&result.result_json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use erebor_runtime_session::CodexNativeHookEvent;

    #[test]
    fn managed_hook_requires_a_declared_native_event() -> Result<(), String> {
        assert!(CodexNativeHookEvent::parse(br#"{}"#).is_err());
        assert_eq!(
            CodexNativeHookEvent::parse(br#"{"hook_event_name":"SessionStart"}"#)?.kind(),
            erebor_runtime_ipc::v1::HookEventKind::SessionStart
        );
        Ok(())
    }
}
