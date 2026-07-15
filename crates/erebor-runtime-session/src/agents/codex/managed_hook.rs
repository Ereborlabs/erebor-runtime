use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

use erebor_runtime_ipc::v1::{HookEvent, HookEventKind};
use erebor_runtime_session::CodexHookClient;

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
    let event = event_from_native_json(&native_event_json)?;
    let result = CodexHookClient::default()
        .submit(HookEvent {
            event: event as i32,
            // The broker selects the pinned schema fingerprint from its
            // managed profile. Native hook JSON never selects a schema.
            schema_sha256: String::new(),
            native_event_json,
        })
        .map_err(|error| error.to_string())?;
    io::stdout()
        .write_all(&result.result_json)
        .map_err(|error| format!("failed to write hook result: {error}"))?;
    Ok(())
}

fn event_from_native_json(native_event_json: &[u8]) -> Result<HookEventKind, String> {
    let payload: serde_json::Value = serde_json::from_slice(native_event_json)
        .map_err(|error| format!("native hook input is not JSON: {error}"))?;
    let event = payload
        .get("hook_event_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| String::from("native hook input omitted hook_event_name"))?;
    Ok(match event {
        "session_start" => HookEventKind::SessionStart,
        "user_prompt_submit" => HookEventKind::UserPromptSubmit,
        "pre_tool_use" => HookEventKind::PreToolUse,
        "permission_request" => HookEventKind::PermissionRequest,
        "post_tool_use" => HookEventKind::PostToolUse,
        "subagent_start" => HookEventKind::SubagentStart,
        "subagent_stop" => HookEventKind::SubagentStop,
        "stop" => HookEventKind::Stop,
        _ => return Err(format!("unknown managed Codex hook event `{event}`")),
    })
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::HookEventKind;

    use super::event_from_native_json;

    #[test]
    fn managed_hook_requires_a_declared_native_event() -> Result<(), String> {
        assert!(event_from_native_json(br#"{}"#).is_err());
        assert_eq!(
            event_from_native_json(br#"{"hook_event_name":"session_start"}"#)?,
            HookEventKind::SessionStart
        );
        Ok(())
    }
}
