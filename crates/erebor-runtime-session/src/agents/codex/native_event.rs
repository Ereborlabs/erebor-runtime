use erebor_runtime_ipc::v1::HookEventKind;

use super::native_schema::CodexV1HookSchema;

/// Parsed native Codex hook input validated against the compiled Codex v1
/// event schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexNativeHookEvent {
    kind: HookEventKind,
}

impl CodexNativeHookEvent {
    pub fn parse(native_event_json: &[u8]) -> Result<Self, String> {
        let payload: serde_json::Value = serde_json::from_slice(native_event_json)
            .map_err(|error| format!("native hook input is not JSON: {error}"))?;
        let event = payload
            .get("hook_event_name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| String::from("native hook input omitted hook_event_name"))?;
        let kind = Self::kind_from_name(event)?;
        CodexV1HookSchema::validate(kind, &payload)?;
        Ok(Self { kind })
    }

    #[must_use]
    pub const fn kind(&self) -> HookEventKind {
        self.kind
    }

    fn kind_from_name(event: &str) -> Result<HookEventKind, String> {
        Ok(match event {
            "SessionStart" => HookEventKind::SessionStart,
            "UserPromptSubmit" => HookEventKind::UserPromptSubmit,
            "PreToolUse" => HookEventKind::PreToolUse,
            "PermissionRequest" => HookEventKind::PermissionRequest,
            "PostToolUse" => HookEventKind::PostToolUse,
            "SubagentStart" => HookEventKind::SubagentStart,
            "SubagentStop" => HookEventKind::SubagentStop,
            "Stop" => HookEventKind::Stop,
            _ => return Err(format!("unknown managed Codex hook event `{event}`")),
        })
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::HookEventKind;

    use super::CodexNativeHookEvent;

    #[test]
    fn validates_all_supported_current_codex_v1_event_schemas() -> Result<(), String> {
        for (event, expected_kind) in [
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"SessionStart","model":"gpt-5","permission_mode":"default","session_id":"session","source":"startup","transcript_path":null}),
                HookEventKind::SessionStart,
            ),
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"UserPromptSubmit","model":"gpt-5","permission_mode":"default","prompt":"review","session_id":"session","transcript_path":null,"turn_id":"turn"}),
                HookEventKind::UserPromptSubmit,
            ),
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"PreToolUse","model":"gpt-5","permission_mode":"default","session_id":"session","tool_input":{},"tool_name":"Bash","tool_use_id":"tool","transcript_path":null,"turn_id":"turn"}),
                HookEventKind::PreToolUse,
            ),
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"PermissionRequest","model":"gpt-5","permission_mode":"default","session_id":"session","tool_input":{},"tool_name":"Bash","transcript_path":null,"turn_id":"turn"}),
                HookEventKind::PermissionRequest,
            ),
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"PostToolUse","model":"gpt-5","permission_mode":"default","session_id":"session","tool_input":{},"tool_name":"Bash","tool_response":{},"tool_use_id":"tool","transcript_path":null,"turn_id":"turn"}),
                HookEventKind::PostToolUse,
            ),
            (
                serde_json::json!({"agent_id":"agent","agent_type":"worker","cwd":"/workspace","hook_event_name":"SubagentStart","model":"gpt-5","permission_mode":"default","session_id":"session","transcript_path":null,"turn_id":"turn"}),
                HookEventKind::SubagentStart,
            ),
            (
                serde_json::json!({"agent_id":"agent","agent_transcript_path":null,"agent_type":"worker","cwd":"/workspace","hook_event_name":"SubagentStop","last_assistant_message":null,"model":"gpt-5","permission_mode":"default","session_id":"session","stop_hook_active":false,"transcript_path":null,"turn_id":"turn"}),
                HookEventKind::SubagentStop,
            ),
            (
                serde_json::json!({"cwd":"/workspace","hook_event_name":"Stop","last_assistant_message":null,"model":"gpt-5","permission_mode":"default","session_id":"session","stop_hook_active":false,"transcript_path":null,"turn_id":"turn"}),
                HookEventKind::Stop,
            ),
        ] {
            let event = CodexNativeHookEvent::parse(
                &serde_json::to_vec(&event).map_err(|error| error.to_string())?,
            )?;
            assert_eq!(event.kind(), expected_kind);
        }
        Ok(())
    }

    #[test]
    fn rejects_a_current_schema_violation() {
        assert!(CodexNativeHookEvent::parse(
            br#"{"cwd":"/workspace","hook_event_name":"SessionStart","model":"gpt-5","permission_mode":"default","session_id":"session","source":"startup","transcript_path":null,"unexpected":true}"#,
        )
        .is_err());
    }
}
