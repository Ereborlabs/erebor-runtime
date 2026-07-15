use std::collections::BTreeSet;

use erebor_runtime_ipc::v1::HookEventKind;
use sha2::{Digest, Sha256};

/// Parsed native Codex hook input and the stable structural fingerprint of its
/// event-specific JSON schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexNativeHookEvent {
    kind: HookEventKind,
    schema_sha256: String,
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
        let shape = Self::schema_shape(&payload);
        let mut digest = Sha256::new();
        digest.update(b"erebor.codex.native-hook-schema.v1\0");
        digest.update(Self::kind_name(kind).as_bytes());
        digest.update(b"\0");
        digest.update(shape.as_bytes());
        Ok(Self {
            kind,
            schema_sha256: format!("{:x}", digest.finalize()),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> HookEventKind {
        self.kind
    }

    #[must_use]
    pub fn schema_sha256(&self) -> &str {
        &self.schema_sha256
    }

    fn kind_from_name(event: &str) -> Result<HookEventKind, String> {
        Ok(match event {
            "session_start" | "SessionStart" => HookEventKind::SessionStart,
            "user_prompt_submit" | "UserPromptSubmit" => HookEventKind::UserPromptSubmit,
            "pre_tool_use" | "PreToolUse" => HookEventKind::PreToolUse,
            "permission_request" | "PermissionRequest" => HookEventKind::PermissionRequest,
            "post_tool_use" | "PostToolUse" => HookEventKind::PostToolUse,
            "subagent_start" | "SubagentStart" => HookEventKind::SubagentStart,
            "subagent_stop" | "SubagentStop" => HookEventKind::SubagentStop,
            "stop" | "Stop" => HookEventKind::Stop,
            _ => return Err(format!("unknown managed Codex hook event `{event}`")),
        })
    }

    const fn kind_name(kind: HookEventKind) -> &'static str {
        match kind {
            HookEventKind::SessionStart => "session_start",
            HookEventKind::UserPromptSubmit => "user_prompt_submit",
            HookEventKind::PreToolUse => "pre_tool_use",
            HookEventKind::PermissionRequest => "permission_request",
            HookEventKind::PostToolUse => "post_tool_use",
            HookEventKind::SubagentStart => "subagent_start",
            HookEventKind::SubagentStop => "subagent_stop",
            HookEventKind::Stop => "stop",
            HookEventKind::Unspecified => "unspecified",
        }
    }

    fn schema_shape(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => String::from("null"),
            serde_json::Value::Bool(_) => String::from("boolean"),
            serde_json::Value::Number(_) => String::from("number"),
            serde_json::Value::String(_) => String::from("string"),
            serde_json::Value::Array(values) => {
                let shapes = values
                    .iter()
                    .map(Self::schema_shape)
                    .collect::<BTreeSet<_>>();
                format!(
                    "array<{}>",
                    shapes.into_iter().collect::<Vec<_>>().join("|")
                )
            }
            serde_json::Value::Object(fields) => {
                let fields = fields
                    .iter()
                    .map(|(key, value)| format!("{key:?}:{}", Self::schema_shape(value)))
                    .collect::<BTreeSet<_>>();
                format!(
                    "object{{{}}}",
                    fields.into_iter().collect::<Vec<_>>().join(",")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::HookEventKind;

    use super::CodexNativeHookEvent;

    #[test]
    fn accepts_the_observed_pascal_case_event_names() -> Result<(), String> {
        let event = CodexNativeHookEvent::parse(br#"{"hook_event_name":"SessionStart"}"#)?;

        assert_eq!(event.kind(), HookEventKind::SessionStart);
        Ok(())
    }

    #[test]
    fn schema_fingerprint_is_key_order_independent_and_shape_sensitive() -> Result<(), String> {
        let first = CodexNativeHookEvent::parse(
            br#"{"hook_event_name":"SessionStart","details":{"id":"one"}}"#,
        )?;
        let reordered = CodexNativeHookEvent::parse(
            br#"{"details":{"id":"two"},"hook_event_name":"SessionStart"}"#,
        )?;
        let changed = CodexNativeHookEvent::parse(
            br#"{"hook_event_name":"SessionStart","details":{"id":2}}"#,
        )?;

        assert_eq!(first.schema_sha256(), reordered.schema_sha256());
        assert_ne!(first.schema_sha256(), changed.schema_sha256());
        Ok(())
    }
}
