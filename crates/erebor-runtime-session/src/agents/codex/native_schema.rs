use erebor_runtime_ipc::v1::HookEventKind;
use serde_json::Value;

pub(crate) struct CodexV1HookSchema;

impl CodexV1HookSchema {
    pub(crate) fn validate(kind: HookEventKind, payload: &Value) -> Result<(), String> {
        let schema = Self::schema(kind)?;
        let object = payload
            .as_object()
            .ok_or_else(|| String::from("native hook input must be a JSON object"))?;

        for field in schema.fields {
            match object.get(field.name) {
                Some(value) if field.value_type.accepts(value) => {}
                Some(_) => {
                    return Err(format!(
                        "native {} hook field `{}` does not match the current Codex v1 schema",
                        schema.event_name, field.name
                    ));
                }
                None if field.required => {
                    return Err(format!(
                        "native {} hook input omits required field `{}`",
                        schema.event_name, field.name
                    ));
                }
                None => {}
            }
        }

        if let Some(field) = object
            .keys()
            .find(|field| !schema.fields.iter().any(|allowed| allowed.name == *field))
        {
            return Err(format!(
                "native {} hook input contains unsupported field `{field}`",
                schema.event_name
            ));
        }
        Ok(())
    }

    fn schema(kind: HookEventKind) -> Result<&'static HookSchema, String> {
        match kind {
            HookEventKind::SessionStart => Ok(&SESSION_START),
            HookEventKind::UserPromptSubmit => Ok(&USER_PROMPT_SUBMIT),
            HookEventKind::PreToolUse => Ok(&PRE_TOOL_USE),
            HookEventKind::PermissionRequest => Ok(&PERMISSION_REQUEST),
            HookEventKind::PostToolUse => Ok(&POST_TOOL_USE),
            HookEventKind::SubagentStart => Ok(&SUBAGENT_START),
            HookEventKind::SubagentStop => Ok(&SUBAGENT_STOP),
            HookEventKind::Stop => Ok(&STOP),
            HookEventKind::Unspecified => Err(String::from("native hook event is unspecified")),
        }
    }
}

struct HookSchema {
    event_name: &'static str,
    fields: &'static [HookField],
}

struct HookField {
    name: &'static str,
    required: bool,
    value_type: HookValueType,
}

#[derive(Clone, Copy)]
enum HookValueType {
    String,
    NullableString,
    Boolean,
    Any,
    PermissionMode,
    SessionStartSource,
    EventName(&'static str),
}

impl HookValueType {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::NullableString => value.is_null() || value.is_string(),
            Self::Boolean => value.is_boolean(),
            Self::Any => true,
            Self::PermissionMode => value.as_str().is_some_and(|value| {
                matches!(
                    value,
                    "default" | "acceptEdits" | "plan" | "dontAsk" | "bypassPermissions"
                )
            }),
            Self::SessionStartSource => value
                .as_str()
                .is_some_and(|value| matches!(value, "startup" | "resume" | "clear" | "compact")),
            Self::EventName(expected) => value.as_str() == Some(expected),
        }
    }
}

const fn field(name: &'static str, required: bool, value_type: HookValueType) -> HookField {
    HookField {
        name,
        required,
        value_type,
    }
}

const SESSION_START: HookSchema = HookSchema {
    event_name: "SessionStart",
    fields: &[
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("SessionStart"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("source", true, HookValueType::SessionStartSource),
        field("transcript_path", true, HookValueType::NullableString),
    ],
};

const USER_PROMPT_SUBMIT: HookSchema = HookSchema {
    event_name: "UserPromptSubmit",
    fields: &[
        field("agent_id", false, HookValueType::String),
        field("agent_type", false, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("UserPromptSubmit"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("prompt", true, HookValueType::String),
        field("session_id", true, HookValueType::String),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const PRE_TOOL_USE: HookSchema = HookSchema {
    event_name: "PreToolUse",
    fields: &[
        field("agent_id", false, HookValueType::String),
        field("agent_type", false, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("PreToolUse"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("tool_input", true, HookValueType::Any),
        field("tool_name", true, HookValueType::String),
        field("tool_use_id", true, HookValueType::String),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const PERMISSION_REQUEST: HookSchema = HookSchema {
    event_name: "PermissionRequest",
    fields: &[
        field("agent_id", false, HookValueType::String),
        field("agent_type", false, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("PermissionRequest"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("tool_input", true, HookValueType::Any),
        field("tool_name", true, HookValueType::String),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const POST_TOOL_USE: HookSchema = HookSchema {
    event_name: "PostToolUse",
    fields: &[
        field("agent_id", false, HookValueType::String),
        field("agent_type", false, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("PostToolUse"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("tool_input", true, HookValueType::Any),
        field("tool_name", true, HookValueType::String),
        field("tool_response", true, HookValueType::Any),
        field("tool_use_id", true, HookValueType::String),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const SUBAGENT_START: HookSchema = HookSchema {
    event_name: "SubagentStart",
    fields: &[
        field("agent_id", true, HookValueType::String),
        field("agent_type", true, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("SubagentStart"),
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const SUBAGENT_STOP: HookSchema = HookSchema {
    event_name: "SubagentStop",
    fields: &[
        field("agent_id", true, HookValueType::String),
        field("agent_transcript_path", true, HookValueType::NullableString),
        field("agent_type", true, HookValueType::String),
        field("cwd", true, HookValueType::String),
        field(
            "hook_event_name",
            true,
            HookValueType::EventName("SubagentStop"),
        ),
        field(
            "last_assistant_message",
            true,
            HookValueType::NullableString,
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("stop_hook_active", true, HookValueType::Boolean),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};

const STOP: HookSchema = HookSchema {
    event_name: "Stop",
    fields: &[
        field("cwd", true, HookValueType::String),
        field("hook_event_name", true, HookValueType::EventName("Stop")),
        field(
            "last_assistant_message",
            true,
            HookValueType::NullableString,
        ),
        field("model", true, HookValueType::String),
        field("permission_mode", true, HookValueType::PermissionMode),
        field("session_id", true, HookValueType::String),
        field("stop_hook_active", true, HookValueType::Boolean),
        field("transcript_path", true, HookValueType::NullableString),
        field("turn_id", true, HookValueType::String),
    ],
};
