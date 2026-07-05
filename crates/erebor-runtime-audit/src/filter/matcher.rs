use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::ActionKind;
use erebor_runtime_policy::Decision;

#[derive(Clone, Copy, Debug)]
pub(super) struct AuditDebugMatcher<'a> {
    record: &'a AuditRecord,
}

impl<'a> AuditDebugMatcher<'a> {
    pub(super) const fn new(record: &'a AuditRecord) -> Self {
        Self { record }
    }

    pub(super) fn is_signal_decision(self) -> bool {
        !matches!(self.record.policy_decision, Decision::Allow { .. })
            || !matches!(self.record.final_decision, Decision::Allow { .. })
    }

    pub(super) fn matches_terminal_command(self, debug_commands: &[String]) -> bool {
        self.matches_any(self.terminal_tokens(), debug_commands)
    }

    pub(super) fn matches_browser_cdp(
        self,
        debug_methods: &[String],
        debug_actions: &[String],
    ) -> bool {
        self.matches_any(self.payload_values(&["method"]), debug_methods)
            || self.matches_action(debug_actions)
    }

    pub(super) fn matches_mcp(self, debug_tools: &[String], debug_actions: &[String]) -> bool {
        self.matches_any(
            self.payload_values(&["tool", "tool_name", "name", "handler_id"]),
            debug_tools,
        ) || self.matches_action(debug_actions)
    }

    pub(super) fn matches_operation(
        self,
        debug_operations: &[String],
        debug_actions: &[String],
    ) -> bool {
        self.matches_any(
            self.payload_values(&["operation", "method", "kind"]),
            debug_operations,
        ) || self.matches_any(
            self.nested_payload_values(&[&["request", "method"]]),
            debug_operations,
        ) || self.matches_action(debug_actions)
    }

    pub(super) fn matches_action(self, debug_actions: &[String]) -> bool {
        self.matches_any(
            [Self::action_name(&self.record.event.action)],
            debug_actions,
        )
    }

    fn matches_any<T>(self, tokens: impl IntoIterator<Item = T>, debug_values: &[String]) -> bool
    where
        T: AsRef<str>,
    {
        if debug_values.is_empty() {
            return false;
        }

        tokens.into_iter().any(|token| {
            debug_values
                .iter()
                .any(|debug_value| Self::command_token_matches(token.as_ref(), debug_value))
        })
    }

    fn terminal_tokens(self) -> Vec<&'a str> {
        let mut tokens = Vec::new();
        if let Some(command) = self
            .record
            .event
            .payload
            .get("command")
            .and_then(serde_json::Value::as_array)
            .and_then(|command| command.first())
            .and_then(serde_json::Value::as_str)
        {
            tokens.push(command);
        }
        if let Some(argv_summary) = self
            .record
            .event
            .payload
            .get("argv_summary")
            .and_then(serde_json::Value::as_str)
            .and_then(|summary| summary.split_whitespace().next())
        {
            tokens.push(argv_summary);
        }
        if let Some(label) = self
            .record
            .event
            .target
            .as_ref()
            .and_then(|target| target.label.as_deref())
        {
            tokens.push(label);
        }
        tokens
    }

    fn payload_values(self, keys: &[&str]) -> Vec<&'a str> {
        keys.iter()
            .filter_map(|key| {
                self.record
                    .event
                    .payload
                    .get(*key)
                    .and_then(serde_json::Value::as_str)
            })
            .collect()
    }

    fn nested_payload_values(self, paths: &[&[&str]]) -> Vec<&'a str> {
        paths
            .iter()
            .filter_map(|path| {
                let mut value = &self.record.event.payload;
                for segment in *path {
                    value = value.get(*segment)?;
                }
                value.as_str()
            })
            .collect()
    }

    fn command_token_matches(token: &str, debug_command: &str) -> bool {
        token == debug_command
            || Self::basename(token) == debug_command
            || Self::basename(debug_command) == token
            || Self::basename(token) == Self::basename(debug_command)
    }

    fn basename(value: &str) -> &str {
        value
            .rsplit_once('/')
            .map_or(value, |(_prefix, basename)| basename)
    }

    fn action_name(action: &ActionKind) -> &'static str {
        match action {
            ActionKind::BrowserNavigate => "browser_navigate",
            ActionKind::BrowserClick => "browser_click",
            ActionKind::BrowserInput => "browser_input",
            ActionKind::BrowserScriptEval => "browser_script_eval",
            ActionKind::BrowserTargetManage => "browser_target_manage",
            ActionKind::BrowserStateRecovery => "browser_state_recovery",
            ActionKind::NetworkRequest => "network_request",
            ActionKind::ProcessExec => "process_exec",
            ActionKind::FileOpen => "file_open",
            ActionKind::FileRead => "file_read",
            ActionKind::FileWrite => "file_write",
            ActionKind::FileMutation => "file_mutation",
            ActionKind::ToolInvoke => "tool_invoke",
            ActionKind::SaaSMutation => "saas_mutation",
            ActionKind::DesktopInput => "desktop_input",
            ActionKind::InternalMutation => "internal_mutation",
            ActionKind::Unknown => "unknown",
        }
    }
}
