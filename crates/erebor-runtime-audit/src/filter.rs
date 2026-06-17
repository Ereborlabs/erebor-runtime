use erebor_runtime_core::{
    AuditCommandLogLevel, AuditError, AuditRecord, AuditSink, BrowserCdpAuditSurfaceLoggingConfig,
    DesktopAuditSurfaceLoggingConfig, InternalSystemAuditSurfaceLoggingConfig,
    McpAuditSurfaceLoggingConfig, NetworkAuditSurfaceLoggingConfig, RuntimeAuditConfig,
    RuntimeAuditSurfaceLoggingConfig, SaaSAuditSurfaceLoggingConfig,
    TerminalAuditSurfaceLoggingConfig,
};
use erebor_runtime_events::{ActionKind, ExecutionSurface};
use erebor_runtime_policy::Decision;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilteredAuditSink<S> {
    inner: S,
    audit: RuntimeAuditConfig,
}

impl<S> FilteredAuditSink<S> {
    #[must_use]
    pub const fn new(inner: S, audit: RuntimeAuditConfig) -> Self {
        Self { inner, audit }
    }

    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AuditSink for FilteredAuditSink<S>
where
    S: AuditSink,
{
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if should_record_audit_record(record, &self.audit) {
            self.inner.record(record)?;
        }
        Ok(())
    }
}

#[must_use]
pub fn should_record_audit_record(record: &AuditRecord, audit: &RuntimeAuditConfig) -> bool {
    should_record_with_surface_logging(record, audit.surfaces())
}

#[must_use]
pub fn should_record_with_surface_logging(
    record: &AuditRecord,
    surfaces: &RuntimeAuditSurfaceLoggingConfig,
) -> bool {
    if is_signal_decision(record) {
        return true;
    }

    match record.event.surface {
        ExecutionSurface::BrowserCdp => should_record_browser_cdp(record, surfaces.browser_cdp()),
        ExecutionSurface::Mcp => should_record_mcp(record, surfaces.mcp()),
        ExecutionSurface::Terminal => should_record_terminal(record, surfaces.terminal()),
        ExecutionSurface::Network => should_record_network(record, surfaces.network()),
        ExecutionSurface::SaaS => should_record_saas(record, surfaces.saas()),
        ExecutionSurface::Desktop => should_record_desktop(record, surfaces.desktop()),
        ExecutionSurface::InternalSystem => {
            should_record_internal_system(record, surfaces.internal_system())
        }
    }
}

fn is_signal_decision(record: &AuditRecord) -> bool {
    !matches!(record.policy_decision, Decision::Allow { .. })
        || !matches!(record.final_decision, Decision::Allow { .. })
}

fn should_record_terminal(
    record: &AuditRecord,
    logging: &TerminalAuditSurfaceLoggingConfig,
) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => {
            !matches_any(record_terminal_tokens(record), logging.debug_commands())
        }
    }
}

fn should_record_browser_cdp(
    record: &AuditRecord,
    logging: &BrowserCdpAuditSurfaceLoggingConfig,
) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_browser_cdp_debug(record, logging),
    }
}

fn should_record_mcp(record: &AuditRecord, logging: &McpAuditSurfaceLoggingConfig) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_mcp_debug(record, logging),
    }
}

fn should_record_network(record: &AuditRecord, logging: &NetworkAuditSurfaceLoggingConfig) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => {
            !matches_operation_debug(record, logging.debug_operations(), logging.debug_actions())
        }
    }
}

fn should_record_saas(record: &AuditRecord, logging: &SaaSAuditSurfaceLoggingConfig) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => {
            !matches_operation_debug(record, logging.debug_operations(), logging.debug_actions())
        }
    }
}

fn should_record_desktop(record: &AuditRecord, logging: &DesktopAuditSurfaceLoggingConfig) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_action_debug(record, logging.debug_actions()),
    }
}

fn should_record_internal_system(
    record: &AuditRecord,
    logging: &InternalSystemAuditSurfaceLoggingConfig,
) -> bool {
    match logging.level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => {
            !matches_operation_debug(record, logging.debug_operations(), logging.debug_actions())
        }
    }
}

fn matches_browser_cdp_debug(
    record: &AuditRecord,
    logging: &BrowserCdpAuditSurfaceLoggingConfig,
) -> bool {
    matches_any(
        record_payload_values(record, &["method"]),
        logging.debug_methods(),
    ) || matches_action_debug(record, logging.debug_actions())
}

fn matches_mcp_debug(record: &AuditRecord, logging: &McpAuditSurfaceLoggingConfig) -> bool {
    matches_any(
        record_payload_values(record, &["tool", "tool_name", "name", "handler_id"]),
        logging.debug_tools(),
    ) || matches_action_debug(record, logging.debug_actions())
}

fn matches_operation_debug(
    record: &AuditRecord,
    debug_operations: &[String],
    debug_actions: &[String],
) -> bool {
    matches_any(
        record_payload_values(record, &["operation", "method", "kind"]),
        debug_operations,
    ) || matches_any(
        nested_payload_values(record, &[&["request", "method"]]),
        debug_operations,
    ) || matches_action_debug(record, debug_actions)
}

fn matches_action_debug(record: &AuditRecord, debug_actions: &[String]) -> bool {
    matches_any([action_name(&record.event.action)], debug_actions)
}

fn matches_any<T>(tokens: impl IntoIterator<Item = T>, debug_values: &[String]) -> bool
where
    T: AsRef<str>,
{
    if debug_values.is_empty() {
        return false;
    }

    tokens.into_iter().any(|token| {
        debug_values
            .iter()
            .any(|debug_value| command_token_matches(token.as_ref(), debug_value))
    })
}

fn record_terminal_tokens(record: &AuditRecord) -> Vec<&str> {
    let mut tokens = Vec::new();
    if let Some(command) = record
        .event
        .payload
        .get("command")
        .and_then(serde_json::Value::as_array)
        .and_then(|command| command.first())
        .and_then(serde_json::Value::as_str)
    {
        tokens.push(command);
    }
    if let Some(argv_summary) = record
        .event
        .payload
        .get("argv_summary")
        .and_then(serde_json::Value::as_str)
        .and_then(|summary| summary.split_whitespace().next())
    {
        tokens.push(argv_summary);
    }
    if let Some(label) = record
        .event
        .target
        .as_ref()
        .and_then(|target| target.label.as_deref())
    {
        tokens.push(label);
    }
    tokens
}

fn record_payload_values<'a>(record: &'a AuditRecord, keys: &[&str]) -> Vec<&'a str> {
    keys.iter()
        .filter_map(|key| {
            record
                .event
                .payload
                .get(*key)
                .and_then(serde_json::Value::as_str)
        })
        .collect()
}

fn nested_payload_values<'a>(record: &'a AuditRecord, paths: &[&[&str]]) -> Vec<&'a str> {
    paths
        .iter()
        .filter_map(|path| {
            let mut value = &record.event.payload;
            for segment in *path {
                value = value.get(*segment)?;
            }
            value.as_str()
        })
        .collect()
}

fn command_token_matches(token: &str, debug_command: &str) -> bool {
    token == debug_command
        || basename(token) == debug_command
        || basename(debug_command) == token
        || basename(token) == basename(debug_command)
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
        ActionKind::FileRead => "file_read",
        ActionKind::FileWrite => "file_write",
        ActionKind::ToolInvoke => "tool_invoke",
        ActionKind::SaaSMutation => "saas_mutation",
        ActionKind::DesktopInput => "desktop_input",
        ActionKind::InternalMutation => "internal_mutation",
        ActionKind::Unknown => "unknown",
    }
}
