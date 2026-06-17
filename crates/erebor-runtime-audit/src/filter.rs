use erebor_runtime_core::{
    AuditCommandLogLevel, AuditError, AuditRecord, AuditSink, RuntimeAuditConfig,
    RuntimeAuditSurfaceLoggingConfig,
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
    let logging = match record.event.surface {
        ExecutionSurface::BrowserCdp => surfaces.browser_cdp(),
        ExecutionSurface::Mcp => surfaces.mcp(),
        ExecutionSurface::Terminal => surfaces.terminal(),
        ExecutionSurface::Network => surfaces.network(),
        ExecutionSurface::SaaS => surfaces.saas(),
        ExecutionSurface::Desktop => surfaces.desktop(),
        ExecutionSurface::InternalSystem => surfaces.internal_system(),
    };

    if is_signal_decision(record) {
        return true;
    }

    match logging.command_level() {
        AuditCommandLogLevel::All => true,
        AuditCommandLogLevel::NonAllow => false,
        AuditCommandLogLevel::Signal => !matches_debug_command(record, logging.debug_commands()),
    }
}

fn is_signal_decision(record: &AuditRecord) -> bool {
    !matches!(record.policy_decision, Decision::Allow { .. })
        || !matches!(record.final_decision, Decision::Allow { .. })
}

fn matches_debug_command(record: &AuditRecord, debug_commands: &[String]) -> bool {
    if debug_commands.is_empty() {
        return false;
    }

    record_command_tokens(record).iter().any(|token| {
        debug_commands
            .iter()
            .any(|debug_command| command_token_matches(token, debug_command))
    })
}

fn record_command_tokens(record: &AuditRecord) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(command) = record
        .event
        .payload
        .get("command")
        .and_then(serde_json::Value::as_array)
        .and_then(|command| command.first())
        .and_then(serde_json::Value::as_str)
    {
        tokens.push(command.to_owned());
    }
    if let Some(method) = record
        .event
        .payload
        .get("method")
        .and_then(serde_json::Value::as_str)
    {
        tokens.push(method.to_owned());
    }
    if let Some(argv_summary) = record
        .event
        .payload
        .get("argv_summary")
        .and_then(serde_json::Value::as_str)
        .and_then(|summary| summary.split_whitespace().next())
    {
        tokens.push(argv_summary.to_owned());
    }
    if let Some(label) = record
        .event
        .target
        .as_ref()
        .and_then(|target| target.label.as_deref())
    {
        tokens.push(label.to_owned());
    }
    tokens.push(action_name(&record.event.action).to_owned());
    tokens
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
