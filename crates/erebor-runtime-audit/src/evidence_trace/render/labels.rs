use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ExecutionSurface, RuntimeEvent};
use erebor_runtime_policy::Decision;
use serde_json::Value;

use crate::evidence_trace::EvidenceRedactor;

#[derive(Clone, Copy, Debug)]
pub(super) struct EvidenceTraceRecordView<'a> {
    record: &'a AuditRecord,
}

impl<'a> EvidenceTraceRecordView<'a> {
    pub(super) const fn new(record: &'a AuditRecord) -> Self {
        Self { record }
    }

    pub(super) fn decision_label(self) -> String {
        self.record.final_decision.rule_id().map_or_else(
            || self.decision_type().to_owned(),
            |rule_id| format!("{} ({rule_id})", self.decision_type()),
        )
    }

    pub(super) fn decision_type(self) -> &'static str {
        decision_type(&self.record.final_decision)
    }

    pub(super) fn action_label(self) -> String {
        let event = &self.record.event;
        event
            .payload
            .get("method")
            .and_then(Value::as_str)
            .map_or_else(
                || action_name(&event.action).to_owned(),
                |method| format!("{} via {method}", action_name(&event.action)),
            )
    }

    pub(super) fn target_text(self) -> String {
        target_text(&self.record.event)
    }
}

pub(super) fn surface_name(surface: &ExecutionSurface) -> &'static str {
    match surface {
        ExecutionSurface::BrowserCdp => "browser_cdp",
        ExecutionSurface::Mcp => "mcp",
        ExecutionSurface::Terminal => "terminal",
        ExecutionSurface::Filesystem => "filesystem",
        ExecutionSurface::Network => "network",
        ExecutionSurface::SaaS => "saas",
        ExecutionSurface::Desktop => "desktop",
        ExecutionSurface::InternalSystem => "internal_system",
    }
}

pub(super) fn action_name(action: &ActionKind) -> &'static str {
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

fn decision_type(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
        Decision::RequireApproval { .. } => "require_approval",
        Decision::Mediate { .. } => "mediate",
    }
}

fn target_text(event: &RuntimeEvent) -> String {
    let target = event.target.as_ref();
    let uri = target
        .and_then(|target| target.uri.as_deref())
        .or_else(|| event.payload.get("url").and_then(Value::as_str))
        .or_else(|| event.payload.pointer("/params/url").and_then(Value::as_str))
        .or_else(|| {
            event
                .payload
                .pointer("/params/request/url")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .payload
                .get("governed_endpoint")
                .and_then(Value::as_str)
        });
    let label = target
        .and_then(|target| target.label.as_deref())
        .or_else(|| event.payload.get("label").and_then(Value::as_str))
        .or_else(|| event.payload.get("handler_id").and_then(Value::as_str));

    match (label, uri) {
        (Some(label), Some(uri)) => format!("{label} ({uri})"),
        (Some(label), None) => label.to_owned(),
        (None, Some(uri)) => uri.to_owned(),
        (None, None) => event
            .payload
            .get("argv_summary")
            .and_then(Value::as_str)
            .unwrap_or("(no target)")
            .to_owned(),
    }
}

pub(super) fn md(value: &str) -> String {
    EvidenceRedactor.markdown_cell(value)
}

pub(super) fn truncate(value: &str, limit: usize) -> String {
    EvidenceRedactor.truncate_markdown(value, limit)
}
