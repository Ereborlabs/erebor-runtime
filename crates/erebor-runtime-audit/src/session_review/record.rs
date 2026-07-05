use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};
use erebor_runtime_policy::Decision;
use serde_json::Value;

use crate::evidence_trace::{EvidenceHasher, EvidenceRedactor};

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionReviewRecord<'a> {
    record: &'a AuditRecord,
}

impl<'a> SessionReviewRecord<'a> {
    pub(crate) const fn new(record: &'a AuditRecord) -> Self {
        Self { record }
    }

    pub(crate) fn event_heading(self) -> &'static str {
        match &self.record.final_decision {
            Decision::Allow { .. } => "Allowed",
            Decision::Deny { .. } => "Denied",
            Decision::RequireApproval { .. } => "Approval-Required",
            Decision::Mediate { .. } => "Mediated",
        }
    }

    pub(crate) fn rule_id(self) -> Option<&'a str> {
        self.record
            .final_decision
            .rule_id()
            .or_else(|| self.record.policy_decision.rule_id())
    }

    pub(crate) fn decision_name(self) -> &'static str {
        decision_name(&self.record.final_decision)
    }

    pub(crate) fn policy_decision_name(self) -> &'static str {
        decision_name(&self.record.policy_decision)
    }

    pub(crate) fn decision_reason(self) -> Option<&'a str> {
        decision_reason(&self.record.final_decision)
            .or_else(|| decision_reason(&self.record.policy_decision))
    }

    pub(crate) fn decision_past_tense(self) -> &'static str {
        match &self.record.final_decision {
            Decision::Allow { .. } => "allowed",
            Decision::Deny { .. } => "denied",
            Decision::RequireApproval { .. } => "held for approval",
            Decision::Mediate { .. } => "mediated",
        }
    }

    pub(crate) fn surface_name(self) -> &'static str {
        surface_name(&self.record.event.surface)
    }

    pub(crate) fn action_name(self) -> &'static str {
        action_name(&self.record.event.action)
    }

    pub(crate) fn risk_name(self) -> &'static str {
        risk_name(&self.record.event.risk.level)
    }

    pub(crate) fn target_summary(self) -> String {
        if let Some(target) = self.record.event.target.as_ref() {
            if let Some(uri) = target.uri.as_deref() {
                return EvidenceRedactor.redact(uri);
            }
            if let Some(label) = target.label.as_deref() {
                return EvidenceRedactor.redact(label);
            }
        }
        self.command_summary()
            .map(|command| EvidenceRedactor.redact(&command))
            .unwrap_or_else(|| String::from("unknown target"))
    }

    pub(crate) fn inferred_mode(self) -> &'static str {
        match self.record.event.surface {
            ExecutionSurface::BrowserCdp
            | ExecutionSurface::Terminal
            | ExecutionSurface::Filesystem => "enforced",
            _ => "observed",
        }
    }

    pub(crate) fn inferred_backend(self) -> &'static str {
        match (&self.record.event.surface, &self.record.event.action) {
            (ExecutionSurface::Terminal, ActionKind::ProcessExec) => {
                if self.is_linux_ptrace_process_record() {
                    "linux_ptrace_process_guard"
                } else {
                    "terminal_process_guard"
                }
            }
            (ExecutionSurface::Terminal, _) => "terminal_process_guard",
            (ExecutionSurface::Filesystem, _) => "filesystem_surface",
            (ExecutionSurface::BrowserCdp, ActionKind::NetworkRequest) => "browser_cdp_observer",
            (ExecutionSurface::BrowserCdp, _) => "browser_cdp_proxy",
            (ExecutionSurface::Mcp, _) => "mcp_gateway",
            (ExecutionSurface::Network, _) => "network_guard",
            (ExecutionSurface::SaaS, _) => "saas_gateway",
            (ExecutionSurface::Desktop, _) => "desktop_guard",
            (ExecutionSurface::InternalSystem, _) => "internal_system_gateway",
        }
    }

    pub(crate) fn inferred_final_effect(self) -> &'static str {
        match (
            &self.record.final_decision,
            &self.record.event.surface,
            &self.record.event.action,
        ) {
            (Decision::Allow { .. }, _, _) => "allowed",
            (Decision::Deny { .. }, ExecutionSurface::Terminal, ActionKind::ProcessExec) => {
                "exec_denied_before_child_gained_authority"
            }
            (Decision::Deny { .. }, ExecutionSurface::BrowserCdp, ActionKind::NetworkRequest) => {
                "blocked_before_upstream"
            }
            (Decision::Deny { .. }, _, _) => "blocked_before_effect",
            (Decision::RequireApproval { .. }, _, _) => "approval_held_no_effect",
            (Decision::Mediate { .. }, _, _) => "mediated_to_governed_endpoint",
        }
    }

    pub(crate) fn inferred_upstream_reached(self) -> Option<bool> {
        match &self.record.final_decision {
            Decision::Deny { .. } | Decision::RequireApproval { .. } => Some(false),
            Decision::Allow { .. } | Decision::Mediate { .. } => None,
        }
    }

    pub(crate) fn raw_payload_sha256(self) -> String {
        EvidenceHasher::sha256_hex(self.record.event.payload.to_string().as_bytes())
    }

    fn command_summary(self) -> Option<String> {
        let command = self.record.event.payload.get("command")?.as_array()?;
        let parts = command
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    fn is_linux_ptrace_process_record(self) -> bool {
        self.record
            .event
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind == "process_interception")
            || self
                .record
                .event
                .payload
                .pointer("/terminal/interception_path")
                .and_then(Value::as_str)
                .is_some_and(|path| path == "linux_ptrace")
    }
}

pub(crate) fn surface_name(surface: &ExecutionSurface) -> &'static str {
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

pub(crate) fn action_name(action: &ActionKind) -> &'static str {
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

pub(crate) fn truncate(text: &str, limit: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= limit {
        return text.to_owned();
    }
    let keep = limit.saturating_sub(3);
    let mut output = text.chars().take(keep).collect::<String>();
    output.push_str("...");
    output
}

fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
        Decision::RequireApproval { .. } => "require_approval",
        Decision::Mediate { .. } => "mediate",
    }
}

fn decision_reason(decision: &Decision) -> Option<&str> {
    match decision {
        Decision::Allow { .. } => None,
        Decision::Deny { reason, .. }
        | Decision::RequireApproval { reason, .. }
        | Decision::Mediate { reason, .. } => Some(reason.as_str()),
    }
}

pub(crate) fn risk_name(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Unknown => "unknown",
    }
}
