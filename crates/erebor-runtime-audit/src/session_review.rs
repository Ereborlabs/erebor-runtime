use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};
use erebor_runtime_policy::Decision;
use serde::Serialize;
use serde_json::Value;

use crate::{
    evidence_trace::{redact, sha256_hex},
    SessionReviewError,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionReviewArtifacts {
    runner: Option<String>,
    policy_sha256: Option<String>,
    config_sha256: Option<String>,
}

impl SessionReviewArtifacts {
    #[must_use]
    pub fn new(runner: Option<String>) -> Self {
        Self {
            runner,
            policy_sha256: None,
            config_sha256: None,
        }
    }

    pub fn from_paths(
        runner: Option<String>,
        policy: &Path,
        config: &Path,
    ) -> Result<Self, SessionReviewError> {
        Ok(Self {
            runner,
            policy_sha256: Some(file_sha256(policy)?),
            config_sha256: Some(file_sha256(config)?),
        })
    }

    #[must_use]
    pub fn runner(&self) -> Option<&str> {
        self.runner.as_deref()
    }

    #[must_use]
    pub fn policy_sha256(&self) -> Option<&str> {
        self.policy_sha256.as_deref()
    }

    #[must_use]
    pub fn config_sha256(&self) -> Option<&str> {
        self.config_sha256.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub status: String,
    pub actor: String,
    pub runner: String,
    pub surfaces: Vec<String>,
    pub allowed: usize,
    pub denied: usize,
    pub require_approval: usize,
    pub mediated: usize,
    pub max_risk: String,
    pub start: String,
    pub end: String,
    pub record_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionDecisionSummary {
    pub event_id: String,
    pub timestamp: String,
    pub surface: String,
    pub action: String,
    pub target: String,
    pub risk: String,
    pub rule_id: Option<String>,
    pub policy_decision: String,
    pub final_decision: String,
    pub reason: Option<String>,
    pub controlled_path_mode: String,
    pub controlled_path_backend: String,
    pub final_effect: String,
    pub upstream_reached: Option<bool>,
    pub raw_payload_sha256: String,
    pub policy_sha256: Option<String>,
    pub config_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionTimelineItem {
    pub event_id: String,
    pub timestamp: String,
    pub heading: String,
    pub surface: String,
    pub action: String,
    pub target: String,
    pub risk: String,
    pub rule_id: Option<String>,
    pub final_decision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionReview {
    pub summary: SessionSummary,
    pub important_decisions: Vec<SessionDecisionSummary>,
    pub timeline: Vec<SessionTimelineItem>,
    pub policy_sha256: Option<String>,
    pub config_sha256: Option<String>,
}

#[derive(Default)]
struct SessionAccumulator {
    actors: BTreeMap<String, usize>,
    surfaces: BTreeSet<String>,
    allowed: usize,
    denied: usize,
    require_approval: usize,
    mediated: usize,
    max_risk: Option<RiskLevel>,
    start: Option<String>,
    end: Option<String>,
    record_count: usize,
}

pub fn session_summaries(
    records: &[AuditRecord],
    artifacts: &SessionReviewArtifacts,
) -> Result<Vec<SessionSummary>, SessionReviewError> {
    if records.is_empty() {
        return Err(SessionReviewError::no_session_records());
    }

    let mut sessions = BTreeMap::<String, SessionAccumulator>::new();
    for record in records {
        let entry = sessions
            .entry(record.event.session_id.as_str().to_owned())
            .or_default();
        *entry
            .actors
            .entry(record.event.actor.id.clone())
            .or_default() += 1;
        entry
            .surfaces
            .insert(surface_name(&record.event.surface).to_owned());
        entry.record_count += 1;
        match &record.final_decision {
            Decision::Allow { .. } => entry.allowed += 1,
            Decision::Deny { .. } => entry.denied += 1,
            Decision::RequireApproval { .. } => entry.require_approval += 1,
            Decision::Mediate { .. } => entry.mediated += 1,
        }
        if entry
            .max_risk
            .as_ref()
            .is_none_or(|risk| record.event.risk.level.severity() > risk.severity())
        {
            entry.max_risk = Some(record.event.risk.level.clone());
        }
        update_time_bounds(entry, &record.event.timestamp);
    }

    let mut summaries = sessions
        .into_iter()
        .map(|(session_id, accumulator)| SessionSummary {
            session_id,
            status: String::from("recorded"),
            actor: dominant_actor(&accumulator.actors),
            runner: artifacts.runner().unwrap_or("unknown").to_owned(),
            surfaces: accumulator.surfaces.into_iter().collect(),
            allowed: accumulator.allowed,
            denied: accumulator.denied,
            require_approval: accumulator.require_approval,
            mediated: accumulator.mediated,
            max_risk: accumulator
                .max_risk
                .as_ref()
                .map_or("unknown", risk_name)
                .to_owned(),
            start: accumulator.start.unwrap_or_else(|| String::from("unknown")),
            end: accumulator.end.unwrap_or_else(|| String::from("unknown")),
            record_count: accumulator.record_count,
        })
        .collect::<Vec<_>>();

    summaries.sort_by(|left, right| {
        right
            .start
            .cmp(&left.start)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    Ok(summaries)
}

pub fn render_session_list(
    records: &[AuditRecord],
    artifacts: &SessionReviewArtifacts,
) -> Result<String, SessionReviewError> {
    let summaries = session_summaries(records, artifacts)?;
    let mut output = String::from(
        "SESSION       STATUS    ACTOR      RUNNER      SURFACES         ALLOW DENY APPROVAL MEDIATE RISK    START\n",
    );

    for summary in summaries {
        output.push_str(&format!(
            "{:<13} {:<9} {:<10} {:<11} {:<16} {:>5} {:>4} {:>8} {:>7} {:<7} {}\n",
            summary.session_id,
            summary.status,
            summary.actor,
            summary.runner,
            summary.surfaces.join(","),
            summary.allowed,
            summary.denied,
            summary.require_approval,
            summary.mediated,
            summary.max_risk,
            summary.start,
        ));
    }

    Ok(output)
}

pub fn review_session(
    records: &[AuditRecord],
    session_id: &str,
    artifacts: &SessionReviewArtifacts,
) -> Result<SessionReview, SessionReviewError> {
    let session_records = records_for_session(records, session_id)?;
    let summary = session_summaries_for_session(&session_records, artifacts);
    let important_decisions = key_records(&session_records)
        .into_iter()
        .map(|record| session_decision_summary(record, artifacts))
        .collect::<Vec<_>>();
    let mut timeline = session_records
        .iter()
        .map(|record| session_timeline_item(record))
        .collect::<Vec<_>>();
    timeline.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    Ok(SessionReview {
        summary,
        important_decisions,
        timeline,
        policy_sha256: artifacts.policy_sha256().map(str::to_owned),
        config_sha256: artifacts.config_sha256().map(str::to_owned),
    })
}

pub fn render_session_show(
    records: &[AuditRecord],
    session_id: &str,
    artifacts: &SessionReviewArtifacts,
) -> Result<String, SessionReviewError> {
    let session_records = records_for_session(records, session_id)?;
    let summary = session_summaries_for_session(&session_records, artifacts);
    let key_records = key_records(&session_records);
    let mut output = String::new();

    output.push_str(&format!("Session {}\n", summary.session_id));
    output.push_str(&format!("Actor: {}\n", summary.actor));
    output.push_str(&format!("Runner: {}\n", summary.runner));
    output.push_str("Status: recorded\n");
    output.push_str(&format!("Surfaces: {}\n", summary.surfaces.join(", ")));
    output.push_str(&format!(
        "Verdict: {} audit record(s), {} allowed, {} denied, {} approval-required, {} mediated; max risk {}\n\n",
        summary.record_count,
        summary.allowed,
        summary.denied,
        summary.require_approval,
        summary.mediated,
        summary.max_risk
    ));

    output.push_str("Summary\n");
    output.push_str(&summary_sentence(&summary, key_records.first().copied()));
    output.push_str("\n\nKey Decisions\n");
    for record in key_records.iter().take(8) {
        output.push_str(&format_key_event_line(record));
        output.push('\n');
    }

    if let Some(record) = key_records.first() {
        output.push_str("\nMost Important Rule\n");
        output.push_str(record_rule_id(record).unwrap_or("none"));
        output.push('\n');
        if let Some(reason) = decision_reason(&record.policy_decision)
            .or_else(|| decision_reason(&record.final_decision))
        {
            output.push_str(reason);
            output.push('\n');
        }
    }

    output.push_str("\nProof Summary\n");
    output.push_str("- Audit JSONL is the source of truth for this session review.\n");
    if let Some(policy_sha256) = artifacts.policy_sha256() {
        output.push_str(&format!("- Policy sha256: {policy_sha256}\n"));
    }
    if let Some(config_sha256) = artifacts.config_sha256() {
        output.push_str(&format!("- Config sha256: {config_sha256}\n"));
    }
    output.push_str("- Use `erebor session describe` for controlled-path details.\n");

    Ok(output)
}

pub fn render_session_describe(
    records: &[AuditRecord],
    session_id: &str,
    artifacts: &SessionReviewArtifacts,
) -> Result<String, SessionReviewError> {
    let session_records = records_for_session(records, session_id)?;
    let key_records = key_records(&session_records);
    let described = if key_records.is_empty() {
        session_records
    } else {
        key_records
    };
    let mut output = String::new();

    output.push_str(&format!("Session {}\n\n", session_id));
    for record in described {
        output.push_str(&format!("{} Event\n", event_heading(record)));
        output.push_str(&format!("Audit record id: {}\n", record.event.id.as_str()));
        output.push_str(&format!("Action: {}\n", action_name(&record.event.action)));
        output.push_str(&format!(
            "Surface: {}\n",
            surface_name(&record.event.surface)
        ));
        output.push_str(&format!("Target: {}\n", target_summary(record)));
        output.push_str(&format!("Risk: {}\n", risk_name(&record.event.risk.level)));
        output.push_str(&format!(
            "Rule: {}\n",
            record_rule_id(record).unwrap_or("none")
        ));
        output.push_str(&format!(
            "Policy decision: {}\n",
            decision_name(&record.policy_decision)
        ));
        output.push_str(&format!(
            "Final decision: {}\n\n",
            decision_name(&record.final_decision)
        ));

        output.push_str("Controlled Path\n");
        output.push_str(&format!("Mode: {}\n", inferred_mode(record)));
        output.push_str(&format!("Backend: {}\n", inferred_backend(record)));
        output.push_str(&format!(
            "Final effect: {}\n",
            inferred_final_effect(record)
        ));
        if let Some(upstream_reached) = inferred_upstream_reached(record) {
            output.push_str(&format!("Upstream reached: {upstream_reached}\n"));
        }

        output.push_str("\nProof\n");
        output.push_str(&format!(
            "Raw payload sha256: {}\n",
            sha256_hex(record.event.payload.to_string().as_bytes())
        ));
        if let Some(policy_sha256) = artifacts.policy_sha256() {
            output.push_str(&format!("Policy sha256: {policy_sha256}\n"));
        }
        if let Some(config_sha256) = artifacts.config_sha256() {
            output.push_str(&format!("Config sha256: {config_sha256}\n"));
        }
        output.push('\n');
    }

    Ok(output)
}

fn session_summaries_for_session(
    records: &[&AuditRecord],
    artifacts: &SessionReviewArtifacts,
) -> SessionSummary {
    let owned_records = records
        .iter()
        .map(|record| (*record).clone())
        .collect::<Vec<_>>();
    session_summaries(&owned_records, artifacts)
        .ok()
        .and_then(|mut summaries| summaries.pop())
        .unwrap_or_else(|| SessionSummary {
            session_id: String::from("unknown"),
            status: String::from("recorded"),
            actor: String::from("unknown"),
            runner: artifacts.runner().unwrap_or("unknown").to_owned(),
            surfaces: Vec::new(),
            allowed: 0,
            denied: 0,
            require_approval: 0,
            mediated: 0,
            max_risk: String::from("unknown"),
            start: String::from("unknown"),
            end: String::from("unknown"),
            record_count: 0,
        })
}

fn records_for_session<'a>(
    records: &'a [AuditRecord],
    session_id: &str,
) -> Result<Vec<&'a AuditRecord>, SessionReviewError> {
    if records.is_empty() {
        return Err(SessionReviewError::no_session_records());
    }
    let session_records = records
        .iter()
        .filter(|record| record.event.session_id.as_str() == session_id)
        .collect::<Vec<_>>();
    if session_records.is_empty() {
        Err(SessionReviewError::unknown_session(session_id))
    } else {
        Ok(session_records)
    }
}

fn session_decision_summary(
    record: &AuditRecord,
    artifacts: &SessionReviewArtifacts,
) -> SessionDecisionSummary {
    SessionDecisionSummary {
        event_id: record.event.id.as_str().to_owned(),
        timestamp: record.event.timestamp.clone(),
        surface: surface_name(&record.event.surface).to_owned(),
        action: action_name(&record.event.action).to_owned(),
        target: target_summary(record),
        risk: risk_name(&record.event.risk.level).to_owned(),
        rule_id: record_rule_id(record).map(str::to_owned),
        policy_decision: decision_name(&record.policy_decision).to_owned(),
        final_decision: decision_name(&record.final_decision).to_owned(),
        reason: decision_reason(&record.final_decision)
            .or_else(|| decision_reason(&record.policy_decision))
            .map(str::to_owned),
        controlled_path_mode: inferred_mode(record).to_owned(),
        controlled_path_backend: inferred_backend(record).to_owned(),
        final_effect: inferred_final_effect(record).to_owned(),
        upstream_reached: inferred_upstream_reached(record),
        raw_payload_sha256: sha256_hex(record.event.payload.to_string().as_bytes()),
        policy_sha256: artifacts.policy_sha256().map(str::to_owned),
        config_sha256: artifacts.config_sha256().map(str::to_owned),
    }
}

fn session_timeline_item(record: &AuditRecord) -> SessionTimelineItem {
    SessionTimelineItem {
        event_id: record.event.id.as_str().to_owned(),
        timestamp: record.event.timestamp.clone(),
        heading: event_heading(record).to_owned(),
        surface: surface_name(&record.event.surface).to_owned(),
        action: action_name(&record.event.action).to_owned(),
        target: target_summary(record),
        risk: risk_name(&record.event.risk.level).to_owned(),
        rule_id: record_rule_id(record).map(str::to_owned),
        final_decision: decision_name(&record.final_decision).to_owned(),
    }
}

fn file_sha256(path: &Path) -> Result<String, SessionReviewError> {
    let bytes = fs::read(path).map_err(|source| SessionReviewError::read_file(path, source))?;
    Ok(sha256_hex(&bytes))
}

fn update_time_bounds(accumulator: &mut SessionAccumulator, timestamp: &str) {
    if accumulator
        .start
        .as_ref()
        .is_none_or(|start| timestamp < start.as_str())
    {
        accumulator.start = Some(timestamp.to_owned());
    }
    if accumulator
        .end
        .as_ref()
        .is_none_or(|end| timestamp > end.as_str())
    {
        accumulator.end = Some(timestamp.to_owned());
    }
}

fn dominant_actor(actors: &BTreeMap<String, usize>) -> String {
    actors
        .iter()
        .max_by_key(|(actor, count)| (*count, std::cmp::Reverse((*actor).clone())))
        .map_or_else(|| String::from("unknown"), |(actor, _count)| actor.clone())
}

fn key_records<'a>(records: &[&'a AuditRecord]) -> Vec<&'a AuditRecord> {
    let mut key = records
        .iter()
        .copied()
        .filter(|record| {
            !matches!(&record.final_decision, Decision::Allow { .. })
                || !matches!(&record.policy_decision, Decision::Allow { .. })
                || record.event.risk.level == RiskLevel::High
                || matches!(
                    record.event.action,
                    ActionKind::BrowserNavigate
                        | ActionKind::NetworkRequest
                        | ActionKind::ProcessExec
                        | ActionKind::ToolInvoke
                        | ActionKind::SaaSMutation
                        | ActionKind::InternalMutation
                )
        })
        .collect::<Vec<_>>();
    key.sort_by(|left, right| {
        left.event
            .timestamp
            .cmp(&right.event.timestamp)
            .then_with(|| left.event.id.as_str().cmp(right.event.id.as_str()))
    });
    key
}

fn summary_sentence(summary: &SessionSummary, key_record: Option<&AuditRecord>) -> String {
    if let Some(record) = key_record {
        let decision = decision_past_tense(&record.final_decision);
        let rule = record_rule_id(record).unwrap_or("no matching rule");
        format!(
            "{} attempted {} on {}. Erebor {} it by rule `{}`.",
            summary.actor,
            action_name(&record.event.action),
            target_summary(record),
            decision,
            rule
        )
    } else {
        format!(
            "Erebor recorded {} action(s) for this session with no denied or mediated key events.",
            summary.record_count
        )
    }
}

fn format_key_event_line(record: &AuditRecord) -> String {
    format!(
        "{} {:<8} {:<16} {}{}",
        record.event.timestamp,
        decision_name(&record.final_decision),
        action_name(&record.event.action),
        truncate(&target_summary(record), 72),
        record_rule_id(record).map_or_else(String::new, |rule| format!(" ({rule})"))
    )
}

fn event_heading(record: &AuditRecord) -> &'static str {
    match &record.final_decision {
        Decision::Allow { .. } => "Allowed",
        Decision::Deny { .. } => "Denied",
        Decision::RequireApproval { .. } => "Approval-Required",
        Decision::Mediate { .. } => "Mediated",
    }
}

fn record_rule_id(record: &AuditRecord) -> Option<&str> {
    record
        .final_decision
        .rule_id()
        .or_else(|| record.policy_decision.rule_id())
}

fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
        Decision::RequireApproval { .. } => "require_approval",
        Decision::Mediate { .. } => "mediate",
    }
}

fn decision_past_tense(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow { .. } => "allowed",
        Decision::Deny { .. } => "denied",
        Decision::RequireApproval { .. } => "held for approval",
        Decision::Mediate { .. } => "mediated",
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

fn target_summary(record: &AuditRecord) -> String {
    if let Some(target) = record.event.target.as_ref() {
        if let Some(uri) = target.uri.as_deref() {
            return redact(uri);
        }
        if let Some(label) = target.label.as_deref() {
            return redact(label);
        }
    }
    command_summary(&record.event.payload)
        .map(|command| redact(&command))
        .unwrap_or_else(|| String::from("unknown target"))
}

fn command_summary(payload: &Value) -> Option<String> {
    let command = payload.get("command")?.as_array()?;
    let mut parts = Vec::new();
    for argument in command {
        if let Some(argument) = argument.as_str() {
            parts.push(argument.to_owned());
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn inferred_mode(record: &AuditRecord) -> &'static str {
    match record.event.surface {
        ExecutionSurface::BrowserCdp | ExecutionSurface::Terminal => "enforced",
        _ => "observed",
    }
}

fn inferred_backend(record: &AuditRecord) -> &'static str {
    match (&record.event.surface, &record.event.action) {
        (ExecutionSurface::Terminal, ActionKind::ProcessExec) => {
            if is_linux_ptrace_process_record(&record.event.payload) {
                "linux_ptrace_process_guard"
            } else {
                "terminal_process_guard"
            }
        }
        (ExecutionSurface::Terminal, _) => "terminal_process_guard",
        (ExecutionSurface::BrowserCdp, ActionKind::NetworkRequest) => "browser_cdp_observer",
        (ExecutionSurface::BrowserCdp, _) => "browser_cdp_proxy",
        (ExecutionSurface::Mcp, _) => "mcp_gateway",
        (ExecutionSurface::Network, _) => "network_guard",
        (ExecutionSurface::SaaS, _) => "saas_gateway",
        (ExecutionSurface::Desktop, _) => "desktop_guard",
        (ExecutionSurface::InternalSystem, _) => "internal_system_gateway",
    }
}

fn is_linux_ptrace_process_record(payload: &Value) -> bool {
    payload
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "process_interception")
        || payload
            .pointer("/terminal/interception_path")
            .and_then(Value::as_str)
            .is_some_and(|path| path == "linux_ptrace")
}

fn inferred_final_effect(record: &AuditRecord) -> &'static str {
    match (
        &record.final_decision,
        &record.event.surface,
        &record.event.action,
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

fn inferred_upstream_reached(record: &AuditRecord) -> Option<bool> {
    match &record.final_decision {
        Decision::Deny { .. } | Decision::RequireApproval { .. } => Some(false),
        Decision::Allow { .. } | Decision::Mediate { .. } => None,
    }
}

fn surface_name(surface: &ExecutionSurface) -> &'static str {
    match surface {
        ExecutionSurface::BrowserCdp => "browser_cdp",
        ExecutionSurface::Mcp => "mcp",
        ExecutionSurface::Terminal => "terminal",
        ExecutionSurface::Network => "network",
        ExecutionSurface::SaaS => "saas",
        ExecutionSurface::Desktop => "desktop",
        ExecutionSurface::InternalSystem => "internal_system",
    }
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

fn risk_name(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Unknown => "unknown",
    }
}

fn truncate(text: &str, limit: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= limit {
        return text.to_owned();
    }
    let keep = limit.saturating_sub(3);
    let mut output = text.chars().take(keep).collect::<String>();
    output.push_str("...");
    output
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use erebor_runtime_core::AuditRecord;
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
        RuntimeEvent, SessionId, TargetRef,
    };
    use erebor_runtime_policy::Decision;
    use serde_json::json;

    use super::{
        render_session_describe, render_session_list, render_session_show, review_session,
        session_summaries, SessionReviewArtifacts,
    };

    #[test]
    fn session_list_groups_records_by_session() -> Result<(), Box<dyn std::error::Error>> {
        let records = vec![
            browser_record(
                "session-1",
                "allow-nav",
                ActionKind::BrowserNavigate,
                "https://example.test",
                Decision::Allow { rule_id: None },
                "2026-06-21T18:00:00Z",
            ),
            process_record(
                "session-1",
                "deny-process",
                "sh --remote-debugging-port=9222",
                Decision::Deny {
                    reason: String::from("raw CDP denied"),
                    rule_id: Some(String::from("deny-raw-cdp")),
                },
                "2026-06-21T18:00:01Z",
            ),
            process_record(
                "session-2",
                "allow-process",
                "grep oauth logs",
                Decision::Allow { rule_id: None },
                "2026-06-21T18:01:00Z",
            ),
        ];

        let summaries = session_summaries(
            &records,
            &SessionReviewArtifacts::new(Some(String::from("linux-host"))),
        )?;

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].session_id, "session-2");
        assert_eq!(summaries[1].session_id, "session-1");
        assert_eq!(summaries[1].allowed, 1);
        assert_eq!(summaries[1].denied, 1);
        assert_eq!(summaries[1].max_risk, "high");
        Ok(())
    }

    #[test]
    fn session_renderers_include_decision_context_and_hashes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = temp_file("policy.json", r#"{"rules":[]}"#)?;
        let config = temp_file("config.json", r#"{"session":{"enabled":true}}"#)?;
        let artifacts =
            SessionReviewArtifacts::from_paths(Some(String::from("linux-host")), &policy, &config)?;
        let records = vec![process_record(
            "session-1",
            "deny-process",
            "sh --remote-debugging-port=9222",
            Decision::Deny {
                reason: String::from("raw CDP process launch is denied"),
                rule_id: Some(String::from("deny-raw-cdp")),
            },
            "2026-06-21T18:00:01Z",
        )];

        let list = render_session_list(&records, &artifacts)?;
        let show = render_session_show(&records, "session-1", &artifacts)?;
        let describe = render_session_describe(&records, "session-1", &artifacts)?;
        let review = review_session(&records, "session-1", &artifacts)?;

        assert!(list.contains("session-1"));
        assert!(list.contains("linux-host"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
        assert!(describe.contains("Denied Event"));
        assert!(describe.contains("linux_ptrace_process_guard"));
        assert!(describe.contains("exec_denied_before_child_gained_authority"));
        assert!(describe.contains("Raw payload sha256:"));
        assert_eq!(review.summary.session_id, "session-1");
        assert_eq!(review.important_decisions.len(), 1);
        assert_eq!(
            review.important_decisions[0].controlled_path_backend,
            "linux_ptrace_process_guard"
        );
        assert_eq!(review.timeline.len(), 1);
        assert!(review.policy_sha256.is_some());
        assert!(review.config_sha256.is_some());

        let _result = fs::remove_file(policy);
        let _result = fs::remove_file(config);
        Ok(())
    }

    #[test]
    fn show_redacts_sensitive_query_values() -> Result<(), Box<dyn std::error::Error>> {
        let records = vec![browser_record(
            "session-1",
            "deny-callback",
            ActionKind::NetworkRequest,
            "http://127.0.0.1:5105/oauth/callback?code=secret&state=secret",
            Decision::Deny {
                reason: String::from("callback denied"),
                rule_id: Some(String::from("deny-oauth-callback-network-request")),
            },
            "2026-06-21T18:00:01Z",
        )];

        let show = render_session_show(&records, "session-1", &SessionReviewArtifacts::default())?;

        assert!(show.contains("code=redacted"));
        assert!(show.contains("state=redacted"));
        assert!(!show.contains("code=secret"));
        Ok(())
    }

    struct RecordFixture<'a> {
        session_id: &'a str,
        id: &'a str,
        surface: ExecutionSurface,
        action: ActionKind,
        target: &'a str,
        risk: RiskLevel,
        final_decision: Decision,
        timestamp: &'a str,
    }

    fn browser_record(
        session_id: &str,
        id: &str,
        action: ActionKind,
        target: &str,
        final_decision: Decision,
        timestamp: &str,
    ) -> AuditRecord {
        record(RecordFixture {
            session_id,
            id,
            surface: ExecutionSurface::BrowserCdp,
            action,
            target,
            risk: risk_for_decision(&final_decision),
            final_decision,
            timestamp,
        })
    }

    fn process_record(
        session_id: &str,
        id: &str,
        target: &str,
        final_decision: Decision,
        timestamp: &str,
    ) -> AuditRecord {
        record(RecordFixture {
            session_id,
            id,
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ProcessExec,
            target,
            risk: risk_for_decision(&final_decision),
            final_decision,
            timestamp,
        })
    }

    fn record(fixture: RecordFixture<'_>) -> AuditRecord {
        let payload = if matches!(&fixture.surface, ExecutionSurface::Terminal) {
            json!({
                "kind": "process_interception",
                "command": fixture.target.split_whitespace().collect::<Vec<_>>()
            })
        } else {
            json!({ "target": fixture.target })
        };

        AuditRecord {
            event: RuntimeEvent {
                id: EventId::new(fixture.id),
                session_id: SessionId::new(fixture.session_id),
                actor: ActorIdentity {
                    id: String::from("test-agent"),
                    kind: ActorKind::Agent,
                },
                surface: fixture.surface,
                action: fixture.action,
                target: Some(TargetRef {
                    label: Some(fixture.target.to_owned()),
                    uri: None,
                }),
                payload,
                risk: RiskMetadata {
                    level: fixture.risk,
                    reasons: vec![String::from("test")],
                },
                timestamp: fixture.timestamp.to_owned(),
            },
            policy_decision: fixture.final_decision.clone(),
            final_decision: fixture.final_decision,
        }
    }

    fn risk_for_decision(decision: &Decision) -> RiskLevel {
        match decision {
            Decision::Allow { .. } => RiskLevel::Low,
            Decision::Deny { .. } | Decision::RequireApproval { .. } | Decision::Mediate { .. } => {
                RiskLevel::High
            }
        }
    }

    fn temp_file(name: &str, content: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-session-review-{nanos}-{}-{name}",
            std::process::id()
        ));
        fs::write(&path, content)?;
        Ok(path)
    }
}
