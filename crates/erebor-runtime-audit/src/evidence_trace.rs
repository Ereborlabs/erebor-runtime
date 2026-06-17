//! Evidence traces derived from governed session audit logs.
//!
//! JSONL audit records are the source of truth. This module turns those records,
//! plus the policy/config artifacts for the same run, into DPO-readable evidence
//! traces and routes them through sink abstractions.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ActorIdentity, ActorKind, ExecutionSurface, RuntimeEvent};
use erebor_runtime_policy::Decision;
use serde_json::Value;

use crate::{read_audit_records, EvidenceTraceError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceArtifact {
    label: String,
    path: PathBuf,
    sha256: String,
}

impl EvidenceTraceArtifact {
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        path: impl Into<PathBuf>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            path: path.into(),
            sha256: sha256.into(),
        }
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceTraceRequest {
    records: Vec<AuditRecord>,
    policy: Value,
    config: Value,
    artifacts: Vec<EvidenceTraceArtifact>,
    session_id: Option<String>,
    purpose: String,
}

impl EvidenceTraceRequest {
    #[must_use]
    pub fn new(
        records: Vec<AuditRecord>,
        policy: Value,
        config: Value,
        artifacts: Vec<EvidenceTraceArtifact>,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            records,
            policy,
            config,
            artifacts,
            session_id: None,
            purpose: purpose.into(),
        }
    }

    pub fn from_paths(paths: EvidenceTracePaths) -> Result<Self, EvidenceTraceError> {
        let records = read_audit_records(&paths.audit).map_err(EvidenceTraceError::audit_log)?;
        let policy = read_json(&paths.policy)?;
        let config = read_json(&paths.config)?;
        let mut artifacts = vec![
            file_artifact("Audit JSONL", &paths.audit)?,
            file_artifact("Policy package", &paths.policy)?,
            file_artifact("Session config", &paths.config)?,
        ];
        if let Some(prompt) = paths.prompt.as_ref() {
            artifacts.push(file_artifact("Prompt", prompt)?);
        }

        Ok(Self {
            records,
            policy,
            config,
            artifacts,
            session_id: paths.session_id,
            purpose: paths.purpose,
        })
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTracePaths {
    pub audit: PathBuf,
    pub policy: PathBuf,
    pub config: PathBuf,
    pub prompt: Option<PathBuf>,
    pub session_id: Option<String>,
    pub purpose: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceReport {
    session_id: String,
    markdown: String,
    sha256: String,
}

impl EvidenceTraceReport {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.markdown
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceReceipt {
    destination: String,
    bytes_written: usize,
    report_sha256: String,
}

impl EvidenceTraceReceipt {
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        bytes_written: usize,
        report_sha256: impl Into<String>,
    ) -> Self {
        Self {
            destination: destination.into(),
            bytes_written,
            report_sha256: report_sha256.into(),
        }
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    #[must_use]
    pub fn report_sha256(&self) -> &str {
        &self.report_sha256
    }
}

pub trait EvidenceTraceSink {
    fn send(
        &self,
        report: &EvidenceTraceReport,
    ) -> Result<EvidenceTraceReceipt, EvidenceTraceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEvidenceTraceSink {
    path: PathBuf,
}

impl FileEvidenceTraceSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EvidenceTraceSink for FileEvidenceTraceSink {
    fn send(
        &self,
        report: &EvidenceTraceReport,
    ) -> Result<EvidenceTraceReceipt, EvidenceTraceError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|source| EvidenceTraceError::write_file(parent, source))?;
        }
        fs::write(&self.path, report.markdown())
            .map_err(|source| EvidenceTraceError::write_file(&self.path, source))?;
        Ok(EvidenceTraceReceipt::new(
            self.path.display().to_string(),
            report.markdown().len(),
            report.sha256(),
        ))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MarkdownEvidenceTraceRenderer;

impl MarkdownEvidenceTraceRenderer {
    pub fn render(
        &self,
        request: &EvidenceTraceRequest,
    ) -> Result<EvidenceTraceReport, EvidenceTraceError> {
        let session_id = select_session_id(&request.records, request.session_id.as_deref())?;
        let records = request
            .records
            .iter()
            .filter(|record| record.event.session_id.as_str() == session_id)
            .cloned()
            .collect::<Vec<_>>();
        let markdown_without_report_hash = render_markdown_body(&session_id, &records, request);
        let report_hash = sha256_hex(markdown_without_report_hash.as_bytes());
        let markdown = format!(
            "{markdown_without_report_hash}| Report body | generated markdown before this hash row | `{report_hash}` |\n\n"
        );
        Ok(EvidenceTraceReport {
            session_id,
            markdown,
            sha256: report_hash,
        })
    }
}

fn read_json(path: &Path) -> Result<Value, EvidenceTraceError> {
    let source =
        fs::read_to_string(path).map_err(|source| EvidenceTraceError::read_file(path, source))?;
    serde_json::from_str(&source).map_err(|source| EvidenceTraceError::invalid_json(path, source))
}

fn file_artifact(label: &str, path: &Path) -> Result<EvidenceTraceArtifact, EvidenceTraceError> {
    let bytes = fs::read(path).map_err(|source| EvidenceTraceError::read_file(path, source))?;
    Ok(EvidenceTraceArtifact::new(
        label,
        path.to_path_buf(),
        sha256_hex(&bytes),
    ))
}

fn select_session_id(
    records: &[AuditRecord],
    requested: Option<&str>,
) -> Result<String, EvidenceTraceError> {
    if let Some(requested) = requested {
        if records
            .iter()
            .any(|record| record.event.session_id.as_str() == requested)
        {
            return Ok(requested.to_owned());
        }
        return Err(EvidenceTraceError::unknown_session(requested));
    }

    let mut summaries = BTreeMap::<&str, SessionSummary>::new();
    for (index, record) in records.iter().enumerate() {
        let entry = summaries
            .entry(record.event.session_id.as_str())
            .or_default();
        entry.last_index = index;
        entry.record_count += 1;
        if record.event.surface == ExecutionSurface::BrowserCdp {
            entry.browser_count += 1;
        }
        if !matches!(record.final_decision, Decision::Allow { .. }) {
            entry.non_allow_count += 1;
        }
    }

    summaries
        .into_iter()
        .max_by_key(|(_session_id, summary)| {
            (
                summary.browser_count > 0 && summary.non_allow_count > 0,
                summary.browser_count > 0,
                summary.last_index,
            )
        })
        .map(|(session_id, _summary)| session_id.to_owned())
        .ok_or_else(EvidenceTraceError::no_session_records)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SessionSummary {
    last_index: usize,
    record_count: usize,
    browser_count: usize,
    non_allow_count: usize,
}

fn render_markdown_body(
    session_id: &str,
    records: &[AuditRecord],
    request: &EvidenceTraceRequest,
) -> String {
    let actor = records.first().map(|record| &record.event.actor);
    let first_timestamp = records
        .first()
        .map_or("unknown", |record| record.event.timestamp.as_str());
    let last_timestamp = records
        .last()
        .map_or("unknown", |record| record.event.timestamp.as_str());
    let allowed = records
        .iter()
        .filter(|record| matches!(record.final_decision, Decision::Allow { .. }))
        .count();
    let denied = records
        .iter()
        .filter(|record| matches!(record.final_decision, Decision::Deny { .. }))
        .count();
    let held = records
        .iter()
        .filter(|record| matches!(record.final_decision, Decision::RequireApproval { .. }))
        .count();
    let mediated = records
        .iter()
        .filter(|record| matches!(record.policy_decision, Decision::Mediate { .. }))
        .count();
    let rule_ids = observed_rule_ids(records);
    let allowed_timeline = records
        .iter()
        .filter(|record| interesting_allowed(record))
        .cloned()
        .collect::<Vec<_>>();
    let transitions = records
        .iter()
        .filter(|record| authority_transition(record))
        .cloned()
        .collect::<Vec<_>>();
    let runner = request
        .config
        .pointer("/session/runner/kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    format!(
        r#"# Governed OpenClaw Evidence Trace

## Executive Summary

This trace summarizes one governed OpenClaw run inside Erebor Runtime. The run
used a shared session audit to record browser CDP and terminal/process actions
under one session id. The strongest evidence in this report is action/resource
provenance: what resources were exposed, what the agent attempted, which policy
rule applied, and whether Erebor allowed, mediated, held, or denied the action.

No semantic PII classifier enabled. This v1 trace does not claim that the agent
never read personal data, does not certify GDPR/HIPAA compliance, and is not
legal advice.

## Session Purpose And Actor

| Field | Value |
| --- | --- |
| Purpose | {} |
| Session id | {} |
| Actor | {} |
| Session runner | {} |
| Audit window | {} to {} |
| Record count | {} |
| Surfaces observed | {} |
| Decisions observed | {} |

## Controls And Non-Claims

{}

## Governed Resources Exposed

{}

## Allowed Action Timeline

{}

## Denied, Held, Or Mediated Authority Transitions

{}

Summary counts: allowed={}, denied={}, held={}, mediated={}.

## Policy Package And Rule Evidence

{}

## Residual Risk

- No semantic PII classifier enabled. The report proves governed
  action/resource provenance, not semantic content classification.
- Linux-host process governance applies to the enrolled session process tree and
  reports residual risk; it is not a claim of whole-host containment.
- The OpenClaw browser profile can contain existing cookies or login state. The
  demo should use a throwaway GitHub account and throwaway OAuth app.
- Browser URL/resource provenance comes from CDP commands/events and observed
  targets. The raw JSONL remains the evidence attachment for deeper review.
- This report is a technical evidence trace for privacy, GRC, security, and AI
  platform review. It is not legal advice, a DPIA, or a compliance certificate.

## Intended Reviewers And Retention

- Intended reviewers: DPO/privacy, GRC, security, AI platform, and counsel when
  an agent workflow approaches regulated or personal-data-bearing systems.
- Suggested retention: store the report with the JSONL audit, policy, config,
  and prompt artifacts for the same retention period as the reviewed support or
  incident workflow.
- Review question: would this evidence be enough to approve the agent workflow,
  or is semantic data classification, stronger sandboxing, or human approval
  still required?

## Artifact Integrity

{}
"#,
        md(&request.purpose),
        md(session_id),
        md(&actor_label(actor)),
        md(runner),
        md(first_timestamp),
        md(last_timestamp),
        records.len(),
        md(&count_by(records, |record| surface_name(
            &record.event.surface
        ))),
        md(&count_by(records, |record| decision_type(
            &record.final_decision
        ))),
        render_controls(records),
        render_resource_list(records),
        render_rows(
            if allowed_timeline.is_empty() {
                records
            } else {
                &allowed_timeline
            },
            12,
            true
        ),
        render_rows(&transitions, 12, false),
        allowed,
        denied,
        held,
        mediated,
        render_rule_rows(&request.policy, &rule_ids),
        render_artifact_rows(&request.artifacts),
    )
}

fn actor_label(actor: Option<&ActorIdentity>) -> String {
    actor.map_or_else(
        || String::from("unknown (unknown)"),
        |actor| format!("{} ({})", actor.id, actor_kind_name(&actor.kind)),
    )
}

fn actor_kind_name(kind: &ActorKind) -> &'static str {
    match kind {
        ActorKind::Agent => "agent",
        ActorKind::User => "user",
        ActorKind::System => "system",
    }
}

fn observed_rule_ids(records: &[AuditRecord]) -> BTreeSet<String> {
    records
        .iter()
        .flat_map(|record| {
            [
                record.policy_decision.rule_id().map(ToOwned::to_owned),
                record.final_decision.rule_id().map(ToOwned::to_owned),
            ]
        })
        .flatten()
        .collect()
}

fn interesting_allowed(record: &AuditRecord) -> bool {
    if !matches!(record.final_decision, Decision::Allow { .. }) {
        return false;
    }
    record.event.surface == ExecutionSurface::BrowserCdp
        || record
            .final_decision
            .rule_id()
            .is_some_and(|rule| rule.contains("process-interception"))
        || matches!(
            record.event.action,
            ActionKind::BrowserNavigate
                | ActionKind::BrowserTargetManage
                | ActionKind::NetworkRequest
        )
}

fn authority_transition(record: &AuditRecord) -> bool {
    !matches!(record.final_decision, Decision::Allow { .. })
        || matches!(
            record.policy_decision,
            Decision::Deny { .. } | Decision::RequireApproval { .. } | Decision::Mediate { .. }
        )
}

fn render_controls(records: &[AuditRecord]) -> String {
    let has_browser = records
        .iter()
        .any(|record| record.event.surface == ExecutionSurface::BrowserCdp);
    let has_terminal = records
        .iter()
        .any(|record| record.event.surface == ExecutionSurface::Terminal);
    let has_callback_block = records.iter().any(|record| {
        record.event.action == ActionKind::NetworkRequest
            && record
                .final_decision
                .rule_id()
                .is_some_and(|rule| rule == "deny-oauth-callback-network-request")
    });
    let rows = [
        (
            "Browser CDP endpoint",
            if has_browser { "enforced" } else { "deferred" },
            if has_browser {
                "Browser CDP audit records are present."
            } else {
                "No browser CDP audit records are present in this run."
            },
        ),
        (
            "OAuth callback handoff",
            if has_callback_block { "enforced" } else { "observed" },
            if has_callback_block {
                "Callback network request was blocked before local callback completion."
            } else {
                "No callback block record is present in this run."
            },
        ),
        (
            "Terminal/process execution",
            if has_terminal { "enforced" } else { "deferred" },
            if has_terminal {
                "Process execution records are present for the governed session process tree."
            } else {
                "No terminal/process records are present in this run."
            },
        ),
        (
            "OpenClaw browser profile/login state",
            "cooperative",
            "The demo uses the normal OpenClaw browser profile; Erebor does not copy or certify cookies.",
        ),
        (
            "OAuth lab event stream",
            "observed",
            "Lab events are supporting evidence, not the enforcement boundary.",
        ),
        (
            "Semantic PII classifier",
            "deferred",
            "No semantic PII classifier enabled. This report proves governed action/resource provenance, not content classification.",
        ),
        (
            "Host-wide network/process containment",
            "deferred",
            "The pilot controls the governed session path and reports residual risk; it does not claim whole-device containment.",
        ),
    ];

    let mut output = String::from("| Control | Label | Evidence |\n| --- | --- | --- |\n");
    for (control, label, evidence) in rows {
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            md(control),
            md(label),
            md(evidence)
        ));
    }
    output
}

fn render_resource_list(records: &[AuditRecord]) -> String {
    let resources = records
        .iter()
        .filter(|record| matches!(record.final_decision, Decision::Allow { .. }))
        .map(|record| {
            format!(
                "{}: {}",
                surface_name(&record.event.surface),
                target_text(&record.event)
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(16)
        .collect::<Vec<_>>();

    if resources.is_empty() {
        return String::from("- No allowed governed resources were recorded for this session.");
    }

    resources
        .iter()
        .map(|resource| format!("- {}", truncate(resource, 180)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_rows(records: &[AuditRecord], limit: usize, only_allowed: bool) -> String {
    let rows = records
        .iter()
        .filter(|record| !only_allowed || matches!(record.final_decision, Decision::Allow { .. }))
        .take(limit)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return String::from("No records in this category.");
    }

    let mut output = String::from(
        "| Time | Surface | Action | Target | Decision |\n| --- | --- | --- | --- | --- |\n",
    );
    for record in &rows {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md(&record.event.timestamp),
            md(surface_name(&record.event.surface)),
            md(&action_label(&record.event)),
            truncate(&target_text(&record.event), 140),
            md(&decision_label(record)),
        ));
    }
    let omitted = records.len().saturating_sub(rows.len());
    if omitted > 0 {
        output.push_str(&format!(
            "\nAdditional records omitted from this summary: {omitted}.\n"
        ));
    }
    output
}

fn render_rule_rows(policy: &Value, observed_rule_ids: &BTreeSet<String>) -> String {
    if observed_rule_ids.is_empty() {
        return String::from("No policy rule ids were observed in this session.");
    }
    let rules = policy
        .get("rules")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut rows = String::from(
        "| Rule id | Surface | Action | Decision | Reason |\n| --- | --- | --- | --- | --- |\n",
    );
    for rule_id in observed_rule_ids {
        if let Some(rule) = rules
            .iter()
            .find(|rule| rule.get("id").and_then(Value::as_str) == Some(rule_id.as_str()))
        {
            rows.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md(rule_id),
                md(json_str(rule.pointer("/match/surface")).unwrap_or("")),
                md(json_str(rule.pointer("/match/action")).unwrap_or("")),
                md(json_str(rule.get("decision")).unwrap_or("")),
                truncate(json_str(rule.get("reason")).unwrap_or(""), 140),
            ));
        } else {
            rows.push_str(&format!(
                "| {} | internal/runtime | n/a | observed | Runtime-generated decision id. |\n",
                md(rule_id)
            ));
        }
    }
    rows
}

fn render_artifact_rows(artifacts: &[EvidenceTraceArtifact]) -> String {
    let mut output = String::from("| Artifact | Path | SHA-256 |\n| --- | --- | --- |\n");
    for artifact in artifacts {
        output.push_str(&format!(
            "| {} | `{}` | `{}` |\n",
            md(artifact.label()),
            md(&artifact.path().display().to_string()),
            artifact.sha256()
        ));
    }
    output
}

fn json_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn decision_label(record: &AuditRecord) -> String {
    record.final_decision.rule_id().map_or_else(
        || decision_type(&record.final_decision).to_owned(),
        |rule_id| format!("{} ({rule_id})", decision_type(&record.final_decision)),
    )
}

fn decision_type(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
        Decision::RequireApproval { .. } => "require_approval",
        Decision::Mediate { .. } => "mediate",
    }
}

fn action_label(event: &RuntimeEvent) -> String {
    event
        .payload
        .get("method")
        .and_then(Value::as_str)
        .map_or_else(
            || action_name(&event.action).to_owned(),
            |method| format!("{} via {method}", action_name(&event.action)),
        )
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

fn count_by(records: &[AuditRecord], key: impl Fn(&AuditRecord) -> &'static str) -> String {
    let mut counts = BTreeMap::<&'static str, usize>::new();
    for record in records {
        *counts.entry(key(record)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| format!("{key}: {count}"))
        .collect::<Vec<_>>()
        .join(", ")
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

fn md(value: &str) -> String {
    redact(value)
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_owned()
}

fn truncate(value: &str, limit: usize) -> String {
    let text = md(value);
    if text.len() <= limit {
        text
    } else {
        format!("{}...", &text[..limit.saturating_sub(3)])
    }
}

fn redact(value: &str) -> String {
    let mut output = value.to_owned();
    for key in [
        "code",
        "state",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
    ] {
        output = redact_query_key(&output, key);
    }
    output
}

fn redact_query_key(value: &str, key: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    let query_key = format!("{key}=");
    while let Some(index) = rest.find(&query_key) {
        let (before, after_before) = rest.split_at(index);
        output.push_str(before);
        output.push_str(&query_key);
        output.push_str("redacted");
        let value_start = query_key.len();
        let after_value = after_before[value_start..]
            .find(['&', '#', ' ', ')'])
            .map_or(after_before.len(), |offset| value_start + offset);
        rest = &after_before[after_value..];
    }
    output.push_str(rest);
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = H0;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
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
        sha256_hex, EvidenceTraceArtifact, EvidenceTraceRequest, EvidenceTraceSink,
        FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer,
    };

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn markdown_trace_contains_dpo_fields_and_non_claims() -> Result<(), Box<dyn std::error::Error>>
    {
        let records = vec![
            record(
                "allow-nav",
                ExecutionSurface::BrowserCdp,
                ActionKind::BrowserNavigate,
                "http://127.0.0.1:5105/repro",
                Decision::Allow {
                    rule_id: Some(String::from("allow-oauth-lab-navigation")),
                },
                Decision::Allow {
                    rule_id: Some(String::from("allow-oauth-lab-navigation")),
                },
            ),
            record(
                "deny-callback",
                ExecutionSurface::BrowserCdp,
                ActionKind::NetworkRequest,
                "http://127.0.0.1:5105/oauth/callback?code=secret&state=secret",
                Decision::Deny {
                    reason: String::from("callback denied"),
                    rule_id: Some(String::from("deny-oauth-callback-network-request")),
                },
                Decision::Deny {
                    reason: String::from("callback denied"),
                    rule_id: Some(String::from("deny-oauth-callback-network-request")),
                },
            ),
        ];
        let request = EvidenceTraceRequest::new(
            records,
            json!({
                "rules": [
                    {
                        "id": "deny-oauth-callback-network-request",
                        "match": { "surface": "browser_cdp", "action": "network_request" },
                        "decision": "deny",
                        "reason": "callback denied"
                    }
                ]
            }),
            json!({ "session": { "runner": { "kind": "linux_host" } } }),
            vec![EvidenceTraceArtifact::new(
                "Audit JSONL",
                "audit.jsonl",
                "abc",
            )],
            "test purpose",
        );

        let report = MarkdownEvidenceTraceRenderer.render(&request)?;

        assert!(report
            .markdown()
            .contains("No semantic PII classifier enabled"));
        assert!(report.markdown().contains("session-1"));
        assert!(report
            .markdown()
            .contains("deny-oauth-callback-network-request"));
        assert!(report.markdown().contains("code=redacted"));
        assert!(report.markdown().contains("Report body"));
        Ok(())
    }

    #[test]
    fn file_sink_writes_report() -> Result<(), Box<dyn std::error::Error>> {
        let request = EvidenceTraceRequest::new(
            vec![record(
                "allow-process",
                ExecutionSurface::Terminal,
                ActionKind::ProcessExec,
                "google-chrome",
                Decision::Allow { rule_id: None },
                Decision::Allow { rule_id: None },
            )],
            json!({ "rules": [] }),
            json!({}),
            vec![],
            "test purpose",
        );
        let report = MarkdownEvidenceTraceRenderer.render(&request)?;
        let path = temp_path("evidence-trace.md")?;
        let sink = FileEvidenceTraceSink::new(&path);

        let receipt = sink.send(&report)?;

        assert_eq!(receipt.bytes_written(), report.markdown().len());
        assert!(fs::read_to_string(&path)?.contains("Governed OpenClaw Evidence Trace"));
        let _result = fs::remove_file(path);
        Ok(())
    }

    fn record(
        id: &str,
        surface: ExecutionSurface,
        action: ActionKind,
        uri: &str,
        policy_decision: Decision,
        final_decision: Decision,
    ) -> AuditRecord {
        AuditRecord {
            event: RuntimeEvent {
                id: EventId::new(id),
                session_id: SessionId::new("session-1"),
                actor: ActorIdentity {
                    id: String::from("openclaw"),
                    kind: ActorKind::Agent,
                },
                surface,
                action,
                target: Some(TargetRef {
                    label: Some(String::from("target")),
                    uri: Some(uri.to_owned()),
                }),
                payload: json!({ "method": "Page.navigate" }),
                risk: RiskMetadata {
                    level: RiskLevel::Medium,
                    reasons: vec![String::from("test")],
                },
                timestamp: String::from("2026-06-17T00:00:00Z"),
            },
            policy_decision,
            final_decision,
        }
    }

    fn temp_path(filename: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("erebor-runtime-audit-evidence-{nanos}-{filename}")))
    }
}
