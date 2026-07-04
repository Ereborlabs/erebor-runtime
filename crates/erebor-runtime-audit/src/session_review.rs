use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};
use erebor_runtime_core::{
    AuditRecord, RuntimeConfig, SessionRegistry, SessionRegistryRecord,
    DEFAULT_SESSION_REGISTRY_PATH,
};
use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};
use erebor_runtime_policy::Decision;
use serde::Serialize;
use serde_json::Value;
use snafu::{OptionExt, ResultExt};

use crate::error::{
    ReviewAuditLogSnafu, ReviewEncodeJsonSnafu, ReviewInvalidRuntimeConfigSnafu,
    ReviewMissingConfigArtifactSnafu, ReviewMissingPolicyArtifactSnafu,
    ReviewNoSessionRecordsSnafu, ReviewReadFileSnafu, ReviewSessionRegistrySnafu,
    ReviewUnknownSessionSnafu,
};
use crate::{
    evidence_trace::{redact, sha256_hex},
    read_audit_records, SessionReviewError,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionReviewOutputFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionReviewSourcePaths {
    registry: PathBuf,
}

impl Default for SessionReviewSourcePaths {
    fn default() -> Self {
        Self {
            registry: PathBuf::from(DEFAULT_SESSION_REGISTRY_PATH),
        }
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
        return ReviewNoSessionRecordsSnafu.fail();
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
    Ok(render_session_summary_table(&summaries))
}

pub fn render_session_list_from_default_registry(
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    render_session_list_from_source(&SessionReviewSourcePaths::default(), format)
}

fn render_session_list_from_source(
    source: &SessionReviewSourcePaths,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    let registry = SessionRegistry::new(source.registry.clone());
    let records = registry
        .list_sessions()
        .context(ReviewSessionRegistrySnafu)?;
    let summaries = registry_session_summaries(&records);
    match format {
        SessionReviewOutputFormat::Text => Ok(render_session_summary_table(&summaries)),
        SessionReviewOutputFormat::Json => encode_json_output(&summaries),
    }
}

pub fn render_session_show_from_paths(
    audit: &Path,
    policy: &Path,
    config: &Path,
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    render_session_from_paths(
        audit,
        policy,
        config,
        session_id,
        format,
        render_session_show,
    )
}

pub fn render_session_show_from_default_registry(
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    render_session_show_from_source(&SessionReviewSourcePaths::default(), session_id, format)
}

fn render_session_show_from_source(
    source: &SessionReviewSourcePaths,
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    let (audit, policy, config) = registry_review_paths(source, session_id)?;
    render_session_show_from_paths(&audit, &policy, &config, session_id, format)
}

pub fn render_session_describe_from_paths(
    audit: &Path,
    policy: &Path,
    config: &Path,
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    render_session_from_paths(
        audit,
        policy,
        config,
        session_id,
        format,
        render_session_describe,
    )
}

pub fn render_session_describe_from_default_registry(
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    render_session_describe_from_source(&SessionReviewSourcePaths::default(), session_id, format)
}

fn render_session_describe_from_source(
    source: &SessionReviewSourcePaths,
    session_id: &str,
    format: SessionReviewOutputFormat,
) -> Result<String, SessionReviewError> {
    let (audit, policy, config) = registry_review_paths(source, session_id)?;
    render_session_describe_from_paths(&audit, &policy, &config, session_id, format)
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

fn render_session_from_paths(
    audit: &Path,
    policy: &Path,
    config: &Path,
    session_id: &str,
    format: SessionReviewOutputFormat,
    text_renderer: fn(
        &[AuditRecord],
        &str,
        &SessionReviewArtifacts,
    ) -> Result<String, SessionReviewError>,
) -> Result<String, SessionReviewError> {
    let records = read_audit_records(audit).context(ReviewAuditLogSnafu)?;
    let artifacts = session_review_artifacts_from_paths(policy, config)?;
    match format {
        SessionReviewOutputFormat::Text => text_renderer(&records, session_id, &artifacts),
        SessionReviewOutputFormat::Json => {
            encode_json_output(&review_session(&records, session_id, &artifacts)?)
        }
    }
}

fn render_session_summary_table(summaries: &[SessionSummary]) -> String {
    let mut table = standard_table();
    table.set_header([
        "SESSION", "STATUS", "ACTOR", "RUNNER", "SURFACES", "ALLOW", "DENY", "APPROVAL", "MEDIATE",
        "RISK", "START",
    ]);

    for summary in summaries {
        table.add_row([
            summary.session_id.clone(),
            summary.status.clone(),
            summary.actor.clone(),
            summary.runner.clone(),
            summary.surfaces.join(","),
            summary.allowed.to_string(),
            summary.denied.to_string(),
            summary.require_approval.to_string(),
            summary.mediated.to_string(),
            summary.max_risk.clone(),
            summary.start.clone(),
        ]);
    }

    format!("{table}\n")
}

fn standard_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn registry_review_paths(
    source: &SessionReviewSourcePaths,
    session_id: &str,
) -> Result<(PathBuf, PathBuf, PathBuf), SessionReviewError> {
    let registry = SessionRegistry::new(source.registry.clone());
    let record = registry
        .load_session(session_id)
        .context(ReviewSessionRegistrySnafu)?;
    let policy = record
        .primary_policy_artifact_path()
        .map(Path::to_path_buf)
        .context(ReviewMissingPolicyArtifactSnafu {
            session_id: session_id.to_owned(),
        })?;
    let config = record
        .config_artifact_path()
        .map(Path::to_path_buf)
        .context(ReviewMissingConfigArtifactSnafu {
            session_id: session_id.to_owned(),
        })?;
    Ok((record.audit_path().to_path_buf(), policy, config))
}

fn registry_session_summaries(records: &[SessionRegistryRecord]) -> Vec<SessionSummary> {
    records
        .iter()
        .map(|record| {
            let artifacts = SessionReviewArtifacts::new(Some(record.runner.clone()));
            read_audit_records(record.audit_path())
                .ok()
                .and_then(|audit_records| session_summaries(&audit_records, &artifacts).ok())
                .and_then(|summaries| {
                    summaries
                        .into_iter()
                        .find(|summary| summary.session_id == record.session_id)
                })
                .map(|mut summary| {
                    summary.status = record.status.as_str().to_owned();
                    summary
                })
                .unwrap_or_else(|| session_summary_from_registry_record(record))
        })
        .collect()
}

fn session_summary_from_registry_record(record: &SessionRegistryRecord) -> SessionSummary {
    SessionSummary {
        session_id: record.session_id.clone(),
        status: record.status.as_str().to_owned(),
        actor: record.actor_id.clone(),
        runner: record.runner.clone(),
        surfaces: record.surfaces.clone(),
        allowed: 0,
        denied: 0,
        require_approval: 0,
        mediated: 0,
        max_risk: String::from("unknown"),
        start: record.started_at_unix_ms.to_string(),
        end: record
            .ended_at_unix_ms
            .map_or_else(|| String::from("unknown"), |time| time.to_string()),
        record_count: 0,
    }
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
        return ReviewNoSessionRecordsSnafu.fail();
    }
    let session_records = records
        .iter()
        .filter(|record| record.event.session_id.as_str() == session_id)
        .collect::<Vec<_>>();
    if session_records.is_empty() {
        ReviewUnknownSessionSnafu {
            session_id: session_id.to_owned(),
        }
        .fail()
    } else {
        Ok(session_records)
    }
}

fn session_review_artifacts_from_paths(
    policy: &Path,
    config: &Path,
) -> Result<SessionReviewArtifacts, SessionReviewError> {
    let config_source = fs::read_to_string(config).context(ReviewReadFileSnafu {
        path: config.to_path_buf(),
    })?;
    let runtime_config =
        RuntimeConfig::from_json_str(&config_source).context(ReviewInvalidRuntimeConfigSnafu {
            path: config.to_path_buf(),
        })?;
    let runner = runtime_config
        .session
        .enabled
        .then(|| runtime_config.session.runner.kind.as_str().to_owned());
    SessionReviewArtifacts::from_paths(runner, policy, config)
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
    let bytes = fs::read(path).context(ReviewReadFileSnafu {
        path: path.to_path_buf(),
    })?;
    Ok(sha256_hex(&bytes))
}

fn encode_json_output<T: Serialize>(value: &T) -> Result<String, SessionReviewError> {
    let mut output = serde_json::to_string_pretty(value).context(ReviewEncodeJsonSnafu)?;
    output.push('\n');
    Ok(output)
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
        ExecutionSurface::BrowserCdp
        | ExecutionSurface::Terminal
        | ExecutionSurface::Filesystem => "enforced",
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
        ExecutionSurface::Filesystem => "filesystem",
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

    use erebor_runtime_core::{
        AuditRecord, RuntimeConfig, SessionRegistry, SessionRegistryFinish, SessionRunOutcome,
        SessionRunPlan, SessionRunnerKind,
    };
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
        RuntimeEvent, SessionId, TargetRef,
    };
    use erebor_runtime_policy::Decision;
    use serde_json::json;

    use super::{
        render_session_describe, render_session_describe_from_source, render_session_list,
        render_session_list_from_source, render_session_show, render_session_show_from_paths,
        render_session_show_from_source, review_session, session_summaries, SessionReviewArtifacts,
        SessionReviewOutputFormat, SessionReviewSourcePaths,
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
        let config = temp_file(
            "config.json",
            &format!(
                r#"{{
                    "policies": ["{}"],
                    "session": {{
                        "enabled": true,
                        "runner": {{ "kind": "linux_host" }}
                    }},
                    "surfaces": {{
                        "terminal": {{ "enabled": true }}
                    }}
                }}"#,
                policy.display()
            ),
        )?;
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
        let audit = temp_file(
            "audit.jsonl",
            &format!("{}\n", serde_json::to_string(&records[0])?),
        )?;

        let list = render_session_list(&records, &artifacts)?;
        let show = render_session_show(&records, "session-1", &artifacts)?;
        let describe = render_session_describe(&records, "session-1", &artifacts)?;
        let review = review_session(&records, "session-1", &artifacts)?;
        let path_json = render_session_show_from_paths(
            &audit,
            &policy,
            &config,
            "session-1",
            SessionReviewOutputFormat::Json,
        )?;

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
        assert!(path_json.contains(r#""controlled_path_backend": "linux_ptrace_process_guard""#));

        let _result = fs::remove_file(policy);
        let _result = fs::remove_file(config);
        let _result = fs::remove_file(audit);
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

    #[test]
    fn source_renderers_resolve_registry_artifacts() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("registry-source")?;
        let policy = root.join("policy.json");
        let config = root.join("config.json");
        fs::write(&policy, r#"{"rules":[]}"#)?;
        fs::write(
            &config,
            format!(
                r#"{{
                    "policies": ["{}"],
                    "session": {{
                        "enabled": true,
                        "workspace": "{}",
                        "actor": {{ "id": "test-agent", "kind": "agent" }},
                        "runner": {{ "kind": "linux_host" }}
                    }},
                    "surfaces": {{
                        "terminal": {{ "enabled": true }}
                    }}
                }}"#,
                policy.display(),
                root.display(),
            ),
        )?;
        let runtime_config = RuntimeConfig::from_json_str(&fs::read_to_string(&config)?)?;
        let plan = SessionRunPlan::from_config(
            &runtime_config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-registry-source"),
            vec![String::from("sh")],
        )?
        .with_config_path(config.clone());
        let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
        let started = registry.start_session(&runtime_config, &plan)?;
        let record = process_record(
            "session-registry-source",
            "deny-process",
            "sh --remote-debugging-port=9222",
            Decision::Deny {
                reason: String::from("raw CDP process launch is denied"),
                rule_id: Some(String::from("deny-raw-cdp")),
            },
            "2026-06-21T18:00:01Z",
        );
        fs::write(
            started.record().audit_path(),
            format!("{}\n", serde_json::to_string(&record)?),
        )?;
        registry.finish_session(
            plan.session_id(),
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
                SessionRunnerKind::LinuxHost,
                Some(0),
            )),
        )?;

        let source = SessionReviewSourcePaths {
            registry: registry.root().to_path_buf(),
        };
        let list = render_session_list_from_source(&source, SessionReviewOutputFormat::Text)?;
        let show = render_session_show_from_source(
            &source,
            "session-registry-source",
            SessionReviewOutputFormat::Text,
        )?;
        let describe = render_session_describe_from_source(
            &source,
            "session-registry-source",
            SessionReviewOutputFormat::Json,
        )?;

        assert!(list.contains("session-registry-source"));
        assert!(list.contains("succeeded"));
        assert!(show.contains("deny-raw-cdp"));
        assert!(show.contains("Policy sha256:"));
        assert!(describe.contains(r#""session_id": "session-registry-source""#));
        assert!(describe.contains(r#""controlled_path_backend": "linux_ptrace_process_guard""#));

        fs::remove_dir_all(root)?;
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

    fn temp_dir(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-session-review-{nanos}-{}-{name}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
