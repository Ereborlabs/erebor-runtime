use std::path::Path;

use erebor_runtime_context::ContextRepository;
use erebor_runtime_core::AuditRecord;
use snafu::{OptionExt, ResultExt};

use crate::{
    error::{
        ReviewAuditLogSnafu, ReviewContextRepositorySnafu, ReviewMissingContextRepositorySnafu,
    },
    read_audit_records, SessionReviewError,
};

use super::{
    artifacts::{SessionReviewArtifactLoader, SessionReviewArtifacts},
    decisions::{SessionDecisionSummaries, SessionKeyRecords},
    record::{truncate, SessionReviewRecord},
    summary::{SessionRecordSelector, SessionSummary, SessionSummaryBuilder},
    timeline::SessionTimelineBuilder,
    SessionReview,
};

mod table;
#[cfg(test)]
mod tests;
pub(crate) use table::SessionReviewOutput;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionReviewOutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionReviewRenderer<'a> {
    records: &'a [AuditRecord],
    artifacts: &'a SessionReviewArtifacts,
}

impl<'a> SessionReviewRenderer<'a> {
    #[must_use]
    pub const fn new(records: &'a [AuditRecord], artifacts: &'a SessionReviewArtifacts) -> Self {
        Self { records, artifacts }
    }

    pub fn render_list(self) -> Result<String, SessionReviewError> {
        let summaries = SessionSummaryBuilder::new(self.records, self.artifacts).build_all()?;
        Ok(SessionReviewOutput::summary_table(&summaries))
    }

    pub fn render_show(self, session_id: &str) -> Result<String, SessionReviewError> {
        let session_records = SessionRecordSelector::new(self.records, session_id).select()?;
        let summary = SessionSummaryBuilder::new(self.records, self.artifacts)
            .build_for_session(&session_records);
        let key_records = SessionKeyRecords::new(&session_records).select();
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
        output.push_str(&Self::summary_sentence(
            &summary,
            key_records.first().copied(),
        ));
        output.push_str("\n\nKey Decisions\n");
        for record in key_records.iter().take(8) {
            output.push_str(&Self::format_key_event_line(record));
            output.push('\n');
        }

        if let Some(record) = key_records.first() {
            let view = SessionReviewRecord::new(record);
            output.push_str("\nMost Important Rule\n");
            output.push_str(view.rule_id().unwrap_or("none"));
            output.push('\n');
            if let Some(reason) = view.decision_reason() {
                output.push_str(reason);
                output.push('\n');
            }
        }

        output.push_str("\nProof Summary\n");
        output.push_str("- Audit JSONL is the source of truth for this session review.\n");
        if let Some(policy_sha256) = self.artifacts.policy_sha256() {
            output.push_str(&format!("- Policy sha256: {policy_sha256}\n"));
        }
        if let Some(config_sha256) = self.artifacts.config_sha256() {
            output.push_str(&format!("- Config sha256: {config_sha256}\n"));
        }
        Self::append_context_pins(&mut output, &session_records);
        output.push_str("- Use `erebor session describe` for controlled-path details.\n");
        Ok(output)
    }

    pub fn render_describe(self, session_id: &str) -> Result<String, SessionReviewError> {
        let session_records = SessionRecordSelector::new(self.records, session_id).select()?;
        let key_records = SessionKeyRecords::new(&session_records).select();
        let described = if key_records.is_empty() {
            session_records
        } else {
            key_records
        };
        let mut output = String::new();

        output.push_str(&format!("Session {}\n\n", session_id));
        for record in described {
            let view = SessionReviewRecord::new(record);
            output.push_str(&format!("{} Event\n", view.event_heading()));
            output.push_str(&format!("Audit record id: {}\n", record.event.id.as_str()));
            output.push_str(&format!("Action: {}\n", view.action_name()));
            output.push_str(&format!("Surface: {}\n", view.surface_name()));
            output.push_str(&format!("Target: {}\n", view.target_summary()));
            output.push_str(&format!("Risk: {}\n", view.risk_name()));
            output.push_str(&format!("Rule: {}\n", view.rule_id().unwrap_or("none")));
            output.push_str(&format!(
                "Policy decision: {}\n",
                view.policy_decision_name()
            ));
            output.push_str(&format!("Final decision: {}\n\n", view.decision_name()));

            output.push_str("Controlled Path\n");
            output.push_str(&format!("Mode: {}\n", view.inferred_mode()));
            output.push_str(&format!("Backend: {}\n", view.inferred_backend()));
            output.push_str(&format!("Final effect: {}\n", view.inferred_final_effect()));
            if let Some(upstream_reached) = view.inferred_upstream_reached() {
                output.push_str(&format!("Upstream reached: {upstream_reached}\n"));
            }

            output.push_str("\nProof\n");
            output.push_str(&format!(
                "Raw payload sha256: {}\n",
                view.raw_payload_sha256()
            ));
            if let Some(policy_sha256) = self.artifacts.policy_sha256() {
                output.push_str(&format!("Policy sha256: {policy_sha256}\n"));
            }
            if let Some(config_sha256) = self.artifacts.config_sha256() {
                output.push_str(&format!("Config sha256: {config_sha256}\n"));
            }
            Self::append_context_pin(&mut output, record);
            output.push('\n');
        }
        Ok(output)
    }

    pub fn review(self, session_id: &str) -> Result<SessionReview, SessionReviewError> {
        SessionReviewAssembler::new(self.records, session_id, self.artifacts).review()
    }

    pub fn render_show_with_context(
        self,
        session_id: &str,
        format: SessionReviewOutputFormat,
        repository: Option<&ContextRepository>,
    ) -> Result<String, SessionReviewError> {
        self.validate_context_pins(session_id, repository)?;
        match format {
            SessionReviewOutputFormat::Text => self.render_show(session_id),
            SessionReviewOutputFormat::Json => SessionReviewOutput::json(&self.review(session_id)?),
        }
    }

    pub fn render_describe_with_context(
        self,
        session_id: &str,
        format: SessionReviewOutputFormat,
        repository: Option<&ContextRepository>,
    ) -> Result<String, SessionReviewError> {
        self.validate_context_pins(session_id, repository)?;
        match format {
            SessionReviewOutputFormat::Text => self.render_describe(session_id),
            SessionReviewOutputFormat::Json => SessionReviewOutput::json(&self.review(session_id)?),
        }
    }

    pub fn render_show_from_paths(
        audit: &Path,
        policy: &Path,
        config: &Path,
        session_id: &str,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let records = read_audit_records(audit).context(ReviewAuditLogSnafu)?;
        let artifacts = SessionReviewArtifactLoader::from_config_paths(policy, config)?;
        match format {
            SessionReviewOutputFormat::Text => {
                SessionReviewRenderer::new(&records, &artifacts).render_show(session_id)
            }
            SessionReviewOutputFormat::Json => SessionReviewOutput::json(
                &SessionReviewAssembler::new(&records, session_id, &artifacts).review()?,
            ),
        }
    }

    pub fn render_describe_from_paths(
        audit: &Path,
        policy: &Path,
        config: &Path,
        session_id: &str,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let records = read_audit_records(audit).context(ReviewAuditLogSnafu)?;
        let artifacts = SessionReviewArtifactLoader::from_config_paths(policy, config)?;
        match format {
            SessionReviewOutputFormat::Text => {
                SessionReviewRenderer::new(&records, &artifacts).render_describe(session_id)
            }
            SessionReviewOutputFormat::Json => SessionReviewOutput::json(
                &SessionReviewAssembler::new(&records, session_id, &artifacts).review()?,
            ),
        }
    }

    fn summary_sentence(summary: &SessionSummary, key_record: Option<&AuditRecord>) -> String {
        if let Some(record) = key_record {
            let view = SessionReviewRecord::new(record);
            let rule = view.rule_id().unwrap_or("no matching rule");
            format!(
                "{} attempted {} on {}. Erebor {} it by rule `{}`.",
                summary.actor,
                view.action_name(),
                view.target_summary(),
                view.decision_past_tense(),
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
        let view = SessionReviewRecord::new(record);
        format!(
            "{} {:<8} {:<16} {}{}",
            record.event.timestamp,
            view.decision_name(),
            view.action_name(),
            truncate(&view.target_summary(), 72),
            view.rule_id()
                .map_or_else(String::new, |rule| format!(" ({rule})"))
        )
    }

    fn validate_context_pins(
        self,
        session_id: &str,
        repository: Option<&ContextRepository>,
    ) -> Result<(), SessionReviewError> {
        for record in self
            .records
            .iter()
            .filter(|record| record.event.session_id.as_str() == session_id)
        {
            let Some(pin) = record.context_pin.as_ref() else {
                continue;
            };
            let repository = repository.context(ReviewMissingContextRepositorySnafu {
                session_id: session_id.to_owned(),
            })?;
            repository
                .validate_session_pin(session_id, pin)
                .map_err(Box::new)
                .context(ReviewContextRepositorySnafu {
                    session_id: session_id.to_owned(),
                })?;
        }
        Ok(())
    }

    fn append_context_pins(output: &mut String, records: &[&AuditRecord]) {
        let pinned_records = records
            .iter()
            .copied()
            .filter(|record| record.context_pin.is_some())
            .collect::<Vec<_>>();
        if pinned_records.is_empty() {
            return;
        }
        output.push_str("\nContext Pins\n");
        for record in pinned_records {
            output.push_str(&format!("- Event {}\n", record.event.id.as_str()));
            Self::append_context_pin_fields(output, record);
        }
    }

    fn append_context_pin(output: &mut String, record: &AuditRecord) {
        let Some(_pin) = record.context_pin.as_ref() else {
            return;
        };
        output.push_str("\nContext Pin\n");
        Self::append_context_pin_fields(output, record);
    }

    fn append_context_pin_fields(output: &mut String, record: &AuditRecord) {
        let Some(pin) = record.context_pin.as_ref() else {
            return;
        };
        output.push_str(&format!("  Scope ref: {}\n", pin.scope_ref()));
        output.push_str(&format!("  Commit: {}\n", pin.commit_id()));
        output.push_str(&format!(
            "  Selected paths: {}\n",
            pin.used_paths().join(", ")
        ));
        output.push_str(&format!(
            "  Selected blob ids: {}\n",
            pin.used_blob_ids().join(", ")
        ));
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionReviewAssembler<'a> {
    records: &'a [AuditRecord],
    session_id: &'a str,
    artifacts: &'a SessionReviewArtifacts,
}

impl<'a> SessionReviewAssembler<'a> {
    pub(crate) const fn new(
        records: &'a [AuditRecord],
        session_id: &'a str,
        artifacts: &'a SessionReviewArtifacts,
    ) -> Self {
        Self {
            records,
            session_id,
            artifacts,
        }
    }

    pub(crate) fn review(self) -> Result<SessionReview, SessionReviewError> {
        let session_records = SessionRecordSelector::new(self.records, self.session_id).select()?;
        let summary = SessionSummaryBuilder::new(self.records, self.artifacts)
            .build_for_session(&session_records);
        let important_decisions = SessionKeyRecords::new(&session_records)
            .select()
            .into_iter()
            .map(|record| SessionDecisionSummaries::new(self.artifacts).summarize(record))
            .collect::<Vec<_>>();
        let mut timeline = session_records
            .iter()
            .map(|record| SessionTimelineBuilder::item(record))
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
            policy_sha256: self.artifacts.policy_sha256().map(str::to_owned),
            config_sha256: self.artifacts.config_sha256().map(str::to_owned),
        })
    }
}
