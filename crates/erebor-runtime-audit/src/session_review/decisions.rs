use erebor_runtime_context::ContextPin;
use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, RiskLevel};
use erebor_runtime_policy::Decision;
use serde::Serialize;

use super::{artifacts::SessionReviewArtifacts, record::SessionReviewRecord};

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
    pub context_pin: Option<ContextPin>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionDecisionSummaries<'a> {
    artifacts: &'a SessionReviewArtifacts,
}

impl<'a> SessionDecisionSummaries<'a> {
    pub(crate) const fn new(artifacts: &'a SessionReviewArtifacts) -> Self {
        Self { artifacts }
    }

    pub(crate) fn summarize(self, record: &AuditRecord) -> SessionDecisionSummary {
        let view = SessionReviewRecord::new(record);
        SessionDecisionSummary {
            event_id: record.event.id.as_str().to_owned(),
            timestamp: record.event.timestamp.clone(),
            surface: view.surface_name().to_owned(),
            action: view.action_name().to_owned(),
            target: view.target_summary(),
            risk: view.risk_name().to_owned(),
            rule_id: view.rule_id().map(str::to_owned),
            policy_decision: view.policy_decision_name().to_owned(),
            final_decision: view.decision_name().to_owned(),
            reason: view.decision_reason().map(str::to_owned),
            controlled_path_mode: view.inferred_mode().to_owned(),
            controlled_path_backend: view.inferred_backend().to_owned(),
            final_effect: view.inferred_final_effect().to_owned(),
            upstream_reached: view.inferred_upstream_reached(),
            raw_payload_sha256: view.raw_payload_sha256(),
            policy_sha256: self.artifacts.policy_sha256().map(str::to_owned),
            config_sha256: self.artifacts.config_sha256().map(str::to_owned),
            context_pin: record.context_pin.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionKeyRecords<'a> {
    records: &'a [&'a AuditRecord],
}

impl<'a> SessionKeyRecords<'a> {
    pub(crate) const fn new(records: &'a [&'a AuditRecord]) -> Self {
        Self { records }
    }

    pub(crate) fn select(self) -> Vec<&'a AuditRecord> {
        let mut key = self
            .records
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
}
