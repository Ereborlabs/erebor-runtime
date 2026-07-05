use erebor_runtime_core::AuditRecord;
use serde::Serialize;

use super::record::SessionReviewRecord;

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SessionTimelineBuilder;

impl SessionTimelineBuilder {
    pub(crate) fn item(record: &AuditRecord) -> SessionTimelineItem {
        let view = SessionReviewRecord::new(record);
        SessionTimelineItem {
            event_id: record.event.id.as_str().to_owned(),
            timestamp: record.event.timestamp.clone(),
            heading: view.event_heading().to_owned(),
            surface: view.surface_name().to_owned(),
            action: view.action_name().to_owned(),
            target: view.target_summary(),
            risk: view.risk_name().to_owned(),
            rule_id: view.rule_id().map(str::to_owned),
            final_decision: view.decision_name().to_owned(),
        }
    }
}
