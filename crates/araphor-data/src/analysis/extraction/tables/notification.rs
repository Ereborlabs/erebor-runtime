use super::*;
use crate::{
    FindingV1, NotificationFailureV1, NotificationObligationV1, NotificationPriorityV1,
    NotificationSinkHealthV1,
};

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn notification(
        &mut self,
        obligation: &NotificationObligationV1,
        finding: Option<&FindingV1>,
        commit_revision: u64,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        if let Some(deadline) = obligation.deadline_utc_ns.filter(|deadline| {
            self.read.relations.contains("notifications")
                && *deadline > self.read.now
                && obligation.overdue(*deadline)
        }) {
            self.next_change = Some(
                self.next_change
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        let priority = |value| match value {
            NotificationPriorityV1::Info => "info",
            NotificationPriorityV1::Warning => "warning",
            NotificationPriorityV1::High => "high",
            NotificationPriorityV1::Critical => "critical",
        };
        let now = self.read.now;
        table_row!(self,"notifications",budget;
            tenant_id=>Binary:Some(&obligation.key.tenant_id),
            notification_id=>Binary:Some(&obligation.key.notification_id),
            notification_revision=>UInt64:Some(obligation.revision),
            kind=>Utf8:Some(if obligation.finding.is_some(){"finding"}else{"unconfirmed_concern"}),
            finding_id=>Utf8:obligation.finding.as_ref().map(|value|value.finding_id.as_str()),
            finding_result_id=>Utf8:obligation.finding.as_ref().map(|value|value.result_id.as_str()),
            finding_revision=>Json:finding.map(|value|&value.revision),
            finding_available=>Boolean:Some(finding.is_some()),
            package_id=>Utf8:Some(&obligation.package_id),
            required_action=>Utf8:obligation.required_action.as_deref(),
            route_id=>Utf8:obligation.route.as_ref().map(|value|value.route_id.as_str()),
            route_revision=>UInt64:obligation.route.as_ref().map(|value|value.revision),
            priority=>Utf8:Some(priority(obligation.priority())),
            source_priority=>Utf8:Some(priority(obligation.source_priority)),
            minimum_priority=>Utf8:Some(priority(obligation.minimum_priority)),
            first_seen_utc_ns=>UInt64:Some(obligation.first_seen_utc_ns),
            deadline_utc_ns=>UInt64:obligation.deadline_utc_ns,
            overdue=>Boolean:Some(obligation.overdue(now)),
            overdue_since_utc_ns=>UInt64:obligation.overdue_since_utc_ns,
            sink_health=>Utf8:Some(match obligation.sink_health {NotificationSinkHealthV1::Unknown=>"unknown",NotificationSinkHealthV1::Healthy=>"healthy",NotificationSinkHealthV1::Unhealthy=>"unhealthy"}),
            failure=>Utf8:obligation.failure.map(|value|match value {NotificationFailureV1::NoRoute=>"no_route",NotificationFailureV1::SinkUnavailable=>"sink_unavailable",NotificationFailureV1::SinkRejected=>"sink_rejected",NotificationFailureV1::TransportFailed=>"transport_failed",NotificationFailureV1::AuthorizationRevoked=>"authorization_revoked",NotificationFailureV1::DisclosureDenied=>"disclosure_denied",NotificationFailureV1::FindingUnavailable=>"finding_unavailable",NotificationFailureV1::InvalidSinkResult=>"invalid_sink_result",NotificationFailureV1::RetryExhausted=>"retry_exhausted"}),
            human_acknowledgement=>Json:obligation.human_acknowledgement.as_ref(),
            agent_receipt=>Json:obligation.agent_receipt.as_ref(),
            advisory=>Json:obligation.advisory.as_ref(),
            unconfirmed_concern=>Json:obligation.unconfirmed_concern.as_ref(),
            delivery_attempts=>Json:Some(&obligation.attempts),
            sensitivity=>Utf8:Some(<&str>::from(obligation.sensitivity)),
            commit_revision=>UInt64:Some(commit_revision),
        )
    }
}
