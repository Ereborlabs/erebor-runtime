use super::input::relation;

relation! {
    pub(super) NOTIFICATIONS, notification(sink; state: &crate::NotificationObligationV1, finding: Option<&crate::FindingV1>, commit_revision: u64, now: u64) {
        name: "notifications",
        join_keys: "tenant_id,notification_id,notification_revision. finding_id and finding_revision identify the exact finding input. Names and time are not join keys.",
        owner: "araphor-data.NotificationRouter",
        readiness: "conditional",
        description: "Current authorized notification obligations. Original deadlines survive retries and restart. Sink and agent receipts do not prove human acknowledgement. A model concern remains unconfirmed and grants no response authority. Unrouted obligations and delivery failures remain visible.",
        setup {
            state.validate()?;
            if finding.is_some_and(|finding| finding.tenant_id != state.key.tenant_id
                || !state.finding.as_ref().is_some_and(|reference| reference.finding_id == finding.finding_id)) {
                return crate::QueryDeniedSnafu.fail();
            }
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(state.key.tenant_id.as_slice());
            notification_id: Binary("16-byte obligation lifetime ID", "") =>
                Some(state.key.notification_id.as_slice());
            notification_revision: UInt64("committed notification owner revision", "") => Some(state.revision);
            kind: Utf8("finding or unconfirmed_concern", "") =>
                Some(if state.finding.is_some() { "finding" } else { "unconfirmed_concern" });
            finding_id: Utf8("exact full finding key", "An unconfirmed concern has no finding.") =>
                state.finding.as_ref().map(|finding| finding.finding_id.as_str());
            finding_result_id: Utf8("immutable graph result row reference", "An unconfirmed concern has no finding.") =>
                state.finding.as_ref().map(|finding| finding.result_id.as_str());
            finding_revision: Binary("JSON exact finding input manifest", "The exact finding reference is absent or unresolved.") =>
                finding.map(|finding| Self::json(sink, &finding.revision)).transpose()?;
            finding_available: Boolean("the exact committed finding reference was resolved", "") =>
                Some(finding.is_some());
            package_id: Utf8("source package ID", "") => Some(state.package_id.as_str());
            required_action: Utf8("required human action", "The source has no required action.") =>
                state.required_action.as_deref();
            route_id: Utf8("approved route ID", "This obligation has no approved route.") =>
                state.route.as_ref().map(|route| route.route_id.as_str());
            route_revision: UInt64("approved route revision", "This obligation has no approved route.") =>
                state.route.as_ref().map(|route| route.revision);
            priority: Utf8("effective priority at or above the source and route floors", "") =>
                Some(format!("{:?}", state.priority()));
            source_priority: Utf8("source priority floor", "") => Some(format!("{:?}", state.source_priority));
            minimum_priority: Utf8("approved route priority floor", "") =>
                Some(format!("{:?}", state.minimum_priority));
            first_seen_utc_ns: UInt64("original obligation UTC nanoseconds", "") => Some(state.first_seen_utc_ns);
            deadline_utc_ns: UInt64("original human acknowledgement deadline", "This obligation is unrouted.") =>
                state.deadline_utc_ns;
            overdue: Boolean("human acknowledgement is overdue at query time", "") => Some(state.overdue(now));
            overdue_since_utc_ns: UInt64("persisted overdue deadline", "No overdue deadline was recorded.") =>
                state.overdue_since_utc_ns;
            sink_health: Utf8("unknown, healthy, or unhealthy", "") =>
                Some(format!("{:?}", state.sink_health).to_ascii_lowercase());
            failure: Utf8("persisted route or sink failure", "No failure was recorded.") =>
                state.failure.map(|failure| format!("{failure:?}"));
            human_acknowledgement: Binary("JSON authenticated human acknowledgement record", "No human acknowledgement was recorded.") =>
                state.human_acknowledgement.as_ref().map(|value| Self::json(sink, value)).transpose()?;
            agent_receipt: Binary("JSON agent receipt; this does not acknowledge the human obligation", "No agent receipt was recorded.") =>
                state.agent_receipt.as_ref().map(|value| Self::json(sink, value)).transpose()?;
            advisory: Binary("JSON advisory priority and model label", "No advisory was recorded.") =>
                state.advisory.as_ref().map(|value| Self::json(sink, value)).transpose()?;
            unconfirmed_concern: Binary("JSON unconfirmed model concern; this grants no authority", "This notification came from a finding.") =>
                state.unconfirmed_concern.as_ref().map(|value| Self::json(sink, value)).transpose()?;
            delivery_attempts: Binary("JSON bounded attempts with exact delivery revisions and sink results", "") =>
                Some(Self::json(sink, &state.attempts)?);
            sensitivity: Utf8("public, tenant, or host_restricted", "") => Some(<&str>::from(state.sensitivity));
            commit_revision: UInt64("captured store commit revision", "") => Some(commit_revision);
        }
    }
}
