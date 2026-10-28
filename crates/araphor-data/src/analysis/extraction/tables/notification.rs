use super::*;
use crate::{
    AnalysisContextVersionV1, ApprovedNotificationRouteV1, FindingV1, NotificationFailureV1,
    NotificationObligationV1, NotificationPriorityV1, NotificationSinkHealthV1,
};

#[derive(serde::Serialize)]
struct RouteRow<'a> {
    #[serde(with = "serde_bytes")]
    tenant_id: &'a [u8],
    route_id: &'a str,
    route_revision: u64,
    escalation_route_id: &'a str,
    package_ids: &'a [String],
    grant_expires_utc_ns: u64,
    grant_current: bool,
    commit_revision: u64,
}

impl Capture<'_> {
    pub(super) fn notification_route(
        &mut self,
        context: &AnalysisContextVersionV1,
        revision: u64,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        const NAMES: &[&str] = &[
            "tenant_id",
            "route_id",
            "route_revision",
            "escalation_route_id",
            "package_ids",
            "grant_expires_utc_ns",
            "grant_current",
            "commit_revision",
        ];
        budget.charge(context.body.len().saturating_mul(2))?;
        let route = ApprovedNotificationRouteV1::try_from(context)?;
        if route.grant.expires_utc_ns > self.read.now {
            self.next_change = Some(
                self.next_change
                    .map_or(route.grant.expires_utc_ns, |current| {
                        current.min(route.grant.expires_utc_ns)
                    }),
            );
        }
        let row = RouteRow {
            tenant_id: &route.policy.tenant_id,
            route_id: &route.policy.route_id,
            route_revision: route.policy.revision,
            escalation_route_id: &route.policy.escalation_route_id,
            package_ids: &route.policy.package_ids,
            grant_expires_utc_ns: route.grant.expires_utc_ns,
            grant_current: self.read.now < route.grant.expires_utc_ns,
            commit_revision: revision,
        };
        let schema = Arc::clone(&self.table("notification_routes", NAMES, budget)?.schema);
        budget.charge(schema.fields().len() * (size_of::<ArrayRef>() + 512))?;
        let batch = if schema.fields().is_empty() {
            RecordBatch::try_new_with_options(
                schema,
                Vec::new(),
                &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(1)),
            )
            .map_err(arrow_error)?
        } else {
            serde_arrow::to_record_batch(schema.fields(), &[row]).map_err(|source| {
                crate::Error::DiscoveryContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                }
            })?
        };
        self.table("notification_routes", NAMES, budget)?
            .append_native(batch, budget)
    }

    pub(super) fn notification_route_fields() -> Vec<sdk::Field> {
        use sdk::DataType::*;
        vec![
            sdk::Field::new("tenant_id", Binary, false),
            sdk::Field::new("route_id", Utf8, false),
            sdk::Field::new("route_revision", UInt64, false),
            sdk::Field::new("escalation_route_id", Utf8, false),
            sdk::Field::new(
                "package_ids",
                List(Arc::new(sdk::Field::new("element", Utf8, false))),
                false,
            ),
            sdk::Field::new("grant_expires_utc_ns", UInt64, false),
            sdk::Field::new("grant_current", Boolean, false),
            sdk::Field::new("commit_revision", UInt64, false),
        ]
    }

    table_row! {
        pub(in crate::analysis::extraction) fn notification(
            &mut self,
            obligation: &NotificationObligationV1,
            finding: Option<&FindingV1>,
            commit_revision: u64,
            retry_utc_ns: Option<u64>,
            budget: &mut ReadBudget<'_>,
        );
        schema notification_fields;
        row(self, "notifications", budget);
        setup {
            let acknowledgement = obligation.deadline_utc_ns.filter(|deadline| {
                self.read.requests.contains_key("notifications")
                    && *deadline > self.read.now
                    && obligation.overdue(*deadline)
            });
            let retry = retry_utc_ns.filter(|retry| *retry > self.read.now);
            if let Some(deadline) = acknowledgement.into_iter().chain(retry).min() {
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
        }
        fields {
            tenant_id => Binary(false):Some(&obligation.key.tenant_id),
            notification_id => Binary(false):Some(&obligation.key.notification_id),
            notification_revision => UInt64(false):Some(obligation.revision),
            kind => Utf8(false):Some(if obligation.finding.is_some(){"finding"}else{"unconfirmed_concern"}),
            finding_id => Utf8(true):obligation.finding.as_ref().map(|value|value.finding_id.as_str()),
            finding_result_id => Utf8(true):obligation.finding.as_ref().map(|value|value.result_id.as_str()),
            finding_available => Boolean(false):Some(finding.is_some()),
            package_id => Utf8(false):Some(&obligation.package_id),
            required_action => Utf8(true):obligation.required_action.as_deref(),
            route_id => Utf8(true):obligation.route.as_ref().map(|value|value.route_id.as_str()),
            route_revision => UInt64(true):obligation.route.as_ref().map(|value|value.revision),
            escalation_route_id => Utf8(true):obligation.escalation.as_ref().map(|value|value.route_id.as_str()),
            escalation_route_revision => UInt64(true):obligation.escalation.as_ref().map(|value|value.revision),
            priority => Utf8(false):Some(priority(obligation.priority())),
            source_priority => Utf8(false):Some(priority(obligation.source_priority)),
            minimum_priority => Utf8(false):Some(priority(obligation.minimum_priority)),
            first_seen_utc_ns => UInt64(false):Some(obligation.first_seen_utc_ns),
            deadline_utc_ns => UInt64(true):obligation.deadline_utc_ns,
            retry_utc_ns => UInt64(true):retry_utc_ns,
            delivery_ready => Boolean(false):Some(retry_utc_ns.is_some_and(|retry| retry <= now)
                || (obligation.overdue(now) && obligation.overdue_since_utc_ns.is_none())),
            overdue => Boolean(false):Some(obligation.overdue(now)),
            overdue_since_utc_ns => UInt64(true):obligation.overdue_since_utc_ns,
            sink_health => Utf8(false):Some(match obligation.sink_health {NotificationSinkHealthV1::Unknown=>"unknown",NotificationSinkHealthV1::Healthy=>"healthy",NotificationSinkHealthV1::Unhealthy=>"unhealthy"}),
            failure => Utf8(true):obligation.failure.map(|value|match value {NotificationFailureV1::NoRoute=>"no_route",NotificationFailureV1::SinkUnavailable=>"sink_unavailable",NotificationFailureV1::SinkRejected=>"sink_rejected",NotificationFailureV1::TransportFailed=>"transport_failed",NotificationFailureV1::AuthorizationRevoked=>"authorization_revoked",NotificationFailureV1::DisclosureDenied=>"disclosure_denied",NotificationFailureV1::FindingUnavailable=>"finding_unavailable",NotificationFailureV1::InvalidSinkResult=>"invalid_sink_result",NotificationFailureV1::RetryExhausted=>"retry_exhausted"}),
            human_acknowledgement => Json(true):obligation.human_acknowledgement.as_ref(),
            acknowledged => Boolean(false):Some(obligation.human_acknowledgement.is_some_and(|ack| ack.finding_revision == obligation.finding_revision)),
            agent_receipt => Json(true):obligation.agent_receipt.as_ref(),
            advisory => Json(true):obligation.advisory.as_ref(),
            unconfirmed_concern => Json(true):obligation.unconfirmed_concern.as_ref(),
            delivery_attempts => Json(false):Some(&obligation.attempts),
            sensitivity => Utf8(false):Some(<&str>::from(obligation.sensitivity)),
            commit_revision => UInt64(false):Some(commit_revision),
        }
    }
}
