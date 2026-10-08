use super::*;
use snafu::ResultExt as _;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationObligationV1 {
    pub schema_version: u32,
    pub key: NotificationKeyV1,
    pub revision: u64,
    pub finding: Option<NotificationFindingRefV1>,
    pub unconfirmed_concern: Option<UnconfirmedNotificationConcernV1>,
    pub finding_revision: u64,
    pub package_id: String,
    pub required_action: Option<String>,
    pub sensitivity: ContextSensitivityV1,
    pub source_priority: NotificationPriorityV1,
    pub minimum_priority: NotificationPriorityV1,
    pub route: Option<NotificationRouteRefV1>,
    pub escalation: Option<NotificationRouteRefV1>,
    pub first_seen_utc_ns: u64,
    pub deadline_utc_ns: Option<u64>,
    pub overdue_since_utc_ns: Option<u64>,
    #[serde(default)]
    pub attempt_sequence: u64,
    pub attempts: Vec<NotificationAttemptV1>,
    pub sink_health: NotificationSinkHealthV1,
    pub failure: Option<NotificationFailureV1>,
    pub human_acknowledgement: Option<NotificationAcknowledgementV1>,
    pub agent_receipt: Option<NotificationAgentReceiptV1>,
    pub advisory: Option<NotificationAdvisoryV1>,
}

impl NotificationObligationV1 {
    pub(crate) fn delivery_route(
        &self,
        kind: NotificationDeliveryKindV1,
    ) -> Option<&NotificationRouteRefV1> {
        match kind {
            NotificationDeliveryKindV1::Finding => self.route.as_ref(),
            NotificationDeliveryKindV1::FailureEscalation
            | NotificationDeliveryKindV1::AcknowledgementEscalation => self.escalation.as_ref(),
        }
    }

    pub(crate) fn pending(&self, kind: NotificationDeliveryKindV1) -> bool {
        self.attempts
            .iter()
            .any(|attempt| attempt.kind == kind && attempt.result.is_none())
    }

    #[must_use]
    pub fn priority(&self) -> NotificationPriorityV1 {
        self.minimum_priority.max(self.source_priority).max(
            self.advisory
                .as_ref()
                .map_or(NotificationPriorityV1::Info, |value| {
                    value.suggested_priority
                }),
        )
    }

    #[must_use]
    pub fn overdue(&self, now_utc_ns: u64) -> bool {
        self.human_acknowledgement
            .is_none_or(|ack| ack.finding_revision != self.finding_revision)
            && self
                .deadline_utc_ns
                .is_some_and(|deadline| now_utc_ns >= deadline)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        NotificationErrorCodeV1::Invalid.require(
            self.schema_version == 1
                && self.key.tenant_id != [0; 16]
                && self.key.notification_id != [0; 16]
                && self.revision > 0
                && self.finding.is_some() != self.unconfirmed_concern.is_some()
                && self.finding.as_ref().is_none_or(|finding| {
                    NotificationGrantV1::identifier(&finding.finding_id, 4096)
                        && NotificationGrantV1::identifier(&finding.result_id, 256)
                })
                && NotificationGrantV1::identifier(&self.package_id, 64)
                && self
                    .required_action
                    .as_ref()
                    .is_none_or(|action| NotificationGrantV1::identifier(action, 256))
                && self.finding_revision > 0
                && self.finding_revision <= self.revision
                && self.first_seen_utc_ns > 0
                && self.attempts.len() <= 48
                && (self.attempt_sequence == 0
                    || self
                        .attempts
                        .iter()
                        .all(|attempt| attempt.number <= self.attempt_sequence))
                && self
                    .deadline_utc_ns
                    .is_none_or(|deadline| deadline > self.first_seen_utc_ns)
                && self.attempts.iter().all(|attempt| {
                    attempt.number > 0
                        && attempt.finding_revision > 0
                        && attempt.finding_revision <= self.revision
                        && attempt.context_revision > 0
                        && attempt.context_revision <= self.revision
                        && attempt.started_utc_ns >= self.first_seen_utc_ns
                        && attempt.completed_utc_ns.is_some() == attempt.result.is_some()
                        && attempt
                            .completed_utc_ns
                            .is_none_or(|completed| completed >= attempt.started_utc_ns)
                        && attempt
                            .result
                            .as_ref()
                            .is_none_or(NotificationSinkResultV1::valid)
                }),
            "obligation",
        )?;
        if let Some(concern) = &self.unconfirmed_concern {
            concern.validate(self.key.tenant_id)?;
        }
        Ok(())
    }
}

impl TryFrom<&crate::AnalysisContextVersionV1> for NotificationObligationV1 {
    type Error = crate::Error;

    fn try_from(context: &crate::AnalysisContextVersionV1) -> Result<Self> {
        NotificationErrorCodeV1::Invalid.require(
            context.key.owner_id == NOTIFICATION_STATE_OWNER
                && context.key.lifetime_key == b"obligation"
                && context.body.len() <= 32 * 1024,
            "notification context owner",
        )?;
        let state: Self =
            serde_json::from_slice(&context.body).context(crate::NotificationEncodingSnafu)?;
        state.validate()?;
        NotificationErrorCodeV1::Invalid.require(
            state.key.tenant_id == context.key.tenant_id
                && state.key.notification_id.as_slice() == context.key.entity_key
                && state.revision == context.key.owner_revision
                && state.sensitivity == context.sensitivity,
            "notification context identity",
        )?;
        Ok(state)
    }
}
