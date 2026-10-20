use super::*;

impl NotificationObligationV1 {
    pub fn retry_utc_ns(
        &self,
        kind: NotificationDeliveryKindV1,
        policy: &NotificationPolicyV1,
    ) -> Option<u64> {
        if self
            .human_acknowledgement
            .is_some_and(|ack| ack.finding_revision == self.finding_revision)
            || self.delivery_route(kind).is_none()
            || (kind == NotificationDeliveryKindV1::FailureEscalation
                && self.failure.is_none()
                && !self.pending(kind))
        {
            return None;
        }
        let last = self
            .attempts
            .iter()
            .rev()
            .find(|attempt| attempt.kind == kind);
        let current = last.filter(|attempt| attempt.finding_revision == self.finding_revision);
        if current.is_some_and(|attempt| {
            attempt
                .result
                .as_ref()
                .is_some_and(NotificationSinkResultV1::accepted)
        }) {
            return None;
        }
        if self.retry_exhausted(kind, policy) {
            return (kind == NotificationDeliveryKindV1::Finding
                && self.failure != Some(NotificationFailureV1::RetryExhausted))
            .then_some(self.first_seen_utc_ns);
        }
        let retry = current
            .and_then(|attempt| attempt.completed_utc_ns)
            .map_or(self.first_seen_utc_ns, |completed| {
                completed.saturating_add(policy.retry_delay_ns)
            });
        if kind == NotificationDeliveryKindV1::AcknowledgementEscalation && !self.pending(kind) {
            self.deadline_utc_ns.map(|deadline| retry.max(deadline))
        } else {
            Some(retry)
        }
    }

    pub fn retry_exhausted(
        &self,
        kind: NotificationDeliveryKindV1,
        policy: &NotificationPolicyV1,
    ) -> bool {
        let mut attempts = self.attempts.iter().filter(|attempt| attempt.kind == kind);
        let count = attempts
            .clone()
            .filter(|attempt| attempt.finding_revision == self.finding_revision)
            .count();
        attempts.next_back().is_some_and(|last| {
            last.finding_revision == self.finding_revision
                && last.result.is_some()
                && !last
                    .result
                    .as_ref()
                    .is_some_and(NotificationSinkResultV1::accepted)
                && count >= usize::from(policy.retry_limit)
        })
    }
}
