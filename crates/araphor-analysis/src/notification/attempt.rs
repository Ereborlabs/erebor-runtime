use super::*;

impl NotificationRouter {
    pub(super) fn send(
        &self,
        state: &mut NotificationObligationV1,
        effect: &mut Effect<'_>,
        kind: NotificationDeliveryKindV1,
        now: u64,
    ) -> Result<bool> {
        let Some(number) = self.prepare_attempt(state, kind, now)? else {
            return Ok(false);
        };
        let result = self.attempt_result(state, effect, kind, number, now)?;
        self.complete_attempt(state, kind, number, result, now)?;
        Ok(true)
    }

    fn prepare_attempt(
        &self,
        state: &mut NotificationObligationV1,
        kind: NotificationDeliveryKindV1,
        now: u64,
    ) -> Result<Option<u64>> {
        let Some(reference) = state.delivery_route(kind) else {
            return Ok(None);
        };
        let Some(route) = self.route_version(state.key.tenant_id, reference)? else {
            if state.failure != Some(NotificationFailureV1::NoRoute) {
                state.failure = Some(NotificationFailureV1::NoRoute);
                self.save(state)?;
            }
            return Ok(None);
        };
        if !self.retry_ready(state, kind, &route.policy, now)? {
            return Ok(None);
        }
        if let Some(pending) = state
            .attempts
            .iter()
            .find(|attempt| attempt.kind == kind && attempt.result.is_none())
        {
            return Ok(Some(pending.number));
        }
        self.append_attempt(state, kind, &route.policy, now)
            .map(Some)
    }

    fn retry_ready(
        &self,
        state: &mut NotificationObligationV1,
        kind: NotificationDeliveryKindV1,
        policy: &NotificationPolicyV1,
        now: u64,
    ) -> Result<bool> {
        if state.retry_exhausted(kind, policy) {
            if kind == NotificationDeliveryKindV1::Finding
                && state.failure != Some(NotificationFailureV1::RetryExhausted)
            {
                state.failure = Some(NotificationFailureV1::RetryExhausted);
                self.save(state)?;
            }
            return Ok(false);
        }
        Ok(state
            .retry_utc_ns(kind, policy)
            .is_some_and(|retry| now >= retry))
    }

    fn append_attempt(
        &self,
        state: &mut NotificationObligationV1,
        kind: NotificationDeliveryKindV1,
        policy: &NotificationPolicyV1,
        now: u64,
    ) -> Result<u64> {
        state.attempt_sequence = state.attempt_sequence.max(
            state
                .attempts
                .iter()
                .map(|attempt| attempt.number)
                .max()
                .unwrap_or(0),
        );
        state.attempts.retain(|attempt| {
            attempt.finding_revision == state.finding_revision || attempt.result.is_none()
        });
        NotificationErrorCodeV1::Limit.require(state.attempts.len() < 48, "delivery attempts")?;
        let number = state.attempt_sequence.checked_add(1).ok_or_else(|| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Limit,
                field: "delivery attempts",
            }
            .build()
        })?;
        state.attempt_sequence = number;
        state.attempts.push(NotificationAttemptV1 {
            number,
            kind,
            finding_revision: state.finding_revision,
            context_revision: state.revision,
            priority: state.priority().max(policy.minimum_priority),
            started_utc_ns: now,
            completed_utc_ns: None,
            result: None,
        });
        self.save(state)?;
        Ok(number)
    }

    fn attempt_result(
        &self,
        state: &NotificationObligationV1,
        effect: &mut Effect<'_>,
        kind: NotificationDeliveryKindV1,
        number: u64,
        now: u64,
    ) -> Result<NotificationSinkResultV1> {
        let pending = state
            .attempts
            .iter()
            .find(|attempt| attempt.kind == kind && attempt.number == number)
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Conflict,
                    field: "pending attempt",
                }
                .build()
            })?;
        NotificationErrorCodeV1::Invalid.require(now >= pending.started_utc_ns, "delivery time")?;
        let subject = self.finding_version(state.key, pending.context_revision)?;
        let route = self.captured_route(&subject, kind)?;
        if let Some(reason) = self.delivery_failure(state, &route, now) {
            return Ok(NotificationSinkResultV1::Failed { reason });
        }
        let delivery = self.captured_delivery(state, pending, kind, subject, &route)?;
        if delivery.finding.is_none() && delivery.unconfirmed_concern.is_none() {
            return Ok(NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::FindingUnavailable,
            });
        }
        let result = effect(&delivery)?;
        Ok(if result.valid() {
            result
        } else {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::InvalidSinkResult,
            }
        })
    }

    fn complete_attempt(
        &self,
        state: &mut NotificationObligationV1,
        kind: NotificationDeliveryKindV1,
        number: u64,
        result: NotificationSinkResultV1,
        now: u64,
    ) -> Result<()> {
        let attempt = state
            .attempts
            .iter_mut()
            .find(|attempt| attempt.kind == kind && attempt.number == number)
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Conflict,
                    field: "pending attempt",
                }
                .build()
            })?;
        NotificationErrorCodeV1::Invalid
            .require(now >= attempt.started_utc_ns, "delivery completion time")?;
        attempt.completed_utc_ns = Some(now);
        attempt.result = Some(result.clone());
        state.sink_health = if result.accepted() {
            NotificationSinkHealthV1::Healthy
        } else {
            NotificationSinkHealthV1::Unhealthy
        };
        match result {
            NotificationSinkResultV1::Failed { reason } => state.failure = Some(reason),
            _ if kind == NotificationDeliveryKindV1::Finding => {
                state.failure = state
                    .escalation
                    .is_none()
                    .then_some(NotificationFailureV1::NoRoute);
            }
            _ => {}
        }
        self.save(state)
    }
}
