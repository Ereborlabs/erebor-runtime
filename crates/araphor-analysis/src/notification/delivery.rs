use super::*;

impl NotificationRouter {
    pub fn deliver_obligation(
        &self,
        key: NotificationKeyV1,
        sink: &dyn NotificationSink,
        now: u64,
    ) -> Result<usize> {
        self.deliver_checked(key, &mut |delivery| Ok(sink.deliver(delivery)), now)
    }

    pub(crate) fn deliver_checked(
        &self,
        key: NotificationKeyV1,
        effect: &mut Effect<'_>,
        now: u64,
    ) -> Result<usize> {
        let _guard = self.lock()?;
        NotificationErrorCodeV1::Invalid.require(now > 0, "delivery time")?;
        let mut state = self.state(key)?;
        self.deliver_state(&mut state, effect, now, None)
    }

    pub(super) fn deliver_state(
        &self,
        state: &mut NotificationObligationV1,
        effect: &mut Effect<'_>,
        now: u64,
        batch: Option<&FindingBatch>,
    ) -> Result<usize> {
        if state
            .human_acknowledgement
            .is_some_and(|ack| ack.finding_revision == state.finding_revision)
        {
            return Ok(0);
        }
        if state.unconfirmed_concern.is_some() {
            self.refresh_concern(state, now)?;
        }
        if state.overdue(now) && state.overdue_since_utc_ns.is_none() {
            state.overdue_since_utc_ns = state.deadline_utc_ns;
            self.save(state)?;
        }
        let mut delivered = usize::from(self.send(
            state,
            effect,
            NotificationDeliveryKindV1::Finding,
            now,
            batch,
        )?);
        if state.failure.is_some() || state.pending(NotificationDeliveryKindV1::FailureEscalation) {
            delivered += usize::from(self.send(
                state,
                effect,
                NotificationDeliveryKindV1::FailureEscalation,
                now,
                batch,
            )?);
        }
        if state.overdue(now)
            || state.pending(NotificationDeliveryKindV1::AcknowledgementEscalation)
        {
            delivered += usize::from(self.send(
                state,
                effect,
                NotificationDeliveryKindV1::AcknowledgementEscalation,
                now,
                batch,
            )?);
        }
        Ok(delivered)
    }
}
