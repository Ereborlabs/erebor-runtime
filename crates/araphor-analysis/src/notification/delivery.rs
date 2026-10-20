use super::*;

impl NotificationRouter {
    pub fn deliver_obligation(
        &self,
        key: NotificationKeyV1,
        sink: &dyn NotificationSink,
        now: u64,
    ) -> Result<usize> {
        let _guard = self.lock()?;
        NotificationErrorCodeV1::Invalid.require(now > 0, "delivery time")?;
        let mut state = self.state(key)?;
        self.deliver_state(&mut state, sink, now)
    }

    pub(super) fn deliver_state(
        &self,
        state: &mut NotificationObligationV1,
        sink: &dyn NotificationSink,
        now: u64,
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
        let mut delivered =
            usize::from(self.send(state, sink, NotificationDeliveryKindV1::Finding, now)?);
        if state.failure.is_some() || state.pending(NotificationDeliveryKindV1::FailureEscalation) {
            delivered += usize::from(self.send(
                state,
                sink,
                NotificationDeliveryKindV1::FailureEscalation,
                now,
            )?);
        }
        if state.overdue(now)
            || state.pending(NotificationDeliveryKindV1::AcknowledgementEscalation)
        {
            delivered += usize::from(self.send(
                state,
                sink,
                NotificationDeliveryKindV1::AcknowledgementEscalation,
                now,
            )?);
        }
        Ok(delivered)
    }
}
