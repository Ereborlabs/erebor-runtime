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
        self.with_cycle(key.tenant_id, &[], &[key], |cycle| {
            let mut state = cycle.state(key)?;
            cycle.deliver_state(&mut state, effect, now)
        })
    }
}

impl NotificationCycle<'_, '_> {
    pub(super) fn deliver_state(
        &mut self,
        state: &mut NotificationObligationV1,
        effect: &mut Effect<'_>,
        now: u64,
    ) -> Result<usize> {
        self.deliver_states(std::slice::from_mut(state), &|| Ok(()), effect, now)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "notification delivery result",
                }
                .build()
            })?
    }

    fn prepare_delivery(&mut self, state: &mut NotificationObligationV1, now: u64) -> Result<()> {
        if state.unconfirmed_concern.is_some() {
            self.refresh_concern(state, now)?;
        }
        if state.overdue(now) && state.overdue_since_utc_ns.is_none() {
            state.overdue_since_utc_ns = state.deadline_utc_ns;
            self.save(state)?;
        }
        Ok(())
    }

    pub(super) fn deliver_states(
        &mut self,
        states: &mut [NotificationObligationV1],
        check: &dyn Fn() -> Result<()>,
        effect: &mut Effect<'_>,
        now: u64,
    ) -> Result<Vec<Result<usize>>> {
        let bytes = states
            .len()
            .checked_mul(
                std::mem::size_of::<Result<usize>>()
                    + std::mem::size_of::<(usize, u64, NotificationObligationV1)>(),
            )
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Limit,
                    field: "notification delivery memory",
                }
                .build()
            })?;
        self.prepared.charge(bytes)?;
        let mut ready = Vec::with_capacity(states.len());
        let mut results = states
            .iter_mut()
            .map(|state| {
                if Self::acknowledged(state) {
                    Ok(0)
                } else {
                    self.prepare_delivery(state, now).map(|()| 0)
                }
            })
            .collect::<Vec<_>>();
        for kind in [
            NotificationDeliveryKindV1::Finding,
            NotificationDeliveryKindV1::FailureEscalation,
            NotificationDeliveryKindV1::AcknowledgementEscalation,
        ] {
            for (index, state) in states.iter_mut().enumerate() {
                if results[index].is_err() || Self::acknowledged(state) {
                    continue;
                }
                let required = match kind {
                    NotificationDeliveryKindV1::Finding => true,
                    NotificationDeliveryKindV1::FailureEscalation => {
                        state.failure.is_some() || state.pending(kind)
                    }
                    NotificationDeliveryKindV1::AcknowledgementEscalation => {
                        state.overdue(now) || state.pending(kind)
                    }
                };
                if required {
                    check()?;
                    match self.prepare_attempt(state, kind, now) {
                        Ok(Some((number, subject))) => ready.push((index, number, subject)),
                        Ok(None) => {}
                        Err(error) => results[index] = Err(error),
                    }
                }
            }
            self.flush(check)?;
            for (index, number, subject) in ready.drain(..) {
                let state = &mut states[index];
                let mut guard_failed = false;
                let result = self.attempt_result(
                    state,
                    &mut |delivery| {
                        if let Err(error) = check() {
                            guard_failed = true;
                            return Err(error);
                        }
                        effect(delivery)
                    },
                    kind,
                    number,
                    subject,
                    now,
                );
                let result = match result {
                    Err(error) if guard_failed => return Err(error),
                    result => result.and_then(|outcome| {
                        self.complete_attempt(state, kind, number, outcome, now)
                    }),
                };
                match result {
                    Ok(()) => {
                        if let Ok(count) = &mut results[index] {
                            *count += 1;
                        }
                    }
                    Err(error) => results[index] = Err(error),
                }
            }
        }
        self.flush(check)?;
        Ok(results)
    }

    fn acknowledged(state: &NotificationObligationV1) -> bool {
        state
            .human_acknowledgement
            .is_some_and(|ack| ack.finding_revision == state.finding_revision)
    }
}
