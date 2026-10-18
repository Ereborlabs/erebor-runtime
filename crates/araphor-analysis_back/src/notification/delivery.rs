use super::*;

impl NotificationRouter {
    pub fn deliver(
        &self,
        graph: &GraphAndFindingOwner,
        sink: &dyn NotificationSink,
        now: u64,
    ) -> Result<usize> {
        let mut work = self.lock()?;
        NotificationErrorCodeV1::Invalid.require(now > 0, "delivery time")?;
        let mut tenant = match &work.delivery {
            Some(cursor) => Some(cursor.tenant),
            None => self
                .store
                .context_tenant_page(NOTIFICATION_STATE_OWNER, None)?
                .first()
                .copied(),
        };
        let mut after = work
            .delivery
            .as_ref()
            .and_then(|cursor| cursor.context.clone());
        let mut delivered = 0;
        let mut examined = 0;
        let mut failure = None;
        while examined < MAX_NOTIFICATION_STATES {
            let Some(current) = tenant else {
                work.delivery = None;
                break;
            };
            let page = match self.state_page(current, after.as_ref()) {
                Ok(page) => page,
                Err(error) => {
                    let _ = failure.get_or_insert(error);
                    Vec::new()
                }
            };
            if page.is_empty() {
                examined += 1;
                tenant = self
                    .store
                    .context_tenant_page(NOTIFICATION_STATE_OWNER, Some(current))?
                    .first()
                    .copied();
                after = None;
                work.delivery = tenant.map(|tenant| DeliveryCursor {
                    tenant,
                    context: None,
                });
                continue;
            }
            for mut state in page {
                match self.deliver_state(&mut state, graph, sink, now) {
                    Ok(count) => delivered += count,
                    Err(error) => {
                        let _ = failure.get_or_insert(error);
                    }
                }
                after = Some(Self::state_key(&state));
                work.delivery = Some(DeliveryCursor {
                    tenant: current,
                    context: after.clone(),
                });
                examined += 1;
                if examined == MAX_NOTIFICATION_STATES {
                    break;
                }
            }
        }
        failure.map_or(Ok(delivered), Err)
    }

    pub(super) fn deliver_state(
        &self,
        state: &mut NotificationObligationV1,
        graph: &GraphAndFindingOwner,
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
            usize::from(self.send(state, graph, sink, NotificationDeliveryKindV1::Finding, now)?);
        if state.failure.is_some() || state.pending(NotificationDeliveryKindV1::FailureEscalation) {
            delivered += usize::from(self.send(
                state,
                graph,
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
                graph,
                sink,
                NotificationDeliveryKindV1::AcknowledgementEscalation,
                now,
            )?);
        }
        Ok(delivered)
    }
}
