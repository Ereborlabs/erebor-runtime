use super::*;

impl NotificationRouter {
    pub fn obligations(
        &self,
        grant: &NotificationGrantV1,
        now: u64,
    ) -> Result<Vec<NotificationObligationV1>> {
        let mut states = Vec::new();
        let mut after = None;
        loop {
            let (page, next) = self.obligations_page(grant, after, now)?;
            NotificationErrorCodeV1::Limit.require(
                states.len() + page.len() <= MAX_NOTIFICATION_STATES,
                "notification read count",
            )?;
            states.extend(page);
            let Some(next) = next else {
                return Ok(states);
            };
            after = Some(next);
        }
    }

    pub fn obligations_page(
        &self,
        grant: &NotificationGrantV1,
        after: Option<NotificationKeyV1>,
        now: u64,
    ) -> Result<(Vec<NotificationObligationV1>, Option<NotificationKeyV1>)> {
        grant.validate()?;
        self.authority.check(grant, now)?;
        NotificationErrorCodeV1::Denied.require(
            now < grant.expires_utc_ns && grant.operations.contains(&NotificationOperationV1::Read),
            "notification read",
        )?;
        NotificationErrorCodeV1::Denied.require(
            after.is_none_or(|key| {
                key.tenant_id == grant.tenant_id && key.notification_id != [0; 16]
            }),
            "notification page scope",
        )?;
        let cursor = after.map(|key| AnalysisContextKeyV1 {
            tenant_id: key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: 1,
        });
        let page = self.state_page(grant.tenant_id, cursor.as_ref())?;
        let next = page.last().map(|state| state.key);
        let visible = page
            .into_iter()
            .filter(|state| {
                state
                    .route
                    .as_ref()
                    .is_none_or(|route| grant.routes.contains(&route.route_id))
                    && NotificationGrantV1::sensitivity(grant.max_sensitivity, state.sensitivity)
            })
            .collect();
        Ok((visible, next))
    }

    pub fn health(&self, grant: &NotificationGrantV1, now: u64) -> Result<NotificationHealthV1> {
        let mut after = None;
        let mut health = NotificationHealthV1 {
            routing_available: false,
            configured_routes: 0,
            obligations: 0,
            unrouted: 0,
            failed: 0,
            overdue: 0,
            acknowledged: 0,
        };
        loop {
            let (page, next) = self.obligations_page(grant, after, now)?;
            for state in page {
                health.obligations += 1;
                health.unrouted += usize::from(state.route.is_none());
                health.failed += usize::from(state.failure.is_some());
                health.overdue += usize::from(state.overdue(now));
                health.acknowledged += usize::from(
                    state
                        .human_acknowledgement
                        .is_some_and(|ack| ack.finding_revision == state.finding_revision),
                );
            }
            let Some(next) = next else {
                break;
            };
            after = Some(next);
        }
        let configured_routes = self
            .routes(grant.tenant_id)?
            .iter()
            .filter(|route| {
                grant.routes.contains(&route.policy.route_id)
                    && self.authority.check(&route.grant, now).is_ok()
            })
            .count();
        health.routing_available = configured_routes > 0;
        health.configured_routes = configured_routes;
        Ok(health)
    }

    pub fn acknowledge(
        &self,
        grant: &NotificationGrantV1,
        key: NotificationKeyV1,
        expected_revision: u64,
        request_id: [u8; 16],
        now: u64,
    ) -> Result<NotificationObligationV1> {
        let _guard = self.lock()?;
        let mut state =
            self.authorized_state(grant, key, NotificationOperationV1::Acknowledge, now)?;
        NotificationErrorCodeV1::Denied.require(
            grant.principal == NotificationPrincipalV1::Human && request_id != [0; 16],
            "human acknowledgement",
        )?;
        NotificationErrorCodeV1::Conflict.require(
            expected_revision == state.finding_revision,
            "acknowledgement finding revision",
        )?;
        if let Some(acknowledgement) = state
            .human_acknowledgement
            .as_ref()
            .filter(|ack| ack.finding_revision == state.finding_revision)
        {
            NotificationErrorCodeV1::Conflict.require(
                acknowledgement.request_id == request_id
                    && acknowledgement.principal_id == grant.principal_id,
                "acknowledgement retry",
            )?;
            return Ok(state);
        }
        NotificationErrorCodeV1::Invalid
            .require(now >= state.first_seen_utc_ns, "acknowledgement time")?;
        if state.overdue(now) {
            state.overdue_since_utc_ns = state.deadline_utc_ns;
        }
        state.human_acknowledgement = Some(NotificationAcknowledgementV1 {
            request_id,
            principal_id: grant.principal_id,
            authorization_revision: grant.authorization_revision,
            finding_revision: state.finding_revision,
            acknowledged_utc_ns: now,
        });
        self.save(&mut state)?;
        Ok(state)
    }

    pub fn record_agent(
        &self,
        grant: &NotificationGrantV1,
        key: NotificationKeyV1,
        request_id: [u8; 16],
        advisory: Option<NotificationAdvisoryV1>,
        now: u64,
    ) -> Result<NotificationObligationV1> {
        let _guard = self.lock()?;
        let mut state =
            self.authorized_state(grant, key, NotificationOperationV1::RecordAgent, now)?;
        NotificationErrorCodeV1::Denied.require(
            grant.principal == NotificationPrincipalV1::Agent && request_id != [0; 16],
            "agent receipt",
        )?;
        NotificationErrorCodeV1::Invalid.require(
            now >= state.first_seen_utc_ns
                && advisory
                    .as_ref()
                    .is_none_or(|value| NotificationGrantV1::identifier(&value.model_label, 128)),
            "agent report",
        )?;
        if let Some(receipt) = &state.agent_receipt {
            NotificationErrorCodeV1::Conflict.require(
                receipt.request_id == request_id
                    && receipt.principal_id == grant.principal_id
                    && state.advisory == advisory,
                "agent retry",
            )?;
            return Ok(state);
        }
        state.agent_receipt = Some(NotificationAgentReceiptV1 {
            request_id,
            principal_id: grant.principal_id,
            authorization_revision: grant.authorization_revision,
            received_utc_ns: now,
        });
        state.advisory = advisory;
        self.save(&mut state)?;
        Ok(state)
    }

    pub(super) fn authorized_state(
        &self,
        grant: &NotificationGrantV1,
        key: NotificationKeyV1,
        operation: NotificationOperationV1,
        now: u64,
    ) -> Result<NotificationObligationV1> {
        grant.validate()?;
        self.authority.check(grant, now)?;
        NotificationErrorCodeV1::Denied
            .require(grant.tenant_id == key.tenant_id, "notification tenant")?;
        let state = self
            .store
            .context_head(
                key.tenant_id,
                NOTIFICATION_STATE_OWNER,
                &key.notification_id,
                b"obligation",
            )?
            .as_ref()
            .map(NotificationObligationV1::try_from)
            .transpose()?
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "notification scope",
                }
                .build()
            })?;
        NotificationErrorCodeV1::Denied.require(
            state
                .route
                .as_ref()
                .is_some_and(|route| grant.allows(key.tenant_id, &route.route_id, operation, now))
                && NotificationGrantV1::sensitivity(grant.max_sensitivity, state.sensitivity),
            "notification operation",
        )?;
        Ok(state)
    }
}
