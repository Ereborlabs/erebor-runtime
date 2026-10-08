use super::*;
use crate::analysis::NotificationLookup;

impl NotificationRouter {
    pub(super) fn refresh_concern(
        &self,
        state: &mut NotificationObligationV1,
        now: u64,
    ) -> Result<()> {
        let routes = self.routes(state.key.tenant_id)?;
        if let Some(route) = routes.iter().find(|route| {
            state
                .route
                .as_ref()
                .is_some_and(|reference| reference.route_id == route.policy.route_id)
                && self.authority.check(&route.grant, now).is_ok()
                && route.grant.allows(
                    state.key.tenant_id,
                    &route.policy.route_id,
                    NotificationOperationV1::Configure,
                    now,
                )
        }) {
            if Self::update_route(state, &route.policy, &routes) {
                self.save(state)?;
            }
        }
        Ok(())
    }

    pub fn submit_concern(
        &self,
        grant: &NotificationGrantV1,
        route_id: &str,
        concern: UnconfirmedNotificationConcernV1,
        now: u64,
    ) -> Result<NotificationObligationV1> {
        let _guard = self.lock()?;
        grant.validate()?;
        concern.validate(grant.tenant_id)?;
        self.authority.check(grant, now)?;
        NotificationErrorCodeV1::Denied.require(
            grant.principal == NotificationPrincipalV1::Agent
                && grant.allows(
                    grant.tenant_id,
                    route_id,
                    NotificationOperationV1::SubmitConcern,
                    now,
                )
                && NotificationGrantV1::sensitivity(grant.max_sensitivity, concern.sensitivity),
            "concern submission",
        )?;
        let routes = self.routes(grant.tenant_id)?;
        let route = routes
            .iter()
            .find(|route| route.policy.route_id == route_id)
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "concern route",
                }
                .build()
            })?;
        self.authority.check(&route.grant, now)?;
        NotificationErrorCodeV1::Denied.require(
            route.policy.allow_concerns
                && route.grant.allows(
                    grant.tenant_id,
                    route_id,
                    NotificationOperationV1::Configure,
                    now,
                )
                && NotificationGrantV1::sensitivity(
                    route.policy.max_sensitivity,
                    concern.sensitivity,
                ),
            "concern route approval",
        )?;
        for key in &concern.context {
            let context = self.store.context_version(key)?.ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Invalid,
                    field: "concern context version",
                }
                .build()
            })?;
            NotificationErrorCodeV1::Denied.require(
                NotificationGrantV1::sensitivity(concern.sensitivity, context.sensitivity),
                "concern context sensitivity",
            )?;
        }
        let contexts = self.store.notification_states(
            grant.tenant_id,
            NotificationLookup::Concern(concern.concern_id, route_id),
        )?;
        NotificationErrorCodeV1::Conflict
            .require(contexts.len() <= 1, "concern obligation count")?;
        if let Some(context) = contexts.first() {
            let state = NotificationObligationV1::try_from(context)?;
            NotificationErrorCodeV1::Conflict.require(
                state.unconfirmed_concern.as_ref() == Some(&concern)
                    && state
                        .agent_receipt
                        .is_some_and(|receipt| receipt.principal_id == grant.principal_id),
                "concern retry",
            )?;
            return Ok(state);
        }
        let mut state = NotificationObligationV1 {
            schema_version: 1,
            key: NotificationKeyV1 {
                tenant_id: grant.tenant_id,
                notification_id: uuid::Uuid::new_v4().into_bytes(),
            },
            revision: 0,
            finding: None,
            finding_revision: 1,
            package_id: "model-concern".into(),
            required_action: Some("review unconfirmed concern".into()),
            sensitivity: concern.sensitivity,
            source_priority: NotificationPriorityV1::Info,
            minimum_priority: route.policy.minimum_priority,
            advisory: Some(NotificationAdvisoryV1 {
                suggested_priority: concern.suggested_priority,
                model_label: concern.model_label.clone(),
            }),
            agent_receipt: Some(NotificationAgentReceiptV1 {
                request_id: concern.concern_id,
                principal_id: grant.principal_id,
                authorization_revision: grant.authorization_revision,
                received_utc_ns: now,
            }),
            unconfirmed_concern: Some(concern),
            route: Some((&route.policy).into()),
            escalation: Self::escalation(&route.policy, &routes),
            first_seen_utc_ns: now,
            deadline_utc_ns: Some(
                now.checked_add(route.policy.acknowledgement_ns)
                    .ok_or_else(|| {
                        crate::NotificationSnafu {
                            code: NotificationErrorCodeV1::Invalid,
                            field: "concern deadline",
                        }
                        .build()
                    })?,
            ),
            overdue_since_utc_ns: None,
            attempt_sequence: 0,
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
        };
        self.save(&mut state)?;
        Ok(state)
    }
}
