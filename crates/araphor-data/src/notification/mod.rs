use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, ContextSensitivityV1, FindingV1,
    GraphAndFindingOwner, NotificationEncodingSnafu, Result,
};

mod model;
pub use model::*;
#[cfg(test)]
mod tests;

pub struct NotificationRouter {
    store: Arc<AnalysisStore>,
    authority: Arc<dyn NotificationAuthorization>,
    operation: Mutex<WorkCursors>,
}

#[derive(Default)]
struct WorkCursors {
    routing: Option<RoutingCursor>,
    delivery: Option<DeliveryCursor>,
}

struct RoutingCursor {
    tenant: [u8; 16],
    finding_id: Option<String>,
}

struct DeliveryCursor {
    tenant: [u8; 16],
    context: Option<AnalysisContextKeyV1>,
}

impl NotificationRouter {
    pub fn new(
        store: Arc<AnalysisStore>,
        authority: Arc<dyn NotificationAuthorization>,
    ) -> Result<Self> {
        NotificationErrorCodeV1::Conflict.require(
            store
                .notification_owner
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "router owner",
        )?;
        Ok(Self {
            store,
            authority,
            operation: Mutex::new(WorkCursors::default()),
        })
    }

    pub fn configure(
        &self,
        grant: &NotificationGrantV1,
        policy: NotificationPolicyV1,
        now: u64,
    ) -> Result<()> {
        let _guard = self.lock()?;
        grant.validate()?;
        policy.validate()?;
        self.authority.check(grant, now)?;
        NotificationErrorCodeV1::Denied.require(
            grant.allows(
                policy.tenant_id,
                &policy.route_id,
                NotificationOperationV1::Configure,
                now,
            ) && NotificationGrantV1::sensitivity(grant.max_sensitivity, policy.max_sensitivity),
            "route approval",
        )?;
        let routes = self.routes(policy.tenant_id)?;
        let prior = routes
            .iter()
            .find(|route| route.policy.route_id == policy.route_id);
        let approved = ApprovedNotificationRouteV1 {
            policy,
            grant: grant.clone(),
            approved_utc_ns: now,
        };
        if let Some(prior) = prior {
            if prior.policy == approved.policy && prior.grant == approved.grant {
                return Ok(());
            }
        }
        NotificationErrorCodeV1::Limit.require(
            prior.is_some() || routes.len() < MAX_NOTIFICATION_ROUTES,
            "route count",
        )?;
        let expected = prior.map_or(0, |route| route.policy.revision);
        NotificationErrorCodeV1::Conflict.require(
            expected.checked_add(1) == Some(approved.policy.revision),
            "route revision",
        )?;
        self.persist(
            &AnalysisContextKeyV1 {
                tenant_id: approved.policy.tenant_id,
                owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                entity_key: approved.policy.route_id.as_bytes().to_vec(),
                lifetime_key: b"route".to_vec(),
                owner_revision: approved.policy.revision,
            },
            &approved,
            expected,
            ContextSensitivityV1::HostRestricted,
        )
    }

    pub fn route(&self, graph: &GraphAndFindingOwner, now: u64) -> Result<usize> {
        let mut work = self.lock()?;
        NotificationErrorCodeV1::Invalid.require(now > 0, "routing time")?;
        let mut tenant = match &work.routing {
            Some(cursor) => Some(cursor.tenant),
            None => self.store.tenant_page(None)?.first().copied(),
        };
        let mut after = work
            .routing
            .as_ref()
            .and_then(|cursor| cursor.finding_id.clone());
        let mut count = 0;
        for _ in 0..MAX_NOTIFICATION_STATES {
            let Some(current) = tenant else {
                work.routing = None;
                break;
            };
            if let Some((result_id, finding)) =
                graph.next_current_finding(current, after.as_deref())?
            {
                let routes = self.routes(current)?;
                let mut states = self.related_states(&finding)?;
                count += self.schedule(graph, &finding, &result_id, &routes, &mut states, now)?;
                after = Some(finding.finding_id);
                work.routing = Some(RoutingCursor {
                    tenant: current,
                    finding_id: after.clone(),
                });
            } else {
                tenant = self.store.tenant_page(Some(current))?.first().copied();
                after = None;
                work.routing = tenant.map(|tenant| RoutingCursor {
                    tenant,
                    finding_id: None,
                });
            }
        }
        Ok(count)
    }

    pub fn route_finding(
        &self,
        graph: &GraphAndFindingOwner,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        now: u64,
    ) -> Result<usize> {
        let _guard = self.lock()?;
        NotificationErrorCodeV1::Invalid.require(now > 0, "routing time")?;
        let (result_id, finding) = graph
            .current_finding(tenant, &reference.finding_id)?
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "current finding scope",
                }
                .build()
            })?;
        NotificationErrorCodeV1::Conflict.require(
            result_id == reference.result_id,
            "current finding reference",
        )?;
        let routes = self.routes(tenant)?;
        let mut states = self.related_states(&finding)?;
        self.schedule(graph, &finding, &result_id, &routes, &mut states, now)
    }

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
        while examined < MAX_NOTIFICATION_STATES {
            let Some(current) = tenant else {
                work.delivery = None;
                break;
            };
            let page = self.state_page(current, after.as_ref())?;
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
                delivered += self.deliver_state(&mut state, graph, sink, now)?;
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
        Ok(delivered)
    }

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
        let mut states = self.states_matching(grant.tenant_id, |state| {
            state
                .unconfirmed_concern
                .as_ref()
                .is_some_and(|prior| prior.concern_id == concern.concern_id)
                && state
                    .route
                    .as_ref()
                    .is_some_and(|route| route.route_id == route_id)
        })?;
        if let Some(state) = states.iter().find(|state| {
            state
                .unconfirmed_concern
                .as_ref()
                .is_some_and(|prior| prior.concern_id == concern.concern_id)
                && state
                    .route
                    .as_ref()
                    .is_some_and(|route| route.route_id == route_id)
        }) {
            NotificationErrorCodeV1::Conflict.require(
                state.unconfirmed_concern.as_ref() == Some(&concern)
                    && state
                        .agent_receipt
                        .is_some_and(|receipt| receipt.principal_id == grant.principal_id),
                "concern retry",
            )?;
            return Ok(state.clone());
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
            escalation: routes
                .iter()
                .find(|candidate| candidate.policy.route_id == route.policy.escalation_route_id)
                .map(|candidate| (&candidate.policy).into()),
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
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
        };
        self.insert(&mut state, &mut states)?;
        Ok(state)
    }

    fn authorized_state(
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

    fn schedule(
        &self,
        graph: &GraphAndFindingOwner,
        finding: &FindingV1,
        result_id: &str,
        routes: &[ApprovedNotificationRouteV1],
        states: &mut Vec<NotificationObligationV1>,
        now: u64,
    ) -> Result<usize> {
        let matching: Vec<_> = routes
            .iter()
            .filter(|route| {
                route.policy.package_ids.contains(&finding.package_id)
                    && self.authority.check(&route.grant, now).is_ok()
                    && route.grant.allows(
                        finding.tenant_id,
                        &route.policy.route_id,
                        NotificationOperationV1::Configure,
                        now,
                    )
            })
            .collect();
        let related = |state: &NotificationObligationV1| {
            state
                .finding
                .as_ref()
                .is_some_and(|value| value.finding_id == finding.finding_id)
                && state.required_action == finding.required_action
        };
        let first_seen = states
            .iter()
            .filter(|state| related(state))
            .map(|state| state.first_seen_utc_ns)
            .min()
            .unwrap_or(now);
        if matching.is_empty() {
            let mut count = 0;
            for state in states.iter_mut().filter(|state| related(state)) {
                let prior = state
                    .finding
                    .as_ref()
                    .map(|reference| {
                        graph.finding_result(
                            finding.tenant_id,
                            &reference.result_id,
                            &reference.finding_id,
                        )
                    })
                    .transpose()?
                    .flatten();
                if prior
                    .as_ref()
                    .is_none_or(|prior| prior.revision != finding.revision)
                {
                    state.finding = Some(NotificationFindingRefV1 {
                        finding_id: finding.finding_id.clone(),
                        result_id: result_id.into(),
                    });
                    state.finding_revision = state.revision.checked_add(1).ok_or_else(|| {
                        crate::NotificationSnafu {
                            code: NotificationErrorCodeV1::Limit,
                            field: "finding delivery revision",
                        }
                        .build()
                    })?;
                    state.source_priority = state.source_priority.max(finding.severity.into());
                    if !NotificationGrantV1::sensitivity(state.sensitivity, finding.sensitivity) {
                        state.sensitivity = finding.sensitivity;
                    }
                    self.save(state)?;
                    count += 1;
                }
            }
            if states.iter().any(related) {
                return Ok(count);
            }
            let mut state = self.obligation(finding, result_id, first_seen);
            state.failure = Some(NotificationFailureV1::NoRoute);
            self.insert(&mut state, states)?;
            return Ok(1);
        }
        let mut count = 0;
        for route in matching {
            if let Some(index) = states.iter().position(|state| {
                related(state)
                    && state
                        .route
                        .as_ref()
                        .is_some_and(|reference| reference.route_id == route.policy.route_id)
            }) {
                let state = &mut states[index];
                let source = NotificationPriorityV1::from(finding.severity);
                let prior = state
                    .finding
                    .as_ref()
                    .map(|reference| {
                        graph.finding_result(
                            finding.tenant_id,
                            &reference.result_id,
                            &reference.finding_id,
                        )
                    })
                    .transpose()?
                    .flatten();
                let changed_finding = prior
                    .as_ref()
                    .is_none_or(|value| value.revision != finding.revision);
                if changed_finding
                    || source > state.source_priority
                    || route.policy.minimum_priority > state.minimum_priority
                    || !NotificationGrantV1::sensitivity(state.sensitivity, finding.sensitivity)
                    || state
                        .route
                        .as_ref()
                        .is_some_and(|reference| reference.revision != route.policy.revision)
                {
                    state.finding = Some(NotificationFindingRefV1 {
                        finding_id: finding.finding_id.clone(),
                        result_id: result_id.into(),
                    });
                    state.source_priority = state.source_priority.max(source);
                    state.minimum_priority =
                        state.minimum_priority.max(route.policy.minimum_priority);
                    state.route = Some((&route.policy).into());
                    state.escalation = routes
                        .iter()
                        .find(|candidate| {
                            candidate.policy.route_id == route.policy.escalation_route_id
                        })
                        .map(|candidate| (&candidate.policy).into());
                    if !NotificationGrantV1::sensitivity(state.sensitivity, finding.sensitivity) {
                        state.sensitivity = finding.sensitivity;
                    }
                    if changed_finding {
                        state.finding_revision =
                            state.revision.checked_add(1).ok_or_else(|| {
                                crate::NotificationSnafu {
                                    code: NotificationErrorCodeV1::Limit,
                                    field: "finding delivery revision",
                                }
                                .build()
                            })?;
                    }
                    self.save(state)?;
                    count += 1;
                }
                continue;
            }
            let pending = states
                .iter()
                .position(|state| related(state) && state.route.is_none());
            let mut state = pending.map_or_else(
                || self.obligation(finding, result_id, first_seen),
                |index| states[index].clone(),
            );
            state.route = Some((&route.policy).into());
            state.finding = Some(NotificationFindingRefV1 {
                finding_id: finding.finding_id.clone(),
                result_id: result_id.into(),
            });
            state.finding_revision = state.revision.checked_add(1).ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Limit,
                    field: "routed finding revision",
                }
                .build()
            })?;
            state.source_priority = state.source_priority.max(finding.severity.into());
            state.minimum_priority = state.minimum_priority.max(route.policy.minimum_priority);
            if !NotificationGrantV1::sensitivity(state.sensitivity, finding.sensitivity) {
                state.sensitivity = finding.sensitivity;
            }
            state.deadline_utc_ns = Some(
                first_seen
                    .checked_add(route.policy.acknowledgement_ns)
                    .ok_or_else(|| {
                        crate::NotificationSnafu {
                            code: NotificationErrorCodeV1::Invalid,
                            field: "acknowledgement deadline",
                        }
                        .build()
                    })?,
            );
            state.escalation = routes
                .iter()
                .find(|candidate| candidate.policy.route_id == route.policy.escalation_route_id)
                .map(|candidate| (&candidate.policy).into());
            state.failure = state
                .escalation
                .is_none()
                .then_some(NotificationFailureV1::NoRoute);
            if let Some(index) = pending {
                self.save(&mut state)?;
                states[index] = state;
            } else {
                self.insert(&mut state, states)?;
            }
            count += 1;
        }
        Ok(count)
    }

    fn obligation(
        &self,
        finding: &FindingV1,
        result_id: &str,
        now: u64,
    ) -> NotificationObligationV1 {
        NotificationObligationV1 {
            schema_version: 1,
            key: NotificationKeyV1 {
                tenant_id: finding.tenant_id,
                notification_id: uuid::Uuid::new_v4().into_bytes(),
            },
            revision: 0,
            finding: Some(NotificationFindingRefV1 {
                finding_id: finding.finding_id.clone(),
                result_id: result_id.into(),
            }),
            unconfirmed_concern: None,
            finding_revision: 1,
            package_id: finding.package_id.clone(),
            required_action: finding.required_action.clone(),
            sensitivity: finding.sensitivity,
            source_priority: finding.severity.into(),
            minimum_priority: NotificationPriorityV1::Info,
            route: None,
            escalation: None,
            first_seen_utc_ns: now,
            deadline_utc_ns: None,
            overdue_since_utc_ns: None,
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
            agent_receipt: None,
            advisory: None,
        }
    }

    fn insert(
        &self,
        state: &mut NotificationObligationV1,
        states: &mut Vec<NotificationObligationV1>,
    ) -> Result<()> {
        NotificationErrorCodeV1::Limit.require(
            states.len() < MAX_NOTIFICATION_ROUTES + 1,
            "related obligation count",
        )?;
        self.save(state)?;
        states.push(state.clone());
        Ok(())
    }

    fn send(
        &self,
        state: &mut NotificationObligationV1,
        graph: &GraphAndFindingOwner,
        sink: &dyn NotificationSink,
        kind: NotificationDeliveryKindV1,
        now: u64,
    ) -> Result<bool> {
        let reference = match kind {
            NotificationDeliveryKindV1::Finding => state.route.as_ref(),
            NotificationDeliveryKindV1::FailureEscalation
            | NotificationDeliveryKindV1::AcknowledgementEscalation => state.escalation.as_ref(),
        };
        let Some(reference) = reference else {
            return Ok(false);
        };
        let Some(route) = self.route_version(state.key.tenant_id, reference)? else {
            if state.failure != Some(NotificationFailureV1::NoRoute) {
                state.failure = Some(NotificationFailureV1::NoRoute);
                self.save(state)?;
            }
            return Ok(false);
        };
        let attempts: Vec<_> = state
            .attempts
            .iter()
            .filter(|attempt| attempt.kind == kind)
            .collect();
        let last = attempts.last().copied();
        let revision_attempts = attempts
            .iter()
            .filter(|attempt| attempt.finding_revision == state.finding_revision)
            .count();
        if last.is_some_and(|attempt| {
            attempt.finding_revision == state.finding_revision
                && attempt
                    .result
                    .as_ref()
                    .is_some_and(NotificationSinkResultV1::accepted)
        }) {
            return Ok(false);
        }
        if let Some(last) = last {
            if last.finding_revision == state.finding_revision
                && last.result.is_some()
                && revision_attempts >= usize::from(route.policy.retry_limit)
            {
                if kind == NotificationDeliveryKindV1::Finding
                    && state.failure != Some(NotificationFailureV1::RetryExhausted)
                {
                    state.failure = Some(NotificationFailureV1::RetryExhausted);
                    self.save(state)?;
                }
                return Ok(false);
            }
            if last.finding_revision == state.finding_revision
                && last.completed_utc_ns.is_some_and(|completed| {
                    now < completed.saturating_add(route.policy.retry_delay_ns)
                })
            {
                return Ok(false);
            }
        }
        let number = if let Some(last) = last.filter(|attempt| attempt.result.is_none()) {
            last.number
        } else {
            NotificationErrorCodeV1::Limit
                .require(state.attempts.len() < 48, "delivery attempts")?;
            let number = u16::try_from(state.attempts.len() + 1).map_err(|_| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Limit,
                    field: "delivery attempts",
                }
                .build()
            })?;
            state.attempts.push(NotificationAttemptV1 {
                number,
                kind,
                finding_revision: state.finding_revision,
                context_revision: state.revision,
                priority: state.priority().max(route.policy.minimum_priority),
                started_utc_ns: now,
                completed_utc_ns: None,
                result: None,
            });
            self.save(state)?;
            number
        };
        let pending = state
            .attempts
            .iter()
            .find(|attempt| attempt.kind == kind && attempt.number == number)
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Conflict,
                    field: "pending attempt",
                }
                .build()
            })?;
        NotificationErrorCodeV1::Invalid.require(now >= pending.started_utc_ns, "delivery time")?;
        let priority = pending.priority;
        let started = pending.started_utc_ns;
        let subject = self.finding_version(state.key, pending.context_revision)?;
        let overdue = subject.overdue(started);
        let captured_route = match kind {
            NotificationDeliveryKindV1::Finding => subject.route.as_ref(),
            NotificationDeliveryKindV1::FailureEscalation
            | NotificationDeliveryKindV1::AcknowledgementEscalation => subject.escalation.as_ref(),
        }
        .ok_or_else(|| {
            crate::NotificationSnafu {
                code: NotificationErrorCodeV1::Invalid,
                field: "attempt route",
            }
            .build()
        })?;
        let route = self
            .route_version(state.key.tenant_id, captured_route)?
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "attempt approved route",
                }
                .build()
            })?;
        let finding = subject
            .finding
            .as_ref()
            .map(|reference| {
                graph.finding_result(
                    state.key.tenant_id,
                    &reference.result_id,
                    &reference.finding_id,
                )
            })
            .transpose()?
            .flatten()
            .map(|finding| NotificationFindingV1 {
                finding_id: finding.finding_id,
                revision: finding.revision,
            });
        let finding_available = finding.is_some() || subject.unconfirmed_concern.is_some();
        let result = if self.authority.check(&route.grant, now).is_err()
            || !route.grant.allows(
                state.key.tenant_id,
                &route.policy.route_id,
                NotificationOperationV1::Configure,
                now,
            ) {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::AuthorizationRevoked,
            }
        } else if !NotificationGrantV1::sensitivity(route.policy.max_sensitivity, state.sensitivity)
            || !NotificationGrantV1::sensitivity(route.grant.max_sensitivity, state.sensitivity)
        {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::DisclosureDenied,
            }
        } else if !finding_available {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::FindingUnavailable,
            }
        } else {
            let mut result = sink.deliver(&NotificationDeliveryV1 {
                key: state.key,
                attempt: number,
                kind,
                route_id: route.policy.route_id,
                route_revision: route.policy.revision,
                finding,
                unconfirmed_concern: subject.unconfirmed_concern,
                required_action: state.required_action.clone(),
                priority,
                deadline_utc_ns: state.deadline_utc_ns.ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: NotificationErrorCodeV1::Invalid,
                        field: "stored deadline",
                    }
                    .build()
                })?,
                overdue,
            });
            if !result.valid() {
                result = NotificationSinkResultV1::Failed {
                    reason: NotificationFailureV1::InvalidSinkResult,
                };
            }
            result
        };
        let attempt = state
            .attempts
            .iter_mut()
            .find(|attempt| attempt.kind == kind && attempt.number == number)
            .ok_or_else(|| {
                crate::NotificationSnafu {
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
            _ if kind == NotificationDeliveryKindV1::Finding => state.failure = None,
            _ => {}
        }
        self.save(state)?;
        Ok(true)
    }

    fn routes(&self, tenant: [u8; 16]) -> Result<Vec<ApprovedNotificationRouteV1>> {
        self.store
            .context_heads(tenant, NOTIFICATION_ROUTE_OWNER, MAX_NOTIFICATION_ROUTES)?
            .iter()
            .map(ApprovedNotificationRouteV1::try_from)
            .collect()
    }

    fn route_version(
        &self,
        tenant: [u8; 16],
        reference: &NotificationRouteRefV1,
    ) -> Result<Option<ApprovedNotificationRouteV1>> {
        self.store
            .context_version(&AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                entity_key: reference.route_id.as_bytes().to_vec(),
                lifetime_key: b"route".to_vec(),
                owner_revision: reference.revision,
            })?
            .as_ref()
            .map(ApprovedNotificationRouteV1::try_from)
            .transpose()
    }

    fn finding_version(
        &self,
        key: NotificationKeyV1,
        revision: u64,
    ) -> Result<NotificationObligationV1> {
        let version = self
            .store
            .context_version(&AnalysisContextKeyV1 {
                tenant_id: key.tenant_id,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: key.notification_id.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision: revision,
            })?
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "attempt finding revision",
                }
                .build()
            })?;
        NotificationObligationV1::try_from(&version)
    }

    fn state_page(
        &self,
        tenant: [u8; 16],
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<NotificationObligationV1>> {
        self.store
            .context_head_page(tenant, NOTIFICATION_STATE_OWNER, after)?
            .iter()
            .map(NotificationObligationV1::try_from)
            .collect()
    }

    fn states_matching(
        &self,
        tenant: [u8; 16],
        matches: impl Fn(&NotificationObligationV1) -> bool,
    ) -> Result<Vec<NotificationObligationV1>> {
        let mut after = None;
        let mut states = Vec::new();
        loop {
            let page = self.state_page(tenant, after.as_ref())?;
            let Some(last) = page.last() else {
                return Ok(states);
            };
            after = Some(Self::state_key(last));
            for state in page.into_iter().filter(&matches) {
                NotificationErrorCodeV1::Limit.require(
                    states.len() < MAX_NOTIFICATION_ROUTES + 1,
                    "related obligation count",
                )?;
                states.push(state);
            }
        }
    }

    fn related_states(&self, finding: &FindingV1) -> Result<Vec<NotificationObligationV1>> {
        self.states_matching(finding.tenant_id, |state| {
            state
                .finding
                .as_ref()
                .is_some_and(|reference| reference.finding_id == finding.finding_id)
                && state.required_action == finding.required_action
        })
    }

    fn state_key(state: &NotificationObligationV1) -> AnalysisContextKeyV1 {
        AnalysisContextKeyV1 {
            tenant_id: state.key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: state.revision,
        }
    }

    fn deliver_state(
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
        if state.overdue(now) && state.overdue_since_utc_ns.is_none() {
            state.overdue_since_utc_ns = state.deadline_utc_ns;
            self.save(state)?;
        }
        let mut delivered =
            usize::from(self.send(state, graph, sink, NotificationDeliveryKindV1::Finding, now)?);
        if state.failure.is_some() {
            delivered += usize::from(self.send(
                state,
                graph,
                sink,
                NotificationDeliveryKindV1::FailureEscalation,
                now,
            )?);
        }
        if state.overdue(now) {
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

    fn save(&self, state: &mut NotificationObligationV1) -> Result<()> {
        let previous = state.revision;
        state.revision = previous.checked_add(1).ok_or_else(|| {
            crate::NotificationSnafu {
                code: NotificationErrorCodeV1::Limit,
                field: "obligation revision",
            }
            .build()
        })?;
        state.validate()?;
        let result = self.persist(&Self::state_key(state), state, previous, state.sensitivity);
        if result.is_err() {
            state.revision = previous;
        }
        result
    }

    fn persist(
        &self,
        key: &AnalysisContextKeyV1,
        value: &impl Serialize,
        expected: u64,
        sensitivity: ContextSensitivityV1,
    ) -> Result<()> {
        let body = serde_json::to_vec(value).context(NotificationEncodingSnafu)?;
        NotificationErrorCodeV1::Limit.require(body.len() <= 32 * 1024, "state bytes")?;
        self.store.commit_context_checked(
            &AnalysisContextVersionV1 {
                key: key.clone(),
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity,
                body,
            },
            expected,
        )?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, WorkCursors>> {
        self.operation.lock().map_err(|_| {
            crate::NotificationSnafu {
                code: NotificationErrorCodeV1::Unavailable,
                field: "router lock",
            }
            .build()
        })
    }
}

impl Drop for NotificationRouter {
    fn drop(&mut self) {
        self.store
            .notification_owner
            .store(false, Ordering::Release);
    }
}
