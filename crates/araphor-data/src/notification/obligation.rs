use super::*;

impl NotificationRouter {
    pub(super) fn schedule(
        &self,
        graph: &GraphAndFindingOwner,
        finding: &FindingV1,
        result_id: &str,
        routes: &[ApprovedNotificationRouteV1],
        now: u64,
    ) -> Result<usize> {
        let mut states = self.related_states(finding)?;
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
        let first_seen = states
            .iter()
            .map(|state| state.first_seen_utc_ns)
            .min()
            .unwrap_or(now);
        if matching.is_empty() {
            let mut count = 0;
            for state in &mut states {
                if self.update_finding(state, graph, finding, result_id)? {
                    self.save(state)?;
                    count += 1;
                }
            }
            if !states.is_empty() {
                return Ok(count);
            }
            let mut state = self.obligation(finding, result_id, first_seen);
            state.failure = Some(NotificationFailureV1::NoRoute);
            self.insert(&mut state, &mut states)?;
            return Ok(1);
        }
        let mut count = 0;
        for route in matching {
            if let Some(index) = states.iter().position(|state| {
                state
                    .route
                    .as_ref()
                    .is_some_and(|reference| reference.route_id == route.policy.route_id)
            }) {
                let state = &mut states[index];
                let mut changed = self.update_finding(state, graph, finding, result_id)?;
                changed |= Self::update_route(state, &route.policy, routes);
                if changed {
                    self.save(state)?;
                    count += 1;
                }
                continue;
            }
            let pending = states.iter().position(|state| state.route.is_none());
            let mut state = pending.map_or_else(
                || self.obligation(finding, result_id, first_seen),
                |index| states[index].clone(),
            );
            self.update_finding(&mut state, graph, finding, result_id)?;
            Self::update_route(&mut state, &route.policy, routes);
            state.finding_revision = state.revision.checked_add(1).ok_or_else(|| {
                crate::NotificationSnafu {
                    code: NotificationErrorCodeV1::Limit,
                    field: "routed finding revision",
                }
                .build()
            })?;
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
            if let Some(index) = pending {
                self.save(&mut state)?;
                states[index] = state;
            } else {
                self.insert(&mut state, &mut states)?;
            }
            count += 1;
        }
        Ok(count)
    }

    fn update_finding(
        &self,
        state: &mut NotificationObligationV1,
        graph: &GraphAndFindingOwner,
        finding: &FindingV1,
        result_id: &str,
    ) -> Result<bool> {
        let changed_finding = match &state.finding {
            Some(reference) if reference.result_id == result_id => false,
            Some(reference) => graph
                .finding_result(
                    finding.tenant_id,
                    &reference.result_id,
                    &reference.finding_id,
                )?
                .is_none_or(|prior| prior.revision != finding.revision),
            None => true,
        };
        let source = NotificationPriorityV1::from(finding.severity);
        let raised_sensitivity =
            !NotificationGrantV1::sensitivity(state.sensitivity, finding.sensitivity);
        let changed = changed_finding || source > state.source_priority || raised_sensitivity;
        if changed {
            state.finding = Some(NotificationFindingRefV1 {
                finding_id: finding.finding_id.clone(),
                result_id: result_id.into(),
            });
            state.source_priority = state.source_priority.max(source);
            if raised_sensitivity {
                state.sensitivity = finding.sensitivity;
            }
            if changed_finding {
                state.finding_revision = state.revision.checked_add(1).ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: NotificationErrorCodeV1::Limit,
                        field: "finding delivery revision",
                    }
                    .build()
                })?;
            }
        }
        Ok(changed)
    }

    pub(super) fn update_route(
        state: &mut NotificationObligationV1,
        policy: &NotificationPolicyV1,
        routes: &[ApprovedNotificationRouteV1],
    ) -> bool {
        let route = NotificationRouteRefV1::from(policy);
        let escalation = Self::escalation(policy, routes);
        let mut changed = state.route.as_ref() != Some(&route)
            || state.escalation != escalation
            || policy.minimum_priority > state.minimum_priority;
        state.route = Some(route);
        state.escalation = escalation;
        state.minimum_priority = state.minimum_priority.max(policy.minimum_priority);
        if state.escalation.is_none() && state.failure.is_none() {
            state.failure = Some(NotificationFailureV1::NoRoute);
            changed = true;
        } else if state.escalation.is_some()
            && state.failure == Some(NotificationFailureV1::NoRoute)
        {
            state.failure = None;
            changed = true;
        }
        changed
    }

    pub(super) fn escalation(
        policy: &NotificationPolicyV1,
        routes: &[ApprovedNotificationRouteV1],
    ) -> Option<NotificationRouteRefV1> {
        routes
            .iter()
            .find(|route| route.policy.route_id == policy.escalation_route_id)
            .map(|route| (&route.policy).into())
    }

    pub(super) fn obligation(
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
            attempt_sequence: 0,
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
            agent_receipt: None,
            advisory: None,
        }
    }

    pub(super) fn insert(
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
}
