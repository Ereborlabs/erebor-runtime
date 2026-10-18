use super::*;

impl NotificationRouter {
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
        let mut examined = 0;
        let mut failure = None;
        while examined < MAX_NOTIFICATION_STATES {
            let Some(current) = tenant else {
                work.routing = None;
                break;
            };
            let findings = match graph.next_current_findings(
                current,
                after.as_deref(),
                MAX_NOTIFICATION_STATES - examined,
            ) {
                Ok(findings) => findings,
                Err(error) => {
                    let _ = failure.get_or_insert(error);
                    Vec::new()
                }
            };
            if findings.is_empty() {
                tenant = self.store.tenant_page(Some(current))?.first().copied();
                after = None;
                work.routing = tenant.map(|tenant| RoutingCursor {
                    tenant,
                    finding_id: None,
                });
                examined += 1;
                continue;
            }
            let routes = match self.routes(current) {
                Ok(routes) => Some(routes),
                Err(error) => {
                    let _ = failure.get_or_insert(error);
                    None
                }
            };
            for (result_id, finding) in findings {
                if let Some(routes) = &routes {
                    match self.schedule(graph, &finding, &result_id, routes, now) {
                        Ok(scheduled) => count += scheduled,
                        Err(error) => {
                            let _ = failure.get_or_insert(error);
                        }
                    }
                }
                after = Some(finding.finding_id);
                work.routing = Some(RoutingCursor {
                    tenant: current,
                    finding_id: after.clone(),
                });
                examined += 1;
            }
        }
        failure.map_or(Ok(count), Err)
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
        self.schedule(graph, &finding, &result_id, &routes, now)
    }
}
