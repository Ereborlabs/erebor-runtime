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
            prior.is_some()
                || self
                    .store
                    .storage_limits()
                    .notification_routes
                    .is_none_or(|limit| routes.len() < limit),
            "route count",
        )?;
        let expected = prior.map_or(0, |route| route.policy.revision);
        NotificationErrorCodeV1::Conflict.require(
            expected.checked_add(1) == Some(approved.policy.revision),
            "route revision",
        )?;
        self.persist(
            AnalysisContextKeyV1 {
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

    pub fn route_finding(
        &self,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        now: u64,
    ) -> Result<usize> {
        let _guard = self.lock()?;
        self.route_states(tenant, reference, now)
            .map(|(count, _)| count)
    }

    // The caller holds the router lock.
    pub(super) fn route_states(
        &self,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        now: u64,
    ) -> Result<(usize, Vec<NotificationObligationV1>)> {
        NotificationErrorCodeV1::Invalid.require(now > 0, "finding reference")?;
        let (finding, revision) = self.store.notification_finding(tenant, reference)?;
        let routes = self.routes(tenant)?;
        self.schedule(&finding, &revision, &reference.result_id, &routes, now)
    }
}
