use std::collections::BTreeMap;
use std::ops::Deref;

use araphor_data::analysis::PreparedNotificationBatch;

use super::*;

pub(super) struct NotificationCycle<'a, 'b> {
    router: &'a NotificationRouter,
    tenant: [u8; 16],
    pub(super) prepared: PreparedNotificationBatch<'b>,
    sizes: BTreeMap<NotificationKeyV1, usize>,
}

impl Deref for NotificationCycle<'_, '_> {
    type Target = NotificationRouter;

    fn deref(&self) -> &Self::Target {
        self.router
    }
}

impl<'a, 'b> NotificationCycle<'a, 'b> {
    pub(super) fn new(
        router: &'a NotificationRouter,
        tenant: [u8; 16],
        prepared: PreparedNotificationBatch<'b>,
    ) -> Self {
        let sizes = prepared
            .states()
            .map(|(state, bytes)| (state.key, bytes))
            .collect();
        Self {
            router,
            tenant,
            prepared,
            sizes,
        }
    }

    fn check_tenant(&self, tenant: [u8; 16]) -> Result<()> {
        NotificationErrorCodeV1::Denied.require(tenant == self.tenant, "notification scope")?;
        Ok(())
    }

    pub(super) fn routes(&self, tenant: [u8; 16]) -> Result<Vec<ApprovedNotificationRouteV1>> {
        self.check_tenant(tenant)?;
        Ok(self.prepared.routes()?.to_vec())
    }

    pub(super) fn route_version(
        &self,
        tenant: [u8; 16],
        reference: &NotificationRouteRefV1,
    ) -> Result<Option<ApprovedNotificationRouteV1>> {
        self.check_tenant(tenant)?;
        Ok(self.prepared.route(reference)?.cloned())
    }

    pub(super) fn state(&self, key: NotificationKeyV1) -> Result<NotificationObligationV1> {
        self.check_tenant(key.tenant_id)?;
        NotificationErrorCodeV1::Invalid
            .require(key.notification_id != [0; 16], "notification key")?;
        self.prepared.check_state(key)?;
        self.prepared
            .states()
            .find(|(state, _)| state.key == key)
            .map(|(state, _)| state.clone())
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "notification scope",
                }
                .build()
                .into()
            })
    }

    pub(super) fn finding_version(
        &self,
        key: NotificationKeyV1,
        revision: u64,
    ) -> Result<NotificationObligationV1> {
        self.check_tenant(key.tenant_id)?;
        Ok(self.prepared.subject(key, revision)?.clone())
    }

    pub(super) fn related_states(
        &self,
        finding: &FindingV1,
    ) -> Result<Vec<NotificationObligationV1>> {
        self.check_tenant(finding.tenant_id)?;
        Ok(self
            .prepared
            .states()
            .filter(|(state, _)| {
                state
                    .finding
                    .as_ref()
                    .is_some_and(|reference| reference.finding_id == finding.finding_id)
                    && state.required_action == finding.required_action
            })
            .map(|(state, _)| state.clone())
            .collect())
    }

    pub(super) fn save(&mut self, state: &mut NotificationObligationV1) -> Result<()> {
        let bytes = self.router.save_bytes(state)?;
        self.sizes.insert(state.key, bytes);
        Ok(())
    }

    pub(super) fn clone_subject(
        &mut self,
        state: &NotificationObligationV1,
    ) -> Result<NotificationObligationV1> {
        let bytes = self.sizes.get(&state.key).copied().ok_or_else(|| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Conflict,
                field: "persisted attempt subject",
            }
            .build()
        })?;
        NotificationErrorCodeV1::Conflict
            .require(state.revision > 0, "persisted attempt subject")?;
        self.prepared.charge(bytes.saturating_mul(12))?;
        Ok(state.clone())
    }
}

impl NotificationRouter {
    pub(super) fn with_cycle<T>(
        &self,
        tenant: [u8; 16],
        references: &[NotificationFindingRefV1],
        keys: &[NotificationKeyV1],
        run: impl FnOnce(&mut NotificationCycle<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let control = araphor_data::AnalysisReadControl::default();
        let memory = araphor_query::memory::Memory::new(None, None);
        let budget = memory.managed_budget(&control, usize::MAX);
        let prepared = self.store.prepare_notifications(
            tenant,
            references,
            keys,
            &control,
            budget.as_ref(),
        )?;
        run(&mut NotificationCycle::new(self, tenant, prepared))
    }
}
