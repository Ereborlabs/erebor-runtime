use super::*;
use crate::analysis::NotificationLookup;
use snafu::ResultExt as _;

impl NotificationRouter {
    pub(super) fn routes(&self, tenant: [u8; 16]) -> Result<Vec<ApprovedNotificationRouteV1>> {
        self.store
            .context_heads(tenant, NOTIFICATION_ROUTE_OWNER, MAX_NOTIFICATION_ROUTES)?
            .iter()
            .map(ApprovedNotificationRouteV1::try_from)
            .collect()
    }

    pub(super) fn route_version(
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

    pub(super) fn finding_version(
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

    pub(super) fn state_page(
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

    pub(super) fn related_states(
        &self,
        finding: &FindingV1,
    ) -> Result<Vec<NotificationObligationV1>> {
        let contexts = self.store.notification_states(
            finding.tenant_id,
            NotificationLookup::Finding(&finding.finding_id, finding.required_action.as_deref()),
        )?;
        NotificationErrorCodeV1::Limit.require(
            contexts.len() <= MAX_NOTIFICATION_ROUTES + 1,
            "related obligation count",
        )?;
        contexts
            .iter()
            .map(NotificationObligationV1::try_from)
            .collect()
    }

    pub(super) fn state_key(state: &NotificationObligationV1) -> AnalysisContextKeyV1 {
        AnalysisContextKeyV1 {
            tenant_id: state.key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: state.revision,
        }
    }

    pub(super) fn save(&self, state: &mut NotificationObligationV1) -> Result<()> {
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

    pub(super) fn persist(
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
}
