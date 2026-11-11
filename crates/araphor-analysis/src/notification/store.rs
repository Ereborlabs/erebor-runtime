use super::*;
use araphor_data::analysis::NotificationLookup;

impl NotificationRouter {
    pub(super) fn state(&self, key: NotificationKeyV1) -> Result<NotificationObligationV1> {
        NotificationErrorCodeV1::Invalid.require(
            key.tenant_id != [0; 16] && key.notification_id != [0; 16],
            "notification key",
        )?;
        self.store
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
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "notification scope",
                }
                .build()
                .into()
            })
    }

    pub(super) fn routes(&self, tenant: [u8; 16]) -> Result<Vec<ApprovedNotificationRouteV1>> {
        let contexts = self
            .store
            .context_heads(tenant, NOTIFICATION_ROUTE_OWNER, usize::MAX)?;
        contexts
            .iter()
            .map(|value| ApprovedNotificationRouteV1::try_from(value).map_err(Into::into))
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
            .map_err(Into::into)
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
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "attempt finding revision",
                }
                .build()
            })?;
        Ok(NotificationObligationV1::try_from(&version)?)
    }

    pub(super) fn state_page(
        &self,
        tenant: [u8; 16],
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<NotificationObligationV1>> {
        self.store
            .context_head_page(tenant, NOTIFICATION_STATE_OWNER, after)?
            .iter()
            .map(|value| NotificationObligationV1::try_from(value).map_err(Into::into))
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
        contexts
            .iter()
            .map(|value| NotificationObligationV1::try_from(value).map_err(Into::into))
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
        self.save_bytes(state).map(|_| ())
    }

    pub(super) fn save_bytes(&self, state: &mut NotificationObligationV1) -> Result<usize> {
        let started = std::time::Instant::now();
        let previous = state.revision;
        state.revision = previous.checked_add(1).ok_or_else(|| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Limit,
                field: "obligation revision",
            }
            .build()
        })?;
        let result = (|| {
            let body = state.encode()?;
            let bytes = body.len();
            self.persist(Self::state_key(state), body, previous, state.sensitivity)?;
            erebor_telemetry::debug!(
                stage = "notification_save_timing",
                notification_id = %uuid::Uuid::from_bytes(state.key.notification_id),
                result_id = state.finding.as_ref().map_or("", |finding| finding.result_id.as_str()),
                finding_id = state.finding.as_ref().map_or("", |finding| finding.finding_id.as_str()),
                previous_revision = previous,
                state_revision = state.revision,
                attempts = state.attempts.len(),
                pending = state.attempts.iter().filter(|attempt| attempt.result.is_none()).count(),
                elapsed_s = started.elapsed().as_secs_f64(),
                "Notification state committed"
            );
            Ok(bytes)
        })();
        if result.is_err() {
            state.revision = previous;
        }
        result
    }

    pub(super) fn persist(
        &self,
        key: AnalysisContextKeyV1,
        body: Vec<u8>,
        expected: u64,
        sensitivity: ContextSensitivityV1,
    ) -> Result<()> {
        self.store.commit_context_checked(
            &AnalysisContextVersionV1 {
                key,
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
