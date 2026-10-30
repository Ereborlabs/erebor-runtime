use super::*;

impl NotificationRouter {
    pub(super) fn captured_route(
        &self,
        subject: &NotificationObligationV1,
        kind: NotificationDeliveryKindV1,
    ) -> Result<ApprovedNotificationRouteV1> {
        let reference = subject.delivery_route(kind).ok_or_else(|| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Invalid,
                field: "attempt route",
            }
            .build()
        })?;
        self.route_version(subject.key.tenant_id, reference)?
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "attempt approved route",
                }
                .build()
            })
            .map_err(Into::into)
    }

    pub(super) fn delivery_failure(
        &self,
        state: &NotificationObligationV1,
        route: &ApprovedNotificationRouteV1,
        now: u64,
    ) -> Option<NotificationFailureV1> {
        if self.authority.check(&route.grant, now).is_err()
            || !route.grant.allows(
                state.key.tenant_id,
                &route.policy.route_id,
                NotificationOperationV1::Configure,
                now,
            )
        {
            Some(NotificationFailureV1::AuthorizationRevoked)
        } else if !NotificationGrantV1::sensitivity(route.policy.max_sensitivity, state.sensitivity)
            || !NotificationGrantV1::sensitivity(route.grant.max_sensitivity, state.sensitivity)
        {
            Some(NotificationFailureV1::DisclosureDenied)
        } else {
            None
        }
    }

    pub(super) fn captured_delivery(
        &self,
        state: &NotificationObligationV1,
        pending: &NotificationAttemptV1,
        kind: NotificationDeliveryKindV1,
        subject: NotificationObligationV1,
        route: &ApprovedNotificationRouteV1,
        batch: Option<&FindingBatch>,
    ) -> Result<NotificationDeliveryV1> {
        let finding = subject
            .finding
            .as_ref()
            .map(|reference| {
                if let Some((revision, finding)) = batch
                    .and_then(|batch| batch.get(&reference.result_id))
                    .and_then(|(revision, findings)| {
                        findings
                            .get(&reference.finding_id)
                            .map(|finding| (revision, finding))
                    })
                {
                    Ok(Some((finding.clone(), revision.clone())))
                } else {
                    self.store.graph_finding(
                        state.key.tenant_id,
                        &reference.result_id,
                        &reference.finding_id,
                    )
                }
            })
            .transpose()?
            .flatten()
            .map(|(finding, revision)| NotificationFindingV1 {
                finding_id: finding.finding_id,
                revision,
            });
        let overdue = subject.overdue(pending.started_utc_ns);
        Ok(NotificationDeliveryV1 {
            key: state.key,
            attempt: pending.number,
            kind,
            route_id: route.policy.route_id.clone(),
            route_revision: route.policy.revision,
            finding,
            unconfirmed_concern: subject.unconfirmed_concern,
            required_action: state.required_action.clone(),
            priority: pending.priority,
            deadline_utc_ns: state.deadline_utc_ns.ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Invalid,
                    field: "stored deadline",
                }
                .build()
            })?,
            overdue,
        })
    }
}
