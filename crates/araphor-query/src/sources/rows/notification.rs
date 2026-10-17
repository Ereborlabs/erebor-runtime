use araphor_data::{
    AnalysisInputV1, NotificationFailureV1, NotificationPriorityV1, NotificationSinkHealthV1,
    ProjectionSink,
};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn notification(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let AnalysisInputV1::Notification {
            obligation,
            finding,
            commit_revision,
        } = input
        else {
            return Ok(true);
        };
        if let Some(deadline) = obligation.deadline_utc_ns.filter(|deadline| {
            self.sources.contains("notifications")
                && *deadline > self.now
                && obligation.overdue(*deadline)
        }) {
            self.next_change = Some(
                self.next_change
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        let priority = |priority| match priority {
            NotificationPriorityV1::Info => "info",
            NotificationPriorityV1::Warning => "warning",
            NotificationPriorityV1::High => "high",
            NotificationPriorityV1::Critical => "critical",
        };
        let now = self.now;
        self.append("notifications", sink, |name, kind, sink| {
            Ok(match name {
                "tenant_id" => Self::binary(Some(&obligation.key.tenant_id), sink)?,
                "notification_id" => Self::binary(Some(&obligation.key.notification_id), sink)?,
                "notification_revision" => ScalarValue::UInt64(Some(obligation.revision)),
                "kind" => Self::text(
                    Some(if obligation.finding.is_some() {
                        "finding"
                    } else {
                        "unconfirmed_concern"
                    }),
                    sink,
                )?,
                "finding_id" => Self::text(
                    obligation
                        .finding
                        .as_ref()
                        .map(|value| value.finding_id.as_str()),
                    sink,
                )?,
                "finding_result_id" => Self::text(
                    obligation
                        .finding
                        .as_ref()
                        .map(|value| value.result_id.as_str()),
                    sink,
                )?,
                "finding_revision" => {
                    if let Some(finding) = finding {
                        Self::json(&finding.revision, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "finding_available" => ScalarValue::Boolean(Some(finding.is_some())),
                "package_id" => Self::text(Some(&obligation.package_id), sink)?,
                "required_action" => Self::text(obligation.required_action.as_deref(), sink)?,
                "route_id" => Self::text(
                    obligation
                        .route
                        .as_ref()
                        .map(|value| value.route_id.as_str()),
                    sink,
                )?,
                "route_revision" => {
                    ScalarValue::UInt64(obligation.route.as_ref().map(|value| value.revision))
                }
                "priority" => Self::text(Some(priority(obligation.priority())), sink)?,
                "source_priority" => Self::text(Some(priority(obligation.source_priority)), sink)?,
                "minimum_priority" => {
                    Self::text(Some(priority(obligation.minimum_priority)), sink)?
                }
                "first_seen_utc_ns" => ScalarValue::UInt64(Some(obligation.first_seen_utc_ns)),
                "deadline_utc_ns" => ScalarValue::UInt64(obligation.deadline_utc_ns),
                "overdue" => ScalarValue::Boolean(Some(obligation.overdue(now))),
                "overdue_since_utc_ns" => ScalarValue::UInt64(obligation.overdue_since_utc_ns),
                "sink_health" => Self::text(
                    Some(match obligation.sink_health {
                        NotificationSinkHealthV1::Unknown => "unknown",
                        NotificationSinkHealthV1::Healthy => "healthy",
                        NotificationSinkHealthV1::Unhealthy => "unhealthy",
                    }),
                    sink,
                )?,
                "failure" => Self::text(
                    obligation.failure.map(|value| match value {
                        NotificationFailureV1::NoRoute => "no_route",
                        NotificationFailureV1::SinkUnavailable => "sink_unavailable",
                        NotificationFailureV1::SinkRejected => "sink_rejected",
                        NotificationFailureV1::TransportFailed => "transport_failed",
                        NotificationFailureV1::AuthorizationRevoked => "authorization_revoked",
                        NotificationFailureV1::DisclosureDenied => "disclosure_denied",
                        NotificationFailureV1::FindingUnavailable => "finding_unavailable",
                        NotificationFailureV1::InvalidSinkResult => "invalid_sink_result",
                        NotificationFailureV1::RetryExhausted => "retry_exhausted",
                    }),
                    sink,
                )?,
                "human_acknowledgement" => {
                    if let Some(value) = &obligation.human_acknowledgement {
                        Self::json(value, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "agent_receipt" => {
                    if let Some(value) = &obligation.agent_receipt {
                        Self::json(value, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "advisory" => {
                    if let Some(value) = &obligation.advisory {
                        Self::json(value, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "unconfirmed_concern" => {
                    if let Some(value) = &obligation.unconfirmed_concern {
                        Self::json(value, sink)?
                    } else {
                        Self::null(kind)?
                    }
                }
                "delivery_attempts" => Self::json(&obligation.attempts, sink)?,
                "sensitivity" => Self::text(Some(obligation.sensitivity.into()), sink)?,
                "commit_revision" => ScalarValue::UInt64(Some(commit_revision)),
                _ => {
                    return Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    ));
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    use araphor_data::{
        AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
        AnalysisStore, ContextSensitivityV1, NotificationAcknowledgementV1, NotificationKeyV1,
        NotificationObligationV1, NotificationPriorityV1, NotificationSinkHealthV1, Selection,
        UnconfirmedNotificationConcernV1, NOTIFICATION_STATE_OWNER,
    };
    use datafusion::common::ScalarValue;

    use crate::execution::{Engine, Limits};
    use crate::parser::Parser;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn obligation() -> NotificationObligationV1 {
        NotificationObligationV1 {
            schema_version: 1,
            key: NotificationKeyV1 {
                tenant_id: [1; 16],
                notification_id: [7; 16],
            },
            revision: 1,
            finding: None,
            unconfirmed_concern: Some(UnconfirmedNotificationConcernV1 {
                concern_id: [9; 16],
                model_label: "clock".into(),
                summary: "Review this concern".into(),
                context: Vec::new(),
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Info,
            }),
            finding_revision: 1,
            package_id: "clock".into(),
            required_action: None,
            sensitivity: ContextSensitivityV1::Tenant,
            source_priority: NotificationPriorityV1::Info,
            minimum_priority: NotificationPriorityV1::Info,
            route: None,
            escalation: None,
            first_seen_utc_ns: 1,
            deadline_utc_ns: Some(100),
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

    fn retain(store: &AnalysisStore, value: &NotificationObligationV1) -> araphor_data::Result<()> {
        value.validate()?;
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: value.key.tenant_id,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: value.key.notification_id.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision: value.revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: value.sensitivity,
            body: serde_json::to_vec(value).unwrap(),
        })?;
        Ok(())
    }

    #[tokio::test]
    async fn obligation_source_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        store.enable_notification_owner()?;
        let engine = Engine::new(Arc::clone(&store), Limits::default())?;
        let mut value = obligation();
        retain(&store, &value)?;
        let state = engine.catalog(BTreeMap::new())?;
        let statement = Parser::parse("SELECT overdue FROM notifications")?;
        let sources = state
            .resolve_table_references(&statement)?
            .into_iter()
            .map(|reference| reference.table().to_owned())
            .collect::<BTreeSet<_>>();
        let plan = Arc::new(engine.plan(&state, statement, vec![])?);
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        for (now, overdue, next_change) in
            [(99, false, Some(100)), (100, true, None), (101, true, None)]
        {
            let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
            let (snapshot, batches) = engine
                .session(selection.clone(), &control, now)?
                .execute(Arc::clone(&plan), &sources)?;
            assert_eq!(
                batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
                1
            );
            assert_eq!(
                ScalarValue::try_from_array(batches[0].column(0), 0)?,
                ScalarValue::Boolean(Some(overdue))
            );
            assert_eq!(snapshot.next_change, next_change);
            let permit = engine.reserve_evaluation([1; 16])?;
            let metadata = engine
                .metadata(selection.clone(), &sources, &control, now)
                .await?;
            assert_eq!(metadata.next_change, next_change);
            assert_eq!(
                metadata.page.extraction.scanned_bytes,
                serde_json::to_vec(&value)?.len()
            );
            assert_eq!(metadata.contexts().count(), 1);
            assert_eq!(
                metadata.contexts().next().unwrap().key.owner_id,
                NOTIFICATION_STATE_OWNER
            );
            assert_eq!(
                metadata.contexts().next().unwrap().key.owner_revision,
                value.revision
            );
            drop(permit);
        }
        let mut scoped = selection.clone();
        scoped.sources = Selection::Exact(Vec::new());
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
        let (snapshot, batches) = engine
            .session(scoped, &control, 99)?
            .execute(Arc::clone(&plan), &sources)?;
        assert!(batches.iter().all(|batch| batch.num_rows() == 0));
        assert!(snapshot.contexts().next().is_none());
        assert_eq!(snapshot.next_change, None);
        value.revision = 2;
        value.human_acknowledgement = Some(NotificationAcknowledgementV1 {
            request_id: [3; 16],
            principal_id: [4; 16],
            authorization_revision: 1,
            finding_revision: 1,
            acknowledged_utc_ns: 50,
        });
        retain(&store, &value)?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
        let complete = engine
            .metadata(selection.clone(), &sources, &control, 99)
            .await?;
        assert_eq!(complete.next_change, None);
        value.revision = 3;
        value.finding_revision = 2;
        retain(&store, &value)?;
        let changed = engine
            .metadata(selection.clone(), &sources, &control, 99)
            .await?;
        assert_eq!(changed.next_change, Some(100));
        value.revision = 4;
        value.deadline_utc_ns = Some(u64::MAX);
        value.human_acknowledgement = None;
        retain(&store, &value)?;
        for (now, expected) in [(u64::MAX - 1, Some(u64::MAX)), (u64::MAX, None)] {
            let metadata = engine
                .metadata(selection.clone(), &sources, &control, now)
                .await?;
            assert_eq!(metadata.next_change, expected);
            let (_, batches) = engine
                .session(selection.clone(), &control, now)?
                .execute(Arc::clone(&plan), &sources)?;
            assert_eq!(
                ScalarValue::try_from_array(batches[0].column(0), 0)?,
                ScalarValue::Boolean(Some(now == u64::MAX))
            );
        }
        let absent = engine
            .metadata(selection, &BTreeSet::new(), &control, 99)
            .await?;
        assert_eq!(absent.next_change, None);
        Ok(())
    }
}
