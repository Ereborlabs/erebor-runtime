use std::collections::{BTreeMap, BTreeSet};

use araphor_query::follow::Update;
use snafu::ResultExt as _;

use super::*;

#[derive(Debug, Default)]
pub struct NotificationUpdate {
    pub routed: Vec<(NotificationFindingRefV1, Result<usize>)>,
    pub delivered: Vec<(NotificationKeyV1, Result<usize>)>,
}

#[derive(serde::Deserialize)]
struct Row {
    finding_id: Option<String>,
    result_id: Option<String>,
    notification_id: Option<Vec<u8>>,
}

impl NotificationRouter {
    pub const SQL: &'static str = include_str!("reactive.sql");

    pub fn consume(
        &self,
        update: &Update,
        sink: &dyn NotificationSink,
    ) -> Result<NotificationUpdate> {
        NotificationErrorCodeV1::Invalid.require(
            update.exhausted && !update.limited && update.evaluated_utc_ns > 0,
            "notification subscription completeness",
        )?;
        self.consume_rows(
            update.snapshot.selection.tenant_id,
            update.evaluated_utc_ns,
            update.batches.as_deref().unwrap_or_default(),
            &|| Ok(()),
            &mut |delivery| Ok(sink.deliver(delivery)),
        )
    }

    pub(crate) fn consume_rows(
        &self,
        tenant: [u8; 16],
        now: u64,
        batches: &[araphor_analysis_sdk::RecordBatch],
        check: &dyn Fn() -> Result<()>,
        effect: &mut Effect<'_>,
    ) -> Result<NotificationUpdate> {
        NotificationErrorCodeV1::Invalid.require(now > 0, "notification evaluation time")?;
        let mut work = Vec::new();
        for batch in batches {
            let rows: Vec<Row> =
                serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu)?;
            for row in rows {
                let reference = match (row.finding_id, row.result_id) {
                    (Some(finding_id), Some(result_id)) => Some(NotificationFindingRefV1 {
                        finding_id,
                        result_id,
                    }),
                    (None, None) => None,
                    _ => {
                        return Err(NotificationSnafu {
                            code: NotificationErrorCodeV1::Invalid,
                            field: "notification subscription row",
                        }
                        .build()
                        .into())
                    }
                };
                let key = row
                    .notification_id
                    .map(|id| -> Result<NotificationKeyV1> {
                        Ok(NotificationKeyV1 {
                            tenant_id: tenant,
                            notification_id: id.try_into().map_err(|_| {
                                NotificationSnafu {
                                    code: NotificationErrorCodeV1::Invalid,
                                    field: "notification subscription key",
                                }
                                .build()
                            })?,
                        })
                    })
                    .transpose()?;
                NotificationErrorCodeV1::Invalid.require(
                    reference.is_some() || key.is_some(),
                    "notification subscription row",
                )?;
                work.push((reference, key));
            }
        }
        erebor_telemetry::debug!(
            tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = now,
            rows = work.len(), routed_items = 0usize, handled_states = 0usize,
            graph_results_sample = ?work.iter().filter_map(|(reference, _)|
                reference.as_ref().map(|reference| reference.result_id.as_str()))
                .collect::<BTreeSet<_>>().into_iter().take(4)
                .map(|id| id.chars().take(64).collect::<String>()).collect::<Vec<_>>(),
            "Notification batch begins"
        );
        let mut update = NotificationUpdate::default();
        let mut routed = BTreeMap::new();
        let mut handled = BTreeSet::new();
        for (reference, key) in work {
            erebor_telemetry::trace!(
                tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = now,
                notification_id = ?key.map(|key| uuid::Uuid::from_bytes(key.notification_id)),
                graph_result_id = %reference.as_ref().map(|reference| reference.result_id.chars()
                    .take(64).collect::<String>()).unwrap_or_default(),
                "Notification work begins"
            );
            check()?;
            let _guard = self.lock()?;
            let mut states = Vec::new();
            if let Some(reference) = reference {
                let identity = (reference.finding_id.clone(), reference.result_id.clone());
                if let Some(valid) = routed.get(&identity) {
                    if !valid {
                        continue;
                    }
                } else {
                    let result = self.route_states(tenant, &reference, now);
                    routed.insert(identity, result.is_ok());
                    match result {
                        Ok((count, values)) => {
                            states = values;
                            update.routed.push((reference, Ok(count)));
                        }
                        Err(error) => {
                            erebor_telemetry::warn!(error; "Notification routing failed",
                                tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = %now,
                                graph_result_id = %reference.result_id.chars().take(64).collect::<String>());
                            update.routed.push((reference, Err(error)));
                            continue;
                        }
                    }
                }
            }
            if let Some(key) = key {
                if !handled.contains(&key) && !states.iter().any(|state| state.key == key) {
                    match self.state(key) {
                        Ok(state) => states.push(state),
                        Err(error) => {
                            erebor_telemetry::warn!(error; "Notification state read failed",
                                tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = %now,
                                notification_id = %uuid::Uuid::from_bytes(key.notification_id));
                            handled.insert(key);
                            update.delivered.push((key, Err(error)));
                        }
                    }
                }
            }
            for state in states {
                if handled.insert(state.key) {
                    self.consume_state(state, now, check, effect, &mut update)?;
                }
            }
        }
        erebor_telemetry::debug!(
            tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = now,
            rows = batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            routed_items = update.routed.len(), handled_states = handled.len(),
            graph_results_sample = ?update.routed.iter().map(|(reference, _)|
                reference.result_id.as_str()).collect::<BTreeSet<_>>().into_iter().take(4)
                .map(|id| id.chars().take(64).collect::<String>()).collect::<Vec<_>>(),
            "Notification batch ends"
        );
        Ok(update)
    }

    fn consume_state(
        &self,
        mut state: NotificationObligationV1,
        now: u64,
        check: &dyn Fn() -> Result<()>,
        effect: &mut Effect<'_>,
        update: &mut NotificationUpdate,
    ) -> Result<()> {
        erebor_telemetry::trace!(
            tenant_id = %uuid::Uuid::from_bytes(state.key.tenant_id), evaluated_ns = now,
            notification_id = %uuid::Uuid::from_bytes(state.key.notification_id),
            graph_result_id = %state.finding.as_ref().map(|reference| reference.result_id.chars()
                .take(64).collect::<String>()).unwrap_or_default(),
            "Notification state begins"
        );
        let mut guard_failed = false;
        let result = self.deliver_state(
            &mut state,
            &mut |delivery| {
                if let Err(error) = check() {
                    guard_failed = true;
                    return Err(error);
                }
                effect(delivery)
            },
            now,
        );
        erebor_telemetry::trace!(
            tenant_id = %uuid::Uuid::from_bytes(state.key.tenant_id), evaluated_ns = now,
            notification_id = %uuid::Uuid::from_bytes(state.key.notification_id),
            ok = result.is_ok(), guard_failed,
            "Notification state returns"
        );
        match result {
            Err(error) if guard_failed => {
                erebor_telemetry::trace!("Notification state guard failed",
                    tenant_id = %uuid::Uuid::from_bytes(state.key.tenant_id), evaluated_ns = %now,
                    notification_id = %uuid::Uuid::from_bytes(state.key.notification_id));
                return Err(error);
            }
            result => {
                if let Err(error) = &result {
                    erebor_telemetry::warn!(error; "Notification delivery failed",
                        tenant_id = %uuid::Uuid::from_bytes(state.key.tenant_id), evaluated_ns = %now,
                        notification_id = %uuid::Uuid::from_bytes(state.key.notification_id));
                }
                update.delivered.push((state.key, result));
            }
        }
        Ok(())
    }
}
