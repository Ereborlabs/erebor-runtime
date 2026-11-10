use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk::arrow_array::{Array as _, BinaryArray, StringArray};
use araphor_query::follow::Update;

use super::*;

#[derive(Debug, Default)]
pub struct NotificationUpdate {
    pub routed: Vec<(NotificationFindingRefV1, Result<usize>)>,
    pub delivered: Vec<(NotificationKeyV1, Result<usize>)>,
    
    pub(crate) publication: Option<(u64, bool)>,
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
        let control = araphor_data::AnalysisReadControl::default();
        let memory = araphor_query::memory::Memory::new(None, None);
        let budget = memory.managed_budget(&control, usize::MAX);
        self.consume_bounded(
            update.snapshot.selection.tenant_id,
            update.evaluated_utc_ns,
            update.batches.as_deref().unwrap_or_default(),
            &control,
            budget.as_ref(),
            &|| Ok(()),
            &mut |delivery| Ok(sink.deliver(delivery)),
            
            update.snapshot.notification_capture(),
        )
    }

    #[cfg(test)]
    pub(crate) fn consume_rows(
        &self,
        tenant: [u8; 16],
        now: u64,
        batches: &[araphor_analysis_sdk::RecordBatch],
        check: &dyn Fn() -> Result<()>,
        effect: &mut Effect<'_>,
    ) -> Result<NotificationUpdate> {
        let control = araphor_data::AnalysisReadControl::default();
        let memory = araphor_query::memory::Memory::new(None, None);
        let budget = memory.managed_budget(&control, usize::MAX);
        self.consume_bounded(
            tenant,
            now,
            batches,
            &control,
            budget.as_ref(),
            check,
            effect,
            
            None,
        )
    }

    pub(crate) fn consume_bounded(
        &self,
        tenant: [u8; 16],
        now: u64,
        batches: &[araphor_analysis_sdk::RecordBatch],
        control: &araphor_data::AnalysisReadControl,
        budget: &dyn araphor_data::ManagedBudget,
        check: &dyn Fn() -> Result<()>,
        effect: &mut Effect<'_>,
         capture: Option<
            &araphor_data::analysis::native::NotificationCapture,
        >,
    ) -> Result<NotificationUpdate> {
        let started = std::time::Instant::now();
        NotificationErrorCodeV1::Invalid.require(now > 0, "notification evaluation time")?;
        let bytes = batches
            .iter()
            .try_fold(0usize, |bytes, batch| {
                bytes.checked_add(batch.get_array_memory_size())
            })
            .and_then(|bytes| bytes.checked_mul(12))
            .ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Limit,
                    field: "notification request memory",
                }
                .build()
            })?;
        let _work_memory = budget.reserve(bytes)?;
        let mut work = Vec::new();
        for batch in batches {
            let invalid = || {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Invalid,
                    field: "notification subscription columns",
                }
                .build()
            };
            let findings = batch
                .column_by_name("finding_id")
                .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                .ok_or_else(invalid)?;
            let results = batch
                .column_by_name("result_id")
                .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                .ok_or_else(invalid)?;
            let notifications = batch
                .column_by_name("notification_id")
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or_else(invalid)?;
            for row in 0..batch.num_rows() {
                let reference = match (findings.is_null(row), results.is_null(row)) {
                    (false, false) => Some(NotificationFindingRefV1 {
                        finding_id: findings.value(row).to_owned(),
                        result_id: results.value(row).to_owned(),
                    }),
                    (true, true) => None,
                    _ => {
                        return Err(NotificationSnafu {
                            code: NotificationErrorCodeV1::Invalid,
                            field: "notification subscription row",
                        }
                        .build()
                        .into())
                    }
                };
                let key = (!notifications.is_null(row))
                    .then(|| notifications.value(row))
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
        let decoded = std::time::Instant::now();
        if work.is_empty() {
            let update = NotificationUpdate::default();
            
            let update = if let Some(capture) = capture {
                check()?;
                let _guard = self.lock()?;
                let tx = self.store.write()?;
                check()?;
                NotificationUpdate {
                    publication: Some(tx.commit_notifications(capture, &[])?),
                    ..update
                }
            } else {
                update
            };
            return Ok(update);
        }
        check()?;
        let _guard = self.lock()?;
        let references = work
            .iter()
            .filter_map(|(reference, _)| reference.clone())
            .collect::<Vec<_>>();
        let keys = work.iter().filter_map(|(_, key)| *key).collect::<Vec<_>>();
        let prepared =
            self.store
                .prepare_notifications(tenant, &references, &keys, control, budget)?;
        let mut cycle = NotificationCycle::new(self, tenant, prepared);
        let heads = Some(cycle.prepared.heads().clone());
        let resolved = std::time::Instant::now();
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
        let mut skipped_stale = false;
        let mut deliveries = Vec::new();
        for (reference, key) in work {
            erebor_telemetry::trace!(
                tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = now,
                notification_id = ?key.map(|key| uuid::Uuid::from_bytes(key.notification_id)),
                graph_result_id = %reference.as_ref().map(|reference| reference.result_id.chars()
                    .take(64).collect::<String>()).unwrap_or_default(),
                "Notification work begins"
            );
            if let Some(reference) = reference.as_ref().filter(|reference| {
                NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                    && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)
                    && heads
                        .as_ref()
                        .and_then(|heads| heads.get(&reference.finding_id))
                        .is_some_and(|result| result != &reference.result_id)
            }) {
                let reference = reference.clone();
                let identity = (reference.finding_id.clone(), reference.result_id.clone());
                if routed.insert(identity, false).is_none() {
                    let error: crate::Error = NotificationSnafu {
                        code: NotificationErrorCodeV1::Conflict,
                        field: "current finding reference",
                    }
                    .build()
                    .into();
                    erebor_telemetry::warn!(error; "Notification routing failed",
                        tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = %now,
                        graph_result_id = %reference.result_id.chars().take(64).collect::<String>());
                    update.routed.push((reference, Err(error)));
                }
                skipped_stale = true;
                continue;
            }
            check()?;
            let mut states = Vec::new();
            if let Some(reference) = reference {
                let identity = (reference.finding_id.clone(), reference.result_id.clone());
                if let Some(valid) = routed.get(&identity) {
                    if !valid {
                        continue;
                    }
                } else {
                    let result = cycle.route_states(tenant, &reference, now);
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
                    match cycle.state(key) {
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
                    deliveries.push(state);
                }
            }
        }
        if skipped_stale {
            check()?;
        }
        let results = cycle.deliver_states(&mut deliveries, check, effect, now)?;
        for (state, result) in deliveries.into_iter().zip(results) {
            if let Err(error) = &result {
                erebor_telemetry::warn!(error; "Notification delivery failed",
                    tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = %now,
                    notification_id = %uuid::Uuid::from_bytes(state.key.notification_id));
            }
            update.delivered.push((state.key, result));
        }
        
        {
            let complete = update.routed.iter().all(|(_, result)| result.is_ok())
                && update.delivered.iter().all(|(_, result)| result.is_ok());
            update.publication = cycle.commit(check, capture.filter(|_| complete))?;
        }
        
        let completed = std::time::Instant::now();
        erebor_telemetry::debug!(
            tenant_id = %uuid::Uuid::from_bytes(tenant), evaluated_ns = now,
            rows = batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            routed_items = update.routed.len(), handled_states = handled.len(),
            decode_s = decoded.duration_since(started).as_secs_f64(),
            prepare_s = resolved.duration_since(decoded).as_secs_f64(),
            processing_s = completed.duration_since(resolved).as_secs_f64(),
            elapsed_s = completed.duration_since(started).as_secs_f64(),
            graph_results_sample = ?update.routed.iter().map(|(reference, _)|
                reference.result_id.as_str()).collect::<BTreeSet<_>>().into_iter().take(4)
                .map(|id| id.chars().take(64).collect::<String>()).collect::<Vec<_>>(),
            "Notification batch ends"
        );
        Ok(update)
    }
}
