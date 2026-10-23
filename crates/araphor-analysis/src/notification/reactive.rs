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
        let mut references = Vec::new();
        let mut keys = Vec::new();
        for batch in batches {
            let rows: Vec<Row> =
                serde_arrow::from_record_batch(batch).context(crate::error::ArrowSnafu)?;
            for row in rows {
                match (row.finding_id, row.result_id, row.notification_id) {
                    (Some(finding_id), Some(result_id), None) => {
                        references.push(NotificationFindingRefV1 {
                            finding_id,
                            result_id,
                        });
                    }
                    (None, None, Some(id)) => keys.push(NotificationKeyV1 {
                        tenant_id: tenant,
                        notification_id: id.try_into().map_err(|_| {
                            NotificationSnafu {
                                code: NotificationErrorCodeV1::Invalid,
                                field: "notification subscription key",
                            }
                            .build()
                        })?,
                    }),
                    _ => {
                        return Err(NotificationSnafu {
                            code: NotificationErrorCodeV1::Invalid,
                            field: "notification subscription row",
                        }
                        .build()
                        .into())
                    }
                }
            }
        }
        let mut update = NotificationUpdate::default();
        for reference in references {
            check()?;
            let result = self.route_finding(tenant, &reference, now);
            update.routed.push((reference, result));
        }
        for key in keys {
            check()?;
            let mut guard_failed = false;
            let result = self.deliver_checked(
                key,
                &mut |delivery| {
                    if let Err(error) = check() {
                        guard_failed = true;
                        return Err(error);
                    }
                    effect(delivery)
                },
                now,
            );
            match result {
                Err(error) if guard_failed => return Err(error),
                result => update.delivered.push((key, result)),
            }
        }
        Ok(update)
    }
}
