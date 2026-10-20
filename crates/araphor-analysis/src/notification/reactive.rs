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
        let mut references = Vec::new();
        let mut keys = Vec::new();
        for batch in update.batches.iter().flatten() {
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
                        tenant_id: update.snapshot.selection.tenant_id,
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
        Ok(NotificationUpdate {
            routed: references
                .into_iter()
                .map(|reference| {
                    let result = self.route_finding(
                        update.snapshot.selection.tenant_id,
                        &reference,
                        update.evaluated_utc_ns,
                    );
                    (reference, result)
                })
                .collect(),
            delivered: keys
                .into_iter()
                .map(|key| {
                    (
                        key,
                        self.deliver_obligation(key, sink, update.evaluated_utc_ns),
                    )
                })
                .collect(),
        })
    }
}
