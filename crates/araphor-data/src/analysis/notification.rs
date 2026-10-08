use duckdb::params;
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisContextVersionV1, AnalysisDatabaseSnafu, Result};

pub(crate) enum NotificationLookup<'a> {
    Finding(&'a str, Option<&'a str>),
    Concern([u8; 16], &'a str),
}

impl AnalysisStore {
    pub(crate) fn notification_states(
        &self,
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        let (finding, action, concern, route, limit) = match lookup {
            NotificationLookup::Finding(id, action) if !id.is_empty() && id.len() <= 4096 => (
                Some(id),
                action,
                None,
                None,
                crate::MAX_NOTIFICATION_ROUTES + 2,
            ),
            NotificationLookup::Concern(id, route)
                if id != [0; 16] && crate::NotificationGrantV1::identifier(route, 64) =>
            {
                (
                    None,
                    None,
                    Some(serde_json::json!(id).to_string()),
                    Some(route),
                    2,
                )
            }
            _ => return self.reject("the notification lookup is invalid"),
        };
        if tenant == [0; 16] {
            return self.reject("the notification lookup tenant is invalid");
        }
        self.read_snapshot(|reader| {
            let owner = crate::NOTIFICATION_STATE_OWNER;
            let mut statement = reader
                .prepare(
                    "WITH heads AS (
                    SELECT * FROM context_versions WHERE tenant_id = ? AND owner_id = ?
                    QUALIFY ROW_NUMBER() OVER (PARTITION BY entity_key, lifetime_key
                        ORDER BY owner_revision DESC, commit_revision DESC) = 1
                 ) SELECT entity_key, lifetime_key, owner_revision,
                    valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, commit_revision
                 FROM heads WHERE
                    (CAST(? AS VARCHAR) IS NOT NULL
                        AND json_extract_string(decode(body), '$.finding.finding_id') = ?
                        AND json_extract_string(decode(body), '$.required_action')
                            IS NOT DISTINCT FROM CAST(? AS VARCHAR))
                    OR (CAST(? AS VARCHAR) IS NOT NULL
                        AND json(json_extract(decode(body), '$.unconfirmed_concern.concern_id'))
                            = CAST(? AS JSON)
                        AND json_extract_string(decode(body), '$.route.route_id') = ?)
                 ORDER BY entity_key, lifetime_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare notification lookup",
                })?;
            let rows = statement
                .query_map(
                    params![
                        tenant.as_slice(),
                        owner,
                        finding,
                        finding,
                        action,
                        concern.as_deref(),
                        concern.as_deref(),
                        route,
                        limit as u32
                    ],
                    |row| Self::context_row(tenant, owner, row),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read notification lookup",
                })?;
            rows.map(|row| {
                let (key, stored) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode notification lookup",
                })?;
                Ok(Self::decode_context_row(&self.root, key, stored)?.0)
            })
            .collect()
        })
    }
}

#[cfg(test)]
mod tests;
