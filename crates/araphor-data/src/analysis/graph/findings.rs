use duckdb::{params, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::graph_rows::GraphHeader;
use super::*;
use crate::{
    FindingV1, GraphInvalidSnafu, GraphRevisionV1, NotificationErrorCodeV1,
    NotificationFindingRefV1, NotificationGrantV1, NotificationSnafu,
};

mod batches;
mod selection;

struct FindingKey {
    result: String,
    finding: String,
}

impl AnalysisStore {
    fn selected_finding_keys(
        &self,
        snapshot: &duckdb::Connection,
        values: &[&dyn duckdb::ToSql],
    ) -> Result<Vec<FindingKey>> {
        let mut statement =
            snapshot
                .prepare_cached(Self::finding_selection())
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected native finding keys",
                })?;
        let mut rows = statement.query(values).context(AnalysisDatabaseSnafu {
            operation: "select native finding keys",
        })?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read selected native finding keys",
        })? {
            keys.push(FindingKey {
                result: row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode selected graph reference",
                })?,
                finding: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode selected native finding key",
                })?,
            });
        }
        Ok(keys)
    }

    pub fn graph_findings(
        &self,
        tenant: [u8; 16],
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        if limit == 0 {
            return GraphInvalidSnafu {
                field: "finding page limit",
            }
            .fail();
        }
        self.check_graph_read(tenant, &[after, exact], "finding page scope")?;
        self.read_snapshot(|snapshot| {
            let keys = self.selected_finding_keys(
                snapshot,
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    after,
                    after,
                    exact,
                    exact,
                    limit.min(i64::MAX as usize) as i64
                ],
            )?;
            self.collect_findings(snapshot, keys, tenant)
        })
    }

    pub fn notification_finding(
        &self,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
    ) -> Result<(FindingV1, GraphRevisionV1)> {
        NotificationErrorCodeV1::Invalid.require(
            tenant != [0; 16]
                && NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                && NotificationGrantV1::identifier(&reference.result_id, usize::MAX),
            "finding reference",
        )?;
        self.read_snapshot(|snapshot| {
            let keys = self.selected_finding_keys(
                snapshot,
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    None::<&str>,
                    None::<&str>,
                    Some(reference.finding_id.as_str()),
                    Some(reference.finding_id.as_str()),
                    1_i64
                ],
            )?;
            let key = keys.first().ok_or_else(|| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Denied,
                    field: "current finding scope",
                }
                .build()
            })?;
            NotificationErrorCodeV1::Conflict.require(
                key.result == reference.result_id,
                "current finding reference",
            )?;
            let header = GraphRows::read_header(snapshot, tenant, &key.result)?
                .ok_or_else(|| self.state_error("the current graph header is absent"))?;
            GraphRows::read_finding(snapshot, &key.result, &key.finding, &header, None)?
                .map(|finding| (finding, header.snapshot.input_manifest))
                .ok_or_else(|| {
                    NotificationSnafu {
                        code: NotificationErrorCodeV1::Denied,
                        field: "current finding scope",
                    }
                    .build()
                })
        })
    }

    pub fn graph_finding(
        &self,
        tenant: [u8; 16],
        result_id: &str,
        finding_id: &str,
    ) -> Result<Option<(FindingV1, GraphRevisionV1)>> {
        self.check_graph_read(
            tenant,
            &[Some(result_id), Some(finding_id)],
            "finding reference",
        )?;
        self.read_snapshot(|snapshot| {
            let Some(header) = GraphRows::read_header(snapshot, tenant, result_id)? else {
                return Ok(None);
            };
            GraphRows::read_finding(snapshot, result_id, finding_id, &header, None)
                .map(|finding| finding.map(|finding| (finding, header.snapshot.input_manifest)))
        })
    }

    pub fn graph_revision_finding(
        &self,
        tenant: [u8; 16],
        finding_id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
        self.check_graph_read(tenant, &[Some(finding_id)], "finding reference")?;
        revision.validate(tenant)?;
        self.read_snapshot(|snapshot| {
            let mut after = None;
            loop {
                let id: Option<String> = snapshot
                    .query_row(
                        "SELECT finding.result_id FROM graph_findings finding
                     JOIN analysis_results result USING (result_id)
                     WHERE result.tenant_id = ? AND result.processor_id = ?
                        AND result.method_version = ? AND finding.finding_id = ?
                        AND result.stream_key IS NOT NULL
                        AND (? IS NULL OR finding.result_id > ?)
                     ORDER BY finding.result_id LIMIT 1",
                        params![
                            tenant.as_slice(),
                            GRAPH_PROCESSOR,
                            GRAPH_SCHEMA_VERSION,
                            finding_id,
                            after,
                            after
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .context(AnalysisDatabaseSnafu {
                        operation: "select historical native finding",
                    })?;
                let Some(id) = id else {
                    return Ok(None);
                };
                let header = GraphRows::read_header(snapshot, tenant, &id)?
                    .ok_or_else(|| self.state_error("the historical graph header is absent"))?;
                if &header.snapshot.input_manifest == revision {
                    return GraphRows::read_finding(snapshot, &id, finding_id, &header, None);
                }
                after = Some(id);
            }
        })
    }
}

#[cfg(test)]
mod tests;
