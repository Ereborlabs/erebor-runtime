use duckdb::{params, OptionalExt as _, Row};
use snafu::ResultExt as _;

use super::super::graph_rows::GraphHeader;
use super::*;
use crate::{FindingV1, GraphInvalidSnafu, GraphRevisionV1};

mod batches;
mod preflight;
mod selection;

use preflight::{FindingHeaders, FindingKey, FindingSelection};

impl AnalysisStore {
    pub(crate) fn graph_findings(
        &self,
        tenant: [u8; 16],
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
        bytes: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        self.read_snapshot(|snapshot| {
            let selection = self.preflight_findings(
                snapshot,
                tenant,
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
            self.collect_findings(snapshot, selection, tenant, bytes)
        })
    }

    fn finding_header(&self, row: &Row<'_>, tenant: [u8; 16]) -> Result<GraphHeader> {
        let body = row.get_ref(1).context(AnalysisDatabaseSnafu {
            operation: "read selected graph header",
        })?;
        let body = body.as_blob().map_err(|_| {
            GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .build()
        })?;
        let header = GraphHeader::decode(body)?;
        let stream = row.get_ref(2).context(AnalysisDatabaseSnafu {
            operation: "read selected graph stream",
        })?;
        let stream = stream.as_blob().map_err(|_| {
            GraphInvalidSnafu {
                field: "graph header index",
            }
            .build()
        })?;
        let method: u64 = row.get(3).context(AnalysisDatabaseSnafu {
            operation: "read selected graph method",
        })?;
        let first: u64 = row.get(4).context(AnalysisDatabaseSnafu {
            operation: "read selected graph first cursor",
        })?;
        header.check_index(tenant, stream, method, first)?;
        Ok(header)
    }

    pub(crate) fn graph_finding(
        &self,
        tenant: [u8; 16],
        result_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingV1>> {
        if tenant == [0; 16] || result_id.is_empty() || result_id.len() > 256 {
            return self.reject("the graph result reference is invalid");
        }
        self.read_snapshot(|snapshot| {
            let Some(header) = GraphRows::read_header(snapshot, tenant, result_id)? else {
                return Ok(None);
            };
            GraphRows::read_finding(snapshot, result_id, finding_id, &header, None)
        })
    }

    pub(crate) fn graph_revision_finding(
        &self,
        tenant: [u8; 16],
        finding_id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
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
