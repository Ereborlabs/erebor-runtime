use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::graph_rows::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, EvidenceIntakeIdentityV1, GraphSnapshotV1, Result,
    GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, GRAPH_WINDOW_RECORDS,
};

const GRAPH_HEADS: &str = "SELECT result_id, commit_revision, first_cursor,
        row_number() OVER (PARTITION BY stream_key, first_cursor
            ORDER BY commit_revision DESC) AS current_rank
     FROM analysis_results WHERE tenant_id = ? AND processor_id = ? AND method_version = ?
        AND stream_key IS NOT NULL AND (? IS NULL OR stream_key = ?)";

type GraphPage = (Vec<(String, GraphSnapshotV1, u64)>, Option<String>);

impl AnalysisStore {
    pub(crate) fn graph_window_headers(
        &self,
        source: &EvidenceIntakeIdentityV1,
        after: Option<u64>,
    ) -> Result<Vec<(String, GraphSnapshotV1, u64)>> {
        if !source.valid() {
            return self.reject("the graph window source is invalid");
        }
        self.read_snapshot(|reader| {
            let query = format!(
                "SELECT result_id, commit_revision FROM ({GRAPH_HEADS}) heads
                 WHERE current_rank = 1 AND (? IS NULL OR first_cursor > ?)
                 ORDER BY first_cursor LIMIT 32"
            );
            let key = source.key();
            let mut statement = reader.prepare(&query).context(AnalysisDatabaseSnafu {
                operation: "prepare graph window headers",
            })?;
            let rows = statement
                .query_map(
                    params![
                        source.tenant_id.as_slice(),
                        GRAPH_PROCESSOR,
                        GRAPH_SCHEMA_VERSION,
                        key.as_slice(),
                        key.as_slice(),
                        after,
                        after
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read graph window headers",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode graph window headers",
                })?;
            rows.into_iter()
                .map(|(id, revision)| {
                    let header =
                        self.selected_graph_header(reader, source.tenant_id, Some(source), &id)?;
                    Ok((id, header.snapshot, revision))
                })
                .collect()
        })
    }

    pub(crate) fn graph_window_page(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        after: Option<&str>,
    ) -> Result<GraphPage> {
        if !source.valid() || first == 0 || last < first || last - first >= GRAPH_WINDOW_RECORDS {
            return self.reject("the graph window range is invalid");
        }
        self.read_snapshot(|reader| {
            self.graph_page(
                reader,
                source.tenant_id,
                Some(source),
                after,
                true,
                Some((first, last)),
            )
        })
    }

    pub(super) fn graph_page(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        source: Option<&EvidenceIntakeIdentityV1>,
        after: Option<&str>,
        current: bool,
        window: Option<(u64, u64)>,
    ) -> Result<GraphPage> {
        let query = format!(
            "SELECT result_id, commit_revision FROM ({GRAPH_HEADS}) heads
             WHERE (? IS NULL OR result_id > ?) AND (NOT ? OR current_rank = 1)
                AND (? IS NULL OR first_cursor >= ?) AND (? IS NULL OR first_cursor <= ?)
             ORDER BY result_id LIMIT 1"
        );
        let key = source.map(EvidenceIntakeIdentityV1::key);
        let lower = window.map(|(first, _)| first.saturating_sub(GRAPH_WINDOW_RECORDS - 1).max(1));
        let upper = window.map(|(_, last)| last);
        let row: Option<(String, u64)> = reader
            .query_row(
                &query,
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    key.as_deref(),
                    key.as_deref(),
                    after,
                    after,
                    current,
                    lower,
                    lower,
                    upper,
                    upper
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read committed graph snapshots",
            })?;
        let Some((id, revision)) = row else {
            return Ok((Vec::new(), None));
        };
        let header = self.selected_graph_header(reader, tenant, source, &id)?;
        let next = Some(id.clone());
        if window.is_some_and(|(first, last)| {
            header.snapshot.first_cursor > last || header.snapshot.last_cursor < first
        }) {
            return Ok((Vec::new(), next));
        }
        let graph = GraphRows::read(reader, &id, &header)?;
        Ok((vec![(id, graph, revision)], next))
    }

    fn selected_graph_header(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        source: Option<&EvidenceIntakeIdentityV1>,
        id: &str,
    ) -> Result<GraphHeader> {
        let header = GraphRows::read_header(reader, tenant, id)?
            .ok_or_else(|| self.state_error("the committed graph header is absent"))?;
        if header.snapshot.scope.identity.tenant_id != tenant
            || source.is_some_and(|source| source != &header.snapshot.scope.identity)
        {
            return self.reject("the committed graph source differs from its index");
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests;
