use super::super::graph_rows::{GraphHeader, GraphRows};
use super::*;

type GraphPage = (Vec<(String, GraphSnapshotV1, u64)>, Option<String>);

impl AnalysisStore {
    pub fn graph_window_headers(
        &self,
        source: &EvidenceIntakeIdentityV1,
        after: Option<u64>,
    ) -> Result<Vec<(String, GraphSnapshotV1, u64)>> {
        if !source.valid() {
            return self.reject("the Graph source is invalid");
        }
        self.read_snapshot(|reader| {
            let mut statement=reader.prepare("SELECT result_id,commit_revision FROM analysis_results WHERE tenant_id=? AND processor_id=? AND method_version=? AND stream_key=? QUALIFY row_number() OVER(PARTITION BY first_cursor ORDER BY commit_revision DESC)=1 AND (? IS NULL OR first_cursor>?) ORDER BY first_cursor LIMIT 32").context(AnalysisDatabaseSnafu {operation:"prepare Graph windows"})?;
            let rows=statement.query_map(params![source.tenant_id.as_slice(),GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,source.key(),after,after],|row|Ok((row.get::<_,String>(0)?,row.get::<_,u64>(1)?))).context(AnalysisDatabaseSnafu {operation:"read Graph windows"})?.collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu {operation:"decode Graph windows"})?;
            rows.into_iter().map(|(id,revision)|self.selected_graph_header(reader,source.tenant_id,Some(source),&id).map(|header|(id,header.snapshot,revision))).collect()
        })
    }

    pub fn graph_window_page(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
        after: Option<&str>,
    ) -> Result<GraphPage> {
        if !source.valid() || first == 0 || last < first {
            return self.reject("the Graph window is invalid");
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
        let source = source.map(EvidenceIntakeIdentityV1::key);
        let mut statement=reader.prepare("SELECT result_id,commit_revision FROM (SELECT result_id,commit_revision,first_cursor,row_number() OVER(PARTITION BY stream_key,first_cursor ORDER BY commit_revision DESC) AS rank FROM analysis_results WHERE tenant_id=? AND processor_id=? AND method_version=? AND stream_key IS NOT NULL AND (? IS NULL OR stream_key=?)) WHERE (? IS NULL OR result_id>?) AND (NOT ? OR rank=1) AND (? IS NULL OR first_cursor<=?) ORDER BY result_id LIMIT 1").context(AnalysisDatabaseSnafu {operation:"prepare Graph page"})?;
        let row: Option<(String, u64)> = statement
            .query_row(
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    source.as_deref(),
                    source.as_deref(),
                    after,
                    after,
                    current,
                    window.map(|(_, last)| last),
                    window.map(|(_, last)| last)
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph page",
            })?;
        let Some((id, revision)) = row else {
            return Ok((Vec::new(), None));
        };
        let header = self.selected_graph_header(reader, tenant, None, &id)?;
        let graph = if window.is_some_and(|(first, last)| {
            header.snapshot.first_cursor > last || header.snapshot.last_cursor < first
        }) {
            None
        } else {
            Some(GraphRows::read(reader, &id, &header)?)
        };
        Ok((
            graph
                .into_iter()
                .map(|graph| (id.clone(), graph, revision))
                .collect(),
            Some(id),
        ))
    }

    pub(super) fn selected_graph_header(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        source: Option<&EvidenceIntakeIdentityV1>,
        id: &str,
    ) -> Result<GraphHeader> {
        let header = GraphRows::read_header(reader, tenant, id)?
            .ok_or_else(|| self.state_error("the Graph header is absent"))?;
        if source.is_some_and(|source| source != &header.snapshot.scope.identity) {
            return self.reject("the Graph source differs");
        }
        Ok(header)
    }
}
