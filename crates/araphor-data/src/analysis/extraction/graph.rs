use snafu::ResultExt as _;

use super::super::graph_rows::{GraphHeader, GraphRows};
use super::*;

impl AnalysisStore {
    pub(super) fn graph_input<T>(
        &self,
        snapshot: &Connection,
        tenant: [u8; 16],
        result_id: &str,
        output: &mut AnalysisExtractionV1<T>,
        control: &AnalysisReadControl,
    ) -> Result<GraphHeader> {
        control.check()?;
        let length: u64 = snapshot
            .query_row(
                "SELECT octet_length(body) FROM analysis_results
             WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND result_id = ?
                AND stream_key IS NOT NULL",
                params![
                    tenant.as_slice(),
                    crate::GRAPH_PROCESSOR,
                    crate::GRAPH_SCHEMA_VERSION,
                    result_id
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read graph header length",
            })?;
        let length = usize::try_from(length)
            .map_err(|_| self.state_error("the graph header length is invalid"))?;
        output.scan(length)?;
        output.charge(length.saturating_mul(2))?;
        let mut header = GraphRows::read_header(snapshot, tenant, result_id)?
            .ok_or_else(|| self.state_error("the selected graph header is absent"))?;
        let remaining = header.snapshot_bytes.saturating_sub(length);
        output.scan(remaining)?;
        output.charge(remaining.saturating_mul(2))?;
        header.snapshot.findings =
            GraphRows::read_findings(snapshot, result_id, &header, Some(control))?;
        if header.snapshot.findings.len() != header.finding_count {
            return self.reject("the selected graph finding count differs");
        }
        header.snapshot.validate()?;
        Ok(header)
    }
}
