use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, GraphInvalidSnafu, Result};

type HeaderRow = (Vec<u8>, Option<Vec<u8>>, u64, u64, u64, u64);

impl GraphRows {
    pub(in crate::analysis) fn read_header(
        writer: &Connection,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphHeader>> {
        Self::read_header_control(writer, tenant, result_id, None)
    }

    pub(in crate::analysis) fn read_header_control(
        writer: &Connection,
        tenant: [u8; 16],
        result_id: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<GraphHeader>> {
        let stored: Option<HeaderRow> = writer
            .query_row(
                "SELECT body,
                CASE WHEN octet_length(stream_key) <= ? THEN stream_key ELSE NULL END,
                method_version, first_cursor, facts_revision, coverage_revision FROM analysis_results
            WHERE tenant_id = ? AND result_id = ? AND processor_id = ?
                AND stream_key IS NOT NULL",
                params![
                    crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64,
                    tenant.as_slice(),
                    result_id,
                    crate::GRAPH_PROCESSOR
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph header",
            })?;
        let Some((bytes, stream, method, first, facts, coverage)) = stored else {
            return Ok(None);
        };
        let mut header = GraphHeader::decode(&bytes)?;
        header.notice = (facts, coverage);
        let stream = stream.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph header index",
            }
            .build()
        })?;
        header.check_index(tenant, &stream, method, first)?;
        let (evidence, positions) = Self::load_inputs(writer, result_id, &header, control)?;
        header.snapshot.input_manifest.evidence = evidence;
        header.snapshot.input_positions = positions;
        header.snapshot.validate()?;
        Self::check_shape(writer, result_id, &header)?;
        Ok(Some(header))
    }

    pub(in crate::analysis) fn check_shape(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
    ) -> Result<()> {
        let (subjects, edges, findings) = Self::stored_shape(writer, result_id)?;
        header.check_shape(subjects, edges, findings)
    }

    pub(super) fn stored_shape(writer: &Connection, result_id: &str) -> Result<(u64, u64, u64)> {
        writer
            .query_row(
                "SELECT (SELECT count(*)::UBIGINT FROM graph_subjects WHERE result_id = ?),
                    (SELECT count(*)::UBIGINT FROM graph_relationships WHERE result_id = ?),
                    (SELECT count(*)::UBIGINT FROM graph_findings WHERE result_id = ?)",
                params![result_id, result_id, result_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check native graph row counts",
            })
    }
}
