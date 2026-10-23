use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, Result};

type HeaderRow = (Option<Vec<u8>>, Option<Vec<u8>>, u64, u64, u64, u64);

impl GraphRows {
    pub(in crate::analysis) fn read_header(
        writer: &Connection,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphHeader>> {
        let stored: Option<HeaderRow> = writer
            .query_row(
                "SELECT CASE WHEN octet_length(body) <= ? THEN body ELSE NULL END,
                CASE WHEN octet_length(stream_key) <= ? THEN stream_key ELSE NULL END,
                method_version, first_cursor, facts_revision, coverage_revision FROM analysis_results
            WHERE tenant_id = ? AND result_id = ? AND processor_id = ?
                AND stream_key IS NOT NULL",
                params![
                    GraphHeader::MAX_BYTES as u64,
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
        let bytes = bytes.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .build()
        })?;
        let mut header = GraphHeader::decode(&bytes)?;
        header.notice = (facts, coverage);
        let stream = stream.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph header index",
            }
            .build()
        })?;
        header.check_index(tenant, &stream, method, first)?;
        Self::check_bytes(writer, result_id, &header)?;
        Ok(Some(header))
    }

    pub(super) fn check_bytes(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
    ) -> Result<()> {
        header.check_bytes(result_id, Self::stored_bytes(writer, result_id)?)
    }

    pub(super) fn stored_bytes(writer: &Connection, result_id: &str) -> Result<u64> {
        let query = format!(
            "WITH analysis_results AS (
            SELECT result_id, tenant_id FROM main.analysis_results WHERE result_id = ?
            ) SELECT coalesce(sum(bytes), 0)::UBIGINT FROM ({})",
            Self::CHARGES
        );
        writer
            .query_row(&query, params![result_id], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "check native graph bytes",
            })
    }
}
