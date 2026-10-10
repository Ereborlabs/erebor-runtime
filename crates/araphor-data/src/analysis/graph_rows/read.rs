use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{GraphHeader, GraphRows};
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, GraphSnapshotV1, Result};

type HeaderRow = (Option<Vec<u8>>, Option<Vec<u8>>, u64, u64);

impl GraphRows {
    pub(in crate::analysis) fn read_body(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        snapshot: &GraphSnapshotV1,
    ) -> Result<Vec<u8>> {
        let encoding: Option<Option<Vec<u8>>> = writer
            .query_row(
                "SELECT CASE WHEN octet_length(graph_encoding) <= ?
                THEN graph_encoding ELSE NULL END FROM analysis_results
                WHERE tenant_id = ? AND result_id = ? AND processor_id = ?
                AND stream_key IS NOT NULL",
                params![
                    Self::MAX_ENCODING as u64,
                    header.snapshot.scope.identity.tenant_id.as_slice(),
                    result_id,
                    crate::GRAPH_PROCESSOR
                ],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph encoding",
            })?;
        let encoding = encoding.flatten().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph encoding bytes",
            }
            .build()
        })?;
        header.body(snapshot, &encoding)
    }

    pub(in crate::analysis) fn read_header(
        writer: &Connection,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphHeader>> {
        let stored: Option<HeaderRow> = writer
            .query_row(
                "SELECT CASE WHEN octet_length(body) <= ? THEN body ELSE NULL END,
                CASE WHEN octet_length(stream_key) <= ? THEN stream_key ELSE NULL END,
                method_version, first_cursor FROM analysis_results
            WHERE tenant_id = ? AND result_id = ? AND processor_id = ?
                AND stream_key IS NOT NULL",
                params![
                    GraphHeader::MAX_BYTES as u64,
                    crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64,
                    tenant.as_slice(),
                    result_id,
                    crate::GRAPH_PROCESSOR
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph header",
            })?;
        let Some((bytes, stream, method, first)) = stored else {
            return Ok(None);
        };
        let bytes = bytes.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .build()
        })?;
        let header = GraphHeader::decode(&bytes)?;
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
        let query = format!(
            "WITH analysis_results AS (
            SELECT result_id, tenant_id FROM main.analysis_results WHERE result_id = ?
            ) SELECT coalesce(sum(bytes), 0)::UBIGINT FROM ({})",
            Self::CHARGES
        );
        let stored: u64 = writer
            .query_row(&query, params![result_id], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "check native graph bytes",
            })?;
        header.check_bytes(result_id, stored)
    }
}
