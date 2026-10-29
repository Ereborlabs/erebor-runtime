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
        header.snapshot.graph.branches =
            Self::read_branches(writer, result_id, tenant, header.branch_count, control)?;
        header.branches_loaded = true;
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
        let (subjects, distinct_subjects, edges, findings): (u64, u64, u64, u64) = writer
            .query_row(
                "WITH version AS (
                    SELECT lineage_id, commit_revision FROM graph_versions WHERE result_id = ?
                ), subjects AS (
                    SELECT s.subject_id FROM version v
                    JOIN graph_subject_membership m ON m.lineage_id = v.lineage_id
                        AND m.valid_from <= v.commit_revision
                        AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                    JOIN graph_subject_values s USING (subject_id)
                ) SELECT
                    (SELECT count(*)::UBIGINT FROM subjects),
                    (SELECT count(DISTINCT subject_id)::UBIGINT FROM subjects),
                    (SELECT count(*)::UBIGINT FROM version v
                        JOIN graph_edge_membership m ON m.lineage_id = v.lineage_id
                            AND m.valid_from <= v.commit_revision
                            AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                        JOIN graph_edge_values e USING (edge_id)),
                    (SELECT count(*)::UBIGINT FROM version v
                        JOIN graph_finding_membership m ON m.lineage_id = v.lineage_id
                            AND m.valid_from <= v.commit_revision
                            AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                        JOIN graph_finding_values f USING (value_id))",
                params![result_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check native graph row counts",
            })?;
        if subjects != distinct_subjects {
            return GraphInvalidSnafu {
                field: "duplicate graph subject membership",
            }
            .fail();
        }
        Ok((subjects, edges, findings))
    }
}
