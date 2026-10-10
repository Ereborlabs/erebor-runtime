use duckdb::Connection;
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, Result};

impl GraphRows {
    pub(in crate::analysis) const CHARGES: &str = "SELECT r.tenant_id, r.result_id,
        256 + octet_length(encode(s.result_id)) + octet_length(s.tenant_id)
        + octet_length(encode(s.subject_kind)) + octet_length(s.authority)
        + octet_length(s.identity) AS bytes
        FROM graph_subjects s JOIN analysis_results r USING (result_id)
        UNION ALL SELECT r.tenant_id, r.result_id,
        256 + octet_length(encode(e.result_id)) + octet_length(e.from_subject_id)
        + octet_length(e.to_subject_id) + octet_length(encode(e.edge_type))
        + octet_length(encode(e.package_id)) + octet_length(encode(e.cause))
        + octet_length(e.evidence) + octet_length(e.proof_quality)
        + octet_length(e.required_coverage_interval_ids)
        FROM graph_relationships e JOIN analysis_results r USING (result_id)
        UNION ALL SELECT r.tenant_id, r.result_id,
        256 + octet_length(encode(f.result_id)) + octet_length(f.tenant_id)
        + octet_length(encode(f.finding_id)) + octet_length(encode(f.package_id))
        + octet_length(f.subject_id) + octet_length(encode(f.state))
        + octet_length(f.evidence) + octet_length(f.required_coverage_interval_ids)
        + octet_length(f.policy_provenance) + octet_length(f.effects)
        + octet_length(encode(f.reason)) + octet_length(encode(f.severity))
        + octet_length(encode(f.sensitivity))
        + coalesce(octet_length(encode(f.required_action)), 0) + octet_length(f.limits)
        FROM graph_findings f JOIN analysis_results r USING (result_id)";

    pub(in crate::analysis) const SCHEMA: &str = "CREATE TABLE graph_subjects (
        result_id VARCHAR NOT NULL, ordinal UINTEGER NOT NULL,
        tenant_id BLOB NOT NULL, subject_kind VARCHAR NOT NULL,
        authority BLOB NOT NULL, identity BLOB NOT NULL,
        PRIMARY KEY (result_id, ordinal));
    CREATE TABLE graph_relationships (
        result_id VARCHAR NOT NULL, ordinal UINTEGER NOT NULL,
        from_subject_id BLOB NOT NULL, to_subject_id BLOB NOT NULL,
        edge_type VARCHAR NOT NULL, package_id VARCHAR NOT NULL,
        cause VARCHAR NOT NULL, evidence BLOB NOT NULL, proof_quality BLOB NOT NULL,
        required_coverage_interval_ids BLOB NOT NULL,
        first_boottime_ns UBIGINT NOT NULL, last_boottime_ns UBIGINT NOT NULL,
        PRIMARY KEY (result_id, ordinal));
    CREATE TABLE graph_findings (
        result_id VARCHAR NOT NULL, ordinal UINTEGER NOT NULL,
        tenant_id BLOB NOT NULL, finding_id VARCHAR NOT NULL,
        package_id VARCHAR NOT NULL, package_version UBIGINT NOT NULL,
        subject_id BLOB NOT NULL, state VARCHAR NOT NULL,
        window_start_utc_ns BIGINT NOT NULL, window_end_utc_ns BIGINT NOT NULL,
        evidence BLOB NOT NULL, required_coverage_interval_ids BLOB NOT NULL,
        policy_provenance BLOB NOT NULL, effects BLOB NOT NULL,
        reason VARCHAR NOT NULL, severity VARCHAR NOT NULL, sensitivity VARCHAR NOT NULL,
        required_action VARCHAR, limits BLOB NOT NULL,
        PRIMARY KEY (result_id, ordinal), UNIQUE (result_id, finding_id));";

    pub(in crate::analysis) fn validate_tables(writer: &Connection) -> Result<()> {
        let expected = super::super::AnalysisStore::open_native(std::path::Path::new(":memory:"))?;
        expected
            .execute_batch(Self::SCHEMA)
            .context(AnalysisDatabaseSnafu {
                operation: "create expected native graph schema",
            })?;
        if Self::schema_shape(writer)? != Self::schema_shape(&expected)? {
            return GraphInvalidSnafu {
                field: "native graph schema",
            }
            .fail();
        }
        Ok(())
    }

    fn schema_shape(writer: &Connection) -> Result<Vec<(String, String)>> {
        let mut statement = writer
            .prepare(
                "SELECT table_name, to_json(struct_pack(
                kind := 'column', name := column_name, data_type := data_type,
                nullable := is_nullable, ordinal := ordinal_position))::VARCHAR
            FROM information_schema.columns
            WHERE table_schema = 'main'
                AND table_name IN ('graph_subjects', 'graph_relationships', 'graph_findings')
            UNION ALL
            SELECT table_name, to_json(struct_pack(
                kind := constraint_type, column_names := constraint_column_names,
                expression := constraint_text))::VARCHAR
            FROM duckdb_constraints()
            WHERE schema_name = 'main'
                AND table_name IN ('graph_subjects', 'graph_relationships', 'graph_findings')
            ORDER BY 1, 2",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native graph schema shape",
            })?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph schema shape",
            })?;
        rows.collect::<std::result::Result<_, _>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode native graph schema shape",
            })
    }
}
