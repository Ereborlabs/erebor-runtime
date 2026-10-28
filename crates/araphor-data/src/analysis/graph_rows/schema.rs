use duckdb::Connection;
use snafu::ResultExt as _;
use std::sync::OnceLock;

use super::GraphRows;
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, Result};

impl GraphRows {
    pub(in crate::analysis) const SCHEMA: &str = "CREATE TABLE graph_versions (
        result_id VARCHAR PRIMARY KEY, lineage_id UBIGINT NOT NULL,
        commit_revision UBIGINT NOT NULL,
        UNIQUE (lineage_id, commit_revision));
    CREATE TABLE graph_evidence (
        evidence_id UBIGINT PRIMARY KEY, stream_key BLOB NOT NULL,
        cpu_id UINTEGER NOT NULL, durable_cursor UBIGINT NOT NULL,
        UNIQUE (stream_key, cpu_id, durable_cursor));
    CREATE TABLE graph_evidence_membership (
        lineage_id UBIGINT NOT NULL, evidence_id UBIGINT NOT NULL,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (lineage_id, evidence_id, valid_from));
    CREATE TABLE graph_input_positions (
        lineage_id UBIGINT NOT NULL, evidence_id UBIGINT NOT NULL,
        rank UINTEGER NOT NULL, commit_revision UBIGINT NOT NULL,
        ordinal UINTEGER NOT NULL, valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (lineage_id, rank, valid_from));
    CREATE TABLE graph_subject_values (
        subject_id UBIGINT PRIMARY KEY,
        tenant_id BLOB NOT NULL, authority_rank UTINYINT NOT NULL,
        authority_text VARCHAR NOT NULL, authority_boot BLOB NOT NULL,
        authority_epoch UBIGINT NOT NULL, subject_kind UTINYINT NOT NULL,
        identity BLOB NOT NULL,
        UNIQUE (tenant_id, authority_rank, authority_text, authority_boot,
            authority_epoch, subject_kind, identity));
    CREATE TABLE graph_subject_membership (
        lineage_id UBIGINT NOT NULL, subject_id UBIGINT NOT NULL,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (lineage_id, subject_id, valid_from));
    CREATE VIEW graph_subjects AS
        SELECT v.result_id,
            (row_number() OVER (PARTITION BY v.result_id
                ORDER BY s.tenant_id, s.authority_rank, s.authority_text,
                    s.authority_boot, s.authority_epoch, s.subject_kind,
                    s.identity) - 1)::UINTEGER AS ordinal,
            s.tenant_id, s.authority_rank, s.authority_text,
            s.authority_boot, s.authority_epoch, s.subject_kind, s.identity
        FROM graph_versions v
        JOIN graph_subject_membership m ON m.lineage_id = v.lineage_id
            AND m.valid_from <= v.commit_revision
            AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
        JOIN graph_subject_values s USING (subject_id);
    CREATE TABLE graph_relationships (
        result_id VARCHAR NOT NULL, ordinal UINTEGER NOT NULL,
        from_subject_id UINTEGER NOT NULL, to_subject_id UINTEGER NOT NULL,
        edge_type VARCHAR NOT NULL, package_id VARCHAR NOT NULL,
        cause VARCHAR NOT NULL, evidence UINTEGER[] NOT NULL,
        proof_quality STRUCT(source_authority UTINYINT, local_subject_binding UTINYINT,
            remote_subject_binding UTINYINT, operation_result_authority UTINYINT,
            temporal_coverage UTINYINT, integrity UTINYINT) NOT NULL,
        required_coverage_interval_ids BLOB[] NOT NULL,
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
        let expected = Self::expected_shape()?;
        if Self::schema_shape(writer)?.as_slice() != expected {
            return GraphInvalidSnafu {
                field: "native graph schema",
            }
            .fail();
        }
        Ok(())
    }

    fn expected_shape() -> Result<&'static [(String, String)]> {
        static EXPECTED: OnceLock<Vec<(String, String)>> = OnceLock::new();
        if let Some(shape) = EXPECTED.get() {
            return Ok(shape);
        }
        let expected = super::super::AnalysisStore::open_native(
            std::path::Path::new(":memory:"),
            Default::default(),
            duckdb::AccessMode::Automatic,
        )?;
        expected
            .execute_batch(Self::SCHEMA)
            .context(AnalysisDatabaseSnafu {
                operation: "create expected native graph schema",
            })?;
        let shape = Self::schema_shape(&expected)?;
        Ok(EXPECTED.get_or_init(|| shape))
    }

    fn schema_shape(writer: &Connection) -> Result<Vec<(String, String)>> {
        let mut statement = writer
            .prepare(
                "SELECT table_name, to_json(struct_pack(
                kind := 'column', name := column_name, data_type := data_type,
                nullable := is_nullable, ordinal := ordinal_position))::VARCHAR
            FROM information_schema.columns
            WHERE table_schema = 'main'
                AND table_name IN ('graph_versions', 'graph_evidence',
                    'graph_evidence_membership', 'graph_input_positions',
                    'graph_subject_values', 'graph_subject_membership',
                    'graph_subjects', 'graph_relationships', 'graph_findings')
            UNION ALL
            SELECT table_name, to_json(struct_pack(
                kind := constraint_type, column_names := constraint_column_names,
                expression := constraint_text))::VARCHAR
            FROM duckdb_constraints()
            WHERE schema_name = 'main'
                AND table_name IN ('graph_versions', 'graph_evidence',
                    'graph_evidence_membership', 'graph_input_positions',
                    'graph_subject_values', 'graph_subject_membership',
                    'graph_subjects', 'graph_relationships', 'graph_findings')
            UNION ALL
            -- DuckDB quotes this cast until the database is reopened.
            SELECT view_name,
                replace(sql, 'AS ' || chr(34) || 'UINTEGER' || chr(34)
                    || ') AS ordinal', 'AS UINTEGER) AS ordinal')
            FROM duckdb_views()
            WHERE schema_name = 'main' AND view_name = 'graph_subjects'
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
