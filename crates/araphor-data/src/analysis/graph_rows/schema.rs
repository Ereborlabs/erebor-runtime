use duckdb::Connection;
use snafu::ResultExt as _;
use std::sync::OnceLock;

use super::GraphRows;
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, Result};
use araphor_graph::FindingRows;

impl GraphRows {
    pub(in crate::analysis) const SCHEMA: &str = "CREATE TABLE graph_versions (
        result_id VARCHAR PRIMARY KEY, lineage_id UBIGINT NOT NULL,
        commit_revision UBIGINT NOT NULL,
        UNIQUE (lineage_id, commit_revision));
    CREATE TABLE graph_sources (
        source_ref UBIGINT PRIMARY KEY, stream_key BLOB NOT NULL UNIQUE,
        tenant_id BLOB NOT NULL);
    CREATE TABLE graph_evidence (
        evidence_id UBIGINT PRIMARY KEY, source_ref UBIGINT NOT NULL,
        cpu_id UINTEGER NOT NULL, durable_cursor UBIGINT NOT NULL,
        UNIQUE (source_ref, cpu_id, durable_cursor));
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
            s.authority_boot, s.authority_epoch, s.subject_kind, s.identity,
            s.subject_id
        FROM graph_versions v
        JOIN graph_subject_membership m ON m.lineage_id = v.lineage_id
            AND m.valid_from <= v.commit_revision
            AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
        JOIN graph_subject_values s USING (subject_id);
    CREATE TABLE graph_edge_properties (
        property_ref UBIGINT PRIMARY KEY,
        property_hash BLOB NOT NULL CHECK (octet_length(property_hash) = 32),
        edge_type VARCHAR NOT NULL, edge_type_rank UTINYINT NOT NULL,
        package_id VARCHAR NOT NULL,
        cause VARCHAR NOT NULL, cause_rank UTINYINT NOT NULL,
        proof_quality STRUCT(source_authority UTINYINT, local_subject_binding UTINYINT,
            remote_subject_binding UTINYINT, operation_result_authority UTINYINT,
            temporal_coverage UTINYINT, integrity UTINYINT) NOT NULL,
        required_coverage_interval_ids BLOB[] NOT NULL);
    CREATE INDEX graph_edge_property_hash ON graph_edge_properties (property_hash);
    CREATE TABLE graph_edge_values (
        edge_id UBIGINT PRIMARY KEY,
        value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32),
        from_ref UBIGINT NOT NULL, to_ref UBIGINT NOT NULL,
        property_ref UBIGINT NOT NULL,
        evidence_refs UBIGINT[] NOT NULL,
        first_boottime_ns UBIGINT NOT NULL, last_boottime_ns UBIGINT NOT NULL,
        CHECK (first_boottime_ns <= last_boottime_ns));
    CREATE INDEX graph_edge_hash ON graph_edge_values (value_hash);
    CREATE VIEW graph_edge_values_expanded AS
        SELECT e.edge_id, e.value_hash, e.from_ref, e.to_ref,
            p.edge_type, p.edge_type_rank, p.package_id,
            p.cause, p.cause_rank, e.evidence_refs, p.proof_quality,
            p.required_coverage_interval_ids,
            e.first_boottime_ns, e.last_boottime_ns
        FROM graph_edge_values e LEFT JOIN graph_edge_properties p USING (property_ref);
    CREATE TABLE graph_edge_membership (
        lineage_id UBIGINT NOT NULL, edge_id UBIGINT NOT NULL,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (lineage_id, edge_id, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from));
    CREATE TABLE graph_call_scopes (
        scope_id UBIGINT PRIMARY KEY, tenant_id BLOB NOT NULL,
        instance_id VARCHAR NOT NULL, call_id UBIGINT NOT NULL,
        package_id VARCHAR NOT NULL, package_revision VARCHAR NOT NULL,
        image_digest VARCHAR NOT NULL, created_revision UBIGINT NOT NULL);
    CREATE TABLE graph_call_versions (
        result_id VARCHAR PRIMARY KEY, scope_id UBIGINT NOT NULL,
        commit_revision UBIGINT NOT NULL, base_result_id VARCHAR,
        subject_count UBIGINT NOT NULL, edge_count UBIGINT NOT NULL,
        finding_count UBIGINT NOT NULL, progress_count UBIGINT NOT NULL,
        UNIQUE (scope_id, commit_revision));
    CREATE TABLE graph_call_subjects (
        scope_id UBIGINT NOT NULL, subject_id UBIGINT NOT NULL,
        anchor_record_id UBIGINT NOT NULL, anchor_fact BLOB,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (scope_id, subject_id, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from));
    CREATE TABLE graph_call_edges (
        scope_id UBIGINT NOT NULL, edge_id UBIGINT NOT NULL,
        anchor_record_id UBIGINT NOT NULL, anchor_fact BLOB,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (scope_id, edge_id, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from));
    CREATE TABLE graph_call_findings (
        scope_id UBIGINT NOT NULL, value_id UBIGINT NOT NULL,
        anchor_record_id UBIGINT NOT NULL, anchor_fact BLOB,
        reason_code VARCHAR NOT NULL,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (scope_id, value_id, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from));
    CREATE TABLE graph_progress_values (
        value_ref UBIGINT PRIMARY KEY, evidence_id UBIGINT NOT NULL,
        digest BLOB NOT NULL CHECK (octet_length(digest) = 32),
        state VARCHAR);
    CREATE TABLE graph_call_progress (
        scope_id UBIGINT NOT NULL, value_ref UBIGINT NOT NULL,
        valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (scope_id, value_ref, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from));
    CREATE VIEW graph_relationships AS
        WITH evidence_ordinals AS (
            SELECT v.result_id, e.evidence_id,
                (row_number() OVER (PARTITION BY v.result_id
                    ORDER BY e.cpu_id, e.durable_cursor) - 1)::UINTEGER AS ordinal
            FROM graph_versions v
            JOIN graph_evidence_membership m ON m.lineage_id = v.lineage_id
                AND m.valid_from <= v.commit_revision
                AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
            JOIN graph_evidence e USING (evidence_id)
        ), selected AS (
            SELECT v.result_id, e.edge_id, source.ordinal AS from_subject_id,
                target.ordinal AS to_subject_id,
                e.edge_type, e.edge_type_rank, e.package_id,
                e.cause, e.cause_rank, e.evidence_refs,
                e.proof_quality, e.required_coverage_interval_ids,
                e.first_boottime_ns, e.last_boottime_ns
            FROM graph_versions v
            JOIN graph_edge_membership m ON m.lineage_id = v.lineage_id
                AND m.valid_from <= v.commit_revision
                AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
            JOIN graph_edge_values_expanded e USING (edge_id)
            LEFT JOIN graph_subjects source ON source.result_id = v.result_id
                AND source.subject_id = e.from_ref
            LEFT JOIN graph_subjects target ON target.result_id = v.result_id
                AND target.subject_id = e.to_ref
        ), edge_evidence AS (
            SELECT s.result_id, s.edge_id,
                list(o.ordinal ORDER BY refs.position)::UINTEGER[] AS evidence
            FROM selected s
            CROSS JOIN unnest(s.evidence_refs)
                WITH ORDINALITY AS refs(evidence_id, position)
            LEFT JOIN evidence_ordinals o ON o.result_id = s.result_id
                AND o.evidence_id = refs.evidence_id
            GROUP BY s.result_id, s.edge_id
        ), resolved AS (
            SELECT s.result_id, s.from_subject_id, s.to_subject_id,
                s.edge_type, s.edge_type_rank, s.package_id,
                s.cause, s.cause_rank,
                coalesce(edge_evidence.evidence, []::UINTEGER[]) AS evidence,
                s.proof_quality, s.required_coverage_interval_ids,
                s.first_boottime_ns, s.last_boottime_ns
            FROM selected s LEFT JOIN edge_evidence
                ON edge_evidence.result_id = s.result_id
                AND edge_evidence.edge_id = s.edge_id
        ) SELECT result_id,
            (row_number() OVER (PARTITION BY result_id
                ORDER BY from_subject_id, to_subject_id, edge_type_rank,
                    package_id, evidence, cause_rank) - 1)::UINTEGER AS ordinal,
            from_subject_id, to_subject_id, edge_type, package_id,
            cause, evidence, proof_quality, required_coverage_interval_ids,
            first_boottime_ns, last_boottime_ns FROM resolved;";

    pub(in crate::analysis) fn schema() -> String {
        let mut schema = String::from(Self::SCHEMA);
        schema.push_str(FindingRows::SCHEMA);
        schema
    }

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
            .execute_batch(&Self::schema())
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
            WHERE table_schema = 'main' AND starts_with(table_name, 'graph_')
            UNION ALL
            SELECT table_name, to_json(struct_pack(
                kind := constraint_type, column_names := constraint_column_names,
                expression := constraint_text))::VARCHAR
            FROM duckdb_constraints()
            WHERE schema_name = 'main' AND starts_with(table_name, 'graph_')
            UNION ALL
            -- DuckDB quotes this cast until the database is reopened.
            SELECT view_name,
                replace(replace(replace(replace(sql, 'AS ' || chr(34) || 'UINTEGER' || chr(34)
                    || ') AS ordinal', 'AS UINTEGER) AS ordinal'),
                    'AS ' || chr(34) || 'UINTEGER' || chr(34)
                    || '))) AS evidence', 'AS UINTEGER))) AS evidence'),
                    'AS ' || chr(34) || 'UINTEGER' || chr(34)
                    || '[]', 'AS UINTEGER[]'),
                    'CROSS JOIN unnest(', ', unnest(')
            FROM duckdb_views()
            WHERE schema_name = 'main' AND starts_with(view_name, 'graph_')
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
