use std::path::Path;
use std::sync::OnceLock;

use duckdb::Connection;
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub(in crate::analysis) fn validate_trace_history(
        reader: &Connection,
        root: &Path,
    ) -> Result<()> {
        static EXPECTED: OnceLock<Vec<Vec<(String, String)>>> = OnceLock::new();
        let relations = [
            ("trace_intents", "traces"),
            ("trace_states", "traces"),
            ("trace_versions", "trace_receipts"),
        ];
        if !Self::schema_matches(
            reader,
            &EXPECTED,
            Self::TRACE_SCHEMA,
            &relations,
            ["open trace schema check", "create trace schema check"],
        )? {
            return Self::reject_path(root, "the trace history schema is invalid");
        }
        let invalid: bool = reader
            .query_row(
                "SELECT EXISTS (
                SELECT 1 FROM (
                    SELECT *, row_number() OVER w AS n,
                        lag(cancel_requested) OVER w AS old_cancel,
                        lag(read_revoked) OVER w AS old_revoked
                    FROM trace_states WINDOW w AS (
                        PARTITION BY tenant_id, request_id ORDER BY revision)
                ) s WHERE revision = 0 OR revision > (SELECT commit_revision FROM store_meta)
                    OR (n = 1 AND (cancel_requested OR read_revoked))
                    OR (read_revoked AND NOT cancel_requested)
                    OR (old_cancel AND NOT cancel_requested)
                    OR (old_revoked AND NOT read_revoked)
                    OR (n > 1 AND old_cancel = cancel_requested AND old_revoked = read_revoked)
                UNION ALL SELECT 1 FROM trace_intents i ANTI JOIN trace_states s
                    USING (tenant_id, request_id)
                UNION ALL SELECT 1 FROM (
                    SELECT *, row_number() OVER w AS n,
                        first_value(identity_json) OVER w AS original_identity,
                        first_value(tenant_id) OVER w AS original_tenant,
                        lag(last_sequence) OVER w AS old_sequence,
                        lag(output_bytes) OVER w AS old_bytes,
                        lag(retained_floor) OVER w AS old_floor,
                        lag(commit_revision) OVER w AS old_revision,
                        lag(terminal) OVER w AS old_terminal
                    FROM trace_versions WINDOW w AS (
                        PARTITION BY stream_key ORDER BY version_revision)
                ) v WHERE version_revision = 0
                    OR version_revision > (SELECT commit_revision FROM store_meta)
                    OR commit_revision > version_revision
                    OR output_bytes < last_sequence
                    OR retained_floor > CAST(last_sequence AS HUGEINT)
                        + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END
                    OR ((last_sequence > 0 OR terminal IS NOT NULL) AND commit_revision = 0)
                    OR identity_json <> original_identity OR tenant_id <> original_tenant
                    OR (n = 1 AND (last_sequence <> 0 OR output_bytes <> 0
                        OR terminal IS NOT NULL OR retained_floor <> 0 OR commit_revision <> 0))
                    OR old_sequence > last_sequence OR old_bytes > output_bytes
                    OR old_floor > retained_floor OR old_revision > commit_revision
                    OR (old_terminal IS NOT NULL AND terminal IS DISTINCT FROM old_terminal)
            )",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate native trace history",
            })?;
        if invalid {
            return Self::reject_path(root, "the trace history is invalid");
        }
        Ok(())
    }
}
