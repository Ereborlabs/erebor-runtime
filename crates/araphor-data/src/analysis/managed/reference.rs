use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::ManagedAttempt;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, AnalysisStoreMetaV1,
    PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub(in crate::analysis) fn check_journal_source(
        &self,
        reader: &Connection,
        key: &[u8],
        selection: &crate::AnalysisSelectionV1,
        read: &crate::AnalysisTableRead<'_>,
        revision: u64,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some((first, last)) = selection.cursor_range() else {
            return Ok(());
        };
        let Some((start, end)) = selection.time_range() else {
            return Ok(());
        };
        let after = match read.mode {
            crate::AnalysisReadModeV1::Changes(after) => after.commit_revision,
            _ => 0,
        };
        let catalog: String = reader
            .query_row("SELECT current_database()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read journal catalog",
            })?;
        let base = format!("\"{}\".main", catalog.replace('"', "\"\""));
        let mut statement = reader
            .prepare(&format!(
                "SELECT first_cursor, last_cursor, received_utc_ns FROM {base}.expired_ranges
             WHERE tenant_id = ? AND stream_key = ? AND source_revision > ?
                AND source_revision <= ? AND commit_revision > ?
                AND first_cursor <= ? AND last_cursor >= ?
                AND received_utc_ns >= ? AND received_utc_ns <= ?
             ORDER BY first_cursor"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare referenced journal availability",
            })?;
        let mut rows = statement
            .query(params![
                selection.tenant_id.as_slice(),
                key,
                after,
                revision,
                revision,
                last,
                first,
                start,
                end
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read referenced journal availability",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read retired journal range",
        })? {
            control.check()?;
            let intake: u64 = row.get(2).context(AnalysisDatabaseSnafu {
                operation: "read retired journal time",
            })?;
            if read.event_ranges.is_some_and(|ranges| {
                !ranges
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&intake))
            }) {
                continue;
            }
            let begin: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read retired journal start",
            })?;
            let finish: u64 = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "read retired journal end",
            })?;
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first.max(begin),
                last_cursor: last.min(finish),
            }
            .fail();
        }
        control.check()
    }

    pub(in crate::analysis) fn bind_reference(
        &self,
        reader: &Connection,
        reference: &ManagedAttempt,
        control: &AnalysisReadControl,
    ) -> Result<(AnalysisStoreMetaV1, AnalysisStoreMetaV1)> {
        let current = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?;
        let selected = reference.source_meta();
        Self::check_trace_reads_from(
            reader,
            reference.instance().spec.tenant,
            &reference.0.capture.traces,
            control,
        )?;
        if current.store_uuid != selected.store_uuid
            || current.schema_version != selected.schema_version
            || current.recovery_epoch < selected.recovery_epoch
            || current.commit_revision < selected.commit_revision
        {
            return Err(Code::Conflict.error("managed journal identity"));
        }
        let catalog: String = reader
            .query_row("SELECT current_database()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read canonical source catalog",
            })?;
        let base = format!("\"{}\".main", catalog.replace('"', "\"\""));
        let revision = selected.commit_revision;
        reader.flush_prepared_statement_cache();
        reader.execute_batch(&format!(
            "CREATE TEMP VIEW source_receipts AS
                SELECT stream_key, identity_json, tenant_id, cpu_id, contiguous_cursor,
                    coverage_revision, retained_floor, commit_revision
                FROM {base}.source_versions WHERE commit_revision <= {revision}
                QUALIFY row_number() OVER (PARTITION BY stream_key ORDER BY commit_revision DESC) = 1;
             CREATE TEMP VIEW expired_ranges AS SELECT * FROM {base}.expired_ranges
                WHERE commit_revision <= {revision};
             CREATE TEMP VIEW recovery_gaps AS SELECT * FROM {base}.recovery_gaps
                WHERE commit_revision <= {revision};
             CREATE TEMP VIEW graph_versions AS SELECT * FROM {base}.graph_versions
                WHERE commit_revision <= {revision};
             CREATE TEMP VIEW managed_source_publications AS SELECT * FROM {base}.managed_source_publications
                WHERE revision <= {revision};
             CREATE TEMP VIEW managed_graph_publications AS SELECT * FROM {base}.managed_graph_publications
                WHERE revision <= {revision};
             CREATE TEMP VIEW trace_receipts AS
                SELECT stream_key, identity_json, tenant_id, last_sequence, output_bytes,
                    terminal, retained_floor, commit_revision FROM {base}.trace_versions
                WHERE version_revision <= {revision}
                QUALIFY row_number() OVER (PARTITION BY stream_key ORDER BY version_revision DESC) = 1;
             CREATE TEMP VIEW traces AS
                SELECT i.tenant_id, i.request_id, i.source, i.source_sha256, i.bindings,
                    i.authority, i.accepted_unix_ns, i.deadline_unix_ns, i.host_sensitive,
                    s.revision, s.cancel_requested, s.read_revoked
                FROM {base}.trace_intents i JOIN {base}.trace_states s USING (tenant_id, request_id)
                WHERE s.revision <= {revision}
                QUALIFY row_number() OVER (PARTITION BY i.tenant_id, i.request_id ORDER BY s.revision DESC) = 1;"
        )).context(AnalysisDatabaseSnafu { operation: "bind committed source views" })?;
        let results = Self::result_state(&base, Some(revision));
        reader
            .execute_batch(&format!(
                "CREATE TEMP VIEW analysis_results AS {results};
             CREATE TEMP VIEW analysis_result_state AS {results};"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "bind committed result views",
            })?;
        Ok((selected, current))
    }
}
