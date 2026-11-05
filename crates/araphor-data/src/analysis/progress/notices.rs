use duckdb::Connection;
use std::{path::Path, sync::OnceLock};

use super::*;
use crate::analysis::PackageResultRefV1;

impl AnalysisStore {
    pub(in crate::analysis) fn notice_schema() -> String {
        format!(
            "{}\nCREATE VIEW analysis_result_state AS {};",
            include_str!("notices.sql"),
            Self::result_state("main", None)
        )
    }

    /// The caller supplies a trusted, qualified catalog prefix.
    pub(in crate::analysis) fn result_state(base: &str, cut: Option<u64>) -> String {
        let notices = cut.map_or_else(String::new, |revision| {
            format!("WHERE commit_revision <= {revision}")
        });
        let results = cut.map_or_else(String::new, |revision| {
            format!("WHERE r.commit_revision <= {revision}")
        });
        format!(
            "SELECT r.result_id, r.tenant_id, r.processor_id, r.body, r.request_meta,
                r.commit_revision, r.stream_key, r.method_version, r.interval_id,
                r.profile_revision, COALESCE(n.facts_revision, r.facts_revision) AS facts_revision,
                COALESCE(n.coverage_revision, r.coverage_revision) AS coverage_revision,
                r.first_cursor
             FROM {base}.analysis_results r LEFT JOIN (
                SELECT tenant_id, result_id, facts_revision, coverage_revision
                FROM {base}.result_notices {notices}
                QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, result_id
                    ORDER BY commit_revision DESC) = 1
             ) n ON n.tenant_id = r.tenant_id AND n.result_id = r.result_id {results}"
        )
    }

    pub(in crate::analysis) fn validate_notices(reader: &Connection, root: &Path) -> Result<()> {
        static EXPECTED: OnceLock<Vec<Vec<(String, String)>>> = OnceLock::new();
        if !Self::schema_matches(
            reader,
            &EXPECTED,
            &Self::notice_schema(),
            &[("result_notices", "analysis_result_state")],
            [
                "open result notice schema check",
                "create result notice schema check",
            ],
        )? {
            return Self::reject_path(root, "the result notice schema is invalid");
        }
        Ok(())
    }

    pub fn graph_notice(
        &self,
        scope: &ProcessorScopeV1,
        result_id: &str,
        revision: u64,
    ) -> Result<Option<(u64, u64)>> {
        self.read_snapshot(|reader| {
            reader
                .query_row(
                    "SELECT facts_revision, coverage_revision FROM analysis_result_state AS target
                    WHERE result_id = ? AND tenant_id = ? AND processor_id = ?
                        AND stream_key = ? AND method_version = ? AND commit_revision = ?
                        AND NOT EXISTS (SELECT 1 FROM analysis_results AS next
                            WHERE next.tenant_id = target.tenant_id
                                AND next.processor_id = target.processor_id
                                AND next.stream_key = target.stream_key
                                AND next.method_version = target.method_version
                                AND next.first_cursor = target.first_cursor
                                AND next.commit_revision > target.commit_revision)",
                    params![
                        result_id,
                        scope.identity.tenant_id.as_slice(),
                        scope.processor_id,
                        scope.identity.key().as_slice(),
                        scope.method_version,
                        revision
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read graph fact notice",
                })
        })
    }

    pub fn mark_notice(
        &self,
        profile: &crate::DiscoveryProfileV1,
        revision: u64,
        facts: u64,
        coverage: u64,
    ) -> Result<()> {
        profile.validate()?;
        self.mark_result_notice(
            &profile.scope,
            &profile.profile_id,
            revision,
            facts,
            coverage,
            &mut || Ok(()),
        )
    }

    pub fn mark_graph_notice(
        &self,
        scope: &ProcessorScopeV1,
        result_id: &str,
        revision: u64,
        facts: u64,
        coverage: u64,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if scope.processor_id != crate::GRAPH_PROCESSOR
            || scope.method_version != u64::from(crate::GRAPH_SCHEMA_VERSION)
        {
            return self.reject("the graph notice scope is invalid");
        }
        self.mark_result_notice(scope, result_id, revision, facts, coverage, &mut check)
    }

    fn mark_result_notice(
        &self,
        scope: &ProcessorScopeV1,
        result_id: &str,
        revision: u64,
        facts: u64,
        coverage: u64,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if !scope.valid() || result_id.is_empty() || revision == 0 {
            return self.reject("the result notice identity is invalid");
        }
        let mut writer_guard = self.writer()?;
        let transaction = writer_guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin analysis notice",
            })?;
        let changed = self.notice_rows(
            &transaction,
            scope,
            &PackageResultRefV1 {
                result_id: result_id.into(),
                commit_revision: revision,
            },
            facts,
            coverage,
            None,
        )?;
        #[cfg(any(test, feature = "test-fixtures"))]
        if scope.processor_id == crate::GRAPH_PROCESSOR {
            self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        }
        if let Some(revision) = changed {
            self.check_revision_limits(&transaction, scope.identity.tenant_id)?;
            Self::record_revision(
                &transaction,
                revision,
                &["result_notices", "analysis_results"],
            )?;
        }
        check()?;
        if let Some(revision) = changed {
            self.commit_metadata(transaction, "commit analysis notice")?;
            self.revision.send_replace(revision);
            let change = super::super::inputs::InputChange::Notice { scope, result: result_id };
            self.inputs.metadata(revision, change);
        }
        Ok(())
    }

    pub(super) fn notice_rows(
        &self,
        writer: &Connection,
        scope: &ProcessorScopeV1,
        reference: &PackageResultRefV1,
        facts: u64,
        coverage: u64,
        revision: Option<u64>,
    ) -> Result<Option<u64>> {
        let graph = scope.processor_id == crate::GRAPH_PROCESSOR;
        let current: Option<(u64, u64)> = writer
            .query_row(
                "SELECT facts_revision, coverage_revision FROM analysis_result_state AS target
                WHERE result_id = ? AND tenant_id = ? AND processor_id = ?
                    AND stream_key = ? AND method_version = ? AND commit_revision = ?
                    AND (NOT ? OR NOT EXISTS (SELECT 1 FROM analysis_results AS next
                        WHERE next.tenant_id = target.tenant_id
                            AND next.processor_id = target.processor_id
                            AND next.stream_key = target.stream_key
                            AND next.method_version = target.method_version
                            AND next.first_cursor = target.first_cursor
                            AND next.commit_revision > target.commit_revision))",
                params![
                    reference.result_id,
                    scope.identity.tenant_id.as_slice(),
                    scope.processor_id,
                    scope.identity.key().as_slice(),
                    scope.method_version,
                    reference.commit_revision,
                    graph
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read analysis notice state",
            })?;
        let Some(current) = current else {
            return AnalysisConflictSnafu.fail();
        };
        let next = (
            if graph { facts } else { current.0.max(facts) },
            current.1.max(coverage),
        );
        if current == next {
            return Ok(None);
        }
        let revision = match revision {
            Some(revision) => revision,
            None => self.package_next(writer)?,
        };
        writer
            .execute(
                "INSERT INTO result_notices VALUES (?, ?, ?, ?, ?)",
                params![
                    scope.identity.tenant_id.as_slice(),
                    reference.result_id,
                    revision,
                    next.0,
                    next.1
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "append analysis notice",
            })?;
        Ok(Some(revision))
    }
}
