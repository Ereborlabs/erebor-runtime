use duckdb::Connection;

use super::*;

impl AnalysisStore {
    pub fn graph_notice(
        &self,
        scope: &ProcessorScopeV1,
        result_id: &str,
        revision: u64,
    ) -> Result<Option<(u64, u64)>> {
        self.read_snapshot(|reader| {
            reader
                .query_row(
                    "SELECT facts_revision, coverage_revision FROM analysis_results AS target
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
        let graph = scope.processor_id == crate::GRAPH_PROCESSOR;
        let mut writer_guard = self.writer()?;
        let transaction = writer_guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin analysis notice",
            })?;
        self.notice_rows(&transaction, scope, result_id, revision, facts, coverage)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        if graph {
            self.run_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit)?;
        }
        check()?;
        self.commit_metadata(transaction, "commit analysis notice")
    }

    pub(super) fn notice_rows(
        &self,
        writer: &Connection,
        scope: &ProcessorScopeV1,
        result_id: &str,
        revision: u64,
        facts: u64,
        coverage: u64,
    ) -> Result<()> {
        let graph = scope.processor_id == crate::GRAPH_PROCESSOR;
        let changed = writer
            .execute(
                "UPDATE analysis_results AS target SET
                    facts_revision = CASE WHEN ? THEN ? ELSE GREATEST(facts_revision, ?) END,
                    coverage_revision = GREATEST(coverage_revision, ?)
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
                    graph,
                    facts,
                    facts,
                    coverage,
                    result_id,
                    scope.identity.tenant_id.as_slice(),
                    scope.processor_id,
                    scope.identity.key().as_slice(),
                    scope.method_version,
                    revision,
                    graph
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "acknowledge analysis notice",
            })?;
        if changed != 1 {
            return AnalysisConflictSnafu.fail();
        }
        Ok(())
    }
}
