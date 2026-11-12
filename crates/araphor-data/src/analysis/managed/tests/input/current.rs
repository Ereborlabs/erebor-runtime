use super::*;

mod follow;

#[derive(Debug, PartialEq)]
struct CommitState {
    meta: crate::AnalysisStoreMetaV1,
    instance: ManagedInstance,
    heads: Vec<(u64, u64, Option<String>)>,
    attempts: Vec<(String, u64, u64, Vec<u8>)>,
    results: Vec<(String, u64, Vec<u8>, Vec<u8>)>,
    references: (u64, u64, u64),
    history: Vec<ManagedReceipt>,
}

impl Saved {
    fn commit_state(&self) -> TestResult<CommitState> {
        self.fixture.commit_state(&self.store)
    }
}

impl Fixture {
    fn commit_state(&self, store: &AnalysisStore) -> TestResult<CommitState> {
        let (heads, attempts, results, references) = store.read_snapshot(|reader| {
            let mut statement = reader.prepare(
                "SELECT call_id, state_revision, result_id FROM managed_calls ORDER BY call_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved call heads" })?;
            let heads = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved call heads" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved call heads" })?;
            let mut statement = reader.prepare(
                "SELECT attempt_id, generation, completed, contract FROM managed_attempts ORDER BY attempt_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved attempts" })?;
            let attempts = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved attempts" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved attempts" })?;
            let mut statement = reader.prepare(
                "SELECT result_id, commit_revision, body, request_meta FROM analysis_results ORDER BY result_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved result rows" })?;
            let results = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved result rows" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved result rows" })?;
            let references = reader.query_row(
                "SELECT (SELECT count(*) FROM managed_edges), (SELECT count(*) FROM evidence_refs), (SELECT count(*) FROM context_refs)",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).context(crate::AnalysisDatabaseSnafu { operation: "read saved reference counts" })?;
            Ok((heads, attempts, results, references))
        })?;
        Ok(CommitState {
            meta: store.meta()?,
            instance: self.current(store)?,
            heads,
            attempts,
            results,
            references,
            history: store.managed_history(
                &self.instance.grant.selection,
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?,
        })
    }
}
