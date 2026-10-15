use araphor_analysis_sdk as sdk;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::super::budget::QueryLease;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisReadControl, AnalysisSelectionV1,
    AnalysisStoreMetaV1, AnalysisWitnessV1, QueryCoverage, QueryCoverageState, QueryOwner,
    QueryPlan, QuerySql, Result,
};

mod read;
use read::SourceRows;

pub struct SqlModelInputRequestV1<'a> {
    pub selection: AnalysisSelectionV1,
    pub sql: QuerySql,
    pub port: &'a sdk::Port,
    pub limits: sdk::Limits,
    pub now_ns: u64,
}

pub struct SqlModelInputV1 {
    pub input: sdk::Input,
    pub meta: AnalysisStoreMetaV1,
    pub sources: Vec<QueryCoverage>,
    pub missing_contexts: Vec<AnalysisContextKeyV1>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    pub result_ids: Vec<String>,
    pub source_revisions: Vec<(String, u64)>,
    _lease: QueryLease,
}

impl QueryOwner {
    pub fn model_input(
        &self,
        request: SqlModelInputRequestV1<'_>,
        control: &AnalysisReadControl,
    ) -> Result<SqlModelInputV1> {
        self.model_input_with(request, control, None)
    }

    pub(super) fn model_input_shared(
        &self,
        request: SqlModelInputRequestV1<'_>,
        control: &AnalysisReadControl,
        connection: &duckdb::Connection,
        sources: &mut crate::query::input::ScopedSources,
    ) -> Result<SqlModelInputV1> {
        self.model_input_with(request, control, Some((connection, sources)))
    }

    fn model_input_with(
        &self,
        request: SqlModelInputRequestV1<'_>,
        control: &AnalysisReadControl,
        shared: Option<(&duckdb::Connection, &mut crate::query::input::ScopedSources)>,
    ) -> Result<SqlModelInputV1> {
        let plan = QueryPlan::model(request.selection.clone(), request.sql.clone())?;
        let selection = plan.dependencies(request.now_ns)?;
        let lease = if shared.is_none() {
            Some(self.budget.model(selection.tenant_id, 0)?)
        } else {
            None
        };
        let bounds = crate::analysis::AnalysisExtractLimits {
            scan_bytes: self.limits.scan_bytes,
            input_bytes: self
                .limits
                .input_bytes
                .min(request.limits.max_bytes as usize),
            ..Default::default()
        };
        let mut rows =
            SourceRows::extract(self, &plan, &selection, request.now_ns, bounds, control)?;
        let (data, bytes) = match shared {
            Some((connection, sources)) => rows.evaluate_shared(
                self,
                &request,
                &plan,
                bounds.input_bytes,
                control,
                (connection, sources),
            )?,
            None => rows.evaluate(self, &request, &plan, bounds.input_bytes, control)?,
        };
        let lease = match lease {
            Some(lease) => lease.input(bytes)?,
            None => self.budget.retained_input(bytes)?,
        };
        rows.finish(self, request.port, selection, data, lease)
    }
}

impl SourceRows {
    fn finish(
        mut self,
        owner: &QueryOwner,
        port: &sdk::Port,
        selection: AnalysisSelectionV1,
        data: sdk::Dataset,
        lease: QueryLease,
    ) -> Result<SqlModelInputV1> {
        self.results.sort_by(|a, b| a.result_id.cmp(&b.result_id));
        let result_ids: Vec<_> = self
            .results
            .iter()
            .map(|row| row.result_id.clone())
            .collect();
        let results = owner
            .store
            .package_result_refs(selection.tenant_id, &result_ids)?;
        if results.iter().zip(&self.results).any(|(actual, expected)| {
            actual.result_id != expected.result_id
                || (expected.commit_revision != 0
                    && actual.commit_revision != expected.commit_revision)
        }) {
            return crate::QueryInvalidSnafu {
                field: "changed model source",
            }
            .fail();
        }
        let keys: Vec<_> = self
            .contexts
            .iter()
            .map(|reference| reference.key.clone())
            .collect();
        let contexts = owner.store.package_contexts(selection.tenant_id, &keys)?;
        let sources: Vec<_> = self
            .extraction
            .sources
            .into_iter()
            .map(QueryCoverage::from)
            .collect();
        let coverage = SqlModelInputV1::coverage(&sources, &self.extraction.missing_contexts);
        let revision = SqlModelInputV1::revision(
            &selection,
            &data,
            &port.schema,
            &sources,
            &contexts,
            &results,
            &coverage,
        )?;
        Ok(SqlModelInputV1 {
            input: sdk::Input {
                data,
                revision,
                coverage,
            },
            source_revisions: QueryOwner::source_revisions(
                &selection,
                self.extraction.meta.commit_revision,
            ),
            meta: self.extraction.meta,
            sources,
            missing_contexts: self.extraction.missing_contexts,
            witnesses: self.witnesses,
            contexts,
            result_ids,
            _lease: lease,
        })
    }
}

impl SqlModelInputV1 {
    fn coverage(sources: &[QueryCoverage], missing: &[AnalysisContextKeyV1]) -> sdk::Coverage {
        let mut limits = Vec::new();
        let state = if sources
            .iter()
            .any(|source| source.state == QueryCoverageState::Gapped)
        {
            limits.push("SOURCE_GAPS".into());
            sdk::CoverageState::Gapped
        } else {
            sdk::CoverageState::Unknown
        };
        if sources.is_empty() {
            limits.push("NO_SOURCE_COVERAGE".into());
        }
        if !missing.is_empty() {
            limits.push("MISSING_CONTEXT".into());
        }
        if state == sdk::CoverageState::Unknown {
            limits.push("SOURCE_COVERAGE_UNQUALIFIED".into());
        }
        sdk::Coverage { state, limits }
    }

    fn revision(
        selection: &AnalysisSelectionV1,
        data: &sdk::Dataset,
        schema: &sdk::Schema,
        sources: &[QueryCoverage],
        contexts: &[AnalysisContextRefV1],
        results: &[crate::analysis::PackageResultRefV1],
        coverage: &sdk::Coverage,
    ) -> Result<sdk::Revision> {
        let receipts: Vec<_> = sources
            .iter()
            .map(|source| {
                (
                    &source.receipt.identity,
                    source.receipt.cpu_id,
                    source.receipt.contiguous_cursor,
                    source.receipt.coverage_revision,
                    source.receipt.retained_floor,
                    &source.expired,
                    &source.recovery,
                    &source.pending,
                )
            })
            .collect();
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-SQL-INPUT-V1\0");
        serde_json::to_writer(
            &mut hash,
            &(selection, receipts, contexts, results, coverage),
        )
        .context(crate::QueryEncodingSnafu)?;
        {
            let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut hash, schema)
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            for batch in &data.batches {
                writer
                    .write(batch)
                    .map_err(sdk::Error::from)
                    .context(crate::AnalysisContractSnafu)?;
            }
            writer
                .finish()
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
        }
        Ok(sdk::Revision {
            owner: "araphor-data.QueryOwner".into(),
            id: format!("{:x}", hash.finalize()),
            window: None,
        })
    }
}
