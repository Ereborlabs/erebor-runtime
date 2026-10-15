use araphor_analysis_sdk as sdk;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::super::budget::QueryLease;
use crate::analysis::{PackageActivationV1, PackageResultRefV1};
use crate::package::{PackageErrorCodeV1 as Code, PackageGrantV1};
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisSelectionV1, AnalysisWitnessV1,
    QueryCoverage, QueryCoverageState, QueryOwner, QuerySql, Result,
};

mod read;
mod table;
use read::SourceRows;

pub(crate) struct ModelInputRequest<'a> {
    pub activation: &'a PackageActivationV1,
    pub model: &'a sdk::Model,
    pub grant: &'a PackageGrantV1,
    pub now: u64,
}

#[derive(Default)]
pub(crate) struct ModelInputs {
    pub inputs: Vec<sdk::Input>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    _leases: Vec<QueryLease>,
}

impl ModelInputs {
    pub(crate) fn coverage<'a>(values: impl Iterator<Item = &'a sdk::Coverage>) -> sdk::Coverage {
        let (mut state, mut limits) = (sdk::CoverageState::Complete, Vec::new());
        for coverage in values {
            if coverage.state == sdk::CoverageState::Unknown
                || (coverage.state == sdk::CoverageState::Gapped
                    && state == sdk::CoverageState::Complete)
            {
                state = coverage.state;
            }
            limits.extend(coverage.limits.iter().cloned());
        }
        limits.sort();
        limits.dedup();
        sdk::Coverage { state, limits }
    }

    pub(super) fn push(&mut self, source: ModelSource) {
        self.inputs.push(source.input);
        self.dependencies.extend(source.dependencies);
        self.source_revisions.extend(source.source_revisions);
        self.witnesses.extend(source.witnesses);
        self.contexts.extend(source.contexts);
        self._leases.push(source._lease);
    }

    pub(super) fn check<'a>(
        sources: impl Iterator<Item = &'a ModelSource>,
        limits: sdk::Limits,
    ) -> Result<()> {
        let (mut rows, mut bytes, mut count) = (0_u64, 0_u64, 0_u64);
        let (mut witnesses, mut contexts, mut dependencies) = (0, 0, 0);
        for source in sources {
            for batch in &source.input.data.batches {
                rows = rows.saturating_add(batch.num_rows() as u64);
                bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
                count += 1;
            }
            witnesses += source.witnesses.len();
            contexts += source.contexts.len();
            dependencies += source.dependencies.len();
        }
        if rows > limits.max_rows
            || bytes > limits.max_bytes.min(64 * 1024 * 1024)
            || count > u64::from(limits.max_batches)
            || witnesses > 8192
            || contexts > 256
            || dependencies > 64
        {
            return Err(Code::Limit.error("selected model inputs"));
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, now: u64) {
        for witness in &mut self.witnesses {
            if witness.expires_utc_ns == 0 {
                witness.expires_utc_ns = now.saturating_add(7 * 24 * 60 * 60 * 1_000_000_000);
            }
        }
        self.dependencies
            .sort_by(|a, b| a.result_id.cmp(&b.result_id));
        self.dependencies.dedup();
        self.source_revisions.sort();
        self.source_revisions.dedup_by(|a, b| a.0 == b.0);
        self.witnesses.sort_by(|a, b| {
            a.identity
                .cmp(&b.identity)
                .then(a.cursor.cmp(&b.cursor))
                .then(a.expires_utc_ns.cmp(&b.expires_utc_ns))
        });
        self.witnesses
            .dedup_by(|a, b| a.identity == b.identity && a.cursor == b.cursor);
        self.contexts.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then(a.commit_revision.cmp(&b.commit_revision))
        });
        self.contexts.dedup();
        if self
            .witnesses
            .iter()
            .any(|witness| witness.expires_utc_ns <= now)
        {
            for input in &mut self.inputs {
                input.coverage.state = sdk::CoverageState::Unknown;
                input
                    .coverage
                    .limits
                    .push("source evidence retention expired".into());
            }
            self.witnesses
                .retain(|witness| witness.expires_utc_ns > now);
        }
    }
}

pub(super) struct ModelSource {
    pub input: sdk::Input,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    pub(crate) dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub(super) _lease: QueryLease,
}

impl SourceRows {
    fn finish(
        mut self,
        owner: &QueryOwner,
        sql: &QuerySql,
        selection: AnalysisSelectionV1,
        data: sdk::Dataset,
        lease: QueryLease,
        inherited: &[&ModelSource],
    ) -> Result<ModelSource> {
        self.results.sort_by(|a, b| a.result_id.cmp(&b.result_id));
        let result_ids: Vec<_> = self
            .results
            .iter()
            .map(|row| row.result_id.clone())
            .collect();
        let results = owner
            .store
            .package_result_refs(selection.tenant_id, &result_ids)?;
        if results.len() != self.results.len()
            || results.iter().zip(&self.results).any(|(actual, expected)| {
                actual.result_id != expected.result_id
                    || (expected.commit_revision != 0
                        && actual.commit_revision != expected.commit_revision)
            })
        {
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
        let mut contexts = owner.store.package_contexts(selection.tenant_id, &keys)?;
        let (witnesses, evidence) = owner
            .store
            .package_evidence(selection.tenant_id, &result_ids)?;
        self.witnesses.extend(witnesses);
        contexts.extend(evidence);
        contexts.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then(a.commit_revision.cmp(&b.commit_revision))
        });
        contexts.dedup();
        let sources: Vec<_> = self
            .extraction
            .sources
            .into_iter()
            .map(QueryCoverage::from)
            .collect();
        let mut coverage = ModelSource::coverage(&sources, &self.extraction.missing_contexts);
        if !inherited.is_empty() {
            let builtin = crate::query::input::SCHEMAS
                .iter()
                .any(|schema| sql.dependencies().contains(schema.name));
            coverage = ModelInputs::coverage(
                inherited
                    .iter()
                    .map(|source| &source.input.coverage)
                    .chain(builtin.then_some(&coverage)),
            );
        }
        let revision = ModelSource::revision(
            &selection, &data, &sources, &contexts, &results, &coverage, inherited,
        )?;
        Ok(ModelSource {
            input: sdk::Input {
                data,
                revision,
                coverage,
            },
            source_revisions: QueryOwner::source_revisions(
                &selection,
                self.extraction.meta.commit_revision,
            ),
            witnesses: self.witnesses,
            contexts,
            dependencies: results,
            _lease: lease,
        })
    }
}

impl ModelSource {
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
        sources: &[QueryCoverage],
        contexts: &[AnalysisContextRefV1],
        results: &[crate::analysis::PackageResultRefV1],
        coverage: &sdk::Coverage,
        inherited: &[&ModelSource],
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
        if !inherited.is_empty() {
            let revisions: Vec<_> = inherited
                .iter()
                .map(|source| &source.input.revision)
                .collect();
            serde_json::to_writer(&mut hash, &revisions).context(crate::QueryEncodingSnafu)?;
        }
        {
            let mut writer =
                arrow_ipc::writer::StreamWriter::try_new(&mut hash, &data.batches[0].schema())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_expiry_merge() {
        let identity = crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
        .into();
        let mut inputs = ModelInputs {
            witnesses: vec![AnalysisWitnessV1 {
                identity,
                cursor: 1,
                expires_utc_ns: 0,
            }],
            ..Default::default()
        };
        let mut inherited = inputs.witnesses[0].clone();
        inherited.expires_utc_ns = 99;
        inputs.witnesses.push(inherited);
        inputs.inputs.push(sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: Vec::new(),
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        });
        inputs.finish(100);
        assert!(inputs.witnesses.is_empty());
        assert_eq!(inputs.inputs[0].coverage.state, sdk::CoverageState::Unknown);
        assert_eq!(
            inputs.inputs[0].coverage.limits,
            ["source evidence retention expired"]
        );
    }
}
