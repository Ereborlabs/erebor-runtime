use araphor_analysis_sdk as sdk;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::analysis::{PackageActivationV1, PackageResultRefV1};
use crate::package::{PackageErrorCodeV1 as Code, PackageGrantV1};
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisSelectionV1, AnalysisSourceSnapshotV1,
    AnalysisWitnessV1, Result,
};
use araphor_query::datafusion::execution::memory_pool::MemoryReservation;
use araphor_query::sources::ArrowSnapshot;
use prost::Message as _;

mod read;
mod table;

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
    pub(super) _metadata: Option<MemoryReservation>,
}

impl ModelInputs {
    pub(super) fn metadata_bytes(&self) -> usize {
        use std::mem::size_of;
        let mut bytes = self.inputs.capacity() * size_of::<sdk::Input>()
            + self.dependencies.capacity() * size_of::<PackageResultRefV1>()
            + self.source_revisions.capacity() * size_of::<(String, u64)>()
            + self.witnesses.capacity() * size_of::<AnalysisWitnessV1>()
            + self.contexts.capacity() * size_of::<AnalysisContextRefV1>();
        for input in &self.inputs {
            bytes = bytes.saturating_add(
                input.data.name.capacity()
                    + input.data.batches.capacity() * size_of::<sdk::RecordBatch>()
                    + input.revision.owner.capacity()
                    + input.revision.id.capacity()
                    + input
                        .revision
                        .window
                        .as_ref()
                        .map_or(0, |window| window.source.capacity())
                    + input.coverage.limits.capacity() * size_of::<String>()
                    + input
                        .coverage
                        .limits
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>(),
            );
            for batch in &input.data.batches {
                bytes = bytes.saturating_add(
                    batch.num_columns() * size_of::<sdk::arrow_array::ArrayRef>()
                        + batch
                            .columns()
                            .iter()
                            .map(|array| {
                                array
                                    .get_array_memory_size()
                                    .saturating_sub(array.get_buffer_memory_size())
                            })
                            .sum::<usize>()
                        + batch
                            .schema_ref()
                            .fields()
                            .iter()
                            .map(|field| field.size())
                            .sum::<usize>(),
                );
            }
        }
        bytes = bytes.saturating_add(
            self.dependencies
                .iter()
                .map(|reference| reference.result_id.capacity())
                .sum::<usize>()
                + self
                    .source_revisions
                    .iter()
                    .map(|(name, _)| name.capacity())
                    .sum::<usize>(),
        );
        for witness in &self.witnesses {
            bytes = bytes.saturating_add(match &witness.identity {
                crate::AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                crate::AnalysisStreamIdentityV1::Diagnostic(identity) => {
                    identity.node_id.capacity()
                }
            });
        }
        for reference in &self.contexts {
            bytes = bytes.saturating_add(
                reference.key.owner_id.capacity()
                    + reference.key.entity_key.capacity()
                    + reference.key.lifetime_key.capacity(),
            );
        }
        bytes
    }

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

    pub(super) fn check(&self, limits: sdk::Limits) -> Result<()> {
        let (mut rows, mut bytes, mut count) = (0u64, 0u64, 0u64);
        for input in &self.inputs {
            for batch in &input.data.batches {
                rows = rows.saturating_add(batch.num_rows() as u64);
                bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
                count += 1;
            }
        }
        if rows > limits.max_rows
            || bytes > limits.max_bytes.min(64 * 1024 * 1024)
            || count > u64::from(limits.max_batches)
            || self.witnesses.len() > 8192
            || self.contexts.len() > 256
            || self.dependencies.len() > 64
        {
            return Err(Code::Limit.error("selected model inputs").into());
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

impl ModelInputs {
    pub(super) fn add_snapshot(
        &mut self,
        source: &ArrowSnapshot,
        store: &crate::AnalysisStore,
        builtin: bool,
        data: sdk::Dataset,
        inherited: &[sdk::Input],
    ) -> Result<sdk::Input> {
        let selection = source.selection.clone();
        let result_ids: Vec<_> = source
            .results
            .iter()
            .map(|row| row.result_id.clone())
            .collect();
        let results = store.package_result_refs(selection.tenant_id, &result_ids)?;
        if results.len() != source.results.len()
            || results
                .iter()
                .zip(&source.results)
                .any(|(actual, expected)| {
                    actual.result_id != expected.result_id
                        || (expected.commit_revision != 0
                            && actual.commit_revision != expected.commit_revision)
                })
        {
            return crate::ModelInvalidSnafu {
                field: "changed model source",
            }
            .fail();
        }
        let keys: Vec<_> = source
            .contexts
            .iter()
            .map(|reference| reference.key.clone())
            .collect();
        let mut contexts = store.package_contexts(selection.tenant_id, &keys)?;
        let (witnesses, evidence) = store.package_evidence(selection.tenant_id, &result_ids)?;
        let mut witnesses = witnesses;
        witnesses.extend(source.witnesses.iter().cloned());
        contexts.extend(evidence);
        contexts.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then(a.commit_revision.cmp(&b.commit_revision))
        });
        contexts.dedup();
        let sources = &source.page.extraction.sources;
        let mut coverage =
            ModelInputs::source_coverage(sources, &source.page.extraction.missing_contexts)?;
        if !inherited.is_empty() {
            coverage = ModelInputs::coverage(
                inherited
                    .iter()
                    .map(|source| &source.coverage)
                    .chain(builtin.then_some(&coverage)),
            );
        }
        let revision = ModelInputs::revision(
            &selection, &data, sources, &contexts, &results, &coverage, inherited,
        )?;
        self.source_revisions
            .extend(selection.source_revisions(source.page.extraction.meta.commit_revision));
        self.witnesses.extend(witnesses);
        self.contexts.extend(contexts);
        self.dependencies.extend(results);
        Ok(sdk::Input {
            data,
            revision,
            coverage,
        })
    }
}

impl ModelInputs {
    fn source_coverage(
        sources: &[AnalysisSourceSnapshotV1],
        missing: &[AnalysisContextKeyV1],
    ) -> Result<sdk::Coverage> {
        let mut gaps = false;
        for source in sources {
            gaps |= !source.expired.is_empty()
                || !source.recovery.is_empty()
                || !source.pending.is_empty();
            if let Some(bytes) = &source.coverage_report {
                let report = crate::CoverageReport::decode(bytes.as_slice()).map_err(|source| {
                    araphor_data::Error::EvidenceDecode {
                        source,
                        frame_bytes: bytes.len(),
                        location: snafu::location!(),
                    }
                })?;
                gaps |= report
                    .intervals
                    .iter()
                    .any(crate::CoverageInterval::has_gap);
            }
        }
        let mut limits = Vec::new();
        if gaps {
            limits.push("SOURCE_GAPS".into());
        }
        if sources.is_empty() {
            limits.push("NO_SOURCE_COVERAGE".into());
        }
        if !missing.is_empty() {
            limits.push("MISSING_CONTEXT".into());
        }
        if !gaps {
            limits.push("SOURCE_COVERAGE_UNQUALIFIED".into());
        }
        Ok(sdk::Coverage {
            state: if gaps {
                sdk::CoverageState::Gapped
            } else {
                sdk::CoverageState::Unknown
            },
            limits,
        })
    }

    fn revision(
        selection: &AnalysisSelectionV1,
        data: &sdk::Dataset,
        sources: &[AnalysisSourceSnapshotV1],
        contexts: &[AnalysisContextRefV1],
        results: &[crate::analysis::PackageResultRefV1],
        coverage: &sdk::Coverage,
        inherited: &[sdk::Input],
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
        .context(crate::ModelEncodingSnafu)?;
        if !inherited.is_empty() {
            let revisions: Vec<_> = inherited.iter().map(|source| &source.revision).collect();
            serde_json::to_writer(&mut hash, &revisions).context(crate::ModelEncodingSnafu)?;
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
            owner: "araphor-analysis.ModelRun".into(),
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
