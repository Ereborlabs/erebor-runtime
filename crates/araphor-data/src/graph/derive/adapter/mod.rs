use araphor_analysis_builtins::{graph as algorithm, Rows};
use araphor_analysis_sdk as sdk;

use super::*;
use crate::AnalysisContractSnafu;

mod authority;
mod credential;
mod edges;
mod facts;
mod output;
#[cfg(test)]
mod tests;

impl GraphDerivation<'_> {
    pub(super) fn evaluation(&self) -> Result<sdk::Evaluation> {
        let package = algorithm::Detector::Process.descriptor();
        let model = &package.exports[0];
        let records = self
            .input
            .records
            .iter()
            .map(|record| self.observation(record))
            .collect::<Result<Vec<_>>>()?;
        let facts = self
            .facts
            .iter()
            .enumerate()
            .map(|(index, fact)| self.algorithm_fact(index, fact))
            .collect::<Result<Vec<_>>>()?;
        let manifest = algorithm::Manifest {
            window_ns: GRAPH_WINDOW_NS,
            window_records: GRAPH_WINDOW_RECORDS,
        };
        let times = self
            .input
            .records
            .iter()
            .map(|record| record.decode().map(|wire| wire.ingested_utc_ns))
            .collect::<Result<Vec<_>>>()?;
        let revision = sdk::Revision {
            owner: GRAPH_PROCESSOR.into(),
            id: crate::digest::InputRevision::of(&(
                &self.input.source,
                &self.input.records,
                &self.input.coverage,
                &self.input.coverage_keys,
                &self.input.facts,
                &self.input.missing_ranges,
            ))
            .context(GraphEncodingSnafu)?,
            window: Some(sdk::SourceWindow {
                source: serde_json::to_vec(&self.input.source).context(GraphEncodingSnafu)?,
                start_utc_ns: times.iter().copied().min().unwrap_or(0),
                end_utc_ns: times.iter().copied().max().unwrap_or(0),
            }),
        };
        let state = if !self.input.missing_ranges.is_empty()
            || self
                .input
                .coverage
                .iter()
                .any(|range| range.state == DiscoveryCoverageStateV1::Gapped)
        {
            sdk::CoverageState::Gapped
        } else if records.iter().any(|record| !record.complete) {
            sdk::CoverageState::Unknown
        } else {
            sdk::CoverageState::Complete
        };
        let coverage = sdk::Coverage {
            state,
            limits: if state == sdk::CoverageState::Complete {
                Vec::new()
            } else {
                vec!["SOURCE_COVERAGE_INSUFFICIENT".into()]
            },
        };
        let datasets = vec![
            Rows::encode(&model.inputs[0], &records, model.limits),
            Rows::encode(&model.inputs[1], &facts, model.limits),
            Rows::encode(&model.inputs[2], &[manifest], model.limits),
        ];
        let inputs = datasets
            .into_iter()
            .map(|data| {
                data.map(|data| sdk::Input {
                    data,
                    revision: revision.clone(),
                    coverage: coverage.clone(),
                })
            })
            .collect::<sdk::Result<Vec<_>>>()
            .context(AnalysisContractSnafu)?;
        let evaluation = sdk::Evaluation {
            export: "detect".into(),
            inputs,
            parameters: None,
            context: sdk::EvaluationContext {
                id: revision.id,
                time_utc_ns: times.into_iter().max().unwrap_or(0),
                seed: None,
                limits: model.limits,
            },
            checkpoint: None,
        };
        Ok(evaluation)
    }

    pub(super) fn evaluate(
        &mut self,
        detector: algorithm::Detector,
        evaluation: &sdk::Evaluation,
    ) -> Result<()> {
        let output = detector
            .evaluate(evaluation)
            .context(AnalysisContractSnafu)?;
        self.apply_output(detector, evaluation, &output)
    }

    fn observation(&self, record: &DiscoveryRecordV1) -> Result<algorithm::Observation> {
        let wire = record.decode()?;
        let effect = self.effect(record, &wire);
        Ok(algorithm::Observation {
            lifetime: serde_json::to_vec(&(
                &record.id.stream.node_id,
                record.id.stream.node_boot_id,
                record.id.stream.label_epoch,
            ))
            .context(GraphEncodingSnafu)?,
            task: wire.task_cookie,
            process: effect.process_instance_id,
            execution: wire.execution_set_id.to_vec(),
            object: wire.exact_object_id.to_vec(),
            role: effect.role_id,
            state: effect.state_id,
            exact_identity: wire.task_cookie > 0
                && effect.process_instance_id.is_some()
                && effect.entry_instance_id.is_some()
                && effect.binding_id.is_some()
                && effect.role_id.is_some()
                && effect.state_id.is_some()
                && effect.entry_rule_id.is_some(),
            policy_conflict: self.policy_conflict(record),
            complete: effect.proof_quality.temporal_coverage == TemporalCoverageV1::Complete,
            network: wire.effect_family == KernelEffectFamilyV1::Network as u32,
            denied: wire.decision == EffectPhysicalResultV1::DeniedBeforeEffect as u32,
            admitted: wire.decision == EffectPhysicalResultV1::UnknownAfterPreEffect as u32,
            operation: match wire.operation {
                value if value == KernelEffectOperationV1::Read as u32 => {
                    algorithm::Operation::Read
                }
                value if value == KernelEffectOperationV1::OpenRead as u32 => {
                    algorithm::Operation::OpenRead
                }
                value if value == KernelEffectOperationV1::MmapRead as u32 => {
                    algorithm::Operation::MmapRead
                }
                _ => algorithm::Operation::Other,
            },
            physical: match effect.physical_result {
                GraphPhysicalResultV1::Prevented => algorithm::Physical::Prevented,
                GraphPhysicalResultV1::PacketDropped => algorithm::Physical::PacketDropped,
                GraphPhysicalResultV1::TerminationQueued => algorithm::Physical::TerminationQueued,
                GraphPhysicalResultV1::Unknown => algorithm::Physical::Unknown,
            },
            boottime: wire.observed_boottime_ns,
        })
    }
}
