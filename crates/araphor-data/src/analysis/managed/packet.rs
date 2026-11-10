use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::{codec::ManagedCodec, model::*, source::SourceEvidence};
use crate::analysis::PackageResultRefV1;
use crate::{PackageErrorCodeV1 as Code, Result, ResultContext};

pub(in crate::analysis) struct Packet {
    pub(in crate::analysis) call: u64,
    pub(in crate::analysis) id: String,
    pub(in crate::analysis) record: Record,
    pub(in crate::analysis) checkpoint: Vec<u8>,
}

impl Packet {
    pub(in crate::analysis) fn prepare(
        attempt: &ManagedAttempt,
        call: u64,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        changes: Option<&ManagedChanges>,
        evidence: &SourceEvidence,
        descriptor: &sdk::Package,
    ) -> Result<Self> {
        let spec = &attempt.1.spec;
        let declaration = spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Invalid.error("managed returned call"))?;
        if evaluation.export != declaration.export
            || evaluation.context.id != attempt.0.request.id
            || evaluation.context.time_utc_ns != attempt.0.request.time_utc_ns as i64
            || evaluation.context.seed != attempt.0.request.seed
        {
            return Err(Code::Invalid.error("managed evaluation request"));
        }
        let checked = descriptor
            .check_evaluation(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let reset = checked
            .model()
            .change_inputs
            .as_ref()
            .is_some_and(|changes| changes.is_reset(evaluation).unwrap_or(false));
        let expected = attempt
            .3
            .get(&call)
            .map(|prior| {
                prior.state(
                    checked.model(),
                    &evaluation.inputs,
                    evaluation.parameters.as_ref(),
                    attempt.0.request.rebuild || reset,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let same = match (&expected.0, &evaluation.checkpoint) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.version == actual.version
                    && expected.datasets.len() == actual.datasets.len()
                    && expected
                        .datasets
                        .iter()
                        .zip(&actual.datasets)
                        .all(|(left, right)| {
                            left.name == right.name && left.batches == right.batches
                        })
            }
            _ => false,
        };
        if !same
            || expected.1.len() != evaluation.previous_outputs.len()
            || !expected
                .1
                .iter()
                .zip(&evaluation.previous_outputs)
                .all(|(left, right)| left.name == right.name && left.batches == right.batches)
        {
            return Err(Code::Conflict.error("managed captured checkpoint"));
        }
        let mut context = ResultContext::new(
            &attempt.0.request.id,
            attempt.0.request.time_utc_ns,
            &evaluation.inputs,
        );
        context.context = evaluation.context.clone();
        context.target = declaration.target.clone();
        context.artifact = declaration.artifact.clone();
        let dependencies = attempt.0.capture.dependencies.clone();
        let changes = RecordChanges::prepare(attempt, call, evaluation, changes, checked.model())?;
        let call_evidence = attempt
            .5
            .as_ref()
            .map(|frame| {
                frame.call_evidence(
                    &spec.manifest.input_calls(call)?,
                    &attempt.0.capture,
                    evidence,
                )
            })
            .transpose()?;
        let call_evidence = call_evidence.as_ref().unwrap_or(evidence);
        let record = Record {
            instance: spec.id.clone(),
            call,
            attempt: attempt.0.request.id.clone(),
            context,
            changes,
            dependencies,
            witnesses: call_evidence.witnesses.clone(),
            contexts: call_evidence.contexts.clone(),
            derived: Vec::new(),
            origins: Vec::new(),
            proofs: Vec::new(),
            graph_proof: None,
        };
        checked
            .validate_output(output)
            .context(crate::AnalysisContractSnafu)?;
        let checkpoint = output
            .checkpoint
            .as_ref()
            .map(|state| {
                sdk::wire::Checkpoint::encode(state, checked.model())
                    .context(crate::AnalysisContractSnafu)
            })
            .transpose()?;
        Ok(Self {
            call,
            id: String::new(),
            record,
            checkpoint: ManagedCodec::encode(&checkpoint).context(crate::ManagedEncodingSnafu)?,
        })
    }
}

impl ManagedReceipt {
    pub(in crate::analysis) fn bind(
        attempt: &ManagedAttempt,
        completed: bool,
        mut packets: Vec<Packet>,
        mut step: Step,
        revision: u64,
    ) -> (Vec<Packet>, Step, ManagedReceipt) {
        let ids = packets
            .iter()
            .map(|packet| {
                (
                    packet.call,
                    PackageResultRefV1 {
                        result_id: format!("managed-{revision}-call-{}", packet.call),
                        commit_revision: revision,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for packet in &mut packets {
            packet.id = ids[&packet.call].result_id.clone();
            packet.record.dependencies.extend(
                attempt.1.spec.manifest.calls[&packet.call]
                    .dependencies
                    .iter()
                    .filter_map(|call| ids.get(call).cloned()),
            );
            packet
                .record
                .dependencies
                .sort_by(|left, right| left.result_id.cmp(&right.result_id));
            packet.record.dependencies.dedup();
        }
        step.dependencies.extend(ids.values().cloned());
        step.dependencies
            .sort_by(|left, right| left.result_id.cmp(&right.result_id));
        step.dependencies.dedup();
        let receipt = ManagedReceipt {
            frontier: attempt.request().frontier.as_ref().map(|frontier| {
                let mut frontier = frontier.clone();
                frontier.pending = !completed;
                frontier
            }),
            instance: attempt.1.spec.id.clone(),
            attempt: attempt.request().id.clone(),
            commit_revision: revision,
            selected: PackageResultRefV1 {
                result_id: format!("managed-{revision}-selected"),
                commit_revision: revision,
            },
            results: ids,
            graph: None,
        };
        (packets, step, receipt)
    }
}

impl Packet {
    pub(in crate::analysis) fn charge<'a>(
        attempt: &ManagedAttempt,
        returns: impl ExactSizeIterator<Item = (&'a sdk::Evaluation, &'a sdk::Output)>,
        evidence: &SourceEvidence,
        memory: &mut super::PreparedMemory<'_>,
    ) -> Result<()> {
        let spec = &attempt.1.spec;
        let mut bytes = spec
            .allocation_bytes()
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        let shared =
            SourceEvidence::metadata_bytes(evidence.witnesses.iter(), evidence.contexts.iter())?;
        bytes = returns
            .len()
            .checked_add(4)
            .and_then(|count| shared.checked_mul(count))
            .and_then(|shared| bytes.checked_add(shared))
            .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        for (evaluation, output) in returns {
            let mut extra = evaluation.context.id.capacity();
            for value in &evaluation.inputs {
                extra = extra
                    .checked_add(value.revision.owner.capacity())
                    .and_then(|bytes| bytes.checked_add(value.revision.id.capacity()))
                    .and_then(|bytes| {
                        bytes.checked_add(
                            value
                                .revision
                                .window
                                .as_ref()
                                .map_or(0, |window| window.source.capacity()),
                        )
                    })
                    .and_then(|bytes| bytes.checked_add(value.coverage.metadata_bytes()))
                    .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
            }
            if let Some(state) = &output.checkpoint {
                for data in &state.datasets {
                    extra = extra
                        .checked_add(
                            data.batches
                                .iter()
                                .try_fold(data.name.capacity(), |bytes, batch| {
                                    bytes.checked_add(batch.get_array_memory_size())
                                })
                                .unwrap_or(usize::MAX),
                        )
                        .ok_or_else(|| Code::Limit.error("managed checkpoint memory"))?;
                }
            }
            bytes = bytes
                .checked_add(
                    extra
                        .checked_mul(8)
                        .ok_or_else(|| Code::Limit.error("managed packet memory"))?,
                )
                .ok_or_else(|| Code::Limit.error("managed packet memory"))?;
        }
        memory.charge(bytes)
    }
}
