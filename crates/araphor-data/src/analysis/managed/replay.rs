use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::model::{Record, RecordInput};
use super::{ManagedInstance, ManagedPrior, RetainedCall};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

pub(super) struct SavedEvaluation {
    call: u64,
    generation: u64,
    descriptor: sdk::Package,
    packet: sdk::wire::Evaluation,
    inputs: Vec<RecordInput>,
    prior: Option<(
        PackageResultRefV1,
        Record,
        sdk::wire::Output,
        Option<Box<SavedEvaluation>>,
    )>,
    native_prior: Option<crate::analysis::graph_rows::GraphCallState>,
    native_graph: bool,
    rebuild: bool,
}

impl AnalysisStore {
    pub(in crate::analysis) fn managed_producer_from(
        reader: &Connection,
        selection: &crate::AnalysisSelectionV1,
        reference: &PackageResultRefV1,
    ) -> Result<(super::ManagedSpec, u64, u64)> {
        let (record, _, revision) =
            Self::managed_header_from(reader, selection.tenant_id, &reference.result_id)?;
        if revision != reference.commit_revision {
            return Err(Code::Conflict.error("managed producer revision"));
        }
        let (_, attempt) = Self::validate_managed_header(
            reader,
            selection.tenant_id,
            &reference.result_id,
            &record,
            revision,
        )?;
        attempt.capture.grant.permitted_by(selection)?;
        let generation = attempt.capture.generation;
        let spec =
            Self::managed_version_from(reader, selection.tenant_id, &record.instance, generation)?;
        Ok((spec, generation, record.call))
    }

    pub fn managed_evaluation_bytes(
        &self,
        instance: &ManagedInstance,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<(u64, u64, usize)> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let saved = Self::saved_evaluation_from(reader, instance, id, control)?;
            Ok((saved.call, saved.generation, saved.decoding_bytes(control)?))
        })
    }

    pub fn managed_evaluation(
        &self,
        instance: &ManagedInstance,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Evaluation> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::saved_evaluation_from(reader, instance, id, control)?.decode(control)
        })
    }

    pub(super) fn saved_evaluation_from(
        reader: &Connection,
        instance: &ManagedInstance,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<SavedEvaluation> {
        Self::saved_call_from(reader, instance, id, control, true)
    }

    pub(super) fn saved_inputs_from(
        reader: &Connection,
        instance: &ManagedInstance,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<SavedEvaluation> {
        Self::saved_call_from(reader, instance, id, control, false)
    }

    fn saved_call_from(
        reader: &Connection,
        instance: &ManagedInstance,
        id: &str,
        control: &AnalysisReadControl,
        state: bool,
    ) -> Result<SavedEvaluation> {
        if Self::managed_version_from(
            reader,
            instance.spec.tenant,
            &instance.spec.id,
            instance.generation,
        )? != instance.spec
        {
            return Err(Code::Denied.error("managed evaluation scope"));
        }
        let (mut record, _, revision) =
            Self::managed_header_from(reader, instance.spec.tenant, id)?;
        if record.instance != instance.spec.id {
            return Err(Code::Denied.error("managed evaluation scope"));
        }
        let (descriptor, attempt) =
            Self::validate_managed_header(reader, instance.spec.tenant, id, &record, revision)?;
        attempt
            .capture
            .grant
            .permitted_by(&instance.grant.selection)?;
        if record
            .parameters
            .as_ref()
            .is_some_and(|data| data.name != "parameters")
        {
            return Err(Code::Invalid.error("managed evaluation parameters"));
        }
        if attempt.request.rebuild != attempt.capture.rebuild {
            return Err(Code::Invalid.error("managed evaluation rebuild"));
        }
        let mut inputs = record
            .inputs
            .iter()
            .enumerate()
            .map(|(slot, input)| sdk::wire::Input {
                data: sdk::wire::Dataset {
                    name: input.name.clone(),
                    arrow_ipc: Vec::new(),
                },
                revision: record.context.inputs[slot].clone(),
                coverage: record.context.input_coverage[slot].clone(),
            })
            .collect::<Vec<_>>();
        let mut statement = reader.prepare("SELECT role, slot, ipc FROM managed_arrow WHERE result_id = ? AND role IN ('input', 'parameters') ORDER BY role, slot")
            .context(AnalysisDatabaseSnafu { operation: "prepare saved evaluation payload" })?;
        let rows = statement
            .query_map(params![id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read saved evaluation payload",
            })?;
        let mut count = 0;
        for row in rows {
            control.check()?;
            let (role, slot, bytes) = row.context(AnalysisDatabaseSnafu {
                operation: "decode saved evaluation payload",
            })?;
            let target = match role.as_str() {
                "input" => inputs.get_mut(slot).map(|input| &mut input.data.arrow_ipc),
                "parameters" if slot == 0 => {
                    record.parameters.as_mut().map(|data| &mut data.arrow_ipc)
                }
                _ => None,
            }
            .ok_or_else(|| Code::Invalid.error("managed evaluation role"))?;
            if !target.is_empty() || bytes.is_empty() {
                return Err(Code::Invalid.error("managed evaluation payload"));
            }
            *target = bytes;
            count += 1;
        }
        if count != inputs.len() + usize::from(record.parameters.is_some()) {
            return Err(Code::Missing.error("managed evaluation payload"));
        }
        let continuation = !attempt.request.rebuild
            && descriptor
                .exports
                .iter()
                .find(|model| model.name == record.declaration.export)
                .and_then(|model| model.checkpoint.as_ref())
                .is_some_and(|spec| spec.resume_input_changes);
        let prior_ref = attempt
            .capture
            .prior
            .get(&record.call)
            .ok_or_else(|| Code::Invalid.error("managed evaluation prior call"))?;
        if prior_ref.as_ref().is_some_and(|reference| {
            reference.commit_revision == 0 || reference.commit_revision > attempt.capture.progress
        }) {
            return Err(Code::Invalid.error("managed evaluation prior"));
        }
        let prior = if state {
            prior_ref
                .as_ref()
                .cloned()
                .map(|reference| {
                    control.check()?;
                    let (prior, output, revision) = if continuation {
                        Self::managed_record_from(
                            reader,
                            instance.spec.tenant,
                            &reference.result_id,
                        )?
                    } else {
                        Self::managed_state_from(
                            reader,
                            instance.spec.tenant,
                            &reference.result_id,
                        )?
                    };
                    Self::validate_managed_header(
                        reader,
                        instance.spec.tenant,
                        &reference.result_id,
                        &prior,
                        revision,
                    )?;
                    if revision != reference.commit_revision
                        || revision > attempt.capture.progress
                        || prior.instance != instance.spec.id
                        || prior.call != record.call
                        || prior.declaration != record.declaration
                    {
                        return Err(Code::Invalid.error("managed evaluation prior"));
                    }
                    let saved = continuation
                        .then(|| {
                            Self::saved_inputs_from(reader, instance, &reference.result_id, control)
                                .map(Box::new)
                        })
                        .transpose()?;
                    Ok((reference, prior, output, saved))
                })
                .transpose()?
        } else {
            None
        };
        let evaluated_spec = Self::managed_version_from(
            reader,
            instance.spec.tenant,
            &instance.spec.id,
            attempt.capture.generation,
        )?;
        let prior_spec = prior
            .as_ref()
            .filter(|_| continuation)
            .map(|(_, _, _, saved)| {
                let generation = saved
                    .as_ref()
                    .ok_or_else(|| Code::Missing.error("Graph call saved input"))?
                    .generation;
                Self::managed_version_from(
                    reader,
                    instance.spec.tenant,
                    &instance.spec.id,
                    generation,
                )
            })
            .transpose()?;
        let native_graph = continuation
            && prior.is_some()
            && matches!(
                &evaluated_spec.destination,
                super::ManagedDestination::Graph { calls, .. } if calls.contains(&record.call)
            )
            && descriptor
                .exports
                .iter()
                .find(|model| model.name == record.declaration.export)
                .is_some_and(araphor_analysis_builtins::graph::Detector::supports);
        let native_prior = if native_graph {
            if !prior_spec.as_ref().is_some_and(|spec| {
                matches!(&spec.destination,
                    super::ManagedDestination::Graph { calls, .. } if calls.contains(&record.call))
            }) {
                return Err(Code::Invalid.error("Graph call prior destination"));
            }
            let (reference, _, _, saved) = prior
                .as_ref()
                .ok_or_else(|| Code::Missing.error("Graph call native prior"))?;
            let evaluation = saved
                .as_ref()
                .ok_or_else(|| Code::Missing.error("Graph call saved input"))?
                .inputs_only(control)?;
            Some(crate::analysis::graph_rows::GraphCallRows::load(
                reader,
                prior_spec
                    .as_ref()
                    .ok_or_else(|| Code::Missing.error("Graph call saved spec"))?,
                record.call,
                &reference.result_id,
                reference.commit_revision,
                &evaluation,
                control,
            )?)
        } else {
            None
        };
        Ok(SavedEvaluation {
            call: record.call,
            generation: attempt.capture.generation,
            descriptor,
            packet: sdk::wire::Evaluation {
                export_name: record.declaration.export,
                inputs,
                parameters: record.parameters.map(|data| data.arrow_ipc),
                context: record.context.context,
                checkpoint: None,
                previous_outputs: Vec::new(),
            },
            inputs: record.inputs,
            prior,
            native_prior,
            native_graph,
            rebuild: attempt.request.rebuild,
        })
    }
}

impl AnalysisStore {
    pub(super) fn managed_state_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<(Record, sdk::wire::Output, u64)> {
        let (mut record, mut packet, revision) = Self::managed_header_from(reader, tenant, id)?;
        let mut statement = reader.prepare("SELECT role, slot, ipc FROM managed_arrow WHERE result_id = ? AND role IN ('parameters', 'checkpoint') ORDER BY role, slot")
            .context(AnalysisDatabaseSnafu { operation: "prepare captured prior payload" })?;
        let rows = statement
            .query_map(params![id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read captured prior payload",
            })?;
        let mut count = 0;
        for row in rows {
            let (role, slot, ipc) = row.context(AnalysisDatabaseSnafu {
                operation: "decode captured prior payload",
            })?;
            let target = if role == "parameters" && slot == 0 {
                record.parameters.as_mut().map(|data| &mut data.arrow_ipc)
            } else if role == "checkpoint" {
                packet
                    .checkpoint
                    .as_mut()
                    .and_then(|checkpoint| checkpoint.datasets.get_mut(slot))
                    .map(|data| &mut data.arrow_ipc)
            } else {
                None
            }
            .ok_or_else(|| Code::Invalid.error("managed prior role"))?;
            if !target.is_empty() || ipc.is_empty() {
                return Err(Code::Invalid.error("managed prior payload"));
            }
            *target = ipc;
            count += 1;
        }
        if count
            != usize::from(record.parameters.is_some())
                + packet
                    .checkpoint
                    .as_ref()
                    .map_or(0, |state| state.datasets.len())
        {
            return Err(Code::Missing.error("managed prior payload"));
        }
        Ok((record, packet, revision))
    }
}

impl SavedEvaluation {
    fn inputs_only(&self, control: &AnalysisReadControl) -> Result<sdk::Evaluation> {
        let mut evaluation = self
            .packet
            .decode(&self.descriptor)
            .context(crate::AnalysisContractSnafu)?;
        for ((shape, input), packet) in self
            .inputs
            .iter()
            .zip(&mut evaluation.inputs)
            .zip(&self.packet.inputs)
        {
            control.check()?;
            if shape.batches == 0 {
                if packet
                    .data
                    .batch_count()
                    .context(crate::AnalysisContractSnafu)?
                    != 0
                {
                    return Err(Code::Invalid.error("saved evaluation input shape"));
                }
                input.data.batches.clear();
            }
            if input.data.name != shape.name
                || input.data.rows() != shape.rows
                || input.data.batches.len() != shape.batches
            {
                return Err(Code::Invalid.error("saved evaluation input shape"));
            }
        }
        Ok(evaluation)
    }

    pub(super) fn decoding_bytes(&self, control: &AnalysisReadControl) -> Result<usize> {
        let mut bytes = self
            .descriptor
            .allocated_bytes()
            .checked_add(
                self.packet
                    .allocated_bytes()
                    .checked_mul(2)
                    .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Self>() + std::mem::size_of::<sdk::Evaluation>(),
                )
            })
            .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
        for input in &self.packet.inputs {
            control.check()?;
            bytes = bytes
                .checked_add(
                    sdk::wire::Dataset::decoding_bytes(&input.data.arrow_ipc)
                        .context(crate::AnalysisContractSnafu)?,
                )
                .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
        }
        if let Some(parameters) = &self.packet.parameters {
            bytes = bytes
                .checked_add(
                    sdk::wire::Dataset::decoding_bytes(parameters)
                        .context(crate::AnalysisContractSnafu)?,
                )
                .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
        }
        if let Some((_, record, output, saved)) = &self.prior {
            let metadata = serde_json::to_vec(record)
                .context(crate::PackageEncodingSnafu)?
                .len();
            bytes = bytes
                .checked_add(
                    metadata
                        .checked_mul(2)
                        .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?,
                )
                .and_then(|bytes| bytes.checked_add(output.allocated_bytes()))
                .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
            if let Some(parameters) = &record.parameters {
                let decoded = sdk::wire::Dataset::decoding_bytes(&parameters.arrow_ipc)
                    .context(crate::AnalysisContractSnafu)?;
                bytes = bytes
                    .checked_add(parameters.allocated_bytes())
                    .and_then(|bytes| bytes.checked_add(decoded))
                    .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
            }
            for data in output.checkpoint.iter().flat_map(|state| &state.datasets) {
                control.check()?;
                bytes = bytes
                    .checked_add(
                        sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc)
                            .context(crate::AnalysisContractSnafu)?,
                    )
                    .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
            }
            if let Some(saved) = saved {
                bytes = bytes
                    .checked_add(saved.decoding_bytes(control)?)
                    .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
                for data in &output.datasets {
                    control.check()?;
                    bytes = bytes
                        .checked_add(
                            sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc)
                                .context(crate::AnalysisContractSnafu)?,
                        )
                        .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
                }
                for reason in &output.reasons {
                    control.check()?;
                    bytes = bytes
                        .checked_add(
                            sdk::wire::Dataset::decoding_bytes(&reason.details)
                                .context(crate::AnalysisContractSnafu)?,
                        )
                        .ok_or_else(|| Code::Limit.error("saved evaluation memory"))?;
                }
            }
        }
        if let Some(native) = &self.native_prior {
            bytes = bytes.saturating_add(native.allocated_bytes());
        }
        Ok(bytes)
    }

    pub(super) fn decode(self, control: &AnalysisReadControl) -> Result<sdk::Evaluation> {
        control.check()?;
        let model = self
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == self.packet.export_name)
            .ok_or_else(|| Code::Missing.error("saved evaluation model"))?;
        let mut evaluation = self.inputs_only(control)?;
        if let Some((reference, record, packet, saved)) = self.prior {
            if record.parameters.is_some() == model.parameters.fields().is_empty() {
                return Err(Code::Invalid.error("managed evaluation prior parameters"));
            }
            let parameters = record
                .parameters
                .as_ref()
                .map(|data| {
                    if data.name != "parameters" {
                        return Err(Code::Invalid.error("managed evaluation prior parameters"));
                    }
                    data.decode(&model.parameters)
                        .context(crate::AnalysisContractSnafu)
                })
                .transpose()?;
            let retained = saved
                .map(|saved| -> Result<_> {
                    let evaluation = saved.decode(control)?;
                    let output =
                        AnalysisStore::decode_managed_record(&self.descriptor, &record, &packet)?;
                    Ok(std::sync::Arc::new(RetainedCall { evaluation, output }))
                })
                .transpose()?;
            let checkpoint = if let Some(retained) = &retained {
                retained.output.checkpoint.clone()
            } else {
                packet
                    .checkpoint
                    .as_ref()
                    .map(|state| {
                        state
                            .decode_model(model)
                            .context(crate::AnalysisContractSnafu)
                    })
                    .transpose()?
            };
            let prior = ManagedPrior {
                revision: reference.commit_revision,
                result: reference.result_id,
                context: record.context,
                parameters,
                checkpoint,
                retained,
                reusable: false,
                native_graph: self.native_graph,
                native: self.native_prior,
            };
            (evaluation.checkpoint, evaluation.previous_outputs) = prior.state(
                model,
                &evaluation.inputs,
                evaluation.parameters.as_ref(),
                self.rebuild,
            )?;
        }
        self.descriptor
            .check_evaluation(&evaluation)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        Ok(evaluation)
    }
}
