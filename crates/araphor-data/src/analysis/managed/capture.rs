use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::{AnalysisExtractionV1, AnalysisSelectionV1, AnalysisStore, PackageResultRefV1};
use super::model::*;
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub(in crate::analysis) fn capture_managed(
        &self,
        reader: &Connection,
        request: &ManagedRead,
        now: u64,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<ManagedCapture> {
        if request.follow
            && matches!(
                &request.instance.spec.destination,
                ManagedDestination::Graph { .. }
            )
            && (request.expected.is_some()
                || request.rebuild
                || request.completed.is_none()
                || !request.instance.running)
        {
            return Err(Code::Invalid.error("managed Graph follow mode"));
        }
        let before = output.input_bytes;
        let expected = request.expected();
        let bytes: u64 = reader.query_row("SELECT octet_length(v.spec) + octet_length(i.authority) FROM managed_instances i JOIN managed_versions v USING (tenant_id, instance_id) WHERE i.tenant_id = ? AND i.instance_id = ? AND v.generation = ?",
            params![expected.spec.tenant.as_slice(), expected.spec.id, request.instance.generation], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "bound managed instance capture" })?;
        output.charge(
            usize::try_from(bytes)
                .unwrap_or(usize::MAX)
                .saturating_mul(2),
        )?;
        let (current, completed) = Self::managed_capture_owner(reader, request)?;
        let instance = request.instance.clone();
        let reuse = request.completed.is_some()
            && request.expected.is_none()
            && !request.rebuild
            && matches!(
                instance.spec.destination,
                ManagedDestination::Graph {
                    operation: ManagedGraphOperation::Evaluate,
                    ..
                }
            )
            && Self::validate_managed_failure(reader, &current)?
                .is_none_or(|failure| failure.progress != current.progress);
        if instance.spec
            != Self::managed_version_from(
                reader,
                expected.spec.tenant,
                &expected.spec.id,
                instance.generation,
            )?
            || instance.grant != current.grant
            || instance.progress != current.progress
            || instance.running != current.running
            || instance.lifecycle != current.lifecycle
        {
            return Err(Code::Conflict.error("managed target version"));
        }
        let mut prior = BTreeMap::new();
        let mut states = BTreeMap::new();
        for call in instance.spec.manifest.calls.keys() {
            control.check()?;
            let compatible = instance.spec.same_call(&current.spec, *call);
            let saved: Option<(u64, Option<String>)> = reader.query_row(
                "SELECT state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = ?",
                params![instance.spec.tenant.as_slice(), instance.spec.id, call], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()
                .context(AnalysisDatabaseSnafu { operation: "capture managed prior reference" })?;
            if !compatible && saved.as_ref().is_some_and(|(_, id)| id.is_some()) && !request.rebuild
            {
                return Err(Code::Conflict.error("managed update requires rebuild"));
            }
            let (revision, id) = saved.filter(|_| compatible).unwrap_or((0, None));
            let reference = if let Some(id) = id {
                if !request.rebuild {
                    let (metadata, payload): (u64, u64) = reader.query_row("SELECT octet_length(request_meta) + octet_length(body),
                    (SELECT COALESCE(SUM(octet_length(ipc)), 0) FROM managed_arrow WHERE result_id = ? AND role IN ('parameters', 'checkpoint'))
                    FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND commit_revision = ?",
                    params![id, instance.spec.tenant.as_slice(), id, revision], |row| Ok((row.get(0)?, row.get(1)?)))
                    .context(AnalysisDatabaseSnafu { operation: "bound managed prior capture" })?;
                    let payload = usize::try_from(payload).unwrap_or(usize::MAX);
                    output.charge(
                        usize::try_from(metadata)
                            .unwrap_or(usize::MAX)
                            .saturating_mul(2),
                    )?;
                    output.charge(payload)?;
                    let mut state = Self::managed_prior_from(
                        reader, &instance, *call, &id, revision, output, control,
                    )?;
                    // The decoded state owns its buffers; the IPC payload has been released.
                    output.input_bytes -= payload;
                    if reuse
                        && matches!(&instance.spec.destination,
                            ManagedDestination::Graph { calls, .. } if calls.contains(call))
                        && matches!(
                            instance.spec.manifest.calls[call].target.as_str(),
                            "wasm" | "native"
                        )
                    {
                        let payload: u64 = reader.query_row(
                            "SELECT COALESCE(SUM(octet_length(ipc)), 0) FROM managed_arrow WHERE result_id = ?",
                            params![id], |row| row.get(0),
                        ).context(AnalysisDatabaseSnafu { operation: "bound retained Graph call" })?;
                        let before = output.input_bytes;
                        output.charge(usize::try_from(payload).unwrap_or(usize::MAX))?;
                        let saved = Self::saved_evaluation_from(reader, &instance, &id, control)?;
                        output.charge(saved.decoding_bytes(control)?)?;
                        let mut evaluation = saved.decode(control)?;
                        evaluation.checkpoint = None;
                        let (record, packet, saved) =
                            Self::managed_record_from(reader, instance.spec.tenant, &id)?;
                        if saved != revision {
                            return Err(Code::Invalid.error("retained Graph call revision"));
                        }
                        let decoding = packet
                            .datasets
                            .iter()
                            .chain(packet.checkpoint.iter().flat_map(|state| &state.datasets))
                            .map(|data| sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc))
                            .chain(
                                packet.reasons.iter().map(|reason| {
                                    sdk::wire::Dataset::decoding_bytes(&reason.details)
                                }),
                            )
                            .try_fold(0usize, |bytes, next| {
                                bytes
                                    .checked_add(next.context(crate::AnalysisContractSnafu)?)
                                    .ok_or_else(|| Code::Limit.error("retained Graph call memory"))
                            })?;
                        output.charge(decoding)?;
                        let returned = Self::validate_managed_record(
                            reader,
                            instance.spec.tenant,
                            &id,
                            &record,
                            &packet,
                            revision,
                        )?;
                        output.input_bytes = before;
                        output.charge(evaluation.allocated_bytes())?;
                        output.charge(returned.allocated_bytes())?;
                        output.charge(
                            std::mem::size_of::<RetainedCall>() + 2 * std::mem::size_of::<usize>(),
                        )?;
                        state.retained = Some(std::sync::Arc::new(RetainedCall {
                            evaluation,
                            output: returned,
                        }));
                    }
                    prior.insert(*call, state);
                }
                Some(PackageResultRefV1 {
                    result_id: id,
                    commit_revision: revision,
                })
            } else {
                if revision != 0 {
                    return Err(Code::Invalid.error("managed empty state"));
                }
                None
            };
            states.insert(*call, reference);
        }
        Ok(ManagedCapture {
            contract: Capture {
                tenant: instance.spec.tenant,
                instance: instance.spec.id.clone(),
                grant: instance.grant.clone(),
                generation: instance.generation,
                expected_generation: current.generation,
                progress: instance.progress,
                completed,
                running: instance.running,
                lifecycle: instance.lifecycle,
                rebuild: request.rebuild,
                follow: request.follow,
                prior: states,
                store: output.meta.store_uuid,
                schema: output.meta.schema_version,
                recovery: output.meta.recovery_epoch,
                revision: output.meta.commit_revision,
                time_utc_ns: now,
                sources: Vec::new(),
                dependencies: Vec::new(),
                witnesses: Vec::new(),
                contexts: Vec::new(),
                traces: Vec::new(),
            },
            instance,
            prior,
            bytes: output.input_bytes.saturating_sub(before),
        })
    }

    pub(super) fn managed_prior_from(
        reader: &Connection,
        instance: &ManagedInstance,
        call: u64,
        id: &str,
        revision: u64,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<ManagedPrior> {
        let tenant = instance.spec.tenant;
        let declaration = instance
            .spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Invalid.error("managed prior call"))?;
        let (record, packet, saved) = Self::managed_state_from(reader, tenant, id)?;
        if saved != revision {
            return Err(Code::Invalid.error("managed prior revision"));
        }
        let descriptor = Self::managed_contract(reader, tenant, declaration)?;
        output.charge(descriptor.allocated_bytes())?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Missing.error("managed prior model"))?;
        if record.instance != instance.spec.id
            || record.call != call
            || record.declaration != *declaration
            || record.context.target != declaration.target
            || record.context.artifact != declaration.artifact
        {
            return Err(Code::Invalid.error("managed prior contract"));
        }
        let parameters = record
            .parameters
            .as_ref()
            .map(|data| {
                control.check()?;
                let before = output.input_bytes;
                output.charge(
                    sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc)
                        .context(crate::AnalysisContractSnafu)?,
                )?;
                let decoded = data
                    .decode(&model.parameters)
                    .context(crate::AnalysisContractSnafu)?;
                output.input_bytes = before;
                output.charge(decoded.allocated_bytes())?;
                if data.name != "parameters" || decoded.batches.len() != 1 || decoded.rows() != 1 {
                    return Err(Code::Invalid.error("managed retained parameters"));
                }
                Ok(decoded)
            })
            .transpose()?;
        let checkpoint = packet
            .checkpoint
            .as_ref()
            .map(|state| -> Result<sdk::Checkpoint> {
                control.check()?;
                let bytes = state.datasets.iter().try_fold(0usize, |bytes, data| {
                    let next = sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc)
                        .context(crate::AnalysisContractSnafu)?;
                    bytes
                        .checked_add(next)
                        .ok_or_else(|| Code::Limit.error("managed prior decode"))
                })?;
                let before = output.input_bytes;
                output.charge(bytes)?;
                let decoded = state
                    .decode_model(model)
                    .context(crate::AnalysisContractSnafu)?;
                output.input_bytes = before;
                output.charge(
                    decoded
                        .datasets
                        .capacity()
                        .saturating_mul(std::mem::size_of::<sdk::Dataset>()),
                )?;
                for data in &decoded.datasets {
                    output.charge(data.allocated_bytes())?;
                }
                Ok(decoded)
            })
            .transpose()?;
        Ok(ManagedPrior {
            revision,
            result: id.into(),
            context: record.context,
            parameters,
            checkpoint,
            retained: None,
        })
    }
}

impl ManagedCapture {
    pub(in crate::analysis) fn seal(
        &mut self,
        selection: &AnalysisSelectionV1,
        output: &AnalysisExtractionV1,
    ) {
        self.bytes = self.bytes.saturating_add(output.allocation_bytes());
        self.contract.sources = selection.source_revisions(output.meta.commit_revision);
        self.contract.dependencies = output
            .references
            .iter()
            .filter_map(|entry| entry.result().cloned())
            .collect();
        self.contract
            .dependencies
            .sort_by(|left, right| left.result_id.cmp(&right.result_id));
        self.contract.dependencies.dedup();
        self.contract.contexts = output
            .references
            .iter()
            .filter_map(|entry| entry.context().cloned())
            .collect();
        self.contract
            .contexts
            .sort_by(|left, right| left.key.cmp(&right.key));
        self.contract.contexts.dedup();
        self.contract.witnesses = output.witnesses.clone();
        self.contract.traces = output.trace_reads().to_vec();
    }
}
