use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};
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
        let before = output.input_bytes;
        let expected = &request.instance;
        let bytes: u64 = reader.query_row("SELECT octet_length(spec) FROM managed_instances WHERE tenant_id = ? AND instance_id = ?",
            params![expected.spec.tenant.as_slice(), expected.spec.id], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "bound managed instance capture" })?;
        output.charge(
            usize::try_from(bytes)
                .unwrap_or(usize::MAX)
                .saturating_mul(2),
        )?;
        let instance =
            Self::managed_instance_from(reader, expected.spec.tenant, &expected.spec.id)?
                .filter(|instance| instance == expected)
                .ok_or_else(|| Code::Conflict.error("managed capture generation"))?;
        let completed =
            Self::managed_completed_from(reader, expected.spec.tenant, &expected.spec.id)?;
        if request
            .completed
            .is_some_and(|expected| expected != completed)
        {
            return Err(Code::Conflict.error("managed capture completion"));
        }
        let mut prior = BTreeMap::new();
        let mut states = BTreeMap::new();
        for call in instance.spec.manifest.calls.keys() {
            control.check()?;
            let (revision, id): (u64, Option<String>) = reader.query_row(
                "SELECT state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = ?",
                params![instance.spec.tenant.as_slice(), instance.spec.id, call], |row| Ok((row.get(0)?, row.get(1)?)))
                .context(AnalysisDatabaseSnafu { operation: "capture managed prior reference" })?;
            let reference = if let Some(id) = id {
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
                let state = Self::managed_prior_from(
                    reader, &instance, *call, &id, revision, output, control,
                )?;
                // The decoded state owns its buffers; the IPC payload has been released.
                output.input_bytes -= payload;
                prior.insert(*call, state);
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
                generation: instance.generation,
                progress: instance.progress,
                completed,
                running: instance.running,
                lifecycle: instance.lifecycle,
                rebuild: request.rebuild,
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
        let (metadata, body): (Vec<u8>, Vec<u8>) = reader.query_row(
            "SELECT request_meta, body FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND commit_revision = ? AND processor_id = 'managed-package-v1'",
            params![tenant.as_slice(), id, revision], |row| Ok((row.get(0)?, row.get(1)?)))
            .context(AnalysisDatabaseSnafu { operation: "read captured managed prior" })?;
        let mut record: Record =
            serde_json::from_slice(&metadata).context(crate::PackageEncodingSnafu)?;
        let mut packet: araphor_analysis_sdk::wire::Output =
            serde_json::from_slice(&body).context(crate::PackageEncodingSnafu)?;
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
            return Err(Code::Invalid.error("managed prior payload count"));
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
                    sdk::wire::Dataset::decoding_bytes(
                        &data.arrow_ipc,
                        record.context.context.limits,
                    )
                    .context(crate::AnalysisContractSnafu)?,
                )?;
                let decoded = data
                    .decode(&model.parameters, record.context.context.limits)
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
                let limits = sdk::Limits {
                    max_bytes: model.limits.max_checkpoint_bytes,
                    ..model.limits
                };
                let bytes = state.datasets.iter().try_fold(0usize, |bytes, data| {
                    let next = sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc, limits)
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
