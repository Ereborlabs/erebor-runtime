use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::context::VerifiedPackages;
use super::super::{AnalysisExtractionV1, AnalysisSelectionV1, AnalysisStore, PackageResultRefV1};
use super::model::*;
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    #[expect(
        clippy::too_many_arguments,
        reason = "A source frame requires the complete sealed read scope."
    )]
    pub(in crate::analysis) fn restore_managed(
        reader: &Connection,
        reference: &ManagedAttempt,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        read: &crate::AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        owners: Option<&BTreeSet<String>>,
        physical: &crate::AnalysisStoreMetaV1,
    ) -> Result<ManagedCapture> {
        let mut captured = ManagedCapture::from(reference);
        if read.now == reference.request().time_utc_ns {
            let mode = match read.mode {
                crate::AnalysisReadModeV1::Complete => Some(super::ManagedSourceRead::Initial),
                crate::AnalysisReadModeV1::Changes(after) => {
                    let parent = Self::managed_parent_from(reader, reference)?
                        .filter(|parent| parent.position == after)
                        .ok_or_else(|| Code::Invalid.error("managed reference source cut"))?;
                    Some(super::ManagedSourceRead::Changes(parent))
                }
                _ => None,
            };
            if let Some(mode) = mode {
                let mut meta = output.meta.clone();
                meta.recovery_epoch = physical.recovery_epoch;
                captured.source = super::source::SourceScope::capture(
                    &captured.instance,
                    &meta,
                    mode,
                    read,
                    selection,
                    owners,
                )?;
                if matches!(read.mode, crate::AnalysisReadModeV1::Changes(_))
                    && captured.source.is_none()
                {
                    return Err(Code::Unsupported.error("managed source projection"));
                }
                if matches!(read.mode, crate::AnalysisReadModeV1::Complete) {
                    if let (Some(source), Some(receipt)) = (&captured.source, reference.receipt()) {
                        source.commit_proof(std::sync::Arc::new(receipt.selected.clone()));
                    }
                }
            }
        }
        if !captured.rebuild() {
            for (call, prior) in &captured.contract.prior {
                let Some(prior) = prior else { continue };
                let state = Self::managed_prior_from(
                    reader,
                    &captured.instance,
                    *call,
                    &prior.result_id,
                    prior.commit_revision,
                    output,
                    control,
                )?;
                captured.prior.insert(*call, std::sync::Arc::new(state));
            }
        }
        captured.bytes = output.input_bytes;
        Ok(captured)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The capture keeps the native read scope and context owners."
    )]
    pub(in crate::analysis) fn capture_managed(
        &self,
        reader: &Connection,
        request: &ManagedRead,
        read: &crate::AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
        context_owners: Option<&BTreeSet<String>>,
    ) -> Result<ManagedCapture> {
        let now = read.now;
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
        let mut verified = VerifiedPackages::default();
        let retained = request
            .execution
            .as_ref()
            .map(|execution| execution.calls(request, &output.meta))
            .unwrap_or_default();
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
                    if let Some(state) = retained
                        .get(call)
                        .filter(|state| state.revision == revision && state.result == id)
                    {
                        let declaration = &instance.spec.manifest.calls[call];
                        self.verify_package_revision(
                            reader,
                            instance.spec.tenant,
                            &declaration.package,
                            &mut verified,
                        )?;
                        output.charge(state.allocated_bytes())?;
                        prior.insert(*call, std::sync::Arc::clone(state));
                        states.insert(
                            *call,
                            Some(PackageResultRefV1 {
                                result_id: id,
                                commit_revision: revision,
                            }),
                        );
                        continue;
                    }
                    let bytes: u64 = reader.query_row(
                        "SELECT octet_length(request_meta) + octet_length(body) FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND commit_revision = ?",
                        params![instance.spec.tenant.as_slice(), id, revision], |row| row.get(0),
                    ).context(AnalysisDatabaseSnafu { operation: "bound canonical prior state" })?;
                    output.charge(usize::try_from(bytes).unwrap_or(usize::MAX))?;
                    let state = Self::managed_prior_from(
                        reader, &instance, *call, &id, revision, output, control,
                    )?;
                    self.verify_package_revision(
                        reader,
                        instance.spec.tenant,
                        &instance.spec.manifest.calls[call].package,
                        &mut verified,
                    )?;
                    prior.insert(*call, std::sync::Arc::new(state));
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
            execution: request.execution.clone(),
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
            source: Self::capture_source(
                reader,
                request,
                read,
                selection,
                &output.meta,
                context_owners,
            )?,
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
        let (_, owner) = Self::managed_call_owner(reader, tenant, id, revision, &record)?;
        let descriptor = Self::managed_contract(reader, tenant, declaration)?;
        output.charge(descriptor.allocated_bytes())?;
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == declaration.export)
            .ok_or_else(|| Code::Missing.error("managed prior model"))?;
        if record.instance != instance.spec.id
            || record.call != call
            || owner.manifest.calls.get(&call) != Some(declaration)
            || record.context.target != declaration.target
            || record.context.artifact != declaration.artifact
        {
            return Err(Code::Invalid.error("managed prior contract"));
        }
        let checkpoint = packet
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
        model
            .validate_checkpoint(checkpoint.as_ref(), true)
            .context(crate::AnalysisContractSnafu)?;
        Ok(ManagedPrior {
            revision,
            result: id.into(),
            context: record.context,
            parameters: None,
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
            .filter(|entry| {
                !self.source.as_ref().is_some_and(|source| {
                    source
                        .projection()
                        .get("context_versions")
                        .is_some_and(Option::is_some)
                }) || entry
                    .origins()
                    .iter()
                    .any(|origin| !matches!(origin, crate::AnalysisReferenceOriginV1::Context))
            })
            .filter_map(|entry| entry.context().cloned())
            .collect();
        self.contract
            .contexts
            .sort_by(|left, right| left.key.cmp(&right.key));
        self.contract.contexts.dedup();
        self.contract.witnesses = output
            .witnesses
            .iter()
            .filter(|witness| {
                !self.source.as_ref().is_some_and(|source| {
                    source
                        .projection()
                        .get("events")
                        .is_some_and(Option::is_some)
                }) || !matches!(
                    &witness.identity,
                    crate::AnalysisStreamIdentityV1::Evidence(_)
                )
            })
            .cloned()
            .collect();
        self.contract.traces = output.trace_reads().to_vec();
    }
}
