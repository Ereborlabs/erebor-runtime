use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::super::{AnalysisStore, PackageResultRefV1};
use super::model::*;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result, ResultContext,
};

struct Packet {
    call: u64,
    id: String,
    record: Record,
    output: sdk::wire::Output,
}

impl AnalysisStore {
    pub fn register_managed_attempt(
        &self,
        captured: &ManagedCapture,
        request: &ManagedRequest,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedAttempt> {
        if request.id.is_empty()
            || request.id.chars().any(char::is_control)
            || request.time_utc_ns == 0
            || i64::try_from(request.time_utc_ns).is_err()
        {
            return Err(Code::Invalid.error("managed attempt request"));
        }
        if request.rebuild != captured.rebuild()
            || request.time_utc_ns != captured.contract.time_utc_ns
        {
            return Err(Code::Invalid.error("managed rebuild capture"));
        }
        let mut contract = captured.contract.clone();
        for witness in &mut contract.witnesses {
            if witness.expires_utc_ns == 0 {
                witness.expires_utc_ns = request.witness_expiry;
            }
        }
        let capture = &contract;
        let spec = &captured.instance.spec;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed attempt",
            })?;
        if let Some(saved) =
            Self::managed_attempt_from(&transaction, spec.tenant, &spec.id, &request.id)?
        {
            if saved.capture != *capture || saved.request != *request {
                return crate::AnalysisConflictSnafu.fail();
            }
            if saved.receipt.is_none() {
                return Err(Code::Incomplete.error("managed pending attempt"));
            }
            check()?;
            return Ok(ManagedAttempt(
                saved,
                captured.instance.clone(),
                false,
                BTreeMap::new(),
            ));
        }
        self.check_managed_capture(&transaction, capture, request.time_utc_ns)?;
        self.resolve_witnesses(&capture.witnesses, capture.revision)?;
        let revision = self.package_next(&transaction)?;
        let attempt = Attempt {
            request: request.clone(),
            capture: capture.clone(),
            registered: revision,
            receipt: None,
        };
        let bytes = serde_json::to_vec(&attempt).context(crate::PackageEncodingSnafu)?;
        transaction
            .execute(
                "INSERT INTO managed_attempts VALUES (?, ?, ?, ?)",
                params![spec.tenant.as_slice(), spec.id, request.id, bytes],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert immutable managed attempt",
            })?;
        self.check_logical(&transaction, spec.tenant, false)?;
        Self::record_revision(&transaction, revision, &["managed_attempts"])?;
        check()?;
        self.commit_metadata(transaction, "commit managed attempt")?;
        self.revision.send_replace(revision);
        Ok(ManagedAttempt(
            attempt,
            captured.instance.clone(),
            true,
            captured.prior.clone(),
        ))
    }

    pub fn commit_managed(
        &self,
        input: &ManagedCommit<'_>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedReceipt> {
        if input.now_utc_ns < input.attempt.request().time_utc_ns {
            return Err(Code::Invalid.error("managed publication time"));
        }
        let supplied = &input.attempt.0;
        let spec = &input.attempt.1.spec;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed publication",
            })?;
        let mut attempt =
            Self::managed_attempt_from(&transaction, spec.tenant, &spec.id, &supplied.request.id)?
                .ok_or_else(|| Code::Missing.error("managed attempt"))?;
        if supplied.request != attempt.request
            || supplied.capture != attempt.capture
            || supplied.registered != attempt.registered
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if attempt.receipt.is_none() && !input.attempt.2 {
            return Err(Code::Incomplete.error("managed pending attempt capture"));
        }
        if attempt.receipt.is_some() {
            return crate::AnalysisConflictSnafu.fail();
        }
        let revision = self.package_next(&transaction)?;
        let (packets, step, selected, receipt) =
            self.prepare_managed(&transaction, &attempt, input, revision)?;
        self.check_managed_capture(&transaction, &attempt.capture, input.now_utc_ns)?;
        let segments = self.resolve_witnesses(&attempt.capture.witnesses, revision - 1)?;
        for packet in packets {
            self.insert_managed(&transaction, spec, packet, revision, &segments)?;
        }
        Self::insert_managed_step(
            &transaction,
            spec,
            &receipt.selected.result_id,
            step,
            selected,
            revision,
        )?;
        Self::insert_references(
            &transaction,
            &receipt.selected.result_id,
            &attempt.capture.witnesses,
            &segments,
            &attempt.capture.contexts,
        )?;
        transaction
            .execute(
                "UPDATE managed_instances SET progress = ? WHERE tenant_id = ? AND instance_id = ?",
                params![revision, spec.tenant.as_slice(), spec.id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance managed progress",
            })?;
        attempt.receipt = Some(receipt.clone());
        transaction.execute("UPDATE managed_attempts SET contract = ? WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ?",
            params![serde_json::to_vec(&attempt).context(crate::PackageEncodingSnafu)?, spec.tenant.as_slice(), spec.id, attempt.request.id])
            .context(AnalysisDatabaseSnafu { operation: "complete managed attempt" })?;
        self.check_logical(&transaction, spec.tenant, false)?;
        self.check_witnesses(&transaction, spec.tenant, input.now_utc_ns)?;
        Self::record_revision(
            &transaction,
            revision,
            &[
                "managed_calls",
                "managed_instances",
                "managed_attempts",
                "managed_edges",
                "managed_arrow",
                "analysis_results",
                "evidence_refs",
                "context_refs",
            ],
        )?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        #[cfg(test)]
        self.crash_at("managed.before");
        self.commit_metadata(transaction, "commit complete managed step")?;
        #[cfg(test)]
        self.crash_at("managed.after");
        self.revision.send_replace(revision);
        Ok(receipt)
    }

    pub(super) fn check_managed_capture(
        &self,
        reader: &Connection,
        capture: &Capture,
        now: u64,
    ) -> Result<()> {
        let instance = Self::managed_instance_from(reader, capture.tenant, &capture.instance)?
            .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let spec = &instance.spec;
        let meta = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?;
        if meta.store_uuid != capture.store
            || meta.schema_version != capture.schema
            || meta.recovery_epoch != capture.recovery
            || meta.commit_revision < capture.revision
            || instance.generation != capture.generation
            || instance.progress != capture.progress
            || capture.prior.keys().ne(spec.manifest.calls.keys())
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        for (call, prior) in &capture.prior {
            let (revision, id): (u64, Option<String>) = reader.query_row(
                "SELECT state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = ?",
                params![spec.tenant.as_slice(), spec.id, call], |row| Ok((row.get(0)?, row.get(1)?)))
                .context(AnalysisDatabaseSnafu { operation: "compare captured managed state" })?;
            if prior
                .as_ref()
                .map(|value| (value.commit_revision, Some(value.result_id.as_str())))
                .unwrap_or((0, None))
                != (revision, id.as_deref())
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let control = AnalysisReadControl::default();
        if !Self::package_sources_current(reader, &capture.sources, &control)? {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_trace_reads_from(reader, spec.tenant, &capture.traces, &control)?;
        for reference in &capture.contexts {
            if Self::read_context_from(reader, &self.root, &reference.key)?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        for reference in &capture.dependencies {
            if !self.managed_current(
                reader,
                spec,
                &reference.result_id,
                reference.commit_revision,
                now,
                &control,
            )? {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        if capture.witnesses.iter().any(|witness| {
            witness.identity.tenant() != spec.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns < now
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        Ok(())
    }

    fn prepare_managed(
        &self,
        reader: &Connection,
        attempt: &Attempt,
        input: &ManagedCommit<'_>,
        revision: u64,
    ) -> Result<(Vec<Packet>, Step, sdk::wire::Dataset, ManagedReceipt)> {
        let current =
            Self::managed_instance_from(reader, attempt.capture.tenant, &attempt.capture.instance)?
                .ok_or_else(|| Code::Missing.error("managed publication instance"))?;
        if current.generation != attempt.capture.generation || current.spec != input.attempt.1.spec
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let spec = &current.spec;
        let mut ids = BTreeMap::new();
        for returned in input.returns {
            if !spec.manifest.calls.contains_key(&returned.call) || ids.contains_key(&returned.call)
            {
                return Err(Code::Invalid.error("managed returned calls"));
            }
            let id = crate::InputRevision::of(&(
                spec.tenant,
                &spec.id,
                &attempt.request.id,
                Some(returned.call),
            ))
            .context(crate::PackageEncodingSnafu)?;
            ids.insert(
                returned.call,
                PackageResultRefV1 {
                    result_id: format!("managed-{id}"),
                    commit_revision: revision,
                },
            );
        }
        let mut packets = Vec::new();
        for returned in input.returns {
            let declaration = &spec.manifest.calls[&returned.call];
            let descriptor = Self::managed_contract(reader, spec.tenant, declaration)?;
            let evaluation = returned.evaluation;
            if evaluation.export != declaration.export
                || evaluation.context.id != attempt.request.id
                || evaluation.context.time_utc_ns != attempt.request.time_utc_ns as i64
                || evaluation.context.seed != attempt.request.seed
            {
                return Err(Code::Invalid.error("managed evaluation request"));
            }
            let checked = descriptor
                .check_evaluation(evaluation)
                .context(crate::AnalysisContractSnafu)?;
            let expected = input
                .attempt
                .3
                .get(&returned.call)
                .map(|prior| {
                    prior.checkpoint(
                        checked.model(),
                        &evaluation.inputs,
                        evaluation.parameters.as_ref(),
                        attempt.request.rebuild,
                    )
                })
                .transpose()?
                .flatten();
            let same =
                match (&expected, &evaluation.checkpoint) {
                    (None, None) => true,
                    (Some(expected), Some(actual)) => {
                        expected.version == actual.version
                            && expected.datasets.len() == actual.datasets.len()
                            && expected.datasets.iter().zip(&actual.datasets).all(
                                |(left, right)| {
                                    left.name == right.name && left.batches == right.batches
                                },
                            )
                    }
                    _ => false,
                };
            if !same {
                return Err(Code::Conflict.error("managed captured checkpoint"));
            }
            let mut context = ResultContext::new(
                &attempt.request.id,
                attempt.request.time_utc_ns,
                checked.model(),
                &evaluation.inputs,
            );
            context.context = evaluation.context.clone();
            context.target = declaration.target.clone();
            context.artifact = declaration.artifact.clone();
            let parameters = evaluation
                .parameters
                .as_ref()
                .map(|batch| {
                    sdk::wire::Dataset::encode(
                        &sdk::Dataset {
                            name: "parameters".into(),
                            batches: vec![batch.clone()],
                        },
                        &checked.model().parameters,
                        evaluation.context.limits,
                    )
                    .context(crate::AnalysisContractSnafu)
                })
                .transpose()?;
            let mut dependencies = attempt.capture.dependencies.clone();
            dependencies.extend(
                declaration
                    .dependencies
                    .iter()
                    .filter_map(|call| ids.get(call).cloned()),
            );
            dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
            dependencies.dedup();
            let rows = evaluation
                .inputs
                .iter()
                .map(|input| (input.data.name.clone(), input.data.rows()))
                .collect();
            let record = Record {
                instance: spec.id.clone(),
                call: returned.call,
                attempt: attempt.request.id.clone(),
                declaration: declaration.clone(),
                context,
                parameters,
                rows,
                dependencies,
                witnesses: attempt.capture.witnesses.clone(),
                contexts: attempt.capture.contexts.clone(),
            };
            let output = sdk::wire::Output::encode_checked(&checked, returned.output)
                .context(crate::AnalysisContractSnafu)?;
            packets.push(Packet {
                call: returned.call,
                id: ids[&returned.call].result_id.clone(),
                record,
                output,
            });
        }
        let selected =
            Self::encode_selected(input.selected, input.selected_schema, input.selected_limits)?;
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(ids.values().cloned());
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        let step = Step {
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            rows: input.selected.rows(),
            dependencies,
            witnesses: attempt.capture.witnesses.clone(),
            contexts: attempt.capture.contexts.clone(),
        };
        let id =
            crate::InputRevision::of(&(spec.tenant, &spec.id, &attempt.request.id, None::<u64>))
                .context(crate::PackageEncodingSnafu)?;
        let receipt = ManagedReceipt {
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            commit_revision: revision,
            selected: PackageResultRefV1 {
                result_id: format!("managed-{id}"),
                commit_revision: revision,
            },
            results: ids,
        };
        Ok((packets, step, selected, receipt))
    }

    fn insert_managed(
        &self,
        transaction: &Transaction<'_>,
        spec: &ManagedSpec,
        mut packet: Packet,
        revision: u64,
        segments: &[u64],
    ) -> Result<()> {
        for (slot, data) in packet.output.datasets.iter_mut().enumerate() {
            Self::insert_managed_arrow(
                transaction,
                &packet.id,
                "output",
                slot,
                &mut data.arrow_ipc,
            )?;
        }
        for (slot, reason) in packet.output.reasons.iter_mut().enumerate() {
            Self::insert_managed_arrow(
                transaction,
                &packet.id,
                "reason",
                slot,
                &mut reason.details,
            )?;
        }
        if let Some(checkpoint) = &mut packet.output.checkpoint {
            for (slot, data) in checkpoint.datasets.iter_mut().enumerate() {
                Self::insert_managed_arrow(
                    transaction,
                    &packet.id,
                    "checkpoint",
                    slot,
                    &mut data.arrow_ipc,
                )?;
            }
        }
        if let Some(data) = &mut packet.record.parameters {
            Self::insert_managed_arrow(
                transaction,
                &packet.id,
                "parameters",
                0,
                &mut data.arrow_ipc,
            )?;
        }
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision) VALUES (?, ?, 'managed-package-v1', ?, ?, ?)",
            params![packet.id, spec.tenant.as_slice(), serde_json::to_vec(&packet.output).context(crate::PackageEncodingSnafu)?, serde_json::to_vec(&packet.record).context(crate::PackageEncodingSnafu)?, revision])
            .context(AnalysisDatabaseSnafu { operation: "insert complete managed result" })?;
        Self::insert_managed_edges(
            transaction,
            spec.tenant,
            &packet.id,
            &packet.record.dependencies,
        )?;
        Self::insert_references(
            transaction,
            &packet.id,
            &packet.record.witnesses,
            segments,
            &packet.record.contexts,
        )?;
        transaction.execute("UPDATE managed_calls SET state_revision = ?, result_id = ? WHERE tenant_id = ? AND instance_id = ? AND call_id = ?",
            params![revision, packet.id, spec.tenant.as_slice(), spec.id, packet.call])
            .context(AnalysisDatabaseSnafu { operation: "advance independent managed call" })?;
        Ok(())
    }

    fn insert_managed_step(
        transaction: &Transaction<'_>,
        spec: &ManagedSpec,
        id: &str,
        step: Step,
        mut selected: sdk::wire::Dataset,
        revision: u64,
    ) -> Result<()> {
        Self::insert_managed_arrow(transaction, id, "selected", 0, &mut selected.arrow_ipc)?;
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision) VALUES (?, ?, 'managed-definition-v1', ?, ?, ?)",
            params![id, spec.tenant.as_slice(), serde_json::to_vec(&selected).context(crate::PackageEncodingSnafu)?, serde_json::to_vec(&step).context(crate::PackageEncodingSnafu)?, revision])
            .context(AnalysisDatabaseSnafu { operation: "insert selected managed relation" })?;
        Self::insert_managed_edges(transaction, spec.tenant, id, &step.dependencies)
    }

    fn insert_managed_edges(
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        id: &str,
        dependencies: &[PackageResultRefV1],
    ) -> Result<()> {
        for dependency in dependencies {
            transaction
                .execute(
                    "INSERT INTO managed_edges VALUES (?, ?, ?, ?)",
                    params![
                        tenant.as_slice(),
                        id,
                        dependency.result_id,
                        dependency.commit_revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert managed result edge",
                })?;
        }
        Ok(())
    }

    fn insert_managed_arrow(
        transaction: &Transaction<'_>,
        id: &str,
        role: &str,
        slot: usize,
        ipc: &mut Vec<u8>,
    ) -> Result<()> {
        transaction
            .execute(
                "INSERT INTO managed_arrow VALUES (?, ?, ?, ?)",
                params![id, role, slot as u64, ipc.as_slice()],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert binary managed Arrow payload",
            })?;
        ipc.clear();
        Ok(())
    }
}
