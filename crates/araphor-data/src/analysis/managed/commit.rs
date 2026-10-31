use super::codec::ManagedCodec;
use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::super::context::VerifiedPackages;
use super::super::{AnalysisStore, PackageResultRefV1};
use super::model::*;
use super::source::SourceEvidence;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result, ResultContext,
};

struct Packet {
    call: u64,
    id: String,
    record: Record,
    output: sdk::wire::Output,
    inputs: Vec<sdk::wire::Dataset>,
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
            || request
                .frontier
                .as_ref()
                .is_some_and(|frontier| frontier.cursor.is_empty() || frontier.pending)
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
        contract.witnesses.sort_unstable_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then(left.cursor.cmp(&right.cursor))
                .then(left.expires_utc_ns.cmp(&right.expires_utc_ns))
        });
        contract
            .witnesses
            .dedup_by(|left, right| left.identity == right.identity && left.cursor == right.cursor);
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
            if saved.receipt.is_none() && saved.terminal.is_none() {
                return Err(Code::Incomplete.error("managed pending attempt"));
            }
            check()?;
            return Ok(ManagedAttempt(
                saved,
                captured.instance.clone(),
                None,
                BTreeMap::new(),
                None,
                None,
            ));
        }
        if request.frontier.is_some() {
            Self::check_managed_pending(
                &transaction,
                spec.tenant,
                &spec.id,
                capture.expected_generation,
            )?;
        }
        self.check_managed_capture(
            &transaction,
            capture,
            request.time_utc_ns,
            (&capture.witnesses, &capture.contexts),
        )?;
        self.resolve_witnesses(&capture.witnesses, capture.revision)?;
        let revision = self.package_next(&transaction)?;
        let attempt = Attempt {
            request: request.clone(),
            capture: capture.clone(),
            registered: revision,
            receipt: None,
            terminal: None,
        };
        let bytes = ManagedCodec::encode(&attempt).context(crate::ManagedEncodingSnafu)?;
        transaction
            .execute(
                "INSERT INTO managed_attempts VALUES (?, ?, ?, ?, ?, 0)",
                params![
                    spec.tenant.as_slice(),
                    spec.id,
                    request.id,
                    capture.generation,
                    bytes
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert immutable managed attempt",
            })?;
        self.check_revision_limits(&transaction, spec.tenant)?;
        Self::record_revision(&transaction, revision, &["managed_attempts"])?;
        check()?;
        self.commit_metadata(transaction, "commit managed attempt")?;
        self.revision.send_replace(revision);
        Ok(ManagedAttempt(
            attempt,
            captured.instance.clone(),
            Some(self.revision.subscribe()),
            captured.prior.clone(),
            captured.execution.as_ref().map(|execution| {
                std::sync::Arc::new(super::execution::Retention::new(std::sync::Arc::clone(
                    execution,
                )))
            }),
            captured.source.clone(),
        ))
    }

    pub(in crate::analysis) const MANAGED_RELATIONS: &'static [&'static str] = &[
        "managed_calls",
        "managed_instances",
        "managed_attempts",
        "managed_edges",
        "managed_arrow",
        "analysis_results",
        "evidence_refs",
        "context_refs",
    ];

    pub fn commit_managed(
        &self,
        input: &ManagedCommit<'_>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedReceipt> {
        if input.attempt.1.spec.destination != ManagedDestination::Selected {
            return Err(Code::Invalid.error("managed selected destination"));
        }
        self.commit_managed_projection(input, |_, _, _, _, _| Ok((Vec::new(), None)), check)
    }

    pub(in crate::analysis) fn commit_managed_projection(
        &self,
        input: &ManagedCommit<'_>,
        project: impl FnOnce(
            &Transaction<'_>,
            u64,
            &ManagedReceipt,
            (&[crate::AnalysisWitnessV1], &[u64]),
            &mut VerifiedPackages,
        ) -> Result<(Vec<&'static str>, Option<PackageResultRefV1>)>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedReceipt> {
        let evidence = match &input.attempt.5 {
            Some(source) => source.frame.freeze_evidence(
                &input.attempt.0.capture,
                input.attempt.request().witness_expiry,
            )?,
            None => SourceEvidence {
                witnesses: input.attempt.0.capture.witnesses.clone(),
                contexts: input.attempt.0.capture.contexts.clone(),
                support: Vec::new(),
            },
        };
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed publication",
            })?;
        let revision = self.package_next(&transaction)?;
        let (receipt, projected, mut verified) =
            self.managed_commit_rows(&transaction, input, revision, &evidence, project)?;
        let retained = self.retain_managed(&transaction, input, &receipt, &mut verified)?;
        let source_proof = input.attempt.5.as_ref().map(|frame| {
            (
                std::sync::Arc::clone(&frame.frame),
                std::sync::Arc::new(super::source::ManagedSourceProof {
                    result: receipt.selected.clone(),
                    witnesses: evidence.witnesses,
                    contexts: evidence.contexts,
                }),
            )
        });
        if let Some((frame, proof)) = &source_proof {
            frame.check_proof(proof)?;
        }
        let mut relations = Self::MANAGED_RELATIONS.to_vec();
        relations.extend(projected);
        relations.sort_unstable();
        relations.dedup();
        let tenant = input.attempt.1.spec.tenant;
        self.check_revision_limits(&transaction, tenant)?;
        self.check_witnesses(&transaction, tenant, input.now_utc_ns)?;
        Self::record_revision(&transaction, revision, &relations)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::super::AnalysisCommitStage::BeforeResultCommit)?;
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("managed.before");
        self.commit_metadata(transaction, "commit complete managed step")?;
        if let Some((frame, proof)) = source_proof {
            frame.commit_proof(proof);
        }
        if let Some((owner, state)) = retained {
            owner.promote(state);
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("managed.after");
        self.revision.send_replace(revision);
        if input.attempt.switches_version() {
            self.activations.send_replace(revision);
        }
        Ok(receipt)
    }

    fn managed_commit_rows(
        &self,
        transaction: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        revision: u64,
        evidence: &SourceEvidence,
        project: impl FnOnce(
            &Transaction<'_>,
            u64,
            &ManagedReceipt,
            (&[crate::AnalysisWitnessV1], &[u64]),
            &mut VerifiedPackages,
        ) -> Result<(Vec<&'static str>, Option<PackageResultRefV1>)>,
    ) -> Result<(ManagedReceipt, Vec<&'static str>, VerifiedPackages)> {
        if input.now_utc_ns < input.attempt.request().time_utc_ns {
            return Err(Code::Invalid.error("managed publication time"));
        }
        if !input.completed && input.attempt.request().frontier.is_none() {
            return Err(Code::Invalid.error("managed pending frontier"));
        }
        let supplied = &input.attempt.0;
        let spec = &input.attempt.1.spec;
        let mut attempt =
            Self::managed_attempt_from(transaction, spec.tenant, &spec.id, &supplied.request.id)?
                .ok_or_else(|| Code::Missing.error("managed attempt"))?;
        if supplied.request != attempt.request
            || supplied.capture != attempt.capture
            || supplied.registered != attempt.registered
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if attempt.receipt.is_some() || attempt.terminal.is_some() {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_managed_claim(input.attempt)?;
        let (packets, mut step, selected, mut receipt) =
            self.prepare_managed(transaction, &attempt, input, revision, evidence)?;
        let mut verified = self.check_managed_capture(
            transaction,
            &attempt.capture,
            input.now_utc_ns,
            (&evidence.witnesses, &evidence.contexts),
        )?;
        let segments = self.resolve_witnesses(&evidence.witnesses, revision - 1)?;
        if segments.len() != evidence.witnesses.len() {
            return Err(Code::Invalid.error("managed witness segments"));
        }
        if attempt.capture.generation != attempt.capture.expected_generation {
            transaction
                .execute(
                    "DELETE FROM managed_calls WHERE tenant_id = ? AND instance_id = ?",
                    params![spec.tenant.as_slice(), spec.id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "replace managed call heads",
                })?;
            for (call, prior) in &attempt.capture.prior {
                transaction
                    .execute(
                        "INSERT INTO managed_calls VALUES (?, ?, ?, ?, ?)",
                        params![
                            spec.tenant.as_slice(),
                            spec.id,
                            call,
                            prior.as_ref().map_or(0, |value| value.commit_revision),
                            prior.as_ref().map(|value| value.result_id.as_str())
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "select managed target state",
                    })?;
            }
        }
        for packet in packets {
            self.insert_managed(transaction, spec, packet, revision, &segments)?;
        }
        let (projected, graph) = project(
            transaction,
            revision,
            &receipt,
            (&evidence.witnesses, &segments),
            &mut verified,
        )?;
        if let Some(reference) = &graph {
            let ManagedDestination::Graph { source, .. } = &spec.destination else {
                return Err(Code::Invalid.error("managed Graph publication destination"));
            };
            Self::check_graph_publication(transaction, spec.tenant, source, reference, revision)?;
            step.dependencies.push(reference.clone());
            step.dependencies
                .sort_by(|left, right| left.result_id.cmp(&right.result_id));
            step.dependencies.dedup();
        }
        receipt.graph = graph;
        Self::insert_managed_step(
            transaction,
            spec,
            &receipt.selected.result_id,
            step,
            selected,
            input.attempt.5.as_ref().map(|source| source.frame.as_ref()),
            revision,
        )?;
        Self::insert_references(
            transaction,
            &receipt.selected.result_id,
            &evidence.witnesses,
            &segments,
            &evidence.contexts,
        )?;
        transaction
            .execute(
                "UPDATE managed_instances SET progress = ?, generation = ?, lifecycle = CASE WHEN generation <> ? THEN ? ELSE lifecycle END, failure = NULL WHERE tenant_id = ? AND instance_id = ?",
                params![revision, attempt.capture.generation, attempt.capture.generation, revision, spec.tenant.as_slice(), spec.id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "advance managed progress",
            })?;
        attempt.receipt = Some(receipt.clone());
        transaction.execute("UPDATE managed_attempts SET contract = ?, completed = ? WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ?",
            params![ManagedCodec::encode(&attempt).context(crate::ManagedEncodingSnafu)?, revision, spec.tenant.as_slice(), spec.id, attempt.request.id])
            .context(AnalysisDatabaseSnafu { operation: "complete managed attempt" })?;
        Ok((receipt, projected, verified))
    }

    pub(super) fn check_managed_claim(&self, attempt: &ManagedAttempt) -> Result<()> {
        let owner = attempt
            .2
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("managed pending attempt capture"))?;
        if !owner.same_channel(&self.revision.subscribe()) {
            return crate::AnalysisConflictSnafu.fail();
        }
        Ok(())
    }

    pub(super) fn check_managed_capture(
        &self,
        reader: &Connection,
        capture: &Capture,
        now: u64,
        evidence: (&[crate::AnalysisWitnessV1], &[crate::AnalysisContextRefV1]),
    ) -> Result<VerifiedPackages> {
        let mut verified = VerifiedPackages::default();
        let instance = Self::managed_instance_from(reader, capture.tenant, &capture.instance)?
            .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let spec = Self::managed_version_from(
            reader,
            capture.tenant,
            &capture.instance,
            capture.generation,
        )?;
        capture.check_follow_mode(&spec)?;
        let meta = Self::read_meta_from(reader, &self.root.join("analysis.duckdb"))?;
        if meta.store_uuid != capture.store
            || meta.schema_version != capture.schema
            || meta.recovery_epoch != capture.recovery
            || meta.commit_revision < capture.revision
            || capture
                .sources
                .iter()
                .any(|(_, revision)| *revision > capture.revision)
            || instance.generation != capture.expected_generation
            || instance.grant != capture.grant
            || instance.lifecycle != capture.lifecycle
            || instance.running != capture.running
            || instance.progress != capture.progress
            || Self::managed_completed_from(
                reader,
                capture.tenant,
                &capture.instance,
                capture.expected_generation,
            )? != capture.completed
            || capture.prior.keys().ne(spec.manifest.calls.keys())
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        for (call, prior) in &capture.prior {
            if !spec.same_call(&instance.spec, *call) {
                if prior.is_some() {
                    return crate::AnalysisConflictSnafu.fail();
                }
                continue;
            }
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
        if !capture.follows_graph(&spec)
            && !Self::package_sources_current(reader, &capture.sources, &control)?
        {
            return if Self::check_trace_reads_from(reader, spec.tenant, &capture.traces, &control)
                .is_ok()
            {
                crate::AnalysisSourceChangedSnafu.fail()
            } else {
                crate::AnalysisConflictSnafu.fail()
            };
        }
        Self::check_trace_reads_from(reader, spec.tenant, &capture.traces, &control)?;
        for reference in evidence.1 {
            if self
                .read_context_verified_from(reader, &self.root, &reference.key, &mut verified)?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        for reference in &capture.dependencies {
            if !self.managed_current(
                reader,
                &spec,
                &reference.result_id,
                reference.commit_revision,
                now,
                &control,
            )? {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        if evidence.0.iter().any(|witness| {
            witness.identity.tenant() != spec.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns <= now
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        Ok(verified)
    }

    fn prepare_managed(
        &self,
        reader: &Connection,
        attempt: &Attempt,
        input: &ManagedCommit<'_>,
        revision: u64,
        evidence: &SourceEvidence,
    ) -> Result<(Vec<Packet>, Step, sdk::wire::Dataset, ManagedReceipt)> {
        let current =
            Self::managed_instance_from(reader, attempt.capture.tenant, &attempt.capture.instance)?
                .ok_or_else(|| Code::Missing.error("managed publication instance"))?;
        if current.generation != attempt.capture.expected_generation
            || current.lifecycle != attempt.capture.lifecycle
            || current.running != attempt.capture.running
            || Self::managed_version_from(
                reader,
                current.spec.tenant,
                &current.spec.id,
                attempt.capture.generation,
            )? != input.attempt.1.spec
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let spec = &input.attempt.1.spec;
        if input.selected_schema != &spec.manifest.selected_schema {
            return Err(Code::Invalid.error("managed selected schema"));
        }
        let mut ids = BTreeMap::new();
        for returned in input.returns {
            if !spec.manifest.calls.contains_key(&returned.call) || ids.contains_key(&returned.call)
            {
                return Err(Code::Invalid.error("managed returned calls"));
            }
            if let Some(reference) = returned.retained {
                if !attempt.retains(spec, returned.call, reference)
                    || input.attempt.3.get(&returned.call).is_none_or(|prior| {
                        !prior.reusable
                            || prior.retained.is_none()
                            || prior.result != reference.result_id
                            || prior.revision != reference.commit_revision
                    })
                    || Self::validate_managed_failure(reader, &current)?
                        .is_some_and(|failure| failure.progress == current.progress)
                {
                    return Err(Code::Conflict.error("managed retained call"));
                }
                ids.insert(returned.call, reference.clone());
                continue;
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
            let input_basis = if let Some(changes) = returned.changes {
                if changes.base.is_some() {
                    InputBasis::Complete
                } else {
                    InputBasis::None
                }
            } else {
                if evaluation.checkpoint.is_some() {
                    InputBasis::Complete
                } else {
                    InputBasis::None
                }
            };
            let mut expected = input
                .attempt
                .3
                .get(&returned.call)
                .map(|prior| {
                    prior.state(
                        checked.model(),
                        &evaluation.inputs,
                        evaluation.parameters.as_ref(),
                        attempt.request.rebuild,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            if checked
                .model()
                .change_inputs
                .as_ref()
                .is_some_and(|changes| changes.is_reset(evaluation).unwrap_or(false))
            {
                expected = (None, Vec::new());
            }
            let same =
                match (&expected.0, &evaluation.checkpoint) {
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
            if returned.retained.is_some() {
                let retained = input
                    .attempt
                    .3
                    .get(&returned.call)
                    .and_then(|prior| prior.retained.as_ref())
                    .ok_or_else(|| Code::Invalid.error("managed retained call"))?;
                if !retained.matches(evaluation)
                    || sdk::wire::Output::encode_checked(&checked, returned.output)
                        .context(crate::AnalysisContractSnafu)?
                        != sdk::wire::Output::encode_checked(&checked, &retained.output)
                            .context(crate::AnalysisContractSnafu)?
                {
                    return Err(Code::Conflict.error("managed retained call output"));
                }
                continue;
            }
            let mut context = ResultContext::new(
                &attempt.request.id,
                attempt.request.time_utc_ns,
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
            let input_shapes = evaluation
                .inputs
                .iter()
                .map(|input| RecordInput {
                    name: input.data.name.clone(),
                    rows: input.data.rows(),
                    batches: input.data.batches.len(),
                })
                .collect();
            let inputs = evaluation
                .inputs
                .iter()
                .map(|input| {
                    let port = checked
                        .model()
                        .inputs
                        .iter()
                        .find(|port| port.port.name == input.data.name)
                        .ok_or_else(|| Code::Invalid.error("managed input port"))?;
                    sdk::wire::Dataset::encode(&input.data, &port.port.schema)
                        .context(crate::AnalysisContractSnafu)
                })
                .collect::<Result<Vec<_>>>()?;
            let changes = Self::prepare_changes(input, returned, checked.model())?;
            let record = Record {
                instance: spec.id.clone(),
                call: returned.call,
                attempt: attempt.request.id.clone(),
                declaration: declaration.clone(),
                context,
                input_basis,
                parameters,
                inputs: input_shapes,
                changes,
                dependencies,
                witnesses: evidence.witnesses.clone(),
                contexts: evidence.contexts.clone(),
            };
            Self::check_change_record(reader, spec.tenant, &record, checked.model(), attempt)?;
            let output = sdk::wire::Output::encode_checked(&checked, returned.output)
                .context(crate::AnalysisContractSnafu)?;
            packets.push(Packet {
                call: returned.call,
                id: ids[&returned.call].result_id.clone(),
                record,
                output,
                inputs,
            });
        }
        let selected = Self::encode_selected(input.selected, input.selected_schema)?;
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(ids.values().cloned());
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        let step = Step {
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            rows: input.selected.rows(),
            dependencies,
            witnesses: evidence.witnesses.clone(),
            contexts: evidence.contexts.clone(),
            source: match (&attempt.capture.source, &input.attempt.5) {
                (None, None) => None,
                (Some(contract), Some(source)) if *contract == source.frame.record.contract => {
                    let mut record = source.frame.record.clone();
                    record.support = evidence.support.clone();
                    Some(record)
                }
                _ => return Err(Code::Invalid.error("managed source buffers")),
            },
        };
        let id =
            crate::InputRevision::of(&(spec.tenant, &spec.id, &attempt.request.id, None::<u64>))
                .context(crate::PackageEncodingSnafu)?;
        let receipt = ManagedReceipt {
            frontier: attempt.request.frontier.as_ref().map(|frontier| {
                let mut frontier = frontier.clone();
                frontier.pending = !input.completed;
                frontier
            }),
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            commit_revision: revision,
            selected: PackageResultRefV1 {
                result_id: format!("managed-{id}"),
                commit_revision: revision,
            },
            results: ids,
            graph: None,
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
        for (slot, data) in packet.inputs.iter_mut().enumerate() {
            Self::insert_managed_arrow(
                transaction,
                &packet.id,
                "input",
                slot,
                &mut data.arrow_ipc,
            )?;
        }
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
            params![packet.id, spec.tenant.as_slice(), ManagedCodec::encode(&packet.output).context(crate::ManagedEncodingSnafu)?, ManagedCodec::encode(&packet.record).context(crate::ManagedEncodingSnafu)?, revision])
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
        source: Option<&super::source::ManagedSourceFrame>,
        revision: u64,
    ) -> Result<()> {
        Self::insert_managed_arrow(transaction, id, "selected", 0, &mut selected.arrow_ipc)?;
        if let Some(source) = source {
            for (slot, mut table) in source.encode()?.into_iter().enumerate() {
                Self::insert_managed_arrow(transaction, id, "source", slot, &mut table.arrow_ipc)?;
            }
        }
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision) VALUES (?, ?, 'managed-definition-v1', ?, ?, ?)",
            params![id, spec.tenant.as_slice(), ManagedCodec::encode(&selected).context(crate::ManagedEncodingSnafu)?, ManagedCodec::encode(&step).context(crate::ManagedEncodingSnafu)?, revision])
            .context(AnalysisDatabaseSnafu { operation: "insert selected managed relation" })?;
        Self::insert_managed_edges(transaction, spec.tenant, id, &step.dependencies)?;
        if let Some(parent) = step
            .source
            .as_ref()
            .and_then(|source| match &source.contract.read {
                super::source::ManagedSourceRead::Initial => None,
                super::source::ManagedSourceRead::Changes(parent) => Some(&parent.result),
            })
        {
            transaction
                .execute(
                    "INSERT INTO managed_edges VALUES (?, ?, ?, ?, 'source')",
                    params![
                        spec.tenant.as_slice(),
                        id,
                        parent.result_id,
                        parent.commit_revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "retain managed source basis",
                })?;
        }
        Ok(())
    }

    pub(in crate::analysis) fn insert_managed_edges(
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        id: &str,
        dependencies: &[PackageResultRefV1],
    ) -> Result<()> {
        for dependency in dependencies {
            transaction
                .execute(
                    "INSERT INTO managed_edges VALUES (?, ?, ?, ?, 'input')",
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
