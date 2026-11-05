use super::codec::ManagedCodec;
use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::super::context::VerifiedPackages;
use super::super::{AnalysisStore, PackageResultRefV1};
use super::model::*;
use super::source::SourceEvidence;
use super::PreparedManagedCommit;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, PackageErrorCodeV1 as Code, Result, ResultContext,
};

pub(super) struct Packet {
    call: u64,
    id: String,
    record: Record,
    checkpoint: Vec<u8>,
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
        let contract = captured.request_capture(request)?;
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
            captured
                .execution
                .as_ref()
                .map(|owner| owner.packages(&captured.instance, capture))
                .unwrap_or_default(),
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
            captured.execution.clone(),
            captured.source.clone(),
        ))
    }

    pub(in crate::analysis) const MANAGED_RELATIONS: &'static [&'static str] = &[
        "managed_calls",
        "managed_instances",
        "managed_attempts",
        "managed_edges",
        "analysis_results",
        "evidence_refs",
        "context_refs",
    ];

    pub fn commit_managed(
        &self,
        prepared: PreparedManagedCommit<'_>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedReceipt> {
        let input = prepared.input();
        if input.attempt.1.spec.destination != ManagedDestination::Selected {
            return Err(Code::Invalid.error("managed selected destination"));
        }
        self.commit_managed_projection(
            prepared,
            |_, _, _, _, _, _, _| Ok((Vec::new(), None, Default::default(), None)),
            check,
        )
        .map(|(receipt, _)| receipt)
    }

    pub(in crate::analysis) fn commit_managed_projection(
        &self,
        mut prepared: PreparedManagedCommit<'_>,
        project: impl FnOnce(
            &Transaction<'_>,
            u64,
            &ManagedReceipt,
            (&[crate::AnalysisWitnessV1], &[u64]),
            &mut VerifiedPackages,
            (u64, u64, u64),
            Option<super::source::publication::PreparedSource>,
        ) -> Result<(
            Vec<&'static str>,
            Option<PackageResultRefV1>,
            BTreeMap<u64, (u64, u64)>,
            Option<std::sync::Arc<crate::analysis::graph_rows::store::InputProof>>,
        )>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<(ManagedReceipt, u64)> {
        let input = prepared.input();
        let started = prepared.started;
        let frozen = prepared.prepared;
        prepared.memory.check()?;
        let requested = std::time::Instant::now();
        let mut writer = self.writer()?;
        let acquired = std::time::Instant::now();
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed publication",
            })?;
        let revision = self.package_next(&transaction)?;
        let (
            receipt,
            projected,
            verified,
            (pin_rows, call_pins, root_cursors, input_proof),
            graph_layer,
            owners,
        ) = self.managed_commit_rows(&transaction, &mut prepared, revision, project)?;
        let owners = self.managed_results.seal(owners)?;
        let retained = Self::retain_managed(input, &receipt, verified, input_proof);
        let source_proof = input.attempt.5.as_ref().map(|frame| {
            (
                std::sync::Arc::clone(frame),
                std::sync::Arc::new(receipt.selected.clone()),
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
        prepared.memory.check()?;
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.crash_at("managed.before");
        let prepared = std::time::Instant::now();
        self.commit_metadata(transaction, "commit complete managed step")?;
        if let Some(layer) = graph_layer {
            layer.commit();
        }
        owners.commit();
        let committed = std::time::Instant::now();
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
        let published = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "managed_commit_timing", instance_id = %input.attempt.instance().spec.id,
            cut_revision = input.attempt.captured_revision(), publication_revision = revision,
            freeze_s = frozen.duration_since(started).as_secs_f64(),
            prepare_exit_s = requested.duration_since(frozen).as_secs_f64(),
            writer_acquire_s = acquired.duration_since(requested).as_secs_f64(),
            transaction_work_s = prepared.duration_since(acquired).as_secs_f64(),
            commit_s = committed.duration_since(prepared).as_secs_f64(),
            postcommit_s = published.duration_since(committed).as_secs_f64(),
            elapsed_s = published.duration_since(started).as_secs_f64(),
            "Managed commit timing completed"
        );
        for returned in input.returns {
            let roots = root_cursors.get(&returned.call).copied();
            let rows = |name: &str| {
                returned
                    .evaluation
                    .inputs
                    .iter()
                    .find(|input| input.data.name == name)
                    .map_or(0, |input| input.data.rows() as u64)
            };
            erebor_telemetry::debug!(stage="call_commit",instance_id=%input.attempt.instance().spec.id,
                call_id=returned.call,cut_revision=input.attempt.captured_revision(),publication_revision=revision,
                result_id=%receipt.results.get(&returned.call).map_or("",|result|result.result_id.as_str()),
                base_result_id=%returned.changes.and_then(|changes|changes.base.as_ref()).map_or("",|base|base.result_id.as_str()),
                base_revision=returned.changes.and_then(|changes|changes.base.as_ref()).map_or(0,|base|base.commit_revision),
                reset=returned.changes.is_some_and(|changes|changes.base.is_none()),
                unit_rows=rows("units"),removal_rows=rows("unit_removals"),record_rows=rows("records"),fact_rows=rows("facts"),
                output_rows=returned.output.datasets.iter().map(|data|data.rows() as u64).sum::<u64>(),
                pin_rows=call_pins.get(&returned.call).copied().unwrap_or(0),
                first_root_cursor=roots.map(|bounds|bounds.0),last_root_cursor=roots.map(|bounds|bounds.1),
                "Package call commit completed");
        }
        Ok((receipt, pin_rows))
    }

    fn managed_commit_rows(
        &self,
        transaction: &Transaction<'_>,
        prepared: &mut PreparedManagedCommit<'_>,
        revision: u64,
        project: impl FnOnce(
            &Transaction<'_>,
            u64,
            &ManagedReceipt,
            (&[crate::AnalysisWitnessV1], &[u64]),
            &mut VerifiedPackages,
            (u64, u64, u64),
            Option<super::source::publication::PreparedSource>,
        ) -> Result<(
            Vec<&'static str>,
            Option<PackageResultRefV1>,
            BTreeMap<u64, (u64, u64)>,
            Option<std::sync::Arc<crate::analysis::graph_rows::store::InputProof>>,
        )>,
    ) -> Result<(
        ManagedReceipt,
        Vec<&'static str>,
        VerifiedPackages,
        (
            u64,
            BTreeMap<u64, u64>,
            BTreeMap<u64, (u64, u64)>,
            Option<std::sync::Arc<crate::analysis::graph_rows::store::InputProof>>,
        ),
        Option<araphor_graph::PendingLayer>,
        super::reader::ResultOwners,
    )> {
        let started = std::time::Instant::now();
        let input = prepared.input();
        let evidence = &prepared.evidence;
        let spec = &input.attempt.1.spec;
        let mut attempt = self.check_managed_state(transaction, input)?;
        for contract in &prepared.contracts {
            if Self::package_from(
                transaction,
                contract.tenant_id,
                &contract.package_id,
                &contract.revision,
            )?
            .as_ref()
                != Some(contract)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        let cached = prepared.verified.recheck(transaction)?;
        let mut verified = self.check_managed_capture(
            transaction,
            &attempt.capture,
            input.now_utc_ns,
            (&evidence.witnesses, &evidence.contexts),
            std::mem::take(&mut prepared.verified),
        )?;
        if let Some(graph) = &prepared.graph {
            graph.check(transaction)?;
        }
        if let Some(source) = &prepared.source {
            super::SourcePublication::check_parent(transaction, input, source)?;
        }
        let ready = std::time::Instant::now();
        let (mut packets, mut step, mut receipt) = Self::bind_packets(
            input,
            std::mem::take(&mut prepared.packets),
            prepared
                .step
                .take()
                .ok_or_else(|| Code::Invalid.error("managed prepared packet state"))?,
            revision,
        );
        let imported = self.import_derived(
            transaction,
            &mut prepared.derived,
            revision,
            &mut verified,
            cached,
        )?;
        for packet in &mut packets {
            packet.record.graph_proof = prepared
                .graph
                .as_mut()
                .and_then(|graph| graph.take_proof(packet.call));
            packet.record.derived = imported
                .calls
                .get(&packet.call)
                .cloned()
                .unwrap_or_default();
            packet.record.origins = imported
                .origins
                .get(&packet.call)
                .cloned()
                .unwrap_or_default();
            packet.record.proofs = imported
                .proofs
                .get(&packet.call)
                .cloned()
                .unwrap_or_default();
        }
        step.derived = imported.references();
        step.origins = imported.history();
        step.proofs = imported.selected_proofs()?;
        step.source = imported.source_step(&mut prepared.derived)?;
        let segments = self.resolve_witnesses(&evidence.witnesses, revision - 1)?;
        if segments.len() != evidence.witnesses.len() {
            return Err(Code::Invalid.error("managed witness segments"));
        }
        let verified_at = std::time::Instant::now();
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
        let mut pins = 0u64;
        let mut call_pins = BTreeMap::new();
        let mut records = Vec::with_capacity(packets.len());
        for packet in packets {
            let id = packet.id.clone();
            let call = packet.call;
            let (rows, record) = self.insert_managed(
                transaction,
                spec,
                packet,
                revision,
                (&evidence.witnesses, &segments),
            )?;
            records.push((id, record));
            call_pins.insert(call, rows);
            pins = pins.saturating_add(rows);
        }
        imported.pin(transaction, &receipt, &prepared.derived)?;
        let inserted = std::time::Instant::now();
        let (mut graph_relations, graph_work, graph_layer) = self.commit_graph_journals(
            transaction,
            input,
            &receipt,
            revision,
            prepared.graph.take(),
            &prepared.memory,
        )?;
        let journal_at = std::time::Instant::now();
        graph_relations.extend(Self::publish_graph(transaction, input, &receipt, revision)?);
        let graph_at = std::time::Instant::now();
        let (mut projected, graph, root_cursors, input_proof) = project(
            transaction,
            revision,
            &receipt,
            (&evidence.witnesses, &segments),
            &mut verified,
            graph_work,
            prepared.source.take(),
        )?;
        let source_at = std::time::Instant::now();
        projected.extend(graph_relations);
        if !step.derived.is_empty() {
            projected.extend([
                "context_versions",
                "graph_fact_records",
                "managed_context_imports",
            ]);
        }
        if !step.origins.is_empty() {
            projected.push("managed_source_reads");
        }
        if !imported.proofs.is_empty() || !step.proofs.is_empty() {
            projected.push("managed_source_proofs");
        }
        if let Some(reference) = &graph {
            let ManagedDestination::Graph { source, .. } = &spec.destination else {
                return Err(Code::Invalid.error("managed Graph publication destination"));
            };
            Self::check_graph_publication(transaction, spec.tenant, source, reference, revision)?;
            if reference.result_id != receipt.selected.result_id {
                step.dependencies.push(reference.clone());
            }
            step.dependencies
                .sort_by(|left, right| left.result_id.cmp(&right.result_id));
            step.dependencies.dedup();
        }
        let projected_at = std::time::Instant::now();
        receipt.graph = graph;
        let selected_contexts = Self::join_contexts(&evidence.contexts, &step.derived)?;
        Self::insert_managed_step(
            transaction,
            spec,
            &receipt.selected.result_id,
            &step,
            revision,
        )?;
        pins = pins.saturating_add(Self::insert_references(
            transaction,
            &receipt.selected.result_id,
            &evidence.witnesses,
            &segments,
            &selected_contexts,
        )?);
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
        let completed = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "managed_rows_timing", instance_id = %spec.id,
            cut_revision = input.attempt.captured_revision(), publication_revision = revision,
            prepare_s = ready.duration_since(started).as_secs_f64(),
            verify_s = verified_at.duration_since(ready).as_secs_f64(),
            calls_s = inserted.duration_since(verified_at).as_secs_f64(),
            project_s = projected_at.duration_since(inserted).as_secs_f64(),
            journals_s = journal_at.duration_since(inserted).as_secs_f64(),
            publication_s = graph_at.duration_since(journal_at).as_secs_f64(),
            source_s = source_at.duration_since(graph_at).as_secs_f64(),
            projection_tail_s = projected_at.duration_since(source_at).as_secs_f64(),
            completion_s = completed.duration_since(projected_at).as_secs_f64(),
            elapsed_s = completed.duration_since(started).as_secs_f64(),
            "Managed publication row work completed"
        );
        Ok((
            receipt,
            projected,
            verified,
            (pins, call_pins, root_cursors, input_proof),
            graph_layer,
            super::reader::ResultOwners::new(step, attempt, spec.clone(), revision, records),
        ))
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
        mut verified: VerifiedPackages,
    ) -> Result<VerifiedPackages> {
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

    pub(super) fn prepare_packets(
        &self,
        reader: &Connection,
        attempt: &Attempt,
        input: &ManagedCommit<'_>,
        evidence: &SourceEvidence,
    ) -> Result<(Vec<Packet>, Step)> {
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
        let mut ids = std::collections::BTreeSet::new();
        for returned in input.returns {
            if !spec.manifest.calls.contains_key(&returned.call) || !ids.insert(returned.call) {
                return Err(Code::Invalid.error("managed returned calls"));
            }
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
            let reset = checked
                .model()
                .change_inputs
                .as_ref()
                .is_some_and(|changes| changes.is_reset(evaluation).unwrap_or(false));
            let expected = input
                .attempt
                .3
                .get(&returned.call)
                .map(|prior| {
                    prior.state(
                        checked.model(),
                        &evaluation.inputs,
                        evaluation.parameters.as_ref(),
                        attempt.request.rebuild || reset,
                    )
                })
                .transpose()?
                .unwrap_or_default();
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
            let mut context = ResultContext::new(
                &attempt.request.id,
                attempt.request.time_utc_ns,
                &evaluation.inputs,
            );
            context.context = evaluation.context.clone();
            context.target = declaration.target.clone();
            context.artifact = declaration.artifact.clone();
            let dependencies = attempt.capture.dependencies.clone();
            let changes = Self::prepare_changes(input, returned, checked.model())?;
            let call_evidence = input
                .attempt
                .5
                .as_ref()
                .map(|frame| {
                    frame.call_evidence(
                        &spec.manifest.input_calls(returned.call)?,
                        &attempt.capture,
                        evidence,
                    )
                })
                .transpose()?;
            let call_evidence = call_evidence.as_ref().unwrap_or(evidence);
            let record = Record {
                instance: spec.id.clone(),
                call: returned.call,
                attempt: attempt.request.id.clone(),
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
            Self::check_change_record(
                reader,
                spec.tenant,
                &record,
                declaration,
                checked.model(),
                attempt,
            )?;
            checked
                .validate_output(returned.output)
                .context(crate::AnalysisContractSnafu)?;
            let checkpoint = returned
                .output
                .checkpoint
                .as_ref()
                .map(|state| {
                    sdk::wire::Checkpoint::encode(state, checked.model())
                        .context(crate::AnalysisContractSnafu)
                })
                .transpose()?;
            packets.push(Packet {
                call: returned.call,
                id: String::new(),
                record,
                checkpoint: ManagedCodec::encode(&checkpoint)
                    .context(crate::ManagedEncodingSnafu)?,
            });
        }
        Self::check_selected(input.selected, input.selected_schema)?;
        let dependencies = attempt.capture.dependencies.clone();
        let step = Step {
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            rows: input.selected.rows(),
            dependencies,
            witnesses: evidence.witnesses.clone(),
            contexts: evidence.contexts.clone(),
            derived: Vec::new(),
            origins: Vec::new(),
            proofs: Vec::new(),
            source: None,
        };
        Ok((packets, step))
    }

    fn bind_packets(
        input: &ManagedCommit<'_>,
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
                input.attempt.1.spec.manifest.calls[&packet.call]
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
            frontier: input.attempt.request().frontier.as_ref().map(|frontier| {
                let mut frontier = frontier.clone();
                frontier.pending = !input.completed;
                frontier
            }),
            instance: input.attempt.1.spec.id.clone(),
            attempt: input.attempt.request().id.clone(),
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

    fn insert_managed(
        &self,
        transaction: &Transaction<'_>,
        spec: &ManagedSpec,
        packet: Packet,
        revision: u64,
        evidence: (&[crate::AnalysisWitnessV1], &[u64]),
    ) -> Result<(u64, Record)> {
        let segments = packet
            .record
            .witnesses
            .iter()
            .map(|witness| {
                let index = evidence
                    .0
                    .binary_search_by(|value| {
                        (&value.identity, value.cursor).cmp(&(&witness.identity, witness.cursor))
                    })
                    .map_err(|_| Code::Invalid.error("managed call witness segment"))?;
                evidence
                    .1
                    .get(index)
                    .copied()
                    .ok_or_else(|| Code::Invalid.error("managed call witness segment"))
            })
            .collect::<Result<Vec<_>>>()?;
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision) VALUES (?, ?, 'managed-package-v1', ?, ?, ?)",
            params![packet.id, spec.tenant.as_slice(), packet.checkpoint, ManagedCodec::encode(&packet.record).context(crate::ManagedEncodingSnafu)?, revision])
            .context(AnalysisDatabaseSnafu { operation: "insert complete managed result" })?;
        Self::insert_managed_edges(
            transaction,
            spec.tenant,
            &packet.id,
            &packet.record.dependencies,
        )?;
        let pins = Self::insert_references(
            transaction,
            &packet.id,
            &packet.record.witnesses,
            &segments,
            &Self::join_contexts(&packet.record.contexts, &packet.record.derived)?,
        )?;
        transaction.execute("UPDATE managed_calls SET state_revision = ?, result_id = ? WHERE tenant_id = ? AND instance_id = ? AND call_id = ?",
            params![revision, packet.id, spec.tenant.as_slice(), spec.id, packet.call])
            .context(AnalysisDatabaseSnafu { operation: "advance independent managed call" })?;
        Ok((pins, packet.record))
    }

    fn insert_managed_step(
        transaction: &Transaction<'_>,
        spec: &ManagedSpec,
        id: &str,
        step: &Step,
        revision: u64,
    ) -> Result<()> {
        transaction.execute("INSERT INTO analysis_results (result_id, tenant_id, processor_id, body, request_meta, commit_revision) VALUES (?, ?, 'managed-definition-v1', ?, ?, ?)",
            params![id, spec.tenant.as_slice(), Vec::<u8>::new(), ManagedCodec::encode(&step).context(crate::ManagedEncodingSnafu)?, revision])
            .context(AnalysisDatabaseSnafu { operation: "insert selected managed relation" })?;
        Self::insert_managed_edges(transaction, spec.tenant, id, &step.dependencies)?;
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
}
