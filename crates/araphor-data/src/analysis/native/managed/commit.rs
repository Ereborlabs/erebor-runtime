use std::{collections::BTreeMap, sync::Arc};

use araphor_analysis_sdk as sdk;

use super::{
    attempts::Attempts,
    results::{ResultBody, StoredResult},
    CallHead, InstanceRecord, ManagedGraphJournal, PreparedManagedCommit, Records,
};
use crate::analysis::PackageResultRefV1;
use crate::analysis::{
    managed::ManagedExecution,
    native::{DataWrite, NativeStore},
};
use crate::{
    AnalysisReadControl, ManagedAttempt, ManagedBudget, ManagedChanges, ManagedDestination,
    ManagedReceipt, PackageErrorCodeV1 as Code, Result,
};

pub struct ManagedReturn<'a> {
    pub call: u64,
    pub evaluation: &'a sdk::Evaluation,
    pub output: &'a sdk::Output,
    pub changes: Option<&'a ManagedChanges>,
    pub graph: Option<&'a Arc<ManagedGraphJournal>>,
    pub retained: Option<&'a PackageResultRefV1>,
}

pub struct ManagedCommit<'a> {
    pub control: &'a AnalysisReadControl,
    pub budget: &'a dyn ManagedBudget,
    pub attempt: &'a ManagedAttempt,
    pub completed: bool,
    pub now_utc_ns: u64,
    pub returns: &'a [ManagedReturn<'a>],
    pub selected: &'a sdk::Dataset,
    pub selected_schema: &'a sdk::Schema,
}

impl NativeStore {
    pub fn commit_managed(
        &self,
        mut prepared: PreparedManagedCommit<'_>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedReceipt> {
        let input = prepared.input;
        let spec = &input.attempt.1.spec;
        if spec.destination != ManagedDestination::Selected {
            return Err(Code::Unsupported.error("native managed destination"));
        }
        prepared.memory.check()?;
        let mut tx = self.write()?;
        let current = self.live_attempt(input.attempt, input.control)?;
        if input.now_utc_ns < input.attempt.request().time_utc_ns {
            return Err(Code::Invalid.error("managed publication time"));
        }
        for (call, contract) in &prepared.contracts {
            let actual = current.managed_contract_charged(
                spec,
                &spec.manifest.calls[call],
                &mut |bytes| prepared.memory.charge(bytes),
            )?;
            if *contract != actual {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        for reference in &prepared.evidence.contexts {
            input.control.check()?;
            if current
                .context_charged(&reference.key, &mut |bytes| prepared.memory.charge(bytes))?
                .is_none_or(|(_, revision)| revision != reference.commit_revision)
            {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        if prepared.evidence.witnesses.iter().any(|witness| {
            witness.identity.tenant() != spec.tenant
                || witness.cursor == 0
                || witness.expires_utc_ns <= input.now_utc_ns
        }) {
            return Err(Code::Incomplete.error("managed witness lifetime"));
        }
        let segments = self.resolve_witnesses(&prepared.evidence.witnesses, tx.revision - 1)?;
        let (mut packets, mut step, receipt) = ManagedReceipt::bind(
            input.attempt,
            input.completed,
            prepared.packets,
            prepared.step,
            tx.revision,
        );
        let mut references = BTreeMap::new();
        for fact in &prepared.derived.facts {
            let reference = tx.context(fact.value(), None)?;
            references.insert(reference.key.clone(), reference);
        }
        let imported = prepared.derived.bind(&references)?;
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
        let (owner, mut instance) = tx.complete_managed_attempt(input.attempt, &receipt)?;
        if input.attempt.switches_version() {
            for call in instance.spec.manifest.calls.keys() {
                tx.transaction
                    .remove(InstanceRecord::call_key(owner, *call));
            }
            for (call, prior) in &input.attempt.0.capture.prior {
                Records::stage(
                    &mut tx.transaction,
                    InstanceRecord::call_key(owner, *call),
                    Records::named(&CallHead {
                        revision: prior.as_ref().map_or(0, |prior| prior.commit_revision),
                        result: prior.as_ref().map(|prior| prior.result_id.clone()),
                    })?,
                );
            }
        }
        let mut results = BTreeMap::new();
        let mut records = Vec::with_capacity(packets.len());
        for packet in packets {
            let call = packet.call;
            let name = packet.id.clone();
            let (id, record) = tx.stage_call(spec.tenant, packet)?;
            records.push((id, record));
            Records::stage(
                &mut tx.transaction,
                InstanceRecord::call_key(owner, call),
                Records::named(&CallHead {
                    revision: tx.revision,
                    result: Some(name),
                })?,
            );
            results.insert(call, id);
        }
        let selected = StoredResult {
            tenant: spec.tenant,
            id: receipt.selected.result_id.clone(),
            revision: tx.revision,
            body: ResultBody::Selected(step),
        };
        let selected_id = tx.stage_result(&selected)?;
        for (id, record) in &records {
            tx.stage_result_references(
                spec.tenant,
                *id,
                &record.witnesses,
                &crate::AnalysisStore::join_contexts(&record.contexts, &record.derived)?,
                &record.dependencies,
                &record.origins,
                imported.resolved(record.call),
                (&prepared.evidence.witnesses, &segments),
                &mut prepared.memory,
            )?;
        }
        let ResultBody::Selected(step) = &selected.body else {
            return Err(Code::Invalid.error("managed selected body"));
        };
        tx.stage_result_references(
            spec.tenant,
            selected_id,
            &step.witnesses,
            &crate::AnalysisStore::join_contexts(&step.contexts, &step.derived)?,
            &step.dependencies,
            &step.origins,
            imported.selected_imports(),
            (&prepared.evidence.witnesses, &segments),
            &mut prepared.memory,
        )?;
        let pending = prepared
            .graph
            .take()
            .map(|graph| graph.stage(&mut tx, input, &receipt, &results, &mut prepared.memory))
            .transpose()?;
        tx.publish_managed_graph(input, &receipt, selected_id, &results, &mut prepared.memory)?;
        instance.spec = spec.clone();
        if instance.generation != input.attempt.0.capture.generation {
            instance.lifecycle = tx.revision;
        }
        instance.generation = input.attempt.0.capture.generation;
        instance.progress = tx.revision;
        tx.stage_instance(&instance)?;
        tx.transaction.remove(Records::key(b'Y', owner));
        let retained = ManagedExecution::retain(
            input.attempt,
            input.returns.iter().map(|returned| {
                (
                    returned.call,
                    returned.evaluation,
                    returned.output,
                    returned.changes,
                )
            }),
            &receipt,
            std::mem::take(&mut tx.verified),
            None,
        );
        let source_proof = input
            .attempt
            .5
            .as_ref()
            .map(|frame| (Arc::clone(frame), Arc::new(receipt.selected.clone())));
        if let Some((frame, proof)) = &source_proof {
            frame.check_proof(proof)?;
        }
        prepared.memory.check()?;
        check()?;
        tx.commit_published(
            pending
                .as_ref()
                .into_iter()
                .flat_map(|pending| pending.stamps.iter().cloned()),
            || {
                if let Some((frame, proof)) = source_proof {
                    frame.commit_proof(proof);
                }
                if let Some((owner, state)) = retained {
                    owner.promote(state);
                }
            },
        )?;
        Ok(receipt)
    }
}

impl DataWrite<'_> {
    fn complete_managed_attempt(
        &mut self,
        supplied: &ManagedAttempt,
        receipt: &ManagedReceipt,
    ) -> Result<(u64, crate::ManagedInstance)> {
        let spec = &supplied.1.spec;
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed publication owner"))?;
        let (id, mut attempt) =
            Attempts::read(spec.tenant, &spec.id, &supplied.0.request.id, |key| {
                Records::staged(key, &self.transaction)
            })?
            .ok_or_else(|| Code::Missing.error("managed publication attempt"))?;
        if attempt != supplied.0 || receipt.commit_revision != self.revision {
            return crate::AnalysisConflictSnafu.fail();
        }
        let instance = self
            .managed_instance(spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed publication instance"))?;
        attempt.receipt = Some(receipt.clone());
        Records::stage(
            &mut self.transaction,
            Records::key(b'a', id),
            Records::named(&attempt)?,
        );
        self.transaction.remove(
            [
                Attempts::pending(owner, attempt.capture.generation),
                id.to_be_bytes().to_vec(),
            ]
            .concat(),
        );
        self.transaction.insert(
            Attempts::outcome(owner, attempt.capture.generation),
            [self.revision.to_be_bytes(), id.to_be_bytes()].concat(),
        );
        self.transaction
            .insert(Attempts::ended(owner, self.revision), id.to_be_bytes());
        self.dirty = true;
        Ok((owner, instance))
    }
}
