use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;

use super::{graph::PreparedGraph, results::ResultBody, ManagedCommit};
use crate::analysis::managed::{
    source::{import::PreparedDerived, SourceEvidence},
    Packet, PreparedMemory, Step,
};
use crate::analysis::native::{DataView, NativeStore};
use crate::{PackageErrorCodeV1 as Code, Result};

pub struct PreparedManagedCommit<'a> {
    pub(super) input: &'a ManagedCommit<'a>,
    pub(super) evidence: SourceEvidence,
    pub(super) packets: Vec<Packet>,
    pub(super) step: Step,
    pub(super) contracts: BTreeMap<u64, sdk::Package>,
    pub(super) derived: PreparedDerived,
    pub(super) graph: Option<PreparedGraph>,
    pub(super) source: Option<crate::analysis::managed::source::publication::PreparedSource>,
    pub(super) memory: PreparedMemory<'a>,
}

impl<'a> PreparedManagedCommit<'a> {
    pub fn input(&self) -> &'a ManagedCommit<'a> {
        self.input
    }

    pub(in crate::analysis::native) fn contract(&self, call: u64) -> Option<&sdk::Package> {
        self.contracts.get(&call)
    }
}

impl NativeStore {
    pub fn prepare_managed<'a>(
        &self,
        input: &'a ManagedCommit<'a>,
    ) -> Result<PreparedManagedCommit<'a>> {
        if input.now_utc_ns < input.attempt.request().time_utc_ns {
            return Err(Code::Invalid.error("managed publication time"));
        }
        if !input.completed && input.attempt.request().frontier.is_none() {
            return Err(Code::Invalid.error("managed pending frontier"));
        }
        let current = self.live_attempt(input.attempt, input.control)?;
        let mut memory = PreparedMemory::new(input.control, input.budget)?;
        let capture = &input.attempt.0.capture;
        let evidence = match &input.attempt.5 {
            Some(source) => source.freeze_evidence(
                capture,
                input.attempt.request().witness_expiry,
                &mut memory,
            )?,
            None => {
                memory.charge(SourceEvidence::metadata_bytes(
                    capture.witnesses.iter(),
                    capture.contexts.iter(),
                )?)?;
                SourceEvidence {
                    witnesses: capture.witnesses.clone(),
                    contexts: capture.contexts.clone(),
                }
            }
        };
        let source = self.prepare_source(input, &mut memory)?;
        Packet::charge(
            input.attempt,
            input
                .returns
                .iter()
                .map(|returned| (returned.evaluation, returned.output)),
            &evidence,
            &mut memory,
        )?;
        let spec = &input.attempt.1.spec;
        let mut ids = BTreeSet::new();
        for returned in input.returns {
            if !spec.manifest.calls.contains_key(&returned.call) || !ids.insert(returned.call) {
                return Err(Code::Invalid.error("managed returned calls"));
            }
        }
        let mut contracts = BTreeMap::new();
        let mut packets = Vec::new();
        for returned in input.returns {
            let declaration = &spec.manifest.calls[&returned.call];
            let descriptor = current
                .managed_contract_charged(spec, declaration, &mut |bytes| memory.charge(bytes))?;
            let packet = Packet::prepare(
                input.attempt,
                returned.call,
                returned.evaluation,
                returned.output,
                returned.changes,
                &evidence,
                &descriptor,
            )?;
            let model = descriptor
                .exports
                .iter()
                .find(|model| model.name == declaration.export)
                .ok_or_else(|| Code::Missing.error("managed returned model"))?;
            current.check_change_record(
                &packet.record,
                &input.attempt.0,
                declaration,
                model,
                &mut |bytes| memory.charge(bytes),
            )?;
            packets.push(packet);
            contracts.insert(returned.call, descriptor);
        }
        let step = Step::prepare(
            input.attempt,
            &evidence,
            input.selected,
            input.selected_schema,
        )?;
        let derived = PreparedDerived::prepare(
            input.attempt,
            input
                .returns
                .iter()
                .map(|returned| (returned.call, returned.retained.is_some())),
            current.revision(),
            &mut memory,
            |facts, _, memory| current.inspect_facts(facts, &mut |bytes| memory.charge(bytes)),
        )?;
        self.source_origins(
            input.attempt,
            derived.origin_refs(),
            input.control,
            &mut |bytes| memory.charge(bytes),
        )?;
        let graph =
            self.prepare_graph_journals(&contracts, input, &evidence, &derived, &mut memory)?;
        memory.check()?;
        Ok(PreparedManagedCommit {
            input,
            evidence,
            packets,
            step,
            contracts,
            derived,
            graph,
            source,
            memory,
        })
    }
}

impl DataView {
    pub(super) fn check_change_record(
        &self,
        record: &crate::analysis::managed::Record,
        attempt: &crate::analysis::managed::Attempt,
        declaration: &crate::ManagedCall,
        model: &sdk::Model,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<()> {
        let (Some(_), Some(changes)) = (&model.change_inputs, &record.changes) else {
            return if model.change_inputs.is_some() || record.changes.is_some() {
                Err(Code::Invalid.error("managed change contract"))
            } else {
                Ok(())
            };
        };
        if let Some(base) = &changes.base {
            if Some(base)
                != attempt
                    .capture
                    .prior
                    .get(&record.call)
                    .and_then(Option::as_ref)
                || base.commit_revision == 0
                || base.commit_revision >= attempt.registered
            {
                return Err(Code::Conflict.error("managed historical base"));
            }
            let (_, old, owner) = self.result_owner(
                attempt.capture.tenant,
                &base.result_id,
                &crate::AnalysisReadControl::default(),
                charge,
            )?;
            let ResultBody::Call(prior) = old.body else {
                return Err(Code::Invalid.error("managed historical call"));
            };
            if prior.call != record.call
                || prior.instance != record.instance
                || owner.1.spec.manifest.calls.get(&record.call) != Some(declaration)
                || old.revision != base.commit_revision
                || prior.changes.is_none()
            {
                return Err(Code::Invalid.error("managed historical call"));
            }
        }
        Ok(())
    }
}
