use std :: { collections :: { BTreeMap , BTreeSet } , sync :: Arc } ;

use araphor_analysis_sdk as sdk;
use araphor_graph::native::{Graph, LayerRequest, Pending, Prepared};

use super::{origin::GraphOrigin, ManagedGraphJournal};
use crate :: analysis :: { managed :: { source :: { import :: PreparedDerived , SourceEvidence } , GraphProof , PreparedMemory } , native :: { DataWrite , ManagedCommit , NativeStore } } ;
use crate::{ManagedReceipt, PackageErrorCodeV1 as Code, Result};

pub(in crate::analysis::native::managed) struct PreparedGraph {
    layers: Prepared,
    journals: Vec<Arc<ManagedGraphJournal>>,
    floors: BTreeMap<u64, bool>,
    pub(super) proofs: BTreeMap<u64, GraphProof>,
}

impl NativeStore {
    pub(in crate::analysis::native::managed) fn prepare_graph_journals(
        &self,
        contracts: &BTreeMap<u64, sdk::Package>,
        input: &ManagedCommit<'_>,
        evidence: &SourceEvidence,
        derived: &PreparedDerived,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Option<PreparedGraph>> {
        let mut journals = BTreeMap::new();
        for returned in input.returns {
            let declaration = &input.attempt.1.spec.manifest.calls[&returned.call];
            let package = &contracts[&returned.call];
            let model = package
                .exports
                .iter()
                .find(|model| model.name == declaration.export)
                .ok_or_else(|| Code::Invalid.error("Graph publication export"))?;
            if let Some(reference) = returned.retained {
                if returned.graph.is_some()
                    || input.attempt.prior_result(returned.call) != Some(reference)
                {
                    return Err(Code::Denied.error("Graph retained call"));
                }
                if model.graph.is_some() {
                    return Err(Code::Unsupported.error("retained Graph publication"));
                }
                continue;
            }
            match (&model.graph, returned.graph) {
                (None, None) => continue,
                (Some(spec), Some(journal))
                    if *spec == journal.call.spec && *package == journal.prepared.package =>
                {
                    if !std::ptr::eq(input.attempt, journal.call.attempt.as_ref())
                        || journal.call.call != returned.call
                        || journal.work.journal.writer() != journal.call.writer
                        || journals
                            .insert(returned.call, Arc::clone(journal))
                            .is_some()
                    {
                        return Err(Code::Denied.error("Graph publication authority"));
                    }
                }
                _ => return Err(Code::Denied.error("Graph publication capability")),
            }
        }
        if journals.is_empty() {
            return Ok(None);
        }
        let order = input.attempt.1.spec.manifest.order()?;
        let mut ordered = Vec::new();
        let mut floors = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        let graph = journals
            .values()
            .next()
            .ok_or_else(|| Code::Invalid.error("Graph publication journals"))?
            .call
            .graph;
        for call in &order {
            let Some(journal) = journals.get(call) else {
                continue;
            };
            if journal.call.graph != graph {
                return Err(Code::Denied.error("Graph publication scope"));
            }
            let ancestors = input.attempt.1.spec.manifest.input_calls(*call)?;
            let mut position = 0;
            for prior in &journal.predecessors {
                let next = order
                    .iter()
                    .position(|id| *id == prior.call.call)
                    .ok_or_else(|| Code::Invalid.error("Graph predecessor call"))?;
                if prior.call.call == *call
                    || !ancestors.contains(&prior.call.call)
                    || next < position
                    || !Arc::ptr_eq(&journal.call.attempt, &prior.call.attempt)
                    || journal.call.graph != prior.call.graph
                    || !journals
                        .get(&prior.call.call)
                        .is_some_and(|actual| Arc::ptr_eq(actual, prior))
                {
                    return Err(Code::Denied.error("Graph predecessor publication"));
                }
                position = next + 1;
            }
            for (id, prior) in &journal.work.pending {
                if !journal
                    .predecessors
                    .iter()
                    .any(|actual| Arc::ptr_eq(actual, prior))
                    || !journals
                        .get(id)
                        .is_some_and(|actual| Arc::ptr_eq(actual, prior))
                {
                    return Err(Code::Denied.error("Graph pending read authority"));
                }
            }
            let contexts = journal.domain_contexts(self, evidence, derived, memory)?;
            let mut floor = contexts.restricted()
                || derived
                    .values(*call)
                    .any(|value| value.sensitivity == crate::ContextSensitivityV1::HostRestricted);
            for (origin, reference) in &journal.work.origins {
                memory.check()?;
                let actual = journal
                    .prepared
                    .snapshot
                    .graph_origin(origin.writer, origin.revision)?;
                if actual.graph != graph
                    || actual.instance != input.attempt.1.spec.id
                    || actual.reference != *reference
                {
                    return Err(Code::Denied.error("Graph historical read authority"));
                }
                actual
                    .grant
                    .permitted_by(&input.attempt.1.grant.selection)?;
                floor |= actual.restricted;
            }
            for row in &journal.work.reads {
                if !journal
                    .work
                    .origins
                    .contains_key(&araphor_graph::ReadOrigin {
                        writer: row.writer,
                        revision: row.revision,
                    })
                {
                    return Err(Code::Denied.error("Graph read row origin"));
                }
            }
            for id in journal.work.pending.keys() {
                floor |= *floors
                    .get(id)
                    .ok_or_else(|| Code::Denied.error("Graph predecessor disclosure"))?;
            }
            if let Some(domain) = journal.prepare_domain(contexts, input.control, memory)? {
                if let Some(proof) = journal.check_domain(domain, derived, floor, memory)? {
                    proofs.insert(*call, proof);
                }
            }
            floors.insert(*call, floor);
            ordered.push(Arc::clone(journal));
        }
        let first = ordered
            .first()
            .ok_or_else(|| Code::Invalid.error("Graph publication order"))?;
        let layers = first.prepared.view.prepare(
            &ordered
                .iter()
                .map(|journal| &journal.work.journal)
                .collect::<Vec<_>>(),
            &|writer, bytes, total| {
                let journal = ordered
                    .iter()
                    .find(|journal| journal.call.writer == writer)
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Denied.error("Graph preparation budget writer"),
                        )
                    })?;
                Self::graph_memory(journal, input, memory, bytes, total)
            },
        )?;
        Ok(Some(PreparedGraph {
            layers,
            journals: ordered,
            floors,
            proofs,
        }))
    }

    fn graph_memory(
        journal: &ManagedGraphJournal,
        input: &ManagedCommit<'_>,
        memory: &PreparedMemory<'_>,
        bytes: usize,
        total: usize,
    ) -> araphor_graph::Result<Option<araphor_graph::native::Lease>> {
        input
            .control
            .check()
            .map_err(araphor_graph::Error::backend)?;
        journal
            .budget
            .check()
            .map_err(araphor_graph::Error::backend)?;
        if total > journal.budget.limit() {
            return Err(araphor_graph::Error::backend(
                Code::Limit.error("Graph publication scratch memory"),
            ));
        }
        if bytes == 0 {
            return Ok(None);
        }
        memory
            .reserve(bytes)
            .map(Some)
            .map_err(araphor_graph::Error::backend)
    }
}

impl PreparedGraph {
    pub(in crate::analysis::native::managed) fn take_proof(
        &mut self,
        call: u64,
    ) -> Option<GraphProof> {
        self.proofs.remove(&call)
    }

    pub(in crate::analysis::native::managed) fn stage(
        self,
        tx: &mut DataWrite<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        results: &BTreeMap<u64, u64>,
        memory: &mut PreparedMemory<'_>,
    ) -> Result<Pending> {
        tx.admit_managed_graph(&input.attempt.1.spec, false)?;
        let current = tx.store.view()?;
        let mut requests = Vec::new();
        let mut writers = BTreeSet::new();
        for journal in &self.journals {
            for (origin, reference) in &journal.work.origins {
                let actual = current.graph_origin(origin.writer, origin.revision)?;
                let prepared = journal
                    .prepared
                    .snapshot
                    .graph_origin(origin.writer, origin.revision)?;
                if actual != prepared || actual.reference != *reference {
                    return Err(Code::Denied.error("Graph historical read authority"));
                }
            }
            if !writers.insert(journal.call.writer) {
                return Err(Code::Denied.error("Graph publication duplicate writer"));
            }
            requests.push(LayerRequest {
                writer: journal.call.writer,
                layer: results[&journal.call.call],
                parent: journal.call.head,
            });
        }
        let graph = self.journals[0].call.graph;
        let pending = Graph::new(graph)?.stage(
            &mut tx.transaction,
            tx.revision,
            &requests,
            self.layers,
            &|writer, bytes, total| {
                let journal = self
                    .journals
                    .iter()
                    .find(|journal| journal.call.writer == writer)
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Denied.error("Graph commit budget writer"),
                        )
                    })?;
                NativeStore::graph_memory(journal, input, memory, bytes, total)
            },
        )?;
        for journal in &self.journals {
            let bytes = journal
                .work
                .reads
                .iter()
                .fold(0usize, |bytes, row| {
                    bytes
                        .saturating_add(row.owner.len())
                        .saturating_add(row.key.len())
                        .saturating_add(4 * size_of::<super::transaction::ReadRow>())
                })
                .saturating_add(
                    journal
                        .work
                        .origins
                        .values()
                        .chain(
                            journal
                                .work
                                .pending
                                .keys()
                                .map(|call| &receipt.results[call]),
                        )
                        .map(|reference| reference.result_id.len().saturating_add(256))
                        .sum::<usize>(),
                );
            memory.charge(bytes.saturating_mul(4))?;
            tx.stage_origin(GraphOrigin {
                graph,
                writer: journal.call.writer,
                layer: results[&journal.call.call],
                call: journal.call.call,
                instance: input.attempt.1.spec.id.clone(),
                reference: receipt.results[&journal.call.call].clone(),
                grant: input.attempt.1.grant.clone(),
                restricted: self.floors[&journal.call.call],
                reads: journal
                    .work
                    .origins
                    .iter()
                    .map(|(origin, reference)| (origin.writer, origin.revision, reference.clone()))
                    .collect(),
                rows: journal.work.reads.iter().cloned().collect(),
                pending: journal
                    .work
                    .pending
                    .keys()
                    .map(|call| (*call, receipt.results[call].clone()))
                    .collect(),
            })?;
        }
        tx.project_graph(input, receipt, results, &self.journals, memory)?;
        Ok(pending)
    }
}
