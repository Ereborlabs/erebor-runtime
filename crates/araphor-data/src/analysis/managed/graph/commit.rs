use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_graph::{GraphStore, LayerRequest, PreparedLayers, WriterCut};
use duckdb::{Connection, Transaction, params};
use snafu::ResultExt as _;

use super::ManagedGraphJournal;
use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, ManagedCommit, ManagedReceipt,
    PackageErrorCodeV1 as Code, Result,
};

pub(in crate::analysis::managed) struct PreparedGraph {
    layers: PreparedLayers,
    journals: Vec<Arc<ManagedGraphJournal>>,
    floors: BTreeMap<u64, bool>,
    staged: u64,
    origins: Vec<OriginProof>,
    proofs: BTreeMap<u64, super::super::model::GraphProof>,
    domains: BTreeMap<u64, super::domain::DomainPreparation>,
}

struct OriginProof {
    writer: u64,
    revision: u64,
    graph: u64,
    call: u64,
    result: String,
    restricted: bool,
}

impl PreparedGraph {
    pub(in crate::analysis::managed) fn take_proof(
        &mut self,
        call: u64,
    ) -> Option<super::super::model::GraphProof> {
        self.proofs.remove(&call)
    }

    pub(in crate::analysis::managed) fn check(
        &mut self,
        store: &AnalysisStore,
        connection: &Connection,
        input: &ManagedCommit<'_>,
        derived: &super::super::source::import::PreparedDerived,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<()> {
        let mut owners = super::super::OwnerRead::new(
            store,
            connection,
            input.attempt.1.spec.tenant,
            input.control,
        );
        for journal in &self.journals {
            for (origin, reference) in &journal.work.origins {
                if journal.call.origin(connection, *origin, &mut owners)? != *reference {
                    return Err(Code::Denied.error("Graph historical read authority"));
                }
            }
        }
        for journal in &self.journals {
            let spec = &journal.call.attempt.1.spec;
            let valid:bool=connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_graph_writers writer
                 JOIN managed_graphs owner USING(graph_id) JOIN graph_writers engine USING(writer_id)
                 WHERE writer.writer_id=? AND writer.graph_id=? AND writer.call_id=?
                    AND owner.tenant_id=? AND owner.instance_id=? AND engine.graph_id=writer.graph_id)",
                params![journal.call.writer,journal.call.graph,journal.call.call,spec.tenant.as_slice(),spec.id],|row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check prepared Graph writer" })?;
            if !valid {
                return Err(Code::Denied.error("Graph publication writer"));
            }
        }
        let spec = &self.journals[0].call.attempt.1.spec;
        for origin in &self.origins {
            let valid:bool=connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_graph_results result
                 JOIN managed_graph_writers writer USING(writer_id) JOIN managed_graphs owner USING(graph_id)
                 JOIN graph_layers layer ON layer.layer_id=result.layer_id AND layer.writer_id=result.writer_id
                    AND layer.revision=result.revision
                 JOIN analysis_results stored ON stored.result_id=result.result_id AND stored.commit_revision=result.revision
                    AND stored.tenant_id=owner.tenant_id AND stored.processor_id='managed-package-v1'
                 WHERE result.writer_id=? AND result.revision=? AND result.result_id=? AND result.restricted=?
                    AND writer.graph_id=? AND writer.call_id=? AND owner.tenant_id=? AND owner.instance_id=?)",
                params![origin.writer,origin.revision,origin.result,origin.restricted,origin.graph,origin.call,spec.tenant.as_slice(),spec.id],
                |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check prepared Graph origin" })?;
            if !valid {
                return Err(Code::Denied.error("Graph historical read authority"));
            }
        }
        for journal in &self.journals {
            if let Some(domain) = self.domains.remove(&journal.call.call) {
                let package = &journal.prepared.package;
                let declaration = &journal.call.attempt.1.spec.manifest.calls[&journal.call.call];
                let model = package
                    .exports
                    .iter()
                    .find(|model| model.name == declaration.export)
                    .ok_or_else(|| Code::Invalid.error("domain Graph export"))?;
                if let Some(proof) = store.check_domain_journal(
                    connection,
                    journal,
                    domain,
                    package,
                    model,
                    derived,
                    self.floors[&journal.call.call],
                    memory,
                )? {
                    self.proofs.insert(journal.call.call, proof);
                }
            }
        }
        Ok(())
    }
}

impl AnalysisStore {
    pub(in crate::analysis::managed) fn prepare_graph_journals(
        &self,
        contracts: &[crate::analysis::PackageRevisionV1],
        input: &ManagedCommit<'_>,
        evidence: &super::super::source::SourceEvidence,
        derived: &super::super::source::import::PreparedDerived,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<Option<PreparedGraph>> {
        let started = std::time::Instant::now();
        let mut journals = BTreeMap::<u64, &Arc<ManagedGraphJournal>>::new();
        let mut descriptors = BTreeMap::new();
        for returned in input.returns {
            let declaration = &input.attempt.1.spec.manifest.calls[&returned.call];
            if !descriptors.contains_key(&declaration.package) {
                let contract = contracts
                    .iter()
                    .find(|contract| {
                        contract.tenant_id == input.attempt.1.spec.tenant
                            && contract.package_id == declaration.package.package_id
                            && contract.revision == declaration.package.revision
                    })
                    .ok_or_else(|| Code::Missing.error("managed prepared package"))?;
                memory.charge(
                    contract
                        .descriptor
                        .len()
                        .saturating_mul(12)
                        .saturating_add(12 * size_of::<sdk::Package>()),
                )?;
                let package: sdk::Package = serde_json::from_slice(&contract.descriptor)
                    .context(crate::PackageEncodingSnafu)?;
                if package.id != declaration.package.package_id
                    || package.revision != declaration.package.revision
                {
                    return Err(Code::Invalid.error("managed SDK descriptor pin"));
                }
                descriptors.insert(&declaration.package, package);
            }
            let package = &descriptors[&declaration.package];
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
                        || journals.insert(returned.call, journal).is_some()
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
        let collected_at = std::time::Instant::now();
        let mut work = [std::time::Duration::ZERO; 6];
        let mut cuts = Vec::new();
        let mut relations = BTreeMap::new();
        let mut ordered = Vec::new();
        let mut floors = BTreeMap::new();
        let mut origins = Vec::new();
        let proofs = BTreeMap::new();
        let mut domains = BTreeMap::new();
        for call in input.attempt.1.spec.manifest.order()? {
            let Some(journal) = journals.get(&call) else {
                continue;
            };
            let linked_at = std::time::Instant::now();
            let manifest = &input.attempt.1.spec.manifest;
            let mut ancestors = std::collections::BTreeSet::new();
            let mut pending = manifest.calls[&call]
                .dependencies
                .iter()
                .copied()
                .collect::<Vec<_>>();
            while let Some(id) = pending.pop() {
                if ancestors.insert(id) {
                    pending.extend(&manifest.calls[&id].dependencies);
                }
            }
            let order = manifest.order()?;
            let mut position = 0;
            for prior in &journal.predecessors {
                let next = order
                    .iter()
                    .position(|id| *id == prior.call.call)
                    .ok_or_else(|| Code::Invalid.error("Graph predecessor call"))?;
                if !ancestors.contains(&prior.call.call)
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
                    .any(|candidate| Arc::ptr_eq(candidate, prior))
                    || !journals
                        .get(id)
                        .is_some_and(|actual| Arc::ptr_eq(actual, prior))
                {
                    return Err(Code::Denied.error("Graph pending read authority"));
                }
            }
            let origin_at = std::time::Instant::now();
            work[0] += origin_at.duration_since(linked_at);
            for (origin, reference) in &journal.work.origins {
                let actual = self
                    .managed_results
                    .graph_origin(input.attempt.1.spec.tenant, origin.writer, origin.revision)?
                    .ok_or_else(|| Code::Missing.error("Graph result origin"))?;
                if actual.graph != journal.call.graph
                    || actual.result != reference.result_id
                    || actual.revision != reference.commit_revision
                {
                    return Err(Code::Denied.error("Graph historical read authority"));
                }
            }
            let origin_time = origin_at.elapsed();
            work[5] += origin_time;
            erebor_telemetry::debug!(stage="graph_origin_timing",instance_id=%input.attempt.1.spec.id,
                cut_revision=input.attempt.captured_revision(),call_id=call,origins=journal.work.origins.len(),
                elapsed_s=origin_time.as_secs_f64(),"Graph preparation origin validation completed");
            let reads_at = std::time::Instant::now();
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
            let disclosure_at = std::time::Instant::now();
            work[0] += disclosure_at.duration_since(reads_at);
            let contexts =
                super::domain::ContextInputs::capture(self, journal, evidence, derived, memory)?;
            let mut floor = contexts.restricted();
            floor |= derived
                .values(call)
                .any(|value| value.sensitivity == crate::ContextSensitivityV1::HostRestricted);
            for (origin, reference) in &journal.work.origins {
                memory.charge(
                    reference
                        .result_id
                        .capacity()
                        .checked_mul(4)
                        .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<OriginProof>()))
                        .ok_or_else(|| Code::Limit.error("Graph origin proof memory"))?,
                )?;
                let actual = self
                    .managed_results
                    .graph_origin(input.attempt.1.spec.tenant, origin.writer, origin.revision)?
                    .ok_or_else(|| Code::Missing.error("Graph result origin"))?;
                let restricted = actual.restricted;
                let writer_call = actual.call;
                floor |= restricted;
                origins.push(OriginProof {
                    writer: origin.writer,
                    revision: origin.revision,
                    graph: journal.call.graph,
                    call: writer_call,
                    result: reference.result_id.clone(),
                    restricted,
                });
            }
            for id in journal.work.pending.keys() {
                floor |= *floors
                    .get(id)
                    .ok_or_else(|| Code::Denied.error("Graph predecessor disclosure"))?;
            }
            floors.insert(call, floor);
            let contract_at = std::time::Instant::now();
            work[1] += contract_at.duration_since(disclosure_at);
            let declaration = &input.attempt.1.spec.manifest.calls[&call];
            let package = &journal.prepared.package;
            let model = package
                .exports
                .iter()
                .find(|model| model.name == declaration.export)
                .ok_or_else(|| Code::Invalid.error("domain Graph export"))?;
            let domain_at = std::time::Instant::now();
            work[2] += domain_at.duration_since(contract_at);
            if let Some(domain) =
                self.prepare_domain_journal(journal, package, model, contexts, memory)?
            {
                domains.insert(call, domain);
            }
            let relations_at = std::time::Instant::now();
            work[3] += relations_at.duration_since(domain_at);
            for relation in &journal.call.spec.relations {
                relations.insert(journal.call.relations[&relation.name], relation.engine());
            }
            cuts.push(WriterCut {
                writer: journal.call.writer,
                parent: journal.call.head,
                revision: input.attempt.captured_revision(),
            });
            ordered.push(&journal.work.journal);
            work[4] += relations_at.elapsed();
        }
        let staged_at = std::time::Instant::now();
        let staged = ordered
            .iter()
            .flat_map(|journal| journal.batches())
            .try_fold(0u64, |count, staged| {
                let rows = match staged {
                    araphor_graph::Staged::Clear { batch, .. }
                    | araphor_graph::Staged::Edits { batch, .. } => batch.num_rows(),
                };
                count
                    .checked_add(rows as u64)
                    .ok_or_else(|| Code::Limit.error("Graph staged row count"))
            })?;
        let layers_at = std::time::Instant::now();
        work[4] += layers_at.duration_since(staged_at);
        let views = journals
            .values()
            .map(|journal| (journal.call.writer, &journal.prepared.view))
            .collect::<BTreeMap<_, _>>();
        let layers = GraphStore::prepare_layers(
            &views,
            &cuts,
            &ordered,
            &relations,
            |writer, bytes, total| {
                let journal = journals
                    .values()
                    .find(|journal| journal.call.writer == writer)
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Denied.error("Graph commit budget writer"),
                        )
                    })?;
                memory.check().map_err(araphor_graph::Error::backend)?;
                if total > journal.budget.limit() {
                    return Err(araphor_graph::Error::backend(
                        Code::Limit.error("Graph commit scratch memory"),
                    ));
                }
                if bytes == 0 {
                    return Ok(None);
                }
                memory
                    .reserve(bytes)
                    .map(Some)
                    .map_err(araphor_graph::Error::backend)
            },
        )?;
        let owned_at = std::time::Instant::now();
        memory.charge(
            journals
                .len()
                .checked_mul(12 * std::mem::size_of::<Arc<ManagedGraphJournal>>())
                .ok_or_else(|| Code::Limit.error("Graph preparation metadata"))?,
        )?;
        let journals: Vec<_> = input
            .attempt
            .1
            .spec
            .manifest
            .order()?
            .into_iter()
            .filter_map(|call| journals.get(&call).map(|journal| Arc::clone(journal)))
            .collect();
        let completed = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "graph_prepare_timing", instance_id = %input.attempt.1.spec.id,
            cut_revision = input.attempt.captured_revision(), journals = journals.len(), staged_rows = staged,
            contracts_s = collected_at.duration_since(started).as_secs_f64(),
            linkage_s = work[0].as_secs_f64(), origins_s = work[5].as_secs_f64(),
            disclosure_s = work[1].as_secs_f64(), models_s = work[2].as_secs_f64(),
            domain_s = work[3].as_secs_f64(), metadata_s = work[4].as_secs_f64(),
            layers_s = owned_at.duration_since(layers_at).as_secs_f64(),
            ownership_s = completed.duration_since(owned_at).as_secs_f64(),
            elapsed_s = completed.duration_since(started).as_secs_f64(),
            "Graph layer preparation completed"
        );
        Ok(Some(PreparedGraph {
            layers,
            journals,
            floors,
            staged,
            origins,
            proofs,
            domains,
        }))
    }

    pub(in crate::analysis::managed) fn commit_graph_journals(
        &self,
        connection: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        revision: u64,
        prepared: Option<PreparedGraph>,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<(
        Vec<&'static str>,
        (u64, u64, u64),
        Option<araphor_graph::PendingLayer>,
        Vec<super::super::reader::GraphOrigin>,
    )> {
        let started = std::time::Instant::now();
        let Some(PreparedGraph {
            layers,
            journals,
            floors,
            staged,
            origins: _,
            proofs: _,
            domains: _,
        }) = prepared
        else {
            return Ok((Vec::new(), (0, 0, 0), None, Vec::new()));
        };
        memory.charge(
            journals
                .len()
                .checked_mul(12 * std::mem::size_of::<super::super::reader::GraphOrigin>())
                .ok_or_else(|| Code::Limit.error("Graph origin metadata"))?,
        )?;
        let mut requests = Vec::new();
        let mut origins = Vec::with_capacity(journals.len());
        for journal in &journals {
            memory.check()?;
            let call = journal.call.call;
            for (origin, reference) in &journal.work.origins {
                connection
                    .execute(
                        "INSERT INTO managed_graph_reads VALUES (?,?,?,?)",
                        params![
                            receipt.results[&call].result_id,
                            origin.writer,
                            origin.revision,
                            reference.result_id
                        ],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "pin Graph historical read",
                    })?;
            }
            let mut append =
                connection
                    .appender("managed_graph_row_reads")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph read row pins",
                    })?;
            for row in &journal.work.reads {
                append
                    .append_row(params![
                        receipt.results[&call].result_id,
                        row.relation,
                        row.writer,
                        row.owner,
                        row.key,
                        row.revision
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph read row pin",
                    })?;
            }
            append.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph read row pins",
            })?;
            let layer = connection
                .query_row("SELECT nextval('managed_graph_layers_seq')", [], |row| {
                    row.get(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "allocate managed Graph layer",
                })?;
            requests.push(LayerRequest {
                writer: journal.call.writer,
                layer,
                parent: journal.call.head,
            });
        }
        let prepared = std::time::Instant::now();
        let (work, layer) = self
            .graph_engine
            .begin_layers(connection, revision, &requests)?
            .apply_prepared(layers, |writer, bytes, total| {
                let journal = journals
                    .iter()
                    .find(|journal| journal.call.writer == writer)
                    .ok_or_else(|| {
                        araphor_graph::Error::backend(
                            Code::Denied.error("Graph commit budget writer"),
                        )
                    })?;
                memory.check().map_err(araphor_graph::Error::backend)?;
                if total > journal.budget.limit() {
                    return Err(araphor_graph::Error::backend(
                        Code::Limit.error("Graph commit scratch memory"),
                    ));
                }
                if bytes == 0 {
                    return Ok(None);
                }
                memory
                    .reserve(bytes)
                    .map(Some)
                    .map_err(araphor_graph::Error::backend)
            })?;
        let applied = std::time::Instant::now();
        let (inserted, closed) =
            work.values()
                .try_fold((0u64, 0u64), |(inserted, closed), (add, remove)| {
                    Ok::<_, crate::Error>((
                        inserted
                            .checked_add(*add)
                            .ok_or_else(|| Code::Limit.error("Graph inserted row count"))?,
                        closed
                            .checked_add(*remove)
                            .ok_or_else(|| Code::Limit.error("Graph closed row count"))?,
                    ))
                })?;
        for (request, journal) in requests.iter().zip(&journals) {
            let call = journal.call.call;
            connection
                .execute(
                    "INSERT INTO managed_graph_results VALUES (?,?,?,?,?)",
                    params![
                        request.writer,
                        request.layer,
                        revision,
                        receipt.results[&call].result_id,
                        floors[&call]
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "attribute managed Graph layer",
                })?;
            memory.charge(
                journal
                    .work
                    .reads
                    .len()
                    .checked_mul(12 * std::mem::size_of::<super::super::reader::GraphRead>())
                    .ok_or_else(|| Code::Limit.error("Graph read metadata"))?,
            )?;
            let mut reads = Vec::with_capacity(journal.work.reads.len());
            for row in &journal.work.reads {
                let reference = &journal.work.origins[&araphor_graph::ReadOrigin {
                    writer: row.writer,
                    revision: row.revision,
                }];
                memory.charge(4 * (row.owner.len() + row.key.len() + reference.result_id.len()))?;
                reads.push(super::super::reader::GraphRead {
                    relation: row.relation,
                    writer: row.writer,
                    revision: row.revision,
                    owner: row.owner.clone(),
                    key: row.key.clone(),
                    producer: reference.result_id.clone(),
                });
            }
            reads.sort_by_key(|row| (row.revision, row.writer));
            let facts = super::super::reader::GraphOrigin::read_facts(
                connection,
                input.attempt.1.spec.tenant,
                &receipt.results[&call].result_id,
                &mut |bytes| memory.charge(bytes),
            )?;
            origins.push(super::super::reader::GraphOrigin {
                tenant: input.attempt.1.spec.tenant,
                graph: journal.call.graph,
                result: receipt.results[&call].result_id.clone(),
                writer: request.writer,
                revision,
                restricted: floors[&call],
                call,
                reads,
                facts,
            });
            Self::check_graph_rows(
                connection,
                &receipt.results[&call].result_id,
                input.attempt.captured_revision(),
            )?;
        }
        erebor_telemetry::debug!(
            stage = "graph_journal_timing", instance_id = %input.attempt.instance().spec.id,
            cut_revision = input.attempt.captured_revision(), publication_revision = revision,
            call_count = journals.len(), staged_rows = staged, inserted_rows = inserted, closed_rows = closed,
            prepare_s = prepared.duration_since(started).as_secs_f64(),
            apply_s = applied.duration_since(prepared).as_secs_f64(),
            pins_s = applied.elapsed().as_secs_f64(), elapsed_s = started.elapsed().as_secs_f64(),
            "Graph journal commit completed"
        );
        Ok((
            vec![
                "graph_layers",
                "graph_members",
                "managed_graph_results",
                "managed_graph_reads",
                "managed_graph_row_reads",
            ],
            (staged, inserted, closed),
            Some(layer),
            origins,
        ))
    }
}
