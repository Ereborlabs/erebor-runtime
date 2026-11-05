use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_graph::{GraphStore, LayerRequest, PreparedLayers, WriterCut};
use duckdb::{params, Connection, Transaction};
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

    pub(in crate::analysis::managed) fn check(&self, connection: &Connection) -> Result<()> {
        self.layers.check_parents(connection)?;
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
        Ok(())
    }
}

impl AnalysisStore {
    pub(in crate::analysis::managed) fn prepare_graph_journals(
        &self,
        connection: &Connection,
        input: &ManagedCommit<'_>,
        evidence: &super::super::source::SourceEvidence,
        derived: &super::super::source::import::PreparedDerived,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<Option<PreparedGraph>> {
        let mut journals = BTreeMap::<u64, &Arc<ManagedGraphJournal>>::new();
        for returned in input.returns {
            let declaration = &input.attempt.1.spec.manifest.calls[&returned.call];
            let package =
                Self::managed_contract(connection, input.attempt.1.spec.tenant, declaration)?;
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
                (Some(spec), Some(journal)) if *spec == journal.call.spec => {
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
        let mut cuts = Vec::new();
        let mut relations = BTreeMap::new();
        let mut ordered = Vec::new();
        let mut floors = BTreeMap::new();
        let mut origins = Vec::new();
        let mut proofs = BTreeMap::new();
        let mut owners = super::super::OwnerRead::new(
            self,
            connection,
            input.attempt.1.spec.tenant,
            input.control,
        );
        for call in input.attempt.1.spec.manifest.order()? {
            let Some(journal) = journals.get(&call) else {
                continue;
            };
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
            for (origin, reference) in &journal.work.origins {
                if journal.call.origin(connection, *origin, &mut owners)? != *reference {
                    return Err(Code::Denied.error("Graph historical read authority"));
                }
            }
            erebor_telemetry::debug!(stage="graph_origin_timing",instance_id=%input.attempt.1.spec.id,
                cut_revision=input.attempt.captured_revision(),call_id=call,origins=journal.work.origins.len(),
                elapsed_s=origin_at.elapsed().as_secs_f64(),"Graph preparation origin validation completed");
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
            let contexts = journal
                .call
                .attempt
                .5
                .as_ref()
                .map(|source| source.call_contexts(&journal.call.input_calls()))
                .transpose()?;
            let contexts = Self::join_contexts(
                contexts.as_deref().unwrap_or(&evidence.contexts),
                &derived.contexts(call),
            )?;
            let mut floor = Self::graph_restricted(connection, &contexts)?;
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
                let (restricted,writer_call):(bool,u64)=connection.query_row(
                    "SELECT result.restricted,writer.call_id FROM managed_graph_results result
                     JOIN managed_graph_writers writer USING(writer_id) WHERE result.writer_id=? AND result.revision=?",
                    params![origin.writer,origin.revision],|row| Ok((row.get(0)?,row.get(1)?)),
                ).context(AnalysisDatabaseSnafu { operation:"read Graph origin disclosure" })?;
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
            let declaration = &input.attempt.1.spec.manifest.calls[&call];
            let package =
                Self::managed_contract(connection, input.attempt.1.spec.tenant, declaration)?;
            let model = package
                .exports
                .iter()
                .find(|model| model.name == declaration.export)
                .ok_or_else(|| Code::Invalid.error("domain Graph export"))?;
            if let Some(proof) = self.check_domain_journal(
                connection, journal, &package, model, derived, floor, memory,
            )? {
                proofs.insert(call, proof);
            }
            for relation in &journal.call.spec.relations {
                relations.insert(journal.call.relations[&relation.name], relation.engine());
            }
            cuts.push(WriterCut {
                writer: journal.call.writer,
                parent: journal.call.head,
                revision: input.attempt.captured_revision(),
            });
            ordered.push(&journal.work.journal);
        }
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
        let layers = GraphStore::prepare_layers(
            connection,
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
        memory.charge(
            journals
                .len()
                .checked_mul(12 * std::mem::size_of::<Arc<ManagedGraphJournal>>())
                .ok_or_else(|| Code::Limit.error("Graph preparation metadata"))?,
        )?;
        let journals = input
            .attempt
            .1
            .spec
            .manifest
            .order()?
            .into_iter()
            .filter_map(|call| journals.get(&call).map(|journal| Arc::clone(journal)))
            .collect();
        Ok(Some(PreparedGraph {
            layers,
            journals,
            floors,
            staged,
            origins,
            proofs,
        }))
    }

    pub(in crate::analysis::managed) fn commit_graph_journals(
        &self,
        connection: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        revision: u64,
        prepared: Option<PreparedGraph>,
        memory: &super::super::budget::PreparedMemory<'_>,
    ) -> Result<(
        Vec<&'static str>,
        (u64, u64, u64),
        Option<araphor_graph::PendingLayer>,
    )> {
        let started = std::time::Instant::now();
        let Some(PreparedGraph {
            layers,
            journals,
            floors,
            staged,
            origins: _,
            proofs: _,
        }) = prepared
        else {
            return Ok((Vec::new(), (0, 0, 0), None));
        };
        let mut requests = Vec::new();
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
        ))
    }

    fn graph_restricted(
        connection: &Connection,
        contexts: &[crate::AnalysisContextRefV1],
    ) -> Result<bool> {
        if contexts.is_empty() {
            return Ok(false);
        }
        connection.execute_batch("CREATE TEMP TABLE managed_graph_contexts (version_key BLOB PRIMARY KEY,revision UBIGINT)")
            .context(AnalysisDatabaseSnafu { operation: "create Graph disclosure keys" })?;
        let result = (|| {
            {
                let mut appender = connection.appender("managed_graph_contexts").context(
                    AnalysisDatabaseSnafu {
                        operation: "open Graph disclosure keys",
                    },
                )?;
                for reference in contexts {
                    appender
                        .append_row(params![
                            crate::analysis::context::version_key(&reference.key)?,
                            reference.commit_revision
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "append Graph disclosure key",
                        })?;
                }
                appender.flush().context(AnalysisDatabaseSnafu {
                    operation: "flush Graph disclosure keys",
                })?;
            }
            let sensitivity: &str = crate::ContextSensitivityV1::HostRestricted.into();
            let (valid,restricted): (bool,bool) = connection.query_row(
                "SELECT bool_and(c.version_key IS NOT NULL AND c.commit_revision=input.revision),
                    COALESCE(bool_or(c.sensitivity=?),false)
                 FROM managed_graph_contexts input LEFT JOIN context_versions c USING(version_key)",
                params![sensitivity], |row| Ok((row.get(0)?,row.get(1)?)),
            ).context(AnalysisDatabaseSnafu { operation: "read canonical Graph disclosure" })?;
            if !valid {
                return Err(Code::Denied.error("Graph disclosure context"));
            }
            Ok(restricted)
        })();
        let cleanup = connection
            .execute_batch("DROP TABLE managed_graph_contexts")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph disclosure keys",
            });
        let floor = result?;
        cleanup?;
        Ok(floor)
    }
}
