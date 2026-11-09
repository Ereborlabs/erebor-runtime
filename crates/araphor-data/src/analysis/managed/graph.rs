use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use duckdb::{OptionalExt as _, Transaction, params};
use snafu::ResultExt as _;

use super::codec::ManagedCodec;
use super::{ManagedAttempt, ManagedBudget, ManagedSpec};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

#[derive(Clone)]
pub(super) struct ManagedGraphCall {
    pub(super) attempt: Arc<ManagedAttempt>,
    pub(super) call: u64,
    pub(super) graph: u64,
    pub(super) writer: u64,
    pub(super) head: Option<u64>,
    pub(super) spec: sdk::GraphSpec,
    pub(super) relations: BTreeMap<String, u64>,
}

mod admission;
mod authority;
mod commit;
pub(in crate::analysis::managed) use commit::PreparedGraph;
mod domain;
pub(in crate::analysis) mod projection;
mod proof;
mod provenance;
mod publication;
mod read;
mod recovery;
mod transaction;
pub use transaction::{ManagedGraphJournal, ManagedGraphTransaction};

impl AnalysisStore {
    pub(super) fn admit_graph(
        &self,
        connection: &Transaction<'_>,
        spec: &ManagedSpec,
    ) -> Result<()> {
        let admission = spec.graph_declarations(|call| Self::managed_contract(connection, spec.tenant, call))?;
        let declarations = admission.relations;
        let calls = admission.calls;
        if calls.is_empty() {
            return Ok(());
        }
        let graph: Option<u64> = connection
            .query_row(
                "SELECT graph_id FROM managed_graphs WHERE tenant_id=? AND instance_id=?",
                params![spec.tenant.as_slice(), spec.id],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read managed Graph identity",
            })?;
        let graph = match graph {
            Some(graph) => graph,
            None => {
                let graph: u64 = connection
                    .query_row("SELECT nextval('managed_graphs_seq')", [], |row| row.get(0))
                    .context(AnalysisDatabaseSnafu {
                        operation: "allocate managed Graph identity",
                    })?;
                connection
                    .execute(
                        "INSERT INTO managed_graphs VALUES (?,?,?)",
                        params![graph, spec.tenant.as_slice(), spec.id],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "register managed Graph identity",
                    })?;
                graph
            }
        };
        let mut relations = BTreeMap::new();
        for declaration in declarations
            .values()
            .filter(|value| value.kind == sdk::GraphKind::Node)
            .chain(
                declarations
                    .values()
                    .filter(|value| value.kind != sdk::GraphKind::Node),
            )
        {
            let prior: Option<(u64,Vec<u8>)> = connection.query_row(
                "SELECT relation_id,contract FROM managed_graph_relations WHERE graph_id=? AND relation_name=?",
                params![graph, declaration.name], |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional().context(AnalysisDatabaseSnafu { operation: "read managed Graph relation" })?;
            let id = match prior {
                Some((id, bytes)) => {
                    let prior: sdk::GraphRelation =
                        ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
                    if prior != *declaration {
                        return Err(Code::Conflict.error("Graph relation declaration changed"));
                    }
                    id
                }
                None => {
                    let id: u64 = connection
                        .query_row("SELECT nextval('managed_graph_relations_seq')", [], |row| {
                            row.get(0)
                        })
                        .context(AnalysisDatabaseSnafu {
                            operation: "allocate managed Graph relation",
                        })?;
                    let endpoints = match &declaration.kind {
                        sdk::GraphKind::Node => None,
                        sdk::GraphKind::Edge { from, to } => Some((
                            *relations
                                .get(from)
                                .ok_or_else(|| Code::Invalid.error("Graph source relation"))?,
                            *relations
                                .get(to)
                                .ok_or_else(|| Code::Invalid.error("Graph target relation"))?,
                        )),
                    };
                    self.graph_engine.create_relation(
                        connection,
                        graph,
                        id,
                        &declaration.engine(),
                        endpoints,
                    )?;
                    connection
                        .execute(
                            "INSERT INTO managed_graph_relations VALUES (?,?,?,?)",
                            params![
                                id,
                                graph,
                                declaration.name,
                                ManagedCodec::encode(declaration)
                                    .context(crate::ManagedEncodingSnafu)?
                            ],
                        )
                        .context(AnalysisDatabaseSnafu {
                            operation: "register managed Graph relation",
                        })?;
                    id
                }
            };
            relations.insert(declaration.name.clone(), id);
        }
        for call in calls {
            let prior: Option<u64> = connection
                .query_row(
                    "SELECT writer_id FROM managed_graph_writers WHERE graph_id=? AND call_id=?",
                    params![graph, call],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read managed Graph writer",
                })?;
            if prior.is_none() {
                let writer: u64 = connection
                    .query_row("SELECT nextval('managed_graph_writers_seq')", [], |row| {
                        row.get(0)
                    })
                    .context(AnalysisDatabaseSnafu {
                        operation: "allocate managed Graph writer",
                    })?;
                connection
                    .execute(
                        "INSERT INTO managed_graph_writers VALUES (?,?,?)",
                        params![writer, graph, call],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "register managed Graph writer",
                    })?;
                connection
                    .execute(
                        "INSERT INTO graph_writers VALUES (?,?)",
                        params![writer, graph],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "register Graph engine writer",
                    })?;
            }
        }
        Ok(())
    }

    fn graph_call_from(
        &self,
        connection: &duckdb::Connection,
        attempt: Arc<ManagedAttempt>,
        call: u64,
        model: &sdk::Model,
        control: &AnalysisReadControl,
    ) -> Result<(ManagedGraphCall, sdk::Package)> {
        self.check_managed_claim(&attempt)?;
        if attempt.receipt().is_some() || attempt.terminal().is_some() {
            return Err(Code::Conflict.error("Graph attempt completed"));
        }
        self.check_managed_capture(
            connection,
            &attempt.0.capture,
            attempt.request().time_utc_ns,
            (&attempt.0.capture.witnesses, &attempt.0.capture.contexts),
            Default::default(),
        )?;
        let declaration = attempt
            .1
            .spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Denied.error("Graph actual call"))?;
        let package = Self::managed_contract(connection, attempt.1.spec.tenant, declaration)?;
        let canonical = package
            .exports
            .iter()
            .find(|export| export.name == declaration.export)
            .ok_or_else(|| Code::Invalid.error("Graph actual export"))?;
        if canonical.name != model.name || canonical.graph != model.graph {
            return Err(Code::Denied.error("Graph actual relation contract"));
        }
        let spec = model
            .graph
            .clone()
            .ok_or_else(|| Code::Denied.error("Graph invocation capability"))?;
        let (graph, writer): (u64, u64) = connection
            .query_row(
                "SELECT graph.graph_id,writer.writer_id FROM managed_graphs graph
             JOIN managed_graph_writers writer USING(graph_id)
             WHERE graph.tenant_id=? AND graph.instance_id=? AND writer.call_id=?",
                params![attempt.1.spec.tenant.as_slice(), attempt.1.spec.id, call],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bind managed Graph writer",
            })?;
        let head = connection.query_row(
            "SELECT layer_id FROM graph_layers WHERE writer_id=? AND revision<=? ORDER BY revision DESC LIMIT 1",
            params![writer,attempt.captured_revision()], |row| row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation: "bind managed Graph head" })?;
        let mut relations = BTreeMap::new();
        for relation in &spec.relations {
            let (id,bytes): (u64,Vec<u8>) = connection.query_row(
                "SELECT relation_id,contract FROM managed_graph_relations WHERE graph_id=? AND relation_name=?",
                params![graph,relation.name], |row| Ok((row.get(0)?,row.get(1)?)),
            ).context(AnalysisDatabaseSnafu { operation: "bind managed Graph relation" })?;
            let canonical: sdk::GraphRelation =
                ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
            if canonical != *relation {
                return Err(Code::Denied.error("Graph admitted relation contract"));
            }
            relations.insert(relation.name.clone(), id);
        }
        Ok((
            ManagedGraphCall {
                attempt,
                call,
                graph,
                writer,
                head,
                spec,
                relations,
            },
            package,
        ))
    }
}
