mod native;
mod publish;
pub(in crate::analysis) use native::FindingRow;

use araphor_analysis_sdk as sdk;
use araphor_analysis_types::{DomainRelations, FindingMember};
use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::super::codec::ManagedCodec;
use crate::{AnalysisDatabaseSnafu, AnalysisStore, PackageErrorCodeV1 as Code, Result};

pub(in crate::analysis) struct DomainProjection {
    findings: Vec<(u64, u64)>,
    subjects: Vec<(u64, u64)>,
    edges: Vec<(u64, u64)>,
}

impl DomainProjection {
    fn check_retention(
        &self,
        connection: &Connection,
        result: &str,
        source: &crate::EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
    ) -> Result<()> {
        for (relations, predicate) in [
            (&self.edges, "upper(member.properties.key.cause) IS DISTINCT FROM 'SUPERSEDED'
                OR member.properties.proof_quality.temporal_coverage IS DISTINCT FROM 2"),
            (&self.findings, "member.properties.value.state IS DISTINCT FROM 'COVERAGE_INSUFFICIENT'
                OR NOT coalesce(list_contains(member.properties.value.limits,'RETAINED_INPUT_EXPIRED'),false)
                OR NOT coalesce(list_contains(member.properties.value.limits,'LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION'),false)
                OR member.properties.value.effects IS NULL
                OR EXISTS(SELECT 1 FROM unnest(member.properties.value.effects) effect(value)
                    WHERE effect.value.proof_quality.temporal_coverage IS DISTINCT FROM 2)"),
        ] {
            let Some(members) = Self::visible(relations) else { continue };
            let invalid: bool = connection.query_row(&format!(
                "SELECT EXISTS(SELECT 1 FROM ({members}) member WHERE member.result_id=?
                    AND member.properties.anchor.record.stream.tenant_id=?
                    AND member.properties.anchor.record.stream.node_id=?
                    AND member.properties.anchor.record.stream.node_boot_id=?
                    AND member.properties.anchor.record.stream.label_epoch=?
                    AND member.properties.anchor.record.stream.source_id=?
                    AND member.properties.anchor.record.stream.source_epoch=?
                    AND member.properties.anchor.record.durable_cursor BETWEEN ? AND ?
                    AND ({predicate}))"),
                params![result,source.tenant_id.as_slice(),source.node_id,source.node_boot_id.as_slice(),
                    source.label_epoch,source.source_id.as_slice(),source.source_epoch,first,last],
                |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation:"check expired source proof claims" })?;
            if invalid { return Err(Code::Denied.error("expired source proof claim")); }
        }
        Ok(())
    }

    pub(in crate::analysis) fn load(connection: &Connection, graph: Option<u64>) -> Result<Self> {
        Self::load_scope(connection, graph, None, &mut |_, _| Ok(()))
    }

    pub(in crate::analysis) fn load_scope(
        connection: &Connection,
        graph: Option<u64>,
        tenant: Option<&[u8]>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Self> {
        let mut query = connection
            .prepare(
                "SELECT relation.graph_id,relation.relation_id,relation.contract,octet_length(relation.contract)
                 FROM managed_graph_relations relation LEFT JOIN managed_graphs owner USING(graph_id)
                 WHERE (? IS NULL OR relation.graph_id=?) AND (? IS NULL OR owner.tenant_id=?)
                 ORDER BY relation.graph_id,relation.relation_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native domain relations",
            })?;
        let mut rows =
            query
                .query(params![graph, graph, tenant, tenant])
                .context(AnalysisDatabaseSnafu {
                    operation: "read native domain relations",
                })?;
        let mut declarations =
            std::collections::BTreeMap::<u64, Vec<(u64, sdk::GraphRelation)>>::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native domain relations",
        })? {
            let length: usize = row.get(3).context(AnalysisDatabaseSnafu {
                operation: "bound native domain contract",
            })?;
            let raw = length
                .checked_mul(4)
                .ok_or_else(|| Code::Limit.error("native domain contract memory"))?;
            charge(length, raw)?;
            let (graph, id, bytes): (u64, u64, Vec<u8>) =
                (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(1)?, row.get(2)?)) })()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode native domain relation",
                    })?;
            ManagedCodec::decode::<serde::de::IgnoredAny>(&bytes)
                .context(crate::ManagedDecodingSnafu)?;
            // Check the complete wire structure before container size hints can allocate.
            let width = std::mem::size_of::<sdk::Field>()
                + std::mem::size_of::<sdk::DataType>()
                + std::mem::size_of::<(String, String)>()
                + std::mem::size_of::<usize>();
            let containers = 12 * std::mem::size_of::<(u64, sdk::GraphRelation)>();
            let allocation = length
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_mul(width))
                .and_then(|bytes| bytes.checked_add(containers))
                .ok_or_else(|| Code::Limit.error("native domain contract memory"))?;
            charge(0, allocation)?;
            let relation: sdk::GraphRelation =
                ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu)?;
            let endpoints = match &relation.kind {
                sdk::GraphKind::Node => Some(0),
                sdk::GraphKind::Edge { from, to } => from.capacity().checked_add(to.capacity()),
            }
            .ok_or_else(|| Code::Limit.error("native domain contract memory"))?;
            let retained = sdk::schema_allocated_bytes(&relation.properties)
                .checked_add(relation.name.capacity())
                .and_then(|bytes| bytes.checked_add(endpoints))
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| bytes.checked_add(containers))
                .ok_or_else(|| Code::Limit.error("native domain contract memory"))?;
            charge(0, retained.saturating_sub(allocation))?;
            declarations.entry(graph).or_default().push((id, relation));
        }
        let mut projection = Self {
            findings: Vec::new(),
            subjects: Vec::new(),
            edges: Vec::new(),
        };
        for (graph, relations) in declarations {
            let spec = sdk::GraphSpec {
                access: sdk::GraphAccess::Read,
                relations: relations
                    .iter()
                    .map(|(_, relation)| relation.clone())
                    .collect(),
            };
            for (id, relation) in &relations {
                if DomainRelations::findings(relation) {
                    projection.findings.push((graph, *id));
                } else if DomainRelations::subjects(relation) {
                    projection.subjects.push((graph, *id));
                } else if DomainRelations::relationships(relation, &spec) {
                    projection.edges.push((graph, *id));
                }
            }
        }
        Ok(projection)
    }

    fn values(relations: &[(u64, u64)]) -> Option<String> {
        (!relations.is_empty()).then(|| {
            relations
                .iter()
                .map(|(graph, relation)| {
                    format!(
                        "SELECT {graph}::UBIGINT AS graph_id,{relation}::UBIGINT AS relation_id,
                property_ref AS properties_ref,properties FROM graph_properties_{relation}"
                    )
                })
                .collect::<Vec<_>>()
                .join(" UNION ALL ")
        })
    }

    fn members(&self) -> Option<String> {
        Self::visible(&self.findings)
    }

    fn visible(relations: &[(u64, u64)]) -> Option<String> {
        Self::values(relations).map(|values| format!(
            "SELECT publication.result_id,member.relation_id,member.properties_ref,member.valid_from,properties.properties
             FROM managed_graph_publications publication
             JOIN managed_graph_publication_layers pin USING(result_id)
             JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
             JOIN graph_members member ON member.writer_id=pin.writer_id
                AND member.valid_from<=layer.revision
                AND (member.valid_to IS NULL OR member.valid_to>layer.revision)
             JOIN ({values}) properties ON properties.graph_id=publication.graph_id
                AND properties.relation_id=member.relation_id AND properties.properties_ref=member.properties_ref"
        ))
    }

    pub(super) fn publish(
        &self,
        engine: &araphor_graph::GraphStore,
        connection: &Transaction<'_>,
        result: &str,
        revision: u64,
        pending: Option<&araphor_graph::PendingLayer>,
        memory: &super::super::budget::PreparedMemory<'_>,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let mut work = [std::time::Duration::ZERO; 4];
        let outcome: Result<()> = (|| {
            let at = std::time::Instant::now();
            if let (Some(values), Some(members)) =
                (Self::values(&self.edges), Self::visible(&self.edges))
            {
                let invalid: bool = connection.query_row(&format!(
                    "WITH touched AS (
                        SELECT DISTINCT properties.properties.key AS key
                        FROM managed_graph_publications publication
                        JOIN graph_writers writer ON writer.graph_id=publication.graph_id
                        JOIN graph_members member ON member.writer_id=writer.writer_id
                            AND (member.valid_from=publication.revision OR member.valid_to=publication.revision)
                        JOIN ({values}) properties ON properties.relation_id=member.relation_id
                            AND properties.properties_ref=member.properties_ref
                        WHERE publication.result_id=?
                     ) SELECT EXISTS(SELECT 1 FROM ({members}) current JOIN touched
                        ON touched.key=current.properties.key WHERE current.result_id=?
                     GROUP BY current.properties.key HAVING count(DISTINCT struct_pack(
                        proof:=current.properties.proof_quality,
                        coverage:=current.properties.required_coverage_interval_ids,
                        first_time:=current.properties.first_boottime_ns,
                        last_time:=current.properties.last_boottime_ns))>1)"
                ), params![result,result], |row| row.get(0))
                    .context(AnalysisDatabaseSnafu { operation: "check native public relationship conflicts" })?;
                work[0] = at.elapsed();
                if invalid {
                    return Err(Code::Conflict.error("public Graph relationship value"));
                }
            }
            let at = std::time::Instant::now();
            self.publish_findings(engine, connection, result, revision, pending, memory)?;
            work[1] = at.elapsed();
            Ok(())
        })();
        if outcome.is_ok() {
            erebor_telemetry::debug!(
                stage = "graph_projection_timing", result_id = result,
                relationships_s = work[0].as_secs_f64(),
                findings_s = work[1].as_secs_f64(),
                missing_s = work[2].as_secs_f64(),
                canonical_s = work[3].as_secs_f64(),
                elapsed_s = started.elapsed().as_secs_f64(),
                "Graph finding projection completed"
            );
        }
        outcome
    }

    pub(super) fn validate(&self, connection: &Connection) -> Result<()> {
        let Some(values) = Self::values(&self.findings) else {
            let present: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_graph_finding_values)",
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check absent native finding relations",
                })?;
            return if present {
                Err(Code::Invalid.error("native finding value relation"))
            } else {
                Ok(())
            };
        };
        let members = self
            .members()
            .ok_or_else(|| Code::Invalid.error("native finding membership"))?;
        let invalid: bool = connection.query_row(&format!(
            "WITH properties AS MATERIALIZED ({values})
             SELECT EXISTS(
                SELECT 1 FROM managed_graph_finding_values map
                LEFT JOIN properties value ON value.relation_id=map.relation_id
                    AND value.properties_ref=map.properties_ref
                LEFT JOIN properties canonical ON canonical.relation_id=map.canonical_relation_id
                    AND canonical.properties_ref=map.canonical_properties_ref
                WHERE value.properties_ref IS NULL OR canonical.properties_ref IS NULL
                    OR value.graph_id IS DISTINCT FROM canonical.graph_id
                    OR value.properties.value IS DISTINCT FROM canonical.properties.value
             ) OR EXISTS(
                SELECT 1 FROM ({members}) member LEFT JOIN managed_graph_finding_values map
                    ON map.relation_id=member.relation_id AND map.properties_ref=member.properties_ref
                WHERE map.properties_ref IS NULL
             ) OR EXISTS(
                SELECT 1 FROM managed_graph_finding_values map JOIN properties value
                    ON value.relation_id=map.relation_id AND value.properties_ref=map.properties_ref
                GROUP BY value.graph_id,value.properties.value
                HAVING count(DISTINCT map.canonical_properties_ref)>1
             )"
        ), [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "check canonical native finding values" })?;
        if invalid {
            return Err(Code::Invalid.error("canonical native finding values"));
        }
        Ok(())
    }
}

impl AnalysisStore {
    pub(in crate::analysis) fn check_source_retention(
        connection: &Connection,
        result: &str,
        source: &crate::EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
    ) -> Result<()> {
        DomainProjection::load(connection, None)?
            .check_retention(connection, result, source, first, last)
    }

    pub(in crate::analysis) fn native_graph_result(
        connection: &Connection,
        result: &str,
    ) -> Result<bool> {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_graph_publications WHERE result_id=?)",
                params![result],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check native Graph result identity",
            })
    }

    pub(in crate::analysis) fn bound_native_findings(
        engine: &araphor_graph::GraphStore,
        connection: &Connection,
        result: &str,
        exact: Option<&str>,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<bool> {
        use duckdb::OptionalExt as _;
        let tenant: Option<Vec<u8>> = connection.query_row(
            "SELECT graph.tenant_id FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id) WHERE publication.result_id=?",
            params![result],|row| row.get(0)).optional().context(AnalysisDatabaseSnafu { operation:"read native finding bound owner" })?;
        let Some(tenant) = tenant else { return Ok(false); };
        let tenant:[u8;16] = tenant.try_into().map_err(|_| Code::Invalid.error("native finding tenant"))?;
        let catalog = DomainProjection::load_scope(connection,None,Some(tenant.as_slice()),charge)?;
        let keys = exact.map(|id| DomainRelations::key(&id)).transpose().context(crate::AnalysisContractSnafu)?.map(|key| vec![key]);
        let mut seen = std::collections::BTreeSet::new();
        for row in catalog.read_findings(engine,connection,tenant,result,keys.as_deref(),charge)? {
            if seen.insert(row.id()?.to_owned()) {
                let bytes = row.member.property_batch()?.get_array_memory_size();
                charge(bytes,bytes.saturating_mul(8))?;
            }
        }
        Ok(true)
    }

    pub(in crate::analysis) fn native_domain_counts(
        connection: &Connection,
        result: &str,
    ) -> Result<(u64, u64, u64)> {
        let projection = DomainProjection::load(connection, None)?;
        let mut counts = [0u64; 3];
        for (index, relations) in [
            &projection.subjects,
            &projection.edges,
            &projection.findings,
        ]
        .into_iter()
        .enumerate()
        {
            let Some(members) = DomainProjection::visible(relations) else {
                continue;
            };
            let key = if index == 2 {
                "properties.value.finding_id"
            } else {
                "properties.key"
            };
            counts[index] = connection
                .query_row(
                    &format!(
                        "SELECT count(DISTINCT {key}) FROM ({members}) member WHERE result_id=?"
                    ),
                    params![result],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "count native public Graph values",
                })?;
        }
        Ok((counts[0], counts[1], counts[2]))
    }

    pub(in crate::analysis) fn native_finding(
        engine: &araphor_graph::GraphStore,
        connection: &Connection,
        tenant: [u8;16],
        result: &str,
        id: &str,
    ) -> Result<Option<(u64,FindingMember)>> {
        Self::native_finding_on(engine,connection,tenant,result,id,&mut |_,_| Ok(()))
    }

    pub(in crate::analysis) fn native_finding_on(
        engine: &araphor_graph::GraphStore,
        connection: &Connection,
        tenant: [u8;16],
        result: &str,
        id: &str,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<Option<(u64,FindingMember)>> {
        let catalog = DomainProjection::load_scope(connection,None,Some(tenant.as_slice()),charge)?;
        charge(0,id.len().saturating_add(16).saturating_mul(4))?;
        let key = DomainRelations::key(&id).context(crate::AnalysisContractSnafu)?;
        let rows = catalog.read_findings(engine,connection,tenant,result,Some(&[key]),charge)?;
        match rows.first() {
            None => Ok(None),
            Some(row) => {
                if row.value==0 { return Err(Code::Invalid.error("native finding value identity")); }
                Ok(Some((row.value,row.decode(charge)?)))
            }
        }
    }
}
