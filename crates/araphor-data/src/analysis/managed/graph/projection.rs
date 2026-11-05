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

    fn load_scope(
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

    pub(in crate::analysis) fn findings(&self) -> Option<String> {
        Self::values(&self.findings).map(|values| format!(
            "SELECT publication.result_id,publication.revision,graph.graph_id,graph.tenant_id,
                graph.instance_id,member.writer_id,member.owner_ref,member.relation_id,
                owner.owner_key,member.entity_key,
                member.properties_ref,properties.properties,origin.restricted,
                origin.result_id AS origin_result_id,origin.revision AS origin_revision,
                canonical.canonical_properties_ref AS finding_value_id
             FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id)
             JOIN managed_graph_publication_layers pin USING(result_id)
             JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
             JOIN graph_members member ON member.writer_id=pin.writer_id
                AND member.valid_from<=layer.revision
                AND (member.valid_to IS NULL OR member.valid_to>layer.revision)
             JOIN graph_writer_owners owner ON owner.writer_id=member.writer_id AND owner.owner_ref=member.owner_ref
             JOIN ({values}) properties ON properties.graph_id=graph.graph_id
                AND properties.relation_id=member.relation_id AND properties.properties_ref=member.properties_ref
             JOIN managed_graph_results origin ON origin.writer_id=member.writer_id AND origin.revision=member.valid_from
             JOIN managed_graph_finding_values canonical ON canonical.relation_id=member.relation_id
                AND canonical.properties_ref=member.properties_ref"
        ))
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

    pub(super) fn publish(&self, connection: &Transaction<'_>, result: &str) -> Result<()> {
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
            if invalid {
                return Err(Code::Conflict.error("public Graph relationship value"));
            }
        }
        let (Some(values), Some(members)) = (Self::values(&self.findings), self.members()) else {
            return Ok(());
        };
        let invalid: bool = connection.query_row(&format!(
            "WITH touched AS (
                SELECT DISTINCT properties.properties.value.tenant_id AS tenant_id,
                    properties.properties.value.finding_id AS finding_id
                FROM managed_graph_publications publication
                JOIN graph_writers writer ON writer.graph_id=publication.graph_id
                JOIN graph_members member ON member.writer_id=writer.writer_id
                    AND (member.valid_from=publication.revision OR member.valid_to=publication.revision)
                JOIN ({values}) properties ON properties.relation_id=member.relation_id
                    AND properties.properties_ref=member.properties_ref
                WHERE publication.result_id=?
             ) SELECT EXISTS(SELECT 1 FROM ({members}) current JOIN touched
                ON touched.tenant_id=current.properties.value.tenant_id
                    AND touched.finding_id=current.properties.value.finding_id
             WHERE current.result_id=?
             GROUP BY current.properties.value.tenant_id,current.properties.value.finding_id
             HAVING count(DISTINCT current.properties.value)>1)"
        ), params![result,result], |row| row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "check native public finding conflicts" })?;
        if invalid {
            return Err(Code::Conflict.error("public Graph finding value"));
        }
        let missing: bool = connection
            .query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM ({members}) current
             JOIN managed_graph_publications publication USING(result_id)
             LEFT JOIN managed_graph_finding_values known ON known.relation_id=current.relation_id
                AND known.properties_ref=current.properties_ref
             WHERE current.result_id=? AND current.valid_from=publication.revision
                AND known.properties_ref IS NULL)"
                ),
                params![result],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check new native finding properties",
            })?;
        if !missing {
            return Ok(());
        }
        connection.execute(&format!(
            "INSERT INTO managed_graph_finding_values
             WITH properties AS MATERIALIZED ({values}),wanted AS (
                SELECT DISTINCT current.relation_id,current.properties_ref,current.properties.value AS value
                FROM ({members}) current LEFT JOIN managed_graph_finding_values known
                    ON known.relation_id=current.relation_id AND known.properties_ref=current.properties_ref
                JOIN managed_graph_publications publication USING(result_id)
                WHERE current.result_id=? AND current.valid_from=publication.revision
                    AND known.properties_ref IS NULL
             ) SELECT wanted.relation_id,wanted.properties_ref,
                COALESCE(known.canonical_relation_id,candidate.relation_id),
                COALESCE(known.canonical_properties_ref,candidate.properties_ref)
             FROM wanted JOIN properties candidate ON candidate.properties.value.tenant_id=wanted.value.tenant_id
                AND candidate.properties.value.finding_id=wanted.value.finding_id
                AND candidate.properties.value IS NOT DISTINCT FROM wanted.value
             LEFT JOIN managed_graph_finding_values known ON known.relation_id=candidate.relation_id
                AND known.properties_ref=candidate.properties_ref
             QUALIFY row_number() OVER(PARTITION BY wanted.relation_id,wanted.properties_ref
                ORDER BY COALESCE(known.canonical_properties_ref,candidate.properties_ref),candidate.relation_id)=1"
        ), params![result]).context(AnalysisDatabaseSnafu { operation: "bind canonical native finding values" })?;
        Ok(())
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
        connection: &Connection,
        result: &str,
        exact: Option<&str>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<bool> {
        if !Self::native_graph_result(connection, result)? {
            return Ok(false);
        }
        let Some(findings) = Self::native_findings_sql(connection)? else {
            return Ok(true);
        };
        let mut query = connection
            .prepare(&format!(
                "SELECT properties FROM ({findings}) member WHERE result_id=?
             AND (? IS NULL OR properties.value.finding_id=?)
             QUALIFY row_number() OVER(PARTITION BY properties.value.finding_id
                ORDER BY relation_id,properties_ref,writer_id,owner_ref)=1"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native finding memory bound",
            })?;
        let batches =
            query
                .query_arrow(params![result, exact, exact])
                .context(AnalysisDatabaseSnafu {
                    operation: "read native finding memory bound",
                })?;
        for batch in batches {
            let bytes = batch.get_array_memory_size();
            let input = bytes
                .checked_mul(8)
                .ok_or_else(|| Code::Limit.error("native finding memory"))?;
            charge(bytes, input)?;
        }
        Ok(true)
    }

    pub(in crate::analysis) fn native_findings_sql(
        connection: &Connection,
    ) -> Result<Option<String>> {
        Ok(DomainProjection::load(connection, None)?.findings())
    }

    pub(in crate::analysis) fn notification_findings_sql(
        connection: &Connection,
        tenant: [u8; 16],
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<String>> {
        let projection =
            DomainProjection::load_scope(connection, None, Some(tenant.as_slice()), charge)?;
        let sql = projection.findings();
        if let Some(sql) = &sql {
            charge(0, sql.capacity())?;
        }
        Ok(sql)
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
        connection: &Connection,
        tenant: [u8; 16],
        result: &str,
        id: &str,
    ) -> Result<Option<(u64, FindingMember)>> {
        Self::native_finding_on(connection, tenant, result, id, &mut |_, _| Ok(()))
    }
    pub(in crate::analysis) fn native_finding_on(
        connection: &Connection,
        tenant: [u8; 16],
        result: &str,
        id: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<(u64, FindingMember)>> {
        let findings = Self::notification_findings_sql(connection, tenant, charge)?;
        Self::native_finding_sql(connection, tenant, result, id, findings.as_deref(), charge)
    }
    pub(in crate::analysis) fn native_finding_sql(
        connection: &Connection,
        tenant: [u8; 16],
        result: &str,
        id: &str,
        findings: Option<&str>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<(u64, FindingMember)>> {
        let Some(findings) = findings else {
            return Ok(None);
        };
        let query = format!(
            "SELECT finding_value_id,properties FROM ({findings}) finding
             WHERE tenant_id=? AND result_id=? AND properties.value.finding_id=?
             QUALIFY row_number() OVER(ORDER BY relation_id,properties_ref,writer_id,owner_ref)=1"
        );
        charge(0, query.capacity())?;
        let mut statement = connection.prepare(&query).context(AnalysisDatabaseSnafu {
            operation: "prepare native point finding",
        })?;
        let batches = statement
            .query_arrow(params![tenant.as_slice(), result, id])
            .context(AnalysisDatabaseSnafu {
                operation: "read native point finding",
            })?;
        let mut found = None;
        for batch in batches {
            let bytes = batch.get_array_memory_size();
            charge(
                bytes,
                bytes
                    .checked_mul(12)
                    .ok_or_else(|| Code::Limit.error("native point finding memory"))?,
            )?;
            use sdk::arrow_array::{Array as _, StructArray, UInt64Array};
            let ids = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| Code::Invalid.error("native finding value identity"))?;
            if ids.iter().any(|id| !matches!(id, Some(1..))) {
                return Err(Code::Invalid.error("native finding value identity"));
            }
            let properties = batch
                .column(1)
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| Code::Invalid.error("native finding value properties"))?;
            if properties.null_count() != 0 {
                return Err(Code::Invalid.error("native finding value null"));
            }
            let native = sdk::RecordBatch::try_new(
                std::sync::Arc::new(sdk::Schema::new(properties.fields().clone())),
                properties.columns().to_vec(),
            )
            .context(crate::PackageArrowSnafu)?;
            let data = sdk::Dataset {
                name: FindingMember::port().name,
                batches: vec![sdk::Dataset::normalize_batch(
                    native,
                    std::sync::Arc::new(FindingMember::port().schema),
                )
                .context(crate::AnalysisContractSnafu)?],
            };
            let values = FindingMember::decode(&data).context(crate::AnalysisContractSnafu)?;
            for (index, value) in values.into_iter().enumerate() {
                if found.replace((ids.value(index), value)).is_some() {
                    return Err(Code::Invalid.error("duplicate native point finding"));
                }
            }
        }
        Ok(found)
    }
}
