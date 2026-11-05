use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::{AnalysisDatabaseSnafu, AnalysisStore, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_graph_rows(
        connection: &Connection,
        result: &str,
        cut: u64,
    ) -> Result<()> {
        let invalid: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_graph_row_reads pin
             LEFT JOIN managed_graph_reads origin ON origin.result_id=pin.result_id
                AND origin.writer_id=pin.writer_id AND origin.revision=pin.revision
             LEFT JOIN graph_writer_owners owner ON owner.writer_id=pin.writer_id AND owner.owner_key=pin.owner_key
             LEFT JOIN graph_members member ON member.writer_id=pin.writer_id AND member.owner_ref=owner.owner_ref
                AND member.relation_id=pin.relation_id AND member.entity_key=pin.entity_key
                AND member.valid_from=pin.revision AND member.valid_from<=?
                AND (member.valid_to IS NULL OR member.valid_to>?)
             LEFT JOIN managed_graph_results consumer ON consumer.result_id=pin.result_id
             LEFT JOIN managed_graph_writers writer ON writer.writer_id=consumer.writer_id
             LEFT JOIN graph_relations relation ON relation.relation_id=pin.relation_id
             WHERE pin.result_id=? AND (origin.result_id IS NULL OR member.writer_id IS NULL
                OR relation.graph_id IS DISTINCT FROM writer.graph_id))",
            params![cut,cut,result],|row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation:"check exact Graph read row authority" })?;
        if invalid {
            return Err(Code::Denied.error("Graph read row authority"));
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn check_graph_result(
        connection: &Connection,
        spec: &super::super::ManagedSpec,
        result: &str,
        call: u64,
        revision: u64,
        declared: bool,
    ) -> Result<()> {
        let stored: Option<bool> = connection.query_row(
            "SELECT owner.tenant_id=? AND owner.instance_id=? AND writer.call_id=? AND result.revision=?
                AND layer.writer_id=result.writer_id AND layer.revision=result.revision
             FROM managed_graph_results result JOIN managed_graph_writers writer USING(writer_id)
             JOIN managed_graphs owner USING(graph_id) LEFT JOIN graph_layers layer USING(layer_id)
             WHERE result.result_id=?",
            params![spec.tenant.as_slice(),spec.id,call,revision,result],|row| row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation:"check native Graph call result" })?;
        if declared && stored != Some(true) || !declared && stored.is_some() {
            return Err(Code::Invalid.error("native Graph call result authority"));
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn validate_graph_calls(
        connection: &Connection,
    ) -> Result<()> {
        araphor_graph::GraphStore::validate(connection)?;
        Self::check_graph_publications(connection)?;
        let invalid: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_graphs graph
                LEFT JOIN managed_instances instance USING(tenant_id,instance_id)
                WHERE graph.graph_id=0 OR instance.instance_id IS NULL)
             OR EXISTS(SELECT 1 FROM managed_graph_writers writer
                LEFT JOIN managed_graphs graph USING(graph_id)
                LEFT JOIN graph_writers engine USING(writer_id)
                WHERE writer.writer_id=0 OR graph.graph_id IS NULL OR engine.graph_id IS DISTINCT FROM writer.graph_id)
             OR EXISTS(SELECT 1 FROM graph_writers engine LEFT JOIN managed_graph_writers writer USING(writer_id)
                WHERE writer.writer_id IS NULL)
             OR EXISTS(SELECT 1 FROM managed_graph_relations relation
                LEFT JOIN managed_graphs graph USING(graph_id)
                LEFT JOIN graph_relations engine USING(relation_id)
                WHERE relation.relation_id=0 OR relation.relation_name='' OR graph.graph_id IS NULL
                    OR engine.graph_id IS DISTINCT FROM relation.graph_id)
             OR EXISTS(SELECT 1 FROM graph_relations engine LEFT JOIN managed_graph_relations relation USING(relation_id)
                WHERE relation.relation_id IS NULL)
             OR EXISTS(SELECT 1 FROM graph_layers layer
                LEFT JOIN managed_graph_results result ON result.layer_id=layer.layer_id AND result.writer_id=layer.writer_id AND result.revision=layer.revision
                WHERE result.result_id IS NULL)
             OR EXISTS(SELECT 1 FROM managed_graph_results result
                LEFT JOIN graph_layers layer ON result.layer_id=layer.layer_id AND result.writer_id=layer.writer_id AND result.revision=layer.revision
                LEFT JOIN managed_graph_writers writer ON writer.writer_id=result.writer_id
                LEFT JOIN managed_graphs graph ON graph.graph_id=writer.graph_id
                LEFT JOIN analysis_results stored ON stored.result_id=result.result_id AND stored.commit_revision=result.revision AND stored.tenant_id=graph.tenant_id
                WHERE layer.layer_id IS NULL OR stored.processor_id IS DISTINCT FROM 'managed-package-v1')
             OR EXISTS(SELECT 1 FROM managed_graph_reads edge
                LEFT JOIN managed_graph_results origin ON origin.writer_id=edge.writer_id AND origin.revision=edge.revision AND origin.result_id=edge.producer_id
                LEFT JOIN managed_graph_results consumer ON consumer.result_id=edge.result_id
                WHERE origin.result_id IS NULL OR consumer.result_id IS NULL OR origin.revision>=consumer.revision
                    OR (origin.restricted AND NOT consumer.restricted))",
            [], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate managed Graph attribution" })?;
        if invalid {
            return Err(Code::Invalid.error("managed Graph recovery"));
        }
        let mut statement = connection.prepare(
            "SELECT graph.tenant_id,graph.instance_id,writer.call_id,result.result_id,result.revision
             FROM managed_graph_results result JOIN managed_graph_writers writer USING(writer_id)
             JOIN managed_graphs graph USING(graph_id) ORDER BY result.revision,writer.call_id",
        ).context(AnalysisDatabaseSnafu { operation: "prepare managed Graph recovery" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read managed Graph recovery",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode managed Graph recovery",
            })?;
        for (tenant, instance, call, id, revision) in rows {
            let tenant: [u8; 16] = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("Graph recovery tenant"))?;
            let (record, stored) = Self::managed_meta_from(connection, tenant, &id)?;
            let (_, attempt, spec) =
                Self::validate_managed_header(connection, tenant, &id, &record, revision)?;
            if stored != revision || spec.id != instance || record.call != call {
                return Err(Code::Invalid.error("Graph recovery producer"));
            }
            Self::check_graph_rows(connection, &id, attempt.capture.revision)?;
            let mut origins = connection.prepare(
                "SELECT edge.producer_id,edge.revision,writer.call_id,graph.instance_id,writer.graph_id
                 FROM managed_graph_reads edge JOIN managed_graph_writers writer USING(writer_id)
                 JOIN managed_graphs graph USING(graph_id) WHERE edge.result_id=?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare Graph read recovery" })?;
            let origins = origins
                .query_map(params![id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph origins",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode Graph origins",
                })?;
            for (id, revision, call, owner, _) in origins {
                let reference = crate::analysis::PackageResultRefV1 {
                    result_id: id,
                    commit_revision: revision,
                };
                let (origin, _, actual) = Self::managed_producer_from(
                    connection,
                    &attempt.capture.grant.selection,
                    &reference,
                )?;
                if revision > attempt.capture.revision
                    || origin.id != instance
                    || origin.id != owner
                    || actual != call
                {
                    return Err(Code::Denied.error("Graph recovered read authority"));
                }
            }
        }
        Ok(())
    }
}
