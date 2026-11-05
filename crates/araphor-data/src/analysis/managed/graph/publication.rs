use duckdb::{Connection, OptionalExt as _, Transaction, params};
use snafu::ResultExt as _;

use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, ManagedCommit, ManagedReceipt,
    PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub(in crate::analysis::managed) fn publish_graph(
        &self,
        connection: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        revision: u64,
        pending: Option<&araphor_graph::PendingLayer>,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<(Vec<&'static str>, super::super::reader::GraphDelta)> {
        let started = std::time::Instant::now();
        let selected = input
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten();
        if selected.is_none()
            && !input
                .returns
                .iter()
                .any(|returned| returned.graph.is_some())
        {
            return Ok((Vec::new(), Default::default()));
        }
        let spec = &input.attempt.instance().spec;
        let graph: Option<u64> = connection
            .query_row(
                "SELECT graph_id FROM managed_graphs WHERE tenant_id=? AND instance_id=?",
                params![spec.tenant.as_slice(), spec.id],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Definition Graph publication owner",
            })?;
        let Some(graph) = graph else {
            return Ok((Vec::new(), Default::default()));
        };
        if revision == 0 || receipt.selected.commit_revision != revision {
            return Err(Code::Invalid.error("Definition Graph publication revision"));
        }
        let previous: Option<String> = connection
            .query_row(
                "SELECT result_id FROM managed_graph_publications WHERE graph_id=?
                    ORDER BY revision DESC LIMIT 1",
                params![graph],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Definition Graph publication head",
            })?;
        connection
            .execute(
                "INSERT INTO managed_graph_publications VALUES(?,?,?,?)",
                params![receipt.selected.result_id, graph, revision, previous],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "publish Definition Graph cut",
            })?;
        let metadata_at = std::time::Instant::now();
        connection
            .execute(
                "INSERT INTO managed_graph_publication_layers
                 SELECT ?,layer.writer_id,layer.layer_id FROM graph_layers layer
                 JOIN graph_writers writer USING(writer_id)
                 WHERE writer.graph_id=? AND layer.revision<=?
                 QUALIFY row_number() OVER(PARTITION BY layer.writer_id
                    ORDER BY layer.revision DESC)=1",
                params![receipt.selected.result_id, graph, revision],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "pin Definition Graph writer heads",
            })?;
        let mut heads = std::collections::BTreeMap::new();
        let mut query = connection.prepare(
            "SELECT pin.writer_id,layer.revision FROM managed_graph_publication_layers pin
             JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
             WHERE pin.result_id=?"
        ).context(AnalysisDatabaseSnafu { operation: "prepare finding publication heads" })?;
        let mut rows =
            query
                .query(params![receipt.selected.result_id])
                .context(AnalysisDatabaseSnafu {
                    operation: "read finding publication heads",
                })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance finding publication heads",
        })? {
            memory.charge(12 * std::mem::size_of::<(u64, u64)>())?;
            let (writer, head) = (|| -> duckdb::Result<_> { Ok((row.get(0)?, row.get(1)?)) })()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode finding publication head",
                })?;
            heads.insert(writer, head);
        }
        let pins_at = std::time::Instant::now();
        let projection = super::projection::DomainProjection::load(connection, Some(graph))?;
        let catalog_at = std::time::Instant::now();
        let canonical = projection.publish(
            &self.graph_engine,
            connection,
            &receipt.selected.result_id,
            revision,
            &heads,
            pending,
            memory,
        )?;
        let completed = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "graph_publication_timing", instance_id = %spec.id,
            cut_revision = input.attempt.captured_revision(), publication_revision = revision,
            metadata_s = metadata_at.duration_since(started).as_secs_f64(),
            pins_s = pins_at.duration_since(metadata_at).as_secs_f64(),
            catalog_s = catalog_at.duration_since(pins_at).as_secs_f64(),
            projection_s = completed.duration_since(catalog_at).as_secs_f64(),
            elapsed_s = completed.duration_since(started).as_secs_f64(),
            "Graph publication completed"
        );
        Ok((
            vec![
                "managed_graph_publications",
                "managed_graph_publication_layers",
                "managed_graph_finding_values",
            ],
            super::super::reader::GraphDelta {
                publication: Some(super::super::reader::GraphPublication {
                    graph,
                    revision,
                    heads,
                }),
                canonical,
                origins: Vec::new(),
            },
        ))
    }

    pub(super) fn check_graph_publications(connection: &Connection) -> Result<()> {
        super::projection::DomainProjection::load(connection, None)?.validate(connection)?;
        let invalid: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM managed_graph_publications publication
                LEFT JOIN managed_graphs graph USING(graph_id)
                LEFT JOIN analysis_results result ON result.result_id=publication.result_id
                WHERE graph.graph_id IS NULL OR result.result_id IS NULL
                    OR result.tenant_id<>graph.tenant_id
                    OR result.processor_id<>'managed-definition-v1'
                    OR result.commit_revision<>publication.revision
                    OR publication.previous_result_id IS DISTINCT FROM (
                        SELECT prior.result_id FROM managed_graph_publications prior
                        WHERE prior.graph_id=publication.graph_id AND prior.revision<publication.revision
                        ORDER BY prior.revision DESC LIMIT 1)
             ) OR EXISTS(
                SELECT 1 FROM managed_graph_results result
                JOIN graph_writers writer USING(writer_id)
                LEFT JOIN managed_graph_publications publication
                    ON publication.graph_id=writer.graph_id AND publication.revision=result.revision
                WHERE publication.result_id IS NULL
             ) OR EXISTS(
                SELECT 1 FROM managed_graph_publication_layers pin
                LEFT JOIN managed_graph_publications publication USING(result_id)
                LEFT JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
                LEFT JOIN graph_writers writer ON writer.writer_id=pin.writer_id
                WHERE publication.result_id IS NULL OR layer.layer_id IS NULL
                    OR writer.graph_id IS DISTINCT FROM publication.graph_id
                    OR layer.revision>publication.revision
                    OR EXISTS(SELECT 1 FROM graph_layers later WHERE later.writer_id=pin.writer_id
                        AND later.revision>layer.revision AND later.revision<=publication.revision)
             ) OR EXISTS(
                SELECT 1 FROM managed_graph_publications publication
                JOIN graph_writers writer USING(graph_id)
                WHERE EXISTS(SELECT 1 FROM graph_layers layer WHERE layer.writer_id=writer.writer_id
                    AND layer.revision<=publication.revision)
                    AND NOT EXISTS(SELECT 1 FROM managed_graph_publication_layers pin
                        WHERE pin.result_id=publication.result_id AND pin.writer_id=writer.writer_id)
             )",
            [],|row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check Definition Graph publications" })?;
        if invalid {
            return Err(Code::Invalid.error("Definition Graph publication pins"));
        }
        let mut query = connection
            .prepare(
                "SELECT graph.tenant_id,graph.instance_id,publication.result_id,publication.revision
                 FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Definition Graph publication owners",
            })?;
        let mut rows = query.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Definition Graph publication owners",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Definition Graph publication owners",
        })? {
            let (tenant, instance, id, revision) = (|| -> duckdb::Result<_> {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Definition Graph publication owner",
            })?;
            let tenant = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("Graph publication tenant"))?;
            let (step, stored) = Self::managed_step_header(connection, tenant, &id)?;
            if stored != revision || step.instance != instance {
                return Err(Code::Invalid.error("Graph publication selected owner"));
            }
        }
        Ok(())
    }
}
