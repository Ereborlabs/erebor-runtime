use duckdb::{params, Connection, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, ManagedCommit, ManagedReceipt,
    PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub(in crate::analysis) fn managed_graph_publication(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<(u64, String, crate::PackageGrantV1)>> {
        let control = crate::AnalysisReadControl::default();
        let mut owners = super::super::OwnerRead::new(reader, tenant, &control);
        Ok(owners
            .publication(reader, tenant, result, charge)?
            .map(|owner| {
                (
                    owner.revision(),
                    owner.instance().to_owned(),
                    owner.grant().clone(),
                )
            }))
    }

    pub(in crate::analysis::managed) fn publish_graph(
        connection: &Transaction<'_>,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        revision: u64,
    ) -> Result<Vec<&'static str>> {
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
            return Ok(Vec::new());
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
            return Ok(Vec::new());
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
        super::projection::DomainProjection::load(connection, Some(graph))?
            .publish(connection, &receipt.selected.result_id)?;
        Ok(vec![
            "managed_graph_publications",
            "managed_graph_publication_layers",
            "managed_graph_finding_values",
        ])
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
