use super::*;
use duckdb::OptionalExt as _;

impl OwnerRead<'_> {
    pub(in crate::analysis) fn publication(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<Arc<PublicationOwner>>> {
        self.check_reader(reader, tenant)?;
        if let Some(owner) = self.publications.get(result) {
            return Ok(owner.clone());
        }
        self.charge(
            result
                .len()
                .checked_add(8 * size_of::<(String, Option<Arc<PublicationOwner>>)>())
                .ok_or_else(|| Code::Limit.error("Graph publication owner memory"))?,
            charge,
        )?;
        let header: Option<(u64, String, u64, u64)> = reader.query_row(
            "SELECT publication.revision,graph.instance_id,publication.graph_id,
                octet_length(encode(graph.instance_id))
             FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id)
             JOIN analysis_results selected ON selected.result_id=publication.result_id
                AND selected.tenant_id=graph.tenant_id AND selected.commit_revision=publication.revision
                AND selected.processor_id='managed-definition-v1'
             WHERE graph.tenant_id=? AND publication.result_id=?",
            params![tenant.as_slice(), result],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read Definition Graph owner" })?;
        let Some((revision, instance, graph, bytes)) = header else {
            self.publications.insert(result.to_owned(), None);
            return Ok(None);
        };
        let bytes = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(12))
            .ok_or_else(|| Code::Limit.error("Definition Graph owner memory"))?;
        self.charge(bytes, charge)?;
        let selected = self.selected(result, charge)?;
        if revision == 0 || selected.revision() != revision || selected.instance() != instance {
            return Err(Code::Denied.error("Definition Graph selected owner"));
        }
        let invalid: bool = reader.query_row(
            "SELECT (NOT EXISTS(
                SELECT 1 FROM managed_graph_results result JOIN graph_writers writer USING(writer_id)
                WHERE writer.graph_id=? AND result.revision=?
             ) AND NOT EXISTS(SELECT 1 FROM managed_source_publications source
                WHERE source.result_id=? AND source.tenant_id=? AND source.instance_id=? AND source.revision=?)) OR EXISTS(
                SELECT 1 FROM managed_graph_publication_layers pin
                LEFT JOIN graph_layers layer ON layer.layer_id=pin.layer_id AND layer.writer_id=pin.writer_id
                LEFT JOIN graph_writers writer ON writer.writer_id=pin.writer_id
                WHERE pin.result_id=? AND (layer.layer_id IS NULL OR writer.graph_id IS DISTINCT FROM ?
                    OR layer.revision>? OR EXISTS(SELECT 1 FROM graph_layers later
                        WHERE later.writer_id=pin.writer_id AND later.revision>layer.revision AND later.revision<=?))
             ) OR EXISTS(
                SELECT 1 FROM graph_writers writer WHERE writer.graph_id=?
                    AND EXISTS(SELECT 1 FROM graph_layers layer WHERE layer.writer_id=writer.writer_id AND layer.revision<=?)
                    AND NOT EXISTS(SELECT 1 FROM managed_graph_publication_layers pin WHERE pin.result_id=? AND pin.writer_id=writer.writer_id)
             )",
            params![graph,revision,result,tenant.as_slice(),instance,revision,result,graph,revision,revision,graph,revision,result], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check Definition Graph writer pins" })?;
        if invalid {
            return Err(Code::Denied.error("Definition Graph writer pins"));
        }
        let owner = Arc::new(PublicationOwner { selected });
        self.publications
            .insert(result.to_owned(), Some(Arc::clone(&owner)));
        Ok(Some(owner))
    }

    pub(in crate::analysis) fn finding_sql(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<Arc<String>>> {
        self.check_reader(reader, tenant)?;
        if let Some(sql) = &self.findings {
            return Ok(sql.clone());
        }
        self.charge(4 * size_of::<String>(), charge)?;
        let sql = AnalysisStore::notification_findings_sql(reader, tenant, charge)?.map(Arc::new);
        self.findings = Some(sql.clone());
        Ok(sql)
    }
    pub(in crate::analysis) fn finding(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        id: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<(u64, araphor_analysis_types::FindingMember)>> {
        let sql = self.finding_sql(reader, tenant, charge)?;
        AnalysisStore::native_finding_sql(
            reader,
            tenant,
            result,
            id,
            sql.as_ref().map(|sql| sql.as_str()),
            charge,
        )
    }

    pub(in crate::analysis) fn finding_heads(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        wanted: &[&String],
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<BTreeMap<String, String>> {
        let sql = self.finding_sql(reader, tenant, charge)?;
        AnalysisStore::read_finding_heads(
            reader,
            tenant,
            wanted,
            sql.as_ref().map(|sql| sql.as_str()),
            charge,
        )
    }

    pub(in crate::analysis) fn finding_changed(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        reference: &crate::NotificationFindingRefV1,
        prior: Option<&crate::NotificationFindingRefV1>,
        value: u64,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<bool> {
        self.check_reader(reader, tenant)?;
        Ok(match prior {
            None => true,
            Some(prior) if prior.result_id == reference.result_id => false,
            Some(prior) => self
                .finding(reader, tenant, &prior.result_id, &prior.finding_id, charge)?
                .is_none_or(|(previous, _)| previous != value),
        })
    }
}
