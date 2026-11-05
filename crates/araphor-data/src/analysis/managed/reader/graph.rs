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
        let Some((revision, instance, _graph, bytes)) = header else {
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
        let owner = Arc::new(PublicationOwner { selected });
        self.publications
            .insert(result.to_owned(), Some(Arc::clone(&owner)));
        Ok(Some(owner))
    }

    pub(in crate::analysis) fn graph_origin(
        &self,
        writer: u64,
        revision: u64,
    ) -> Result<Option<Arc<GraphOrigin>>> {
        self.control.check()?;
        self.store
            .managed_results
            .graph_origin(self.tenant, writer, revision)
    }

    pub(in crate::analysis) fn producer_contexts(
        &mut self,
        result: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Arc<Vec<crate::AnalysisContextRefV1>>> {
        self.control.check()?;
        if let Some(contexts) = self.contexts.get(result) {
            return Ok(Arc::clone(contexts));
        }
        self.charge(
            result.len().saturating_mul(4)
                + 12 * std::mem::size_of::<(String, Arc<Vec<crate::AnalysisContextRefV1>>)>(),
            charge,
        )?;
        let mut query = self.reader.prepare(
            "SELECT pin.owner_id,pin.entity_key,pin.lifetime_key,pin.owner_revision,pin.commit_revision,
                octet_length(encode(pin.owner_id))+octet_length(pin.entity_key)+octet_length(pin.lifetime_key)
             FROM context_refs pin JOIN context_versions context ON context.tenant_id=pin.tenant_id
                AND context.owner_id=pin.owner_id AND context.entity_key=pin.entity_key
                AND context.lifetime_key=pin.lifetime_key AND context.owner_revision=pin.owner_revision
                AND context.commit_revision=pin.commit_revision
             WHERE pin.tenant_id=? AND pin.ref_id=?"
        ).context(AnalysisDatabaseSnafu { operation: "prepare visible producer contexts" })?;
        let mut rows = query
            .query(params![self.tenant.as_slice(), result])
            .context(AnalysisDatabaseSnafu {
                operation: "read visible producer contexts",
            })?;
        let mut contexts = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance visible producer contexts",
        })? {
            self.control.check()?;
            let bytes: usize = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "bound visible producer context",
            })?;
            let bytes = bytes
                .checked_mul(4)
                .and_then(|bytes| {
                    bytes.checked_add(4 * std::mem::size_of::<crate::AnalysisContextRefV1>())
                })
                .ok_or_else(|| Code::Limit.error("native finding context memory"))?;
            charge(bytes, bytes)?;
            contexts.push(
                (|| -> duckdb::Result<_> {
                    Ok(crate::AnalysisContextRefV1 {
                        key: crate::AnalysisContextKeyV1 {
                            tenant_id: self.tenant,
                            owner_id: row.get(0)?,
                            entity_key: row.get(1)?,
                            lifetime_key: row.get(2)?,
                            owner_revision: row.get(3)?,
                        },
                        commit_revision: row.get(4)?,
                    })
                })()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode visible producer context",
                })?,
            );
        }
        let contexts = Arc::new(contexts);
        self.contexts
            .insert(result.to_owned(), Arc::clone(&contexts));
        Ok(contexts)
    }

    pub(in crate::analysis) fn finding_catalog(
        &mut self,
        reader: &Connection,
        tenant: [u8; 16],
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Arc<super::super::graph::projection::DomainProjection>> {
        self.check_reader(reader, tenant)?;
        if let Some(catalog) = &self.findings {
            return Ok(Arc::clone(catalog));
        }
        let catalog = Arc::new(
            super::super::graph::projection::DomainProjection::load_scope(
                reader,
                None,
                Some(tenant.as_slice()),
                charge,
            )?,
        );
        self.findings = Some(Arc::clone(&catalog));
        Ok(catalog)
    }

    pub(in crate::analysis) fn finding_rows(
        &mut self,
        _engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        keys: Option<&[Vec<u8>]>,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Vec<super::super::graph::projection::FindingRow>> {
        self.finding_catalog(reader, tenant, charge)?
            .read_findings(self.store, reader, tenant, result, keys, charge)
    }

    pub(in crate::analysis) fn finding(
        &mut self,
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        id: &str,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<Option<(u64, araphor_analysis_types::FindingMember)>> {
        charge(0, id.len().saturating_add(16).saturating_mul(4))?;
        let key = araphor_analysis_types::DomainRelations::key(&id)
            .context(crate::AnalysisContractSnafu)?;
        let rows = self.finding_rows(engine, reader, tenant, result, Some(&[key]), charge)?;
        match rows.first() {
            None => Ok(None),
            Some(row) => {
                if row.value == 0 {
                    return Err(Code::Invalid.error("native finding value identity"));
                }
                Ok(Some((row.value, row.decode(charge)?)))
            }
        }
    }

    pub(in crate::analysis) fn finding_heads(
        &mut self,
        _engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        wanted: &[&String],
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<BTreeMap<String, String>> {
        let catalog = self.finding_catalog(reader, tenant, charge)?;
        AnalysisStore::read_finding_heads(self.store, reader, tenant, wanted, &catalog, charge)
    }

    pub(in crate::analysis) fn finding_changed(
        &mut self,
        engine: &araphor_graph::GraphStore,
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
                .finding(
                    engine,
                    reader,
                    tenant,
                    &prior.result_id,
                    &prior.finding_id,
                    charge,
                )?
                .is_none_or(|(previous, _)| previous != value),
        })
    }
}
