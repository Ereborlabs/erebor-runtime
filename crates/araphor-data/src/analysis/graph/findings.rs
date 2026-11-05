use super::super::graph_rows::GraphRows;
use super::*;
use crate::{
    FindingV1, GraphRevisionV1, NotificationErrorCodeV1 as Notice, NotificationFindingRefV1,
    NotificationGrantV1,
};
use std::collections::{BTreeMap, BTreeSet};

type GraphFindingBatch = BTreeMap<String, (GraphRevisionV1, BTreeMap<String, FindingV1>)>;

impl AnalysisStore {
    pub(in crate::analysis) fn definition_graph(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
    ) -> Result<bool> {
        let source: bool = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_source_publications WHERE tenant_id=? AND result_id=?)",
            params![tenant.as_slice(), result], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "read finding publication kind" })?;
        Ok(!source
            && Self::managed_graph_publication(reader, tenant, result, &mut |_, _| Ok(()))?
                .is_some())
    }

    pub(in crate::analysis) fn definition_finding(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        finding: &str,
    ) -> Result<Option<(FindingV1, GraphRevisionV1)>> {
        let Some((_, member)) = Self::native_finding(engine, reader, tenant, result, finding)? else {
            return Ok(None);
        };
        let (_, _, revision) = Self::native_finding_basis(
            engine,
            reader,
            tenant,
            result,
            &BTreeSet::from([finding.to_owned()]),
            &crate::AnalysisReadControl::default(),
            &mut |_, _| Ok(()),
        )?;
        revision.validate_finding(&member.value)?;
        Ok(Some((member.value, revision)))
    }

    pub fn notification_finding_value(
        &self,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        prior: Option<&NotificationFindingRefV1>,
    ) -> Result<(FindingV1, bool)> {
        Notice::Invalid.require(
            tenant != [0; 16]
                && std::iter::once(reference).chain(prior).all(|reference| {
                    NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                        && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)
                })
                && prior.is_none_or(|prior| prior.finding_id == reference.finding_id),
            "finding reference",
        )?;
        self.read_snapshot(|reader| {
            let heads =
                self.current_finding_keys(reader, tenant, None, Some(&reference.finding_id), 1)?;
            let current = heads.first().ok_or_else(|| {
                crate::NotificationSnafu {
                    code: Notice::Denied,
                    field: "current finding scope",
                }
                .build()
            })?;
            Notice::Conflict.require(
                current.0 == reference.result_id,
                "current finding reference",
            )?;
            if let Some((value, member)) =
                Self::native_finding(&self.graph_engine, reader, tenant, &reference.result_id, &reference.finding_id)?
            {
                let changed = Self::native_finding_changed(
                    &self.graph_engine,
                    reader,
                    tenant,
                    reference,
                    prior,
                    value,
                    &mut |_, _| Ok(()),
                )?;
                if Self::definition_graph(reader, tenant, &reference.result_id)? {
                    Self::managed_graph_publication(
                        reader,
                        tenant,
                        &reference.result_id,
                        &mut |_, _| Ok(()),
                    )?
                    .ok_or_else(|| self.state_error("the Definition Graph owner is absent"))?;
                }
                return Ok((member.value, changed));
            }
            let header = GraphRows::read_summary(reader, tenant, &reference.result_id, None)?
                .ok_or_else(|| self.state_error("the Graph header is absent"))?;
            let finding = GraphRows::read_finding(
                    &self.graph_engine,
                reader,
                &reference.result_id,
                &reference.finding_id,
                &header,
                None,
            )?
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: Notice::Denied,
                    field: "current finding scope",
                }
                .build()
            })?;
            let changed =
                Self::legacy_finding_changed(&self.graph_engine, reader, tenant, reference, prior, &finding, &header)?;
            Ok((finding, changed))
        })
    }

    pub(in crate::analysis) fn native_finding_changed(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        prior: Option<&NotificationFindingRefV1>,
        value: u64,
        charge: &mut dyn FnMut(usize, usize) -> Result<()>,
    ) -> Result<bool> {
        let control = crate::AnalysisReadControl::default();
        let mut owners = crate::analysis::managed::OwnerRead::new(reader, tenant, &control);
        owners.finding_changed(engine, reader, tenant, reference, prior, value, charge)
    }

    pub(in crate::analysis) fn legacy_finding_changed(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
        prior: Option<&NotificationFindingRefV1>,
        finding: &FindingV1,
        header: &super::super::graph_rows::GraphHeader,
    ) -> Result<bool> {
        Ok(match prior {
            None => true,
            Some(prior) if prior.result_id == reference.result_id => false,
            Some(prior) => match GraphRows::read_summary(reader, tenant, &prior.result_id, None)? {
                None => true,
                Some(previous) => match GraphRows::read_finding(
                    engine,
                    reader,
                    &prior.result_id,
                    &prior.finding_id,
                    &previous,
                    None,
                )? {
                    None => true,
                    Some(value) => {
                        value != *finding
                            && !GraphRows::same_revision(
                                reader,
                                &prior.result_id,
                                &previous,
                                &reference.result_id,
                                &header,
                                None,
                            )?
                    }
                },
            },
        })
    }

    pub(in crate::analysis) fn finding_heads_on(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8;16],
        wanted: Option<&[&str]>,
        catalog: &crate::analysis::managed::graph::projection::DomainProjection,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<BTreeMap<String,(String,u64)>> {
        if wanted.is_some_and(|ids| ids.is_empty()) { return Ok(BTreeMap::new()); }
        let mut parameters = vec![duckdb::types::Value::Blob(tenant.to_vec()),duckdb::types::Value::Text(GRAPH_PROCESSOR.into()),GRAPH_SCHEMA_VERSION.into()];
        let mut predicate = String::new();
        let keys = if let Some(ids) = wanted {
            let bytes = ids.iter().try_fold(0usize,|sum,id| sum.checked_add(id.len().saturating_mul(12)+12*size_of::<duckdb::types::Value>()))
                .ok_or_else(|| crate::PackageErrorCodeV1::Limit.error("finding head input memory"))?;
            charge(0,bytes)?;
            predicate = format!("WHERE keys.finding_id IN ({})",std::iter::repeat_n("?",ids.len()).collect::<Vec<_>>().join(","));
            let mut keys = Vec::with_capacity(ids.len());
            for id in ids {
                parameters.push(duckdb::types::Value::Text((*id).into()));
                keys.push(araphor_analysis_types::DomainRelations::key(id).context(crate::AnalysisContractSnafu)?);
            }
            Some(keys)
        } else { None };
        let mut heads = BTreeMap::new();
        let mut query = reader.prepare(&format!(
            "SELECT keys.finding_id,head.result_id,head.commit_revision,
                octet_length(encode(keys.finding_id))+octet_length(encode(head.result_id))
             FROM (SELECT tenant_id,result_id,commit_revision FROM analysis_results
                WHERE tenant_id=? AND processor_id=? AND method_version=? AND stream_key IS NOT NULL
                QUALIFY row_number() OVER(PARTITION BY tenant_id,stream_key,first_cursor
                    ORDER BY commit_revision DESC,result_id DESC)=1) head
             JOIN graph_finding_keys keys USING(result_id) {predicate}"
        )).context(AnalysisDatabaseSnafu { operation:"prepare legacy finding heads" })?;
        let mut rows = query.query(duckdb::params_from_iter(parameters.iter())).context(AnalysisDatabaseSnafu { operation:"read legacy finding heads" })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu { operation:"advance legacy finding heads" })? {
            let bytes:usize = row.get(3).context(AnalysisDatabaseSnafu { operation:"bound legacy finding head" })?;
            charge(0,bytes.saturating_mul(4)+12*size_of::<(String,(String,u64))>())?;
            let (id,result,revision):(String,String,u64) = (|| -> duckdb::Result<_> { Ok((row.get(0)?,row.get(1)?,row.get(2)?)) })().context(AnalysisDatabaseSnafu { operation:"decode legacy finding head" })?;
            let entry = heads.entry(id).or_insert((result.clone(),revision));
            if (revision,&result) > (entry.1,&entry.0) { *entry = (result,revision); }
        }
        let mut query = reader.prepare_cached(
            "SELECT publication.result_id,octet_length(encode(publication.result_id)) FROM managed_graph_publications publication
             JOIN managed_graphs graph USING(graph_id) WHERE graph.tenant_id=? AND publication.result_id IN (
                SELECT result_id FROM managed_source_publications
                QUALIFY row_number() OVER(PARTITION BY tenant_id,instance_id,stream_key,first_cursor ORDER BY revision DESC)=1
                UNION ALL SELECT current.result_id FROM managed_graph_publications current
                WHERE NOT EXISTS(SELECT 1 FROM managed_source_publications source WHERE source.result_id=current.result_id)
                QUALIFY row_number() OVER(PARTITION BY current.graph_id ORDER BY current.revision DESC)=1)"
        ).context(AnalysisDatabaseSnafu { operation:"prepare native finding heads" })?;
        let mut input = query.query(params![tenant.as_slice()]).context(AnalysisDatabaseSnafu { operation:"read native finding heads" })?;
        while let Some(row) = input.next().context(AnalysisDatabaseSnafu { operation:"advance native finding heads" })? {
            let bytes:usize = row.get(1).context(AnalysisDatabaseSnafu { operation:"bound native finding head" })?;
            charge(0,bytes.saturating_mul(4)+12*size_of::<String>())?;
            let result:String = row.get(0).context(AnalysisDatabaseSnafu { operation:"decode native finding head" })?;
            for row in catalog.read_findings(engine,reader,tenant,&result,keys.as_deref(),charge)? {
                let id = row.id()?;
                charge(0,(id.len()+result.len()).saturating_mul(4)+12*size_of::<(String,(String,u64))>())?;
                let id = id.to_owned();
                let entry = heads.entry(id).or_insert((result.clone(),row.revision));
                if (row.revision,&result) > (entry.1,&entry.0) { *entry = (result.clone(),row.revision); }
            }
        }
        Ok(heads)
    }

    pub(in crate::analysis) fn current_finding_keys(
        &self,
        reader: &Connection,
        tenant: [u8;16],
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String,String)>> {
        let catalog = crate::analysis::managed::graph::projection::DomainProjection::load_scope(reader,None,Some(tenant.as_slice()),&mut |_,_| Ok(()))?;
        let wanted = exact.map(|id| vec![id]);
        Ok(Self::finding_heads_on(&self.graph_engine,reader,tenant,wanted.as_deref(),&catalog,&mut |_,_| Ok(()))?
            .into_iter().filter(|(id,_)| after.is_none_or(|after| id.as_str()>after) && exact.is_none_or(|exact| id==exact))
            .take(limit).map(|(id,(result,_))| (result,id)).collect())
    }

    pub fn notification_finding_heads(
        &self,
        tenant: [u8; 16],
        finding_ids: &[String],
    ) -> Result<BTreeMap<String, String>> {
        Notice::Invalid.require(
            tenant != [0; 16]
                && finding_ids
                    .iter()
                    .all(|id| NotificationGrantV1::identifier(id, usize::MAX)),
            "finding reference",
        )?;
        let wanted = finding_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        self.read_snapshot(|reader| {
            Self::notification_heads_from(&self.graph_engine, reader, tenant, &wanted, &mut |_, _| Ok(()))
        })
    }

    pub(in crate::analysis) fn notification_heads_from(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8;16],
        wanted: &[&String],
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<BTreeMap<String,String>> {
        let catalog = crate::analysis::managed::graph::projection::DomainProjection::load_scope(reader,None,Some(tenant.as_slice()),charge)?;
        Self::read_finding_heads(engine,reader,tenant,wanted,&catalog,charge)
    }

    pub(in crate::analysis) fn read_finding_heads(
        engine: &araphor_graph::GraphStore,
        reader: &Connection,
        tenant: [u8;16],
        wanted: &[&String],
        catalog: &crate::analysis::managed::graph::projection::DomainProjection,
        charge: &mut dyn FnMut(usize,usize) -> Result<()>,
    ) -> Result<BTreeMap<String,String>> {
        charge(0,wanted.len().saturating_mul(4*size_of::<&str>()))?;
        let ids = wanted.iter().map(|id| id.as_str()).collect::<Vec<_>>();
        Ok(Self::finding_heads_on(engine,reader,tenant,Some(&ids),catalog,charge)?
            .into_iter().map(|(id,(result,_))| (id,result)).collect())
    }

    pub fn graph_findings(
        &self,
        tenant: [u8; 16],
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        if limit == 0 {
            return crate::GraphInvalidSnafu {
                field: "finding page limit",
            }
            .fail();
        }
        self.check_graph_read(tenant, &[after, exact], "finding page scope")?;
        self.read_snapshot(|reader| {
            let keys = self.current_finding_keys(reader, tenant, after, exact, limit)?;
            let mut requested = BTreeMap::<String, Vec<String>>::new();
            for (result, finding) in &keys {
                requested
                    .entry(result.clone())
                    .or_default()
                    .push(finding.clone());
            }
            let mut selected = BTreeMap::new();
            for (result, ids) in requested {
                if Self::definition_graph(reader, tenant, &result)? {
                    let mut values = BTreeMap::new();
                    for id in ids {
                        let (_, member) = Self::native_finding(&self.graph_engine, reader, tenant, &result, &id)?
                            .ok_or_else(|| self.state_error("the Graph finding is absent"))?;
                        values.insert(id, member.value);
                    }
                    selected.insert(result, values);
                } else {
                    let header = GraphRows::read_finding_header(reader, tenant, &result)?
                        .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                    let values =
                        GraphRows::read_finding_keys(&self.graph_engine, reader, &result, &header, &ids, None)?;
                    selected.insert(result, values);
                }
            }
            keys.into_iter()
                .map(|(result, finding)| {
                    let value = selected
                        .get_mut(&result)
                        .and_then(|values| values.remove(&finding))
                        .ok_or_else(|| self.state_error("the Graph finding is absent"))?;
                    Ok((result, value))
                })
                .collect()
        })
    }

    pub fn graph_finding(
        &self,
        tenant: [u8; 16],
        result_id: &str,
        finding_id: &str,
    ) -> Result<Option<(FindingV1, GraphRevisionV1)>> {
        self.check_graph_read(
            tenant,
            &[Some(result_id), Some(finding_id)],
            "finding reference",
        )?;
        self.read_snapshot(|reader| {
            if Self::definition_graph(reader, tenant, result_id)? {
                return Self::definition_finding(&self.graph_engine, reader, tenant, result_id, finding_id);
            }
            let Some(header) = GraphRows::read_finding_header(reader, tenant, result_id)? else {
                return Ok(None);
            };
            GraphRows::read_finding(&self.graph_engine, reader, result_id, finding_id, &header, None).and_then(
                |finding| {
                    let revision = Self::native_source_revision(
                        reader,
                        tenant,
                        result_id,
                        &mut |_, _| Ok(()),
                    )?
                    .unwrap_or(header.snapshot.input_manifest);
                    Ok(finding.map(|finding| (finding, revision)))
                },
            )
        })
    }

    pub fn graph_finding_batch(
        &self,
        tenant: [u8; 16],
        references: &[NotificationFindingRefV1],
    ) -> Result<GraphFindingBatch> {
        Notice::Invalid.require(
            tenant != [0; 16]
                && references.iter().all(|reference| {
                    NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                        && NotificationGrantV1::identifier(&reference.result_id, usize::MAX)
                }),
            "finding reference",
        )?;
        if references.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut requested = BTreeMap::<&str, BTreeSet<&str>>::new();
        for reference in references {
            requested
                .entry(&reference.result_id)
                .or_default()
                .insert(&reference.finding_id);
        }
        self.read_snapshot(|reader| {
            let mut results = BTreeMap::new();
            for (result, ids) in requested {
                if Self::definition_graph(reader, tenant, result)? {
                    let ids = ids.into_iter().map(str::to_owned).collect::<BTreeSet<_>>();
                    let mut findings = BTreeMap::new();
                    for id in ids {
                        if let Some((_, member)) =
                            Self::native_finding(&self.graph_engine, reader, tenant, result, &id)?
                        {
                            findings.insert(id, member.value);
                        }
                    }
                    let (_, _, revision) = Self::native_finding_basis(
                        &self.graph_engine,
                        reader,
                        tenant,
                        result,
                        &findings.keys().cloned().collect(),
                        &crate::AnalysisReadControl::default(),
                        &mut |_, _| Ok(()),
                    )?;
                    for finding in findings.values() {
                        revision.validate_finding(finding)?;
                    }
                    results.insert(result.to_owned(), (revision, findings));
                    continue;
                }
                let header = GraphRows::read_finding_header(reader, tenant, result)?
                    .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                let ids = ids.into_iter().map(str::to_owned).collect::<Vec<_>>();
                let findings = GraphRows::read_finding_keys(&self.graph_engine, reader, result, &header, &ids, None)?;
                results.insert(
                    result.to_owned(),
                    (
                        Self::native_source_revision(reader, tenant, result, &mut |_, _| Ok(()))?
                            .unwrap_or(header.snapshot.input_manifest),
                        findings,
                    ),
                );
            }
            Ok(results)
        })
    }

    pub fn notification_finding(
        &self,
        tenant: [u8; 16],
        reference: &NotificationFindingRefV1,
    ) -> Result<(FindingV1, GraphRevisionV1)> {
        Notice::Invalid.require(
            tenant != [0; 16]
                && NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                && NotificationGrantV1::identifier(&reference.result_id, usize::MAX),
            "finding reference",
        )?;
        self.read_snapshot(|reader| {
            let keys =
                self.current_finding_keys(reader, tenant, None, Some(&reference.finding_id), 1)?;
            let result = keys.first().ok_or_else(|| {
                crate::NotificationSnafu {
                    code: Notice::Denied,
                    field: "current finding scope",
                }
                .build()
            })?;
            if Self::definition_graph(reader, tenant, &reference.result_id)? {
                Notice::Denied.require(
                    Self::definition_graph(reader, tenant, &result.0)?,
                    "current finding scope",
                )?;
                let current =
                    Self::native_finding(&self.graph_engine, reader, tenant, &result.0, &reference.finding_id)?;
                let requested = Self::native_finding(&self.graph_engine,
                    reader,
                    tenant,
                    &reference.result_id,
                    &reference.finding_id,
                )?;
                let (Some((current, _)), Some((requested, _))) = (current, requested) else {
                    return Err(crate::NotificationSnafu {
                        code: Notice::Denied,
                        field: "current finding scope",
                    }
                    .build());
                };
                Notice::Conflict.require(current == requested, "current finding reference")?;
                return Self::definition_finding(
                    &self.graph_engine,
                    reader,
                    tenant,
                    &reference.result_id,
                    &reference.finding_id,
                )?
                .ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: Notice::Denied,
                        field: "current finding scope",
                    }
                    .build()
                });
            }
            Notice::Conflict
                .require(result.0 == reference.result_id, "current finding reference")?;
            let header = GraphRows::read_finding_header(reader, tenant, &result.0)?
                .ok_or_else(|| self.state_error("the Graph header is absent"))?;
            let finding =
                GraphRows::read_finding(&self.graph_engine, reader, &result.0, &reference.finding_id, &header, None)?
                    .ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: Notice::Denied,
                        field: "current finding scope",
                    }
                    .build()
                })?;
            Ok((
                finding,
                Self::native_source_revision(reader, tenant, &result.0, &mut |_, _| Ok(()))?
                    .unwrap_or(header.snapshot.input_manifest),
            ))
        })
    }

    pub fn graph_revision_finding(
        &self,
        tenant: [u8; 16],
        finding_id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
        self.check_graph_read(tenant, &[Some(finding_id)], "finding reference")?;
        revision.validate(tenant)?;
        self.read_snapshot(|reader| {
            let catalog = crate::analysis::managed::graph::projection::DomainProjection::load_scope(reader,None,Some(tenant.as_slice()),&mut |_,_| Ok(()))?;
            let key = araphor_analysis_types::DomainRelations::key(&finding_id).context(crate::AnalysisContractSnafu)?;
            let mut query = reader.prepare("SELECT publication.result_id FROM managed_graph_publications publication JOIN managed_graphs graph USING(graph_id) WHERE graph.tenant_id=? ORDER BY publication.result_id")
                .context(AnalysisDatabaseSnafu { operation:"prepare historical Definition findings" })?;
            let ids = query.query_map(params![tenant.as_slice()],|row| row.get::<_,String>(0))
                .context(AnalysisDatabaseSnafu { operation:"read historical Definition findings" })?
                .collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu { operation:"decode historical Definition findings" })?;
            for id in ids {
                if !catalog.read_findings(&self.graph_engine,reader,tenant,&id,Some(std::slice::from_ref(&key)),&mut |_,_| Ok(()))?.is_empty()
                    && Self::definition_graph(reader,tenant,&id)? {
                    if let Some((finding,basis)) = Self::definition_finding(&self.graph_engine,reader,tenant,&id,finding_id)? {
                        if &basis == revision { return Ok(Some(finding)); }
                    }
                }
            }
            let mut statement = reader
                .prepare("SELECT DISTINCT f.result_id FROM graph_finding_keys f JOIN analysis_results r USING(result_id) WHERE r.tenant_id=? AND r.processor_id=? AND r.method_version=? AND r.stream_key IS NOT NULL AND f.finding_id=? ORDER BY f.result_id")
                .context(AnalysisDatabaseSnafu { operation: "prepare historical finding" })?;
            let ids = statement
                .query_map(
                    params![tenant.as_slice(), GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION, finding_id],
                    |row| row.get::<_, String>(0),
                )
                .context(AnalysisDatabaseSnafu { operation: "read historical finding" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu { operation: "decode historical finding" })?;
            for id in ids {
                let header = GraphRows::read_finding_header(reader, tenant, &id)?
                    .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                if &header.snapshot.input_manifest == revision {
                    return GraphRows::read_finding(&self.graph_engine, reader, &id, finding_id, &header, None);
                }
            }
            Ok(None)
        })
    }
}

#[cfg(test)]
mod tests;
