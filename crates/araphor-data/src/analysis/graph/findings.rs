use super::super::graph_rows::GraphRows;
use super::*;
use crate::{
    FindingV1, GraphRevisionV1, NotificationErrorCodeV1 as Notice, NotificationFindingRefV1,
    NotificationGrantV1,
};
use std::collections::{BTreeMap, BTreeSet};

type GraphFindingBatch = BTreeMap<String, (GraphRevisionV1, BTreeMap<String, FindingV1>)>;

impl AnalysisStore {
    fn current_finding_keys(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        after: Option<&str>,
        exact: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let mut statement=reader.prepare("WITH heads AS (SELECT result_id,commit_revision FROM analysis_results WHERE tenant_id=? AND processor_id=? AND method_version=? AND stream_key IS NOT NULL QUALIFY row_number() OVER(PARTITION BY stream_key,first_cursor ORDER BY commit_revision DESC,result_id DESC)=1), current AS (SELECT f.result_id,f.finding_id,h.commit_revision FROM heads h JOIN graph_finding_keys f USING(result_id) QUALIFY row_number() OVER(PARTITION BY f.finding_id ORDER BY h.commit_revision DESC,f.result_id DESC)=1) SELECT result_id,finding_id FROM current WHERE (? IS NULL OR finding_id>?) AND (? IS NULL OR finding_id=?) ORDER BY finding_id LIMIT ?").context(AnalysisDatabaseSnafu {operation:"prepare current finding keys"})?;
        statement
            .query_map(
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    after,
                    after,
                    exact,
                    exact,
                    limit.min(i64::MAX as usize) as i64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read current finding keys",
            })?
            .collect::<duckdb::Result<_>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode current finding keys",
            })
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
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        self.read_snapshot(|reader| {
            let mut heads=BTreeMap::new();
            for chunk in wanted.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
                let values=std::iter::repeat_n("(?)",chunk.len()).collect::<Vec<_>>().join(",");
                let query=format!("WITH wanted(finding_id) AS (VALUES {values}),heads AS (SELECT result_id,commit_revision FROM analysis_results WHERE tenant_id=? AND processor_id=? AND method_version=? AND stream_key IS NOT NULL QUALIFY row_number() OVER(PARTITION BY stream_key,first_cursor ORDER BY commit_revision DESC,result_id DESC)=1) SELECT f.result_id,f.finding_id FROM wanted JOIN graph_finding_keys f USING(finding_id) JOIN heads h USING(result_id) QUALIFY row_number() OVER(PARTITION BY f.finding_id ORDER BY h.commit_revision DESC,f.result_id DESC)=1");
                let mut parameters=chunk.iter().map(|id|duckdb::types::Value::Text((*id).clone())).collect::<Vec<_>>();
                parameters.extend([duckdb::types::Value::Blob(tenant.to_vec()),duckdb::types::Value::Text(GRAPH_PROCESSOR.into()),duckdb::types::Value::UBigInt(u64::from(GRAPH_SCHEMA_VERSION))]);
                let mut statement=reader.prepare(&query).context(AnalysisDatabaseSnafu {operation:"prepare requested finding heads"})?;
                let mut rows=statement.query(duckdb::params_from_iter(parameters.iter())).context(AnalysisDatabaseSnafu {operation:"read requested finding heads"})?;
                while let Some(row)=rows.next().context(AnalysisDatabaseSnafu {operation:"advance requested finding heads"})? {
                    let result:String=row.get(0).context(AnalysisDatabaseSnafu {operation:"decode finding head result"})?;
                    let finding:String=row.get(1).context(AnalysisDatabaseSnafu {operation:"decode finding head identity"})?;
                    if heads.insert(finding,result).is_some(){return crate::GraphInvalidSnafu {field:"duplicate current finding"}.fail();}
                }
            }
            Ok(heads)
        })
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
                let header = GraphRows::read_finding_header(reader, tenant, &result)?
                    .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                let values = GraphRows::read_finding_keys(reader, &result, &header, &ids, None)?;
                selected.insert(result, values);
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
            let Some(header) = GraphRows::read_finding_header(reader, tenant, result_id)? else {
                return Ok(None);
            };
            GraphRows::read_finding(reader, result_id, finding_id, &header, None)
                .map(|finding| finding.map(|finding| (finding, header.snapshot.input_manifest)))
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
                let header = GraphRows::read_finding_header(reader, tenant, result)?
                    .ok_or_else(|| self.state_error("the Graph header is absent"))?;
                let ids = ids.into_iter().map(str::to_owned).collect::<Vec<_>>();
                let findings = GraphRows::read_finding_keys(reader, result, &header, &ids, None)?;
                results.insert(
                    result.to_owned(),
                    (header.snapshot.input_manifest, findings),
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
            Notice::Conflict
                .require(result.0 == reference.result_id, "current finding reference")?;
            let header = GraphRows::read_finding_header(reader, tenant, &result.0)?
                .ok_or_else(|| self.state_error("the Graph header is absent"))?;
            let finding =
                GraphRows::read_finding(reader, &result.0, &reference.finding_id, &header, None)?
                    .ok_or_else(|| {
                    crate::NotificationSnafu {
                        code: Notice::Denied,
                        field: "current finding scope",
                    }
                    .build()
                })?;
            Ok((finding, header.snapshot.input_manifest))
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
                    return GraphRows::read_finding(reader, &id, finding_id, &header, None);
                }
            }
            Ok(None)
        })
    }
}

#[cfg(test)]
mod tests;
