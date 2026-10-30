use super::*;
use crate::GraphValidate as _;

impl GraphRows {
    pub(in crate::analysis) fn validate_history(
        reader: &Connection,
        root: &std::path::Path,
    ) -> Result<()> {
        for query in [
            "SELECT EXISTS(SELECT 1 FROM graph_sources s LEFT JOIN source_receipts r USING(stream_key) WHERE r.stream_key IS NULL OR r.tenant_id<>s.tenant_id)",
            "SELECT EXISTS(SELECT 1 FROM graph_evidence e LEFT JOIN graph_sources s USING(source_ref) WHERE s.source_ref IS NULL OR e.durable_cursor=0)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_scopes s LEFT JOIN graph_sources src USING(source_ref) WHERE src.source_ref IS NULL OR src.tenant_id<>s.tenant_id OR s.created_revision=0 OR s.first_cursor=0 OR (s.producer_kind=0 AND (s.instance_id='' OR s.package_id='' OR s.package_revision='' OR s.image_digest='')))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE s.producer_kind<>0 AND v.derived_progress_digest IS NOT NULL)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v LEFT JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_producer_versions b ON b.result_id=v.base_result_id WHERE s.scope_id IS NULL OR v.commit_revision<s.created_revision OR (v.base_result_id IS NOT NULL AND (b.result_id IS NULL OR b.commit_revision>=v.commit_revision)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN analysis_results r ON r.result_id=v.result_id WHERE s.producer_kind=0 AND (r.result_id IS NULL OR r.processor_id<>'managed-package-v1' OR r.tenant_id<>s.tenant_id OR r.commit_revision<>v.commit_revision))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m LEFT JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from LEFT JOIN graph_producer_versions closed ON closed.scope_id=m.scope_id AND closed.commit_revision=m.valid_to WHERE s.scope_id IS NULL OR opened.result_id IS NULL OR (m.valid_to IS NOT NULL AND (m.valid_to<=m.valid_from OR closed.result_id IS NULL)) OR (s.producer_kind=0 AND (m.member_kind NOT IN (2,3,4,5) OR m.anchor_record_id IS NULL)) OR (s.producer_kind=1 AND m.member_kind NOT IN (2,3,4,6)) OR (s.producer_kind=2 AND m.member_kind NOT IN (0,1,7)))",
            "SELECT EXISTS(SELECT 1 FROM (SELECT valid_from,lag(valid_from) OVER(PARTITION BY scope_id,member_kind,member_key ORDER BY valid_from) AS previous,lag(valid_to) OVER(PARTITION BY scope_id,member_kind,member_key ORDER BY valid_from) AS previous_to FROM graph_producer_members) ranges WHERE previous IS NOT NULL AND (previous_to IS NULL OR previous_to>valid_from))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_evidence e ON e.evidence_id=m.anchor_record_id WHERE m.anchor_record_id IS NOT NULL AND (e.evidence_id IS NULL OR e.source_ref<>s.source_ref))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m LEFT JOIN graph_evidence e ON e.evidence_id=m.value_ref LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref LEFT JOIN graph_subject_values s ON s.subject_id=m.value_ref LEFT JOIN graph_edge_values edge ON edge.edge_id=m.value_ref LEFT JOIN graph_finding_values f ON f.value_id=m.value_ref LEFT JOIN graph_progress_values progress ON progress.value_ref=m.value_ref LEFT JOIN graph_branch_values branch ON branch.branch_id=m.value_ref LEFT JOIN graph_fact_values fact ON fact.fact_id=m.value_ref WHERE (member_kind=0 AND e.evidence_id IS NULL) OR (member_kind=1 AND p.value_ref IS NULL) OR (member_kind=2 AND s.subject_id IS NULL) OR (member_kind=3 AND edge.edge_id IS NULL) OR (member_kind=4 AND f.value_id IS NULL) OR (member_kind=5 AND progress.value_ref IS NULL) OR (member_kind=6 AND branch.branch_id IS NULL) OR (member_kind=7 AND fact.fact_id IS NULL))",
            "SELECT EXISTS(SELECT 1 FROM graph_versions v LEFT JOIN analysis_results r USING(result_id) LEFT JOIN graph_producer_versions metadata ON metadata.result_id=v.metadata_result_id LEFT JOIN graph_producer_scopes s ON s.scope_id=metadata.scope_id LEFT JOIN graph_sources src ON src.source_ref=s.source_ref WHERE r.result_id IS NULL OR r.processor_id<>'graph-findings' OR r.commit_revision<>v.commit_revision OR metadata.result_id IS NULL OR metadata.commit_revision<>v.commit_revision OR s.producer_kind<>2 OR s.tenant_id<>r.tenant_id OR src.stream_key<>r.stream_key)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b LEFT JOIN graph_versions graph ON graph.result_id=b.result_id LEFT JOIN graph_producer_versions v ON v.result_id=b.producer_result_id LEFT JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_sources src USING(source_ref) LEFT JOIN analysis_results r ON r.result_id=b.result_id WHERE graph.result_id IS NULL OR v.result_id IS NULL OR v.commit_revision>graph.commit_revision OR s.tenant_id<>r.tenant_id OR src.stream_key<>r.stream_key)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id GROUP BY b.result_id,v.scope_id HAVING count(*)<>1)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id JOIN graph_producer_scopes s USING(scope_id) JOIN analysis_results graph ON graph.result_id=b.result_id WHERE s.producer_kind=0 AND NOT EXISTS(SELECT 1 FROM managed_edges edge WHERE edge.tenant_id=graph.tenant_id AND edge.result_id=b.result_id AND edge.dependency_id=b.producer_result_id AND edge.commit_revision=graph.commit_revision))",
            "SELECT EXISTS(SELECT 1 FROM graph_versions v WHERE NOT EXISTS(SELECT 1 FROM graph_result_producers b WHERE b.result_id=v.result_id AND b.producer_result_id=v.metadata_result_id))",
            "SELECT EXISTS(SELECT g.result_id FROM graph_versions g LEFT JOIN graph_result_producers b ON b.result_id=g.result_id LEFT JOIN graph_producer_versions v ON v.result_id=b.producer_result_id LEFT JOIN graph_producer_scopes s USING(scope_id) GROUP BY g.result_id,g.metadata_result_id,g.derive_branches,g.commit_revision HAVING count(*) FILTER(WHERE s.producer_kind=2)<>1 OR count(*) FILTER(WHERE s.producer_kind=2 AND v.result_id<>g.metadata_result_id)>0 OR (g.derive_branches AND (count(*) FILTER(WHERE s.producer_kind=1)>0 OR count(*) FILTER(WHERE s.producer_kind=0)=0)) OR (NOT g.derive_branches AND (count(*) FILTER(WHERE s.producer_kind=0)>0 OR count(*) FILTER(WHERE s.producer_kind=1)<>1 OR count(*) FILTER(WHERE s.producer_kind=1 AND v.commit_revision<>g.commit_revision)>0)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_subject_values s ON s.subject_id=m.value_ref WHERE m.member_kind=2 AND s.tenant_id<>owner.tenant_id)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_evidence e ON e.evidence_id=m.value_ref WHERE m.member_kind=0 AND e.source_ref<>owner.source_ref)",
            "SELECT EXISTS(SELECT 1 FROM graph_progress_values v LEFT JOIN graph_evidence e USING(evidence_id) WHERE e.evidence_id IS NULL OR octet_length(v.digest)<>32)",
            "SELECT EXISTS(SELECT 1 FROM graph_position_values v LEFT JOIN graph_evidence e USING(evidence_id) WHERE e.evidence_id IS NULL OR v.commit_revision=0)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_producer_versions b ON b.result_id=v.base_result_id WHERE (v.commit_revision=s.created_revision AND v.base_result_id IS NOT NULL) OR (v.commit_revision>s.created_revision AND (b.result_id IS NULL OR b.scope_id<>v.scope_id OR b.commit_revision>=v.commit_revision)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v WHERE v.subject_count<>(SELECT count(*) FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.member_kind=2 AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)) OR v.edge_count<>(SELECT count(*) FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.member_kind=3 AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)) OR v.finding_count<>(SELECT count(*) FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.member_kind=4 AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)) OR v.progress_count<>(SELECT count(*) FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.member_kind=5 AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)))",
        ] {
            let invalid:bool=reader.query_row(query,[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"validate Graph history"})?;
            if invalid {
                return super::super::AnalysisStore::reject_path(root,"the Graph history has an invalid reference");
            }
        }
        let registry = Self::registry_keys(reader)?;
        let mut statement=reader.prepare("SELECT member_kind,value_ref,member_key FROM graph_producer_members WHERE member_kind IN (0,2,3,4,5)").context(AnalysisDatabaseSnafu {operation:"prepare Graph key validation"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph key validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph key validation",
        })? {
            let kind = Self::column::<u8>(row, 0)?;
            let value = Self::column::<u64>(row, 1)?;
            let key: Vec<u8> = Self::column(row, 2)?;
            if registry.get(&(kind, value)) != Some(&key) {
                return Err(Self::invalid("graph member identity collision"));
            }
        }
        drop(rows);
        drop(statement);
        for kind in [MemberKind::Position, MemberKind::Fact] {
            let mut statement = reader
                .prepare(
                    "SELECT member_key,ordinal FROM graph_producer_members WHERE member_kind=?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph ordinal validation",
                })?;
            let mut rows = statement
                .query(params![kind as u8])
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph ordinal validation",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance Graph ordinal validation",
            })? {
                let ordinal: u32 = Self::column(row, 1)?;
                let key: Vec<u8> = Self::column(row, 0)?;
                if key != Self::encode_value(&(ordinal as usize))? {
                    return Err(Self::invalid("graph metadata ordinal key"));
                }
            }
        }
        araphor_graph::FindingRows::validate(reader)?;
        Self::validate_branches(reader)?;
        for table in ["graph_branch_values", "graph_fact_values"] {
            let mut statement = reader
                .prepare(&format!("SELECT tenant_id,value_hash,body FROM {table}"))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph typed validation",
                })?;
            let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                operation: "read Graph typed validation",
            })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance Graph typed validation",
            })? {
                let tenant: Vec<u8> = Self::column(row, 0)?;
                let hash: Vec<u8> = Self::column(row, 1)?;
                let body: Vec<u8> = Self::column(row, 2)?;
                if hash != Self::hash(&body) || tenant.len() != 16 {
                    return Err(Self::invalid("graph typed value hash"));
                }
                if table == "graph_fact_values" {
                    let fact: crate::GraphFactV1 = Self::decode_value(&body)?;
                    fact.validate()?;
                    if fact.record_id.stream.tenant_id.as_slice() != tenant {
                        return Err(Self::invalid("graph fact tenant"));
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::analysis) fn validate_edge_values(reader: &Connection) -> Result<()> {
        Self::registry_keys(reader).map(|_| ())
    }

    pub(in crate::analysis) fn validate_branches(reader: &Connection) -> Result<()> {
        let mut statement = reader
            .prepare("SELECT tenant_id,body FROM graph_branch_values")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph branch validation",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph branch validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph branch validation",
        })? {
            let tenant: Vec<u8> = Self::column(row, 0)?;
            let body: Vec<u8> = Self::column(row, 1)?;
            let branch: GraphBranchV1 = Self::decode_value(&body)?;
            let tenant = tenant
                .try_into()
                .map_err(|_| Self::invalid("graph branch tenant"))?;
            Self::check_branch(&branch, tenant)?;
        }
        Ok(())
    }

    pub(super) fn check_branch(branch: &GraphBranchV1, tenant: [u8; 16]) -> Result<()> {
        branch.seed.validate()?;
        if branch.seed.tenant_id != tenant
            || branch
                .evidence
                .iter()
                .any(|record| record.stream.tenant_id != tenant)
        {
            return Err(Self::invalid("graph branch tenant"));
        }
        Ok(())
    }
}
