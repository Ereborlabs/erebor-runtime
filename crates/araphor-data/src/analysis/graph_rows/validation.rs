use super::*;
use crate::GraphValidate as _;

#[derive(Default)]
struct CallSupport {
    records: BTreeMap<u64, (crate::DiscoveryRecordIdV1, Option<u64>)>,
    facts: BTreeMap<crate::AnalysisContextKeyV1, (FactAnchor, Option<u64>)>,
}

impl CallSupport {
    fn covers(until: Option<u64>, end: Option<u64>) -> bool {
        until.is_none_or(|until| end.is_some_and(|end| until >= end))
    }
}

impl GraphRows {
    pub(in crate::analysis) fn validate_positions(
        reader: &Connection,
        raw: &super::super::raw::RawJournal,
        revision: u64,
    ) -> Result<()> {
        let mut statement=reader.prepare(
            "SELECT p.commit_revision,p.ordinal,e.durable_cursor,s.identity FROM graph_position_values p
             JOIN graph_evidence e USING(evidence_id) JOIN graph_sources s USING(source_ref)"
        ).context(AnalysisDatabaseSnafu {operation:"prepare canonical Graph positions"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read canonical Graph positions",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance canonical Graph positions",
        })? {
            let source: crate::EvidenceIntakeIdentityV1 =
                Self::decode_value(&Self::column::<Vec<u8>>(row, 3)?)?;
            let cursor: u64 = Self::column(row, 2)?;
            let key = super::super::raw::RawIdentity::Evidence(source).key();
            if let Some((entry, index)) = raw.locate_retained(&key, cursor, revision) {
                let span = &entry.commit.spans[index];
                let ordinal = u32::try_from(cursor - span.first)
                    .ok()
                    .and_then(|offset| span.ordinal.checked_add(offset));
                if Self::column::<u64>(row, 0)? != entry.commit.revision
                    || Some(Self::column::<u32>(row, 1)?) != ordinal
                {
                    return Err(Self::invalid("graph canonical input position"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn derived_fact(
        reader: &Connection,
        call: &PackageResultRefV1,
        context: &crate::AnalysisContextRefV1,
        fact: &crate::GraphFactV1,
        evidence: u64,
        captured: u64,
        introduction: u64,
    ) -> Result<bool> {
        if context.commit_revision != call.commit_revision || introduction != call.commit_revision {
            return Ok(false);
        }
        let id:Option<String>=reader.query_row(
            "SELECT g.result_id FROM graph_versions g JOIN graph_result_producers b ON b.result_id=g.result_id
             WHERE b.producer_result_id=? AND g.commit_revision=? AND g.derive_branches",
            params![call.result_id,call.commit_revision],|row|row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation:"read derived Graph fact owner" })?;
        let Some(id) = id else {
            return Ok(false);
        };
        let result = PackageResultRefV1 {
            result_id: id,
            commit_revision: call.commit_revision,
        };
        if super::super::AnalysisStore::graph_capture_cut(
            reader,
            context.key.tenant_id,
            &result,
            None,
            Some(&call.result_id),
        )? != captured
        {
            return Err(Self::invalid("graph derived fact captured cut"));
        }
        let body = Self::encode_value(fact)?;
        reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM graph_versions g JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
             JOIN graph_producer_members m ON m.scope_id=v.scope_id AND m.valid_from=? AND m.unit_ref=?
                AND m.member_kind=7 AND m.member_key=? AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
             JOIN graph_fact_values f ON f.fact_id=m.value_ref AND f.tenant_id=? AND f.body=?
             JOIN context_refs r ON r.ref_id=g.result_id AND r.tenant_id=? AND r.owner_id=?
                AND r.entity_key=? AND r.lifetime_key=? AND r.owner_revision=?
             WHERE g.result_id=? AND g.commit_revision=?)",
            params![introduction,evidence,super::super::context::version_key(&context.key)?,context.key.tenant_id.as_slice(),
                body,context.key.tenant_id.as_slice(),context.key.owner_id,context.key.entity_key,
                context.key.lifetime_key,context.key.owner_revision,result.result_id,result.commit_revision],
            |row|row.get(0),
        ).context(AnalysisDatabaseSnafu { operation:"check canonical derived Graph fact" })
    }

    fn validate_metadata(
        reader: &Connection,
        registry: &BTreeMap<(u8, u64), Vec<u8>>,
    ) -> Result<()> {
        let invalid:bool=reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id)
             WHERE (s.producer_kind<>2 AND v.restricted_count IS NOT NULL)
                OR (s.producer_kind=1 AND v.captured_revision IS NOT NULL)
                OR (s.producer_kind=2 AND ((v.restricted_count IS NULL)<>(v.captured_revision IS NULL)))
                OR (v.restricted_count IS NOT NULL AND v.restricted_count<>(
                    SELECT count(DISTINCT m.member_key) FROM graph_producer_members m
                    JOIN context_versions c ON c.version_key=m.member_key
                    WHERE m.scope_id=v.scope_id AND m.member_kind=7 AND c.sensitivity='host_restricted'
                        AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision))))
             OR EXISTS(SELECT 1 FROM graph_versions g JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
                WHERE g.derive_branches AND (v.restricted_count IS NULL OR v.captured_revision IS NULL OR EXISTS(
                    SELECT 1 FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.unit_ref=0
                        AND m.member_kind IN (0,1,7) AND m.valid_from<=v.commit_revision
                        AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision))))
             OR EXISTS(SELECT 1 FROM graph_versions g JOIN graph_producer_versions metadata ON metadata.result_id=g.metadata_result_id
                WHERE g.derive_branches AND (
                    NOT EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
                        JOIN graph_producer_scopes s ON s.scope_id=v.scope_id
                        WHERE b.result_id=g.result_id AND s.producer_kind=0 AND v.commit_revision=g.commit_revision
                            AND v.captured_revision=metadata.captured_revision)
                    OR EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
                        JOIN graph_producer_scopes s ON s.scope_id=v.scope_id
                        WHERE b.result_id=g.result_id AND s.producer_kind=0 AND v.commit_revision=g.commit_revision
                            AND v.captured_revision IS DISTINCT FROM metadata.captured_revision)))",
            [],|row|row.get(0),
        ).context(AnalysisDatabaseSnafu { operation:"validate Graph metadata summaries" })?;
        if invalid {
            return Err(Self::invalid("graph metadata summary"));
        }
        let mut statement=reader.prepare(
            "SELECT m.member_kind,m.member_key,m.value_ref,m.unit_ref,m.valid_from,m.anchor_record_id,
                m.ordinal,g.result_id,s.tenant_id,p.evidence_id,p.commit_revision,f.body,
                c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,c.commit_revision,c.body,
                e.cpu_id,e.durable_cursor,source.identity,
                EXISTS(SELECT 1 FROM context_refs r WHERE r.ref_id=g.result_id AND r.tenant_id=c.tenant_id
                    AND r.owner_id=c.owner_id AND r.entity_key=c.entity_key AND r.lifetime_key=c.lifetime_key
                    AND r.owner_revision=c.owner_revision)
             FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id)
             JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
             LEFT JOIN graph_versions g ON g.metadata_result_id=opened.result_id
             LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref
             LEFT JOIN graph_fact_values f ON f.fact_id=m.value_ref
             LEFT JOIN context_versions c ON c.version_key=m.member_key
             LEFT JOIN graph_evidence e ON e.evidence_id=m.unit_ref
             LEFT JOIN graph_sources source ON source.source_ref=e.source_ref
             WHERE s.producer_kind=2 AND (m.unit_ref<>0 OR m.member_kind=10)"
        ).context(AnalysisDatabaseSnafu { operation:"prepare Graph metadata history" })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph metadata history",
        })?;
        let mut cuts = BTreeMap::new();
        let mut headers = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph metadata history",
        })? {
            let kind: u8 = Self::column(row, 0)?;
            let key: Vec<u8> = Self::column(row, 1)?;
            let value: u64 = Self::column(row, 2)?;
            let unit: u64 = Self::column(row, 3)?;
            let opening: u64 = Self::column(row, 4)?;
            let result: String = Self::column(row, 7)?;
            let tenant: [u8; 16] = Self::column::<Vec<u8>>(row, 8)?
                .try_into()
                .map_err(|_| Self::invalid("graph metadata tenant"))?;
            let captured = match cuts.get(&(result.clone(), opening)) {
                Some(cut) => *cut,
                None => {
                    let cut = super::super::AnalysisStore::graph_capture_cut(
                        reader,
                        tenant,
                        &PackageResultRefV1 {
                            result_id: result.clone(),
                            commit_revision: opening,
                        },
                        None,
                        None,
                    )?;
                    cuts.insert((result.clone(), opening), cut);
                    cut
                }
            };
            if Self::column::<u32>(row, 6)? != 0 {
                return Err(Self::invalid("graph metadata ordinal"));
            }
            match kind {
                0 if unit == value && registry.get(&(0, unit)) == Some(&key) => {
                    if !headers.contains_key(&result) {
                        let header = Self::read_summary(reader, tenant, &result, None)?
                            .ok_or_else(|| Self::invalid("graph metadata opening header"))?;
                        headers.insert(
                            result.clone(),
                            (
                                header.snapshot.witness_deadline_utc_ns,
                                header.snapshot.missing_ranges,
                            ),
                        );
                    }
                    let (deadline, missing) = &headers[&result];
                    let cursor: u64 = Self::column(row, 20)?;
                    if !missing
                        .iter()
                        .any(|(first, last)| (*first..=*last).contains(&cursor))
                    {
                        let source: crate::EvidenceIntakeIdentityV1 =
                            Self::decode_value(&Self::column::<Vec<u8>>(row, 21)?)?;
                        super::super::AnalysisStore::check_witness_ref(
                            reader,
                            &result,
                            &crate::AnalysisWitnessV1 {
                                identity: source.into(),
                                cursor,
                                expires_utc_ns: *deadline,
                            },
                        )?;
                    }
                }
                1 if Self::column::<u64>(row, 9)? == unit
                    && Self::column::<u64>(row, 10)? <= captured
                    && registry.get(&(0, unit)) == Some(&key) => {}
                7 | 10 => {
                    let context = crate::AnalysisContextKeyV1 {
                        tenant_id: Self::column::<Vec<u8>>(row, 12)?
                            .try_into()
                            .map_err(|_| Self::invalid("graph metadata context tenant"))?,
                        owner_id: Self::column(row, 13)?,
                        entity_key: Self::column(row, 14)?,
                        lifetime_key: Self::column(row, 15)?,
                        owner_revision: Self::column(row, 16)?,
                    };
                    let revision: u64 = Self::column(row, 17)?;
                    if !context.valid()
                        || context.tenant_id != tenant
                        || revision == 0
                        || super::super::context::version_key(&context)? != key
                        || !Self::column::<bool>(row, 22)?
                    {
                        return Err(Self::invalid("graph metadata context ref"));
                    }
                    if kind == 10 {
                        if revision != value
                            || revision > captured
                            || Self::column::<Option<u64>>(row, 5)?
                                != if unit == 0 { None } else { Some(unit) }
                        {
                            return Err(Self::invalid("graph metadata proof ref"));
                        }
                    } else {
                        let fact: crate::GraphFactV1 =
                            Self::decode_value(&Self::column::<Vec<u8>>(row, 11)?)?;
                        let canonical =
                            crate::GraphFactV1::decode_context(&Self::column::<Vec<u8>>(row, 18)?)
                                .map_err(|_| Self::invalid("graph metadata canonical fact"))?;
                        let record = crate::DiscoveryRecordIdV1 {
                            stream: Self::decode_value(&Self::column::<Vec<u8>>(row, 21)?)?,
                            cpu_id: Self::column(row, 19)?,
                            durable_cursor: Self::column(row, 20)?,
                        };
                        if fact != canonical || fact.record_id != record || revision > opening {
                            return Err(Self::invalid("graph metadata fact owner"));
                        }
                    }
                }
                _ => return Err(Self::invalid("graph metadata member owner")),
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn validate_history(
        reader: &Connection,
        root: &std::path::Path,
    ) -> Result<()> {
        let lineage = format!("SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE {})",Self::LINEAGE_INVALID);
        let counts = [
            (MemberKind::Subject, "subject_count"),
            (MemberKind::Edge, "edge_count"),
            (MemberKind::Finding, "finding_count"),
            (MemberKind::UnitState, "state_count"),
            (MemberKind::Evidence, "evidence_count"),
            (MemberKind::Position, "position_count"),
            (MemberKind::Fact, "fact_count"),
        ]
        .into_iter()
        .map(|(kind, column)| format!("v.{column}<>(SELECT count(DISTINCT member_key) FROM graph_producer_members m WHERE m.scope_id=v.scope_id AND m.member_kind={} AND m.valid_from<=v.commit_revision AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision))",kind as u8))
        .collect::<Vec<_>>()
        .join(" OR ");
        let counts =
            format!("SELECT EXISTS(SELECT 1 FROM graph_producer_versions v WHERE {counts})");
        for query in [
            lineage.as_str(),
            "SELECT EXISTS(SELECT 1 FROM graph_sources s LEFT JOIN source_receipts r USING(stream_key) WHERE r.stream_key IS NULL OR r.tenant_id<>s.tenant_id)",
            "SELECT EXISTS(SELECT 1 FROM graph_evidence e LEFT JOIN graph_sources s USING(source_ref) WHERE s.source_ref IS NULL OR e.durable_cursor=0)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_scopes s LEFT JOIN graph_sources src USING(source_ref) WHERE (s.source_ref IS NOT NULL AND (src.source_ref IS NULL OR src.tenant_id<>s.tenant_id)) OR s.created_revision=0 OR s.first_cursor=0 OR (s.producer_kind=0 AND (s.instance_id IS NULL OR s.instance_id='' OR s.view_id IS NULL OR s.view_id='' OR s.call_id IS NULL)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE (s.producer_kind=0 AND (v.package_id IS NULL OR v.package_id='' OR v.package_revision IS NULL OR v.package_revision='' OR v.image_digest IS NULL OR v.image_digest='')) OR (s.producer_kind<>0 AND (v.package_id IS NOT NULL OR v.package_revision IS NOT NULL OR v.image_digest IS NOT NULL)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE s.producer_kind<>0 AND v.selected_state_ref IS NOT NULL)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v LEFT JOIN graph_producer_scopes s USING(scope_id) WHERE s.scope_id IS NULL)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN analysis_results r ON r.result_id=v.result_id WHERE s.producer_kind=0 AND (r.result_id IS NULL OR r.processor_id<>'managed-package-v1' OR r.tenant_id<>s.tenant_id OR r.commit_revision<>v.commit_revision))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m LEFT JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from LEFT JOIN graph_producer_versions closed ON closed.scope_id=m.scope_id AND closed.commit_revision=m.valid_to WHERE s.scope_id IS NULL OR opened.result_id IS NULL OR (m.valid_to IS NOT NULL AND (m.valid_to<=m.valid_from OR closed.result_id IS NULL)) OR (s.producer_kind=0 AND (m.member_kind NOT IN (2,3,4,8,9,10) OR m.anchor_record_id IS NULL)) OR (s.producer_kind=1 AND m.member_kind NOT IN (2,3,4,6)) OR (s.producer_kind=2 AND m.member_kind NOT IN (0,1,7,10)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id) WHERE s.producer_kind<>0 AND ((m.anchor_record_id IS NOT NULL AND NOT(s.producer_kind=2 AND m.member_kind=10 AND m.anchor_record_id=m.unit_ref AND m.unit_ref<>0)) OR m.anchor_fact IS NOT NULL OR m.reason_code IS NOT NULL))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id) WHERE member_kind IN (9,10) AND ((unit_ref=0 AND NOT(s.producer_kind=2 AND member_kind=10 AND anchor_record_id IS NULL)) OR anchor_fact IS NOT NULL OR reason_code IS NOT NULL OR ordinal<>0))",
            "SELECT EXISTS(SELECT 1 FROM (SELECT valid_from,lag(valid_from) OVER(PARTITION BY scope_id,unit_ref,member_kind,member_key ORDER BY valid_from) AS previous,lag(valid_to) OVER(PARTITION BY scope_id,unit_ref,member_kind,member_key ORDER BY valid_from) AS previous_to FROM graph_producer_members) ranges WHERE previous IS NOT NULL AND (previous_to IS NULL OR previous_to>valid_from))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members a JOIN graph_producer_members b ON a.scope_id=b.scope_id AND a.unit_ref<b.unit_ref AND a.member_kind=b.member_kind AND a.member_key=b.member_key WHERE a.value_ref<>b.value_ref AND (a.valid_to IS NULL OR b.valid_from<a.valid_to) AND (b.valid_to IS NULL OR a.valid_from<b.valid_to))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_evidence unit ON unit.evidence_id=m.unit_ref WHERE m.unit_ref<>0 AND (s.producer_kind=1 OR unit.evidence_id IS NULL OR unit.source_ref<>s.source_ref))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_evidence e ON e.evidence_id=m.anchor_record_id WHERE m.anchor_record_id IS NOT NULL AND (e.evidence_id IS NULL OR e.source_ref<>s.source_ref))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m LEFT JOIN graph_evidence e ON e.evidence_id=m.value_ref LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref LEFT JOIN graph_subject_values s ON s.subject_id=m.value_ref LEFT JOIN graph_edge_values edge ON edge.edge_id=m.value_ref LEFT JOIN graph_finding_values f ON f.value_id=m.value_ref LEFT JOIN graph_branch_values branch ON branch.branch_id=m.value_ref LEFT JOIN graph_fact_values fact ON fact.fact_id=m.value_ref WHERE (member_kind=0 AND e.evidence_id IS NULL) OR (member_kind IN (1,9) AND p.value_ref IS NULL) OR (member_kind=2 AND s.subject_id IS NULL) OR (member_kind=3 AND edge.edge_id IS NULL) OR (member_kind=4 AND f.value_id IS NULL) OR (member_kind=6 AND branch.branch_id IS NULL) OR (member_kind=7 AND fact.fact_id IS NULL))",
            "SELECT EXISTS(SELECT 1 FROM graph_versions v LEFT JOIN analysis_results r USING(result_id) LEFT JOIN graph_producer_versions metadata ON metadata.result_id=v.metadata_result_id LEFT JOIN graph_producer_scopes s ON s.scope_id=metadata.scope_id LEFT JOIN graph_sources src ON src.source_ref=s.source_ref WHERE r.result_id IS NULL OR r.processor_id<>'graph-findings' OR r.commit_revision<>v.commit_revision OR metadata.result_id IS NULL OR metadata.commit_revision<>v.commit_revision OR s.producer_kind<>2 OR s.tenant_id<>r.tenant_id OR src.stream_key<>r.stream_key)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b LEFT JOIN graph_versions graph ON graph.result_id=b.result_id LEFT JOIN graph_producer_versions v ON v.result_id=b.producer_result_id LEFT JOIN graph_producer_scopes s USING(scope_id) LEFT JOIN graph_sources src USING(source_ref) LEFT JOIN analysis_results r ON r.result_id=b.result_id WHERE graph.result_id IS NULL OR v.result_id IS NULL OR v.commit_revision>graph.commit_revision OR s.tenant_id<>r.tenant_id OR src.stream_key<>r.stream_key)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id GROUP BY b.result_id,v.scope_id HAVING count(*)<>1)",
            "SELECT EXISTS(SELECT 1 FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id JOIN graph_producer_scopes s USING(scope_id) JOIN analysis_results graph ON graph.result_id=b.result_id WHERE s.producer_kind=0 AND NOT EXISTS(SELECT 1 FROM managed_edges edge WHERE edge.tenant_id=graph.tenant_id AND edge.result_id=b.result_id AND edge.dependency_id=b.producer_result_id AND edge.commit_revision=graph.commit_revision))",
            "SELECT EXISTS(SELECT 1 FROM graph_versions v WHERE NOT EXISTS(SELECT 1 FROM graph_result_producers b WHERE b.result_id=v.result_id AND b.producer_result_id=v.metadata_result_id))",
            "SELECT EXISTS(SELECT g.result_id FROM graph_versions g LEFT JOIN graph_result_producers b ON b.result_id=g.result_id LEFT JOIN graph_producer_versions v ON v.result_id=b.producer_result_id LEFT JOIN graph_producer_scopes s USING(scope_id) GROUP BY g.result_id,g.metadata_result_id,g.derive_branches,g.commit_revision HAVING count(*) FILTER(WHERE s.producer_kind=2)<>1 OR count(*) FILTER(WHERE s.producer_kind=2 AND v.result_id<>g.metadata_result_id)>0 OR (g.derive_branches AND (count(*) FILTER(WHERE s.producer_kind=1)>0 OR count(*) FILTER(WHERE s.producer_kind=0)=0)) OR (NOT g.derive_branches AND (count(*) FILTER(WHERE s.producer_kind=0)>0 OR count(*) FILTER(WHERE s.producer_kind=1)<>1 OR count(*) FILTER(WHERE s.producer_kind=1 AND v.commit_revision<>g.commit_revision)>0)))",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_subject_values s ON s.subject_id=m.value_ref WHERE m.member_kind=2 AND s.tenant_id<>owner.tenant_id)",
            "SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_evidence e ON e.evidence_id=m.value_ref WHERE m.member_kind=0 AND e.source_ref<>owner.source_ref)",
            "SELECT EXISTS(SELECT 1 FROM graph_position_values v LEFT JOIN graph_evidence e USING(evidence_id) WHERE e.evidence_id IS NULL OR v.commit_revision=0)",
            counts.as_str(),
        ] {
            let invalid:bool=reader.query_row(query,[],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"validate Graph history"})?;
            if invalid {
                return super::super::AnalysisStore::reject_path(root,"the Graph history has an invalid reference");
            }
        }
        let registry = Self::registry_keys(reader)?;
        let mut statement=reader.prepare("SELECT member_kind,value_ref,member_key FROM graph_producer_members WHERE member_kind IN (0,2,3,4)").context(AnalysisDatabaseSnafu {operation:"prepare Graph key validation"})?;
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
                    "SELECT member_key,ordinal FROM graph_producer_members WHERE member_kind=? AND unit_ref=0",
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
        Self::validate_metadata(reader, &registry)?;
        crate::analysis::graph_rows::store::FindingRows::validate(reader)?;
        crate::analysis::graph_rows::store::StateRows::validate(reader)?;
        Self::validate_branches(reader)?;
        for table in ["graph_branch_values", "graph_fact_values"] {
            let mut statement = reader
                .prepare(&format!("SELECT tenant_id,body FROM {table}"))
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
                let body: Vec<u8> = Self::column(row, 1)?;
                if tenant.len() != 16 {
                    return Err(Self::invalid("graph typed value tenant"));
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

    pub(in crate::analysis) fn validate_call_members(
        reader: &Connection,
        root: &std::path::Path,
        scope: u64,
        revision: u64,
        captured: u64,
    ) -> Result<()> {
        if captured == 0 || captured >= revision {
            return Err(Self::invalid("graph call captured revision"));
        }
        let native:Option<u64>=reader.query_row("SELECT captured_revision FROM graph_producer_versions WHERE scope_id=? AND commit_revision=?",
            params![scope,revision],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"read native Graph captured cut"})?;
        if native != Some(captured) {
            return Err(Self::invalid("graph call captured revision"));
        }
        let (call, cpu): (String,u32) = reader.query_row("SELECT version.result_id,receipt.cpu_id FROM graph_producer_versions version JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_sources source USING(source_ref) JOIN source_versions receipt ON receipt.stream_key=source.stream_key AND receipt.tenant_id=owner.tenant_id AND receipt.commit_revision<=? WHERE version.scope_id=? AND version.commit_revision=? AND owner.producer_kind=0 ORDER BY receipt.commit_revision DESC LIMIT 1",params![captured,scope,revision],|row|Ok((row.get(0)?,row.get(1)?)))
            .context(AnalysisDatabaseSnafu { operation: "read Graph call dependency owner" })?;
        let selected = "member.scope_id=? AND member.valid_from<=? AND (member.valid_to IS NULL OR member.valid_to>?) AND member.unit_ref IN (SELECT unit_ref FROM graph_producer_members WHERE scope_id=? AND valid_from=?)";
        let mut support = BTreeMap::<u64, CallSupport>::new();
        let mut statement = reader.prepare(&format!("SELECT member.unit_ref,member.member_key,member.anchor_record_id,member.anchor_fact,member.reason_code,member.ordinal,position.evidence_id,position.commit_revision,source.identity,evidence.cpu_id,evidence.durable_cursor,evidence.source_ref,owner.source_ref,member.valid_to FROM graph_producer_members member JOIN graph_producer_scopes owner USING(scope_id) LEFT JOIN graph_position_values position ON position.value_ref=member.value_ref LEFT JOIN graph_evidence evidence ON evidence.evidence_id=position.evidence_id LEFT JOIN graph_sources source ON source.source_ref=evidence.source_ref WHERE {selected} AND member.member_kind=9"))
            .context(AnalysisDatabaseSnafu { operation: "prepare Graph record support" })?;
        let mut rows = statement
            .query(params![scope, revision, revision, scope, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph record support",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph record support",
        })? {
            let unit: u64 = Self::column(row, 0)?;
            let evidence: u64 = Self::column(row, 6)?;
            let position: u64 = Self::column(row, 7)?;
            let record = crate::DiscoveryRecordIdV1 {
                stream: Self::decode_value(&Self::column::<Vec<u8>>(row, 8)?)?,
                cpu_id: Self::column(row, 9)?,
                durable_cursor: Self::column(row, 10)?,
            };
            if unit == 0
                || record.durable_cursor == 0
                || record.cpu_id != cpu
                || position == 0
                || position > captured
                || Self::column::<Vec<u8>>(row, 1)? != Self::member_key(&record)?
                || Self::column::<Option<u64>>(row, 2)? != Some(evidence)
                || Self::column::<Option<Vec<u8>>>(row, 3)?.is_some()
                || Self::column::<Option<String>>(row, 4)?.is_some()
                || Self::column::<u32>(row, 5)? != 0
                || Self::column::<u64>(row, 11)? != Self::column::<u64>(row, 12)?
                || support
                    .entry(unit)
                    .or_default()
                    .records
                    .insert(evidence, (record, Self::column(row, 13)?))
                    .is_some()
            {
                return Err(Self::invalid("graph call record dependency"));
            }
        }
        drop(rows);
        drop(statement);
        let mut statement = reader.prepare(&format!("SELECT member.unit_ref,member.member_key,member.anchor_record_id,member.anchor_fact,member.reason_code,member.ordinal,context.tenant_id,context.owner_id,context.entity_key,context.lifetime_key,context.owner_revision,context.valid_from_utc_ns,context.valid_until_utc_ns,context.sensitivity,context.body,context.commit_revision,reference.commit_revision,member.valid_to,member.valid_from FROM graph_producer_members member LEFT JOIN context_versions context ON context.version_key=member.member_key AND context.commit_revision=member.value_ref LEFT JOIN context_refs reference ON reference.ref_id=? AND reference.tenant_id=context.tenant_id AND reference.owner_id=context.owner_id AND reference.entity_key=context.entity_key AND reference.lifetime_key=context.lifetime_key AND reference.owner_revision=context.owner_revision WHERE {selected} AND member.member_kind=10"))
            .context(AnalysisDatabaseSnafu { operation: "prepare Graph fact support" })?;
        let mut rows = statement
            .query(params![call, scope, revision, revision, scope, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph fact support",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph fact support",
        })? {
            let key = crate::AnalysisContextKeyV1 {
                tenant_id: Self::column::<Vec<u8>>(row, 6)?
                    .try_into()
                    .map_err(|_| Self::invalid("graph dependency tenant"))?,
                owner_id: Self::column(row, 7)?,
                entity_key: Self::column(row, 8)?,
                lifetime_key: Self::column(row, 9)?,
                owner_revision: Self::column(row, 10)?,
            };
            let (context, committed) = super::super::AnalysisStore::decode_context_row(
                root,
                key.clone(),
                (
                    Self::column(row, 11)?,
                    Self::column(row, 12)?,
                    Self::column(row, 13)?,
                    Self::column(row, 14)?,
                    Self::column(row, 15)?,
                ),
            )?;
            let fact = crate::GraphFactV1::try_from(&context)?;
            let unit: u64 = Self::column(row, 0)?;
            let evidence: u64 = Self::column(row, 2)?;
            let until: Option<u64> = Self::column(row, 17)?;
            let support = support
                .get_mut(&unit)
                .ok_or_else(|| Self::invalid("graph fact dependency unit"))?;
            let ordinary =
                committed <= captured && Self::column::<Option<u64>>(row, 16)? == Some(committed);
            let derived = if committed > captured {
                Self::derived_fact(
                    reader,
                    &PackageResultRefV1 {
                        result_id: call.clone(),
                        commit_revision: revision,
                    },
                    &crate::AnalysisContextRefV1 {
                        key: key.clone(),
                        commit_revision: committed,
                    },
                    &fact,
                    evidence,
                    captured,
                    Self::column(row, 18)?,
                )?
            } else {
                false
            };
            if (!ordinary && !derived)
                || Self::column::<Vec<u8>>(row, 1)? != super::super::context::version_key(&key)?
                || Self::column::<Option<Vec<u8>>>(row, 3)?.is_some()
                || Self::column::<Option<String>>(row, 4)?.is_some()
                || Self::column::<u32>(row, 5)? != 0
                || support.records.get(&evidence).is_none_or(|(record, end)| {
                    record != &fact.record_id || !CallSupport::covers(*end, until)
                })
                || support
                    .facts
                    .insert(
                        key.clone(),
                        (
                            FactAnchor {
                                record: fact.record_id,
                                key,
                                sensitivity: context.sensitivity,
                                value: fact.value,
                            },
                            until,
                        ),
                    )
                    .is_some()
            {
                return Err(Self::invalid("graph call fact dependency"));
            }
        }
        drop(rows);
        drop(statement);
        for (unit, support) in &support {
            let (_, until) = support
                .records
                .get(unit)
                .ok_or_else(|| Self::invalid("graph call unit support"))?;
            if support
                .records
                .values()
                .any(|(_, end)| !CallSupport::covers(*until, *end))
                || support
                    .facts
                    .values()
                    .any(|(_, end)| !CallSupport::covers(*until, *end))
            {
                return Err(Self::invalid("graph call support interval"));
            }
        }
        let mut statement = reader.prepare("SELECT member.unit_ref,source.identity,anchor.cpu_id,anchor.durable_cursor,member.anchor_fact,member.valid_to,member.anchor_record_id FROM graph_producer_members member JOIN graph_producer_scopes owner USING(scope_id) JOIN graph_sources source ON source.source_ref=owner.source_ref LEFT JOIN graph_evidence anchor ON anchor.evidence_id=member.anchor_record_id AND anchor.source_ref=owner.source_ref WHERE member.scope_id=? AND member.valid_from=? AND member.member_kind IN (2,3,4,8)")
            .context(AnalysisDatabaseSnafu { operation: "prepare Graph call anchor validation" })?;
        let mut rows =
            statement
                .query(params![scope, revision])
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph call anchor validation",
                })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call anchor validation",
        })? {
            let source =
                Self::decode_value::<crate::EvidenceIntakeIdentityV1>(&Self::column::<Vec<u8>>(
                    row, 1,
                )?)?;
            let bytes: Option<Vec<u8>> = Self::column(row, 4)?;
            let fact = bytes
                .as_deref()
                .map(Self::decode_value::<FactAnchor>)
                .transpose()?;
            if fact.as_ref().map(Self::encode_value).transpose()? != bytes {
                return Err(Self::invalid("graph call fact encoding"));
            }
            let anchor = Anchor {
                record: crate::DiscoveryRecordIdV1 {
                    stream: source,
                    cpu_id: Self::column(row, 2)?,
                    durable_cursor: Self::column(row, 3)?,
                },
                fact,
            };
            let unit: u64 = Self::column(row, 0)?;
            let support = support
                .get(&unit)
                .ok_or_else(|| Self::invalid("graph call member unit"))?;
            let until: Option<u64> = Self::column(row, 5)?;
            let record: u64 = Self::column(row, 6)?;
            if support
                .records
                .get(&unit)
                .is_none_or(|(_, end)| !CallSupport::covers(*end, until))
                || support.records.get(&record).is_none_or(|(record, end)| {
                    record != &anchor.record || !CallSupport::covers(*end, until)
                })
                || anchor.fact.as_ref().is_some_and(|fact| {
                    support.facts.get(&fact.key).is_none_or(|(value, end)| {
                        value != fact || !CallSupport::covers(*end, until)
                    })
                })
            {
                return Err(Self::invalid("graph call member support"));
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
