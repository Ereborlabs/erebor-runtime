use super::*;
use crate::{AnalysisStore, DiscoveryRecordIdV1, GraphEdgeV1, GraphValidate as _, StorePositionV1};
use araphor_analysis_builtins::graph::BranchExt;

type GraphInputs = (
    Vec<DiscoveryRecordIdV1>,
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
);

impl GraphRows {
    pub(in crate::analysis) fn same_revision(
        reader: &Connection,
        before: &str,
        prior: &GraphHeader,
        after: &str,
        current: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<bool> {
        let tenant = prior.snapshot.scope.identity.tenant_id;
        if current.snapshot.scope.identity.tenant_id != tenant {
            return Err(Self::invalid("graph revision tenant"));
        }
        if AnalysisStore::native_graph_result(reader,before)? || AnalysisStore::native_graph_result(reader,after)? {
            return Ok(before==after);
        }
        prior.snapshot.input_manifest.validate(tenant)?;
        current.snapshot.input_manifest.validate(tenant)?;
        if before == after {
            return Ok(true);
        }
        if prior.snapshot.input_manifest.coverage != current.snapshot.input_manifest.coverage
            || prior.snapshot.missing_ranges != current.snapshot.missing_ranges
        {
            return Ok(false);
        }
        if prior.restricted_count.is_some()
            && current.restricted_count.is_some()
            && (prior.evidence_count != current.evidence_count
                || prior.fact_count != current.fact_count)
        {
            return Ok(false);
        }
        let mut cuts = Vec::with_capacity(2);
        for id in [before, after] {
            let cut: (u64, u64) = reader
                .query_row(
                    "SELECT v.scope_id,v.commit_revision FROM graph_versions g
                 JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
                 JOIN graph_producer_scopes s USING(scope_id)
                 WHERE g.result_id=? AND v.commit_revision=g.commit_revision AND s.producer_kind=2",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph revision metadata cut",
                })?;
            cuts.push(cut);
        }
        if cuts[0].0 != cuts[1].0
            || prior.restricted_count.is_none()
            || current.restricted_count.is_none()
        {
            let prior = Self::read_metadata_control(reader, tenant, before, control)?
                .ok_or_else(|| Self::invalid("graph revision source"))?;
            let current = Self::read_metadata_control(reader, tenant, after, control)?
                .ok_or_else(|| Self::invalid("graph revision source"))?;
            return Ok(prior.snapshot.input_manifest == current.snapshot.input_manifest);
        }
        Self::check(control)?;
        let (low, high) = (cuts[0].1.min(cuts[1].1), cuts[0].1.max(cuts[1].1));
        let changed: bool = reader
            .query_row(
                "WITH touched AS (
                SELECT member_kind,member_key FROM graph_producer_members
                WHERE scope_id=? AND member_kind IN (0,7) AND valid_from>? AND valid_from<=?
                UNION SELECT member_kind,member_key FROM graph_producer_members
                WHERE scope_id=? AND member_kind IN (0,7) AND valid_to>? AND valid_to<=?
             ), before_members AS (
                SELECT DISTINCT m.member_kind,m.member_key FROM touched k
                JOIN graph_producer_members m USING(member_kind,member_key)
                WHERE m.scope_id=? AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)
             ), after_members AS (
                SELECT DISTINCT m.member_kind,m.member_key FROM touched k
                JOIN graph_producer_members m USING(member_kind,member_key)
                WHERE m.scope_id=? AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)
             ) SELECT EXISTS((SELECT * FROM before_members EXCEPT SELECT * FROM after_members)
                UNION ALL (SELECT * FROM after_members EXCEPT SELECT * FROM before_members))",
                params![
                    cuts[0].0, low, high, cuts[0].0, low, high, cuts[0].0, low, low, cuts[0].0,
                    high, high
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "compare native Graph revision endpoints",
            })?;
        Ok(!changed)
    }

    pub(in crate::analysis) fn provenance(
        reader: &Connection,
        result: &PackageResultRefV1,
        request: super::super::graph::GraphRequestMeta,
        control: Option<&AnalysisReadControl>,
        charge: &mut impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<(
        Vec<crate::AnalysisWitnessV1>,
        Vec<crate::AnalysisContextRefV1>,
    )> {
        let tenant = request.scope.identity.tenant_id;
        let header = Self::read_summary(reader, tenant, &result.result_id, control)?
            .ok_or_else(|| Self::invalid("graph provenance result"))?;
        if !header.derive_branches {
            return Ok((request.witnesses, request.context_refs));
        }
        let revision: u64 = reader
            .query_row(
                "SELECT commit_revision FROM graph_versions WHERE result_id=?",
                params![result.result_id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check Graph provenance revision",
            })?;
        if revision != result.commit_revision || request.scope != header.snapshot.scope {
            return Err(Self::invalid("graph provenance cut"));
        }
        let size = header
            .evidence_count
            .saturating_mul(
                std::mem::size_of::<DiscoveryRecordIdV1>()
                    .saturating_add(header.snapshot.scope.identity.node_id.len())
                    .saturating_add(std::mem::size_of::<crate::AnalysisWitnessV1>()),
            )
            .saturating_add(
                header
                    .position_count
                    .saturating_mul(std::mem::size_of::<(DiscoveryRecordIdV1, StorePositionV1)>()),
            );
        charge(size, size)?;
        let (records, _) = Self::inputs(reader, &result.result_id, &header, control)?;
        let witnesses = records
            .into_iter()
            .filter(|record| {
                !header
                    .snapshot
                    .missing_ranges
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&record.durable_cursor))
            })
            .map(|record| crate::AnalysisWitnessV1 {
                identity: record.stream.into(),
                cursor: record.durable_cursor,
                expires_utc_ns: header.snapshot.witness_deadline_utc_ns,
            })
            .collect();
        let mut contexts = BTreeMap::new();
        let mut statement=reader.prepare(
            "SELECT DISTINCT c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,c.commit_revision
             FROM graph_versions g JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
             JOIN graph_producer_members m ON m.scope_id=v.scope_id AND m.valid_from<=v.commit_revision
                AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
             LEFT JOIN context_versions c ON c.version_key=m.member_key
                AND (m.member_kind=7 OR c.commit_revision=m.value_ref)
             WHERE g.result_id=? AND m.member_kind IN (7,10)"
        ).context(AnalysisDatabaseSnafu { operation:"prepare native Graph context refs" })?;
        let mut rows =
            statement
                .query(params![result.result_id])
                .context(AnalysisDatabaseSnafu {
                    operation: "read native Graph context refs",
                })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native Graph context refs",
        })? {
            Self::check(control)?;
            let key = crate::AnalysisContextKeyV1 {
                tenant_id: Self::column::<Vec<u8>>(row, 0)?
                    .try_into()
                    .map_err(|_| Self::invalid("graph provenance tenant"))?,
                owner_id: Self::column(row, 1)?,
                entity_key: Self::column(row, 2)?,
                lifetime_key: Self::column(row, 3)?,
                owner_revision: Self::column(row, 4)?,
            };
            let revision: u64 = Self::column(row, 5)?;
            let bytes = std::mem::size_of::<crate::AnalysisContextRefV1>().saturating_add(
                key.owner_id.capacity() + key.entity_key.capacity() + key.lifetime_key.capacity(),
            );
            charge(bytes, bytes)?;
            if !key.valid()
                || key.tenant_id != tenant
                || revision == 0
                || revision > result.commit_revision
                || contexts
                    .insert(key, revision)
                    .is_some_and(|prior| prior != revision)
            {
                return Err(Self::invalid("graph provenance context ref"));
            }
        }
        Ok((
            witnesses,
            contexts
                .into_iter()
                .map(|(key, commit_revision)| crate::AnalysisContextRefV1 {
                    key,
                    commit_revision,
                })
                .collect(),
        ))
    }

    pub(in crate::analysis) fn bound_findings(
        reader: &Connection,
        result: &str,
        id: Option<&str>,
        source: &crate::EvidenceIntakeIdentityV1,
        charge: &mut impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<()> {
        if AnalysisStore::bound_native_findings(reader,result,id,charge)? { return Ok(()); }
        let role = MemberKind::Finding as u8;
        let filter = if id.is_some() {
            "AND m.member_key=?"
        } else {
            ""
        };
        let selected = if id.is_some() {
            "WHERE f.finding_id=?"
        } else {
            ""
        };
        let mut parameters = vec![duckdb::types::Value::Text(result.to_owned())];
        if let Some(id) = id {
            parameters.push(duckdb::types::Value::Blob(Self::member_key(&id)?));
            parameters.push(duckdb::types::Value::Text(id.to_owned()));
        }
        let (count,bytes,records,intervals,limits):(u64,u64,u64,u64,u64)=reader.query_row(&format!(
            "WITH members AS (SELECT DISTINCT m.value_ref FROM graph_result_producers b
                JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
                JOIN graph_producer_members m ON m.scope_id=v.scope_id AND m.valid_from<=v.commit_revision
                    AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
                WHERE b.result_id=? AND m.member_kind={role} {filter})
             SELECT count(*),coalesce(sum(octet_length(f.policy_provenance)+octet_length(f.effects)+octet_length(f.reason)
                +octet_length(encode(f.finding_id))+octet_length(encode(f.package_id))
                +octet_length(encode(f.state))+octet_length(encode(f.severity))+octet_length(encode(f.sensitivity))
                +coalesce(octet_length(encode(f.required_action)),0)
                +coalesce(list_sum(list_transform(f.required_coverage_interval_ids,x->octet_length(x))),0)
                +coalesce(list_sum(list_transform(f.limits,x->octet_length(encode(x)))),0)
                +octet_length(encode(s.authority_text))+octet_length(s.authority_boot)+octet_length(s.identity)),0),
                coalesce(sum(len(f.evidence_refs)),0),coalesce(sum(len(f.required_coverage_interval_ids)),0),coalesce(sum(len(f.limits)),0)
             FROM members m JOIN graph_finding_values f ON f.value_id=m.value_ref
             JOIN graph_subject_values s ON s.subject_id=f.subject_ref {selected}"
        ),duckdb::params_from_iter(parameters.iter()),|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))
            .context(AnalysisDatabaseSnafu {operation:"bound native finding values"})?;
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        let input = bytes
            .saturating_mul(2)
            .saturating_add(usize::try_from(count).unwrap_or(usize::MAX).saturating_mul(
                std::mem::size_of::<FindingV1>() + std::mem::size_of::<GraphSubjectKeyV1>(),
            ))
            .saturating_add(
                usize::try_from(records)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(
                        std::mem::size_of::<DiscoveryRecordIdV1>() + source.node_id.len(),
                    )
                    .saturating_mul(2),
            )
            .saturating_add(
                usize::try_from(intervals)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(std::mem::size_of::<[u8; 16]>()),
            )
            .saturating_add(
                usize::try_from(limits)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(std::mem::size_of::<String>()),
            );
        charge(bytes, input)
    }

    pub(in crate::analysis) fn finding_provenance(
        reader: &Connection,
        root: &std::path::Path,
        result: &PackageResultRefV1,
        request: super::super::graph::GraphRequestMeta,
        findings: &BTreeSet<String>,
        control: Option<&AnalysisReadControl>,
        charge: &mut impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<(
        Vec<crate::AnalysisWitnessV1>,
        Vec<crate::AnalysisContextRefV1>,
    )> {
        let tenant = request.scope.identity.tenant_id;
        let finding_kind = MemberKind::Finding as u8;
        let record_kind = MemberKind::UnitRecord as u8;
        let fact_kind = MemberKind::UnitFact as u8;
        let evidence_kind = MemberKind::Evidence as u8;
        let position_kind = MemberKind::Position as u8;
        let metadata_fact = MemberKind::Fact as u8;
        let length:u64=reader.query_row("SELECT octet_length(body) FROM analysis_results WHERE tenant_id=? AND result_id=? AND commit_revision=? AND processor_id=?",
            params![tenant.as_slice(),result.result_id,result.commit_revision,crate::GRAPH_PROCESSOR],|row|row.get(0))
            .context(AnalysisDatabaseSnafu {operation:"bound finding provenance header"})?;
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        charge(length, length.saturating_mul(2))?;
        let header = Self::read_summary(reader, tenant, &result.result_id, control)?
            .ok_or_else(|| Self::invalid("graph finding provenance result"))?;
        if !header.derive_branches || header.restricted_count.is_none() {
            return Self::provenance(reader, result, request, control, charge);
        }
        let (scope, revision): (u64, u64) = reader
            .query_row(
                &format!(
                    "SELECT v.scope_id,g.commit_revision FROM graph_versions g
             JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
             JOIN graph_producer_scopes s ON s.scope_id=v.scope_id
             WHERE g.result_id=? AND s.producer_kind={} AND s.tenant_id=?",
                    Self::METADATA_PRODUCER
                ),
                params![result.result_id, tenant.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read finding provenance cut",
            })?;
        if revision != result.commit_revision
            || request.scope != header.snapshot.scope
            || findings.is_empty()
        {
            return Err(Self::invalid("graph finding provenance cut"));
        }
        let source = &header.snapshot.scope.identity;
        charge(
            0,
            findings
                .len()
                .saturating_add(1)
                .saturating_mul(std::mem::size_of::<duckdb::types::Value>())
                .saturating_add(result.result_id.len()),
        )?;
        let placeholders = std::iter::repeat_n("?", findings.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut parameters = Vec::with_capacity(findings.len().saturating_add(1));
        parameters.push(duckdb::types::Value::Text(result.result_id.clone()));
        for finding in findings {
            let key = Self::member_key(finding)?;
            charge(0, key.capacity())?;
            parameters.push(duckdb::types::Value::Blob(key));
        }
        let mut statement=reader.prepare(&format!(
            "SELECT DISTINCT v.scope_id,v.commit_revision,m.unit_ref,v.result_id,f.finding_id,m.member_key,
                s.tenant_id,src.stream_key,s.producer_kind,s.first_cursor,f.package_id=v.package_id
             FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
             JOIN graph_producer_scopes s ON s.scope_id=v.scope_id
             JOIN graph_sources src ON src.source_ref=s.source_ref
             JOIN graph_producer_members m ON m.scope_id=v.scope_id AND m.valid_from<=v.commit_revision
                AND (m.valid_to IS NULL OR m.valid_to>v.commit_revision)
             JOIN graph_finding_values f ON f.value_id=m.value_ref
             WHERE b.result_id=? AND m.member_kind={finding_kind} AND m.member_key IN ({placeholders})"
        )).context(AnalysisDatabaseSnafu {operation:"prepare finding provenance owners"})?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read finding provenance owners",
            })?;
        let mut owners = BTreeSet::new();
        let mut selected = BTreeSet::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance finding provenance owners",
        })? {
            Self::check(control)?;
            let finding: String = Self::column(row, 4)?;
            let unit: u64 = Self::column(row, 2)?;
            let cut: u64 = Self::column(row, 1)?;
            let call: String = Self::column(row, 3)?;
            if !findings.contains(&finding)
                || Self::column::<Vec<u8>>(row, 5)? != Self::member_key(&finding)?
                || Self::column::<Vec<u8>>(row, 6)? != tenant
                || Self::column::<Vec<u8>>(row, 7)? != source.key()
                || Self::column::<u8>(row, 8)? != Self::CALL_PRODUCER
                || Self::column::<u64>(row, 9)? != header.snapshot.first_cursor
                || unit == 0
                || cut > revision
                || call.is_empty()
                || !Self::column::<bool>(row, 10)?
            {
                return Err(Self::invalid("graph finding provenance owner"));
            }
            let bytes = std::mem::size_of::<((u64, u64, u64), String)>()
                + call.capacity()
                + std::mem::size_of::<String>()
                + finding.capacity();
            charge(bytes, bytes)?;
            owners.insert((Self::column::<u64>(row, 0)?, cut, unit));
            selected.insert(finding);
        }
        if &selected != findings {
            return Err(Self::invalid("graph finding provenance membership"));
        }
        drop(rows);
        drop(statement);
        let mut records = BTreeMap::<u64, (DiscoveryRecordIdV1, StorePositionV1)>::new();
        let mut contexts = BTreeMap::new();
        let mut cuts = BTreeMap::new();
        for (owner, cut, unit) in owners {
            Self::check(control)?;
            let mut statement=reader.prepare(&format!(
                "WITH candidates AS MATERIALIZED (SELECT * FROM graph_producer_members WHERE unit_ref=?)
                 SELECT m.member_key,m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal,
                    p.evidence_id,p.commit_revision,p.ordinal,e.cpu_id,e.durable_cursor,src.stream_key,r.cpu_id,
                    m.valid_from,opened.result_id,introduced.result_id
                 FROM candidates m JOIN graph_producer_scopes s USING(scope_id)
                 LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
                 LEFT JOIN (SELECT g.*,b.producer_result_id FROM graph_versions g
                    JOIN graph_result_producers b ON b.result_id=g.result_id) introduced
                    ON introduced.commit_revision=opened.commit_revision AND introduced.derive_branches
                    AND introduced.producer_result_id=opened.result_id
                 LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref
                 LEFT JOIN graph_evidence e ON e.evidence_id=p.evidence_id AND e.source_ref=s.source_ref
                 LEFT JOIN graph_sources src ON src.source_ref=e.source_ref
                 LEFT JOIN source_receipts r ON r.stream_key=src.stream_key AND r.tenant_id=s.tenant_id
                 WHERE m.scope_id=? AND m.member_kind={record_kind}
                    AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)"
            )).context(AnalysisDatabaseSnafu {operation:"prepare finding record support"})?;
            let mut rows =
                statement
                    .query(params![unit, owner, cut, cut])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read finding record support",
                    })?;
            let mut support = BTreeMap::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance finding record support",
            })? {
                Self::check(control)?;
                let opening: u64 = Self::column(row, 12)?;
                let call: String = Self::column(row, 13)?;
                let graph: String = Self::column(row, 14)?;
                let captured = match cuts.get(&(graph.clone(), Some(call.clone()), opening)) {
                    Some(captured) => *captured,
                    None => {
                        let captured = super::super::AnalysisStore::graph_capture_cut(
                            reader,
                            tenant,
                            &PackageResultRefV1 {
                                result_id: graph.clone(),
                                commit_revision: opening,
                            },
                            None,
                            Some(&call),
                        )?;
                        charge(
                            0,
                            std::mem::size_of::<((String, Option<String>, u64), u64)>()
                                + graph.capacity()
                                + call.capacity(),
                        )?;
                        cuts.insert((graph, Some(call), opening), captured);
                        captured
                    }
                };
                let record = DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: Self::column(row, 8)?,
                    durable_cursor: Self::column(row, 9)?,
                };
                let evidence: u64 = Self::column(row, 5)?;
                let position = StorePositionV1 {
                    commit_revision: Self::column(row, 6)?,
                    ordinal: Self::column(row, 7)?,
                };
                if record.durable_cursor == 0
                    || Self::column::<Vec<u8>>(row, 0)? != Self::member_key(&record)?
                    || Self::column::<Option<u64>>(row, 1)? != Some(evidence)
                    || Self::column::<Option<Vec<u8>>>(row, 2)?.is_some()
                    || Self::column::<Option<String>>(row, 3)?.is_some()
                    || Self::column::<u32>(row, 4)? != 0
                    || Self::column::<Vec<u8>>(row, 10)? != source.key()
                    || Self::column::<u32>(row, 11)? != record.cpu_id
                    || position.commit_revision == 0
                    || position.commit_revision > captured
                    || support.contains_key(&evidence)
                    || records
                        .get(&evidence)
                        .is_some_and(|prior| prior != &(record.clone(), position))
                {
                    return Err(Self::invalid("graph finding record dependency"));
                }
                let bytes = 2usize.saturating_mul(
                    std::mem::size_of::<(u64, (DiscoveryRecordIdV1, StorePositionV1))>()
                        + record.stream.node_id.capacity(),
                );
                charge(bytes, bytes)?;
                support.insert(evidence, record.clone());
                records.insert(evidence, (record, position));
            }
            if !support.contains_key(&unit) {
                return Err(Self::invalid("graph finding unit support"));
            }
            drop(rows);
            drop(statement);
            let mut statement=reader.prepare(&format!(
                "WITH candidates AS MATERIALIZED (SELECT * FROM graph_producer_members WHERE unit_ref=?)
                 SELECT m.member_key,m.anchor_record_id,m.anchor_fact,m.reason_code,m.ordinal,m.valid_from,
                    c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,c.owner_revision,c.valid_from_utc_ns,
                    c.valid_until_utc_ns,c.sensitivity,octet_length(c.body),c.body,c.commit_revision,r.commit_revision,
                    opened.result_id,introduced.result_id
                 FROM candidates m
                 LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
                 LEFT JOIN (SELECT g.*,b.producer_result_id FROM graph_versions g
                    JOIN graph_result_producers b ON b.result_id=g.result_id) introduced
                    ON introduced.commit_revision=opened.commit_revision AND introduced.derive_branches
                    AND introduced.producer_result_id=opened.result_id
                 LEFT JOIN context_versions c ON c.version_key=m.member_key AND c.commit_revision=m.value_ref
                 LEFT JOIN context_refs r ON r.ref_id=opened.result_id AND r.tenant_id=c.tenant_id AND r.owner_id=c.owner_id
                    AND r.entity_key=c.entity_key AND r.lifetime_key=c.lifetime_key AND r.owner_revision=c.owner_revision
                 WHERE m.scope_id=? AND m.member_kind={fact_kind}
                    AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)"
            )).context(AnalysisDatabaseSnafu {operation:"prepare finding fact support"})?;
            let mut rows =
                statement
                    .query(params![unit, owner, cut, cut])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read finding fact support",
                    })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance finding fact support",
            })? {
                Self::check(control)?;
                let opening: u64 = Self::column(row, 5)?;
                let call: String = Self::column(row, 18)?;
                let graph: String = Self::column(row, 19)?;
                let captured = match cuts.get(&(graph.clone(), Some(call.clone()), opening)) {
                    Some(captured) => *captured,
                    None => {
                        let captured = super::super::AnalysisStore::graph_capture_cut(
                            reader,
                            tenant,
                            &PackageResultRefV1 {
                                result_id: graph.clone(),
                                commit_revision: opening,
                            },
                            None,
                            Some(&call),
                        )?;
                        charge(
                            0,
                            std::mem::size_of::<((String, Option<String>, u64), u64)>()
                                + graph.capacity()
                                + call.capacity(),
                        )?;
                        cuts.insert((graph, Some(call.clone()), opening), captured);
                        captured
                    }
                };
                let length = usize::try_from(Self::column::<u64>(row, 14)?).unwrap_or(usize::MAX);
                charge(length, length.saturating_mul(3))?;
                let key = crate::AnalysisContextKeyV1 {
                    tenant_id: Self::column::<Vec<u8>>(row, 6)?
                        .try_into()
                        .map_err(|_| Self::invalid("graph finding fact tenant"))?,
                    owner_id: Self::column(row, 7)?,
                    entity_key: Self::column(row, 8)?,
                    lifetime_key: Self::column(row, 9)?,
                    owner_revision: Self::column(row, 10)?,
                };
                let bytes = key.owner_id.capacity()
                    + key.entity_key.capacity()
                    + key.lifetime_key.capacity();
                charge(bytes, bytes.saturating_mul(3))?;
                let (context, committed) = super::super::AnalysisStore::decode_context_row(
                    root,
                    key.clone(),
                    (
                        Self::column(row, 11)?,
                        Self::column(row, 12)?,
                        Self::column(row, 13)?,
                        Self::column(row, 15)?,
                        Self::column(row, 16)?,
                    ),
                )?;
                let fact = crate::GraphFactV1::try_from(&context)?;
                let evidence: u64 = Self::column(row, 1)?;
                let reference = crate::AnalysisContextRefV1 {
                    key: key.clone(),
                    commit_revision: committed,
                };
                let ordinary = committed <= captured
                    && Self::column::<Option<u64>>(row, 17)? == Some(committed);
                let derived = committed > captured
                    && Self::derived_fact(
                        reader,
                        &PackageResultRefV1 {
                            result_id: call.clone(),
                            commit_revision: opening,
                        },
                        &reference,
                        &fact,
                        evidence,
                        captured,
                        Self::column(row, 5)?,
                    )?;
                let body = Self::encode_value(&fact)?;
                let native:bool=reader.query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_fact_values f ON f.fact_id=m.value_ref
                     WHERE m.unit_ref=? AND m.scope_id=? AND m.member_kind={metadata_fact} AND m.member_key=?
                        AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)
                        AND f.tenant_id=? AND f.body=?)"),
                    params![evidence,scope,super::super::context::version_key(&key)?,revision,revision,tenant.as_slice(),body],|row|row.get(0),
                ).context(AnalysisDatabaseSnafu {operation:"check finding metadata fact"})?;
                if committed == 0
                    || !ordinary && !derived
                    || !native
                    || key.tenant_id != tenant
                    || !key.valid()
                    || Self::column::<Vec<u8>>(row, 0)? != super::super::context::version_key(&key)?
                    || Self::column::<Option<Vec<u8>>>(row, 2)?.is_some()
                    || Self::column::<Option<String>>(row, 3)?.is_some()
                    || Self::column::<u32>(row, 4)? != 0
                    || support.get(&evidence) != Some(&fact.record_id)
                {
                    return Err(Self::invalid("graph finding fact dependency"));
                }
                charge(
                    0,
                    std::mem::size_of::<(crate::AnalysisContextKeyV1, u64)>()
                        + key.owner_id.capacity()
                        + key.entity_key.capacity()
                        + key.lifetime_key.capacity()
                        + fact.allocated_bytes(),
                )?;
                if contexts
                    .insert(key, committed)
                    .is_some_and(|old| old != committed)
                {
                    return Err(Self::invalid("graph finding context conflict"));
                }
            }
        }
        charge(
            0,
            records
                .len()
                .saturating_mul(std::mem::size_of::<crate::AnalysisWitnessV1>()),
        )?;
        let mut witnesses = Vec::with_capacity(records.len());
        for (unit, (record, position)) in &records {
            Self::check(control)?;
            let mut statement=reader.prepare(&format!(
                "SELECT evidence.member_key,evidence.value_ref,evidence.valid_from,g.result_id,
                    p.evidence_id,p.commit_revision,p.ordinal,position.member_key,
                    evidence.anchor_record_id,evidence.anchor_fact,evidence.reason_code,evidence.ordinal,
                    position.anchor_record_id,position.anchor_fact,position.reason_code,position.ordinal
                 FROM graph_producer_members evidence
                 JOIN graph_producer_versions opened ON opened.scope_id=evidence.scope_id AND opened.commit_revision=evidence.valid_from
                 JOIN graph_versions g ON g.metadata_result_id=opened.result_id
                 JOIN graph_producer_members position ON position.scope_id=evidence.scope_id AND position.unit_ref=evidence.unit_ref
                    AND position.member_kind={position_kind} AND position.valid_from<=? AND (position.valid_to IS NULL OR position.valid_to>?)
                 JOIN graph_position_values p ON p.value_ref=position.value_ref
                 WHERE evidence.unit_ref=? AND evidence.scope_id=? AND evidence.member_kind={evidence_kind}
                    AND evidence.valid_from<=? AND (evidence.valid_to IS NULL OR evidence.valid_to>?) LIMIT 2"
            )).context(AnalysisDatabaseSnafu {operation:"prepare finding metadata record"})?;
            let mut rows = statement
                .query(params![revision, revision, unit, scope, revision, revision])
                .context(AnalysisDatabaseSnafu {
                    operation: "read finding metadata record",
                })?;
            let row = rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "advance finding metadata record",
                })?
                .ok_or_else(|| Self::invalid("graph finding metadata record"))?;
            let opening: u64 = Self::column(row, 2)?;
            let id: String = Self::column(row, 3)?;
            if Self::column::<Vec<u8>>(row, 0)? != Self::member_key(record)?
                || Self::column::<u64>(row, 1)? != *unit
                || Self::column::<u64>(row, 4)? != *unit
                || Self::column::<u64>(row, 5)? != position.commit_revision
                || Self::column::<u32>(row, 6)? != position.ordinal
                || Self::column::<Vec<u8>>(row, 7)? != Self::member_key(record)?
                || Self::column::<Option<u64>>(row, 8)?.is_some()
                || Self::column::<Option<Vec<u8>>>(row, 9)?.is_some()
                || Self::column::<Option<String>>(row, 10)?.is_some()
                || Self::column::<u32>(row, 11)? != 0
                || Self::column::<Option<u64>>(row, 12)?.is_some()
                || Self::column::<Option<Vec<u8>>>(row, 13)?.is_some()
                || Self::column::<Option<String>>(row, 14)?.is_some()
                || Self::column::<u32>(row, 15)? != 0
            {
                return Err(Self::invalid("graph finding metadata position"));
            }
            if rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "check finding metadata record uniqueness",
                })?
                .is_some()
            {
                return Err(Self::invalid("graph finding metadata record conflict"));
            }
            let captured = match cuts.get(&(id.clone(), None, opening)) {
                Some(captured) => *captured,
                None => {
                    let captured = super::super::AnalysisStore::graph_capture_cut(
                        reader,
                        tenant,
                        &PackageResultRefV1 {
                            result_id: id.clone(),
                            commit_revision: opening,
                        },
                        None,
                        None,
                    )?;
                    charge(
                        0,
                        std::mem::size_of::<((String, Option<String>, u64), u64)>() + id.len(),
                    )?;
                    cuts.insert((id.clone(), None, opening), captured);
                    captured
                }
            };
            if position.commit_revision > captured {
                return Err(Self::invalid("graph finding position cut"));
            }
            let length:u64=reader.query_row("SELECT octet_length(body) FROM analysis_results WHERE tenant_id=? AND result_id=? AND processor_id=?",
                params![tenant.as_slice(),id,crate::GRAPH_PROCESSOR],|row|row.get(0))
                .context(AnalysisDatabaseSnafu {operation:"bound finding opening header"})?;
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            charge(length, length.saturating_mul(2))?;
            let original = Self::read_summary(reader, tenant, &id, control)?
                .ok_or_else(|| Self::invalid("graph finding opening header"))?;
            if original.snapshot.scope != header.snapshot.scope
                || header.snapshot.witness_deadline_utc_ns
                    > original.snapshot.witness_deadline_utc_ns
            {
                return Err(Self::invalid("graph finding witness deadline"));
            }
            if !original
                .snapshot
                .missing_ranges
                .iter()
                .any(|(first, last)| (*first..=*last).contains(&record.durable_cursor))
            {
                super::super::AnalysisStore::check_witness_ref(
                    reader,
                    &id,
                    &crate::AnalysisWitnessV1 {
                        identity: record.stream.clone().into(),
                        cursor: record.durable_cursor,
                        expires_utc_ns: original.snapshot.witness_deadline_utc_ns,
                    },
                )?;
            }
            if !header
                .snapshot
                .missing_ranges
                .iter()
                .any(|(first, last)| (*first..=*last).contains(&record.durable_cursor))
            {
                charge(0, record.stream.node_id.capacity())?;
                witnesses.push(crate::AnalysisWitnessV1 {
                    identity: record.stream.clone().into(),
                    cursor: record.durable_cursor,
                    expires_utc_ns: header.snapshot.witness_deadline_utc_ns,
                });
            }
        }
        charge(
            0,
            records
                .len()
                .saturating_add(1)
                .saturating_mul(std::mem::size_of::<u64>()),
        )?;
        let mut units = Vec::with_capacity(records.len().saturating_add(1));
        units.extend(records.keys().copied());
        units.push(0);
        let mut statement=reader.prepare(&format!(
            "SELECT m.member_key,m.anchor_record_id,m.value_ref,c.tenant_id,c.owner_id,c.entity_key,c.lifetime_key,
                c.owner_revision,c.commit_revision,m.valid_from,g.result_id,r.commit_revision,
                m.anchor_fact,m.reason_code,m.ordinal
             FROM graph_producer_members m LEFT JOIN context_versions c ON c.version_key=m.member_key AND c.commit_revision=m.value_ref
             LEFT JOIN graph_producer_versions opened ON opened.scope_id=m.scope_id AND opened.commit_revision=m.valid_from
             LEFT JOIN graph_versions g ON g.metadata_result_id=opened.result_id
             LEFT JOIN context_refs r ON r.ref_id=g.result_id AND r.tenant_id=c.tenant_id AND r.owner_id=c.owner_id
                AND r.entity_key=c.entity_key AND r.lifetime_key=c.lifetime_key AND r.owner_revision=c.owner_revision
             WHERE m.unit_ref=? AND m.scope_id=? AND m.member_kind={fact_kind} AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?)"
        )).context(AnalysisDatabaseSnafu {operation:"prepare finding upstream refs"})?;
        for unit in units {
            let mut rows = statement
                .query(params![unit, scope, revision, revision])
                .context(AnalysisDatabaseSnafu {
                    operation: "read finding upstream refs",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance finding upstream refs",
            })? {
                Self::check(control)?;
                let key = crate::AnalysisContextKeyV1 {
                    tenant_id: Self::column::<Vec<u8>>(row, 3)?
                        .try_into()
                        .map_err(|_| Self::invalid("graph finding proof tenant"))?,
                    owner_id: Self::column(row, 4)?,
                    entity_key: Self::column(row, 5)?,
                    lifetime_key: Self::column(row, 6)?,
                    owner_revision: Self::column(row, 7)?,
                };
                let committed: u64 = Self::column(row, 8)?;
                let opening: u64 = Self::column(row, 9)?;
                let id: String = Self::column(row, 10)?;
                let captured = match cuts.get(&(id.clone(), None, opening)) {
                    Some(captured) => *captured,
                    None => {
                        let captured = super::super::AnalysisStore::graph_capture_cut(
                            reader,
                            tenant,
                            &PackageResultRefV1 {
                                result_id: id.clone(),
                                commit_revision: opening,
                            },
                            None,
                            None,
                        )?;
                        charge(
                            0,
                            std::mem::size_of::<((String, Option<String>, u64), u64)>()
                                + id.capacity(),
                        )?;
                        cuts.insert((id, None, opening), captured);
                        captured
                    }
                };
                if !key.valid()
                    || key.tenant_id != tenant
                    || committed == 0
                    || committed > captured
                    || Self::column::<u64>(row, 2)? != committed
                    || Self::column::<Option<u64>>(row, 11)? != Some(committed)
                    || Self::column::<Vec<u8>>(row, 0)? != super::super::context::version_key(&key)?
                    || Self::column::<Option<u64>>(row, 1)?
                        != if unit == 0 { None } else { Some(unit) }
                    || Self::column::<Option<Vec<u8>>>(row, 12)?.is_some()
                    || Self::column::<Option<String>>(row, 13)?.is_some()
                    || Self::column::<u32>(row, 14)? != 0
                {
                    return Err(Self::invalid("graph finding upstream ref"));
                }
                let bytes = std::mem::size_of::<(crate::AnalysisContextKeyV1, u64)>()
                    + key.owner_id.capacity()
                    + key.entity_key.capacity()
                    + key.lifetime_key.capacity();
                charge(bytes, bytes)?;
                if contexts
                    .insert(key, committed)
                    .is_some_and(|old| old != committed)
                {
                    return Err(Self::invalid("graph finding context conflict"));
                }
            }
        }
        witnesses.sort_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then(left.cursor.cmp(&right.cursor))
        });
        witnesses.dedup();
        charge(
            0,
            contexts
                .len()
                .saturating_mul(std::mem::size_of::<crate::AnalysisContextRefV1>()),
        )?;
        Ok((
            witnesses,
            contexts
                .into_iter()
                .map(|(key, commit_revision)| crate::AnalysisContextRefV1 {
                    key,
                    commit_revision,
                })
                .collect(),
        ))
    }

    pub(in crate::analysis) fn frozen_records(
        reader: &Connection,
        capture: &crate::ManagedCapture,
        result: &PackageResultRefV1,
        control: &AnalysisReadControl,
        charge: &mut impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<Vec<DiscoveryRecordIdV1>> {
        let graph = crate::analysis::graph_rows::store::Relations::new(reader);
        let snapshot = graph
            .read_snapshot(capture.instance().spec.tenant, &result.result_id, charge)?
            .ok_or_else(|| Self::invalid("frozen Graph result"))?;
        let crate::ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination
        else {
            return Err(Self::invalid("frozen Graph destination"));
        };
        if snapshot.header.snapshot.scope.identity != *source
            || snapshot.head.commit_revision != result.commit_revision
        {
            return Err(Self::invalid("frozen Graph source"));
        }
        let bytes = snapshot
            .header
            .evidence_count
            .saturating_add(snapshot.header.position_count)
            .saturating_mul(
                std::mem::size_of::<(DiscoveryRecordIdV1, StorePositionV1)>()
                    + source.node_id.capacity()
                    + 6 * std::mem::size_of::<usize>(),
            );
        charge(bytes, bytes)?;
        let (records, _) =
            graph.inputs(&result.result_id, &snapshot.header, &mut || control.check())?;
        Ok(records)
    }

    pub(in crate::analysis) fn frozen_facts(
        reader: &Connection,
        root: &std::path::Path,
        capture: &crate::ManagedCapture,
        result: &PackageResultRefV1,
        records: Option<&BTreeSet<DiscoveryRecordIdV1>>,
        control: &AnalysisReadControl,
        charge: &mut impl FnMut(usize, usize) -> Result<()>,
    ) -> Result<(
        crate::analysis::graph::GraphSourceSummary,
        Vec<(crate::AnalysisContextVersionV1, crate::AnalysisContextRefV1)>,
        Vec<(DiscoveryRecordIdV1, crate::AnalysisContextRefV1)>,
    )> {
        let started = std::time::Instant::now();
        let tenant = capture.instance().spec.tenant;
        let graph = crate::analysis::graph_rows::store::Relations::new(reader);
        let snapshot = graph
            .read_snapshot(tenant, &result.result_id, charge)?
            .ok_or_else(|| Self::invalid("frozen Graph result"))?;
        let crate::ManagedDestination::Graph { source, .. } = &capture.instance().spec.destination
        else {
            return Err(Self::invalid("frozen Graph destination"));
        };
        if &snapshot.header.snapshot.scope.identity != source
            || snapshot.head.commit_revision != result.commit_revision
        {
            return Err(Self::invalid("frozen Graph source"));
        }
        let permit = |key: &crate::AnalysisContextKeyV1| -> Result<()> {
            let selection = &capture.instance().grant.selection.contexts;
            if !selection.is_all() && !selection.as_slice().contains(key) {
                return Err(crate::PackageErrorCodeV1::Denied.error("frozen Graph context scope"));
            }
            Ok(())
        };
        let mut cuts = BTreeMap::new();
        let selected = std::time::Instant::now();
        let output = graph.frozen(
            snapshot,
            records,
            &mut || control.check(),
            charge,
            &mut super::super::context::version_key,
            &mut |context: crate::analysis::graph_rows::store::FrozenContext| {
                permit(&context.key)?;
                let (context, revision) = super::super::AnalysisStore::decode_context_row(
                    root,
                    context.key,
                    (
                        context.from,
                        context.until,
                        context.sensitivity,
                        context.body,
                        context.revision,
                    ),
                )?;
                super::super::AnalysisStore::validate_context_packages(reader, &context)
                    .map_err(crate::Error::stored_artifact)?;
                let reference = crate::AnalysisContextRefV1 {
                    key: context.key.clone(),
                    commit_revision: revision,
                };
                Ok((context, reference))
            },
            &mut |proof: &crate::analysis::graph_rows::store::FrozenProof| {
                permit(&proof.key)?;
                let owner = &proof.opening;
                let key = (owner.result_id.clone(), owner.commit_revision);
                if let Some(cut) = cuts.get(&key) {
                    return Ok(*cut);
                }
                let cut = super::super::AnalysisStore::graph_capture_cut(
                    reader,
                    tenant,
                    &PackageResultRefV1 {
                        result_id: owner.result_id.clone(),
                        commit_revision: owner.commit_revision,
                    },
                    None,
                    None,
                )?;
                cuts.insert(key, cut);
                Ok(cut)
            },
        );
        let finished = std::time::Instant::now();
        erebor_telemetry::debug!(
            stage = "graph_relations_timing",
            cut_revision = capture.revision(),
            graph_revision = result.commit_revision,
            keys = records.map_or(0, BTreeSet::len),
            snapshot_s = selected.duration_since(started).as_secs_f64(),
            relations_s = finished.duration_since(selected).as_secs_f64(),
            elapsed_s = finished.duration_since(started).as_secs_f64(),
            success = output.is_ok(),
            "Frozen Graph relation timing completed"
        );
        let output = output?;
        Ok((
            crate::analysis::graph::GraphSourceSummary {
                manifest: output.summary,
                restricted_count: output.restricted,
                expired: output.expired,
            },
            output.contexts,
            output
                .proofs
                .into_iter()
                .map(|proof| {
                    (
                        proof.record,
                        crate::AnalysisContextRefV1 {
                            key: proof.key,
                            commit_revision: proof.revision,
                        },
                    )
                })
                .collect(),
        ))
    }

    pub(super) fn member_ids(
        reader: &Connection,
        result: &str,
        kind: MemberKind,
    ) -> Result<Vec<u64>> {
        let mut statement=reader.prepare("SELECT value_ref FROM graph_selected_members WHERE result_id=? AND member_kind=? ORDER BY ordinal,member_key").context(AnalysisDatabaseSnafu {operation:"prepare selected Graph members"})?;
        statement
            .query_map(params![result, kind as u8], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read selected Graph members",
            })?
            .collect::<duckdb::Result<_>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode selected Graph members",
            })
    }

    pub(in crate::analysis) fn read_header(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
    ) -> Result<Option<GraphHeader>> {
        Self::read_header_control(reader, tenant, result, None)
    }

    pub(in crate::analysis) fn read_metadata_control(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<GraphHeader>> {
        Self::header_mode(reader, tenant, result, control, false)
    }

    pub(in crate::analysis) fn read_header_control(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<GraphHeader>> {
        Self::header_mode(reader, tenant, result, control, true)
    }

    pub(in crate::analysis) fn read_finding_header(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
    ) -> Result<Option<GraphHeader>> {
        Self::header_mode(reader, tenant, result, None, false)
    }

    pub(in crate::analysis) fn read_summary(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<GraphHeader>> {
        Self::check(control)?;
        if let Some(header) = AnalysisStore::native_source_header(reader, tenant, result)? {
            return Ok(Some(header));
        }
        let selected =
            crate::analysis::graph_rows::store::Relations::new(reader).snapshot(tenant, result)?;
        Self::check(control)?;
        Ok(selected.map(|selected| selected.header))
    }

    fn header_mode(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        control: Option<&AnalysisReadControl>,
        complete: bool,
    ) -> Result<Option<GraphHeader>> {
        if let Some(header) = AnalysisStore::native_source_header(reader, tenant, result)? {
            Self::check(control)?;
            return Ok(Some(header));
        }
        let Some(mut header) = Self::read_summary(reader, tenant, result, control)? else {
            return Ok(None);
        };
        crate::analysis::graph_rows::store::Relations::new(reader).metadata(
            result,
            &mut header,
            complete,
            &mut || Self::check(control),
            &mut super::super::context::version_key,
        )?;
        Ok(Some(header))
    }

    pub(in crate::analysis) fn visit_headers(
        reader: &Connection,
        tenant: [u8; 16],
        ids: &[String],
        control: &AnalysisReadControl,
        mut visit: impl FnMut(&str, GraphHeader, u64, Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        let mut headers = Vec::new();
        for id in ids {
            control.check()?;
            let header = Self::read_header_control(reader, tenant, id, Some(control))?
                .ok_or_else(|| crate::AnalysisReadDeniedSnafu.build())?;
            let (revision, bytes): (u64, Vec<u8>) = reader
                .query_row(
                    "SELECT commit_revision,body FROM analysis_results WHERE result_id=?",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph header receipt",
                })?;
            headers.push((id, header, revision, bytes));
        }
        for (id, header, revision, bytes) in headers {
            control.check()?;
            visit(id, header, revision, bytes)?;
        }
        Ok(())
    }

    pub(super) fn inputs(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<GraphInputs> {
        crate::analysis::graph_rows::store::Relations::new(reader).inputs(
            result,
            header,
            &mut || Self::check(control),
        )
    }

    pub(super) fn load_inputs(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<GraphInputs> {
        Self::inputs(reader, result, header, control)
    }

    pub(in crate::analysis) fn read(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
    ) -> Result<GraphSnapshotV1> {
        Self::read_control(reader, result, header, None)
    }

    pub(in crate::analysis) fn read_control(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<GraphSnapshotV1> {
        Self::read_control_with_ids(reader, result, header, control, false).map(|(graph, _)| graph)
    }

    pub(in crate::analysis) fn read_control_with_ids(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
        include_ids: bool,
    ) -> Result<(GraphSnapshotV1, BTreeMap<String, u64>)> {
        let completed = if header.complete {
            None
        } else {
            Some(
                Self::read_header_control(
                    reader,
                    header.snapshot.scope.identity.tenant_id,
                    result,
                    control,
                )?
                .ok_or_else(|| Self::invalid("graph header result"))?,
            )
        };
        let header = completed.as_ref().unwrap_or(header);
        let mut graph = header.snapshot.clone();
        let (evidence, positions) = Self::load_inputs(reader, result, header, control)?;
        graph.input_manifest.evidence = evidence;
        graph.input_positions = positions;
        graph.graph.subjects = Self::read_subjects(reader, result, header.subject_count, control)?;
        graph.graph.edges = Self::read_edges(reader, result, header.edge_count, control)?;
        let (findings, finding_value_ids) =
            Self::read_findings_selected(reader, result, header, control, include_ids)?;
        graph.findings = findings;
        Self::check_union(reader, result)?;
        if header.derive_branches {
            graph.graph.branches = Self::branches(&graph.findings);
        }
        graph.validate()?;
        if header.expired
            && (graph
                .packages
                .iter()
                .any(|package| package.state != GraphPackageStateV1::CoverageInsufficient)
                || graph.graph.edges.iter().any(|edge| {
                    edge.key.cause != GraphCauseV1::Superseded
                        || edge.proof_quality.temporal_coverage != TemporalCoverageV1::Unknown
                })
                || graph.findings.iter().any(|finding| {
                    finding.state != FindingStateV1::CoverageInsufficient
                        || !finding
                            .limits
                            .iter()
                            .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
                        || finding.effects.iter().any(|effect| {
                            effect.proof_quality.temporal_coverage != TemporalCoverageV1::Unknown
                        })
                })
                || graph.graph.branches.iter().any(|branch| {
                    branch.state != GraphBranchStateV1::CoverageUnknown
                        || !branch
                            .missing_fields
                            .iter()
                            .any(|field| field == "RETAINED_INPUT_EXPIRED")
                }))
        {
            return Err(Self::invalid("graph expiry values"));
        }
        Ok((graph, finding_value_ids))
    }

    pub(in crate::analysis) fn read_subjects(
        reader: &Connection,
        result: &str,
        count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphSubjectKeyV1>> {
        let mut statement = reader
            .prepare(&format!(
                "SELECT {} FROM graph_subjects WHERE result_id=? ORDER BY ordinal",
                crate::analysis::graph_rows::store::SubjectRows::COLUMNS
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph subjects",
            })?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph subjects",
            })?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph subjects",
        })? {
            Self::check(control)?;
            if Self::column::<u32>(row, 0)? as usize != selected.len() {
                return Err(Self::invalid("graph subject ordinal"));
            }
            selected.push(Self::decode_subject(row)?);
        }
        if selected.len() != count {
            return Err(Self::invalid("graph subject row counts"));
        }
        Ok(selected)
    }

    pub(in crate::analysis) fn read_edges(
        reader: &Connection,
        result: &str,
        count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphEdgeV1>> {
        let mut statement = reader
            .prepare(&format!(
                "SELECT {} FROM graph_relationships WHERE result_id=? ORDER BY ordinal",
                crate::analysis::graph_rows::store::RelationshipRows::COLUMNS
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph relationships",
            })?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph relationships",
            })?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph relationships",
        })? {
            Self::check(control)?;
            if Self::column::<u32>(row, 0)? as usize != selected.len() {
                return Err(Self::invalid("graph relationship ordinal"));
            }
            selected.push(Self::decode_edge(row)?);
        }
        if selected.len() != count {
            return Err(Self::invalid("graph edge row counts"));
        }
        Ok(selected)
    }

    pub(super) fn decode_edge(row: &Row<'_>) -> Result<GraphEdgeV1> {
        crate::analysis::graph_rows::store::RelationshipRows::decode(row).map_err(Into::into)
    }

    pub(in crate::analysis) fn read_findings(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<FindingV1>> {
        Self::read_findings_selected(reader, result, header, control, false)
            .map(|(findings, _)| findings)
    }

    pub(in crate::analysis) fn read_findings_with_ids(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<(Vec<FindingV1>, BTreeMap<String, u64>)> {
        Self::read_findings_selected(reader, result, header, control, true)
    }

    fn read_findings_selected(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
        include_ids: bool,
    ) -> Result<(Vec<FindingV1>, BTreeMap<String, u64>)> {
        Self::check(control)?;
        let mut subjects = BTreeMap::new();
        let mut statement=reader.prepare("SELECT DISTINCT s.subject_id,s.tenant_id,s.authority_rank,s.authority_text,s.authority_boot,s.authority_epoch,s.subject_kind,s.identity FROM graph_findings f JOIN graph_subjects s ON s.result_id=f.result_id AND s.subject_id=f.subject_ref WHERE f.result_id=?").context(AnalysisDatabaseSnafu {operation:"prepare finding subjects"})?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read finding subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance finding subjects",
        })? {
            Self::check(control)?;
            subjects.insert(Self::column::<u64>(row, 0)?, Self::decode_subject(row)?);
        }
        drop(rows);
        drop(statement);
        let source = &header.snapshot.scope.identity;
        let mut evidence = BTreeMap::new();
        let mut statement=reader.prepare("WITH needed AS (SELECT DISTINCT unnest(evidence_refs) AS evidence_id FROM graph_findings WHERE result_id=?) SELECT n.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,m.value_ref,r.cpu_id FROM needed n LEFT JOIN graph_selected_members m ON m.result_id=? AND m.member_kind=0 AND m.value_ref=n.evidence_id LEFT JOIN graph_evidence e ON e.evidence_id=n.evidence_id LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id").context(AnalysisDatabaseSnafu {operation:"prepare finding evidence"})?;
        let mut rows = statement
            .query(params![result, result])
            .context(AnalysisDatabaseSnafu {
                operation: "read finding evidence",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance finding evidence",
        })? {
            Self::check(control)?;
            let key: Option<Vec<u8>> = Self::column(row, 3)?;
            let tenant: Option<Vec<u8>> = Self::column(row, 4)?;
            let retained: Option<Vec<u8>> = Self::column(row, 5)?;
            let cpu: u32 = Self::column(row, 1)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || Self::column::<Option<u64>>(row, 6)?.is_none()
                || Self::column::<Option<u32>>(row, 7)? != Some(cpu)
            {
                return Err(Self::invalid("graph finding evidence source"));
            }
            if evidence
                .insert(
                    Self::column::<u64>(row, 0)?,
                    DiscoveryRecordIdV1 {
                        stream: source.clone(),
                        cpu_id: cpu,
                        durable_cursor: Self::column(row, 2)?,
                    },
                )
                .is_some()
            {
                return Err(Self::invalid("graph finding evidence reference"));
            }
        }
        drop(rows);
        drop(statement);
        let mut revision = header.snapshot.input_manifest.clone();
        revision.evidence = evidence.values().cloned().collect();
        revision.evidence.sort_unstable();
        revision.validate(source.tenant_id)?;
        let columns = crate::analysis::graph_rows::store::FindingRows::COLUMNS;
        let value_id = if include_ids { ",value_id" } else { "" };
        let mut statement = reader
            .prepare(&format!(
                "SELECT {columns}{value_id} FROM graph_findings WHERE result_id=? ORDER BY ordinal"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph findings",
            })?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph findings",
            })?;
        let mut findings = Vec::new();
        let mut finding_value_ids = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph findings",
        })? {
            Self::check(control)?;
            if Self::column::<u32>(row, 0)? as usize != findings.len() {
                return Err(Self::invalid("graph finding ordinal"));
            }
            let (subject, refs) = crate::analysis::graph_rows::store::FindingRows::references(row)?;
            let finding = crate::analysis::graph_rows::store::FindingRows::decode(
                row,
                subjects
                    .get(&subject)
                    .cloned()
                    .ok_or_else(|| Self::invalid("graph finding subject reference"))?,
                refs.into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| Self::invalid("graph finding evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            )?;
            Self::check_finding_value(&finding, header, &revision)?;
            if findings
                .last()
                .is_some_and(|previous: &FindingV1| previous.finding_id >= finding.finding_id)
            {
                return Err(Self::invalid("duplicate graph finding"));
            }
            if include_ids
                && finding_value_ids
                    .insert(finding.finding_id.clone(), Self::column(row, 18)?)
                    .is_some()
            {
                return Err(Self::invalid("duplicate graph finding value"));
            }
            findings.push(finding);
        }
        if findings.len() != header.finding_count {
            return Err(Self::invalid("graph finding row counts"));
        }
        Ok((findings, finding_value_ids))
    }

    pub(in crate::analysis) fn read_finding_keys(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        ids: &[String],
        control: Option<&AnalysisReadControl>,
    ) -> Result<BTreeMap<String, FindingV1>> {
        Ok(
            Self::read_finding_keys_with_ids(reader, result, header, ids, control)?
                .into_iter()
                .map(|(key, (_, finding))| (key, finding))
                .collect(),
        )
    }

    pub(in crate::analysis) fn read_finding_keys_with_ids(
        reader: &Connection,
        result: &str,
        header: &GraphHeader,
        ids: &[String],
        control: Option<&AnalysisReadControl>,
    ) -> Result<BTreeMap<String, (u64, FindingV1)>> {
        Self::check(control)?;
        if AnalysisStore::native_graph_result(reader,result)? {
            let mut values = BTreeMap::new();
            for id in ids.iter().collect::<BTreeSet<_>>() {
                Self::check(control)?;
                if let Some((value,member)) = AnalysisStore::native_finding(reader,header.snapshot.scope.identity.tenant_id,result,id)? {
                    values.insert(id.clone(),(value,member.value));
                }
            }
            return Ok(values);
        }
        let wanted = ids.iter().collect::<BTreeSet<_>>();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = std::iter::repeat_n("(?)", wanted.len())
            .collect::<Vec<_>>()
            .join(",");
        let parameters_sql = std::iter::repeat_n("?", wanted.len())
            .collect::<Vec<_>>()
            .join(",");
        let selected=format!("WITH wanted(finding_id) AS (VALUES {placeholders}),selected AS (SELECT DISTINCT m.result_id,f.*,m.member_key FROM wanted w JOIN graph_finding_values f ON f.finding_id=w.finding_id JOIN graph_selected_members m ON m.member_kind=4 AND m.value_ref=f.value_id WHERE m.result_id=? AND m.member_key IN ({parameters_sql}))");
        let mut parameters = wanted
            .iter()
            .map(|id| duckdb::types::Value::Text((*id).clone()))
            .collect::<Vec<_>>();
        parameters.push(duckdb::types::Value::Text(result.into()));
        parameters.extend(
            wanted
                .into_iter()
                .map(|id| Self::member_key(id).map(duckdb::types::Value::Blob))
                .collect::<Result<Vec<_>>>()?,
        );
        let mut subjects = BTreeMap::new();
        let mut statement=reader.prepare(&format!("{selected} SELECT DISTINCT s.*,m.member_key FROM selected f JOIN graph_subject_values s ON s.subject_id=f.subject_ref JOIN graph_selected_members m ON m.result_id=f.result_id AND m.member_kind=2 AND m.value_ref=s.subject_id")).context(AnalysisDatabaseSnafu {operation:"prepare requested finding subjects"})?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read requested finding subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance requested finding subjects",
        })? {
            Self::check(control)?;
            let subject = Self::decode_subject(row)?;
            if Self::member_key(&subject)? != Self::column::<Vec<u8>>(row, 8)? {
                return Err(Self::invalid("graph finding subject reference"));
            }
            subjects.insert(Self::column::<u64>(row, 0)?, subject);
        }
        drop(rows);
        drop(statement);
        let source = &header.snapshot.scope.identity;
        let mut evidence = BTreeMap::new();
        let mut statement=reader.prepare(&format!("{selected},needed AS (SELECT DISTINCT f.result_id,unnest(f.evidence_refs) AS evidence_id FROM selected f) SELECT n.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,m.value_ref,r.cpu_id FROM needed n LEFT JOIN graph_selected_members m ON m.result_id=n.result_id AND m.member_kind=0 AND m.value_ref=n.evidence_id LEFT JOIN graph_evidence e ON e.evidence_id=n.evidence_id LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id")).context(AnalysisDatabaseSnafu {operation:"prepare requested finding evidence"})?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read requested finding evidence",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance requested finding evidence",
        })? {
            Self::check(control)?;
            if Self::column::<Option<u64>>(row, 6)?.is_none() {
                return Err(Self::invalid("graph finding evidence reference"));
            }
            let key: Option<Vec<u8>> = Self::column(row, 3)?;
            let tenant: Option<Vec<u8>> = Self::column(row, 4)?;
            let retained: Option<Vec<u8>> = Self::column(row, 5)?;
            let cpu: u32 = Self::column(row, 1)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || Self::column::<Option<u32>>(row, 7)? != Some(cpu)
            {
                return Err(Self::invalid("graph finding evidence source"));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: cpu,
                durable_cursor: Self::column(row, 2)?,
            };
            if evidence
                .insert(Self::column::<u64>(row, 0)?, record)
                .is_some()
            {
                return Err(Self::invalid("graph finding evidence reference"));
            }
        }
        drop(rows);
        drop(statement);
        let mut revision = header.snapshot.input_manifest.clone();
        revision.evidence = evidence.values().cloned().collect();
        revision.evidence.sort_unstable();
        revision.validate(source.tenant_id)?;
        let columns = crate::analysis::graph_rows::store::FindingRows::COLUMNS
            .split(',')
            .enumerate()
            .map(|(index, column)| {
                if index == 0 {
                    "f.value_id AS ordinal".to_owned()
                } else {
                    format!("f.{column}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut statement=reader.prepare(&format!("{selected} SELECT {columns},f.member_key FROM selected f ORDER BY f.finding_id,f.value_id")).context(AnalysisDatabaseSnafu {operation:"prepare requested Graph findings"})?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read requested Graph findings",
            })?;
        let mut findings = BTreeMap::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance requested Graph findings",
        })? {
            Self::check(control)?;
            let (subject, refs) = crate::analysis::graph_rows::store::FindingRows::references(row)?;
            let finding = crate::analysis::graph_rows::store::FindingRows::decode(
                row,
                subjects
                    .get(&subject)
                    .cloned()
                    .ok_or_else(|| Self::invalid("graph finding subject reference"))?,
                refs.into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| Self::invalid("graph finding evidence reference"))
                    })
                    .collect::<Result<_>>()?,
            )?;
            Self::check_finding_value(&finding, header, &revision)?;
            if Self::member_key(&finding.finding_id)? != Self::column::<Vec<u8>>(row, 18)? {
                return Err(Self::invalid("graph finding member identity"));
            }
            if findings
                .insert(finding.finding_id.clone(), (Self::column(row, 0)?, finding))
                .is_some()
            {
                return Err(Self::invalid("duplicate graph finding identity"));
            }
        }
        Ok(findings)
    }

    pub(in crate::analysis) fn read_finding(
        reader: &Connection,
        result: &str,
        finding: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<FindingV1>> {
        Ok(
            Self::read_finding_with_id(reader, result, finding, header, control)?
                .map(|(_, finding)| finding),
        )
    }

    pub(in crate::analysis) fn read_finding_with_id(
        reader: &Connection,
        result: &str,
        finding: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<(u64, FindingV1)>> {
        Self::check(control)?;
        if AnalysisStore::native_graph_result(reader,result)? {
            return AnalysisStore::native_finding(reader,header.snapshot.scope.identity.tenant_id,result,finding)
                .map(|value| value.map(|(id,member)| (id,member.value)));
        }
        Ok(Self::read_finding_keys_with_ids(
            reader,
            result,
            header,
            &[finding.to_owned()],
            control,
        )?
        .remove(finding))
    }

    fn check_finding_value(
        finding: &FindingV1,
        header: &GraphHeader,
        revision: &crate::GraphRevisionV1,
    ) -> Result<()> {
        if finding.tenant_id != header.snapshot.scope.identity.tenant_id {
            return Err(Self::invalid("graph finding tenant"));
        }
        finding.validate()?;
        revision.validate_finding(finding)?;
        if finding.evidence.iter().any(|record| {
            record.stream != header.snapshot.scope.identity
                || !(header.snapshot.first_cursor..=header.snapshot.last_cursor)
                    .contains(&record.durable_cursor)
        }) {
            return Err(Self::invalid("graph finding evidence scope"));
        }
        if header.expired
            && (finding.state != FindingStateV1::CoverageInsufficient
                || !finding
                    .limits
                    .iter()
                    .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
                || !finding
                    .limits
                    .iter()
                    .any(|limit| limit == "LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION")
                || finding.effects.iter().any(|effect| {
                    effect.proof_quality.temporal_coverage != TemporalCoverageV1::Unknown
                }))
        {
            return Err(Self::invalid("graph expired finding value"));
        }
        if !header.snapshot.packages.iter().any(|package| {
            package.package_id == finding.package_id
                && package.package_version == finding.package_version
        }) {
            return Err(Self::invalid("graph finding manifest"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn selected_subjects(
        reader: &Connection,
        result: &str,
        keys: &[GraphSubjectKeyV1],
        control: &AnalysisReadControl,
        binding: bool,
    ) -> Result<Vec<(GraphSubjectKeyV1, u32)>> {
        control.check()?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut expected = BTreeMap::new();
        for key in keys {
            let digest = Self::member_key(key)?;
            if expected
                .insert(digest, key)
                .is_some_and(|prior| prior != key)
            {
                return Err(Self::invalid("graph requested subject collision"));
            }
        }
        let values = std::iter::repeat_n("(?)", expected.len())
            .collect::<Vec<_>>()
            .join(",");
        let query=format!("WITH wanted(member_key) AS (VALUES {values}) SELECT DISTINCT s.ordinal,s.tenant_id,s.authority_rank,s.authority_text,s.authority_boot,s.authority_epoch,s.subject_kind,s.identity,m.member_key FROM wanted JOIN graph_selected_members m USING(member_key) JOIN graph_subjects s ON s.result_id=m.result_id AND s.subject_id=m.value_ref WHERE m.result_id=? AND m.member_kind=2 AND (NOT ? OR EXISTS(SELECT 1 FROM graph_selected_members incident JOIN graph_edge_values e ON incident.member_kind=3 AND e.edge_id=incident.value_ref WHERE incident.result_id=m.result_id AND (e.from_ref=m.value_ref OR e.to_ref=m.value_ref)) OR EXISTS(SELECT 1 FROM graph_selected_members incident JOIN graph_finding_values f ON incident.member_kind=4 AND f.value_id=incident.value_ref WHERE incident.result_id=m.result_id AND f.subject_ref=m.value_ref)) ORDER BY s.ordinal");
        let mut parameters = expected
            .keys()
            .cloned()
            .map(duckdb::types::Value::Blob)
            .collect::<Vec<_>>();
        parameters.extend([
            duckdb::types::Value::Text(result.into()),
            duckdb::types::Value::Boolean(binding),
        ]);
        let mut statement = reader.prepare(&query).context(AnalysisDatabaseSnafu {
            operation: "prepare selected Graph subjects",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read selected Graph subjects",
            })?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance selected Graph subjects",
        })? {
            control.check()?;
            let subject = Self::decode_subject(row)?;
            let key: Vec<u8> = Self::column(row, 8)?;
            if expected.get(&key).copied() != Some(&subject) {
                return Err(Self::invalid("graph selected subject collision"));
            }
            selected.push((subject, Self::column(row, 0)?));
        }
        Ok(selected)
    }

    pub(in crate::analysis) fn selected_edges(
        reader: &Connection,
        result: &str,
        ordinals: &[u32],
        control: &AnalysisReadControl,
    ) -> Result<Vec<GraphEdgeV1>> {
        control.check()?;
        if ordinals.is_empty() {
            return Ok(Vec::new());
        }
        let values = std::iter::repeat_n("(?,?)", ordinals.len())
            .collect::<Vec<_>>()
            .join(",");
        let query=format!("WITH wanted(ordinal,rank) AS (VALUES {values}) SELECT e.ordinal,e.from_subject_id,e.to_subject_id,e.edge_type,e.package_id,e.cause,e.evidence,e.proof_quality,e.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns FROM wanted JOIN graph_relationships e USING(ordinal) WHERE e.result_id=? ORDER BY wanted.rank");
        let mut parameters = Vec::new();
        for (rank, ordinal) in ordinals.iter().enumerate() {
            parameters.push(duckdb::types::Value::UInt(*ordinal));
            parameters.push(duckdb::types::Value::UBigInt(rank as u64));
        }
        parameters.push(duckdb::types::Value::Text(result.into()));
        let mut statement = reader.prepare(&query).context(AnalysisDatabaseSnafu {
            operation: "prepare selected relationships",
        })?;
        let mut rows = statement
            .query(duckdb::params_from_iter(parameters.iter()))
            .context(AnalysisDatabaseSnafu {
                operation: "read selected relationships",
            })?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance selected relationships",
        })? {
            control.check()?;
            selected.push(Self::decode_edge(row)?);
        }
        if selected.len() != ordinals.len() {
            return Err(Self::invalid("graph relationship ordinal"));
        }
        Ok(selected)
    }

    pub(in crate::analysis) fn branches(findings: &[FindingV1]) -> Vec<GraphBranchV1> {
        let mut branches = findings.iter().map(GraphBranchV1::from_value).collect();
        Self::sort_branches(&mut branches);
        branches
    }
    pub(super) fn sort_branches(branches: &mut Vec<GraphBranchV1>) {
        branches.sort_by(|left, right| {
            (
                &left.package_id,
                &left.seed,
                &left.evidence,
                &left.missing_fields,
            )
                .cmp(&(
                    &right.package_id,
                    &right.seed,
                    &right.evidence,
                    &right.missing_fields,
                ))
        });
        branches.dedup();
    }
}
