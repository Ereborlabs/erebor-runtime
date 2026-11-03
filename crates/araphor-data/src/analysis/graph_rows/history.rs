use crate::{GraphValidate as _, ManagedDestination, ManagedSpec};

use super::*;

type ManagedProducerRow = (
    u64,
    u64,
    Vec<u8>,
    Vec<u8>,
    String,
    u64,
    String,
    String,
    String,
    u8,
);

#[derive(Clone)]
pub(super) struct Member {
    pub(super) kind: MemberKind,
    pub(super) key: Vec<u8>,
    pub(super) value: u64,
    pub(super) anchor: Option<Anchor>,
    pub(super) reason: Option<String>,
    pub(super) ordinal: u32,
}

pub(super) struct ProducerPin<'a> {
    pub(super) instance: &'a str,
    pub(super) call: u64,
    pub(super) declaration: &'a crate::ManagedCall,
}

impl GraphRows {
    pub(in crate::analysis) const LINEAGE_INVALID: &'static str =
        "v.commit_revision<s.created_revision
        OR (v.commit_revision=s.created_revision AND (v.base_result_id IS NOT NULL
            OR EXISTS(SELECT 1 FROM graph_producer_versions prior
                WHERE prior.scope_id=v.scope_id AND prior.commit_revision<v.commit_revision)))
        OR (v.commit_revision>s.created_revision AND (v.base_result_id IS NULL
            OR v.base_result_id IS DISTINCT FROM (SELECT prior.result_id
                FROM graph_producer_versions prior WHERE prior.scope_id=v.scope_id
                    AND prior.commit_revision<v.commit_revision
                ORDER BY prior.commit_revision DESC LIMIT 1)))";

    pub(in crate::analysis) fn commit(
        writer: &Connection,
        result: &PackageResultRefV1,
        metadata: &GraphManifest,
        input: GraphWrite<'_>,
    ) -> Result<(Vec<u8>, (u64, u64, u64), (u64, u64))> {
        if matches!(input, GraphWrite::Managed { .. }) {
            return Err(Self::invalid("graph producer stage is required"));
        }
        metadata.validate()?;
        match &input {
            GraphWrite::Expiry(_)
                if metadata
                    .packages
                    .iter()
                    .any(|package| package.state != GraphPackageStateV1::CoverageInsufficient) =>
            {
                return Err(Self::invalid("graph expiry package state"))
            }
            GraphWrite::Direct(graph) => {
                graph.validate()?;
                for branch in &graph.graph.branches {
                    Self::check_branch(branch, metadata.scope.identity.tenant_id)?;
                }
            }
            _ => {}
        }
        let expiry_graph = if let GraphWrite::Expiry(base) = &input {
            if metadata.previous_result_id.as_deref() != Some(base.result_id.as_str()) {
                return Err(Self::invalid("graph expiry base"));
            }
            let header =
                Self::read_header(writer, metadata.scope.identity.tenant_id, &base.result_id)?
                    .ok_or_else(|| Self::invalid("graph expiry base"))?;
            let revision: u64 = writer
                .query_row(
                    "SELECT commit_revision FROM graph_versions WHERE result_id=?",
                    params![base.result_id],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check Graph expiry revision",
                })?;
            if revision != base.commit_revision {
                return Err(Self::invalid("graph expiry revision"));
            }
            let graph = Self::read(writer, &base.result_id, &header)?;
            let mut expected = GraphManifest::from_snapshot(&graph);
            expected.previous_result_id = Some(base.result_id.clone());
            expected
                .missing_ranges
                .push((expected.first_cursor, expected.last_cursor));
            expected.missing_ranges.sort();
            expected.missing_ranges.dedup();
            expected.input_manifest.missing_ranges = expected.missing_ranges.clone();
            for package in &mut expected.packages {
                package.state = GraphPackageStateV1::CoverageInsufficient;
            }
            if expected != *metadata {
                return Err(Self::invalid("graph expiry metadata"));
            }
            Some(graph)
        } else {
            None
        };
        let source = Self::source_id(writer, &metadata.scope.identity)?;
        let indexed:Option<(Vec<u8>,Vec<u8>,u64)>=writer.query_row("SELECT tenant_id,stream_key,commit_revision FROM analysis_results WHERE result_id=?",params![result.result_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().context(AnalysisDatabaseSnafu {operation:"check Graph result index"})?;
        if indexed
            != Some((
                metadata.scope.identity.tenant_id.to_vec(),
                metadata.scope.identity.key(),
                result.commit_revision,
            ))
        {
            return Err(Self::invalid("graph result index"));
        }
        let previous = if let Some(id) = metadata.previous_result_id.as_deref() {
            let prior:Option<(u64,String)>=writer.query_row("SELECT commit_revision,metadata_result_id FROM graph_versions WHERE result_id=?",params![id],|row|Ok((row.get(0)?,row.get(1)?))).optional().context(AnalysisDatabaseSnafu {operation:"read Graph previous producer"})?;
            let prior = prior.ok_or_else(|| Self::invalid("graph previous result"))?;
            if prior.0 >= result.commit_revision {
                return Err(Self::invalid("graph previous result"));
            }
            Some(prior)
        } else {
            None
        };
        let metadata_id = format!("{}:metadata", result.result_id);
        let (metadata_scope, metadata_base) = Self::publication_scope(
            writer,
            metadata,
            source,
            2,
            previous.as_ref().map(|(_, id)| id.as_str()),
            result.commit_revision,
        )?;
        Self::version(
            writer,
            &metadata_id,
            metadata_scope,
            result.commit_revision,
            metadata_base.as_deref(),
        )?;
        let mut work =
            Self::write_metadata(writer, metadata_scope, result.commit_revision, metadata)?;
        let metadata_rows = (work.1, work.2);
        writer
            .execute(
                "INSERT INTO graph_versions VALUES(?,?,?,?,?)",
                params![
                    result.result_id,
                    result.commit_revision,
                    metadata_id,
                    false,
                    matches!(input, GraphWrite::Expiry(_))
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph version",
            })?;
        Self::bind_result(writer, &result.result_id, &metadata_id)?;
        match input {
            GraphWrite::Managed { .. } => {
                return Err(Self::invalid("graph producer stage is required"))
            }
            GraphWrite::Direct(graph) => {
                graph.validate()?;
                let producer = format!("{}:publication", result.result_id);
                let base = metadata
                    .previous_result_id
                    .as_deref()
                    .map(|id| format!("{id}:publication"));
                let (scope, base) = Self::publication_scope(
                    writer,
                    metadata,
                    source,
                    1,
                    base.as_deref(),
                    result.commit_revision,
                )?;
                Self::version(
                    writer,
                    &producer,
                    scope,
                    result.commit_revision,
                    base.as_deref(),
                )?;
                let next = Self::write_snapshot(writer, scope, result.commit_revision, graph)?;
                work.0 = work.0.saturating_add(next.0);
                work.1 = work.1.saturating_add(next.1);
                work.2 = work.2.saturating_add(next.2);
                Self::bind_result(writer, &result.result_id, &producer)?;
            }
            GraphWrite::Expiry(base) => {
                let mut graph = expiry_graph.ok_or_else(|| Self::invalid("graph expiry base"))?;
                graph.previous_result_id = Some(base.result_id.clone());
                graph.context_notice_revision = metadata.context_notice_revision;
                graph.missing_ranges = metadata.missing_ranges.clone();
                graph.input_manifest.missing_ranges = metadata.missing_ranges.clone();
                graph.packages = metadata.packages.clone();
                for edge in &mut graph.graph.edges {
                    edge.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
                    edge.key.cause = GraphCauseV1::Superseded;
                }
                graph
                    .graph
                    .edges
                    .sort_by(|left, right| left.key.cmp(&right.key));
                graph
                    .graph
                    .edges
                    .dedup_by(|left, right| left.key == right.key);
                for branch in &mut graph.graph.branches {
                    branch.state = GraphBranchStateV1::CoverageUnknown;
                    branch.missing_fields.push("RETAINED_INPUT_EXPIRED".into());
                    branch.missing_fields.sort();
                    branch.missing_fields.dedup();
                }
                for finding in &mut graph.findings {
                    finding.state = FindingStateV1::CoverageInsufficient;
                    finding.limits.push("RETAINED_INPUT_EXPIRED".into());
                    finding
                        .limits
                        .push("LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into());
                    finding.limits.sort();
                    finding.limits.dedup();
                    for effect in &mut finding.effects {
                        effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
                    }
                }
                graph.validate()?;
                let producer = format!("{}:publication", result.result_id);
                let scope =
                    Self::new_scope(writer, metadata, source, 1, None, result.commit_revision)?;
                Self::version(writer, &producer, scope, result.commit_revision, None)?;
                let next = Self::write_snapshot(writer, scope, result.commit_revision, &graph)?;
                work.0 = work.0.saturating_add(next.0);
                work.1 = work.1.saturating_add(next.1);
                work.2 = work.2.saturating_add(next.2);
                Self::bind_result(writer, &result.result_id, &producer)?;
            }
        }
        let (subjects, edges, findings) = Self::result_counts(
            writer,
            &result.result_id,
            metadata.previous_result_id.as_deref(),
            result.commit_revision,
            true,
        )?;
        let branches = Self::member_ids(writer, &result.result_id, MemberKind::Branch)?.len();
        let body = GraphHeader::encode(
            metadata,
            (
                subjects as usize,
                edges as usize,
                findings as usize,
                branches,
            ),
            (
                metadata.input_manifest.evidence.len(),
                metadata.input_positions.len(),
                metadata.facts.len(),
            ),
        )?;
        Ok((body, work, metadata_rows))
    }

    pub(super) fn bind_result(writer: &Connection, graph: &str, producer: &str) -> Result<()> {
        writer
            .execute(
                "INSERT INTO graph_result_producers VALUES(?,?)",
                params![graph, producer],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bind Graph producer result",
            })?;
        Ok(())
    }

    pub(super) fn new_scope(
        writer: &Connection,
        metadata: &GraphManifest,
        source: u64,
        kind: u8,
        pin: Option<ProducerPin<'_>>,
        created: u64,
    ) -> Result<u64> {
        let id = Self::next_id(writer, "graph_producer_scopes")?;
        writer
            .execute(
                "INSERT INTO graph_producer_scopes VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    id,
                    metadata.scope.identity.tenant_id.as_slice(),
                    source,
                    kind,
                    pin.as_ref().map(|pin| pin.instance),
                    pin.as_ref().map(|pin| pin.call),
                    pin.as_ref()
                        .map(|pin| pin.declaration.package.package_id.as_str()),
                    pin.as_ref()
                        .map(|pin| pin.declaration.package.revision.as_str()),
                    pin.as_ref()
                        .map(|pin| pin.declaration.image.digest.as_str()),
                    metadata.first_cursor,
                    created
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph producer scope",
            })?;
        Ok(id)
    }

    pub(super) fn publication_scope(
        writer: &Connection,
        metadata: &GraphManifest,
        source: u64,
        kind: u8,
        base: Option<&str>,
        revision: u64,
    ) -> Result<(u64, Option<String>)> {
        if let Some(base) = base {
            let scope:Option<(u64,u64,u8,u64)>=writer.query_row("SELECT s.scope_id,s.source_ref,s.producer_kind,s.first_cursor FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE v.result_id=?",params![base],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().context(AnalysisDatabaseSnafu {operation:"read publication producer scope"})?;
            if let Some((id, stored, stored_kind, first)) = scope {
                if source != stored || kind != stored_kind || first != metadata.first_cursor {
                    return Err(Self::invalid("graph publication scope"));
                }
                return Ok((id, Some(base.to_owned())));
            }
        }
        Self::new_scope(writer, metadata, source, kind, None, revision).map(|scope| (scope, None))
    }

    pub(in crate::analysis) fn call_scope(
        writer: &Connection,
        spec: &ManagedSpec,
        call: u64,
        result: &PackageResultRefV1,
    ) -> Result<u64> {
        let pin = spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Self::invalid("graph call pin"))?;
        let ManagedDestination::Graph { source, .. } = &spec.destination else {
            return Err(Self::invalid("graph call destination"));
        };
        let row: Option<ManagedProducerRow> = writer.query_row("SELECT s.scope_id,v.commit_revision,s.tenant_id,src.stream_key,s.instance_id,s.call_id,s.package_id,s.package_revision,s.image_digest,s.producer_kind FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) JOIN graph_sources src USING(source_ref) JOIN source_receipts receipt ON receipt.stream_key=src.stream_key AND receipt.tenant_id=src.tenant_id WHERE v.result_id=?",params![result.result_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?))).optional().context(AnalysisDatabaseSnafu {operation:"read managed Graph producer"})?;
        let row = row.ok_or_else(|| Self::invalid("graph call result"))?;
        if row.1 != result.commit_revision
            || row.2 != spec.tenant
            || row.3 != source.key()
            || row.4 != spec.id
            || row.5 != call
            || row.6 != pin.package.package_id
            || row.7 != pin.package.revision
            || row.8 != pin.image.digest
            || row.9 != 0
        {
            return Err(Self::invalid("graph call scope"));
        }
        let invalid: bool = writer.query_row(&format!("SELECT {} FROM graph_producer_versions v JOIN graph_producer_scopes s USING(scope_id) WHERE v.result_id=?",Self::LINEAGE_INVALID),params![result.result_id],|row|row.get(0))
            .context(AnalysisDatabaseSnafu { operation: "check Graph call lineage" })?;
        if invalid {
            return Err(Self::invalid("graph call base"));
        }
        Ok(row.0)
    }

    pub(super) fn version(
        writer: &Connection,
        result: &str,
        scope: u64,
        revision: u64,
        base: Option<&str>,
    ) -> Result<()> {
        let latest: Option<(String,u64)> = writer
            .query_row(
                "SELECT result_id,commit_revision FROM graph_producer_versions WHERE scope_id=? ORDER BY commit_revision DESC LIMIT 1",
                params![scope],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph producer frontier",
            })?;
        if let Some((id, cut)) = latest {
            if base != Some(id.as_str()) || cut >= revision {
                return Err(Self::invalid("graph producer stale base"));
            }
        } else {
            let created: u64 = writer
                .query_row(
                    "SELECT created_revision FROM graph_producer_scopes WHERE scope_id=?",
                    params![scope],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check new Graph producer scope",
                })?;
            if base.is_some() || created != revision {
                return Err(Self::invalid("graph producer fresh base"));
            }
        }
        writer
            .execute(
                "INSERT INTO graph_producer_versions
                    (result_id,scope_id,commit_revision,base_result_id,subject_count,edge_count,
                        finding_count,state_count,selected_state_ref)
                 VALUES(?,?,?,?,0,0,0,0,NULL)",
                params![result, scope, revision, base],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph producer version",
            })?;
        Ok(())
    }

    pub(super) fn write_metadata(
        writer: &Connection,
        scope: u64,
        revision: u64,
        metadata: &GraphManifest,
    ) -> Result<(u64, u64, u64)> {
        let (replacements, staged) = Self::metadata_members(writer, metadata, None)?;
        let mut work =
            araphor_graph::Contributions::apply(writer, scope, revision, &replacements, false)?;
        work.0 = work.0.saturating_add(staged);
        Ok(work)
    }

    pub(super) fn metadata_members(
        writer: &Connection,
        metadata: &GraphManifest,
        removed: Option<&[crate::DiscoveryRecordIdV1]>,
    ) -> Result<(Vec<araphor_graph::Replacement>, u64)> {
        let keys = metadata
            .input_manifest
            .evidence
            .iter()
            .chain(removed.unwrap_or_default())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let records = Self::intern_records(writer, &metadata.scope.identity, &keys)?;
        if removed.is_some() && metadata.input_manifest.context.len() != metadata.facts.len() {
            return Err(Self::invalid("graph metadata context count"));
        }
        writer.execute_batch(
            "CREATE TEMP TABLE graph_metadata_positions(evidence_id UBIGINT,commit_revision UBIGINT,ordinal UINTEGER,list_ordinal UBIGINT);
             CREATE TEMP TABLE graph_metadata_facts(list_ordinal UBIGINT,context_key BLOB)"
        ).context(AnalysisDatabaseSnafu { operation: "stage Graph metadata values" })?;
        {
            let mut appender =
                writer
                    .appender("graph_metadata_positions")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph metadata positions",
                    })?;
            for (index, (record, position)) in metadata.input_positions.iter().enumerate() {
                appender
                    .append_row(params![
                        records[record],
                        position.commit_revision,
                        position.ordinal,
                        index as u64
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph metadata position",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph metadata positions",
            })?;
        }
        let mut bodies = Vec::with_capacity(metadata.facts.len());
        {
            let mut appender =
                writer
                    .appender("graph_metadata_facts")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph metadata facts",
                    })?;
            for (index, fact) in metadata.facts.iter().enumerate() {
                fact.validate()?;
                let body = Self::encode_value(fact)?;
                let key = removed
                    .map(|_| {
                        super::super::context::version_key(&metadata.input_manifest.context[index])
                    })
                    .transpose()?;
                appender
                    .append_row(params![index as u64, key])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph metadata fact",
                    })?;
                bodies.push(body);
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph metadata facts",
            })?;
        }
        if removed.is_some() {
            let mut statement=writer.prepare("SELECT c.list_ordinal,v.body FROM graph_metadata_facts c LEFT JOIN context_versions v ON v.version_key=c.context_key")
                .context(AnalysisDatabaseSnafu { operation:"prepare canonical Graph metadata facts" })?;
            let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                operation: "read canonical Graph metadata facts",
            })?;
            let mut count = 0;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance canonical Graph metadata facts",
            })? {
                let index: u64 = Self::column(row, 0)?;
                let fact = crate::GraphFactV1::decode_context(&Self::column::<Vec<u8>>(row, 1)?)
                    .map_err(|_| Self::invalid("graph metadata canonical fact"))?;
                if metadata.facts.get(index as usize) != Some(&fact) {
                    return Err(Self::invalid("graph metadata canonical fact"));
                }
                count += 1;
            }
            if count != metadata.facts.len() {
                return Err(Self::invalid("graph metadata canonical fact count"));
            }
        }
        writer.execute_batch(
            "INSERT INTO graph_position_values
             SELECT nextval('graph_position_values_seq'),c.evidence_id,c.commit_revision,c.ordinal
             FROM (SELECT DISTINCT evidence_id,commit_revision,ordinal FROM graph_metadata_positions) c
             WHERE NOT EXISTS(SELECT 1 FROM graph_position_values v WHERE v.evidence_id=c.evidence_id
                AND v.commit_revision=c.commit_revision AND v.ordinal=c.ordinal)"
        ).context(AnalysisDatabaseSnafu { operation: "intern Graph metadata positions" })?;
        let facts = Self::intern_values(
            writer,
            metadata.scope.identity.tenant_id,
            MemberKind::Fact,
            bodies,
        )?
        .into_iter()
        .enumerate()
        .collect::<BTreeMap<_, _>>();
        let mut positions=writer.prepare(
            "SELECT c.list_ordinal,v.value_ref FROM graph_metadata_positions c
             JOIN graph_position_values v USING(evidence_id,commit_revision,ordinal) ORDER BY c.list_ordinal"
        ).context(AnalysisDatabaseSnafu { operation: "prepare Graph metadata positions" })?;
        let positions = positions
            .query_map([], |row| {
                Ok((row.get::<_, usize>(0)?, row.get::<_, u64>(1)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph metadata positions",
            })?
            .collect::<duckdb::Result<BTreeMap<_, _>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Graph metadata positions",
            })?;
        if positions.len() != metadata.input_positions.len() || facts.len() != metadata.facts.len()
        {
            return Err(Self::invalid("graph metadata value count"));
        }
        let mut members = metadata
            .input_manifest
            .evidence
            .iter()
            .map(|record| {
                Ok((
                    records[record],
                    vec![araphor_graph::Member {
                        kind: 0,
                        key: Self::member_key(record)?,
                        value: records[record],
                        record: None,
                        fact: None,
                        reason: None,
                        ordinal: 0,
                    }],
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (index, (record, _)) in metadata.input_positions.iter().enumerate() {
            members
                .get_mut(&records[record])
                .ok_or_else(|| Self::invalid("graph metadata position record"))?
                .push(araphor_graph::Member {
                    kind: 1,
                    key: if removed.is_some() {
                        Self::member_key(record)?
                    } else {
                        Self::encode_value(&index)?
                    },
                    value: positions[&index],
                    record: None,
                    fact: None,
                    reason: None,
                    ordinal: if removed.is_some() {
                        0
                    } else {
                        u32::try_from(index).map_err(|_| Self::invalid("graph position ordinal"))?
                    },
                });
        }
        for (index, fact) in metadata.facts.iter().enumerate() {
            members
                .get_mut(&records[&fact.record_id])
                .ok_or_else(|| Self::invalid("graph metadata fact record"))?
                .push(araphor_graph::Member {
                    kind: 7,
                    key: if removed.is_some() {
                        super::super::context::version_key(&metadata.input_manifest.context[index])?
                    } else {
                        Self::encode_value(&index)?
                    },
                    value: facts[&index],
                    record: None,
                    fact: None,
                    reason: None,
                    ordinal: if removed.is_some() {
                        0
                    } else {
                        u32::try_from(index).map_err(|_| Self::invalid("graph fact ordinal"))?
                    },
                });
        }
        writer
            .execute_batch("DROP TABLE graph_metadata_positions; DROP TABLE graph_metadata_facts")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph metadata values",
            })?;
        if let Some(removed) = removed {
            for record in removed {
                members.entry(records[record]).or_default();
            }
            Ok((
                members
                    .into_iter()
                    .map(|(unit, members)| araphor_graph::Replacement {
                        unit: Some(unit),
                        members,
                    })
                    .collect(),
                (keys.len() + metadata.input_positions.len() + metadata.facts.len()) as u64,
            ))
        } else {
            Ok((
                vec![araphor_graph::Replacement {
                    unit: None,
                    members: members.into_values().flatten().collect(),
                }],
                (keys.len() + metadata.input_positions.len() + metadata.facts.len()) as u64,
            ))
        }
    }

    fn write_snapshot(
        writer: &Connection,
        scope: u64,
        revision: u64,
        graph: &GraphSnapshotV1,
    ) -> Result<(u64, u64, u64)> {
        let records = Self::intern_records(
            writer,
            &graph.scope.identity,
            &graph.input_manifest.evidence,
        )?;
        let subjects = Self::intern_subjects(writer, &graph.graph.subjects)?;
        let edges = graph
            .graph
            .edges
            .iter()
            .map(|edge| {
                let key = RelationshipIdentity::from_keys(
                    &edge.key,
                    &graph.graph.subjects,
                    &graph.input_manifest.evidence,
                )
                .context(crate::AnalysisContractSnafu)?;
                Ok(EdgeValue {
                    key,
                    proof_quality: edge.proof_quality,
                    required_coverage_interval_ids: edge.required_coverage_interval_ids.clone(),
                    first_boottime_ns: edge.first_boottime_ns,
                    last_boottime_ns: edge.last_boottime_ns,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let edge_ids = Self::intern_edges(writer, &subjects, &records, &edges)?;
        let findings = Self::intern_findings(writer, &subjects, &records, &graph.findings)?;
        let branches = Self::intern_branches(
            writer,
            graph.scope.identity.tenant_id,
            &graph.graph.branches,
        )?;
        let mut members = Vec::with_capacity(
            graph.graph.subjects.len() + edges.len() + findings.len() + branches.len(),
        );
        for key in &graph.graph.subjects {
            members.push(Member {
                kind: MemberKind::Subject,
                key: Self::member_key(key)?,
                value: subjects[key],
                anchor: None,
                reason: None,
                ordinal: 0,
            });
        }
        for (edge, id) in edges.into_iter().zip(edge_ids) {
            members.push(Member {
                kind: MemberKind::Edge,
                key: Self::member_key(&edge.key)?,
                value: id,
                anchor: None,
                reason: None,
                ordinal: 0,
            });
        }
        for finding in &graph.findings {
            members.push(Member {
                kind: MemberKind::Finding,
                key: Self::member_key(&finding.finding_id)?,
                value: findings[&finding.finding_id],
                anchor: None,
                reason: None,
                ordinal: 0,
            });
        }
        for (index, id) in branches.into_iter().enumerate() {
            members.push(Member {
                kind: MemberKind::Branch,
                key: Self::encode_value(&index)?,
                value: id,
                anchor: None,
                reason: None,
                ordinal: u32::try_from(index).map_err(|_| Self::invalid("graph branch ordinal"))?,
            });
        }
        let mut work = super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &records,
        }
        .replace(members)?;
        work.0 = work.0.saturating_add(
            (graph.input_manifest.evidence.len() + graph.graph.subjects.len()) as u64,
        );
        Ok(work)
    }

    pub(super) fn result_counts(
        writer: &Connection,
        result: &str,
        previous: Option<&str>,
        revision: u64,
        full_check: bool,
    ) -> Result<(u64, u64, u64)> {
        if full_check {
            Self::check_union(writer, result)?;
            return writer
                .query_row(
                    "SELECT count(DISTINCT CASE WHEN member_kind = 2 THEN value_ref END),
                        count(DISTINCT CASE WHEN member_kind = 3 THEN value_ref END),
                        count(DISTINCT CASE WHEN member_kind = 4 THEN value_ref END)
                 FROM graph_selected_members WHERE result_id = ?",
                    params![result],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "count initial Graph result",
                });
        }
        let prior = previous.ok_or_else(|| Self::invalid("graph previous count"))?;
        Self::check_touched(writer, result, revision)?;
        let body: Vec<u8> = writer
            .query_row(
                "SELECT body FROM analysis_results WHERE result_id = ?",
                params![prior],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read previous Graph counts",
            })?;
        let header = GraphHeader::decode(&body)?;
        let mut counts = [
            header.subject_count as u64,
            header.edge_count as u64,
            header.finding_count as u64,
        ];
        let mut statement = writer
            .prepare(
                "WITH touched AS (
                SELECT member_kind,member_key FROM graph_stage_touched WHERE member_kind IN (2,3,4)
             ), presence AS (
                SELECT touched.member_kind,
                  EXISTS (SELECT 1 FROM graph_selected_members old
                          WHERE old.result_id = ? AND old.member_kind = touched.member_kind
                            AND old.member_key = touched.member_key) AS before,
                  EXISTS (SELECT 1 FROM graph_selected_members now
                          WHERE now.result_id = ? AND now.member_kind = touched.member_kind
                            AND now.member_key = touched.member_key) AS after
                FROM touched
             )
             SELECT member_kind,
                count(*) FILTER (WHERE NOT before AND after),
                count(*) FILTER (WHERE before AND NOT after)
             FROM presence GROUP BY member_kind",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare changed Graph counts",
            })?;
        let changes = statement
            .query_map(params![prior, result], |row| {
                Ok((
                    row.get::<_, u8>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read changed Graph counts",
            })?;
        for change in changes {
            let (kind, added, removed) = change.context(AnalysisDatabaseSnafu {
                operation: "decode changed Graph counts",
            })?;
            let count = counts
                .get_mut((kind - 2) as usize)
                .ok_or_else(|| Self::invalid("graph changed count kind"))?;
            *count = count
                .checked_add(added)
                .and_then(|value| value.checked_sub(removed))
                .ok_or_else(|| Self::invalid("graph changed count"))?;
        }
        Ok((counts[0], counts[1], counts[2]))
    }

    fn check_touched(writer: &Connection, result: &str, _revision: u64) -> Result<()> {
        let conflict: bool = writer
            .query_row(
                "WITH touched AS (
                SELECT member_kind,member_key FROM graph_stage_touched WHERE member_kind IN (2,3,4)
             )
             SELECT EXISTS (
                 SELECT 1 FROM graph_selected_members selected
                 JOIN touched USING (member_kind, member_key)
                 WHERE selected.result_id = ?
                 GROUP BY selected.member_kind, selected.member_key
                 HAVING count(DISTINCT selected.value_ref) > 1
             )",
                params![result],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate changed Graph keys",
            })?;
        if conflict {
            return Err(Self::invalid("graph producer merge"));
        }
        let orphan: bool = writer.query_row(
            "WITH changed_subjects AS (
                SELECT DISTINCT m.value_ref FROM graph_producer_members m
                JOIN graph_stage_touched touched USING(member_kind,member_key)
                WHERE m.member_kind=2 AND m.scope_id IN (
                    SELECT versions.scope_id FROM graph_result_producers bound
                    JOIN graph_producer_versions versions ON versions.result_id=bound.producer_result_id
                    WHERE bound.result_id=?
                )
             ), changed_output AS (
                SELECT member_kind,member_key FROM graph_stage_touched WHERE member_kind IN (3,4)
             ), affected_edges AS (
                SELECT DISTINCT edge.from_ref, edge.to_ref
                FROM graph_selected_members selected
                JOIN graph_edge_values edge ON edge.edge_id = selected.value_ref
                WHERE selected.result_id = ? AND selected.member_kind = 3
                  AND (edge.from_ref IN (SELECT value_ref FROM changed_subjects)
                       OR edge.to_ref IN (SELECT value_ref FROM changed_subjects)
                       OR selected.member_key IN (SELECT member_key FROM changed_output
                                                  WHERE member_kind = 3))
             ), affected_findings AS (
                SELECT DISTINCT finding.subject_ref
                FROM graph_selected_members selected
                JOIN graph_finding_values finding ON finding.value_id = selected.value_ref
                WHERE selected.result_id = ? AND selected.member_kind = 4
                  AND (finding.subject_ref IN (SELECT value_ref FROM changed_subjects)
                       OR selected.member_key IN (SELECT member_key FROM changed_output
                                                  WHERE member_kind = 4))
             )
             SELECT EXISTS (
                SELECT 1 FROM affected_edges edge
                WHERE NOT EXISTS (SELECT 1 FROM graph_selected_members subject
                                  WHERE subject.result_id = ? AND subject.member_kind = 2
                                    AND subject.value_ref = edge.from_ref)
                   OR NOT EXISTS (SELECT 1 FROM graph_selected_members subject
                                  WHERE subject.result_id = ? AND subject.member_kind = 2
                                    AND subject.value_ref = edge.to_ref)
             ) OR EXISTS (
                SELECT 1 FROM affected_findings finding
                WHERE NOT EXISTS (SELECT 1 FROM graph_selected_members subject
                                  WHERE subject.result_id = ? AND subject.member_kind = 2
                                    AND subject.value_ref = finding.subject_ref)
             )",
            params![result,result,result,result,result,result],
            |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate changed Graph endpoints" })?;
        if orphan {
            return Err(Self::invalid("graph changed endpoint"));
        }
        Ok(())
    }

    pub(super) fn check_union(writer: &Connection, result: &str) -> Result<()> {
        let invalid:bool=writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_selected_members WHERE result_id=? AND member_kind IN (2,3,4) GROUP BY member_kind,member_key HAVING count(DISTINCT value_ref)>1) OR EXISTS(SELECT 1 FROM graph_selected_members m JOIN graph_edge_values e ON e.edge_id=m.value_ref WHERE m.result_id=? AND m.member_kind=3 AND (NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=e.from_ref) OR NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=e.to_ref))) OR EXISTS(SELECT 1 FROM graph_selected_members m JOIN graph_finding_values f ON f.value_id=m.value_ref WHERE m.result_id=? AND m.member_kind=4 AND NOT EXISTS(SELECT 1 FROM graph_selected_members s WHERE s.result_id=m.result_id AND s.member_kind=2 AND s.value_ref=f.subject_ref))",params![result,result,result],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"validate Graph producer merge"})?;
        if invalid {
            return Err(Self::invalid("graph producer merge"));
        }
        Ok(())
    }
}
