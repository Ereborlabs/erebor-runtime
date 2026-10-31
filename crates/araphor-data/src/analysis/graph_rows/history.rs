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
    pub(in crate::analysis) fn commit(
        writer: &Connection,
        result: &PackageResultRefV1,
        metadata: &GraphManifest,
        input: GraphWrite<'_>,
    ) -> Result<Vec<u8>> {
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
        Self::write_metadata(
            writer,
            metadata_scope,
            source,
            result.commit_revision,
            metadata,
        )?;
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
                Self::write_snapshot(writer, scope, result.commit_revision, graph)?;
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
                Self::write_snapshot(writer, scope, result.commit_revision, &graph)?;
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
        GraphHeader::encode(
            metadata,
            (
                subjects as usize,
                edges as usize,
                findings as usize,
                branches,
            ),
        )
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

    pub(super) fn call_scope(
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
                "INSERT INTO graph_producer_versions VALUES(?,?,?,?,0,0,0,0,NULL)",
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
        source: u64,
        revision: u64,
        metadata: &GraphManifest,
    ) -> Result<()> {
        Self::check_record_cpus(
            writer,
            &metadata.scope.identity,
            &metadata.input_manifest.evidence,
        )?;
        writer.execute_batch(
            "CREATE TEMP TABLE graph_stage_evidence (cpu_id UINTEGER, durable_cursor UBIGINT, member_key BLOB);
             CREATE TEMP TABLE graph_stage_positions (cpu_id UINTEGER, durable_cursor UBIGINT,
                 position_revision UBIGINT, position_ordinal UINTEGER, member_key BLOB, list_ordinal UINTEGER);
             CREATE TEMP TABLE graph_stage_facts (member_key BLOB, list_ordinal UINTEGER, value_hash BLOB, body BLOB);
             CREATE TEMP TABLE graph_stage_members (member_kind UTINYINT, member_key BLOB,
                 value_ref UBIGINT, ordinal UINTEGER, PRIMARY KEY (member_kind, member_key));",
        ).context(AnalysisDatabaseSnafu { operation: "stage Graph metadata" })?;
        {
            let mut appender =
                writer
                    .appender("graph_stage_evidence")
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph evidence",
                    })?;
            for record in &metadata.input_manifest.evidence {
                appender
                    .append_row(params![
                        record.cpu_id,
                        record.durable_cursor,
                        Self::member_key(record)?,
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph evidence",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph evidence stage",
            })?;
        }
        {
            let mut appender =
                writer
                    .appender("graph_stage_positions")
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph positions",
                    })?;
            for (index, (record, position)) in metadata.input_positions.iter().enumerate() {
                let ordinal =
                    u32::try_from(index).map_err(|_| Self::invalid("graph position ordinal"))?;
                appender
                    .append_row(params![
                        record.cpu_id,
                        record.durable_cursor,
                        position.commit_revision,
                        position.ordinal,
                        Self::encode_value(&index)?,
                        ordinal,
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph positions",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph position stage",
            })?;
        }
        {
            let mut appender =
                writer
                    .appender("graph_stage_facts")
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph facts",
                    })?;
            for (index, fact) in metadata.facts.iter().enumerate() {
                fact.validate()?;
                let body = Self::encode_value(fact)?;
                let ordinal =
                    u32::try_from(index).map_err(|_| Self::invalid("graph fact ordinal"))?;
                appender
                    .append_row(params![
                        Self::encode_value(&index)?,
                        ordinal,
                        Self::hash(&body),
                        body,
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage Graph facts",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph fact stage",
            })?;
        }
        writer
            .execute(
                "INSERT INTO graph_evidence
             SELECT nextval('graph_evidence_seq'), ?, stage.cpu_id, stage.durable_cursor
             FROM graph_stage_evidence stage
             LEFT JOIN graph_evidence saved ON saved.source_ref = ?
                 AND saved.cpu_id = stage.cpu_id AND saved.durable_cursor = stage.durable_cursor
             WHERE saved.evidence_id IS NULL",
                params![source, source],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "intern Graph evidence batch",
            })?;
        writer.execute(
            "INSERT INTO graph_position_values
             SELECT nextval('graph_position_values_seq'), evidence.evidence_id,
                 stage.position_revision, stage.position_ordinal
             FROM (SELECT DISTINCT cpu_id, durable_cursor, position_revision, position_ordinal
                   FROM graph_stage_positions) stage
             JOIN graph_evidence evidence ON evidence.source_ref = ?
                 AND evidence.cpu_id = stage.cpu_id AND evidence.durable_cursor = stage.durable_cursor
             LEFT JOIN graph_position_values saved ON saved.evidence_id = evidence.evidence_id
                 AND saved.commit_revision = stage.position_revision
                 AND saved.ordinal = stage.position_ordinal
             WHERE saved.value_ref IS NULL",
            params![source],
        ).context(AnalysisDatabaseSnafu { operation: "intern Graph position batch" })?;
        writer
            .execute(
                "INSERT INTO graph_fact_values
             SELECT nextval('graph_fact_values_seq'), ?, stage.value_hash, stage.body
             FROM (SELECT DISTINCT value_hash, body FROM graph_stage_facts) stage
             WHERE NOT EXISTS (SELECT 1 FROM graph_fact_values saved
                 WHERE saved.tenant_id = ? AND saved.value_hash = stage.value_hash
                   AND saved.body = stage.body)",
                params![
                    metadata.scope.identity.tenant_id.as_slice(),
                    metadata.scope.identity.tenant_id.as_slice()
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "intern Graph fact batch",
            })?;
        writer.execute(
            "INSERT INTO graph_stage_members
             SELECT 0, stage.member_key, evidence.evidence_id, 0
             FROM graph_stage_evidence stage
             JOIN graph_evidence evidence ON evidence.source_ref = ?
                 AND evidence.cpu_id = stage.cpu_id AND evidence.durable_cursor = stage.durable_cursor",
            params![source],
        ).context(AnalysisDatabaseSnafu { operation: "stage Graph evidence members" })?;
        writer.execute(
            "INSERT INTO graph_stage_members
             SELECT 1, stage.member_key, position.value_ref, stage.list_ordinal
             FROM graph_stage_positions stage
             JOIN graph_evidence evidence ON evidence.source_ref = ?
                 AND evidence.cpu_id = stage.cpu_id AND evidence.durable_cursor = stage.durable_cursor
             JOIN graph_position_values position ON position.evidence_id = evidence.evidence_id
                 AND position.commit_revision = stage.position_revision
                 AND position.ordinal = stage.position_ordinal",
            params![source],
        ).context(AnalysisDatabaseSnafu { operation: "stage Graph position members" })?;
        writer
            .execute(
                "INSERT INTO graph_stage_members
             SELECT 7, stage.member_key, min(fact.fact_id), stage.list_ordinal
             FROM graph_stage_facts stage
             JOIN graph_fact_values fact ON fact.tenant_id = ?
                 AND fact.value_hash = stage.value_hash AND fact.body = stage.body
             GROUP BY stage.member_key, stage.list_ordinal",
                params![metadata.scope.identity.tenant_id.as_slice()],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "stage Graph fact members",
            })?;
        let mut statement = writer
            .prepare("SELECT member_kind,member_key,value_ref,ordinal FROM graph_stage_members")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph metadata members",
            })?;
        let members = statement
            .query_map([], |row| {
                Ok(araphor_graph::Member {
                    kind: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                    record: None,
                    fact: None,
                    reason: None,
                    ordinal: row.get(3)?,
                })
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph metadata members",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Graph metadata members",
            })?;
        drop(statement);
        araphor_graph::Contributions::apply(
            writer,
            scope,
            revision,
            &[araphor_graph::Replacement {
                unit: None,
                members,
            }],
            false,
        )?;
        writer
            .execute_batch(
                "DROP TABLE graph_stage_members;
             DROP TABLE graph_stage_facts;
             DROP TABLE graph_stage_positions;
             DROP TABLE graph_stage_evidence;",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph metadata stage",
            })?;
        Ok(())
    }

    fn write_snapshot(
        writer: &Connection,
        scope: u64,
        revision: u64,
        graph: &GraphSnapshotV1,
    ) -> Result<()> {
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
        super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &records,
            basis: None,
            sparse: false,
            full: true,
        }
        .apply(members, Vec::new(), None)
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
