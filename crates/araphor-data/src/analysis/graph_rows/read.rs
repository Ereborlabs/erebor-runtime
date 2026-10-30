use super::*;
use crate::{
    DiscoveryRecordIdV1, GraphEdgeKeyV1, GraphEdgeV1, GraphValidate as _, StorePositionV1,
};

type GraphIndexRow = (Vec<u8>, Vec<u8>, u64, u64, u64, u64);
type GraphInputs = (
    Vec<DiscoveryRecordIdV1>,
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
);

impl GraphRows {
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

    fn header_mode(
        reader: &Connection,
        tenant: [u8; 16],
        result: &str,
        control: Option<&AnalysisReadControl>,
        complete: bool,
    ) -> Result<Option<GraphHeader>> {
        Self::check(control)?;
        let indexed: Option<GraphIndexRow> = reader.query_row("SELECT body,stream_key,method_version,first_cursor,facts_revision,coverage_revision FROM analysis_results WHERE result_id=? AND tenant_id=? AND processor_id=?",params![result,tenant.as_slice(),crate::GRAPH_PROCESSOR],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).optional().context(AnalysisDatabaseSnafu {operation:"read Graph result header"})?;
        let Some((body, stream, method, first, context, coverage)) = indexed else {
            return Ok(None);
        };
        let mut header = GraphHeader::decode(&body)?;
        header.check_index(tenant, &stream, method, first)?;
        header.notice = (context, coverage);
        (header.expired, header.derive_branches) = reader
            .query_row(
                "SELECT expired,derive_branches FROM graph_versions WHERE result_id=?",
                params![result],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph expiry state",
            })?;
        if header.expired
            && header
                .snapshot
                .packages
                .iter()
                .any(|package| package.state != GraphPackageStateV1::CoverageInsufficient)
        {
            return Err(Self::invalid("graph expired package state"));
        }
        if complete {
            let counts:(u64,u64,u64)=reader.query_row("SELECT count(DISTINCT s.subject_id),count(DISTINCT e.edge_id),count(DISTINCT f.value_id) FROM graph_selected_members m LEFT JOIN graph_subject_values s ON m.member_kind=2 AND s.subject_id=m.value_ref LEFT JOIN graph_edge_values e ON m.member_kind=3 AND e.edge_id=m.value_ref LEFT JOIN graph_finding_values f ON m.member_kind=4 AND f.value_id=m.value_ref WHERE m.result_id=?",params![result],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).context(AnalysisDatabaseSnafu {operation:"check Graph header counts"})?;
            header.check_shape(counts.0, counts.1, counts.2)?;
        }
        let (evidence, positions) = Self::inputs(reader, result, &header, control)?;
        header.snapshot.input_manifest.evidence = evidence;
        header.snapshot.input_positions = positions;
        let mut facts = Vec::new();
        let mut statement=reader.prepare("SELECT v.body,v.tenant_id,v.value_hash,m.ordinal,m.member_key FROM graph_selected_members m LEFT JOIN graph_fact_values v ON v.fact_id=m.value_ref WHERE m.result_id=? AND m.member_kind=7 ORDER BY m.ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph facts"})?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph facts",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph facts",
        })? {
            Self::check(control)?;
            let body: Vec<u8> = Self::column(row, 0)?;
            let stored: Vec<u8> = Self::column(row, 1)?;
            let hash: Vec<u8> = Self::column(row, 2)?;
            if stored != tenant || hash != Self::hash(&body) {
                return Err(Self::invalid("graph fact value"));
            }
            let ordinal: u32 = Self::column(row, 3)?;
            let key: Vec<u8> = Self::column(row, 4)?;
            if ordinal as usize != facts.len() || key != Self::encode_value(&(ordinal as usize))? {
                return Err(Self::invalid("graph fact ordinal"));
            }
            let fact: crate::GraphFactV1 = Self::decode_value(&body)?;
            fact.validate()?;
            if fact.record_id.stream != header.snapshot.scope.identity
                || header
                    .snapshot
                    .input_manifest
                    .evidence
                    .binary_search(&fact.record_id)
                    .is_err()
            {
                return Err(Self::invalid("graph fact input"));
            }
            facts.push(fact);
        }
        if facts.len() != header.fact_count {
            return Err(Self::invalid("graph fact count"));
        }
        header.snapshot.graph.facts = facts;
        drop(rows);
        drop(statement);
        if complete && !header.derive_branches {
            let mut branches = Vec::new();
            let mut statement=reader.prepare("SELECT v.body,v.tenant_id,v.value_hash,m.ordinal,m.member_key FROM graph_selected_members m LEFT JOIN graph_branch_values v ON v.branch_id=m.value_ref WHERE m.result_id=? AND m.member_kind=6 ORDER BY m.ordinal,m.member_key").context(AnalysisDatabaseSnafu {operation:"prepare Graph branches"})?;
            let mut rows = statement
                .query(params![result])
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph branches",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance Graph branches",
            })? {
                Self::check(control)?;
                let body: Vec<u8> = Self::column(row, 0)?;
                let stored: Vec<u8> = Self::column(row, 1)?;
                let hash: Vec<u8> = Self::column(row, 2)?;
                if stored != tenant || hash != Self::hash(&body) {
                    return Err(Self::invalid("graph branch value"));
                }
                {
                    let ordinal: u32 = Self::column(row, 3)?;
                    let key: Vec<u8> = Self::column(row, 4)?;
                    if ordinal as usize != branches.len()
                        || key != Self::encode_value(&(ordinal as usize))?
                    {
                        return Err(Self::invalid("graph branch ordinal"));
                    }
                }
                branches.push(Self::decode_value(&body)?);
            }
            if branches.len() != header.branch_count {
                return Err(Self::invalid("graph branch count"));
            }
            header.snapshot.graph.branches = branches;
            header.branches_loaded = true;
        }
        header.complete = complete;
        header.snapshot.validate()?;
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
        let source = &header.snapshot.scope.identity;
        let mut evidence = Vec::new();
        let mut statement=reader.prepare("SELECT e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,r.cpu_id,m.member_key FROM graph_selected_members m LEFT JOIN graph_evidence e ON e.evidence_id=m.value_ref LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.result_id=? AND m.member_kind=0 ORDER BY e.cpu_id,e.durable_cursor").context(AnalysisDatabaseSnafu {operation:"prepare Graph input identities"})?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph input identities",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph input identities",
        })? {
            Self::check(control)?;
            let key: Option<Vec<u8>> = Self::column(row, 2)?;
            let tenant: Option<Vec<u8>> = Self::column(row, 3)?;
            let retained: Option<Vec<u8>> = Self::column(row, 4)?;
            let cpu: u32 = Self::column(row, 0)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || Self::column::<Option<u32>>(row, 5)? != Some(cpu)
            {
                return Err(Self::invalid("graph evidence source"));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: cpu,
                durable_cursor: Self::column(row, 1)?,
            };
            if Self::column::<Vec<u8>>(row, 6)? != Self::member_key(&record)? {
                return Err(Self::invalid("graph evidence member identity"));
            }
            evidence.push(record);
        }
        drop(rows);
        drop(statement);
        let mut positions = Vec::new();
        let mut statement=reader.prepare("SELECT m.ordinal,p.commit_revision,p.ordinal,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key,r.cpu_id,m.member_key FROM graph_selected_members m LEFT JOIN graph_position_values p ON p.value_ref=m.value_ref LEFT JOIN graph_evidence e USING(evidence_id) LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.result_id=? AND m.member_kind=1 ORDER BY m.ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph input positions"})?;
        let mut rows = statement
            .query(params![result])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph input positions",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph input positions",
        })? {
            Self::check(control)?;
            if Self::column::<u32>(row, 0)? as usize != positions.len() {
                return Err(Self::invalid("graph position ordinal"));
            }
            let key: Option<Vec<u8>> = Self::column(row, 5)?;
            let tenant: Option<Vec<u8>> = Self::column(row, 6)?;
            let retained: Option<Vec<u8>> = Self::column(row, 7)?;
            let cpu: u32 = Self::column(row, 3)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
                || Self::column::<Option<u32>>(row, 8)? != Some(cpu)
            {
                return Err(Self::invalid("graph evidence source"));
            }
            if Self::column::<Vec<u8>>(row, 9)? != Self::encode_value(&positions.len())? {
                return Err(Self::invalid("graph position member identity"));
            }
            positions.push((
                DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: cpu,
                    durable_cursor: Self::column(row, 4)?,
                },
                StorePositionV1 {
                    commit_revision: Self::column(row, 1)?,
                    ordinal: Self::column(row, 2)?,
                },
            ));
        }
        if evidence.len() != header.evidence_count
            || positions.len() != header.position_count
            || evidence.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Self::invalid("graph input row counts"));
        }
        Ok((evidence, positions))
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
        let mut statement=reader.prepare("SELECT ordinal,tenant_id,authority_rank,authority_text,authority_boot,authority_epoch,subject_kind,identity FROM graph_subjects WHERE result_id=? ORDER BY ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph subjects"})?;
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
        let mut statement=reader.prepare("SELECT ordinal,from_subject_id,to_subject_id,edge_type,package_id,cause,evidence,proof_quality,required_coverage_interval_ids,first_boottime_ns,last_boottime_ns FROM graph_relationships WHERE result_id=? ORDER BY ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph relationships"})?;
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
        let evidence = match Self::column(row, 6)? {
            duckdb::types::Value::List(values) => values
                .into_iter()
                .map(|value| match value {
                    duckdb::types::Value::UInt(id) => Ok(id),
                    _ => Err(Self::invalid("graph relationship evidence")),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(Self::invalid("graph relationship evidence")),
        };
        Ok(GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: Self::column(row, 1)?,
                to: Self::column(row, 2)?,
                edge_type: Self::label_column(row, 3)?,
                package_id: Self::column(row, 4)?,
                cause: Self::label_column(row, 5)?,
                evidence,
            },
            proof_quality: Self::read_proof(row, 7)?,
            required_coverage_interval_ids: Self::read_bytes(row, 8)?,
            first_boottime_ns: Self::column(row, 9)?,
            last_boottime_ns: Self::column(row, 10)?,
        })
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
        let mut statement=reader.prepare("SELECT e.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key FROM graph_selected_members m JOIN graph_evidence e ON m.value_ref=e.evidence_id LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.result_id=? AND m.member_kind=0").context(AnalysisDatabaseSnafu {operation:"prepare finding evidence"})?;
        let mut rows = statement
            .query(params![result])
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
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
            {
                return Err(Self::invalid("graph finding evidence source"));
            }
            evidence.insert(
                Self::column::<u64>(row, 0)?,
                DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: Self::column(row, 1)?,
                    durable_cursor: Self::column(row, 2)?,
                },
            );
        }
        drop(rows);
        drop(statement);
        let columns = araphor_graph::FindingRows::COLUMNS;
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
            let (subject, refs) = araphor_graph::FindingRows::references(row)?;
            let finding = araphor_graph::FindingRows::decode(
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
            Self::check_finding_value(&finding, header)?;
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
        let wanted = ids.iter().collect::<BTreeSet<_>>();
        if wanted.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = std::iter::repeat_n("(?)", wanted.len())
            .collect::<Vec<_>>()
            .join(",");
        let selected=format!("WITH wanted(finding_id) AS (VALUES {placeholders}),selected AS (SELECT DISTINCT m.result_id,f.*,m.member_key FROM wanted w JOIN graph_finding_values f ON f.finding_id=w.finding_id JOIN graph_selected_members m ON m.member_kind=4 AND m.value_ref=f.value_id WHERE m.result_id=?)");
        let mut parameters = wanted
            .into_iter()
            .map(|id| duckdb::types::Value::Text(id.clone()))
            .collect::<Vec<_>>();
        parameters.push(duckdb::types::Value::Text(result.into()));
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
        let columns = araphor_graph::FindingRows::COLUMNS
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
            let (subject, refs) = araphor_graph::FindingRows::references(row)?;
            let finding = araphor_graph::FindingRows::decode(
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
            Self::check_finding_value(&finding, header)?;
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
        Ok(Self::read_finding_keys_with_ids(
            reader,
            result,
            header,
            &[finding.to_owned()],
            control,
        )?
        .remove(finding))
    }

    fn check_finding_value(finding: &FindingV1, header: &GraphHeader) -> Result<()> {
        if finding.tenant_id != header.snapshot.scope.identity.tenant_id {
            return Err(Self::invalid("graph finding tenant"));
        }
        finding.validate()?;
        header.snapshot.input_manifest.validate_finding(finding)?;
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
