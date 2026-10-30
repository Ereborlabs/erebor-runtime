use super::super::history::Member;
use super::*;

pub(super) struct NativeRows;
pub(super) struct NativeIds {
    pub edges: BTreeMap<RelationshipIdentity, u64>,
}

impl NativeRows {
    pub fn insert(graph: &GraphSnapshotV1, writer: &Connection, id: &str) -> Result<NativeIds> {
        let revision = writer
            .query_row(
                "SELECT commit_revision FROM analysis_results WHERE result_id=?",
                params![id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read native Graph fixture revision",
            })?;
        let reference = PackageResultRefV1 {
            result_id: id.into(),
            commit_revision: revision,
        };
        let body = GraphRows::commit(
            writer,
            &reference,
            &GraphManifest::from_snapshot(graph),
            GraphWrite::Direct(graph),
        )?;
        writer
            .execute(
                "UPDATE analysis_results SET body=? WHERE result_id=?",
                params![body, id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "write native Graph fixture header",
            })?;
        let edges = Self::edges(writer, graph)?;
        Ok(NativeIds { edges })
    }

    pub fn insert_with_reuse(
        graph: &GraphSnapshotV1,
        writer: &Connection,
        id: &str,
        previous: Option<&PackageResultRefV1>,
    ) -> Result<NativeIds> {
        if let Some(previous) = previous {
            let revision: Option<u64> = writer
                .query_row(
                    "SELECT commit_revision FROM graph_versions WHERE result_id=?",
                    params![previous.result_id],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read retained Graph fixture",
                })?;
            if graph.previous_result_id.as_deref() != Some(&previous.result_id)
                || revision != Some(previous.commit_revision)
            {
                return Err(GraphRows::invalid("graph unchanged finding base"));
            }
        }
        Self::insert(graph, writer, id)
    }

    pub fn edges(
        writer: &Connection,
        graph: &GraphSnapshotV1,
    ) -> Result<BTreeMap<RelationshipIdentity, u64>> {
        let subjects = GraphRows::intern_subjects(writer, &graph.graph.subjects)?;
        let records = GraphRows::intern_records(
            writer,
            &graph.scope.identity,
            &graph.input_manifest.evidence,
        )?;
        let changes = graph
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
        let ids = GraphRows::intern_edges(writer, &subjects, &records, &changes)?;
        Ok(changes
            .into_iter()
            .zip(ids)
            .map(|(change, id)| (change.key, id))
            .collect())
    }

    pub fn bind(writer: &Connection, id: &str, scope: u64, revision: u64) -> TestResult {
        writer.execute("INSERT INTO graph_producer_scopes VALUES(?, ?,1,1,NULL,NULL,NULL,NULL,NULL,1,1) ON CONFLICT DO NOTHING",params![scope,[1u8;16].as_slice()])?;
        writer.execute(
            "INSERT INTO graph_producer_versions VALUES(?,?,?,NULL,0,0,0,0,NULL)",
            params![id, scope, revision],
        )?;
        writer.execute(
            "INSERT INTO graph_versions VALUES(?,?,?,false,false)",
            params![id, revision, id],
        )?;
        writer.execute(
            "INSERT INTO graph_result_producers VALUES(?,?)",
            params![id, id],
        )?;
        Ok(())
    }

    pub fn subjects(
        writer: &Connection,
        subjects: &[GraphSubjectKeyV1],
        scope: u64,
        revision: u64,
    ) -> Result<()> {
        let values = GraphRows::intern_subjects(writer, subjects)?;
        let members = subjects
            .iter()
            .map(|key| {
                Ok(Member {
                    kind: MemberKind::Subject,
                    key: GraphRows::member_key(key)?,
                    value: values[key],
                    anchor: None,
                    reason: None,
                    ordinal: 0,
                })
            })
            .collect::<Result<_>>()?;
        super::super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &BTreeMap::new(),
            basis: None,
            sparse: false,
            full: true,
        }
        .apply(members, Vec::new(), None)
    }

    pub fn branches(
        writer: &Connection,
        tenant: [u8; 16],
        scope: u64,
        revision: u64,
        branches: &[GraphBranchV1],
    ) -> Result<()> {
        let values = GraphRows::intern_branches(writer, tenant, branches)?;
        let members = branches
            .iter()
            .enumerate()
            .map(|(index, _)| {
                Ok(Member {
                    kind: MemberKind::Branch,
                    key: GraphRows::encode_value(&index)?,
                    value: values[index],
                    anchor: None,
                    reason: None,
                    ordinal: index as u32,
                })
            })
            .collect::<Result<_>>()?;
        super::super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &BTreeMap::new(),
            basis: None,
            sparse: false,
            full: true,
        }
        .apply(members, Vec::new(), None)
    }

    pub fn read_branches(
        writer: &Connection,
        id: &str,
        tenant: [u8; 16],
        count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphBranchV1>> {
        let mut statement=writer.prepare("SELECT m.ordinal,v.tenant_id,v.body,v.value_hash FROM graph_selected_members m LEFT JOIN graph_branch_values v ON v.branch_id=m.value_ref WHERE m.result_id=? AND m.member_kind=6 ORDER BY m.ordinal").context(AnalysisDatabaseSnafu {operation:"prepare native branch fixture"})?;
        let mut rows = statement
            .query(params![id])
            .context(AnalysisDatabaseSnafu {
                operation: "read native branch fixture",
            })?;
        let mut branches = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native branch fixture",
        })? {
            GraphRows::check(control)?;
            let stored: Vec<u8> = GraphRows::column(row, 1)?;
            let body: Vec<u8> = GraphRows::column(row, 2)?;
            let hash: Vec<u8> = GraphRows::column(row, 3)?;
            if stored != tenant
                || hash != GraphRows::hash(&body)
                || GraphRows::column::<u32>(row, 0)? as usize != branches.len()
            {
                return Err(GraphRows::invalid("graph branch fixture value"));
            }
            branches.push(GraphRows::decode_value(&body)?);
        }
        if branches.len() != count {
            return Err(GraphRows::invalid("graph branch count"));
        }
        Ok(branches)
    }
}
