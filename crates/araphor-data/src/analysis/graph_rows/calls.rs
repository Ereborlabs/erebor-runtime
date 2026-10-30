use super::history::Member;
use super::*;
use crate::{AnalysisContractSnafu, DiscoveryRecordIdV1, GraphValidate as _, ManagedSpec};

pub(super) struct OutputMode<'a> {
    pub(super) sparse: bool,
    pub(super) full: bool,
    pub(super) native_progress: bool,
    pub(super) retained: Option<(&'a super::super::managed::Retention, u64)>,
}

#[derive(Clone, Debug, Default)]
pub(in crate::analysis) struct GraphCallState {
    pub subjects: BTreeMap<GraphSubjectKeyV1, (u64, SubjectChange)>,
    pub edges: BTreeMap<RelationshipIdentity, (u64, RelationshipChange)>,
    pub findings: BTreeMap<String, (u64, FindingChange)>,
    pub progress: BTreeMap<DiscoveryRecordIdV1, Progress>,
}

impl GraphCallState {
    pub fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.subjects
                    .iter()
                    .map(|(key, (_, value))| {
                        std::mem::size_of_val(key)
                            + std::mem::size_of_val(value)
                            + key.allocated_bytes()
                            + value.allocated_bytes()
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.edges
                    .iter()
                    .map(|(key, (_, value))| {
                        std::mem::size_of_val(key)
                            + std::mem::size_of_val(value)
                            + key.allocated_bytes()
                            + value.allocated_bytes()
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.findings
                    .iter()
                    .map(|(key, (_, value))| {
                        std::mem::size_of_val(key)
                            + std::mem::size_of_val(value)
                            + key.capacity()
                            + value.allocated_bytes()
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.progress
                    .iter()
                    .map(|(key, value)| {
                        std::mem::size_of_val(key)
                            + std::mem::size_of_val(value)
                            + key.allocated_bytes()
                            + value.allocated_bytes()
                    })
                    .sum::<usize>(),
            )
    }

    pub fn outputs(&self) -> Result<Vec<sdk::Dataset>> {
        Ok(vec![
            SubjectChange::encode(
                &self
                    .subjects
                    .values()
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            SubjectRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            RelationshipChange::encode(
                &self
                    .edges
                    .values()
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            RelationshipRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            FindingChange::encode(
                &self
                    .findings
                    .values()
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            FindingRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            Progress::encode(&self.progress.values().cloned().collect::<Vec<_>>())
                .context(AnalysisContractSnafu)?,
            ProgressRemoval::encode(&[]).context(AnalysisContractSnafu)?,
        ])
    }
}

pub(in crate::analysis) struct GraphCallRows;

pub(super) struct CallBasis {
    records: BTreeMap<DiscoveryRecordIdV1, u32>,
    facts: BTreeMap<crate::AnalysisContextKeyV1, (u32, FactAnchor)>,
    restricted: bool,
}

impl CallBasis {
    pub(super) fn new(evaluation: &sdk::Evaluation) -> Result<Self> {
        let records = Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let facts = Fact::decode(
            &evaluation
                .input("facts")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let mut indexed = BTreeMap::new();
        for (index, row) in records.iter().enumerate() {
            if indexed
                .insert(
                    row.id.clone(),
                    u32::try_from(index).map_err(|_| GraphRows::invalid("graph record ordinal"))?,
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate record"));
            }
        }
        let mut anchored = BTreeMap::new();
        let mut restricted = false;
        for (index, fact) in facts.into_iter().enumerate() {
            let record = records
                .get(fact.record as usize)
                .ok_or_else(|| GraphRows::invalid("graph fact record"))?;
            restricted |= fact.sensitivity == ContextSensitivityV1::HostRestricted;
            let anchor = FactAnchor {
                record: record.id.clone(),
                key: fact.key.clone(),
                sensitivity: fact.sensitivity,
                value: fact.value,
            };
            if anchored
                .insert(
                    fact.key,
                    (
                        u32::try_from(index)
                            .map_err(|_| GraphRows::invalid("graph fact ordinal"))?,
                        anchor,
                    ),
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate fact"));
            }
        }
        Ok(Self {
            records: indexed,
            facts: anchored,
            restricted,
        })
    }

    pub(super) fn local(&self, anchor: &Anchor) -> Result<(u32, Option<u32>)> {
        let record = *self
            .records
            .get(&anchor.record)
            .ok_or_else(|| GraphRows::invalid("graph anchor record"))?;
        let fact = anchor
            .fact
            .as_ref()
            .map(|fact| {
                let (index, expected) = self
                    .facts
                    .get(&fact.key)
                    .ok_or_else(|| GraphRows::invalid("graph anchor fact"))?;
                if fact != expected {
                    return Err(GraphRows::invalid("graph anchor fact"));
                }
                Ok(*index)
            })
            .transpose()?;
        Ok((record, fact))
    }
}

impl GraphRows {
    pub(super) fn apply_output(
        writer: &Connection,
        scope: u64,
        revision: u64,
        metadata: &GraphManifest,
        returned: &crate::ManagedReturn<'_>,
        pin: &crate::ManagedCall,
        mode: OutputMode<'_>,
    ) -> Result<()> {
        let evaluation = returned.evaluation;
        let output = returned.output;
        let basis = CallBasis::new(evaluation)?;
        if basis.records.keys().any(|record| {
            record.stream != metadata.scope.identity
                || metadata
                    .input_manifest
                    .evidence
                    .binary_search(record)
                    .is_err()
        }) {
            return Err(Self::invalid("graph call input evidence"));
        }
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .ok_or_else(|| Self::invalid("graph output dataset"))
        };
        let mut removals = Vec::new();
        for row in
            SubjectRemoval::decode(dataset("subject_removals")?).context(AnalysisContractSnafu)?
        {
            removals.push((MemberKind::Subject, Self::encode_value(&row.key)?));
        }
        for row in RelationshipRemoval::decode(dataset("relationship_removals")?)
            .context(AnalysisContractSnafu)?
        {
            removals.push((MemberKind::Edge, Self::encode_value(&row.key)?));
        }
        for row in
            FindingRemoval::decode(dataset("finding_removals")?).context(AnalysisContractSnafu)?
        {
            removals.push((MemberKind::Finding, Self::encode_value(&row.finding_id)?));
        }
        let subjects =
            SubjectChange::decode(dataset("subjects")?).context(AnalysisContractSnafu)?;
        for row in &subjects {
            basis.local(&row.anchor)?;
            row.key.validate()?;
            if row.key.tenant_id != metadata.scope.identity.tenant_id {
                return Err(Self::invalid("graph subject tenant"));
            }
        }
        let edges =
            RelationshipChange::decode(dataset("relationships")?).context(AnalysisContractSnafu)?;
        for row in &edges {
            basis.local(&row.anchor)?;
            if row.key.from.tenant_id != metadata.scope.identity.tenant_id
                || row.key.to.tenant_id != metadata.scope.identity.tenant_id
                || row.key.package_id != pin.package.package_id
                || row.first_boottime_ns > row.last_boottime_ns
                || row.key.evidence.is_empty()
                || row.key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || row.key.evidence.iter().any(|record| {
                    !basis.records.contains_key(record)
                        || metadata
                            .input_manifest
                            .evidence
                            .binary_search(record)
                            .is_err()
                })
                || (row.key.edge_type == GraphEdgeTypeV1::NativeParent
                    && (row.key.from.authority != row.key.to.authority
                        || !matches!(
                            row.key.from.authority,
                            GraphSubjectAuthorityV1::Native { .. }
                        )))
            {
                return Err(Self::invalid("graph edge value"));
            }
        }
        let changes = FindingChange::decode(dataset("findings")?).context(AnalysisContractSnafu)?;
        let mut reasons = BTreeMap::new();
        for reason in &output.reasons {
            if reason.output.dataset != "findings"
                || reasons.insert(reason.output.row, reason).is_some()
            {
                return Err(Self::invalid("graph finding reason"));
            }
        }
        if reasons.len() != changes.len() {
            return Err(Self::invalid("graph finding reason"));
        }
        let positions = basis
            .records
            .iter()
            .map(|(record, index)| (record, *index))
            .collect();
        let mut findings = Vec::with_capacity(changes.len());
        for (index, row) in changes.iter().enumerate() {
            let (record, context) = basis.local(&row.anchor)?;
            if row.prior_reason.is_some() {
                return Err(Self::invalid("graph finding prior reason"));
            }
            let reason = FindingReasonV1::from_output(
                &row.package_id,
                &row.local(record, context),
                &positions,
                reasons
                    .get(&(index as u64))
                    .ok_or_else(|| Self::invalid("graph finding reason"))?,
            )
            .context(AnalysisContractSnafu)?;
            let finding = row.clone().into_finding(reason);
            metadata.input_manifest.validate_finding(&finding)?;
            if finding.tenant_id != metadata.scope.identity.tenant_id
                || finding.package_id != pin.package.package_id
                || !metadata.packages.iter().any(|package| {
                    package.package_id == finding.package_id
                        && package.package_version == finding.package_version
                })
                || (basis.restricted && finding.sensitivity != ContextSensitivityV1::HostRestricted)
                || finding
                    .policy_provenance
                    .iter()
                    .flat_map(|policy| &policy.observations)
                    .any(|record| !basis.records.contains_key(record))
            {
                return Err(Self::invalid("graph finding authority"));
            }
            findings.push(finding);
        }
        let detector = if mode.native_progress {
            Some(Detector::from_id(&pin.package.package_id).context(AnalysisContractSnafu)?)
        } else {
            None
        };
        let progress_plan = Self::progress_plan(evaluation, output, detector, mode.full)?;
        for record in progress_plan.removals {
            removals.push((MemberKind::Progress, Self::encode_value(&record)?));
        }
        let progress = progress_plan.additions;
        for row in &progress {
            if row.digest.len() != 32 || !basis.records.contains_key(&row.record) {
                return Err(Self::invalid("graph progress value"));
            }
        }
        let records = Self::intern_records(
            writer,
            &metadata.scope.identity,
            &metadata.input_manifest.evidence,
        )?;
        let keys = subjects
            .iter()
            .map(|row| row.key.clone())
            .chain(
                edges
                    .iter()
                    .flat_map(|edge| [edge.key.from.clone(), edge.key.to.clone()]),
            )
            .chain(findings.iter().map(|finding| finding.subject_id.clone()))
            .collect::<Vec<_>>();
        let subject_ids = Self::intern_subjects(writer, &keys)?;
        let values = edges.iter().map(EdgeValue::from).collect::<Vec<_>>();
        let edge_ids = Self::intern_edges(writer, &subject_ids, &records, &values)?;
        let finding_ids = Self::intern_findings(writer, &subject_ids, &records, &findings)?;
        let progress_ids = Self::intern_progress(writer, &records, &progress)?;
        let mut members =
            Vec::with_capacity(subjects.len() + edges.len() + findings.len() + progress.len());
        for row in subjects {
            members.push(Member {
                kind: MemberKind::Subject,
                key: Self::member_key(&row.key)?,
                value: subject_ids[&row.key],
                anchor: Some(row.anchor),
                reason: None,
                ordinal: 0,
            });
        }
        for (row, id) in edges.into_iter().zip(edge_ids) {
            members.push(Member {
                kind: MemberKind::Edge,
                key: Self::member_key(&row.key)?,
                value: id,
                anchor: Some(row.anchor),
                reason: None,
                ordinal: 0,
            });
        }
        for (row, finding) in changes.into_iter().zip(findings) {
            let key = Self::member_key(&row.finding_id)?;
            members.push(Member {
                kind: MemberKind::Finding,
                key,
                value: finding_ids[&finding.finding_id],
                anchor: Some(row.anchor),
                reason: Some(row.reason_code),
                ordinal: 0,
            });
        }
        for row in progress {
            members.push(Member {
                kind: MemberKind::Progress,
                key: Self::member_key(&row.record)?,
                value: progress_ids[&row.record],
                anchor: Some(Anchor {
                    record: row.record,
                    fact: None,
                }),
                reason: None,
                ordinal: 0,
            });
        }
        super::stage::GraphStage {
            writer,
            scope,
            revision,
            records: &records,
            basis: Some(&basis),
            sparse: mode.sparse,
            full: mode.full,
        }
        .apply(members, removals, progress_plan.root.as_deref())?;
        if let (Some((retained, call)), Some(progress)) = (mode.retained, progress_plan.next) {
            retained.progress(call, progress);
        }
        Ok(())
    }

    pub(super) fn check_call(
        writer: &Connection,
        scope: u64,
        revision: u64,
        metadata: &GraphManifest,
        evaluation: &sdk::Evaluation,
    ) -> Result<()> {
        let basis = CallBasis::new(evaluation)?;
        let source = Self::source_id(writer, &metadata.scope.identity)?;
        let mut statement = writer
            .prepare(
                "SELECT evidence_id,cpu_id,durable_cursor FROM graph_evidence WHERE source_ref=?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare invalidated Graph inputs",
            })?;
        let records = statement
            .query_map(params![source], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read invalidated Graph inputs",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode invalidated Graph inputs",
            })?
            .into_iter()
            .filter(|(_, cpu, cursor)| {
                basis.records.contains_key(&DiscoveryRecordIdV1 {
                    stream: metadata.scope.identity.clone(),
                    cpu_id: *cpu,
                    durable_cursor: *cursor,
                })
            })
            .map(|(id, _, _)| id)
            .collect::<Vec<_>>();
        writer.execute_batch("CREATE TEMP TABLE graph_check_records(evidence_id UBIGINT PRIMARY KEY); CREATE TEMP TABLE graph_check_facts(body BLOB PRIMARY KEY)").context(AnalysisDatabaseSnafu {operation:"create Graph input checks"})?;
        {
            let mut appender =
                writer
                    .appender("graph_check_records")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph record checks",
                    })?;
            for record in records {
                appender
                    .append_row(params![record])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph record check",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph record checks",
            })?;
        }
        {
            let mut appender =
                writer
                    .appender("graph_check_facts")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph fact checks",
                    })?;
            for (_, fact) in basis.facts.values() {
                appender
                    .append_row(params![Self::encode_value(fact)?])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph fact check",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph fact checks",
            })?;
        }
        let invalid:bool=writer.query_row("SELECT EXISTS(SELECT 1 FROM graph_producer_members m WHERE scope_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) AND ((anchor_record_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM graph_check_records r WHERE r.evidence_id=m.anchor_record_id)) OR (anchor_fact IS NOT NULL AND NOT EXISTS(SELECT 1 FROM graph_check_facts f WHERE f.body=m.anchor_fact)))) OR EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_edge_values e ON e.edge_id=m.value_ref WHERE scope_id=? AND m.member_kind=3 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) AND EXISTS(SELECT 1 FROM unnest(e.evidence_refs) refs(id) WHERE NOT EXISTS(SELECT 1 FROM graph_check_records r WHERE r.evidence_id=refs.id))) OR EXISTS(SELECT 1 FROM graph_producer_members m JOIN graph_finding_values f ON f.value_id=m.value_ref WHERE scope_id=? AND m.member_kind=4 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) AND ((? AND f.sensitivity<>'host_restricted') OR EXISTS(SELECT 1 FROM unnest(f.evidence_refs) refs(id) WHERE NOT EXISTS(SELECT 1 FROM graph_check_records r WHERE r.evidence_id=refs.id))))",params![scope,revision,revision,scope,revision,revision,scope,revision,revision,basis.restricted],|row|row.get(0)).context(AnalysisDatabaseSnafu {operation:"check Graph retained dependencies"})?;
        writer
            .execute_batch("DROP TABLE graph_check_facts; DROP TABLE graph_check_records")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph input checks",
            })?;
        if invalid {
            return Err(Self::invalid("graph retained input dependency"));
        }
        let _ = metadata;
        Ok(())
    }
}

impl GraphCallRows {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis) fn load_progress(
        reader: &Connection,
        spec: &ManagedSpec,
        call: u64,
        result_id: &str,
        revision: u64,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        verified_native: Option<bool>,
    ) -> Result<GraphCallState> {
        let reference = PackageResultRefV1 {
            result_id: result_id.into(),
            commit_revision: revision,
        };
        let scope = GraphRows::call_scope(reader, spec, call, &reference)?;
        let input_basis = CallBasis::new(evaluation)?;
        Self::validate_record_cut(reader, spec, result_id, &input_basis)?;
        let crate::ManagedDestination::Graph { source, .. } = &spec.destination else {
            return Err(GraphRows::invalid("graph call destination"));
        };
        let records = Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?
        .into_iter()
        .map(|record| record.id)
        .collect::<BTreeSet<_>>();
        let mut state = GraphCallState {
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            progress: BTreeMap::new(),
        };
        let mut statement=reader.prepare("SELECT p.value_ref,e.cpu_id,e.durable_cursor,p.digest,p.state,s.stream_key,s.tenant_id,r.stream_key,m.member_key FROM graph_producer_members m LEFT JOIN graph_progress_values p ON p.value_ref=m.value_ref LEFT JOIN graph_evidence e USING(evidence_id) LEFT JOIN graph_sources s USING(source_ref) LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id WHERE m.scope_id=? AND m.member_kind=5 AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) ORDER BY e.cpu_id,e.durable_cursor").context(AnalysisDatabaseSnafu {operation:"prepare Graph progress basis"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph progress basis",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph progress basis",
        })? {
            control.check()?;
            let key: Option<Vec<u8>> = GraphRows::column(row, 5)?;
            let tenant: Option<Vec<u8>> = GraphRows::column(row, 6)?;
            let retained: Option<Vec<u8>> = GraphRows::column(row, 7)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(spec.tenant.as_slice())
                || retained.is_none()
            {
                return Err(GraphRows::invalid("graph progress source"));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: GraphRows::column(row, 1)?,
                durable_cursor: GraphRows::column(row, 2)?,
            };
            let digest: Vec<u8> = GraphRows::column(row, 3)?;
            let member_key: Vec<u8> = GraphRows::column(row, 8)?;
            if digest.len() != 32
                || !records.contains(&record)
                || member_key != GraphRows::member_key(&record)?
            {
                return Err(GraphRows::invalid("graph progress basis"));
            }
            let value = Progress {
                record: record.clone(),
                digest: digest.into(),
                state: GraphRows::column(row, 4)?,
            };
            if state.progress.insert(record, value).is_some() {
                return Err(GraphRows::invalid("graph progress duplicate"));
            }
        }
        let (count,root):(u64,Option<Vec<u8>>) = reader
            .query_row(
                "SELECT progress_count,derived_progress_digest FROM graph_producer_versions WHERE result_id=?",
                params![result_id],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check Graph progress count",
            })?;
        if count != state.progress.len() as u64 {
            return Err(GraphRows::invalid("graph progress count"));
        }
        let detector = Self::progress_detector(reader, spec, call, verified_native)?;
        state.progress = GraphRows::expand_progress(
            evaluation,
            state.progress.into_values().collect(),
            root.as_deref(),
            detector,
        )?;
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis) fn load(
        reader: &Connection,
        spec: &ManagedSpec,
        call: u64,
        result_id: &str,
        revision: u64,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
        verified_native: Option<bool>,
    ) -> Result<GraphCallState> {
        let reference = PackageResultRefV1 {
            result_id: result_id.into(),
            commit_revision: revision,
        };
        let scope = GraphRows::call_scope(reader, spec, call, &reference)?;
        let crate::ManagedDestination::Graph { source, .. } = &spec.destination else {
            return Err(GraphRows::invalid("graph call destination"));
        };
        let package = &spec.manifest.calls[&call].package.package_id;
        let basis = CallBasis::new(evaluation)?;
        Self::validate_record_cut(reader, spec, result_id, &basis)?;
        let selected="WITH selected AS (SELECT * FROM graph_producer_members WHERE scope_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?))";
        let mut evidence = BTreeMap::new();
        let mut statement=reader.prepare(&format!("{selected}, refs AS (
            SELECT anchor_record_id AS evidence_id FROM selected WHERE anchor_record_id IS NOT NULL
            UNION SELECT unnest(e.evidence_refs) FROM selected m JOIN graph_edge_values e ON m.member_kind=3 AND e.edge_id=m.value_ref
            UNION SELECT unnest(f.evidence_refs) FROM selected m JOIN graph_finding_values f ON m.member_kind=4 AND f.value_id=m.value_ref
            UNION SELECT p.evidence_id FROM selected m JOIN graph_progress_values p ON m.member_kind=5 AND p.value_ref=m.value_ref)
            SELECT refs.evidence_id,e.cpu_id,e.durable_cursor,s.stream_key,s.tenant_id,r.stream_key
            FROM refs LEFT JOIN graph_evidence e USING(evidence_id) LEFT JOIN graph_sources s USING(source_ref)
            LEFT JOIN source_receipts r ON r.stream_key=s.stream_key AND r.tenant_id=s.tenant_id"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call evidence"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call evidence",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call evidence",
        })? {
            control.check()?;
            let key: Option<Vec<u8>> = GraphRows::column(row, 3)?;
            let tenant: Option<Vec<u8>> = GraphRows::column(row, 4)?;
            let retained: Option<Vec<u8>> = GraphRows::column(row, 5)?;
            if key.as_deref() != Some(source.key().as_slice())
                || tenant.as_deref() != Some(source.tenant_id.as_slice())
                || retained.is_none()
            {
                return Err(GraphRows::invalid("graph call evidence source"));
            }
            let record = DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: GraphRows::column(row, 1)?,
                durable_cursor: GraphRows::column(row, 2)?,
            };
            if !basis.records.contains_key(&record)
                || evidence
                    .insert(GraphRows::column::<u64>(row, 0)?, record)
                    .is_some()
            {
                return Err(GraphRows::invalid("graph call evidence input"));
            }
        }
        drop(rows);
        drop(statement);
        let mut subjects = BTreeMap::new();
        let mut statement=reader.prepare(&format!("{selected}, refs AS (
            SELECT value_ref AS subject_id FROM selected WHERE member_kind=2
            UNION SELECT e.from_ref FROM selected m JOIN graph_edge_values e ON m.member_kind=3 AND e.edge_id=m.value_ref
            UNION SELECT e.to_ref FROM selected m JOIN graph_edge_values e ON m.member_kind=3 AND e.edge_id=m.value_ref
            UNION SELECT f.subject_ref FROM selected m JOIN graph_finding_values f ON m.member_kind=4 AND f.value_id=m.value_ref)
            SELECT refs.subject_id,s.tenant_id,s.authority_rank,s.authority_text,s.authority_boot,s.authority_epoch,s.subject_kind,s.identity
            FROM refs LEFT JOIN graph_subject_values s USING(subject_id)"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call subjects"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call subjects",
        })? {
            control.check()?;
            let subject = GraphRows::decode_subject(row)?;
            if subject.tenant_id != spec.tenant
                || subjects
                    .insert(GraphRows::column::<u64>(row, 0)?, subject)
                    .is_some()
            {
                return Err(GraphRows::invalid("graph call subject identity"));
            }
        }
        drop(rows);
        drop(statement);
        let anchor = |row: &duckdb::Row<'_>, record: usize, fact: usize| -> Result<Anchor> {
            let id: u64 = GraphRows::column(row, record)?;
            let bytes: Option<Vec<u8>> = GraphRows::column(row, fact)?;
            let anchor = Anchor {
                record: evidence
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph call anchor record"))?,
                fact: bytes.as_deref().map(GraphRows::decode_value).transpose()?,
            };
            basis.local(&anchor)?;
            Ok(anchor)
        };
        let mut state = GraphCallState {
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            progress: BTreeMap::new(),
        };
        let mut statement=reader.prepare(&format!("{selected} SELECT value_ref,anchor_record_id,anchor_fact FROM selected WHERE member_kind=2"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call subject members"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call subject members",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call subject members",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let key = subjects
                .get(&id)
                .cloned()
                .ok_or_else(|| GraphRows::invalid("graph call subject reference"))?;
            if state
                .subjects
                .insert(
                    key.clone(),
                    (
                        id,
                        SubjectChange {
                            anchor: anchor(row, 1, 2)?,
                            key,
                        },
                    ),
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph call subject key"));
            }
        }
        drop(rows);
        drop(statement);
        let mut statement=reader.prepare(&format!("{selected} SELECT e.edge_id,e.from_ref,e.to_ref,p.edge_type,p.package_id,p.cause,e.evidence_refs,p.proof_quality,p.required_coverage_interval_ids,e.first_boottime_ns,e.last_boottime_ns,m.anchor_record_id,m.anchor_fact,p.edge_rank,p.cause_rank FROM selected m LEFT JOIN graph_edge_values e ON e.edge_id=m.value_ref LEFT JOIN graph_edge_properties p USING(property_ref) WHERE m.member_kind=3"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call relationships"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call relationships",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call relationships",
        })? {
            control.check()?;
            let key = RelationshipIdentity {
                from: subjects
                    .get(&GraphRows::column::<u64>(row, 1)?)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph call source subject"))?,
                to: subjects
                    .get(&GraphRows::column::<u64>(row, 2)?)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph call target subject"))?,
                edge_type: GraphRows::parse(&GraphRows::column::<String>(row, 3)?)?,
                package_id: GraphRows::column(row, 4)?,
                cause: GraphRows::parse(&GraphRows::column::<String>(row, 5)?)?,
                evidence: GraphRows::read_ids(row, 6)?
                    .into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| GraphRows::invalid("graph call edge evidence"))
                    })
                    .collect::<Result<_>>()?,
            };
            if key.package_id != *package
                || key.evidence.is_empty()
                || key.edge_type as u8 != GraphRows::column::<u8>(row, 13)?
                || key.cause as u8 != GraphRows::column::<u8>(row, 14)?
                || key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(GraphRows::invalid("graph call edge identity"));
            }
            let value = RelationshipChange {
                anchor: anchor(row, 11, 12)?,
                key: key.clone(),
                proof_quality: GraphRows::read_proof(row, 7)?,
                required_coverage_interval_ids: GraphRows::read_bytes(row, 8)?,
                first_boottime_ns: GraphRows::column(row, 9)?,
                last_boottime_ns: GraphRows::column(row, 10)?,
            };
            if state
                .edges
                .insert(key, (GraphRows::column(row, 0)?, value))
                .is_some()
            {
                return Err(GraphRows::invalid("graph call edge key"));
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
        let mut statement=reader.prepare(&format!("{selected} SELECT {columns},m.anchor_record_id,m.anchor_fact,m.reason_code FROM selected m LEFT JOIN graph_finding_values f ON f.value_id=m.value_ref WHERE m.member_kind=4"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call findings"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call findings",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call findings",
        })? {
            control.check()?;
            let (subject, refs) = araphor_graph::FindingRows::references(row)?;
            let finding = araphor_graph::FindingRows::decode(
                row,
                subjects
                    .get(&subject)
                    .cloned()
                    .ok_or_else(|| GraphRows::invalid("graph call finding subject"))?,
                refs.into_iter()
                    .map(|id| {
                        evidence
                            .get(&id)
                            .cloned()
                            .ok_or_else(|| GraphRows::invalid("graph call finding evidence"))
                    })
                    .collect::<Result<_>>()?,
            )?;
            finding.validate()?;
            let reason = finding.reason.clone();
            let reason_code: String = GraphRows::column(row, 20)?;
            if finding.package_id != *package
                || reason
                    .analysis_code(package)
                    .context(AnalysisContractSnafu)?
                    != reason_code
            {
                return Err(GraphRows::invalid("graph call finding reason"));
            }
            let anchor = anchor(row, 18, 19)?;
            let (record, context) = basis.local(&anchor)?;
            let mut value = FindingChange::from_local(
                Finding::from_finding(record, context, finding, reason_code),
                anchor,
            );
            value.prior_reason = Some(reason);
            if state
                .findings
                .insert(
                    value.finding_id.clone(),
                    (GraphRows::column(row, 0)?, value),
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph call finding key"));
            }
        }
        drop(rows);
        drop(statement);
        let mut statement=reader.prepare(&format!("{selected} SELECT p.value_ref,p.evidence_id,p.digest,p.state FROM selected m LEFT JOIN graph_progress_values p ON p.value_ref=m.value_ref WHERE m.member_kind=5"))
            .context(AnalysisDatabaseSnafu {operation:"prepare Graph call progress"})?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call progress",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call progress",
        })? {
            control.check()?;
            let record = evidence
                .get(&GraphRows::column::<u64>(row, 1)?)
                .cloned()
                .ok_or_else(|| GraphRows::invalid("graph call progress evidence"))?;
            let digest: Vec<u8> = GraphRows::column(row, 2)?;
            if digest.len() != 32
                || state
                    .progress
                    .insert(
                        record.clone(),
                        Progress {
                            record,
                            digest: digest.into(),
                            state: GraphRows::column(row, 3)?,
                        },
                    )
                    .is_some()
            {
                return Err(GraphRows::invalid("graph call progress key"));
            }
        }
        let (counts,root):((u64,u64,u64,u64),Option<Vec<u8>>)=reader.query_row("SELECT subject_count,edge_count,finding_count,progress_count,derived_progress_digest FROM graph_producer_versions WHERE result_id=?",params![result_id],|row|Ok(((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?),row.get(4)?))).context(AnalysisDatabaseSnafu {operation:"read Graph call counts"})?;
        if counts
            != (
                state.subjects.len() as u64,
                state.edges.len() as u64,
                state.findings.len() as u64,
                state.progress.len() as u64,
            )
        {
            return Err(GraphRows::invalid("graph call row counts"));
        }
        let detector = Self::progress_detector(reader, spec, call, verified_native)?;
        state.progress = GraphRows::expand_progress(
            evaluation,
            state.progress.into_values().collect(),
            root.as_deref(),
            detector,
        )?;
        Ok(state)
    }

    fn validate_record_cut(
        reader: &Connection,
        spec: &ManagedSpec,
        result_id: &str,
        basis: &CallBasis,
    ) -> Result<()> {
        let crate::ManagedDestination::Graph { source, .. } = &spec.destination else {
            return Err(GraphRows::invalid("graph call destination"));
        };
        if basis.records.keys().any(|record| &record.stream != source) {
            return Err(GraphRows::invalid("graph call input source"));
        }
        let mut statement=reader.prepare("SELECT DISTINCT e.cpu_id,e.durable_cursor FROM evidence_refs r JOIN graph_sources s ON s.stream_key=r.stream_key AND s.tenant_id=r.tenant_id JOIN graph_evidence e USING(source_ref) JOIN source_receipts receipt ON receipt.stream_key=s.stream_key AND receipt.tenant_id=s.tenant_id WHERE r.ref_id=? AND s.stream_key=? AND s.tenant_id=? AND e.cpu_id=receipt.cpu_id AND e.durable_cursor=r.durable_cursor").context(AnalysisDatabaseSnafu {operation:"prepare Graph input witness cut"})?;
        let records = statement
            .query_map(
                params![result_id, source.key(), source.tenant_id.as_slice()],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u64>(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph input witness cut",
            })?
            .collect::<duckdb::Result<BTreeSet<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode Graph input witness cut",
            })?;
        if basis
            .records
            .keys()
            .any(|record| !records.contains(&(record.cpu_id, record.durable_cursor)))
        {
            return Err(GraphRows::invalid("graph call input cut"));
        }
        Ok(())
    }

    fn progress_detector(
        reader: &Connection,
        spec: &ManagedSpec,
        call: u64,
        verified_native: Option<bool>,
    ) -> Result<Option<Detector>> {
        let native = match verified_native {
            Some(native) => native,
            None => super::super::AnalysisStore::native_graph_call(
                reader,
                spec.tenant,
                &spec.manifest.calls[&call],
            )?,
        };
        if native {
            Detector::from_id(&spec.manifest.calls[&call].package.package_id)
                .map(Some)
                .context(AnalysisContractSnafu)
        } else {
            Ok(None)
        }
    }

    pub(in crate::analysis) fn validate(reader: &Connection, root: &std::path::Path) -> Result<()> {
        GraphRows::validate_history(reader, root)
    }
}
