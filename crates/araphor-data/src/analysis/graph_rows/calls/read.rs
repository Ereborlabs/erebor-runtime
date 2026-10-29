use araphor_analysis_builtins::graph::Finding;
use araphor_graph::FindingRows;
use duckdb::{params_from_iter, types::Value};
use serde::Deserialize;

use super::super::{relationships::StoredEdge, GraphRows};
use super::*;
use crate::{AnalysisReadControl, EvidenceIntakeIdentityV1, ManagedDestination};

struct AnchorRef {
    record: u64,
    fact: Option<Vec<u8>>,
}

impl AnchorRef {
    fn read(
        self,
        evidence: &BTreeMap<u64, DiscoveryRecordIdV1>,
        basis: &CallBasis,
    ) -> Result<Anchor> {
        let record = evidence
            .get(&self.record)
            .cloned()
            .ok_or_else(|| Code::Invalid.error("Graph call anchor record"))?;
        let fact = self
            .fact
            .map(|bytes| {
                let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(&bytes));
                let fact = FactAnchor::deserialize(&mut decoder)
                    .map_err(|_| Code::Invalid.error("Graph call anchor fact"))?;
                if decoder.position() != bytes.len() as u64 {
                    return Err(Code::Invalid.error("Graph call anchor fact"));
                }
                Ok(fact)
            })
            .transpose()?;
        let anchor = Anchor { record, fact };
        if !basis.contains(&anchor) {
            return Err(Code::Invalid.error("Graph call anchor input"));
        }
        Ok(anchor)
    }
}

impl GraphCallRows {
    pub(in crate::analysis) fn load(
        reader: &Connection,
        spec: &ManagedSpec,
        call: u64,
        result_id: &str,
        revision: u64,
        evaluation: &sdk::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<GraphCallState> {
        control.check()?;
        let ManagedDestination::Graph { source, .. } = &spec.destination else {
            return Err(Code::Invalid.error("Graph call destination"));
        };
        let pin = spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Invalid.error("Graph call pin"))?;
        let version: Option<(
            u64,
            u64,
            Vec<u8>,
            String,
            u64,
            String,
            String,
            String,
            u64,
            u64,
            u64,
            u64,
        )> = reader
            .query_row(
                "SELECT v.scope_id, v.commit_revision, s.tenant_id, s.instance_id,
                    s.call_id, s.package_id, s.package_revision, s.image_digest,
                    v.subject_count, v.edge_count, v.finding_count, v.progress_count
                 FROM graph_call_versions v JOIN graph_call_scopes s USING (scope_id)
                 WHERE v.result_id = ?",
                params![result_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call version",
            })?;
        let version = version.ok_or_else(|| Code::Missing.error("Graph call native version"))?;
        if version.1 != revision
            || version.2.as_slice() != spec.tenant
            || version.3 != spec.id
            || version.4 != call
            || version.5 != pin.package.package_id
            || version.6 != pin.package.revision
            || version.7 != pin.image.digest
            || source.tenant_id != spec.tenant
        {
            return Err(Code::Invalid.error("Graph call version pin"));
        }
        let scope = version.0;
        let basis = CallBasis::new(evaluation)?;
        if basis
            .positions
            .keys()
            .any(|record| record.stream != *source)
        {
            return Err(Code::Invalid.error("Graph call input source"));
        }
        let mut evidence_ids = BTreeSet::new();
        let mut subject_rows = Vec::new();
        let mut subject_by_id = BTreeMap::new();
        let mut statement = reader
            .prepare(
                "SELECT v.subject_id, v.tenant_id, v.authority_rank, v.authority_text,
                v.authority_boot, v.authority_epoch, v.subject_kind, v.identity,
                m.anchor_record_id, m.anchor_fact
             FROM graph_call_subjects m JOIN graph_subject_values v USING (subject_id)
             WHERE m.scope_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)
             ORDER BY v.subject_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph call subjects",
            })?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call subjects",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let subject = GraphRows::decode_subject(row)?;
            let anchor = AnchorRef {
                record: GraphRows::column(row, 8)?,
                fact: GraphRows::column(row, 9)?,
            };
            evidence_ids.insert(anchor.record);
            if subject.tenant_id != spec.tenant
                || subject_by_id.insert(id, subject.clone()).is_some()
            {
                return Err(Code::Invalid.error("Graph call subject identity"));
            }
            subject_rows.push((id, subject, anchor));
        }
        drop(rows);
        drop(statement);

        let mut edge_rows = Vec::new();
        let mut statement = reader
            .prepare(
                "SELECT v.edge_id, v.from_ref, v.to_ref, v.edge_type, v.package_id, v.cause,
                v.evidence_refs, v.proof_quality.source_authority,
                v.proof_quality.local_subject_binding, v.proof_quality.remote_subject_binding,
                v.proof_quality.operation_result_authority, v.proof_quality.temporal_coverage,
                v.proof_quality.integrity, v.required_coverage_interval_ids,
                v.first_boottime_ns, v.edge_type_rank, v.cause_rank, v.last_boottime_ns,
                m.anchor_record_id, m.anchor_fact
             FROM graph_call_edges m JOIN graph_edge_values v USING (edge_id)
             WHERE m.scope_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)
             ORDER BY v.edge_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph call edges",
            })?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call edges",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call edges",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let edge = StoredEdge::from_row(row)?;
            let anchor = AnchorRef {
                record: GraphRows::column(row, 18)?,
                fact: GraphRows::column(row, 19)?,
            };
            evidence_ids.insert(anchor.record);
            evidence_ids.extend(edge.evidence.iter().copied());
            edge_rows.push((id, edge, anchor));
        }
        drop(rows);
        drop(statement);

        let finding_refs = "FROM graph_call_findings m
             JOIN graph_finding_values f USING (value_id)
             WHERE m.scope_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)
             ORDER BY f.value_id";
        let mut finding_rows = BTreeMap::new();
        let mut statement = reader
            .prepare(&format!(
                "SELECT f.value_id, f.subject_ref, f.evidence_refs,
                m.anchor_record_id, m.anchor_fact, m.reason_code {finding_refs}"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph call findings",
            })?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call findings",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call findings",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let subject: u64 = GraphRows::column(row, 1)?;
            let evidence = FindingRows::evidence_references(row, 2)?;
            let anchor = AnchorRef {
                record: GraphRows::column(row, 3)?,
                fact: GraphRows::column(row, 4)?,
            };
            let reason: String = GraphRows::column(row, 5)?;
            evidence_ids.insert(anchor.record);
            evidence_ids.extend(evidence.iter().copied());
            if finding_rows
                .insert(id, (subject, evidence, anchor, reason))
                .is_some()
            {
                return Err(Code::Invalid.error("Graph call finding identity"));
            }
        }
        drop(rows);
        drop(statement);

        let mut progress_rows = Vec::new();
        let mut statement = reader
            .prepare(
                "SELECT evidence_id, digest, state FROM graph_call_progress
             WHERE scope_id = ? AND valid_from <= ?
                 AND (valid_to IS NULL OR valid_to > ?)
             ORDER BY evidence_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph call progress",
            })?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call progress",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call progress",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let digest: Vec<u8> = GraphRows::column(row, 1)?;
            let state: Option<String> = GraphRows::column(row, 2)?;
            if digest.len() != 32 {
                return Err(Code::Invalid.error("Graph call progress digest"));
            }
            evidence_ids.insert(id);
            progress_rows.push((id, digest, state));
        }
        drop(rows);
        drop(statement);
        let evidence = Self::evidence(reader, source, &evidence_ids, control)?;
        let mut state = GraphCallState {
            scope,
            revision,
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            progress: BTreeMap::new(),
        };
        for (id, key, anchor) in subject_rows {
            let change = SubjectChange {
                anchor: anchor.read(&evidence, &basis)?,
                key: key.clone(),
            };
            if state.subjects.insert(key, (id, change)).is_some() {
                return Err(Code::Invalid.error("Graph call subject key"));
            }
        }
        for (id, edge, anchor) in edge_rows {
            let change =
                edge.into_change(anchor.read(&evidence, &basis)?, &subject_by_id, &evidence)?;
            if change.key.package_id != pin.package.package_id
                || change
                    .key
                    .evidence
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || change
                    .key
                    .evidence
                    .iter()
                    .any(|record| !basis.positions.contains_key(record))
                || state
                    .edges
                    .insert(change.key.clone(), (id, change))
                    .is_some()
            {
                return Err(Code::Invalid.error("Graph call edge key"));
            }
        }
        let columns = FindingRows::COLUMNS
            .split(',')
            .enumerate()
            .map(|(index, column)| {
                if index == 0 {
                    "f.value_id".into()
                } else {
                    format!("f.{}", column.trim())
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = reader
            .prepare(&format!("SELECT {columns} {finding_refs}"))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph call finding values",
            })?;
        let mut rows = statement
            .query(params![scope, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read Graph call finding values",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph call finding values",
        })? {
            control.check()?;
            let id: u64 = GraphRows::column(row, 0)?;
            let (subject_id, evidence_ids, anchor, reason_code) = finding_rows
                .remove(&id)
                .ok_or_else(|| Code::Invalid.error("Graph call finding value"))?;
            if FindingRows::references(row)? != (subject_id, evidence_ids.clone()) {
                return Err(Code::Invalid.error("Graph call finding reference"));
            }
            let subject = subject_by_id
                .get(&subject_id)
                .cloned()
                .ok_or_else(|| Code::Invalid.error("Graph call finding subject"))?;
            let records = evidence_ids
                .iter()
                .map(|id| {
                    evidence
                        .get(id)
                        .cloned()
                        .ok_or_else(|| Code::Invalid.error("Graph call finding evidence"))
                })
                .collect::<Result<Vec<_>>>()?;
            let value = FindingRows::decode(row, subject, records)?;
            if value.tenant_id != spec.tenant
                || value.package_id != pin.package.package_id
                || value
                    .reason
                    .analysis_code(&value.package_id)
                    .context(AnalysisContractSnafu)?
                    != reason_code
                || value
                    .evidence
                    .iter()
                    .any(|id| !basis.positions.contains_key(id))
            {
                return Err(Code::Invalid.error("Graph call finding value"));
            }
            let anchor = anchor.read(&evidence, &basis)?;
            let prior_reason = value.reason.clone();
            let mut change = FindingChange::from_local(
                Finding::from_finding(0, None, value, reason_code),
                anchor,
            );
            change.prior_reason = Some(prior_reason);
            if state
                .findings
                .insert(change.finding_id.clone(), (id, change))
                .is_some()
            {
                return Err(Code::Invalid.error("Graph call finding key"));
            }
        }
        if !finding_rows.is_empty() {
            return Err(Code::Invalid.error("Graph call finding count"));
        }
        for (id, digest, marker) in progress_rows {
            let record = evidence
                .get(&id)
                .cloned()
                .ok_or_else(|| Code::Invalid.error("Graph call progress record"))?;
            if !basis.positions.contains_key(&record) {
                return Err(Code::Invalid.error("Graph call progress input"));
            }
            let progress = Progress {
                record: record.clone(),
                digest: digest.into(),
                state: marker,
            };
            if state.progress.insert(record, (id, progress)).is_some() {
                return Err(Code::Invalid.error("Graph call progress key"));
            }
        }
        if (
            state.subjects.len() as u64,
            state.edges.len() as u64,
            state.findings.len() as u64,
            state.progress.len() as u64,
        ) != (version.8, version.9, version.10, version.11)
        {
            return Err(Code::Invalid.error("Graph call membership counts"));
        }
        control.check()?;
        Ok(state)
    }

    fn evidence(
        reader: &Connection,
        source: &EvidenceIntakeIdentityV1,
        selected: &BTreeSet<u64>,
        control: &AnalysisReadControl,
    ) -> Result<BTreeMap<u64, DiscoveryRecordIdV1>> {
        let mut known = BTreeMap::new();
        let expected_key = source.key();
        for chunk in selected
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
        {
            control.check()?;
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut statement = reader
                .prepare(&format!(
                    "SELECT evidence_id, stream_key, cpu_id, durable_cursor FROM graph_evidence
                 WHERE evidence_id IN ({placeholders})"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph call evidence",
                })?;
            let mut rows = statement
                .query(params_from_iter(chunk.iter().map(|id| Value::UBigInt(*id))))
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph call evidence",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance Graph call evidence",
            })? {
                control.check()?;
                let id: u64 = GraphRows::column(row, 0)?;
                let key: Vec<u8> = GraphRows::column(row, 1)?;
                if key != expected_key {
                    return Err(Code::Invalid.error("Graph call evidence source"));
                }
                let record = DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: GraphRows::column(row, 2)?,
                    durable_cursor: GraphRows::column(row, 3)?,
                };
                if known.insert(id, record).is_some() {
                    return Err(Code::Invalid.error("Graph call evidence identity"));
                }
            }
        }
        if known.len() != selected.len() {
            return Err(Code::Missing.error("Graph call evidence"));
        }
        Ok(known)
    }
}
