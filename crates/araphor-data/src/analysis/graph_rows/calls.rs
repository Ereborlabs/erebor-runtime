use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::{
    discovery::DiscoveryRecordIdV1,
    graph::{
        Anchor, Fact, FactAnchor, FindingChange, FindingReasonV1, FindingRemoval, Observation,
        Progress, ProgressRemoval, RelationshipChange, RelationshipIdentity, RelationshipRemoval,
        SubjectChange, SubjectRemoval,
    },
};
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::PackageResultRefV1;
use super::GraphValueIds;
use crate::{
    AnalysisContextKeyV1, AnalysisContractSnafu, AnalysisDatabaseSnafu, GraphSnapshotV1,
    GraphSubjectKeyV1, ManagedSpec, PackageErrorCodeV1 as Code, Result,
};

mod read;
mod validate;

#[derive(Clone, Debug)]
pub(in crate::analysis) struct GraphCallState {
    pub scope: u64,
    pub revision: u64,
    pub subjects: BTreeMap<GraphSubjectKeyV1, (u64, SubjectChange)>,
    pub edges: BTreeMap<RelationshipIdentity, (u64, RelationshipChange)>,
    pub findings: BTreeMap<String, (u64, FindingChange)>,
    pub progress: BTreeMap<DiscoveryRecordIdV1, (u64, Progress)>,
}

impl GraphCallState {
    pub fn allocated_bytes(&self) -> usize {
        fn rows<K: Ord, V>(
            values: &BTreeMap<K, (u64, V)>,
            key_bytes: impl Fn(&K) -> usize,
            value_bytes: impl Fn(&V) -> usize,
        ) -> usize {
            // Charge one map header per entry for tree allocation overhead.
            let entry = std::mem::size_of::<(K, (u64, V))>()
                .saturating_add(std::mem::size_of::<BTreeMap<K, (u64, V)>>());
            values.iter().fold(0usize, |bytes, (key, (_, value))| {
                bytes
                    .saturating_add(entry)
                    .saturating_add(key_bytes(key))
                    .saturating_add(value_bytes(value))
            })
        }
        std::mem::size_of::<Self>()
            .saturating_add(rows(
                &self.subjects,
                |key| key.allocated_bytes(),
                |value| value.allocated_bytes(),
            ))
            .saturating_add(rows(
                &self.edges,
                |key| key.allocated_bytes(),
                |value| value.allocated_bytes(),
            ))
            .saturating_add(rows(&self.findings, String::capacity, |value| {
                value.allocated_bytes()
            }))
            .saturating_add(rows(
                &self.progress,
                |key| key.allocated_bytes(),
                |value| value.allocated_bytes(),
            ))
    }

    pub fn outputs(&self) -> Result<Vec<sdk::Dataset>> {
        Ok(vec![
            SubjectChange::encode(
                &self
                    .subjects
                    .values()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            SubjectRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            RelationshipChange::encode(
                &self
                    .edges
                    .values()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            RelationshipRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            FindingChange::encode(
                &self
                    .findings
                    .values()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            FindingRemoval::encode(&[]).context(AnalysisContractSnafu)?,
            Progress::encode(
                &self
                    .progress
                    .values()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            ProgressRemoval::encode(&[]).context(AnalysisContractSnafu)?,
        ])
    }
}

struct CallBasis {
    positions: BTreeMap<DiscoveryRecordIdV1, u32>,
    facts: BTreeMap<AnalysisContextKeyV1, (u32, FactAnchor)>,
}

impl CallBasis {
    fn new(evaluation: &sdk::Evaluation) -> Result<Self> {
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
        let mut positions = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| Code::Limit.error("Graph call record count"))?;
            if positions.insert(record.id.clone(), index).is_some() {
                return Err(Code::Invalid.error("Graph call record identity"));
            }
        }
        let facts = facts
            .into_iter()
            .enumerate()
            .map(|(index, fact)| {
                let record = records
                    .get(fact.record as usize)
                    .ok_or_else(|| Code::Invalid.error("Graph call fact record"))?;
                let anchor = FactAnchor {
                    record: record.id.clone(),
                    key: fact.key.clone(),
                    sensitivity: fact.sensitivity,
                    value: fact.value,
                };
                let index =
                    u32::try_from(index).map_err(|_| Code::Limit.error("Graph call fact count"))?;
                Ok((fact.key, (index, anchor)))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut indexed = BTreeMap::new();
        for (key, value) in facts {
            if indexed.insert(key, value).is_some() {
                return Err(Code::Invalid.error("Graph call fact identity"));
            }
        }
        Ok(Self {
            positions,
            facts: indexed,
        })
    }

    fn contains(&self, anchor: &Anchor) -> bool {
        self.positions.contains_key(&anchor.record)
            && anchor.fact.as_ref().is_none_or(|fact| {
                self.positions.contains_key(&fact.record)
                    && self
                        .facts
                        .get(&fact.key)
                        .is_some_and(|(_, value)| value == fact)
            })
    }

    fn local(&self, anchor: &Anchor) -> Result<(u32, Option<u32>)> {
        if !self.contains(anchor) {
            return Err(Code::Invalid.error("Graph call anchor input"));
        }
        let record = *self
            .positions
            .get(&anchor.record)
            .ok_or_else(|| Code::Invalid.error("Graph call anchor record"))?;
        let context = anchor
            .fact
            .as_ref()
            .map(|fact| {
                self.facts
                    .get(&fact.key)
                    .map(|(index, _)| *index)
                    .ok_or_else(|| Code::Invalid.error("Graph call anchor fact"))
            })
            .transpose()?;
        Ok((record, context))
    }
}

pub(in crate::analysis) struct GraphCallRows;

impl GraphCallRows {
    pub(in crate::analysis) fn apply_delta(
        writer: &Connection,
        scope: u64,
        revision: u64,
        graph: &GraphSnapshotV1,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        ids: &GraphValueIds,
        prior: Option<&GraphCallState>,
    ) -> Result<()> {
        if prior.is_some_and(|prior| prior.scope != scope || prior.revision >= revision) {
            return Err(Code::Invalid.error("Graph call prior scope"));
        }
        let basis = CallBasis::new(evaluation)?;
        let mut subject_count = prior.map_or(0, |prior| prior.subjects.len() as u64);
        let mut edge_count = prior.map_or(0, |prior| prior.edges.len() as u64);
        let mut finding_count = prior.map_or(0, |prior| prior.findings.len() as u64);
        let mut progress_count = prior.map_or(0, |prior| prior.progress.len() as u64);
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| Code::Invalid.error("Graph call output dataset"))
        };
        let mut removed = BTreeSet::new();
        for row in
            SubjectRemoval::decode(dataset("subject_removals")?).context(AnalysisContractSnafu)?
        {
            let old = prior.and_then(|prior| prior.subjects.get(&row.key));
            if !removed.insert(row.key.clone()) || old.is_none() {
                return Err(Code::Invalid.error("Graph call subject removal"));
            }
            Self::close(
                writer,
                "graph_call_subjects",
                "subject_id",
                scope,
                old.unwrap().0,
                revision,
            )?;
            subject_count -= 1;
        }
        let mut insert_subject =
            writer
                .appender("graph_call_subjects")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph call subject",
                })?;
        for row in SubjectChange::decode(dataset("subjects")?).context(AnalysisContractSnafu)? {
            if prior.is_some_and(|prior| prior.subjects.contains_key(&row.key))
                && !removed.contains(&row.key)
            {
                return Err(Code::Invalid.error("Graph call subject addition"));
            }
            if !graph.graph.subjects.contains(&row.key) {
                return Err(Code::Invalid.error("Graph call subject value"));
            }
            let id = *ids
                .subjects
                .get(&row.key)
                .ok_or_else(|| Code::Invalid.error("Graph call subject value"))?;
            let (record, fact) = Self::anchor(&row.anchor, &basis, graph, ids)?;
            insert_subject
                .append_row(params![scope, id, record, fact, revision, None::<u64>])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert Graph call subject",
                })?;
            subject_count = subject_count
                .checked_add(1)
                .ok_or_else(|| Code::Limit.error("Graph call subject count"))?;
        }
        insert_subject.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph call subjects",
        })?;
        drop(insert_subject);
        let additions =
            RelationshipChange::decode(dataset("relationships")?).context(AnalysisContractSnafu)?;
        let mut edges = BTreeMap::new();
        if !additions.is_empty() {
            for edge in &graph.graph.edges {
                let key = RelationshipIdentity::from_keys(
                    &edge.key,
                    &graph.graph.subjects,
                    &graph.input_manifest.evidence,
                )
                .context(AnalysisContractSnafu)?;
                if edges.insert(key, edge).is_some() {
                    return Err(Code::Invalid.error("Graph call edge identity"));
                }
            }
        }
        let mut removed = BTreeSet::new();
        for row in RelationshipRemoval::decode(dataset("relationship_removals")?)
            .context(AnalysisContractSnafu)?
        {
            let old = prior.and_then(|prior| prior.edges.get(&row.key));
            if !removed.insert(row.key.clone()) || old.is_none() {
                return Err(Code::Invalid.error("Graph call edge removal"));
            }
            Self::close(
                writer,
                "graph_call_edges",
                "edge_id",
                scope,
                old.unwrap().0,
                revision,
            )?;
            edge_count -= 1;
        }
        let mut insert_edge =
            writer
                .appender("graph_call_edges")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph call edge",
                })?;
        for row in additions {
            if prior.is_some_and(|prior| prior.edges.contains_key(&row.key))
                && !removed.contains(&row.key)
            {
                return Err(Code::Invalid.error("Graph call edge addition"));
            }
            let edge = edges
                .get(&row.key)
                .ok_or_else(|| Code::Invalid.error("Graph call edge value"))?;
            if edge.proof_quality != row.proof_quality
                || edge.required_coverage_interval_ids != row.required_coverage_interval_ids
                || edge.first_boottime_ns != row.first_boottime_ns
                || edge.last_boottime_ns != row.last_boottime_ns
                || row
                    .key
                    .evidence
                    .iter()
                    .any(|record| !basis.positions.contains_key(record))
            {
                return Err(Code::Invalid.error("Graph call edge value"));
            }
            let id = *ids
                .edges
                .get(&row.key)
                .ok_or_else(|| Code::Invalid.error("Graph call edge value"))?;
            let (record, fact) = Self::anchor(&row.anchor, &basis, graph, ids)?;
            insert_edge
                .append_row(params![scope, id, record, fact, revision, None::<u64>])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert Graph call edge",
                })?;
            edge_count = edge_count
                .checked_add(1)
                .ok_or_else(|| Code::Limit.error("Graph call edge count"))?;
        }
        insert_edge.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph call edges",
        })?;
        drop(insert_edge);
        let additions =
            FindingChange::decode(dataset("findings")?).context(AnalysisContractSnafu)?;
        let findings = if additions.is_empty() {
            BTreeMap::new()
        } else {
            graph
                .findings
                .iter()
                .map(|row| (&row.finding_id, row))
                .collect::<BTreeMap<_, _>>()
        };
        let mut removed = BTreeSet::new();
        for row in
            FindingRemoval::decode(dataset("finding_removals")?).context(AnalysisContractSnafu)?
        {
            let old = prior.and_then(|prior| prior.findings.get(&row.finding_id));
            if !removed.insert(row.finding_id.clone()) || old.is_none() {
                return Err(Code::Invalid.error("Graph call finding removal"));
            }
            Self::close(
                writer,
                "graph_call_findings",
                "value_id",
                scope,
                old.unwrap().0,
                revision,
            )?;
            finding_count -= 1;
        }
        let mut reasons = BTreeMap::new();
        for reason in &output.reasons {
            if reason.output.dataset != "findings"
                || reasons.insert(reason.output.row, reason).is_some()
            {
                return Err(Code::Invalid.error("Graph call finding reason"));
            }
        }
        if reasons.len() != additions.len() {
            return Err(Code::Invalid.error("Graph call finding reason"));
        }
        let indices = basis.positions.iter().map(|(id, row)| (id, *row)).collect();
        let mut insert_finding =
            writer
                .appender("graph_call_findings")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph call finding",
                })?;
        for (index, row) in additions.into_iter().enumerate() {
            if row.prior_reason.is_some()
                || (prior.is_some_and(|prior| prior.findings.contains_key(&row.finding_id))
                    && !removed.contains(&row.finding_id))
            {
                return Err(Code::Invalid.error("Graph call finding addition"));
            }
            let value = findings
                .get(&row.finding_id)
                .ok_or_else(|| Code::Invalid.error("Graph call finding value"))?;
            let reason = reasons
                .get(&(index as u64))
                .ok_or_else(|| Code::Invalid.error("Graph call finding reason"))?;
            let (local_record, local_context) = basis.local(&row.anchor)?;
            let resolved = FindingReasonV1::from_output(
                &row.package_id,
                &row.local(local_record, local_context),
                &indices,
                reason,
            )
            .context(AnalysisContractSnafu)?;
            if row.reason_code
                != value
                    .reason
                    .analysis_code(&value.package_id)
                    .context(AnalysisContractSnafu)?
                || resolved != value.reason
                || row.clone().into_finding(value.reason.clone()) != **value
                || row
                    .evidence
                    .iter()
                    .any(|record| !basis.positions.contains_key(record))
                || row
                    .effects
                    .iter()
                    .any(|effect| !basis.positions.contains_key(&effect.evidence))
                || row
                    .policy_provenance
                    .iter()
                    .flat_map(|policy| &policy.observations)
                    .any(|record| !basis.positions.contains_key(record))
            {
                return Err(Code::Invalid.error("Graph call finding value"));
            }
            let id = *ids
                .findings
                .get(&row.finding_id)
                .ok_or_else(|| Code::Invalid.error("Graph call finding value"))?;
            let (record, fact) = Self::anchor(&row.anchor, &basis, graph, ids)?;
            insert_finding
                .append_row(params![
                    scope,
                    id,
                    record,
                    fact,
                    row.reason_code,
                    revision,
                    None::<u64>
                ])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert Graph call finding",
                })?;
            finding_count = finding_count
                .checked_add(1)
                .ok_or_else(|| Code::Limit.error("Graph call finding count"))?;
        }
        insert_finding.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph call findings",
        })?;
        drop(insert_finding);
        let mut removed = BTreeSet::new();
        for row in
            ProgressRemoval::decode(dataset("progress_removals")?).context(AnalysisContractSnafu)?
        {
            let old = prior.and_then(|prior| prior.progress.get(&row.record));
            if !removed.insert(row.record.clone()) || old.is_none() {
                return Err(Code::Invalid.error("Graph call progress removal"));
            }
            Self::close(
                writer,
                "graph_call_progress",
                "evidence_id",
                scope,
                old.unwrap().0,
                revision,
            )?;
            progress_count -= 1;
        }
        let mut insert_progress =
            writer
                .appender("graph_call_progress")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph call progress",
                })?;
        for row in Progress::decode(dataset("progress")?).context(AnalysisContractSnafu)? {
            if row.digest.len() != 32
                || !basis.positions.contains_key(&row.record)
                || (prior.is_some_and(|prior| prior.progress.contains_key(&row.record))
                    && !removed.contains(&row.record))
            {
                return Err(Code::Invalid.error("Graph call progress addition"));
            }
            let id = Self::record_id(&row.record, graph, ids)?;
            insert_progress
                .append_row(params![
                    scope,
                    id,
                    row.digest.as_ref(),
                    row.state,
                    revision,
                    None::<u64>
                ])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert Graph call progress",
                })?;
            progress_count = progress_count
                .checked_add(1)
                .ok_or_else(|| Code::Limit.error("Graph call progress count"))?;
        }
        insert_progress.flush().context(AnalysisDatabaseSnafu {
            operation: "flush Graph call progress",
        })?;
        drop(insert_progress);
        let changed = writer.execute(
            "UPDATE graph_call_versions SET subject_count = ?, edge_count = ?, finding_count = ?,
                progress_count = ? WHERE scope_id = ? AND commit_revision = ?",
            params![subject_count, edge_count, finding_count, progress_count, scope, revision],
        ).context(AnalysisDatabaseSnafu { operation: "record Graph call row counts" })?;
        if changed != 1 {
            return Err(Code::Invalid.error("Graph call result version"));
        }
        Ok(())
    }

    fn record_id(
        record: &DiscoveryRecordIdV1,
        graph: &GraphSnapshotV1,
        ids: &GraphValueIds,
    ) -> Result<u64> {
        if record.stream != graph.scope.identity {
            return Err(Code::Invalid.error("Graph call source"));
        }
        ids.evidence
            .get(&(record.cpu_id, record.durable_cursor))
            .copied()
            .ok_or_else(|| Code::Invalid.error("Graph call evidence reference"))
    }

    fn anchor(
        anchor: &Anchor,
        basis: &CallBasis,
        graph: &GraphSnapshotV1,
        ids: &GraphValueIds,
    ) -> Result<(u64, Option<Vec<u8>>)> {
        if !basis.contains(anchor) {
            return Err(Code::Invalid.error("Graph call anchor input"));
        }
        let record = Self::record_id(&anchor.record, graph, ids)?;
        let fact = anchor
            .fact
            .as_ref()
            .map(|fact| {
                rmp_serde::to_vec(fact)
                    .map_err(|_| Code::Invalid.error("Graph call anchor fact encoding"))
            })
            .transpose()?;
        Ok((record, fact))
    }

    fn close(
        writer: &Connection,
        table: &'static str,
        key: &'static str,
        scope: u64,
        id: u64,
        revision: u64,
    ) -> Result<()> {
        let mut statement = writer.prepare_cached(
            &format!("UPDATE {table} SET valid_to = ? WHERE scope_id = ? AND {key} = ? AND valid_to IS NULL"),
        ).context(AnalysisDatabaseSnafu { operation: "prepare Graph call close" })?;
        let changed =
            statement
                .execute(params![revision, scope, id])
                .context(AnalysisDatabaseSnafu {
                    operation: "close Graph call row",
                })?;
        if changed != 1 {
            return Err(Code::Invalid.error("Graph call row membership"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn bind(
        writer: &Connection,
        spec: &ManagedSpec,
        call: u64,
        result: &PackageResultRefV1,
        base: Option<&PackageResultRefV1>,
        rebuild: bool,
    ) -> Result<u64> {
        let pin = spec
            .manifest
            .calls
            .get(&call)
            .ok_or_else(|| Code::Invalid.error("Graph call pin"))?;
        let continued = if let Some(base) = base.filter(|_| !rebuild) {
            let saved: Option<(u64, u64, Vec<u8>, String, u64, String, String, String)> = writer
                .query_row(
                    "SELECT v.scope_id, v.commit_revision, s.tenant_id, s.instance_id,
                        s.call_id, s.package_id, s.package_revision, s.image_digest
                     FROM graph_call_versions v JOIN graph_call_scopes s USING (scope_id)
                     WHERE v.result_id = ?",
                    params![base.result_id],
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
                        ))
                    },
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read Graph call scope",
                })?;
            let saved = saved.ok_or_else(|| Code::Missing.error("Graph call scope"))?;
            if saved.1 != base.commit_revision
                || saved.2.as_slice() != spec.tenant
                || saved.3 != spec.id
                || saved.4 != call
                || saved.5 != pin.package.package_id
                || saved.6 != pin.package.revision
                || saved.7 != pin.image.digest
            {
                return Err(Code::Conflict.error("Graph call scope"));
            }
            Some(saved.0)
        } else {
            None
        };
        let scope = if let Some(scope) = continued {
            scope
        } else {
            let next: u64 = writer
                .query_row(
                    "SELECT coalesce(max(scope_id), 0) FROM graph_call_scopes",
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read next Graph call scope",
                })?;
            let scope = next
                .checked_add(1)
                .ok_or_else(|| Code::Limit.error("Graph call scope ID"))?;
            writer
                .execute(
                    "INSERT INTO graph_call_scopes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        scope,
                        spec.tenant.as_slice(),
                        spec.id,
                        call,
                        pin.package.package_id,
                        pin.package.revision,
                        pin.image.digest,
                        result.commit_revision,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert Graph call scope",
                })?;
            scope
        };
        writer
            .execute(
                "INSERT INTO graph_call_versions VALUES (?, ?, ?, ?, 0, 0, 0, 0)",
                params![
                    result.result_id,
                    scope,
                    result.commit_revision,
                    base.map(|base| base.result_id.as_str()),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert Graph call result scope",
            })?;
        Ok(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_state_charges_owned_keys_and_progress() {
        let mut node_id = String::with_capacity(128);
        node_id.push_str("node-a");
        let record = DiscoveryRecordIdV1 {
            stream: crate::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id,
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            cpu_id: 1,
            durable_cursor: 4,
        };
        let mut marker = String::with_capacity(64);
        marker.push_str("NATIVE_EFFECT");
        let progress = Progress {
            record: record.clone(),
            digest: vec![0; 32].into(),
            state: Some(marker),
        };
        let mut state = GraphCallState {
            scope: 1,
            revision: 2,
            subjects: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            progress: BTreeMap::new(),
        };
        let empty = state.allocated_bytes();
        let key_bytes = record.allocated_bytes();
        let value_bytes = progress.allocated_bytes();
        state.progress.insert(record, (7, progress));
        assert!(
            state.allocated_bytes()
                >= empty
                    + std::mem::size_of::<(DiscoveryRecordIdV1, (u64, Progress))>()
                    + key_bytes
                    + value_bytes
        );
        assert!(key_bytes >= 128);
        assert!(value_bytes >= 32 + 64);
    }
}
