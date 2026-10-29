use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Progress {
    pub(super) digest: ByteBuf,
    pub(super) state: Option<String>,
}

impl Progress {
    pub(super) fn new(record: &Observation, window: u64) -> sdk::Result<Self> {
        let mut digest = Sha256::new();
        (record, window)
            .serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| Computation::invalid("graph progress identity"))?;
        Ok(Self {
            digest: digest.finalize().to_vec().into(),
            state: None,
        })
    }

    fn compatible(&self, detector: Detector) -> bool {
        self.digest.len() == 32
            && matches!(
                (detector, self.state.as_deref()),
                (_, None)
                    | (Detector::Process, Some("NATIVE_EFFECT" | "CONTRADICTED"))
                    | (
                        Detector::Credentials,
                        Some(
                            "DIRECT_PIVOT"
                                | "CONTEXTUAL_PIVOT"
                                | "CONTRADICTED"
                                | "COVERAGE_INSUFFICIENT",
                        ),
                    )
            )
    }
}

impl Computation {
    pub(super) fn update(&mut self, evaluation: &sdk::Evaluation) -> sdk::Result<()> {
        let affected = self
            .resume(evaluation)?
            .unwrap_or_else(|| vec![true; self.records.len()]);
        match self.detector {
            Detector::Process => self.process(&affected),
            Detector::Credentials => self.credentials(&affected),
            Detector::Kubernetes => self.kubernetes(&affected),
        }
    }

    fn resume(&mut self, evaluation: &sdk::Evaluation) -> sdk::Result<Option<Vec<bool>>> {
        let Some(checkpoint) = &evaluation.checkpoint else {
            return Ok(None);
        };
        if evaluation.previous_outputs.is_empty() {
            return Ok(None);
        }
        let Some(progress) = checkpoint
            .datasets
            .iter()
            .find(|data| data.name == "progress")
        else {
            return Ok(None);
        };
        let progress = Progress::decode(progress)?;
        let dataset = |name: &str| {
            evaluation
                .previous_outputs
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| Self::invalid("graph previous output"))
        };
        let mut metadata = Metadata::decode(dataset("metadata")?)?;
        if metadata.len() != 1 {
            return Ok(None);
        }
        let metadata = metadata.remove(0);
        if metadata.record_ids.is_empty()
            || metadata.package.package_id != self.detector.id()
            || progress.len() != metadata.record_ids.len()
        {
            return Ok(None);
        }
        let subjects = Subject::decode(dataset("subjects")?)?;
        let edges = Relationship::decode(dataset("relationships")?)?;
        let findings = Finding::decode(dataset("findings")?)?;

        let restored = (|| {
            let current: BTreeMap<_, _> = self
                .records
                .iter()
                .enumerate()
                .map(|(row, record)| (&record.id, row as u32))
                .collect();
            let records = metadata
                .record_ids
                .iter()
                .map(|id| current.get(id).copied())
                .collect::<Vec<_>>();
            let mut last = None;
            for row in records.iter().copied().flatten() {
                if last.is_some_and(|prior| prior >= row) {
                    return None;
                }
                last = Some(row);
            }
            for (old, row) in progress.iter().zip(&records) {
                if !old.compatible(self.detector)
                    || row.is_some_and(|row| old.digest != self.progress[row as usize].digest)
                {
                    return None;
                }
            }
            let mut prior_facts = vec![Vec::new(); records.len()];
            for (index, fact) in metadata.facts.iter().enumerate() {
                prior_facts.get_mut(fact.record as usize)?.push(index);
            }
            let mut facts = vec![None; metadata.facts.len()];
            for (old, row) in records.iter().copied().enumerate() {
                let Some(row) = row else { continue };
                let prior = &prior_facts[old];
                let selected = &self.fact_rows[row as usize];
                if prior.len() != selected.len() {
                    return None;
                }
                for (&before, &after) in prior.iter().zip(selected) {
                    let prior = &metadata.facts[before];
                    let current = &self.facts[after];
                    if prior.key != current.key
                        || prior.sensitivity != current.sensitivity
                        || prior.value != current.value
                    {
                        return None;
                    }
                    facts[before] = Some(after as u32);
                }
            }

            let record = |row: u32| records.get(row as usize).copied().flatten();
            let context = |index: Option<u32>| match index {
                Some(index) => facts.get(index as usize).copied().flatten().map(Some),
                None => Some(None),
            };
            let mut affected = vec![true; self.records.len()];
            for row in records.iter().copied().flatten() {
                affected[row as usize] = false;
            }
            if matches!(self.detector, Detector::Credentials) {
                let triggers = self
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(row, value)| {
                        affected[*row]
                            && (value.network()
                                || self.facts(*row as u32).any(|(_, fact)| {
                                    matches!(
                                        fact.value,
                                        FactValue::AuthorityUse { .. } | FactValue::Channel { .. }
                                    )
                                }))
                    })
                    .map(|(_, value)| value)
                    .collect::<Vec<_>>();
                for row in records.iter().copied().flatten() {
                    if self
                        .facts(row)
                        .any(|(_, fact)| matches!(fact.value, FactValue::Credential { .. }))
                        && triggers
                            .iter()
                            .any(|later| self.bounded(&self.records[row as usize], later))
                    {
                        affected[row as usize] = true;
                    }
                }
            }

            if records.iter().any(Option::is_none) {
                for edge in &edges {
                    let stale = record(edge.record).is_none()
                        || context(edge.fact).is_none()
                        || edge
                            .edge
                            .key
                            .evidence
                            .iter()
                            .any(|&row| record(row).is_none());
                    if stale {
                        for old in std::iter::once(edge.record)
                            .chain(edge.edge.key.evidence.iter().copied())
                        {
                            if let Some(row) = record(old) {
                                if !matches!(self.detector, Detector::Credentials)
                                    || self.facts(row).any(|(_, fact)| {
                                        matches!(fact.value, FactValue::Credential { .. })
                                    })
                                {
                                    affected[row as usize] = true;
                                }
                            }
                        }
                    }
                }
                for finding in &findings {
                    let stale = record(finding.record).is_none()
                        || context(finding.context).is_none()
                        || finding.evidence.iter().any(|id| !current.contains_key(id))
                        || finding
                            .effects
                            .iter()
                            .any(|effect| !current.contains_key(&effect.evidence))
                        || finding
                            .policy_provenance
                            .iter()
                            .flat_map(|value| &value.observations)
                            .any(|id| !current.contains_key(id));
                    if stale {
                        if let Some(row) = record(finding.record) {
                            affected[row as usize] = true;
                        }
                        for id in finding
                            .evidence
                            .iter()
                            .chain(finding.effects.iter().map(|effect| &effect.evidence))
                            .chain(
                                finding
                                    .policy_provenance
                                    .iter()
                                    .flat_map(|value| &value.observations),
                            )
                        {
                            if let Some(&row) = current.get(id) {
                                if !matches!(self.detector, Detector::Credentials)
                                    || self.facts(row).any(|(_, fact)| {
                                        matches!(fact.value, FactValue::Credential { .. })
                                    })
                                {
                                    affected[row as usize] = true;
                                }
                            }
                        }
                    }
                }
            }
            if matches!(self.detector, Detector::Credentials) {
                let times = self
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(row, _)| {
                        affected[*row]
                            && self
                                .facts(*row as u32)
                                .any(|(_, fact)| matches!(fact.value, FactValue::Credential { .. }))
                    })
                    .map(|(_, value)| value.observed_boottime_ns)
                    .collect::<BTreeSet<_>>();
                for (row, value) in self.records.iter().enumerate() {
                    if times.contains(&value.observed_boottime_ns)
                        && self
                            .facts(row as u32)
                            .any(|(_, fact)| matches!(fact.value, FactValue::Credential { .. }))
                    {
                        affected[row] = true;
                    }
                }
            }

            let mut kept_subjects: Vec<Subject> = Vec::new();
            let mut subject_rows = BTreeMap::new();
            let mut add_subject = |key: GraphSubjectKeyV1, row, fact| {
                if let Some(&index) = subject_rows.get(&key) {
                    let subject: &mut Subject = &mut kept_subjects[index as usize];
                    if (row, fact) < (subject.record, subject.context) {
                        subject.record = row;
                        subject.context = fact;
                    }
                    return Some(index);
                }
                let index = u32::try_from(kept_subjects.len()).ok()?;
                subject_rows.insert(key.clone(), index);
                kept_subjects.push(Subject {
                    key,
                    record: row,
                    context: fact,
                });
                Some(index)
            };
            let mut kept_edges = Vec::new();
            for mut edge in edges {
                let Some(row) = record(edge.record) else {
                    continue;
                };
                if affected[row as usize] {
                    continue;
                }
                edge.record = row;
                edge.fact = context(edge.fact)?;
                let fact_anchor = edge
                    .fact
                    .map(|index| (self.facts[index as usize].record, Some(index)));
                let local_anchor = (row, None);
                let from_anchor = if edge.edge.key.edge_type == GraphEdgeTypeV1::NativeParent {
                    fact_anchor?
                } else {
                    local_anchor
                };
                let to_anchor = if matches!(
                    edge.edge.key.edge_type,
                    GraphEdgeTypeV1::NativeParent
                        | GraphEdgeTypeV1::CredentialAuthority
                        | GraphEdgeTypeV1::KubernetesExpansion
                ) {
                    fact_anchor?
                } else {
                    local_anchor
                };
                edge.edge.key.from = add_subject(
                    subjects.get(edge.edge.key.from as usize)?.key.clone(),
                    from_anchor.0,
                    from_anchor.1,
                )?;
                edge.edge.key.to = add_subject(
                    subjects.get(edge.edge.key.to as usize)?.key.clone(),
                    to_anchor.0,
                    to_anchor.1,
                )?;
                edge.edge.key.evidence = edge
                    .edge
                    .key
                    .evidence
                    .iter()
                    .map(|&old| record(old))
                    .collect::<Option<Vec<_>>>()?;
                Self::canonical(&mut edge.edge.key.evidence);
                kept_edges.push(edge);
            }
            let mut kept_findings = Vec::new();
            for mut finding in findings {
                let Some(row) = record(finding.record) else {
                    continue;
                };
                if affected[row as usize] {
                    continue;
                }
                finding.record = row;
                finding.context = context(finding.context)?;
                if finding.evidence.iter().any(|id| !current.contains_key(id))
                    || finding
                        .effects
                        .iter()
                        .any(|effect| !current.contains_key(&effect.evidence))
                    || finding
                        .policy_provenance
                        .iter()
                        .flat_map(|value| &value.observations)
                        .any(|id| !current.contains_key(id))
                {
                    return None;
                }
                add_subject(finding.subject_id.clone(), row, finding.context)?;
                kept_findings.push(finding);
            }
            if matches!(self.detector, Detector::Process) {
                for (row, value) in self.records.iter().enumerate() {
                    if !affected[row] {
                        add_subject(value.task_subject(), row as u32, None)?;
                    }
                }
            }
            Some((records, affected, kept_subjects, kept_edges, kept_findings))
        })();
        let Some((records, affected, subjects, edges, findings)) = restored else {
            return Ok(None);
        };
        for (old, row) in progress.into_iter().zip(records) {
            if let Some(row) = row {
                self.progress[row as usize].state = old.state;
            }
        }
        self.subject_indices = subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| (subject.key.clone(), index as u32))
            .collect();
        self.subjects = subjects;
        self.edges = edges
            .into_iter()
            .map(|edge| (edge.edge.key.clone(), edge))
            .collect();
        self.findings = findings
            .into_iter()
            .map(|finding| (finding.finding_id.clone(), finding))
            .collect();
        Ok(Some(affected))
    }
}
