use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Progress {
    pub record: crate::discovery::DiscoveryRecordIdV1,
    pub digest: ByteBuf,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressRemoval {
    pub record: crate::discovery::DiscoveryRecordIdV1,
}

impl Progress {
    pub fn from_evaluation(evaluation: &sdk::Evaluation) -> sdk::Result<Vec<Self>> {
        let records = Observation::decode(&evaluation.input("records")?.data)?;
        let facts = Fact::decode(&evaluation.input("facts")?.data)?;
        let manifests = Manifest::decode(&evaluation.input("manifest")?.data)?;
        let [manifest] = manifests.as_slice() else {
            return Err(Computation::invalid("graph progress manifest"));
        };
        let mut ids = BTreeSet::new();
        let mut positions = BTreeSet::new();
        let source = records.first().map(|record| &record.id.stream);
        for record in &records {
            if source != Some(&record.id.stream)
                || !ids.insert(&record.id)
                || record.position.commit_revision == 0
                || !positions.insert(record.position)
            {
                return Err(Computation::invalid("graph progress record"));
            }
        }
        let mut by_record = vec![Vec::new(); records.len()];
        for fact in &facts {
            let row = by_record
                .get_mut(fact.record as usize)
                .ok_or_else(|| Computation::invalid("graph progress fact"))?;
            row.push(fact);
        }
        records
            .iter()
            .zip(by_record)
            .map(|(record, facts)| Self::new(record, manifest.window_ns, &facts))
            .collect()
    }

    pub fn output_digest(rows: &[Self]) -> sdk::Result<[u8; 32]> {
        let mut ordered = BTreeMap::new();
        for row in rows {
            if row.digest.len() != 32 || ordered.insert(&row.record, row).is_some() {
                return Err(Computation::invalid("graph progress output"));
            }
        }
        let mut digest = Sha256::new();
        ordered
            .values()
            .copied()
            .collect::<Vec<_>>()
            .serialize(&mut rmp_serde::Serializer::new(&mut digest).with_struct_map())
            .map_err(|_| Computation::invalid("graph progress output"))?;
        Ok(digest.finalize().into())
    }

    pub(super) fn new(record: &Observation, window: u64, facts: &[&Fact]) -> sdk::Result<Self> {
        let mut digest = Sha256::new();
        let basis = facts
            .iter()
            .map(|fact| (&fact.key, fact.sensitivity, &fact.value))
            .collect::<Vec<_>>();
        (record, window, basis)
            .serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| Computation::invalid("graph progress identity"))?;
        Ok(Self {
            record: record.id.clone(),
            digest: digest.finalize().to_vec().into(),
            state: None,
        })
    }

    pub fn compatible(&self, detector: Detector) -> bool {
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
            if !evaluation.previous_outputs.is_empty() {
                return Err(Self::invalid("graph previous output without checkpoint"));
            }
            return Ok(None);
        };
        if evaluation.previous_outputs.is_empty() {
            return Err(Self::invalid("graph checkpoint without previous output"));
        }
        if Resume::basis(checkpoint)? == ResumeBasis::Progress {
            return self.resume_progress(&evaluation.previous_outputs);
        }
        let dataset = |name: &str| {
            evaluation
                .previous_outputs
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| Self::invalid("graph previous output"))
        };
        if !SubjectRemoval::decode(dataset("subject_removals")?)?.is_empty()
            || !RelationshipRemoval::decode(dataset("relationship_removals")?)?.is_empty()
            || !FindingRemoval::decode(dataset("finding_removals")?)?.is_empty()
            || !ProgressRemoval::decode(dataset("progress_removals")?)?.is_empty()
        {
            return Err(Self::invalid("graph previous normalized output"));
        }
        let previous = Progress::decode(dataset("progress")?)?;
        for row in previous {
            if row.digest.len() != 32
                || !row.compatible(self.detector)
                || self
                    .prior_progress
                    .insert(row.record.clone(), row)
                    .is_some()
            {
                return Err(Self::invalid("graph previous progress identity"));
            }
        }
        for row in SubjectChange::decode(dataset("subjects")?)? {
            if self.prior_subjects.insert(row.key.clone(), row).is_some() {
                return Err(Self::invalid("graph previous subject identity"));
            }
        }
        for row in RelationshipChange::decode(dataset("relationships")?)? {
            if row.key.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || self.prior_edges.insert(row.key.clone(), row).is_some()
            {
                return Err(Self::invalid("graph previous relationship identity"));
            }
        }
        let previous_findings = FindingChange::decode(dataset("findings")?)?;
        for row in &previous_findings {
            let reason = row
                .prior_reason
                .clone()
                .ok_or_else(|| Self::invalid("graph previous finding reason"))?;
            let expected = FindingReasonV1::from_analysis_code(&row.package_id, &row.reason_code)?;
            if reason != expected
                || row.evidence.windows(2).any(|pair| pair[0] >= pair[1])
                || self
                    .prior_findings
                    .insert(
                        row.finding_id.clone(),
                        (row.clone().into_finding(reason), row.anchor.clone()),
                    )
                    .is_some()
            {
                return Err(Self::invalid("graph previous finding identity"));
            }
        }
        let current = self
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                u32::try_from(index)
                    .map(|index| (record.id.clone(), index))
                    .map_err(|_| Self::invalid("graph record count"))
            })
            .collect::<sdk::Result<BTreeMap<_, _>>>()?;
        let mut affected = vec![true; self.records.len()];
        for (id, previous) in &self.prior_progress {
            if let Some(&row) = current.get(id) {
                if previous.digest != self.progress[row as usize].digest {
                    return Ok(None);
                }
            }
        }
        if matches!(self.detector, Detector::Credentials) {
            let latest_retained = self
                .records
                .iter()
                .filter(|record| self.prior_progress.contains_key(&record.id))
                .map(|record| record.position)
                .max();
            if latest_retained.is_some_and(|latest| {
                self.records.iter().any(|record| {
                    !self.prior_progress.contains_key(&record.id) && record.position <= latest
                })
            }) {
                return Ok(None);
            }
        }
        for (id, previous) in &self.prior_progress {
            if let Some(&row) = current.get(id) {
                affected[row as usize] = false;
                self.progress[row as usize].state = previous.state.clone();
            }
        }
        let relevant = |row: u32| {
            !matches!(self.detector, Detector::Credentials)
                || self.records[row as usize].network()
                || self.facts(row).any(|(_, fact)| {
                    matches!(
                        fact.value,
                        FactValue::Credential { .. } | FactValue::AuthorityUse { .. }
                    )
                })
        };
        for edge in self.prior_edges.values() {
            let stale = self.local_anchor(&edge.anchor, &current).is_none()
                || edge.key.evidence.iter().any(|id| !current.contains_key(id));
            if stale {
                if matches!(self.detector, Detector::Credentials) {
                    for finding in &previous_findings {
                        if edge
                            .key
                            .evidence
                            .iter()
                            .all(|id| finding.evidence.binary_search(id).is_ok())
                        {
                            if let Some(&row) = current.get(&finding.anchor.record) {
                                if relevant(row) {
                                    affected[row as usize] = true;
                                }
                            }
                        }
                    }
                } else {
                    for id in std::iter::once(&edge.anchor.record).chain(&edge.key.evidence) {
                        if let Some(&row) = current.get(id) {
                            if relevant(row) {
                                affected[row as usize] = true;
                            }
                        }
                    }
                }
            }
        }
        for finding in &previous_findings {
            let stale = self.local_anchor(&finding.anchor, &current).is_none()
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
                if matches!(self.detector, Detector::Credentials) {
                    if let Some(&row) = current.get(&finding.anchor.record) {
                        if relevant(row) {
                            affected[row as usize] = true;
                        }
                    }
                } else {
                    for id in std::iter::once(&finding.anchor.record)
                        .chain(&finding.evidence)
                        .chain(finding.effects.iter().map(|effect| &effect.evidence))
                        .chain(
                            finding
                                .policy_provenance
                                .iter()
                                .flat_map(|value| &value.observations),
                        )
                    {
                        if let Some(&row) = current.get(id) {
                            if relevant(row) {
                                affected[row as usize] = true;
                            }
                        }
                    }
                }
            }
        }
        let mut support = BTreeMap::<GraphSubjectKeyV1, (u32, Option<u32>)>::new();
        let mut needed = BTreeSet::new();
        let mut retain = |key: &GraphSubjectKeyV1, anchor: (u32, Option<u32>)| {
            support
                .entry(key.clone())
                .and_modify(|old| {
                    if anchor < *old {
                        *old = anchor;
                    }
                })
                .or_insert(anchor);
        };
        for subject in self.prior_subjects.values() {
            if let Some(anchor) = self.local_anchor(&subject.anchor, &current) {
                if !affected[anchor.0 as usize] {
                    retain(&subject.key, anchor);
                }
            }
        }
        for edge in self.prior_edges.values() {
            let Some((row, fact)) = self.local_anchor(&edge.anchor, &current) else {
                continue;
            };
            if affected[row as usize]
                || edge.key.evidence.iter().any(|id| {
                    current
                        .get(id)
                        .is_none_or(|&index| affected[index as usize])
                })
            {
                continue;
            }
            let fact_row = edge
                .anchor
                .fact
                .as_ref()
                .and_then(|anchor| current.get(&anchor.record))
                .copied()
                .unwrap_or(row);
            let (from, to) = match edge.key.edge_type {
                GraphEdgeTypeV1::TaskInProcess
                | GraphEdgeTypeV1::TaskInExecutionSet
                | GraphEdgeTypeV1::NativeEffect => ((row, None), (row, None)),
                GraphEdgeTypeV1::NativeParent => ((fact_row, fact), (fact_row, fact)),
                GraphEdgeTypeV1::CredentialAuthority | GraphEdgeTypeV1::KubernetesExpansion => {
                    ((row, None), (fact_row, fact))
                }
            };
            needed.insert(edge.key.from.clone());
            needed.insert(edge.key.to.clone());
            retain(&edge.key.from, from);
            retain(&edge.key.to, to);
        }
        for finding in &previous_findings {
            let Some(anchor) = self.local_anchor(&finding.anchor, &current) else {
                continue;
            };
            if !affected[anchor.0 as usize]
                && finding.evidence.iter().all(|id| {
                    current
                        .get(id)
                        .is_some_and(|&index| !affected[index as usize])
                })
            {
                needed.insert(finding.subject_id.clone());
                retain(&finding.subject_id, anchor);
            }
        }
        support.retain(|key, _| needed.contains(key));
        for (key, (row, context)) in support {
            if !self.prior_subjects.contains_key(&key) {
                return Err(Self::invalid("graph previous subject reference"));
            }
            let index = u32::try_from(self.subjects.len())
                .map_err(|_| Self::invalid("graph subject count"))?;
            self.subject_indices.insert(key.clone(), index);
            self.subjects.push(Subject {
                record: row,
                context,
                key,
            });
        }
        for edge in self.prior_edges.values() {
            let Some((row, fact)) = self.local_anchor(&edge.anchor, &current) else {
                continue;
            };
            if affected[row as usize] {
                continue;
            }
            let Some(&from) = self.subject_indices.get(&edge.key.from) else {
                continue;
            };
            let Some(&to) = self.subject_indices.get(&edge.key.to) else {
                continue;
            };
            let Some(evidence) = edge
                .key
                .evidence
                .iter()
                .map(|id| current.get(id).copied())
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if evidence.iter().any(|&index| affected[index as usize]) {
                continue;
            }
            let value = Relationship {
                record: row,
                fact,
                edge: GraphEdgeV1 {
                    key: GraphEdgeKeyV1 {
                        from,
                        to,
                        edge_type: edge.key.edge_type,
                        package_id: edge.key.package_id.clone(),
                        evidence,
                        cause: edge.key.cause,
                    },
                    proof_quality: edge.proof_quality,
                    required_coverage_interval_ids: edge.required_coverage_interval_ids.clone(),
                    first_boottime_ns: edge.first_boottime_ns,
                    last_boottime_ns: edge.last_boottime_ns,
                },
            };
            if self.edges.insert(value.edge.key.clone(), value).is_some() {
                return Err(Self::invalid("graph previous relationship identity"));
            }
        }
        for finding in previous_findings {
            let Some((row, context)) = self.local_anchor(&finding.anchor, &current) else {
                continue;
            };
            if affected[row as usize]
                || finding.evidence.iter().any(|id| !current.contains_key(id))
                || finding
                    .effects
                    .iter()
                    .any(|effect| !current.contains_key(&effect.evidence))
                || finding
                    .policy_provenance
                    .iter()
                    .flat_map(|value| &value.observations)
                    .any(|id| !current.contains_key(id))
                || !self.subject_indices.contains_key(&finding.subject_id)
            {
                continue;
            }
            let value = self
                .prior_findings
                .get(&finding.finding_id)
                .ok_or_else(|| Self::invalid("graph previous finding"))?
                .0
                .clone();
            let value = Finding::from_finding(row, context, value, finding.reason_code);
            if self
                .findings
                .insert(value.finding_id.clone(), value)
                .is_some()
            {
                return Err(Self::invalid("graph previous finding identity"));
            }
        }
        Ok(Some(affected))
    }

    fn resume_progress(&mut self, previous: &[sdk::Dataset]) -> sdk::Result<Option<Vec<bool>>> {
        if previous.len() != self.detector.descriptor().exports[0].outputs.len()
            || previous.iter().any(|data| {
                data.name != "progress" && data.batches.iter().any(|batch| batch.num_rows() != 0)
            })
        {
            return Err(Self::invalid("graph progress basis output"));
        }
        let progress = previous
            .iter()
            .find(|data| data.name == "progress")
            .ok_or_else(|| Self::invalid("graph progress basis output"))
            .and_then(Progress::decode)?;
        if !Resume::append_eligible(
            self.detector,
            &self.records,
            &self.facts,
            &self.manifest,
            &progress,
        )? {
            return Err(Self::invalid("graph progress basis changed"));
        }
        let mut affected = vec![true; self.records.len()];
        let current = self
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| (&record.id, index))
            .collect::<BTreeMap<_, _>>();
        for row in progress {
            let index = *current
                .get(&row.record)
                .ok_or_else(|| Self::invalid("graph progress basis record"))?;
            affected[index] = false;
            self.progress[index].state = row.state.clone();
            if self
                .prior_progress
                .insert(row.record.clone(), row)
                .is_some()
            {
                return Err(Self::invalid("graph progress basis identity"));
            }
        }
        Ok(Some(affected))
    }

    fn local_anchor(
        &self,
        anchor: &Anchor,
        current: &BTreeMap<crate::discovery::DiscoveryRecordIdV1, u32>,
    ) -> Option<(u32, Option<u32>)> {
        let row = *current.get(&anchor.record)?;
        let fact = match anchor.fact.as_ref() {
            Some(anchor) => {
                let fact_record = *current.get(&anchor.record)?;
                let index = self
                    .fact_rows
                    .get(fact_record as usize)?
                    .iter()
                    .copied()
                    .find(|&index| {
                        let fact = &self.facts[index];
                        fact.key == anchor.key
                            && fact.sensitivity == anchor.sensitivity
                            && fact.value == anchor.value
                    })?;
                Some(u32::try_from(index).ok()?)
            }
            None => None,
        };
        Some((row, fact))
    }
}
