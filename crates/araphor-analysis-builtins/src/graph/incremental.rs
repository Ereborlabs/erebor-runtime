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
        serde_json::to_writer(&mut digest, &(record, window)).map_err(Computation::json_error)?;
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
        let mut subjects = Subject::decode(dataset("subjects")?)?;
        let mut edges = Relationship::decode(dataset("relationships")?)?;
        let mut findings = Finding::decode(dataset("findings")?)?;

        // shortcut: Rebuild changed old input; add removal updates if measured work requires them.
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
                .collect::<Option<Vec<_>>>()?;
            if records.windows(2).any(|pair| pair[0] >= pair[1]) {
                return None;
            }
            for (old, &row) in progress.iter().zip(&records) {
                if !old.compatible(self.detector)
                    || old.digest != self.progress[row as usize].digest
                {
                    return None;
                }
            }
            let mut prior_facts = vec![Vec::new(); records.len()];
            for (index, fact) in metadata.facts.iter().enumerate() {
                prior_facts.get_mut(fact.record as usize)?.push(index);
            }
            let mut facts = vec![0; metadata.facts.len()];
            for (old, &row) in records.iter().enumerate() {
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
                    facts[before] = after as u32;
                }
            }

            let mut affected = vec![true; self.records.len()];
            for &row in &records {
                affected[row as usize] = false;
            }
            if matches!(self.detector, Detector::Credentials) {
                let triggers = self
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(row, record)| {
                        affected[*row]
                            && (record.network()
                                || self.facts(*row as u32).any(|(_, fact)| {
                                    matches!(
                                        fact.value,
                                        FactValue::AuthorityUse { .. } | FactValue::Channel { .. }
                                    )
                                }))
                    })
                    .map(|(_, record)| record)
                    .collect::<Vec<_>>();
                for &row in &records {
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

            let record = |row: u32| records.get(row as usize).copied();
            let context = |index: Option<u32>| match index {
                Some(index) => facts.get(index as usize).copied().map(Some),
                None => Some(None),
            };
            for subject in &mut subjects {
                subject.record = record(subject.record)?;
                subject.context = context(subject.context)?;
            }
            if subjects
                .iter()
                .map(|subject| &subject.key)
                .collect::<BTreeSet<_>>()
                .len()
                != subjects.len()
            {
                return None;
            }
            for edge in &mut edges {
                edge.record = record(edge.record)?;
                edge.fact = context(edge.fact)?;
                subjects.get(edge.edge.key.from as usize)?;
                subjects.get(edge.edge.key.to as usize)?;
                edge.edge.key.evidence = edge
                    .edge
                    .key
                    .evidence
                    .iter()
                    .map(|&row| record(row))
                    .collect::<Option<_>>()?;
                Self::canonical(&mut edge.edge.key.evidence);
            }
            edges.retain(|edge| !affected[edge.record as usize]);
            for finding in &mut findings {
                finding.record = record(finding.record)?;
                finding.context = context(finding.context)?;
                if !finding.evidence.iter().all(|id| current.contains_key(id)) {
                    return None;
                }
            }
            findings.retain(|finding| !affected[finding.record as usize]);
            Some((records, affected))
        })();
        let Some((records, affected)) = restored else {
            return Ok(None);
        };
        for (old, row) in progress.into_iter().zip(records) {
            self.progress[row as usize].state = old.state;
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
