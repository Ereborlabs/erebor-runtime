use araphor_analysis_sdk as sdk;
use std::collections::{BTreeMap, BTreeSet};

mod contract;
mod credential;
mod edges;
mod finding;
mod finish;
mod incremental;
mod kubernetes;
mod model;
mod native;
mod observation;
mod policy;
mod process;
mod resume;

pub use contract::ReasonDetails;
pub use model::*;

pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

pub use incremental::{Progress, ProgressRemoval};
pub use resume::{Resume, ResumeBasis};
use GraphContextActionV1 as ContextClass;
use GraphFactValueV1 as FactValue;
use GraphReadPathV1 as ReadPath;

#[derive(Clone, Copy, Debug)]
pub enum Detector {
    Process,
    Credentials,
    Kubernetes,
}

struct Computation {
    records: Vec<Observation>,
    facts: Vec<Fact>,
    fact_rows: Vec<Vec<usize>>,
    fact_ids: Vec<usize>,
    manifest: Manifest,
    detector: Detector,
    subjects: Vec<Subject>,
    subject_indices: BTreeMap<GraphSubjectKeyV1, u32>,
    edges: BTreeMap<GraphEdgeKeyV1, Relationship>,
    findings: BTreeMap<String, Finding>,
    prior_findings: BTreeMap<String, (FindingV1, FindingAnchor)>,
    prior_subjects: BTreeMap<GraphSubjectKeyV1, SubjectChange>,
    prior_edges: BTreeMap<RelationshipIdentity, RelationshipChange>,
    prior_progress: BTreeMap<crate::discovery::DiscoveryRecordIdV1, Progress>,
    state: String,
    progress: Vec<Progress>,
    #[cfg(test)]
    work: usize,
}

impl Computation {
    fn new(
        records: Vec<Observation>,
        facts: Vec<Fact>,
        manifest: Manifest,
        detector: Detector,
    ) -> sdk::Result<Self> {
        if u32::try_from(records.len()).is_err() {
            return Err(Self::invalid("graph record count"));
        }
        let mut record_ids = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for record in &records {
            if record.id.stream != records[0].id.stream
                || !record_ids.insert(record.id.clone())
                || record.position.commit_revision == 0
                || !positions.insert(record.position)
            {
                return Err(Self::invalid("graph record identity"));
            }
        }
        let mut fact_rows: Vec<Vec<usize>> = vec![Vec::new(); records.len()];
        let mut fact_ids = Vec::with_capacity(facts.len());
        for (index, fact) in facts.iter().enumerate() {
            let rows = fact_rows
                .get_mut(fact.record as usize)
                .ok_or_else(|| Self::invalid("graph record reference"))?;
            fact_ids.push(
                rows.iter()
                    .copied()
                    .find(|&previous| facts[previous].value == fact.value)
                    .unwrap_or(index),
            );
            rows.push(index);
        }
        let progress = records
            .iter()
            .zip(&fact_rows)
            .map(|(record, rows)| {
                let basis = rows.iter().map(|&index| &facts[index]).collect::<Vec<_>>();
                Progress::new(record, manifest.window_ns, &basis)
            })
            .collect::<sdk::Result<_>>()?;
        let computation = Self {
            fact_rows,
            records,
            facts,
            fact_ids,
            manifest,
            detector,
            subjects: Vec::new(),
            subject_indices: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            prior_findings: BTreeMap::new(),
            prior_subjects: BTreeMap::new(),
            prior_edges: BTreeMap::new(),
            prior_progress: BTreeMap::new(),
            progress,
            #[cfg(test)]
            work: 0,
            state: match detector {
                Detector::Kubernetes => "KUBERNETES_PROOF_MISSING",
                _ => "WAITING",
            }
            .into(),
        };
        Ok(computation)
    }

    fn facts(&self, record: u32) -> impl Iterator<Item = (usize, &Fact)> {
        self.fact_rows
            .get(record as usize)
            .into_iter()
            .flatten()
            .map(|&index| (index, &self.facts[index]))
    }

    fn record(&self, row: u32) -> sdk::Result<&Observation> {
        self.records
            .get(row as usize)
            .ok_or_else(|| Self::invalid("graph record reference"))
    }

    fn invalid(field: &str) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Invalid, field)
    }
}

#[cfg(test)]
mod tests;
