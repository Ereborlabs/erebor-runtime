use araphor_analysis_sdk as sdk;
use std::collections::{BTreeMap, BTreeSet};

mod contract;
mod credential;
mod edges;
mod finding;
mod finish;
mod kubernetes;
mod model;
mod native;
mod observation;
mod policy;
mod process;

pub use contract::ReasonDetails;
pub use model::*;

pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

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
    state: State,
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
        for record in &records {
            if record.id.stream != records[0].id.stream || !record_ids.insert(record.id.clone()) {
                return Err(Self::invalid("graph record identity"));
            }
        }
        let mut computation = Self {
            fact_rows: vec![Vec::new(); records.len()],
            records,
            facts,
            fact_ids: Vec::new(),
            manifest,
            detector,
            subjects: Vec::new(),
            subject_indices: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
            state: State {
                value: match detector {
                    Detector::Kubernetes => "KUBERNETES_PROOF_MISSING",
                    _ => "WAITING",
                }
                .into(),
            },
        };
        for (index, fact) in computation.facts.iter().enumerate() {
            computation.record(fact.record)?;
            computation.fact_rows[fact.record as usize].push(index);
            computation.fact_ids.push(
                computation.facts[..index]
                    .iter()
                    .position(|previous| {
                        previous.record == fact.record && previous.value == fact.value
                    })
                    .unwrap_or(index),
            );
        }
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

    fn json_error(error: serde_json::Error) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Invalid, error.to_string())
    }
}

#[cfg(test)]
mod tests;
