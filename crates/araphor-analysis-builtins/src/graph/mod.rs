use araphor_analysis_sdk as sdk;
use std::collections::{BTreeMap, BTreeSet};

mod commands;
pub use commands::GraphCommands;
mod contract;
mod credential;
mod edges;
mod finding;
mod finish;
mod model;
mod native;
mod policy;
mod units;

pub use contract::ReasonDetails;
pub use finding::FindingResolve;
pub use finish::{BranchExt, CheckpointExt};
pub use model::*;

pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

#[cfg(test)]
use GraphContextActionV1 as ContextClass;
use GraphFactValueV1 as FactValue;
use GraphReadPathV1 as ReadPath;

#[derive(Clone, Copy, Debug)]
pub enum Detector {
    Credentials,
}

struct Computation {
    records: Vec<Observation>,
    facts: Vec<Fact>,
    fact_rows: Vec<Vec<usize>>,
    fact_ids: Vec<usize>,
    allowed_rows: Option<BTreeSet<u32>>,
    manifest: Manifest,
    detector: Detector,
    subjects: Vec<Subject>,
    subject_indices: BTreeMap<GraphSubjectKeyV1, u32>,
    edges: BTreeMap<GraphEdgeKeyV1, Relationship>,
    findings: BTreeMap<String, Finding>,
}

impl Computation {
    fn indexed(
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
        for (index, fact) in facts.iter().enumerate() {
            fact_rows
                .get_mut(fact.record as usize)
                .ok_or_else(|| Self::invalid("graph record reference"))?
                .push(index);
        }
        let mut fact_ids = (0..facts.len()).collect::<Vec<_>>();
        for rows in &mut fact_rows {
            rows.sort_by(|&left, &right| facts[left].key.cmp(&facts[right].key));
            for &index in rows.iter() {
                fact_ids[index] = rows
                    .iter()
                    .copied()
                    .find(|&previous| facts[previous].value == facts[index].value)
                    .unwrap_or(index);
            }
        }
        let computation = Self {
            fact_rows,
            records,
            facts,
            fact_ids,
            allowed_rows: None,
            manifest,
            detector,
            subjects: Vec::new(),
            subject_indices: BTreeMap::new(),
            edges: BTreeMap::new(),
            findings: BTreeMap::new(),
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

    fn anchor_key(
        &self,
        record: u32,
        fact: Option<u32>,
    ) -> (
        &crate::discovery::DiscoveryRecordIdV1,
        Option<&AnalysisContextKeyV1>,
    ) {
        (
            &self.records[record as usize].id,
            fact.map(|index| &self.facts[index as usize].key),
        )
    }

    fn selected(&self, row: u32) -> bool {
        self.allowed_rows
            .as_ref()
            .is_none_or(|rows| rows.contains(&row))
    }

    fn invalid(field: &str) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Invalid, field)
    }
}

#[cfg(test)]
mod tests;
