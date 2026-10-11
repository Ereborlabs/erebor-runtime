use araphor_analysis_sdk as sdk;

mod contract;
mod credential;
mod kubernetes;
mod model;
mod process;

pub use model::*;

#[derive(Clone, Copy, Debug)]
pub enum Detector {
    Process,
    Credentials,
    Kubernetes,
}

struct Computation {
    records: Vec<Observation>,
    facts: Vec<Fact>,
    manifest: Manifest,
    subjects: Vec<Subject>,
    edges: Vec<Relationship>,
    findings: Vec<Finding>,
    state: State,
}

impl Computation {
    fn facts(&self, record: u64) -> impl Iterator<Item = (usize, &Fact)> {
        self.facts
            .iter()
            .enumerate()
            .filter(move |(_, fact)| fact.record == record)
    }

    fn record(&self, row: u64) -> sdk::Result<&Observation> {
        usize::try_from(row)
            .ok()
            .and_then(|row| self.records.get(row))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "graph record reference"))
    }

    fn finding(
        &mut self,
        record: u64,
        reason: &str,
        confirmed: bool,
        evidence: Vec<u64>,
        limits: Vec<String>,
    ) {
        self.findings.push(Finding {
            record,
            context: None,
            reason: reason.into(),
            confirmed,
            evidence,
            limits,
        });
    }

    fn edge(
        &mut self,
        record: u64,
        fact: Option<u64>,
        kind: EdgeKind,
        cause: Cause,
        evidence: Vec<u64>,
    ) {
        self.edges.push(Relationship {
            record,
            fact,
            kind,
            cause,
            evidence,
        });
    }
}

#[cfg(test)]
mod tests;
