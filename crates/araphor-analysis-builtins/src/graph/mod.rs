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
    fact_rows: Vec<Vec<usize>>,
    manifest: Manifest,
    subjects: Vec<Subject>,
    edges: Vec<Relationship>,
    findings: Vec<Finding>,
    state: State,
}

impl Computation {
    fn new(
        records: Vec<Observation>,
        facts: Vec<Fact>,
        manifest: Manifest,
        detector: Detector,
    ) -> sdk::Result<Self> {
        let mut computation = Self {
            fact_rows: vec![Vec::new(); records.len()],
            records,
            facts,
            manifest,
            subjects: Vec::new(),
            edges: Vec::new(),
            findings: Vec::new(),
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
        }
        Ok(computation)
    }

    fn facts(&self, record: u64) -> impl Iterator<Item = (usize, &Fact)> {
        usize::try_from(record)
            .ok()
            .and_then(|record| self.fact_rows.get(record))
            .into_iter()
            .flatten()
            .map(|&index| (index, &self.facts[index]))
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
