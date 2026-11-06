use std::collections::BTreeMap;
use std::time::Instant;

use araphor_graph::Staged;
use arrow_array::RecordBatch;
use serde::Serialize;

use super::{Engine, Result, fixture::Fixture, incident::Incident, package};

#[derive(Default)]
pub struct History(BTreeMap<u64, Reference>);
struct Reference {
    commands: Vec<(u64, u64, u64, RecordBatch)>,
    calls: Vec<(u64, String, u64, Vec<Vec<u8>>, usize)>,
    frontier: Vec<usize>,
}
#[derive(Serialize)]
pub struct Sample {
    engine: String,
    round: usize,
    stage: String,
    direction: String,
    revision: u64,
    captured: u64,
    elapsed_s: f64,
    capture_s: f64,
    index_s: f64,
    resolve_s: f64,
    detect_s: f64,
    normalize_s: f64,
    frontier_records: Vec<usize>,
    calls: Vec<package::Call>,
}

impl Reference {
    fn new(prepared: &package::Prepared) -> Self {
        Self {
            commands: prepared
                .step
                .journals
                .iter()
                .flat_map(|(&writer, journal)| {
                    journal.batches().iter().map(move |command| match command {
                        Staged::Clear { sequence, batch } => {
                            (writer, 0, *sequence, batch.as_ref().clone())
                        }
                        Staged::Edits {
                            relation,
                            sequence,
                            batch,
                        } => (writer, *relation, *sequence, batch.as_ref().clone()),
                    })
                })
                .collect(),
            calls: prepared
                .calls
                .iter()
                .map(|c| {
                    let (writer, operation, relation, keys, rows) = c.signature();
                    (writer, operation.to_string(), relation, keys.to_vec(), rows)
                })
                .collect(),
            frontier: prepared.frontier.clone(),
        }
    }
    fn check(&self, prepared: &package::Prepared) {
        let actual = Self::new(prepared);
        assert_eq!(self.commands, actual.commands);
        assert_eq!(self.calls, actual.calls);
        assert_eq!(self.frontier, actual.frontier);
    }
}

impl History {
    pub fn orders() -> Vec<Vec<&'static str>> {
        #[allow(unused_mut)]
        let mut engines = vec![
            "duckdb",
            "redb",
            "fjall",
            "home",
            "surrealkv",
            "surrealkv-native",
        ];
        #[cfg(feature = "neon-poc")]
        engines.push("neon-layers");
        let size = engines.len();
        let mut first = vec![0];
        for slot in 1..size {
            first.push(if slot % 2 == 1 {
                slot.div_ceil(2)
            } else {
                size - slot / 2
            });
        }
        let mut orders = Vec::new();
        for shift in 0..size {
            let row = first
                .iter()
                .map(|i| engines[(i + shift) % size])
                .collect::<Vec<_>>();
            orders.push(row.clone());
            orders.push(row.into_iter().rev().collect());
        }
        orders
    }
    pub fn remember(&mut self, revision: u64, prepared: &package::Prepared) -> Result<()> {
        if let Some(reference) = self.0.get(&revision) {
            reference.check(prepared);
        } else {
            self.0.insert(revision, Reference::new(prepared));
        }
        Ok(())
    }
    pub fn replay(
        &self,
        engine: &Engine,
        fixture: &Fixture,
        incident: &Incident,
        inputs: &[araphor_analysis_sdk::Evaluation],
        kind: &str,
        round: usize,
        stage: &str,
    ) -> Result<Vec<Sample>> {
        let mut samples = Vec::new();
        for direction in ["backward", "forward"] {
            let mut order = (0..fixture.steps.len()).collect::<Vec<_>>();
            if direction == "backward" {
                order.reverse();
            }
            for i in order {
                let spec = fixture.steps[i];
                let started = Instant::now();
                let (prepared, capture_s) =
                    engine.capture(fixture, spec.captured, |view, capture_s| {
                        Ok((
                            package::evaluate(view, fixture, incident, spec, &inputs[i])?,
                            capture_s,
                        ))
                    })?;
                let elapsed_s = started.elapsed().as_secs_f64();
                self.0[&spec.revision].check(&prepared);
                engine.verify_metadata(fixture, 87, 87)?;
                engine.verify_metadata(fixture, 88, 87)?;
                samples.push(Sample {
                    engine: kind.into(),
                    round,
                    stage: stage.into(),
                    direction: direction.into(),
                    revision: spec.revision,
                    captured: spec.captured,
                    elapsed_s,
                    capture_s,
                    index_s: prepared.index_s,
                    resolve_s: prepared.resolve_s,
                    detect_s: prepared.detect_s,
                    normalize_s: prepared.normalize_s,
                    frontier_records: prepared.frontier,
                    calls: prepared.calls,
                });
            }
        }
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn balanced_orders() {
        let orders = super::History::orders();
        let engines = orders[0].clone();
        for engine in &engines {
            for position in 0..engines.len() {
                assert_eq!(
                    orders.iter().filter(|row| row[position] == *engine).count(),
                    2
                );
            }
            for other in &engines {
                if engine != other {
                    assert_eq!(
                        orders
                            .iter()
                            .flat_map(|row| row.windows(2))
                            .filter(|pair| pair[0] == *engine && pair[1] == *other)
                            .count(),
                        2
                    );
                }
            }
        }
    }
}
