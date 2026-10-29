use std::collections::BTreeMap;

use super::{GraphReplayInputV1, GraphRevisionV1};
use crate::{GraphInvalidSnafu, Result};

impl GraphReplayInputV1 {
    pub fn normalized(&self) -> Result<Self> {
        let mut records = BTreeMap::new();
        for record in &self.records {
            if records
                .insert(record.id.clone(), record.clone())
                .is_some_and(|previous| previous != *record)
            {
                return GraphInvalidSnafu {
                    field: "conflicting observation",
                }
                .fail();
            }
        }
        let mut positions = BTreeMap::new();
        for (id, position) in &self.input_positions {
            if positions.insert(id.clone(), *position).is_some() {
                return GraphInvalidSnafu {
                    field: "conflicting input position",
                }
                .fail();
            }
        }
        let mut facts = BTreeMap::new();
        for fact in &self.facts {
            if facts
                .insert(fact.key.clone(), fact.clone())
                .is_some_and(|previous| previous != *fact)
            {
                return GraphInvalidSnafu {
                    field: "conflicting context version",
                }
                .fail();
            }
        }
        let mut coverage = self.coverage.clone();
        coverage.sort();
        coverage.dedup();
        let mut coverage_keys = self.coverage_keys.clone();
        coverage_keys.sort();
        coverage_keys.dedup();
        let mut gaps = self.missing_ranges.clone();
        gaps.sort();
        gaps.dedup();
        Ok(Self {
            source: self.source.clone(),
            records: records.into_values().collect(),
            input_positions: positions.into_iter().collect(),
            coverage,
            coverage_keys,
            facts: facts.into_values().collect(),
            missing_ranges: gaps,
        })
    }

    pub fn manifest(&self) -> GraphRevisionV1 {
        GraphRevisionV1 {
            evidence: self
                .records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            coverage: self.coverage_keys.clone(),
            context: self.facts.iter().map(|fact| fact.key.clone()).collect(),
            missing_ranges: self.missing_ranges.clone(),
        }
    }
}
