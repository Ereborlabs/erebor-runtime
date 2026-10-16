use std::collections::BTreeMap;

use crate::Rows;
use araphor_analysis_sdk as sdk;

use super::{
    BehaviorAtomV1, BehaviorDisplayGroupV1, BehaviorDisplayKeyV1, Discovery, DiscoveryCoverageV1,
};

impl Discovery {
    pub(super) fn groups(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let atoms = Rows::input::<BehaviorAtomV1>(input, "atoms")?;
        let coverage = Rows::input::<DiscoveryCoverageV1>(input, "coverage")?;
        let mut groups = BTreeMap::<_, BehaviorDisplayGroupV1>::new();
        for atom in &atoms {
            let key = BehaviorDisplayKeyV1::from(&atom.key);
            let group = groups
                .entry(key.clone())
                .or_insert_with(|| BehaviorDisplayGroupV1 {
                    key,
                    count: 0,
                    members: Vec::new(),
                    evidence_sample: Vec::new(),
                    coverage: Vec::new(),
                });
            Self::add(&mut group.count, atom.count)?;
            group.members.push(atom.key.clone());
            group.evidence_sample.extend(atom.evidence_sample.clone());
            group.coverage.extend(
                coverage
                    .iter()
                    .filter(|range| {
                        range.stream == atom.key.stream
                            && range.cpu_id == atom.key.cpu_id
                            && range.coverage_interval_id == atom.key.coverage_interval_id
                            && range.first_cursor <= atom.last_cursor
                            && range.last_cursor >= atom.first_cursor
                    })
                    .cloned(),
            );
        }
        for group in groups.values_mut() {
            group.evidence_sample.sort();
            group.evidence_sample.dedup();
            group.evidence_sample.truncate(8);
            group.coverage.sort();
            group.coverage.dedup();
        }
        Ok(sdk::Output {
            datasets: vec![Self::write(
                input,
                "groups",
                &groups.into_values().collect::<Vec<_>>(),
            )?],
            ..sdk::Output::default()
        })
    }
}
