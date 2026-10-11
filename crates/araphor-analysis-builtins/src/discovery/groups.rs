use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::{Coverage, Discovery, Group, GroupAtom};

impl Discovery {
    pub(super) fn groups(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let atoms = Self::read::<GroupAtom>(input, "atoms")?;
        let coverage = Self::read::<Coverage>(input, "coverage")?;
        let mut groups = BTreeMap::<String, Group>::new();
        for (index, row) in atoms.iter().enumerate() {
            let group = groups.entry(row.group.clone()).or_insert_with(|| Group {
                key: row.group.clone(),
                count: 0,
                members: Vec::new(),
                samples: Vec::new(),
                coverage: Vec::new(),
            });
            Self::add(&mut group.count, row.atom.count)?;
            group.members.push(index as u64);
            group.samples.extend(row.atom.samples.clone());
            for (index, range) in coverage.iter().enumerate() {
                if range.source == row.source
                    && range.cpu == row.cpu
                    && range.interval == row.interval
                    && range.first <= row.atom.last
                    && range.last >= row.atom.first
                {
                    group.coverage.push(index as u64);
                }
            }
        }
        for group in groups.values_mut() {
            group.samples.sort();
            group.samples.dedup();
            group.samples.truncate(8);
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
