use super::*;

impl BehaviorSnapshotV1 {
    pub fn validate_groups(&self, groups: &[BehaviorDisplayGroupV1]) -> Result<()> {
        self.validate()?;
        let input = self;
        let atoms: BTreeMap<_, _> = input.atoms.iter().map(|atom| (&atom.key, atom)).collect();
        let mut used = BTreeSet::new();
        require(
            groups.windows(2).all(|pair| pair[0].key < pair[1].key),
            "analysis group order",
        )?;
        for group in groups {
            let mut count = 0;
            let mut samples = BTreeSet::new();
            let mut coverage = BTreeSet::new();
            require(
                !group.members.is_empty()
                    && !group.evidence_sample.is_empty()
                    && group.evidence_sample.len() <= MAX_DISCOVERY_SAMPLES
                    && group
                        .evidence_sample
                        .windows(2)
                        .all(|pair| pair[0] < pair[1]),
                "analysis group members",
            )?;
            for key in &group.members {
                let atom = atoms.get(key).ok_or_else(|| {
                    DiscoveryInvalidSnafu {
                        field: "analysis group atom",
                    }
                    .build()
                })?;
                require(
                    used.insert(key) && BehaviorDisplayKeyV1::from(key) == group.key,
                    "analysis group identity",
                )?;
                count += atom.count;
                samples.extend(&atom.evidence_sample);
                coverage.extend(input.coverage.iter().filter(|range| {
                    range.stream == key.stream
                        && range.cpu_id == key.cpu_id
                        && range.coverage_interval_id == key.coverage_interval_id
                        && range.first_cursor <= atom.last_cursor
                        && range.last_cursor >= atom.first_cursor
                }));
            }
            require(
                count == group.count
                    && group.evidence_sample.iter().all(|id| samples.contains(id))
                    && group.coverage.iter().collect::<BTreeSet<_>>() == coverage,
                "analysis group evidence",
            )?;
        }
        require(used.len() == atoms.len(), "analysis group inputs")
    }
}
