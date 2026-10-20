use super::*;

impl BehaviorSnapshotV1 {
    pub(super) fn validate_lifecycle<'a>(
        output: &[DiscoveryLifecycleEntryV1],
        inputs: impl Iterator<Item = &'a DiscoveryLifecycleEntryV1>,
    ) -> Result<()> {
        let mut sources = BTreeMap::<_, Vec<_>>::new();
        for entry in inputs {
            sources.entry(entry.case).or_default().push(&entry.state);
        }
        require(
            output.len() == DiscoveryLifecycleCaseV1::ALL.len(),
            "analysis lifecycle cases",
        )?;
        for entry in output {
            let states = sources.remove(&entry.case).unwrap_or_default();
            let mut known = states
                .iter()
                .filter(|state| ***state != DiscoveryLifecycleStateV1::Missing);
            if let Some(first) = known.next() {
                same(
                    known.all(|state| {
                        **state == **first
                            || matches!(
                                (state, first),
                                (
                                    DiscoveryLifecycleStateV1::Recorded { .. },
                                    DiscoveryLifecycleStateV1::Recorded { .. }
                                )
                            )
                    }),
                    "lifecycle state",
                )?;
            }
            let records: BTreeSet<_> = states
                .iter()
                .flat_map(|state| match state {
                    DiscoveryLifecycleStateV1::Recorded { records } => records.as_slice(),
                    _ => &[],
                })
                .collect();
            if !records.is_empty() {
                let DiscoveryLifecycleStateV1::Recorded { records: actual } = &entry.state else {
                    return DiscoveryInvalidSnafu {
                        field: "analysis lifecycle records",
                    }
                    .fail();
                };
                require(
                    actual.iter().collect::<BTreeSet<_>>() == records,
                    "analysis lifecycle records",
                )?;
            } else {
                let expected = states
                    .into_iter()
                    .find(|state| **state != DiscoveryLifecycleStateV1::Missing)
                    .unwrap_or(&DiscoveryLifecycleStateV1::Missing);
                require(&entry.state == expected, "analysis lifecycle proof")?;
            }
        }
        require(sources.is_empty(), "analysis lifecycle sources")
    }
}
