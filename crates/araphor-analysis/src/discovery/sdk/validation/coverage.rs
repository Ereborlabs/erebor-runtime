use super::*;

impl Adapter {
    pub(super) fn recorded_coverage<'a>(
        input: &DiscoveryInputManifestV1,
        records: impl Iterator<Item = &'a DiscoveryRecordV1>,
    ) -> Result<Vec<DiscoveryCoverageV1>> {
        let mut ranges = input.coverage.clone();
        let mut counts = vec![0_u64; ranges.len()];
        for record in records {
            let wire = record.decode()?;
            let (index, range) = ranges
                .iter_mut()
                .enumerate()
                .find(|(_, range)| {
                    range.stream == record.id.stream
                        && range.cpu_id == record.id.cpu_id
                        && range.first_cursor <= record.id.durable_cursor
                        && range.last_cursor >= record.id.durable_cursor
                })
                .ok_or_else(|| {
                    DiscoveryInvalidSnafu {
                        field: "analysis source range",
                    }
                    .build()
                })?;
            counts[index] += 1;
            match wire.temporal_coverage {
                2 => {
                    range.state = DiscoveryCoverageStateV1::Gapped;
                    range.gap_reasons.push("OBSERVATION_COVERAGE_GAPPED".into());
                }
                0 => {
                    if range.state != DiscoveryCoverageStateV1::Gapped {
                        range.state = DiscoveryCoverageStateV1::Unknown;
                    }
                    range
                        .gap_reasons
                        .push("OBSERVATION_COVERAGE_UNKNOWN".into());
                }
                _ => {}
            }
        }
        for (range, count) in ranges.iter_mut().zip(counts) {
            if count != range.expected_records {
                range.state = DiscoveryCoverageStateV1::Gapped;
                range.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
            }
        }
        Ok(ranges)
    }

    pub(super) fn validate_coverage(
        output: &[DiscoveryCoverageV1],
        inputs: &[DiscoveryCoverageV1],
    ) -> Result<()> {
        let mut used = BTreeSet::new();
        for range in output {
            let mut sources: Vec<_> = inputs
                .iter()
                .enumerate()
                .filter(|(_, source)| {
                    source.stream == range.stream
                        && source.cpu_id == range.cpu_id
                        && source.coverage_interval_id == range.coverage_interval_id
                        && source.coverage_revision == range.coverage_revision
                        && source.first_cursor >= range.first_cursor
                        && source.last_cursor <= range.last_cursor
                })
                .collect();
            sources.sort_by_key(|(_, source)| source.first_cursor);
            require(
                !sources.is_empty()
                    && sources[0].1.first_cursor == range.first_cursor
                    && sources
                        .last()
                        .is_some_and(|(_, source)| source.last_cursor == range.last_cursor)
                    && sources.windows(2).all(|pair| {
                        pair[0].1.last_cursor.checked_add(1) == Some(pair[1].1.first_cursor)
                    })
                    && sources
                        .iter()
                        .map(|(_, source)| source.expected_records)
                        .sum::<u64>()
                        == range.expected_records,
                "analysis coverage ranges",
            )?;
            for (index, source) in sources {
                require(
                    used.insert(index)
                        && Self::coverage_rank(range.state) <= Self::coverage_rank(source.state)
                        && source
                            .gap_reasons
                            .iter()
                            .all(|reason| range.gap_reasons.contains(reason)),
                    "analysis coverage proof",
                )?;
            }
        }
        Ok(require(
            used.len() == inputs.len(),
            "analysis coverage inputs",
        )?)
    }

    fn coverage_rank(state: DiscoveryCoverageStateV1) -> u8 {
        match state {
            DiscoveryCoverageStateV1::Gapped => 0,
            DiscoveryCoverageStateV1::Unknown => 1,
            DiscoveryCoverageStateV1::Closed => 2,
            DiscoveryCoverageStateV1::Healthy => 3,
        }
    }
}
