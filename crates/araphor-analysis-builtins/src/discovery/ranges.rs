use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::{
    Discovery, DiscoveryCoverageStateV1 as CoverageState, DiscoveryCoverageV1 as Coverage,
    DiscoveryLifecycleCaseV1, DiscoveryLifecycleEntryV1 as Lifecycle,
    DiscoveryLifecycleStateV1 as LifecycleState,
};

impl Discovery {
    pub(super) fn merge_coverage(mut ranges: Vec<Coverage>) -> sdk::Result<Vec<Coverage>> {
        ranges.sort_by(|left, right| {
            (&left.stream, left.cpu_id, left.first_cursor).cmp(&(
                &right.stream,
                right.cpu_id,
                right.first_cursor,
            ))
        });
        let mut output: Vec<Coverage> = Vec::new();
        for range in ranges {
            if let Some(previous) = output.last_mut() {
                if previous.stream == range.stream && previous.cpu_id == range.cpu_id {
                    Self::same(
                        previous.last_cursor < range.first_cursor,
                        "snapshot overlap",
                    )?;
                    if previous.last_cursor.checked_add(1) == Some(range.first_cursor)
                        && previous.coverage_revision == range.coverage_revision
                        && previous.coverage_interval_id == range.coverage_interval_id
                    {
                        previous.last_cursor = range.last_cursor;
                        Self::add(&mut previous.expected_records, range.expected_records)?;
                        previous.state = match (previous.state, range.state) {
                            (CoverageState::Gapped, _) | (_, CoverageState::Gapped) => {
                                CoverageState::Gapped
                            }
                            (CoverageState::Unknown, _) | (_, CoverageState::Unknown) => {
                                CoverageState::Unknown
                            }
                            (CoverageState::Closed, _) | (_, CoverageState::Closed) => {
                                CoverageState::Closed
                            }
                            _ => CoverageState::Healthy,
                        };
                        previous.gap_reasons.extend(range.gap_reasons);
                        previous.gap_reasons.sort();
                        previous.gap_reasons.dedup();
                        continue;
                    }
                }
            }
            output.push(range);
        }
        Ok(output)
    }

    pub(super) fn merge_lifecycle(input: Vec<Lifecycle>) -> sdk::Result<Vec<Lifecycle>> {
        let mut cases = BTreeMap::new();
        for entry in input {
            let state = cases.entry(entry.case).or_insert(LifecycleState::Missing);
            match (state, entry.state) {
                (state @ LifecycleState::Missing, incoming) => *state = incoming,
                (_, LifecycleState::Missing) => {}
                (
                    LifecycleState::Recorded { records },
                    LifecycleState::Recorded { records: incoming },
                ) => {
                    records.extend(incoming);
                    records.sort();
                    records.dedup();
                }
                (state, incoming) => Self::same(*state == incoming, "lifecycle state")?,
            }
        }
        Ok(DiscoveryLifecycleCaseV1::ALL
            .into_iter()
            .map(|case| {
                let mut state = cases.remove(&case).unwrap_or(LifecycleState::Missing);
                if let LifecycleState::Recorded { records } = &mut state {
                    records.sort();
                }
                Lifecycle { case, state }
            })
            .collect())
    }
}
