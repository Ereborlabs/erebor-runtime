use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::{Coverage, CoverageState, Discovery, Lifecycle, LifecycleState};

impl Discovery {
    pub(super) fn merge_coverage(mut ranges: Vec<Coverage>) -> sdk::Result<Vec<Coverage>> {
        ranges.sort_by(|left, right| {
            (&left.source, left.cpu, left.first).cmp(&(&right.source, right.cpu, right.first))
        });
        let mut output: Vec<Coverage> = Vec::new();
        for range in ranges {
            if let Some(previous) = output.last_mut() {
                if previous.source == range.source && previous.cpu == range.cpu {
                    Self::same(previous.last < range.first, "snapshot overlap")?;
                    if previous.last.checked_add(1) == Some(range.first)
                        && previous.revision == range.revision
                        && previous.interval == range.interval
                    {
                        previous.last = range.last;
                        Self::add(&mut previous.expected, range.expected)?;
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
                        previous.gaps.extend(range.gaps);
                        previous.gaps.sort();
                        previous.gaps.dedup();
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
            Self::require(entry.case < 9, "lifecycle case")?;
            let state = cases.entry(entry.case).or_insert(LifecycleState::Missing);
            match (state, entry.state) {
                (state @ LifecycleState::Missing, incoming) => *state = incoming,
                (_, LifecycleState::Missing) => {}
                (LifecycleState::Recorded(records), LifecycleState::Recorded(incoming)) => {
                    records.extend(incoming);
                    records.sort();
                    records.dedup();
                    Self::require(records.len() <= 64, "lifecycle records")?;
                }
                (state, incoming) => Self::same(*state == incoming, "lifecycle state")?,
            }
        }
        Ok((0..9)
            .map(|case| {
                let mut state = cases.remove(&case).unwrap_or(LifecycleState::Missing);
                if let LifecycleState::Recorded(records) = &mut state {
                    records.sort();
                }
                Lifecycle { case, state }
            })
            .collect())
    }
}
