use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;

use super::{Comparison, Discovery, MatchGroup, MatchState, Side};

impl Discovery {
    pub(super) fn compare(input: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let groups = Self::read::<MatchGroup>(input, "groups")?;
        let forbidden = Self::read::<String>(input, "forbidden")?;
        let states = Self::read::<MatchState>(input, "states")?;
        Self::require(states.len() == 2, "comparison states")?;
        let mut current = Vec::new();
        let mut previous = Vec::new();
        for group in &groups {
            Self::require(group.side < 2, "snapshot side")?;
            if group.side == 0 {
                current.push(group);
            } else {
                previous.push(group);
            }
        }
        let old: BTreeMap<_, _> = previous
            .iter()
            .enumerate()
            .map(|(i, row)| (&row.key, i))
            .collect();
        let new: BTreeMap<_, _> = current
            .iter()
            .enumerate()
            .map(|(i, row)| (&row.key, i))
            .collect();
        let mut outcomes = BTreeMap::<_, Vec<_>>::new();
        let mut identities = BTreeMap::<_, Vec<_>>::new();
        for (index, group) in previous.iter().enumerate() {
            outcomes.entry(&group.outcome).or_default().push(index);
            identities.entry(&group.identity).or_default().push(index);
        }
        let mut result = Comparison {
            removed: previous
                .iter()
                .enumerate()
                .filter_map(|(i, row)| (!new.contains_key(&row.key)).then_some(i as u64))
                .collect(),
            coverage_changed: states[0].coverage != states[1].coverage,
            lifecycle_changed: states[0].lifecycle != states[1].lifecycle,
            ..Comparison::default()
        };
        let mut remaining = input.context.limits.max_bytes;
        Self::charge_refs(&mut remaining, result.removed.len(), 8)?;
        for (index, group) in current.iter().enumerate() {
            if let Some(&before) = old.get(&group.key) {
                if previous[before].count != group.count {
                    Self::charge_refs(&mut remaining, 1, 16)?;
                    result.counts.push((before as u64, index as u64));
                }
            } else {
                Self::charge_refs(&mut remaining, 1, 8)?;
                result.added.push(index as u64);
                if let Some(matches) = outcomes.get(&group.outcome) {
                    Self::charge_refs(&mut remaining, matches.len(), 16)?;
                    for &before in matches {
                        result.outcomes.push((before as u64, index as u64));
                    }
                }
                if let Some(matches) = identities.get(&group.identity) {
                    for &before in matches {
                        if previous[before].revision != group.revision {
                            Self::charge_refs(&mut remaining, 1, 16)?;
                            result.identities.push((before as u64, index as u64));
                        }
                    }
                }
            }
            if forbidden.contains(&group.policy) {
                Self::charge_refs(&mut remaining, 1, 8)?;
                result.forbidden.push(index as u64);
            }
        }
        let resources = Self::read::<Side<String>>(input, "resources")?;
        for row in &resources {
            Self::require(row.side < 2, "snapshot side")?;
        }
        let old: BTreeSet<_> = resources
            .iter()
            .filter(|row| row.side == 1)
            .map(|row| &row.value)
            .collect();
        result.resources = resources
            .iter()
            .filter(|row| row.side == 0)
            .enumerate()
            .filter_map(|(index, row)| (!old.contains(&row.value)).then_some(index as u64))
            .collect();
        Ok(sdk::Output {
            datasets: vec![Self::write(input, "comparison", &[result])?],
            ..sdk::Output::default()
        })
    }

    fn charge_refs(remaining: &mut u64, count: usize, width: u64) -> sdk::Result<()> {
        *remaining = (count as u64)
            .checked_mul(width)
            .and_then(|bytes| remaining.checked_sub(bytes))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "comparison references"))?;
        Ok(())
    }
}
