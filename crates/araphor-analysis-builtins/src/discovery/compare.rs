use std::collections::{BTreeMap, BTreeSet};

use crate::Rows;
use araphor_analysis_sdk as sdk;

use super::{
    BehaviorAtomKeyV1, BehaviorDisplayGroupV1, Discovery, DiscoveryComparisonV1 as Comparison,
    DiscoveryGroupChangeV1, DiscoveryPolicyKeyV1, MatchState, Side,
};

impl Discovery {
    pub(super) fn compare(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let groups = Rows::input::<Side<BehaviorDisplayGroupV1>>(input, "groups")?;
        let forbidden = Rows::input::<DiscoveryPolicyKeyV1>(input, "forbidden")?;
        let states = Rows::input::<MatchState>(input, "states")?;
        Self::require(states.len() == 2, "comparison states")?;
        let mut current = Vec::new();
        let mut previous = Vec::new();
        for group in &groups {
            Self::require(group.side < 2, "snapshot side")?;
            if group.side == 0 {
                current.push(&group.value);
            } else {
                previous.push(&group.value);
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
            outcomes.entry(group.key.outcome()).or_default().push(index);
            identities
                .entry(group.key.identity())
                .or_default()
                .push(index);
        }
        let mut result = Comparison {
            removed: previous
                .iter()
                .filter(|row| !new.contains_key(&row.key))
                .map(|row| (**row).clone())
                .collect(),
            ..Comparison::default()
        };
        if states[0].coverage != states[1].coverage {
            result.coverage_before = states[1].coverage.clone();
            result.coverage_after = states[0].coverage.clone();
        }
        if states[0].lifecycle != states[1].lifecycle {
            result.lifecycle_before = states[1].lifecycle.clone();
            result.lifecycle_after = states[0].lifecycle.clone();
        }
        let mut remaining = input.evaluation().context.limits.max_bytes;
        Self::charge_refs(&mut remaining, result.removed.len(), 8)?;
        for group in &current {
            if let Some(&before) = old.get(&group.key) {
                if previous[before].count != group.count {
                    Self::charge_refs(&mut remaining, 1, 16)?;
                    result.changed_counts.push(DiscoveryGroupChangeV1 {
                        before: (*previous[before]).clone(),
                        after: (**group).clone(),
                    });
                }
            } else {
                Self::charge_refs(&mut remaining, 1, 8)?;
                result.added.push((**group).clone());
                if let Some(matches) = outcomes.get(&group.key.outcome()) {
                    Self::charge_refs(&mut remaining, matches.len(), 16)?;
                    for &before in matches {
                        result.changed_results.push(DiscoveryGroupChangeV1 {
                            before: (*previous[before]).clone(),
                            after: (**group).clone(),
                        });
                    }
                }
                if let Some(matches) = identities.get(&group.key.identity()) {
                    for &before in matches {
                        if previous[before].key.revision() != group.key.revision() {
                            Self::charge_refs(&mut remaining, 1, 16)?;
                            result.changed_identities.push(DiscoveryGroupChangeV1 {
                                before: (*previous[before]).clone(),
                                after: (**group).clone(),
                            });
                        }
                    }
                }
            }
            if forbidden.contains(&group.key.static_key) {
                Self::charge_refs(&mut remaining, 1, 8)?;
                result.forbidden_groups.push((**group).clone());
            }
        }
        let resources = Rows::input::<Side<BehaviorAtomKeyV1>>(input, "resources")?;
        for row in &resources {
            Self::require(row.side < 2, "snapshot side")?;
        }
        let old: BTreeSet<_> = resources
            .iter()
            .filter(|row| row.side == 1)
            .map(|row| row.value.resource())
            .collect();
        result.new_resources = resources
            .iter()
            .filter(|row| row.side == 0)
            .filter(|row| !old.contains(&row.value.resource()))
            .map(|row| row.value.clone())
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
