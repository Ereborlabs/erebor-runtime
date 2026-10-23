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
        for group in &current {
            if let Some(&before) = old.get(&group.key) {
                if previous[before].count != group.count {
                    result.changed_counts.push(DiscoveryGroupChangeV1 {
                        before: (*previous[before]).clone(),
                        after: (**group).clone(),
                    });
                }
            } else {
                result.added.push((**group).clone());
                if let Some(matches) = outcomes.get(&group.key.outcome()) {
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
                            result.changed_identities.push(DiscoveryGroupChangeV1 {
                                before: (*previous[before]).clone(),
                                after: (**group).clone(),
                            });
                        }
                    }
                }
            }
            if forbidden.contains(&group.key.static_key) {
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
}
