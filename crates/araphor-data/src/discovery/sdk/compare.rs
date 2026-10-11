use araphor_analysis_builtins::discovery as builtin;

use super::{Adapter, Result};
use crate::*;

impl BehaviorSnapshotV1 {
    pub fn compare(&self, baseline: &DiscoveryReviewedBaselineV1) -> Result<DiscoveryComparisonV1> {
        self.validate()?;
        baseline.snapshot.validate()?;
        crate::discovery::model::require(
            !baseline.reviewer.is_empty()
                && baseline.reviewer.len() <= 256
                && baseline.reviewed_utc_ns > 0
                && baseline.forbidden.len() <= MAX_DISCOVERY_ATOMS,
            "reviewed baseline",
        )?;
        crate::discovery::model::same(
            self.tenant_id == baseline.snapshot.tenant_id,
            "baseline tenant",
        )?;
        let current = self.display_groups()?;
        let previous = baseline.snapshot.display_groups()?;
        let mut groups = Vec::new();
        for (side, values) in [&current, &previous].into_iter().enumerate() {
            for group in values {
                groups.push(Adapter::match_group(side as u8, group)?);
            }
        }
        let mut resources = Vec::new();
        let mut states = Vec::new();
        for (side, snapshot) in [self, &baseline.snapshot].into_iter().enumerate() {
            for atom in &snapshot.atoms {
                let key = &atom.key;
                resources.push(builtin::Side {
                    side: side as u8,
                    value: Adapter::json(&(
                        &key.subject_revision,
                        &key.static_key,
                        &key.binding_id,
                        &key.effect.exact_object_id,
                        &key.effect.exact_file_object,
                    ))?,
                });
            }
            states.push(builtin::MatchState {
                coverage: Adapter::json(&snapshot.coverage)?,
                lifecycle: Adapter::json(&snapshot.lifecycle)?,
            });
        }
        let forbidden = baseline
            .forbidden
            .iter()
            .map(Adapter::json)
            .collect::<Result<Vec<_>>>()?;
        let output = Adapter::run(
            "compare",
            vec![
                Adapter::dataset("groups", &groups)?,
                Adapter::dataset("resources", &resources)?,
                Adapter::dataset("states", &states)?,
                Adapter::dataset("forbidden", &forbidden)?,
            ],
            Adapter::revision(&(self, baseline))?,
        )?;
        let mut rows = Adapter::output::<builtin::Comparison>(&output, "comparison")?;
        crate::discovery::model::require(rows.len() == 1, "analysis comparison")?;
        let result = rows.remove(0);
        Ok(DiscoveryComparisonV1 {
            added: Adapter::groups_at(&current, result.added)?,
            removed: Adapter::groups_at(&previous, result.removed)?,
            changed_counts: Adapter::changes(&current, &previous, result.counts)?,
            changed_results: Adapter::changes(&current, &previous, result.outcomes)?,
            changed_identities: Adapter::changes(&current, &previous, result.identities)?,
            new_resources: result
                .resources
                .into_iter()
                .map(|index| {
                    Adapter::at(&self.atoms, index, "analysis resource reference")
                        .map(|atom| atom.key.clone())
                })
                .collect::<Result<_>>()?,
            coverage_before: if result.coverage_changed {
                baseline.snapshot.coverage.clone()
            } else {
                Vec::new()
            },
            coverage_after: if result.coverage_changed {
                self.coverage.clone()
            } else {
                Vec::new()
            },
            lifecycle_before: if result.lifecycle_changed {
                baseline.snapshot.lifecycle.clone()
            } else {
                Vec::new()
            },
            lifecycle_after: if result.lifecycle_changed {
                self.lifecycle.clone()
            } else {
                Vec::new()
            },
            forbidden_groups: Adapter::groups_at(&current, result.forbidden)?,
        })
    }
}

impl Adapter {
    fn match_group(side: u8, group: &BehaviorDisplayGroupV1) -> Result<builtin::MatchGroup> {
        let key = &group.key;
        Ok(builtin::MatchGroup {
            side,
            key: Self::json(key)?,
            outcome: Self::json(&(
                &key.subject_revision,
                &key.image_digest,
                &key.configuration_digest,
                key.role_id,
                key.state_id,
                key.entry_rule_id,
                &key.static_key,
                &key.policy_revision,
                key.proof_kind,
            ))?,
            identity: Self::json(&(
                key.role_id,
                key.state_id,
                key.entry_rule_id,
                &key.static_key,
                key.source_reason,
                key.source_decision,
                key.kernel_result,
                key.physical_result,
                key.proof_kind,
            ))?,
            revision: Self::json(&(
                &key.subject_revision,
                &key.image_digest,
                &key.configuration_digest,
                &key.policy_revision,
            ))?,
            policy: Self::json(&key.static_key)?,
            count: group.count,
        })
    }

    fn group_at(groups: &[BehaviorDisplayGroupV1], index: u64) -> Result<BehaviorDisplayGroupV1> {
        Self::at(groups, index, "analysis group reference").cloned()
    }

    fn groups_at(
        groups: &[BehaviorDisplayGroupV1],
        indices: Vec<u64>,
    ) -> Result<Vec<BehaviorDisplayGroupV1>> {
        indices
            .into_iter()
            .map(|index| Self::group_at(groups, index))
            .collect()
    }

    fn changes(
        current: &[BehaviorDisplayGroupV1],
        previous: &[BehaviorDisplayGroupV1],
        pairs: Vec<(u64, u64)>,
    ) -> Result<Vec<DiscoveryGroupChangeV1>> {
        pairs
            .into_iter()
            .map(|(before, after)| {
                Ok(DiscoveryGroupChangeV1 {
                    before: Self::group_at(previous, before)?,
                    after: Self::group_at(current, after)?,
                })
            })
            .collect()
    }
}
