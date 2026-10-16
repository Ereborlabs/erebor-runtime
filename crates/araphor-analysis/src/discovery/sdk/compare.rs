use araphor_analysis_builtins::discovery as builtin;

use super::{Adapter, Result};
use crate::*;

impl DiscoveryOwner {
    pub fn compare(
        current: &BehaviorSnapshotV1,
        baseline: &DiscoveryReviewedBaselineV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<DiscoveryComparisonV1> {
        current.validate()?;
        baseline.snapshot.validate()?;
        let execution = execution.snapshot(current.tenant_id)?;
        crate::discovery::model::require(
            !baseline.reviewer.is_empty()
                && baseline.reviewer.len() <= 256
                && baseline.reviewed_utc_ns > 0
                && baseline.forbidden.len() <= MAX_DISCOVERY_ATOMS,
            "reviewed baseline",
        )?;
        crate::discovery::model::same(
            current.tenant_id == baseline.snapshot.tenant_id,
            "baseline tenant",
        )?;
        let current_groups = Self::display_groups(current, &execution)?;
        let previous = Self::display_groups(&baseline.snapshot, &execution)?;
        let mut groups = Vec::new();
        for (side, values) in [&current_groups, &previous].into_iter().enumerate() {
            for group in values {
                groups.push(builtin::Side {
                    side: side as u8,
                    value: group.clone(),
                });
            }
        }
        let mut resources = Vec::new();
        let mut states = Vec::new();
        for (side, snapshot) in [current, &baseline.snapshot].into_iter().enumerate() {
            for atom in &snapshot.atoms {
                let key = &atom.key;
                resources.push(builtin::Side {
                    side: side as u8,
                    value: key.clone(),
                });
            }
            states.push(builtin::MatchState {
                coverage: snapshot.coverage.clone(),
                lifecycle: snapshot.lifecycle.clone(),
            });
        }
        let output = Adapter::run(
            &execution,
            current.tenant_id,
            "compare",
            vec![
                Adapter::dataset("groups", &groups)?,
                Adapter::dataset("resources", &resources)?,
                Adapter::dataset("states", &states)?,
                Adapter::dataset("forbidden", &baseline.forbidden)?,
            ],
            Adapter::revision(&(current, baseline))?,
        )?;
        let mut rows = Adapter::output::<DiscoveryComparisonV1>(&output.output, "comparison")?;
        crate::discovery::model::require(rows.len() == 1, "analysis comparison")?;
        let result = rows.remove(0);
        Adapter::validate_comparison(
            current,
            &baseline.snapshot,
            &current_groups,
            &previous,
            &result,
        )?;
        Ok(result)
    }
}

impl Adapter {
    pub(super) fn validate_comparison(
        current: &BehaviorSnapshotV1,
        previous: &BehaviorSnapshotV1,
        groups: &[BehaviorDisplayGroupV1],
        prior: &[BehaviorDisplayGroupV1],
        result: &DiscoveryComparisonV1,
    ) -> Result<()> {
        crate::discovery::model::require(
            Self::comparison_state(
                &result.coverage_before,
                &result.coverage_after,
                &previous.coverage,
                &current.coverage,
            ) && Self::comparison_state(
                &result.lifecycle_before,
                &result.lifecycle_after,
                &previous.lifecycle,
                &current.lifecycle,
            ),
            "analysis comparison proof",
        )?;
        for (groups, input) in [
            (&result.added, groups),
            (&result.removed, prior),
            (&result.forbidden_groups, groups),
        ] {
            crate::discovery::model::require(
                groups.iter().all(|group| input.contains(group)),
                "analysis group reference",
            )?;
        }
        for change in result
            .changed_counts
            .iter()
            .chain(&result.changed_results)
            .chain(&result.changed_identities)
        {
            crate::discovery::model::require(
                prior.contains(&change.before) && groups.contains(&change.after),
                "analysis group reference",
            )?;
        }
        crate::discovery::model::require(
            result
                .new_resources
                .iter()
                .all(|key| current.atoms.iter().any(|atom| &atom.key == key)),
            "analysis resource reference",
        )?;
        Ok(())
    }

    fn comparison_state<T: Eq>(before: &[T], after: &[T], previous: &[T], current: &[T]) -> bool {
        if before.is_empty() && after.is_empty() {
            previous == current
        } else {
            before == previous && after == current
        }
    }
}
