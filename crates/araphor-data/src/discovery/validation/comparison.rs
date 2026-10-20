use super::*;

impl BehaviorSnapshotV1 {
    pub fn validate_comparison(
        &self,
        previous: &BehaviorSnapshotV1,
        groups: &[BehaviorDisplayGroupV1],
        prior: &[BehaviorDisplayGroupV1],
        result: &DiscoveryComparisonV1,
    ) -> Result<()> {
        self.validate_groups(groups)?;
        previous.validate_groups(prior)?;
        let current = self;
        require(
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
            require(
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
            require(
                prior.contains(&change.before) && groups.contains(&change.after),
                "analysis group reference",
            )?;
        }
        require(
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
