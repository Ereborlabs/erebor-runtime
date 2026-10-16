use std::collections::BTreeMap;

use crate::Rows;
use araphor_analysis_sdk as sdk;
use serde::de::DeserializeOwned;

use super::{
    BehaviorAtomV1 as Atom, Counts, Discovery, DiscoveryCoverageV1 as Coverage,
    DiscoveryLifecycleEntryV1 as Lifecycle, DiscoveryUnresolvedV1 as Disposition, Side, Snapshot,
};

impl Discovery {
    pub(super) fn merge(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let snapshots = Rows::input::<Snapshot>(input, "snapshots")?;
        Self::require(snapshots.len() == 2, "snapshot count")?;
        Self::same(
            snapshots[0].tenant_id == snapshots[1].tenant_id
                && snapshots[0].source_revision == snapshots[1].source_revision
                && snapshots[0].proof_kind == snapshots[1].proof_kind,
            "snapshot source",
        )?;
        let [left_atoms, right_atoms] = Self::split::<Atom>(input, "atoms")?;
        let [left_ranges, right_ranges] = Self::split::<Coverage>(input, "coverage")?;
        let [left_unresolved, right_unresolved] = Self::split::<Disposition>(input, "unresolved")?;
        let [left_excluded, right_excluded] = Self::split::<Disposition>(input, "excluded")?;
        let [left_lifecycle, right_lifecycle] = Self::split::<Lifecycle>(input, "lifecycle")?;
        let repeated = snapshots[0] == snapshots[1]
            && left_atoms == right_atoms
            && left_ranges == right_ranges
            && left_unresolved == right_unresolved
            && left_excluded == right_excluded
            && left_lifecycle == right_lifecycle;
        let (atoms, coverage, unresolved, excluded, lifecycle, counts) = if repeated {
            (
                left_atoms,
                left_ranges,
                left_unresolved,
                left_excluded,
                left_lifecycle,
                snapshots[0].counts.clone(),
            )
        } else {
            let coverage =
                Self::merge_coverage(left_ranges.into_iter().chain(right_ranges).collect())?;
            let atoms = Self::merge_atoms(left_atoms.into_iter().chain(right_atoms))?;
            let mut unresolved: Vec<_> = left_unresolved
                .into_iter()
                .chain(right_unresolved)
                .collect();
            unresolved.sort_by(|left, right| left.record_id.cmp(&right.record_id));
            let mut excluded: Vec<_> = left_excluded.into_iter().chain(right_excluded).collect();
            excluded.sort_by(|left, right| left.record_id.cmp(&right.record_id));
            let lifecycle =
                Self::merge_lifecycle(left_lifecycle.into_iter().chain(right_lifecycle).collect())?;
            let counts = Self::merge_counts(&snapshots[0].counts, &snapshots[1].counts)?;
            (atoms, coverage, unresolved, excluded, lifecycle, counts)
        };
        Ok(sdk::Output {
            datasets: vec![
                Self::write(input, "atoms", &atoms)?,
                Self::write(input, "coverage", &coverage)?,
                Self::write(input, "unresolved", &unresolved)?,
                Self::write(input, "excluded", &excluded)?,
                Self::write(input, "lifecycle", &lifecycle)?,
                Self::write(input, "counts", &[counts])?,
            ],
            ..sdk::Output::default()
        })
    }

    fn split<T: DeserializeOwned>(
        input: &sdk::CheckedEvaluation<'_>,
        name: &str,
    ) -> sdk::Result<[Vec<T>; 2]> {
        let mut output = [Vec::new(), Vec::new()];
        for row in Rows::input::<Side<T>>(input, name)? {
            Self::require(row.side < 2, "snapshot side")?;
            output[row.side as usize].push(row.value);
        }
        Ok(output)
    }

    fn merge_atoms(rows: impl Iterator<Item = Atom>) -> sdk::Result<Vec<Atom>> {
        let mut atoms = BTreeMap::<super::BehaviorAtomKeyV1, Atom>::new();
        for row in rows {
            if let Some(known) = atoms.get_mut(&row.key) {
                Self::add(&mut known.count, row.count)?;
                known.first_cursor = known.first_cursor.min(row.first_cursor);
                known.last_cursor = known.last_cursor.max(row.last_cursor);
                known.evidence_sample.extend(row.evidence_sample);
                known.evidence_sample.sort();
                known.evidence_sample.dedup();
                known.evidence_sample.truncate(8);
            } else {
                atoms.insert(row.key.clone(), row);
            }
        }
        Ok(atoms.into_values().collect())
    }

    fn merge_counts(left: &Counts, right: &Counts) -> sdk::Result<Counts> {
        let mut value = left.clone();
        Self::add(&mut value.accepted, right.accepted)?;
        Self::add(&mut value.included, right.included)?;
        Self::add(&mut value.unresolved, right.unresolved)?;
        Self::add(&mut value.excluded, right.excluded)?;
        Ok(value)
    }
}
