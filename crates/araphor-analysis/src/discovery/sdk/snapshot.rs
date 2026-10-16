use araphor_analysis_builtins::discovery as builtin;
use araphor_analysis_sdk as sdk;

use super::{Adapter, Result};
use crate::*;

impl DiscoveryOwner {
    pub fn merge(
        current: &BehaviorSnapshotV1,
        next: &BehaviorSnapshotV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<BehaviorSnapshotV1> {
        current.validate()?;
        next.validate()?;
        Self::merge_control(
            current,
            next,
            execution,
            &Adapter::revision(&(current, next))?,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(60))?,
        )
    }

    // Both callers validate the snapshots before this call.
    pub(super) fn merge_control(
        current: &BehaviorSnapshotV1,
        next: &BehaviorSnapshotV1,
        execution: &crate::InstalledAnalysis,
        revision: &str,
        control: &AnalysisReadControl,
    ) -> Result<BehaviorSnapshotV1> {
        control.check()?;
        let snapshots = [current, next];
        let metadata = snapshots.map(Adapter::metadata);
        let atoms = Adapter::sides(&snapshots, |snapshot| &snapshot.atoms);
        let coverage = Adapter::sides(&snapshots, |snapshot| &snapshot.coverage);
        let unresolved = Adapter::sides(&snapshots, |snapshot| &snapshot.unresolved);
        let excluded = Adapter::sides(&snapshots, |snapshot| &snapshot.excluded);
        let lifecycle = Adapter::sides(&snapshots, |snapshot| &snapshot.lifecycle);
        let output = Adapter::run_control(
            execution,
            current.tenant_id,
            "merge",
            vec![
                Adapter::dataset("snapshots", &metadata)?,
                Adapter::dataset("atoms", &atoms)?,
                Adapter::dataset("coverage", &coverage)?,
                Adapter::dataset("unresolved", &unresolved)?,
                Adapter::dataset("excluded", &excluded)?,
                Adapter::dataset("lifecycle", &lifecycle)?,
            ],
            revision.into(),
            control,
        )?;
        let snapshot = Adapter::snapshot(
            &output.output,
            current.tenant_id,
            current.source_revision.clone(),
            current.proof_kind,
        )?
        .snapshot;
        Adapter::validate_merge(current, next, &snapshot)?;
        control.check()?;
        Ok(snapshot)
    }

    pub fn display_groups(
        current: &BehaviorSnapshotV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<Vec<BehaviorDisplayGroupV1>> {
        current.validate()?;
        let output = Adapter::run(
            execution,
            current.tenant_id,
            "groups",
            vec![
                Adapter::dataset("atoms", &current.atoms)?,
                Adapter::dataset("coverage", &current.coverage)?,
            ],
            Adapter::revision(current)?,
        )?;
        let mut groups = Adapter::output::<BehaviorDisplayGroupV1>(&output.output, "groups")?;
        groups.sort_by(|left, right| left.key.cmp(&right.key));
        Adapter::validate_groups(current, &groups)?;
        Ok(groups)
    }
}

impl Adapter {
    fn metadata(snapshot: &BehaviorSnapshotV1) -> builtin::Snapshot {
        builtin::Snapshot {
            tenant_id: snapshot.tenant_id,
            source_revision: snapshot.source_revision.clone(),
            proof_kind: snapshot.proof_kind,
            counts: builtin::Counts {
                duplicates: 0,
                accepted: snapshot.accepted_records,
                included: snapshot.included_records,
                unresolved: snapshot.unresolved_records,
                excluded: snapshot.excluded_records,
            },
        }
    }

    fn sides<T: Clone>(
        snapshots: &[&BehaviorSnapshotV1; 2],
        project: impl Fn(&BehaviorSnapshotV1) -> &[T],
    ) -> Vec<builtin::Side<T>> {
        snapshots
            .iter()
            .enumerate()
            .flat_map(|(side, snapshot)| {
                project(snapshot)
                    .iter()
                    .cloned()
                    .map(move |value| builtin::Side {
                        side: side as u8,
                        value,
                    })
            })
            .collect()
    }

    pub(super) fn snapshot(
        output: &sdk::Output,
        tenant_id: [u8; 16],
        source_revision: String,
        proof_kind: DiscoveryProofKindV1,
    ) -> Result<DiscoveryRecordedResultV1> {
        let mut counts = Self::output::<builtin::Counts>(output, "counts")?;
        crate::discovery::model::require(counts.len() == 1, "analysis counts")?;
        let counts = counts.remove(0);
        let mut snapshot = BehaviorSnapshotV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id,
            source_revision,
            proof_kind,
            accepted_records: counts.accepted,
            included_records: counts.included,
            unresolved_records: counts.unresolved,
            excluded_records: counts.excluded,
            atoms: Self::output(output, "atoms")?,
            coverage: Self::output(output, "coverage")?,
            unresolved: Self::output(output, "unresolved")?,
            excluded: Self::output(output, "excluded")?,
            lifecycle: Self::output(output, "lifecycle")?,
        };
        snapshot
            .atoms
            .sort_by(|left, right| left.key.cmp(&right.key));
        snapshot.coverage.sort();
        snapshot.validate()?;
        Ok(DiscoveryRecordedResultV1 {
            snapshot,
            duplicate_deliveries: counts.duplicates,
        })
    }
}
