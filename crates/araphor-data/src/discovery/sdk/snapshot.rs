use araphor_analysis_builtins::discovery as builtin;
use araphor_analysis_sdk as sdk;

use super::{Adapter, Result};
use crate::*;

impl BehaviorSnapshotV1 {
    pub fn merge(&self, next: &Self, execution: &crate::InstalledAnalysis) -> Result<Self> {
        self.validate()?;
        next.validate()?;
        self.merge_control(
            next,
            execution,
            &Adapter::revision(&(self, next))?,
            &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(60))?,
        )
    }

    // Both callers validate the snapshots before this call.
    pub(super) fn merge_control(
        &self,
        next: &Self,
        execution: &crate::InstalledAnalysis,
        revision: &str,
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        control.check()?;
        let snapshots = [self, next];
        let metadata = snapshots.map(Adapter::metadata);
        let atoms = Adapter::sides(&snapshots, |snapshot| &snapshot.atoms);
        let coverage = Adapter::sides(&snapshots, |snapshot| &snapshot.coverage);
        let unresolved = Adapter::sides(&snapshots, |snapshot| &snapshot.unresolved);
        let excluded = Adapter::sides(&snapshots, |snapshot| &snapshot.excluded);
        let lifecycle = Adapter::sides(&snapshots, |snapshot| &snapshot.lifecycle);
        let output = Adapter::run_control(
            execution,
            self.tenant_id,
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
            self.tenant_id,
            self.source_revision.clone(),
            self.proof_kind,
        )?
        .snapshot;
        Adapter::validate_merge(self, next, &snapshot)?;
        control.check()?;
        Ok(snapshot)
    }

    pub fn display_groups(
        &self,
        execution: &crate::InstalledAnalysis,
    ) -> Result<Vec<BehaviorDisplayGroupV1>> {
        self.validate()?;
        let output = Adapter::run(
            execution,
            self.tenant_id,
            "groups",
            vec![
                Adapter::dataset("atoms", &self.atoms)?,
                Adapter::dataset("coverage", &self.coverage)?,
            ],
            Adapter::revision(self)?,
        )?;
        let mut groups = Adapter::output::<BehaviorDisplayGroupV1>(&output.output, "groups")?;
        groups.sort_by(|left, right| left.key.cmp(&right.key));
        Adapter::validate_groups(self, &groups)?;
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
