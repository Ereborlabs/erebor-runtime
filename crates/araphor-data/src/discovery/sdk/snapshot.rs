use araphor_analysis_builtins::discovery as builtin;
use araphor_analysis_sdk as sdk;

use super::{Adapter, Result};
use crate::*;

impl BehaviorSnapshotV1 {
    pub fn merge(&self, next: &Self) -> Result<Self> {
        self.validate()?;
        next.validate()?;
        let adapter = Adapter::new(
            Adapter::references(self)
                .into_iter()
                .chain(Adapter::references(next)),
        );
        let snapshots = [self, next];
        let metadata = snapshots
            .iter()
            .map(|snapshot| Adapter::metadata(snapshot))
            .collect::<Result<Vec<_>>>()?;
        let atoms = Adapter::sides(&snapshots, |snapshot| {
            snapshot.atoms.iter().map(|row| adapter.atom(row)).collect()
        })?;
        let coverage = Adapter::sides(&snapshots, |snapshot| {
            snapshot.coverage.iter().map(Adapter::coverage).collect()
        })?;
        let unresolved = Adapter::sides(&snapshots, |snapshot| {
            snapshot
                .unresolved
                .iter()
                .map(|row| adapter.disposition(row))
                .collect()
        })?;
        let excluded = Adapter::sides(&snapshots, |snapshot| {
            snapshot
                .excluded
                .iter()
                .map(|row| adapter.disposition(row))
                .collect()
        })?;
        let lifecycle = Adapter::sides(&snapshots, |snapshot| {
            snapshot
                .lifecycle
                .iter()
                .map(|row| adapter.lifecycle(row))
                .collect()
        })?;
        let output = Adapter::run(
            "merge",
            vec![
                Adapter::dataset("snapshots", &metadata)?,
                Adapter::dataset("atoms", &atoms)?,
                Adapter::dataset("coverage", &coverage)?,
                Adapter::dataset("unresolved", &unresolved)?,
                Adapter::dataset("excluded", &excluded)?,
                Adapter::dataset("lifecycle", &lifecycle)?,
            ],
            Adapter::revision(&(self, next))?,
        )?;
        Ok(adapter
            .snapshot(
                &output,
                self.tenant_id,
                self.source_revision.clone(),
                self.proof_kind,
            )?
            .snapshot)
    }

    pub fn display_groups(&self) -> Result<Vec<BehaviorDisplayGroupV1>> {
        self.validate()?;
        let adapter = Adapter::new(Adapter::references(self));
        let atoms = self
            .atoms
            .iter()
            .map(|atom| {
                Ok(builtin::GroupAtom {
                    group: Adapter::json(&BehaviorDisplayKeyV1::from(&atom.key))?,
                    source: Adapter::json(&atom.key.stream)?,
                    cpu: atom.key.cpu_id,
                    interval: atom.key.coverage_interval_id,
                    atom: adapter.atom(atom)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let coverage = self
            .coverage
            .iter()
            .map(Adapter::coverage)
            .collect::<Result<Vec<_>>>()?;
        let output = Adapter::run(
            "groups",
            vec![
                Adapter::dataset("atoms", &atoms)?,
                Adapter::dataset("coverage", &coverage)?,
            ],
            Adapter::revision(self)?,
        )?;
        let mut groups = Adapter::output::<builtin::Group>(&output, "groups")?
            .into_iter()
            .map(|row| {
                Ok(BehaviorDisplayGroupV1 {
                    key: Adapter::decode(&row.key)?,
                    count: row.count,
                    members: row
                        .members
                        .into_iter()
                        .map(|index| {
                            Adapter::at(&self.atoms, index, "analysis atom reference")
                                .map(|row| row.key.clone())
                        })
                        .collect::<Result<_>>()?,
                    evidence_sample: row
                        .samples
                        .into_iter()
                        .map(|id| adapter.record(id))
                        .collect::<Result<_>>()?,
                    coverage: row
                        .coverage
                        .into_iter()
                        .map(|index| {
                            Adapter::at(&self.coverage, index, "analysis coverage reference")
                                .cloned()
                        })
                        .collect::<Result<_>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        groups.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(groups)
    }
}

impl Adapter {
    fn metadata(snapshot: &BehaviorSnapshotV1) -> Result<builtin::Snapshot> {
        Ok(builtin::Snapshot {
            identity: Self::json(&(
                snapshot.tenant_id,
                &snapshot.source_revision,
                snapshot.proof_kind,
            ))?,
            counts: builtin::Counts {
                duplicates: 0,
                accepted: snapshot.accepted_records,
                included: snapshot.included_records,
                unresolved: snapshot.unresolved_records,
                excluded: snapshot.excluded_records,
            },
        })
    }

    fn sides<T>(
        snapshots: &[&BehaviorSnapshotV1; 2],
        project: impl Fn(&BehaviorSnapshotV1) -> Result<Vec<T>>,
    ) -> Result<Vec<builtin::Side<T>>> {
        let mut rows = Vec::new();
        for (side, snapshot) in snapshots.iter().enumerate() {
            rows.extend(project(snapshot)?.into_iter().map(|value| builtin::Side {
                side: side as u8,
                value,
            }));
        }
        Ok(rows)
    }

    pub(super) fn snapshot(
        &self,
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
            atoms: Self::output::<builtin::Atom>(output, "atoms")?
                .into_iter()
                .map(|row| self.host_atom(row))
                .collect::<Result<_>>()?,
            coverage: Self::output::<builtin::Coverage>(output, "coverage")?
                .into_iter()
                .map(Self::host_coverage)
                .collect::<Result<_>>()?,
            unresolved: Self::output::<builtin::Disposition>(output, "unresolved")?
                .into_iter()
                .map(|row| self.host_disposition(row))
                .collect::<Result<_>>()?,
            excluded: Self::output::<builtin::Disposition>(output, "excluded")?
                .into_iter()
                .map(|row| self.host_disposition(row))
                .collect::<Result<_>>()?,
            lifecycle: Self::output::<builtin::Lifecycle>(output, "lifecycle")?
                .into_iter()
                .map(|row| self.host_lifecycle(row))
                .collect::<Result<_>>()?,
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
