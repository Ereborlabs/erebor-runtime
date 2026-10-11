use araphor_analysis_builtins::discovery as builtin;

use super::{Adapter, Result};
use crate::*;

impl Adapter {
    pub(super) fn coverage(value: &DiscoveryCoverageV1) -> Result<builtin::Coverage> {
        Ok(builtin::Coverage {
            source: Self::json(&value.stream)?,
            cpu: value.cpu_id,
            first: value.first_cursor,
            last: value.last_cursor,
            expected: value.expected_records,
            revision: value.coverage_revision,
            interval: value.coverage_interval_id,
            state: match value.state {
                DiscoveryCoverageStateV1::Healthy => builtin::CoverageState::Healthy,
                DiscoveryCoverageStateV1::Gapped => builtin::CoverageState::Gapped,
                DiscoveryCoverageStateV1::Unknown => builtin::CoverageState::Unknown,
                DiscoveryCoverageStateV1::Closed => builtin::CoverageState::Closed,
            },
            gaps: value.gap_reasons.clone(),
        })
    }

    pub(super) fn host_coverage(value: builtin::Coverage) -> Result<DiscoveryCoverageV1> {
        Ok(DiscoveryCoverageV1 {
            stream: Self::decode(&value.source)?,
            cpu_id: value.cpu,
            first_cursor: value.first,
            last_cursor: value.last,
            expected_records: value.expected,
            coverage_revision: value.revision,
            coverage_interval_id: value.interval,
            state: match value.state {
                builtin::CoverageState::Healthy => DiscoveryCoverageStateV1::Healthy,
                builtin::CoverageState::Gapped => DiscoveryCoverageStateV1::Gapped,
                builtin::CoverageState::Unknown => DiscoveryCoverageStateV1::Unknown,
                builtin::CoverageState::Closed => DiscoveryCoverageStateV1::Closed,
            },
            gap_reasons: value.gaps,
        })
    }

    pub(super) fn lifecycle(
        &self,
        value: &DiscoveryLifecycleEntryV1,
    ) -> Result<builtin::Lifecycle> {
        Ok(builtin::Lifecycle {
            case: value.case as u8,
            state: match &value.state {
                DiscoveryLifecycleStateV1::Recorded { records } => {
                    builtin::LifecycleState::Recorded(
                        records
                            .iter()
                            .map(|id| self.identity(id))
                            .collect::<Result<_>>()?,
                    )
                }
                DiscoveryLifecycleStateV1::Declared { reason } => {
                    builtin::LifecycleState::Declared(reason.clone())
                }
                DiscoveryLifecycleStateV1::Missing => builtin::LifecycleState::Missing,
                DiscoveryLifecycleStateV1::NotApplicable { reason } => {
                    builtin::LifecycleState::NotApplicable(reason.clone())
                }
                DiscoveryLifecycleStateV1::Unsupported { reason } => {
                    builtin::LifecycleState::Unsupported(reason.clone())
                }
            },
        })
    }

    pub(super) fn host_lifecycle(
        &self,
        value: builtin::Lifecycle,
    ) -> Result<DiscoveryLifecycleEntryV1> {
        let case = DiscoveryLifecycleCaseV1::ALL
            .get(value.case as usize)
            .copied()
            .ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "analysis lifecycle case",
                }
                .build()
            })?;
        Ok(DiscoveryLifecycleEntryV1 {
            case,
            state: match value.state {
                builtin::LifecycleState::Recorded(records) => DiscoveryLifecycleStateV1::Recorded {
                    records: records
                        .into_iter()
                        .map(|id| self.record(id))
                        .collect::<Result<_>>()?,
                },
                builtin::LifecycleState::Declared(reason) => {
                    DiscoveryLifecycleStateV1::Declared { reason }
                }
                builtin::LifecycleState::Missing => DiscoveryLifecycleStateV1::Missing,
                builtin::LifecycleState::NotApplicable(reason) => {
                    DiscoveryLifecycleStateV1::NotApplicable { reason }
                }
                builtin::LifecycleState::Unsupported(reason) => {
                    DiscoveryLifecycleStateV1::Unsupported { reason }
                }
            },
        })
    }

    pub(super) fn disposition(
        &self,
        value: &DiscoveryUnresolvedV1,
    ) -> Result<builtin::Disposition> {
        Ok(builtin::Disposition {
            id: self.identity(&value.record_id)?,
            reason: value.reason.clone(),
        })
    }

    pub(super) fn host_disposition(
        &self,
        value: builtin::Disposition,
    ) -> Result<DiscoveryUnresolvedV1> {
        Ok(DiscoveryUnresolvedV1 {
            record_id: self.record(value.id)?,
            reason: value.reason,
        })
    }

    pub(super) fn atom(&self, value: &BehaviorAtomV1) -> Result<builtin::Atom> {
        Ok(builtin::Atom {
            key: Self::json(&value.key)?,
            count: value.count,
            first: value.first_cursor,
            last: value.last_cursor,
            samples: value
                .evidence_sample
                .iter()
                .map(|id| self.identity(id))
                .collect::<Result<_>>()?,
            prevented: value.key.physical_result == DiscoveryPhysicalResultV1::Prevented,
        })
    }

    pub(super) fn host_atom(&self, value: builtin::Atom) -> Result<BehaviorAtomV1> {
        let mut key: BehaviorAtomKeyV1 = Self::decode(&value.key)?;
        key.physical_result = if value.prevented {
            DiscoveryPhysicalResultV1::Prevented
        } else {
            DiscoveryPhysicalResultV1::Unknown
        };
        Ok(BehaviorAtomV1 {
            key,
            count: value.count,
            first_cursor: value.first,
            last_cursor: value.last,
            evidence_sample: value
                .samples
                .into_iter()
                .map(|id| self.record(id))
                .collect::<Result<_>>()?,
        })
    }

    pub(super) fn references(snapshot: &BehaviorSnapshotV1) -> Vec<&DiscoveryRecordIdV1> {
        snapshot
            .atoms
            .iter()
            .flat_map(|atom| &atom.evidence_sample)
            .chain(
                snapshot
                    .unresolved
                    .iter()
                    .chain(&snapshot.excluded)
                    .map(|item| &item.record_id),
            )
            .chain(
                snapshot
                    .lifecycle
                    .iter()
                    .flat_map(|entry| match &entry.state {
                        DiscoveryLifecycleStateV1::Recorded { records } => records.as_slice(),
                        _ => &[],
                    }),
            )
            .collect()
    }
}
