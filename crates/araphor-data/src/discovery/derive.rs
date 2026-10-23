use std::collections::BTreeSet;

use super::model::{add, require};
use super::*;
use crate::Result;

impl BehaviorSnapshotV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION,
            "snapshot schema",
        )?;
        require(
            self.tenant_id != [0; 16]
                && !self.source_revision.is_empty()
                && self.source_revision.len() <= 128
                && self.unresolved_records == self.unresolved.len() as u64
                && self.excluded_records == self.excluded.len() as u64,
            "snapshot bounds",
        )?;
        require(
            self.included_records
                .checked_add(self.unresolved_records)
                .and_then(|count| count.checked_add(self.excluded_records))
                == Some(self.accepted_records),
            "snapshot accounting",
        )?;
        let mut included = 0;
        let mut records = BTreeSet::new();
        for atom in &self.atoms {
            atom.key.validate()?;
            add(&mut included, atom.count)?;
            require(
                atom.count > 0
                    && atom.first_cursor > 0
                    && atom.last_cursor >= atom.first_cursor
                    && atom.count <= atom.last_cursor - atom.first_cursor + 1
                    && !atom.evidence_sample.is_empty()
                    && atom.evidence_sample.len() as u64 <= atom.count
                    && atom.key.proof_kind == self.proof_kind
                    && atom.key.stream.tenant_id == self.tenant_id
                    && atom
                        .evidence_sample
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && atom.evidence_sample.iter().all(|id| {
                        id.stream == atom.key.stream
                            && id.cpu_id == atom.key.cpu_id
                            && id.durable_cursor >= atom.first_cursor
                            && id.durable_cursor <= atom.last_cursor
                            && records.insert(id)
                            && self.coverage.iter().any(|range| {
                                range.stream == id.stream
                                    && range.cpu_id == id.cpu_id
                                    && range.coverage_interval_id == atom.key.coverage_interval_id
                                    && range.first_cursor <= id.durable_cursor
                                    && id.durable_cursor <= range.last_cursor
                            })
                    }),
                "snapshot atom",
            )?;
        }
        require(included == self.included_records, "snapshot atom count")?;
        require(
            self.atoms.windows(2).all(|pair| pair[0].key < pair[1].key),
            "snapshot atom order",
        )?;
        for range in &self.coverage {
            range.validate()?;
            require(
                range.stream.tenant_id == self.tenant_id,
                "snapshot range tenant",
            )?;
        }
        require(
            self.coverage.windows(2).all(|pair| {
                pair[0] < pair[1]
                    && (pair[0].stream != pair[1].stream
                        || pair[0].cpu_id != pair[1].cpu_id
                        || pair[0].last_cursor < pair[1].first_cursor)
            }),
            "snapshot range order",
        )?;
        for item in self.unresolved.iter().chain(&self.excluded) {
            item.record_id.validate()?;
            require(
                !item.reason.is_empty()
                    && item.reason.len() <= 128
                    && item.record_id.stream.tenant_id == self.tenant_id
                    && records.insert(&item.record_id),
                "snapshot disposition",
            )?;
            require(
                self.coverage.iter().any(|range| {
                    range.stream == item.record_id.stream
                        && range.cpu_id == item.record_id.cpu_id
                        && range.first_cursor <= item.record_id.durable_cursor
                        && item.record_id.durable_cursor <= range.last_cursor
                }),
                "snapshot disposition range",
            )?;
        }
        require(
            self.unresolved
                .windows(2)
                .all(|pair| pair[0].record_id < pair[1].record_id)
                && self
                    .excluded
                    .windows(2)
                    .all(|pair| pair[0].record_id < pair[1].record_id),
            "snapshot disposition order",
        )?;
        for entry in &self.lifecycle {
            match &entry.state {
                DiscoveryLifecycleStateV1::Recorded { records } => {
                    require(
                        !records.is_empty() && records.windows(2).all(|pair| pair[0] < pair[1]),
                        "snapshot lifecycle records",
                    )?;
                    for id in records {
                        id.validate()?;
                        require(
                            id.stream.tenant_id == self.tenant_id
                                && self.coverage.iter().any(|range| {
                                    range.stream == id.stream
                                        && range.cpu_id == id.cpu_id
                                        && range.first_cursor <= id.durable_cursor
                                        && id.durable_cursor <= range.last_cursor
                                }),
                            "snapshot lifecycle range",
                        )?;
                    }
                }
                DiscoveryLifecycleStateV1::Declared { reason }
                | DiscoveryLifecycleStateV1::NotApplicable { reason }
                | DiscoveryLifecycleStateV1::Unsupported { reason } => require(
                    !reason.is_empty() && reason.len() <= 128,
                    "snapshot lifecycle reason",
                )?,
                DiscoveryLifecycleStateV1::Missing => {}
            }
        }
        require(
            self.lifecycle.len() == DiscoveryLifecycleCaseV1::ALL.len()
                && self
                    .lifecycle
                    .iter()
                    .map(|entry| entry.case)
                    .eq(DiscoveryLifecycleCaseV1::ALL),
            "snapshot lifecycle",
        )
    }
}
