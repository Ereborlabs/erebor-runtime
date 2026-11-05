use std::collections::BTreeMap;

use crate::analysis::graph_rows::store::source::EvidenceIntakeIdentityV1;
use crate::analysis::graph_rows::store::values::{Observation, TemporalCoverageV1};

use crate::analysis::graph_rows::store::{GraphFactV1, GraphFactValueV1};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputProof {
    source: EvidenceIntakeIdentityV1,
    first: u64,
    last: u64,
    groups: BTreeMap<(u32, [u8; 16]), SequenceProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SequenceProof {
    first: u64,
    last: u64,
    count: u64,
}

impl InputProof {
    pub fn new(source: EvidenceIntakeIdentityV1, first: u64, last: u64) -> Self {
        Self {
            source,
            first,
            last,
            groups: BTreeMap::new(),
        }
    }

    pub fn scope(&self, source: &EvidenceIntakeIdentityV1, first: u64, last: u64) -> bool {
        self.source == *source && self.first == first && self.last <= last
    }

    pub fn extend_window(&mut self, last: u64) {
        self.last = last;
    }

    pub fn add_record(&mut self, row: &Observation, interval: [u8; 16]) -> bool {
        self.add_position(&row.id, row.original_kernel_sequence,
            row.proof_quality.temporal_coverage == TemporalCoverageV1::Complete, interval)
    }

    pub fn add_position(
        &mut self, record: &crate::DiscoveryRecordIdV1, sequence: Option<u64>,
        complete: bool, interval: [u8; 16],
    ) -> bool {
        let Some(sequence) = sequence.filter(|sequence| *sequence != 0)
        else {
            return false;
        };
        if record.stream != self.source
            || interval == [0; 16]
            || !(self.first..=self.last).contains(&record.durable_cursor)
            || !complete
        {
            return false;
        }
        let group = self
            .groups
            .entry((record.cpu_id, interval))
            .or_insert(SequenceProof {
                first: sequence,
                last: sequence,
                count: 0,
            });
        group.first = group.first.min(sequence);
        group.last = group.last.max(sequence);
        let Some(count) = group.count.checked_add(1) else {
            return false;
        };
        group.count = count;
        true
    }

    pub fn boundaries(&self) -> impl Iterator<Item = (u32, [u8; 16], u64)> + '_ {
        self.groups.iter().flat_map(|(&(cpu, interval), group)| {
            std::iter::once((cpu, interval, group.first))
                .chain((group.first != group.last).then_some((cpu, interval, group.last)))
        })
    }

    pub fn has_count(&self, count: usize) -> bool {
        self.groups
            .values()
            .try_fold(0u64, |sum, group| sum.checked_add(group.count))
            == u64::try_from(count).ok()
    }

    pub fn metadata_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.source.node_id.capacity()
            + self.groups.len()
                * (std::mem::size_of::<((u32, [u8; 16]), SequenceProof)>()
                    + 6 * std::mem::size_of::<usize>())
    }

    pub fn check_local(fact: &GraphFactV1) -> crate::analysis::graph_rows::store::Result<()> {
        if let GraphFactValueV1::Policy(value) = &fact.value {
            if value.observations.as_slice() != std::slice::from_ref(&fact.record_id) {
                return crate::analysis::graph_rows::store::error::InvalidSnafu {
                    field: "Graph local policy observations",
                }
                .fail();
            }
        }
        Ok(())
    }
}
