use std::mem::size_of;

use super::*;

impl SourceCapture {
    pub(in crate::analysis::managed) fn member_bytes(members: &BTreeSet<Vec<u8>>) -> usize {
        members
            .iter()
            .fold(size_of::<BTreeSet<Vec<u8>>>(), |bytes, key| {
                bytes
                    .saturating_add(size_of::<Vec<u8>>())
                    .saturating_add(key.capacity())
            })
    }

    pub(super) fn allocated_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.frame.allocated_bytes())
            .saturating_add(Self::member_bytes(&self.members))
    }
}

impl ManagedSourceFrame {
    pub fn allocated_bytes(&self) -> usize {
        let record = &self.record;
        let mut bytes = size_of::<Self>()
            .saturating_add(
                record
                    .contract
                    .selection
                    .allocation_bytes()
                    .saturating_sub(size_of::<AnalysisSelectionV1>()),
            )
            .saturating_add(size_of::<OnceLock<Arc<ManagedSourceProof>>>())
            .saturating_add(
                self.tables
                    .capacity()
                    .saturating_mul(size_of::<sdk::Dataset>()),
            )
            .saturating_add(
                self.tables
                    .iter()
                    .map(sdk::Dataset::allocated_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(
                record
                    .tables
                    .capacity()
                    .saturating_mul(size_of::<RecordInput>()),
            )
            .saturating_add(
                record
                    .tables
                    .iter()
                    .map(|table| table.name.capacity())
                    .sum::<usize>(),
            )
            .saturating_add(
                record
                    .metadata
                    .capacity()
                    .saturating_mul(size_of::<ManagedSourceMetadata>()),
            )
            .saturating_add(record.contract.event_ranges.as_ref().map_or(0, |ranges| {
                ranges.capacity().saturating_mul(size_of::<(u64, u64)>())
            }));
        if let ManagedSourceRead::Changes(parent) = &record.contract.read {
            bytes = bytes.saturating_add(parent.result.result_id.capacity());
        }
        for (name, columns) in &record.contract.tables {
            bytes = bytes
                .saturating_add(size_of::<(String, Option<BTreeSet<usize>>)>())
                .saturating_add(name.capacity())
                .saturating_add(columns.as_ref().map_or(0, |columns| {
                    columns.len().saturating_mul(size_of::<usize>())
                }));
        }
        for (identity, ranges) in &record.removals {
            bytes = bytes
                .saturating_add(size_of::<(AnalysisStreamIdentityV1, Vec<AnalysisGapV1>)>())
                .saturating_add(ranges.capacity().saturating_mul(size_of::<AnalysisGapV1>()))
                .saturating_add(match identity {
                    AnalysisStreamIdentityV1::Evidence(source) => source.node_id.capacity(),
                    AnalysisStreamIdentityV1::Diagnostic(source) => source.node_id.capacity(),
                });
        }
        for metadata in &record.metadata {
            let ranges = match &metadata.state {
                ManagedSourceState::Initial { pending, .. } => pending,
                ManagedSourceState::Changes { accepted } => accepted,
            };
            bytes = bytes
                .saturating_add(metadata.receipt.identity.node_id.capacity())
                .saturating_add(
                    metadata
                        .coverage
                        .as_ref()
                        .map_or(0, |report| report.source.node_id.capacity()),
                )
                .saturating_add(ranges.capacity().saturating_mul(size_of::<AnalysisGapV1>()))
                .saturating_add(
                    metadata
                        .expired
                        .capacity()
                        .saturating_mul(size_of::<AnalysisGapV1>()),
                )
                .saturating_add(
                    metadata
                        .recovery
                        .capacity()
                        .saturating_mul(size_of::<AnalysisGapV1>()),
                );
        }
        if let Some(proof) = self.proof() {
            bytes = bytes
                .saturating_add(size_of::<ManagedSourceProof>())
                .saturating_add(proof.result.result_id.capacity())
                .saturating_add(
                    proof
                        .witnesses
                        .capacity()
                        .saturating_mul(size_of::<crate::AnalysisWitnessV1>()),
                )
                .saturating_add(
                    proof
                        .contexts
                        .capacity()
                        .saturating_mul(size_of::<crate::AnalysisContextRefV1>()),
                );
            for witness in &proof.witnesses {
                bytes = bytes.saturating_add(match &witness.identity {
                    AnalysisStreamIdentityV1::Evidence(source) => source.node_id.capacity(),
                    AnalysisStreamIdentityV1::Diagnostic(source) => source.node_id.capacity(),
                });
            }
            for context in &proof.contexts {
                bytes = bytes
                    .saturating_add(context.key.owner_id.capacity())
                    .saturating_add(context.key.entity_key.capacity())
                    .saturating_add(context.key.lifetime_key.capacity());
            }
        }
        bytes
    }
}
