use std::mem::size_of;

use super::*;

impl SourceScope {
    pub fn allocated_bytes(&self) -> Option<usize> {
        let mut bytes = size_of::<Self>()
            .checked_add(self.instance.capacity())?
            .checked_add(
                self.selection
                    .allocation_bytes()
                    .checked_sub(size_of::<AnalysisSelectionV1>())?,
            )?
            .checked_add(self.event_ranges.as_ref().map_or(Some(0), |ranges| {
                ranges.capacity().checked_mul(size_of::<(u64, u64)>())
            })?)?;
        if let ManagedSourceRead::Changes(parent) = &self.read {
            bytes = bytes.checked_add(parent.result.result_id.capacity())?;
        }
        for (name, columns) in &self.tables {
            bytes = bytes
                .checked_add(size_of::<(String, Option<BTreeSet<usize>>)>())?
                .checked_add(name.capacity())?
                .checked_add(columns.as_ref().map_or(Some(0), |columns| {
                    columns.len().checked_mul(size_of::<usize>())
                })?)?;
        }
        if let Some(owners) = &self.context_owners {
            for owner in owners {
                bytes = bytes
                    .checked_add(size_of::<String>())?
                    .checked_add(owner.capacity())?;
            }
        }
        Some(bytes)
    }
}

impl super::super::model::ManagedAttempt {
    /// Count the sealed reference metadata, without execution buffers.
    pub fn allocation_bytes(&self) -> Option<usize> {
        let capture = &self.0.capture;
        let request = &self.0.request;
        let mut bytes = size_of::<Self>()
            .checked_add(
                self.1
                    .allocation_bytes()?
                    .checked_sub(size_of::<ManagedInstance>())?,
            )?
            .checked_add(request.id.capacity())?
            .checked_add(
                request
                    .frontier
                    .as_ref()
                    .map_or(0, |frontier| frontier.cursor.capacity()),
            )?
            .checked_add(capture.instance.capacity())?
            .checked_add(capture.grant.principal.capacity())?
            .checked_add(
                capture
                    .grant
                    .authorization_id
                    .as_ref()
                    .map_or(0, String::capacity),
            )?
            .checked_add(
                capture
                    .grant
                    .selection
                    .allocation_bytes()
                    .checked_sub(size_of::<AnalysisSelectionV1>())?,
            )?
            .checked_add(
                capture
                    .prior
                    .len()
                    .checked_mul(size_of::<(u64, Option<PackageResultRefV1>)>())?,
            )?
            .checked_add(
                capture
                    .sources
                    .capacity()
                    .checked_mul(size_of::<(String, u64)>())?,
            )?
            .checked_add(
                capture
                    .dependencies
                    .capacity()
                    .checked_mul(size_of::<PackageResultRefV1>())?,
            )?
            .checked_add(
                capture
                    .witnesses
                    .capacity()
                    .checked_mul(size_of::<crate::AnalysisWitnessV1>())?,
            )?
            .checked_add(
                capture
                    .contexts
                    .capacity()
                    .checked_mul(size_of::<crate::AnalysisContextRefV1>())?,
            )?
            .checked_add(
                capture
                    .traces
                    .capacity()
                    .checked_mul(size_of::<[u8; 16]>())?,
            )?;
        for reference in capture
            .prior
            .values()
            .flatten()
            .chain(capture.dependencies.iter())
        {
            bytes = bytes.checked_add(reference.result_id.capacity())?;
        }
        for (source, _) in &capture.sources {
            bytes = bytes.checked_add(source.capacity())?;
        }
        for witness in &capture.witnesses {
            bytes = bytes.checked_add(match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(source) => source.node_id.capacity(),
                AnalysisStreamIdentityV1::Diagnostic(source) => source.node_id.capacity(),
            })?;
        }
        for context in &capture.contexts {
            bytes = bytes
                .checked_add(context.key.owner_id.capacity())?
                .checked_add(context.key.entity_key.capacity())?
                .checked_add(context.key.lifetime_key.capacity())?;
        }
        if let Some(receipt) = &self.0.receipt {
            bytes = bytes
                .checked_add(receipt.instance.capacity())?
                .checked_add(receipt.attempt.capacity())?
                .checked_add(receipt.selected.result_id.capacity())?
                .checked_add(
                    receipt
                        .frontier
                        .as_ref()
                        .map_or(0, |frontier| frontier.cursor.capacity()),
                )?
                .checked_add(
                    receipt
                        .results
                        .len()
                        .checked_mul(size_of::<(u64, PackageResultRefV1)>())?,
                )?;
            for reference in receipt.results.values().chain(receipt.graph.iter()) {
                bytes = bytes.checked_add(reference.result_id.capacity())?;
            }
        }
        if let Some(terminal) = &self.0.terminal {
            bytes = bytes
                .checked_add(terminal.instance.capacity())?
                .checked_add(terminal.attempt.capacity())?;
        }
        Some(bytes)
    }
}

impl ManagedSourceBlock {
    pub fn selection_bytes(&self, indices: &[usize]) -> Option<(usize, usize)> {
        let mut scratch = 0usize;
        let mut retained = size_of::<ManagedSourceRows>()
            .checked_add(size_of::<SourceCells>() + 4 * size_of::<Arc<SourceCells>>())?
            .checked_add(indices.len().checked_mul(size_of::<usize>())?)?;
        for index in indices {
            let (heap, value, entry) = match self.rows.get(*index)? {
                SourceRow::Event(witness, _) => (
                    match &witness.identity {
                        AnalysisStreamIdentityV1::Evidence(source) => source.node_id.capacity(),
                        AnalysisStreamIdentityV1::Diagnostic(source) => source.node_id.capacity(),
                    },
                    size_of::<crate::AnalysisWitnessV1>(),
                    size_of::<((AnalysisStreamIdentityV1, u64), crate::AnalysisWitnessV1)>(),
                ),
                SourceRow::Context(context) => (
                    context
                        .key
                        .owner_id
                        .capacity()
                        .checked_add(context.key.entity_key.capacity())?
                        .checked_add(context.key.lifetime_key.capacity())?,
                    size_of::<crate::AnalysisContextRefV1>(),
                    size_of::<(
                        (crate::AnalysisContextKeyV1, u64),
                        crate::AnalysisContextRefV1,
                    )>(),
                ),
            };
            scratch = scratch
                .checked_add(entry)?
                .checked_add(heap.checked_mul(2)?)?;
            retained = retained.checked_add(value)?.checked_add(heap)?;
        }
        Some((scratch, retained))
    }
}

impl ManagedSourceFrame {
    pub fn block_bytes(&self, table: &str, batch: usize) -> Option<usize> {
        let batch = self
            .tables
            .iter()
            .find(|data| data.name == table)?
            .batches
            .get(batch)?;
        let mut heap = 0usize;
        for name in match table {
            "events" => &["node_id"][..],
            "context_versions" => &["owner_id"][..],
            _ => return None,
        } {
            let values = batch
                .column_by_name(name)?
                .as_any()
                .downcast_ref::<sdk::arrow_array::StringArray>()?;
            for value in values.iter().flatten() {
                heap = heap.checked_add(value.len())?;
            }
        }
        if table == "context_versions" {
            for name in ["entity_key", "lifetime_key"] {
                let values = batch
                    .column_by_name(name)?
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::BinaryArray>()?;
                for value in values.iter().flatten() {
                    heap = heap.checked_add(value.len())?;
                }
            }
        }
        heap.checked_add(batch.num_rows().checked_mul(size_of::<SourceRow>())?)?
            .checked_add(size_of::<ManagedSourceBlock>() + size_of::<sdk::RecordBatch>())?
            .checked_add(
                batch
                    .num_columns()
                    .checked_mul(size_of::<sdk::arrow_array::ArrayRef>())?,
            )?
            .checked_add(6 * size_of::<usize>())?
            .checked_add(table.len())
    }

    pub fn allocated_bytes(&self) -> usize {
        let record = self;
        let mut bytes = size_of::<Self>()
            .saturating_add(
                self.coverage
                    .capacity()
                    .saturating_mul(size_of::<super::coverage::SourceCoverage>()),
            )
            .saturating_add(
                self.coverage
                    .iter()
                    .map(super::coverage::SourceCoverage::allocated_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.scope.allocated_bytes().unwrap_or(usize::MAX))
            .saturating_add(size_of::<OnceLock<Arc<PackageResultRefV1>>>())
            .saturating_add(size_of::<Mutex<SourceSelection>>())
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
            );
        for (identity, ranges) in &record.removals {
            bytes = bytes
                .saturating_add(size_of::<(AnalysisStreamIdentityV1, Vec<AnalysisGapV1>)>())
                .saturating_add(ranges.capacity().saturating_mul(size_of::<AnalysisGapV1>()))
                .saturating_add(match identity {
                    AnalysisStreamIdentityV1::Evidence(source) => source.node_id.capacity(),
                    AnalysisStreamIdentityV1::Diagnostic(source) => source.node_id.capacity(),
                });
        }
        if let Some(proof) = self.proof() {
            bytes = bytes
                .saturating_add(size_of::<PackageResultRefV1>())
                .saturating_add(proof.result_id.capacity());
        }
        bytes
    }
}
