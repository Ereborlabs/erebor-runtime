use super::*;
use araphor_data::EvidenceIntakeIdentityV1;
use datafusion::arrow::array::{Array, UInt32Array};
use datafusion::arrow::datatypes::{Field, Schema};

impl SourceSnapshot {
    pub fn event_keys(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        range: (u64, u64),
        memory: &MemoryReservation,
    ) -> Result<RecordBatch> {
        let view = self.source_view()?.ok_or_else(SourceIndex::conflict)?;
        if self.reference.get().is_some()
            || view.historical
            || view.frame.position().commit_revision
                != self.snapshot()?.page.extraction.meta.commit_revision
            || !self.selection.includes_source(identity)
        {
            return Err(SourceIndex::conflict());
        }
        let scope = self.selection.cursor_range();
        let range = scope.map(|scope| (range.0.max(scope.0), range.1.min(scope.1)));
        let scratch = self.memory.reserve_input(0)?;
        let rows = match range.filter(|range| range.0 <= range.1) {
            Some(range) => view.event_keys(identity, range, &scratch, self.limits.input_bytes)?,
            None => Vec::new(),
        };
        let bytes = rows
            .len()
            .checked_mul(size_of::<u32>() + size_of::<u64>())
            .ok_or_else(SourceIndex::limit)?;
        if bytes > self.limits.input_bytes {
            return Err(SourceIndex::limit());
        }
        memory.try_grow(bytes)?;
        let cpus = UInt32Array::from(rows.iter().map(|row| row.0).collect::<Vec<_>>());
        let cursors = UInt64Array::from(rows.iter().map(|row| row.1).collect::<Vec<_>>());
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("cpu_id", DataType::UInt32, false),
                Field::new("source_cursor", DataType::UInt64, false),
            ])),
            vec![Arc::new(cpus), Arc::new(cursors)],
        )?;
        self.memory.retain_input(&batch, memory)?;
        Ok(batch)
    }
}

impl SourceView {
    fn event_keys(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        range: (u64, u64),
        memory: &MemoryReservation,
        limit: usize,
    ) -> Result<Vec<(u32, u64)>> {
        let state = self.index.lock()?;
        memory.try_grow(identity.node_id.len())?;
        let identity = AnalysisStreamIdentityV1::Evidence(identity.clone());
        let mut rows = Vec::new();
        for (table, retained) in state
            .tables
            .get("events")
            .map(|table| (table, true))
            .into_iter()
            .chain(self.tables.get("events").map(|table| (table, false)))
        {
            let Some(cursors) = table.cursors.get(&identity) else {
                continue;
            };
            for (cursor, addresses) in cursors.range(range.0..=range.1) {
                for address in addresses {
                    self.control.check().map_err(SourceSnapshot::data_error)?;
                    if retained
                        && (!table.visible(*address, self.version())
                            || self
                                .removed
                                .get("events")
                                .is_some_and(|rows| rows.contains(address)))
                    {
                        continue;
                    }
                    let block = table
                        .blocks
                        .get(&address.block)
                        .ok_or_else(SourceIndex::conflict)?;
                    let cpus = block
                        .batch
                        .column_by_name("cpu_id")
                        .and_then(|array| array.as_any().downcast_ref::<UInt32Array>())
                        .ok_or_else(SourceIndex::conflict)?;
                    if cpus.is_null(address.row) {
                        return Err(SourceIndex::conflict());
                    }
                    if rows.len() == rows.capacity() {
                        let added = rows.capacity().max(4);
                        let bytes = added
                            .checked_mul(size_of::<(u32, u64)>())
                            .ok_or_else(SourceIndex::limit)?;
                        if memory
                            .size()
                            .checked_add(bytes)
                            .is_none_or(|bytes| bytes > limit)
                        {
                            return Err(SourceIndex::limit());
                        }
                        memory.try_grow(bytes)?;
                        rows.reserve_exact(added);
                    }
                    rows.push((cpus.value(address.row), *cursor));
                }
            }
        }
        rows.sort_unstable();
        if rows.windows(2).any(|rows| rows[0] == rows[1]) {
            return Err(SourceIndex::conflict());
        }
        Ok(rows)
    }
}
