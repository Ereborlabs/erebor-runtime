use std::sync::{Arc, RwLock, Weak};

use super::*;
use crate::{
    AnalysisReadControl, AnalysisReadPageV1, AnalysisRecordV1, AnalysisSelectionV1, StorePositionV1,
};

struct EventSelection {
    batch: EventBatch,
    slot: usize,
    first: u64,
    last: u64,
}

#[derive(Clone)]
pub(in crate::analysis) struct EventRead {
    pub(super) batch: EventBatch,
    pub(super) slot: usize,
    pub(super) first: u64,
    pub(super) last: u64,
    pub(super) available: u64,
    pub(super) bytes: fjall::Slice,
    pub(super) current: Weak<RwLock<Arc<DataView>>>,
}

impl EventRead {
    pub(in crate::analysis) fn window(
        &self,
        after: Option<StorePositionV1>,
        limit: usize,
    ) -> Option<Self> {
        if limit == 0 {
            return None;
        }
        let span = self.batch.meta.spans.get(self.slot)?;
        let mut first = self.first;
        if let Some(after) = after {
            if after.commit_revision > self.batch.meta.revision {
                return None;
            }
            if after.commit_revision == self.batch.meta.revision {
                let skipped =
                    (u64::from(after.ordinal) + 1).saturating_sub(u64::from(span.ordinal));
                first = first.max(span.first.saturating_add(skipped));
            }
        }
        if first > self.available {
            return None;
        }
        let mut read = self.clone();
        read.first = first;
        read.last = self.available.min(first.saturating_add(limit as u64 - 1));
        Some(read)
    }

    pub(in crate::analysis) fn end(&self) -> StorePositionV1 {
        let span = &self.batch.meta.spans[self.slot];
        StorePositionV1 {
            commit_revision: self.batch.meta.revision,
            ordinal: span.ordinal + (self.available - span.first) as u32,
        }
    }

    pub(in crate::analysis) fn first(&self) -> u64 {
        self.first
    }

    pub(in crate::analysis) fn bytes(&self) -> usize {
        self.batch.bytes
    }

    pub(in crate::analysis) fn intake(&self) -> u64 {
        self.batch.meta.intake
    }

    pub(in crate::analysis) fn metadata_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.batch.source.node_id.capacity()
            + self.batch.meta.spans.capacity()
                * std::mem::size_of::<crate::analysis::raw::RawRange>()
            + self.bytes.len()
    }

    fn check(&self) -> Result<()> {
        let current = self.current.upgrade().ok_or_else(|| {
            NativeStateSnafu {
                field: "native evidence reader owner",
            }
            .build()
        })?;
        let view = current.read().map_err(|_| {
            NativeStateSnafu {
                field: "evidence publication lock",
            }
            .build()
        })?;
        if Events::new(&view)
            .expiry(self.batch.meta.revision)?
            .is_some()
        {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: self.first,
                last_cursor: self.available,
            }
            .fail();
        }
        Ok(())
    }

    pub(in crate::analysis) fn read(
        &self,
        root: &Path,
    ) -> Result<(Vec<AnalysisRecordV1>, usize, usize)> {
        self.check()?;
        let commit = self.batch.decode(&self.bytes, root)?;
        let span = commit.spans.get(self.slot).ok_or_else(|| {
            NativeStateSnafu {
                field: "native evidence read span",
            }
            .build()
        })?;
        let mut records = Vec::new();
        for cursor in self.first..=self.last {
            let index = (cursor - span.first) as usize;
            let first = span.start as usize
                + if index == 0 {
                    0
                } else {
                    span.ends[index - 1] as usize
                };
            let last = span.start as usize + span.ends[index] as usize;
            records.push(AnalysisRecordV1 {
                cursor,
                framed_record: commit.body[first..last].to_vec(),
                position: StorePositionV1 {
                    commit_revision: commit.revision,
                    ordinal: span.ordinal + index as u32,
                },
            });
        }
        self.check()?;
        Ok((
            records,
            commit.spans.iter().map(|span| span.ends.len()).sum(),
            commit.body.len(),
        ))
    }
}

impl NativeStore {
    pub(super) fn event_range(
        &self,
        view: &DataView,
        batch: EventBatch,
        slot: usize,
        first: u64,
        last: u64,
        limit: usize,
    ) -> Result<crate::analysis::segments::InputRange> {
        let current = self.view()?;
        if Events::new(&current).expiry(batch.meta.revision)?.is_some() {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: last,
            }
            .fail();
        }
        let bytes = Events::new(view).bytes(&batch)?;
        let read = EventRead {
            batch,
            slot,
            first,
            last: last.min(first.saturating_add(limit as u64 - 1)),
            available: last,
            bytes,
            current: Arc::downgrade(&self.published),
        };
        Ok(crate::analysis::segments::InputRange::native(read))
    }

    pub(in crate::analysis::native) fn event_page(
        &self,
        view: &DataView,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisReadPageV1> {
        let receipt = view.source_receipt(source)?.ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: &self.root,
                reason: "the raw source is absent",
            }
            .build()
        })?;
        if first == 0 || first > receipt.contiguous_cursor.saturating_add(1) {
            return crate::Error::reject_path(
                &self.root,
                "the raw read cursor is outside accepted progress",
            );
        }
        let current = self.source_receipt(source)?.ok_or_else(|| {
            NativeStateSnafu {
                field: "current evidence receipt",
            }
            .build()
        })?;
        if first <= current.retained_floor {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: current.retained_floor,
            }
            .fail();
        }
        let events = Events::new(view);
        let mut records = Vec::new();
        let mut encoded_bytes = 0_usize;
        let mut cursor = first;
        while cursor <= receipt.contiguous_cursor
            && records.len() < crate::analysis::MAX_ANALYSIS_PAGE_RECORDS
        {
            control.check()?;
            let Some((batch, slot)) = events.lookup(source, cursor)? else {
                return NativeStateSnafu {
                    field: "accepted evidence span",
                }
                .fail();
            };
            let last = batch.meta.spans[slot].last.min(receipt.contiguous_cursor);
            let range = self.event_range(
                view,
                batch,
                slot,
                cursor,
                last,
                crate::analysis::MAX_ANALYSIS_PAGE_RECORDS - records.len(),
            )?;
            let (page, _, _) = range.read(&self.root)?;
            for row in page {
                let total = encoded_bytes
                    .checked_add(row.framed_record.len())
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "evidence page bytes",
                        }
                        .build()
                    })?;
                if !records.is_empty() && total > crate::analysis::MAX_ANALYSIS_PAGE_BYTES {
                    control.check()?;
                    return Ok(AnalysisReadPageV1 {
                        first_cursor: first,
                        records,
                        encoded_bytes,
                        next_cursor: Some(cursor),
                        read_revision: view.revision,
                    });
                }
                encoded_bytes = total;
                cursor = row.cursor.checked_add(1).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "evidence cursor exhausted",
                    }
                    .build()
                })?;
                records.push(row);
            }
        }
        control.check()?;
        Ok(AnalysisReadPageV1 {
            first_cursor: first,
            records,
            encoded_bytes,
            next_cursor: (cursor <= receipt.contiguous_cursor).then_some(cursor),
            read_revision: view.revision,
        })
    }

    fn event_selection(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        revision: u64,
        limit: usize,
        event_ranges: Option<&[(u64, u64)]>,
        control: &AnalysisReadControl,
    ) -> Result<Option<EventSelection>> {
        if limit == 0 || selection.sources.as_slice().is_empty() {
            return Ok(None);
        }
        let events = Events::new(view);
        let current = self.view()?;
        for row in events.batches(after.map_or(0, |position| position.commit_revision)) {
            control.check()?;
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "select native evidence positions",
            })?;
            let batch = events.decode_batch(&key, &value)?;
            if batch.meta.revision > revision {
                break;
            }
            if !selection.sources.as_slice().contains(&batch.source)
                || !selection
                    .time_range()
                    .is_some_and(|(first, last)| (first..=last).contains(&batch.meta.intake))
            {
                continue;
            }
            let expired = Events::new(&current).expiry(batch.meta.revision)?;
            if expired
                .as_ref()
                .is_some_and(|expiry| expiry.revision <= view.revision)
            {
                continue;
            }
            for (slot, span) in batch.meta.spans.iter().enumerate() {
                let end = StorePositionV1 {
                    commit_revision: batch.meta.revision,
                    ordinal: span.ordinal + (span.last - span.first) as u32,
                };
                if after.is_some_and(|after| after >= end) {
                    continue;
                }
                let skipped = after
                    .filter(|after| after.commit_revision == batch.meta.revision)
                    .map_or(0, |after| {
                        (u64::from(after.ordinal) + 1).saturating_sub(u64::from(span.ordinal))
                    });
                let Some((from, until)) = selection.cursor_range() else {
                    continue;
                };
                let first = span.first.saturating_add(skipped).max(from);
                let last = span.last.min(until);
                if first > last {
                    continue;
                }
                if expired.is_some() {
                    if event_ranges.is_some_and(|ranges| {
                        !ranges
                            .iter()
                            .any(|(first, last)| (*first..=*last).contains(&batch.meta.intake))
                    }) {
                        continue;
                    }
                }
                return Ok(Some(EventSelection {
                    batch: batch.clone(),
                    slot,
                    first,
                    last,
                }));
            }
        }
        Ok(None)
    }

    pub(in crate::analysis) fn select_input(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        revision: u64,
        limit: usize,
        event_ranges: Option<&[(u64, u64)]>,
        control: &AnalysisReadControl,
    ) -> Result<
        Option<(
            crate::analysis::raw::RawIdentity,
            Option<u32>,
            crate::analysis::segments::InputRange,
        )>,
    > {
        if limit == 0 {
            return Ok(None);
        }
        let event = self.event_selection(
            view,
            selection,
            after,
            revision,
            limit,
            event_ranges,
            control,
        )?;
        let before = event.as_ref().map_or(revision, |event| {
            event.batch.meta.revision.saturating_sub(1)
        });
        if !selection.traces.as_slice().is_empty()
            && after.is_none_or(|after| after.commit_revision <= before)
        {
            if let Some(trace) = self.raw.until(control)?.select_position_at(
                &view.raw,
                selection,
                after,
                before,
                limit,
                event_ranges,
                control,
            )? {
                return Ok(Some(trace));
            }
        }
        let Some(event) = event else {
            return Ok(None);
        };
        let identity = event.batch.source.clone().into();
        let cpu = event.batch.meta.kind.cpu();
        let range = self.event_range(
            view,
            event.batch,
            event.slot,
            event.first,
            event.last,
            limit,
        )?;
        Ok(Some((identity, cpu, range)))
    }
}

impl Events<'_> {
    pub(in crate::analysis::native) fn source_state(
        &self,
        root: &Path,
        receipt: &crate::AnalysisSourceReceiptV1,
        control: &AnalysisReadControl,
        budget: (usize, usize),
    ) -> Result<crate::analysis::raw::RawSourceState> {
        let mut state = crate::analysis::raw::RawSourceState {
            covered: 0,
            pending: Vec::new(),
        };
        let mut previous = 0;
        let mut next = receipt.contiguous_cursor.checked_add(1);
        let mut allocated = 0_usize;
        for row in self.spans(&receipt.identity, 1, u64::MAX)? {
            control.check()?;
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read accepted evidence ranges",
            })?;
            let (first, span) = Self::decode_span(&receipt.identity, &key, &value)?;
            self.lookup(&receipt.identity, first)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "accepted evidence range",
                }
                .build()
            })?;
            if first <= previous {
                return crate::Error::reject_path(
                    root,
                    "the accepted source ranges overlap or are invalid",
                );
            }
            previous = span.last;
            if first <= receipt.contiguous_cursor {
                state.covered = state
                    .covered
                    .checked_add(span.last.min(receipt.contiguous_cursor) - first + 1)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "accepted source count",
                        }
                        .build()
                    })?;
            }
            if let Some(begin) = next.filter(|_| span.last > receipt.contiguous_cursor) {
                if first > begin {
                    allocated += crate::AnalysisExtractionV1::grow(
                        &mut state.pending,
                        budget.0.saturating_add(allocated),
                        budget.1,
                    )?;
                    state.pending.push(crate::AnalysisGapV1 {
                        first_cursor: begin,
                        last_cursor: first - 1,
                        commit_revision: self.view.revision,
                    });
                }
                next = span.last.checked_add(1);
            }
        }
        Ok(state)
    }
}
