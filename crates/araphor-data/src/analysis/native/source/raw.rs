use super::super::{DataView, DataWrite, NativeStore};
use super::{Records, Sources};
use crate::analysis::raw::RawReceipt;
use crate::analysis::raw::{RawBatch, RawIdentity, RawJournal, RawKind};
use crate::{
    AnalysisReadControl, EvidenceIntakeIdentityV1, NativeStateSnafu, NativeStorageSnafu, Result,
};
use crate::{AnalysisReadPageV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1};
use fjall::BranchSnapshot;
use snafu::ResultExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::Excluded,
};

impl NativeStore {
    pub(in crate::analysis::native) fn recover_raw(
        root: &std::path::Path,
        snapshot: &BranchSnapshot,
        counts: &mut super::super::capacity::RevisionCounts,
        protected: Option<&crate::analysis::raw::RawIndex>,
    ) -> Result<RawJournal> {
        let mut ends = BTreeMap::new();
        for row in snapshot.prefix(Sources::ENDS) {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read raw segment ends",
            })?;
            ends.insert(
                Self::number(&key[Sources::ENDS.len()..])?,
                Self::number(&value)?,
            );
        }
        let recorded = ends.clone();
        if let Some(protected) = protected {
            for entry in protected.entries.values() {
                if !protected.expired.contains_key(&entry.reference.id) {
                    ends.entry(entry.reference.id)
                        .and_modify(|end| *end = (*end).max(entry.reference.offset))
                        .or_insert(entry.reference.offset);
                }
            }
        }
        let deletions = super::super::retention::ExpiredSegment::finish_files(root, snapshot)?;
        let mut raw = RawJournal::diagnostics(root, &ends)?;
        raw.budget.deletions.extend(deletions);
        super::super::retention::ExpiredSegment::restore(&mut raw, snapshot)?;
        for (id, end) in &recorded {
            if raw
                .segments
                .get(id)
                .is_none_or(|segment| segment.end < *end)
            {
                return NativeStateSnafu {
                    field: "protected raw segment",
                }
                .fail();
            }
        }
        if let Some(next) = snapshot.get(Sources::NEXT).context(NativeStorageSnafu {
            operation: "read raw allocator",
        })? {
            let next = Self::number(&next)?;
            if next == 0 {
                return NativeStateSnafu {
                    field: "raw allocator floor",
                }
                .fail();
            }
            raw.next_segment = raw.next_segment.max(next);
        }
        let metadata = Self::number(&Self::required(snapshot, super::super::HEAD)?)?;
        if raw
            .segments
            .values()
            .any(|segment| segment.source.first() == Some(&0))
            || raw
                .index
                .entries
                .values()
                .any(|entry| entry.identity.evidence().is_some())
        {
            return NativeStateSnafu {
                field: "legacy evidence segments in native store",
            }
            .fail();
        }
        super::super::trace::Traces::recover(&mut raw, snapshot)?;
        raw.index.refresh_receipts()?;

        for row in snapshot.prefix(Sources::CHANGES) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "recover source binding history",
            })?;
            let reference: crate::CoverageReportRef =
                Sources::read(snapshot, &key)?.ok_or_else(|| {
                    NativeStateSnafu {
                        field: "source binding history",
                    }
                    .build()
                })?;
            let revision = reference.position.commit_revision;
            if !reference.source.valid()
                || reference.revision == 0
                || revision == 0
                || revision > metadata
                || reference.position.ordinal != 0
                || Sources::change(&reference) != key.as_ref()
            {
                return NativeStateSnafu {
                    field: "source binding history identity",
                }
                .fail();
            }
            counts.add(reference.source.tenant_id, 0)?;
        }
        let mut expected = BTreeMap::<u64, u64>::new();
        for (revision, entry) in raw.index.entries.iter() {
            if *revision <= metadata && !raw.index.expired.contains_key(&entry.reference.id) {
                expected
                    .entry(entry.reference.id)
                    .and_modify(|end| *end = (*end).max(entry.reference.offset))
                    .or_insert(entry.reference.offset);
            }
            if snapshot
                .get(Self::cut(*revision))
                .context(NativeStorageSnafu {
                    operation: "check raw revision identity",
                })?
                .is_some()
            {
                return NativeStateSnafu {
                    field: "duplicate Data revision",
                }
                .fail();
            }
        }
        if recorded != expected {
            return NativeStateSnafu {
                field: "raw segment baseline",
            }
            .fail();
        }
        Ok(raw)
    }

    pub fn accept_validated_batch(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.accept_events(identity, batch)
    }

    pub(in crate::analysis::native) fn commit_raw(
        &self,
        identity: RawIdentity,
        batch: RawBatch,
    ) -> Result<(EvidenceStoreOutcomeV1, RawReceipt)> {
        if identity.evidence().is_some() {
            return NativeStateSnafu {
                field: "evidence cannot use diagnostic segments",
            }
            .fail();
        }
        let _writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        let view = self.view()?;
        let mut raw = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let last = batch.last_cursor;
        let key = identity.key();
        if !raw.index.sources.contains_key(&key) {
            return crate::TraceInvalidSnafu {
                reason: "the diagnostic execution is not admitted",
            }
            .fail();
        }
        if let Some(source) = raw.index.sources.get(&key) {
            if !source.receipt.matches(&identity) || source.receipt.cpu() != batch.kind.cpu() {
                return crate::AnalysisConflictSnafu.fail();
            }
            if batch.first_cursor <= source.receipt.floor() {
                if last <= source.receipt.floor() {
                    return Ok((
                        EvidenceStoreOutcomeV1::AlreadyAcceptedExpired,
                        source.receipt.clone(),
                    ));
                }
                return crate::RetainedRangeExpiredSnafu {
                    first_cursor: batch.first_cursor,
                    last_cursor: source.receipt.floor(),
                }
                .fail();
            }
        }
        if let Some(((_, first), last)) = raw
            .budget
            .expired
            .range((key.clone(), 0)..=(key.clone(), batch.last_cursor))
            .next_back()
            .filter(|(_, last)| **last >= batch.first_cursor)
        {
            if *first <= batch.first_cursor && *last >= batch.last_cursor {
                return Ok((
                    EvidenceStoreOutcomeV1::AlreadyAcceptedExpired,
                    raw.index.sources[&key].receipt.clone(),
                ));
            }
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: batch.first_cursor.max(*first),
                last_cursor: *last,
            }
            .fail();
        }
        let revision = view.revision.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "revision exhausted",
            }
            .build()
        })?;
        let commit = raw.prepare(&identity, &batch, revision)?;
        if commit.spans.is_empty() {
            return Ok((
                raw.outcome(&identity, last),
                raw.index.sources[&key].receipt.clone(),
            ));
        }
        self.require_retention()?;
        let append = raw.prepare_append(&identity, commit)?;
        let terminal =
            matches!(&append.commit.kind, Some(RawKind::Diagnostic(progress)) if progress.terminal);
        let initial = !raw.segments.values().any(|segment| segment.source == key);
        let released_slots = if terminal {
            if initial {
                2
            } else {
                1
            }
        } else {
            usize::from(initial && append.header.is_some())
        };
        let slots = raw
            .budget
            .trace_slots
            .checked_sub(released_slots)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "diagnostic slot reserve",
                }
                .build()
            })?;
        let reserve = raw
            .budget
            .trace_reserve
            .checked_sub(if terminal {
                crate::analysis::quota::TRACE_RESERVE
            } else {
                0
            })
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "diagnostic byte reserve",
                }
                .build()
            })?;
        let _rotation = if append.header.is_some()
            && raw
                .index
                .sources
                .get(&identity.key())
                .is_some_and(|source| source.written)
        {
            drop(raw);
            let guard = self.maintenance.write().map_err(|_| {
                NativeStateSnafu {
                    field: "maintenance lock",
                }
                .build()
            })?;
            raw = self.raw.lock().map_err(|_| {
                NativeStateSnafu {
                    field: "raw owner lock",
                }
                .build()
            })?;
            Some(guard)
        } else {
            None
        };
        #[cfg(any(test, feature = "test-fixtures"))]
        {
            if _rotation.is_some() {
                self.run_commit_hook(crate::AnalysisCommitStage::BeforeRotation)?;
            }
            self.run_commit_hook(crate::AnalysisCommitStage::BeforeAppend)?;
        }
        if let Err(error) = raw.append(&identity, append) {
            self.poison();
            return Err(error);
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        if let Err(error) = self.run_commit_hook(crate::AnalysisCommitStage::AfterSync) {
            self.poison();
            return Err(error);
        }
        raw.budget.trace_slots = slots;
        raw.budget.trace_reserve = reserve;
        let next = DataView {
            revision,
            store_uuid: view.store_uuid,
            snapshot: view.snapshot.clone(),
            metadata_revision: view.metadata_revision,
            schema_version: view.schema_version,
            recovery_epoch: view.recovery_epoch,
            raw: raw.index.clone(),
            graphs: view.graphs.clone(),
            contexts: view.contexts.clone(),
        };
        let mut published = self.published.write().map_err(|_| {
            self.poison();
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })?;
        *published = std::sync::Arc::new(next);
        drop(published);
        self.revision.send_replace(revision);
        Ok((
            raw.outcome(&identity, last),
            raw.index.sources[&key].receipt.clone(),
        ))
    }

    pub fn read_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<AnalysisReadPageV1> {
        self.read_page_cancel(identity, first_cursor, &AnalysisReadControl::default())
    }

    pub fn read_page_cancel(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisReadPageV1> {
        let view = self.view()?;
        self.read_page_at(&view, identity, first_cursor, control)
    }

    pub fn read_page_at(
        &self,
        view: &DataView,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisReadPageV1> {
        let _lease = self.maintenance.read_until(control)?;
        self.check()?;
        if view.store_uuid != self.view()?.store_uuid {
            return NativeStateSnafu {
                field: "read store identity",
            }
            .fail();
        }
        self.event_page(view, identity, first_cursor, control)
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn stage_raw(&mut self) -> Result<()> {
        if self.raw.revision <= self.metadata_revision {
            return Ok(());
        }
        let mut sources = BTreeSet::new();
        let mut segments = BTreeSet::new();
        for (_, entry) in self
            .raw
            .entries
            .range((Excluded(self.metadata_revision), std::ops::Bound::Unbounded))
        {
            sources.insert(entry.identity.key());
            segments.insert(entry.reference.id);
        }
        for key in sources {
            let source = self.raw.sources.get(&key).ok_or_else(|| {
                NativeStateSnafu {
                    field: "raw source baseline",
                }
                .build()
            })?;
            match &source.receipt {
                RawReceipt::Evidence(_) => {
                    return NativeStateSnafu {
                        field: "evidence in diagnostic raw index",
                    }
                    .fail();
                }
                RawReceipt::Diagnostic(receipt) => {
                    Records::stage(
                        &mut self.transaction,
                        super::super::trace::Traces::receipt_key(&receipt.identity),
                        Records::encode(receipt)?,
                    );
                }
            }
        }
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        for id in segments {
            if self.raw.expired.contains_key(&id) {
                self.transaction
                    .remove(Sources::key(Sources::ENDS, &id.to_be_bytes()));
                continue;
            }
            let segment = raw.segments.get(&id).ok_or_else(|| {
                NativeStateSnafu {
                    field: "raw segment baseline",
                }
                .build()
            })?;
            self.transaction.insert(
                Sources::key(Sources::ENDS, &id.to_be_bytes()),
                segment.end.to_be_bytes(),
            );
        }
        let next = raw.next_segment.to_be_bytes();
        if self
            .transaction
            .get(Sources::NEXT)
            .context(NativeStorageSnafu {
                operation: "read raw allocator baseline",
            })?
            .as_deref()
            != Some(next.as_slice())
        {
            self.transaction.insert(Sources::NEXT, next);
        }
        Ok(())
    }
}
