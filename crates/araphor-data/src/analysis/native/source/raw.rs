use super::super::{DataView, DataWrite, NativeStore};
use super::{Records, Sources};
use crate::analysis::raw::RawReceipt;
use crate::analysis::raw::{RawIdentity, RawJournal};
use crate::{
    AnalysisReadControl, AnalysisStore, EvidenceIntakeIdentityV1, NativeStateSnafu,
    NativeStorageSnafu, Result,
};
use crate::{
    AnalysisReadPageV1, AnalysisSourceReceiptV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1,
};
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
        let mut raw = RawJournal::open(root, &ends)?;
        for (id, end) in &ends {
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
        for row in snapshot.prefix(Sources::RECEIPTS) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read raw receipt keys",
            })?;
            let receipt: AnalysisSourceReceiptV1 =
                Sources::read(snapshot, &key)?.ok_or_else(|| {
                    NativeStateSnafu {
                        field: "raw receipt baseline",
                    }
                    .build()
                })?;
            if !receipt.identity.valid()
                || receipt.retained_floor > receipt.contiguous_cursor
                || Sources::key(Sources::RECEIPTS, &receipt.identity.key()) != key.as_ref()
            {
                return NativeStateSnafu {
                    field: "raw receipt baseline identity",
                }
                .fail();
            }
            let source = raw.index.sources.get_mut(&receipt.identity.key());
            match source {
                Some(source) => {
                    let RawReceipt::Evidence(saved) = &mut source.receipt else {
                        return NativeStateSnafu {
                            field: "raw receipt kind",
                        }
                        .fail();
                    };
                    if saved.identity != receipt.identity || saved.cpu_id != receipt.cpu_id {
                        return NativeStateSnafu {
                            field: "raw receipt binding",
                        }
                        .fail();
                    }
                    saved.contiguous_cursor =
                        saved.contiguous_cursor.max(receipt.contiguous_cursor);
                    saved.coverage_revision = receipt.coverage_revision;
                    saved.retained_floor = receipt.retained_floor;
                }
                None => {
                    raw.index
                        .sources
                        .insert_mut(receipt.identity.key(), receipt.into());
                }
            }
        }
        raw.index.refresh_receipts()?;
        let metadata = Self::number(&Self::required(snapshot, super::super::HEAD)?)?;
        let mut births = BTreeMap::<Vec<u8>, u64>::new();
        for (revision, entry) in raw.index.entries.iter() {
            if entry.identity.evidence().is_some() {
                births.entry(entry.identity.key()).or_insert(*revision);
            }
        }
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
            births
                .entry(reference.source.key())
                .and_modify(|first| *first = (*first).min(revision))
                .or_insert(revision);
        }
        let bindings = raw
            .index
            .relations
            .range((b'B', 0)..=(b'B', u64::MAX))
            .map(|(key, ())| *key)
            .collect::<Vec<_>>();
        for key in bindings {
            raw.index.relations.remove_mut(&key);
        }
        raw.index.binding_revision = 0;
        for revision in births.into_values() {
            raw.index.relations.insert_mut((b'B', revision), ());
            raw.index.binding_revision = raw.index.binding_revision.max(revision);
        }
        let mut expected = BTreeMap::<u64, u64>::new();
        for (revision, entry) in raw.index.entries.iter() {
            if *revision <= metadata {
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
        if ends != expected {
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
        batch.validate_identity(&identity, &self.root)?;
        if batch.intake_utc_ns == 0 {
            return AnalysisStore::reject_path(&self.root, "live evidence has no intake time");
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
        let identity = RawIdentity::Evidence(identity);
        let revision = view.revision.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "revision exhausted",
            }
            .build()
        })?;
        let commit = raw.prepare(&identity, &batch.into(), revision)?;
        if commit.spans.is_empty() {
            return Ok(raw.outcome(&identity, last));
        }
        let append = raw.prepare_append(&identity, commit)?;
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
        if let Err(error) = raw.append(&identity, append) {
            self.ready
                .store(false, std::sync::atomic::Ordering::Release);
            return Err(error);
        }
        let next = DataView {
            revision,
            store_uuid: view.store_uuid,
            snapshot: view.snapshot.clone(),
            metadata_revision: view.metadata_revision,
            schema_version: view.schema_version,
            recovery_epoch: view.recovery_epoch,
            raw: raw.index.clone(),
            graphs: view.graphs.clone(),
        };
        let mut published = self.published.write().map_err(|_| {
            self.ready
                .store(false, std::sync::atomic::Ordering::Release);
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })?;
        *published = std::sync::Arc::new(next);
        drop(published);
        self.revision.send_replace(revision);
        Ok(raw.outcome(&identity, last))
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
        let receipt = view.source_receipt(identity)?.ok_or_else(|| {
            NativeStateSnafu {
                field: "raw source",
            }
            .build()
        })?;
        let raw = self.raw.until(control)?;
        self.check()?;
        let page = raw.freeze_page(
            &view.raw,
            &RawReceipt::Evidence(receipt),
            first_cursor,
            view.revision,
            control,
            crate::analysis::MAX_ANALYSIS_PAGE_RECORDS,
        )?;
        drop(raw);
        page.read(
            &self.root,
            control,
            crate::analysis::MAX_ANALYSIS_PAGE_BYTES,
        )
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn stage_raw(&mut self) -> Result<()> {
        self.note_relation("events", self.raw.evidence_revision)?;
        self.note_relation("source_receipts", self.raw.evidence_revision)?;
        self.note_relation("source_bindings", self.raw.binding_revision)?;
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
            let receipt = self
                .raw
                .sources
                .get(&key)
                .and_then(|source| source.receipt.evidence())
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "raw source baseline",
                    }
                    .build()
                })?;
            let encoded = Records::encode(receipt)?;
            Records::stage(
                &mut self.transaction,
                Sources::key(Sources::RECEIPTS, &key),
                encoded,
            );
            self.transaction.insert(
                Sources::key(Sources::EPOCHS, &receipt.identity.epoch_key()),
                Records::encode(&receipt.identity)?,
            );
        }
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        for id in segments {
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
