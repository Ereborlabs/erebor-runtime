use super::super::{DataView, DataWrite, NativeStore};
use super::{Records, Sources};
use crate::analysis::raw::RawReceipt;
use crate::analysis::raw::{RawBatch, RawIdentity, RawJournal, RawKind};
use crate :: { AnalysisReadControl , EvidenceIntakeIdentityV1 , NativeStateSnafu , NativeStorageSnafu , Result } ;
use crate :: { AnalysisReadPageV1 , AnalysisSourceReceiptV1 , EvidenceStoreOutcomeV1 , ValidatedEvidenceBatchV1 } ;
use fjall::BranchSnapshot;
use snafu::ResultExt as _;
use std :: { collections :: { BTreeMap , BTreeSet } , ops :: Bound :: Excluded } ;

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
                    ends.entry(entry.reference.id).and_modify(|end| *end = (*end).max(entry.reference.offset))
                        .or_insert(entry.reference.offset);
                }
            }
        }
        let deletions = super::super::retention::ExpiredSegment::finish_files(root, snapshot)?;
        let mut raw = RawJournal::open(root, &ends)?;
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
            let key = receipt.identity.key();
            let mut contiguous = 0u64;
            for (_, &(revision, slot)) in raw.index.ranges.range((key.clone(), 0)..=(key, u64::MAX)) {
                if revision > metadata { continue; }
                let span = &raw.index.entries[&revision].commit.spans[slot];
                if span.first > contiguous.saturating_add(1) { break; }
                contiguous = contiguous.max(span.last);
            }
            if contiguous != receipt.contiguous_cursor {
                return NativeStateSnafu { field: "raw receipt original prefix" }.fail();
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
        super::super::trace::Traces::recover(&mut raw, snapshot)?;
        raw.index.refresh_receipts()?;

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
            counts.add(reference.source.tenant_id, 0)?;
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
        batch.validate_identity(&identity, &self.root)?;
        if batch.intake_utc_ns == 0 {
            return crate::Error::reject_path(&self.root, "live evidence has no intake time");
        }
        self.commit_raw(RawIdentity::Evidence(identity), batch.into())
            .map(|(outcome, _)| outcome)
    }

    pub(in crate::analysis::native) fn commit_raw(
        &self,
        identity: RawIdentity,
        batch: RawBatch,
    ) -> Result<(EvidenceStoreOutcomeV1, RawReceipt)> {
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
        let diagnostic = identity.evidence().is_none();
        if diagnostic && !raw.index.sources.contains_key(&key) {
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
        if let Some(((_, first), last)) = raw.budget.expired
            .range((key.clone(), 0)..=(key.clone(), batch.last_cursor)).next_back()
            .filter(|(_, last)| **last >= batch.first_cursor) {
            if *first <= batch.first_cursor && *last >= batch.last_cursor {
                return Ok((EvidenceStoreOutcomeV1::AlreadyAcceptedExpired, raw.index.sources[&key].receipt.clone()));
            }
            if diagnostic {
                return crate::RetainedRangeExpiredSnafu { first_cursor: batch.first_cursor.max(*first), last_cursor: *last }.fail();
            }
            return crate::Error::reject_path(&self.root, "an evidence retry crosses an expired range boundary");
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
        if !diagnostic && (self.retention.raw_max_age_ns.is_some() || self.retention.raw_max_bytes.is_some()) {
            raw.reconcile_backlog(identity.tenant(), self.retention)?;
            if raw.budget.required.contains_key(&key) {
                if self.retention.raw_max_age_ns.is_some_and(|limit| raw.budget.oldest.get(&key)
                    .is_some_and(|intake| commit.intake.saturating_sub(*intake) >= limit)) {
                    return crate::ProtectedInputCapacitySnafu { resource: "age" }.fail();
                }
                if self.retention.raw_max_bytes.is_some_and(|limit| raw.budget.protected.get(&identity.tenant())
                    .copied().unwrap_or(0).checked_add(commit.body.len() as u64).is_none_or(|bytes| bytes > limit)) {
                    return crate::ProtectedInputCapacitySnafu { resource: "bytes" }.fail();
                }
            }
        }
        if !diagnostic && !raw.index.sources.contains_key(&key) {
            self.storage.check_sources(
                raw.index.sources.values().filter(|source| source.receipt.evidence().is_some()).count() + 1,
                0,
                false,
            )?;
        }
        let body_bytes = commit.body.len() as u64;
        let prior_cursor = raw.index.sources.get(&key).map_or(0, |source| source.receipt.cursor());
        let append = raw.prepare_append(&identity, commit)?;
        self.check_append_witnesses(&view, &raw, identity.tenant(), append.commit.intake, append.id, append.added())?;
        let terminal =
            matches!(&append.commit.kind, Some(RawKind::Diagnostic(progress)) if progress.terminal);
        let initial = diagnostic && !raw.segments.values().any(|segment| segment.source == key);
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
        if diagnostic || reserve != 0
            || self.storage.disk_max_bytes.is_some()
            || self.storage.policy_reserve_bytes.is_some()
            || self.storage.write_reserve_bytes.is_some()
            || self.storage.storage_entries.is_some()
            || self.storage.diagnostic_entries.is_some()
        {
            let added = append.added();
            let created = append.header.is_some();
            let terminal_only = matches!(&append.commit.kind, Some(RawKind::Diagnostic(progress))
                if progress.terminal && append.commit.spans.len() == 1 && progress.last_sequence.checked_add(1) == Some(append.commit.spans[0].first));
            let prepaid = terminal_only
                && added
                    .checked_add(batch.terminal_bytes as u64)
                    .is_some_and(|bytes| bytes <= crate::analysis::quota::TRACE_RESERVE);
            let usage = crate::StorageUsageV1::inspect(
                &self.root,
                usize::from(created && !diagnostic),
                slots
                    .checked_add(usize::from(created && diagnostic))
                    .ok_or_else(|| {
                        crate::StorageCapacitySnafu {
                            resource: "diagnostic storage entries",
                        }
                        .build()
                    })?,
                Some(&raw),
                self.storage,
            )?;
            let projected = added.checked_add(reserve).ok_or_else(|| {
                crate::StorageCapacitySnafu {
                    resource: "diagnostic physical reserve",
                }
                .build()
            })?;
            if prepaid {
                self.storage.check_terminal(usage, projected)?;
            } else {
                self.storage.check_append(usage, projected)?;
            }
        }
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
        if let Err(error) = raw.extend_backlog(&key, identity.tenant(), prior_cursor, body_bytes, self.retention) {
            self.poison();
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

    pub fn read_page(&self, identity: &EvidenceIntakeIdentityV1, first_cursor: u64) -> Result<AnalysisReadPageV1> {
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
        let receipt = view.source_receipt(identity)?.ok_or_else(|| {
            crate::AnalysisStateSnafu { path: &self.root, reason: "the raw source is absent" }.build()
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
            let source = self.raw.sources.get(&key).ok_or_else(|| {
                NativeStateSnafu {
                    field: "raw source baseline",
                }
                .build()
            })?;
            match &source.receipt {
                RawReceipt::Evidence(receipt) => {
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
                self.transaction.remove(Sources::key(Sources::ENDS, &id.to_be_bytes()));
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
