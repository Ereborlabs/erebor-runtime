use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::raw_segments::{
    EvidenceSegmentKindV1, EvidenceSegmentOwner, EvidenceSegmentReadV1, EvidenceSegmentRefV1,
    EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1,
};
use super::{source_key, AnalysisSourceReceiptV1, AnalysisStore, ValidatedEvidenceBatchV1};
use crate::{EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, Result};

impl AnalysisStore {
    pub fn read_page_cancel(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        control: &super::AnalysisReadControl,
    ) -> Result<super::AnalysisReadPageV1> {
        control.check()?;
        let _permit = self
            .read_slots
            .try_acquire()
            .map_err(|_| crate::AnalysisBusySnafu { resource: "reader" }.build())?;
        let coordinator = self.raw_coordinator(control)?;
        let _snapshot = control.lock(|| self.maintenance.try_read())?;
        let raw = control.lock(|| self.raw.try_lock())?;
        let key = source_key(identity);
        let source = raw
            .sources
            .get(&key)
            .filter(|source| &source.receipt.identity == identity)
            .ok_or_else(|| self.state_error("the evidence source is absent"))?;
        let receipt = &source.receipt;
        if first_cursor == 0 || first_cursor > receipt.contiguous_cursor.saturating_add(1) {
            return self.reject("the evidence read cursor is outside the accepted range");
        }
        let expired = raw
            .budget
            .expired
            .range((key, 0)..=(key, first_cursor))
            .next_back()
            .map(|(_, &last)| last)
            .filter(|last| *last >= first_cursor);
        if first_cursor <= receipt.retained_floor || expired.is_some() {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor,
                last_cursor: expired.unwrap_or(receipt.retained_floor),
            }
            .fail();
        }
        let expiry = raw
            .budget
            .expired
            .range((key, first_cursor)..=(key, u64::MAX))
            .next()
            .map(|((_, first), _)| *first)
            .filter(|first| *first <= receipt.contiguous_cursor);
        let page_end = expiry.map_or(receipt.contiguous_cursor, |first| first - 1);
        let mut frozen = Vec::new();
        let mut count = 0;
        let mut encoded_bytes = 0;
        let mut bounded = false;
        if first_cursor <= page_end {
            let start = raw
                .ranges
                .range((key, 0)..=(key, first_cursor))
                .next_back()
                .filter(|(_, (revision, index))| {
                    raw.entries[revision].commit.spans[*index].last >= first_cursor
                })
                .map_or(first_cursor, |((_, first), _)| *first);
            for (_, &(revision, index)) in raw.ranges.range((key, start)..=(key, page_end)) {
                control.check()?;
                let entry = &raw.entries[&revision];
                let span = &entry.commit.spans[index];
                let first = span.first.max(first_cursor);
                if first_cursor.checked_add(count as u64) != Some(first) {
                    return self.reject("the accepted evidence range has a missing record");
                }
                let mut last = None;
                for cursor in first..=span.last.min(page_end) {
                    let offset = (cursor - span.first) as usize;
                    let bytes = (span.ends[offset]
                        - if offset == 0 {
                            0
                        } else {
                            span.ends[offset - 1]
                        }) as usize;
                    if count == super::MAX_ANALYSIS_PAGE_RECORDS
                        || encoded_bytes + bytes > super::MAX_ANALYSIS_PAGE_BYTES
                    {
                        if count == 0 {
                            return self.reject("one evidence frame exceeds the read page bound");
                        }
                        bounded = true;
                        break;
                    }
                    encoded_bytes += bytes;
                    count += 1;
                    last = Some(cursor);
                }
                if let Some(last) = last {
                    frozen.push(raw.freeze(entry, index, first, last)?);
                }
                if bounded {
                    break;
                }
            }
        }
        let next_cursor = first_cursor.checked_add(count as u64);
        if next_cursor.is_some_and(|next| next <= page_end) && !bounded {
            return self.reject("the accepted evidence range has a missing record");
        }
        let next_cursor = next_cursor.filter(|next| *next <= receipt.contiguous_cursor);
        let read_revision = *self.revision.borrow();
        drop(raw);
        drop(coordinator);
        let mut records = Vec::with_capacity(count);
        for range in frozen {
            control.check()?;
            records.extend(range.read(&self.root)?);
        }
        control.check()?;
        Ok(super::AnalysisReadPageV1 {
            first_cursor,
            records,
            encoded_bytes,
            next_cursor,
            read_revision,
        })
    }

    pub(super) fn commit_evidence(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.validate_batch(&identity, &batch)?;
        let _writer = self.raw_access()?;
        let mut raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        self.require_retention()?;
        let key = source_key(&identity);
        if let Some(source) = raw.sources.get(&key) {
            if source.receipt.cpu_id != batch.cpu_id || source.receipt.identity != identity {
                return self.reject("the evidence source changed its identity or CPU");
            }
            if batch.first_cursor <= source.receipt.retained_floor {
                if batch.last_cursor <= source.receipt.retained_floor {
                    return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
                }
                return self.reject("an evidence retry crosses an expired range boundary");
            }
        }
        if let Some(((_, first), last)) = raw
            .budget
            .expired
            .range((key, 0)..=(key, batch.last_cursor))
            .next_back()
            .filter(|(_, last)| **last >= batch.first_cursor)
        {
            if *first <= batch.first_cursor && *last >= batch.last_cursor {
                return Ok(EvidenceStoreOutcomeV1::AlreadyAcceptedExpired);
            }
            return self.reject("an evidence retry crosses an expired range boundary");
        }
        let revision = (*self.revision.borrow())
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let commit = raw.prepare(&identity, &batch, revision)?;
        if commit.spans.is_empty() {
            return Ok(raw.outcome(&identity, batch.last_cursor));
        }
        let (stream, sequence) = raw.next_position(&identity)?;
        let (id, added, created) = raw.segments.append_plan(
            &identity,
            stream,
            sequence,
            commit.encoded_len() as u64 + 8,
        )?;
        let json =
            serde_json::to_string(&identity).context(crate::JsonSnafu { path: &self.root })?;
        let mut charge = added
            + commit
                .spans
                .iter()
                .map(|span| 256 + 4 * span.ends.len() as u64)
                .sum::<u64>();
        if created {
            charge += 256 + json.len() as u64;
        }
        if !raw.sources.contains_key(&key) {
            charge += 512 + json.len() as u64;
        }
        let scoped = raw
            .budget
            .usage
            .get(&identity.tenant_id)
            .copied()
            .unwrap_or(0);
        if scoped.checked_add(charge).is_none_or(|bytes| {
            bytes > self.storage.tenant_max_bytes - self.storage.tenant_max_bytes / 4
        }) {
            return crate::StorageCapacitySnafu {
                resource: "tenant logical bytes",
            }
            .fail();
        }
        if raw.budget.total.checked_add(charge).is_none_or(|bytes| {
            bytes > self.storage.logical_max_bytes - self.storage.logical_max_bytes / 4
        }) {
            return crate::StorageCapacitySnafu {
                resource: "global logical bytes",
            }
            .fail();
        }
        let required = raw.budget.required.contains_key(&key);
        if required {
            if raw.budget.oldest.get(&key).is_some_and(|time| {
                batch.intake_utc_ns.saturating_sub(*time) >= self.retention.raw_max_age_ns
            }) {
                return crate::ProtectedInputCapacitySnafu { resource: "age" }.fail();
            }
            let protected = raw
                .budget
                .protected
                .get(&identity.tenant_id)
                .copied()
                .unwrap_or(0);
            if protected
                .checked_add(commit.body.len() as u64)
                .is_none_or(|bytes| bytes > self.retention.raw_max_bytes)
            {
                return crate::ProtectedInputCapacitySnafu { resource: "bytes" }.fail();
            }
        }
        let mut witnesses = raw
            .budget
            .contexts
            .get(&identity.tenant_id)
            .copied()
            .unwrap_or(0);
        for descriptor in raw.segments.descriptors() {
            if raw
                .budget
                .pins
                .get(&descriptor.reference.id)
                .is_some_and(|(tenant, expiry)| {
                    *tenant == identity.tenant_id && *expiry > batch.intake_utc_ns
                })
            {
                witnesses += descriptor.reference.offset;
                if descriptor.reference.id == id {
                    witnesses += added;
                }
            }
        }
        if witnesses > self.storage.witness_max_bytes {
            return crate::StorageCapacitySnafu {
                resource: "tenant witness bytes",
            }
            .fail();
        }
        let usage = if created {
            self.storage_with_entries(1)?
        } else {
            self.storage_usage()?
        };
        self.storage.check_append(usage, added)?;
        let _rotation = if created
            && raw
                .sources
                .get(&key)
                .is_some_and(|source| source.stream != 0)
        {
            Some(
                self.maintenance
                    .write()
                    .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?,
            )
        } else {
            None
        };
        #[cfg(feature = "test-fixtures")]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeAppend)?;
        self.write_ready.store(false, Ordering::Release);
        #[cfg(test)]
        self.crash_at("evidence.before");
        let body_bytes = commit.body.len() as u64;
        let prior_cursor = raw
            .sources
            .get(&key)
            .map_or(0, |source| source.receipt.contiguous_cursor);
        raw.append(&identity, commit)?;
        #[cfg(feature = "test-fixtures")]
        self.run_commit_hook(super::AnalysisCommitStage::AfterSync)?;
        #[cfg(test)]
        self.crash_at("evidence.after");
        raw.budget.total += charge;
        *raw.budget.usage.entry(identity.tenant_id).or_default() += charge;
        if required {
            *raw.budget.protected.entry(identity.tenant_id).or_default() += body_bytes;
            let floor = raw.budget.required[&key];
            let contiguous = raw.sources[&key].receipt.contiguous_cursor;
            let oldest = prior_cursor
                .max(floor)
                .checked_add(1)
                .filter(|first| *first <= contiguous)
                .and_then(|first| {
                    raw.ranges
                        .range((key, first)..=(key, contiguous))
                        .map(|(_, (revision, _))| raw.entries[revision].commit.intake)
                        .min()
                });
            if let Some(oldest) = oldest {
                raw.budget
                    .oldest
                    .entry(key)
                    .and_modify(|time| *time = (*time).min(oldest))
                    .or_insert(oldest);
            }
        }
        self.write_ready.store(true, Ordering::Release);
        self.raw_pending.store(true, Ordering::Release);
        self.revision.send_replace(revision);
        Ok(raw.outcome(&identity, batch.last_cursor))
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct RawSpan {
    #[prost(uint64, tag = "1")]
    pub first: u64,
    #[prost(uint64, tag = "2")]
    pub last: u64,
    #[prost(uint32, tag = "3")]
    pub start: u32,
    #[prost(uint32, repeated, packed = "true", tag = "4")]
    pub ends: Vec<u32>,
    #[prost(uint32, tag = "5")]
    pub ordinal: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct RawCommit {
    #[prost(uint64, tag = "1")]
    pub revision: u64,
    #[prost(uint32, tag = "2")]
    pub cpu: u32,
    #[prost(uint64, tag = "3")]
    pub intake: u64,
    #[prost(message, repeated, tag = "4")]
    pub spans: Vec<RawSpan>,
    #[prost(bytes = "bytes", tag = "5")]
    pub body: prost::bytes::Bytes,
}

#[derive(Clone)]
pub(super) struct RawEntry {
    pub identity: EvidenceIntakeIdentityV1,
    pub commit: RawCommit,
    pub reference: EvidenceSegmentRefV1,
    pub stream: u64,
    pub sequence: u64,
    pub body_start: u64,
    pub body_bytes: usize,
    pub digests: Vec<[u8; 32]>,
}

pub(super) struct RawSource {
    pub receipt: AnalysisSourceReceiptV1,
    pub stream: u64,
    pub sequence: u64,
}

impl From<AnalysisSourceReceiptV1> for RawSource {
    fn from(receipt: AnalysisSourceReceiptV1) -> Self {
        Self {
            receipt,
            stream: 0,
            sequence: 0,
        }
    }
}

pub(super) struct RawRead {
    reader: EvidenceSegmentReadV1,
    span: RawSpan,
    digest: [u8; 32],
    revision: u64,
    cpu: u32,
    intake: u64,
    first: u64,
    last: u64,
}

impl RawRead {
    pub(super) fn read(self, root: &Path) -> Result<Vec<super::AnalysisRecordV1>> {
        let commit = self.reader.decode::<RawCommit>()?.pop().ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the frozen raw commit is absent",
            }
            .build()
        })?;
        commit.validate(root)?;
        if commit.revision != self.revision
            || commit.cpu != self.cpu
            || commit.intake != self.intake
            || !commit.spans.contains(&self.span)
        {
            return AnalysisStore::reject_path(root, "the frozen raw commit changed its metadata");
        }
        let bytes = &commit.body[self.span.start as usize
            ..self.span.start as usize + *self.span.ends.last().unwrap_or(&0) as usize];
        let mut digest = Sha256::new();
        digest.update((self.span.ends.len() as u64).to_be_bytes());
        for end in &self.span.ends {
            digest.update(u64::from(*end).to_be_bytes());
        }
        digest.update(bytes);
        if digest.finalize().as_slice() != self.digest {
            return AnalysisStore::reject_path(root, "the frozen raw range changed its content");
        }
        let mut records = Vec::new();
        for cursor in self.first..=self.last {
            let index = (cursor - self.span.first) as usize;
            let start = if index == 0 {
                0
            } else {
                self.span.ends[index - 1] as usize
            };
            let end = self.span.ends[index] as usize;
            records.push(super::AnalysisRecordV1 {
                cursor,
                framed_record: bytes[start..end].to_vec(),
                position: super::StorePositionV1 {
                    commit_revision: self.revision,
                    ordinal: self.span.ordinal + index as u32,
                },
            });
        }
        Ok(records)
    }
}

pub(super) struct RawJournal {
    pub root: PathBuf,
    pub segments: EvidenceSegmentOwner,
    pub sources: BTreeMap<[u8; 32], RawSource>,
    pub entries: BTreeMap<u64, RawEntry>,
    pub ranges: BTreeMap<([u8; 32], u64), (u64, usize)>,
    pub revision: u64,
    pub budget: super::raw_catalog::RawBudget,
}

impl RawJournal {
    pub(super) fn freeze(
        &self,
        entry: &RawEntry,
        index: usize,
        first: u64,
        last: u64,
    ) -> Result<RawRead> {
        Ok(RawRead {
            reader: self.reader(entry.reference.id, entry.stream, entry.sequence)?,
            span: entry.commit.spans[index].clone(),
            digest: entry.digests[index],
            revision: entry.commit.revision,
            cpu: entry.commit.cpu,
            intake: entry.commit.intake,
            first,
            last,
        })
    }
    pub(super) fn open(root: &Path, maximum: u64, committed: &BTreeMap<u64, u64>) -> Result<Self> {
        let segments = EvidenceSegmentOwner::open(
            &root.join("segments"),
            EvidenceStoreLimitsV1 {
                maximum_retained_bytes: maximum,
                maximum_retained_records: u64::MAX,
                capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
            },
            committed,
        )?;
        let identities: BTreeMap<_, _> = segments
            .identities()
            .map(|(stream, identity)| (stream, identity.clone()))
            .collect();
        let descriptors: Vec<_> = segments.descriptors().collect();
        let mut journal = Self {
            root: root.to_path_buf(),
            segments,
            sources: BTreeMap::new(),
            entries: BTreeMap::new(),
            ranges: BTreeMap::new(),
            revision: 0,
            budget: super::raw_catalog::RawBudget::default(),
        };
        for descriptor in descriptors {
            let EvidenceSegmentKindV1::Records {
                stream_id,
                first_cursor,
                last_cursor,
            } = descriptor.kind
            else {
                return AnalysisStore::reject_path(
                    root,
                    "the raw journal has an unknown stream kind",
                );
            };
            let identity = identities
                .get(&stream_id)
                .ok_or_else(|| journal.invalid("the raw stream identity is absent"))?;
            for sequence in first_cursor..=last_cursor {
                let reference = journal
                    .segments
                    .reference_at(descriptor.reference.id, sequence)?;
                let reader = journal.reader(reference.id, stream_id, sequence)?;
                let mut commits = reader.decode::<RawCommit>()?;
                let commit = commits
                    .pop()
                    .ok_or_else(|| journal.invalid("the raw commit is absent"))?;
                commit.validate(root)?;
                let body_bytes = commit.body.len();
                let body_start = reference
                    .offset
                    .checked_sub(4 + body_bytes as u64)
                    .ok_or_else(|| journal.invalid("the raw payload offset is invalid"))?;
                journal.publish(RawEntry {
                    identity: identity.clone(),
                    commit,
                    reference,
                    stream: stream_id,
                    sequence,
                    body_start,
                    body_bytes,
                    digests: Vec::new(),
                })?;
            }
        }
        journal.refresh_receipts()?;
        Ok(journal)
    }

    pub(super) fn prepare(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        batch: &ValidatedEvidenceBatchV1,
        revision: u64,
    ) -> Result<RawCommit> {
        let key = source_key(identity);
        let source = self.sources.get(&key);
        if let Some(source) = source {
            if &source.receipt.identity != identity || source.receipt.cpu_id != batch.cpu_id {
                return Err(self.invalid("the raw source changed its identity or CPU"));
            }
        } else {
            if self.sources.len() >= 4096 {
                return crate::StorageCapacitySnafu {
                    resource: "source bindings",
                }
                .fail();
            }
            if self.sources.values().any(|source| {
                let saved = &source.receipt.identity;
                saved.tenant_id == identity.tenant_id
                    && saved.node_id == identity.node_id
                    && saved.source_id == identity.source_id
                    && saved.source_epoch == identity.source_epoch
                    && saved != identity
            }) {
                return Err(self.invalid("one raw source epoch changed its boot or label"));
            }
        }
        let contiguous = source.map_or(0, |source| source.receipt.contiguous_cursor);
        if batch.first_cursor > contiguous.saturating_add(1)
            && batch.last_cursor > contiguous.saturating_add(crate::MAX_PENDING_EVIDENCE_RECORDS)
        {
            return Err(self.invalid("out-of-order evidence exceeds the pending window"));
        }
        let mut retained = vec![false; batch.frame_ends.len()];
        for (_, &(stored_revision, index)) in
            self.ranges.range((key, 0)..=(key, batch.last_cursor)).rev()
        {
            let entry = &self.entries[&stored_revision];
            let span = &entry.commit.spans[index];
            if span.last < batch.first_cursor {
                break;
            }
            let commit = self.read_entry(entry)?;
            for cursor in span.first.max(batch.first_cursor)..=span.last.min(batch.last_cursor) {
                let saved = (cursor - span.first) as usize;
                let input = (cursor - batch.first_cursor) as usize;
                let saved_start = if saved == 0 {
                    0
                } else {
                    span.ends[saved - 1] as usize
                };
                let input_start = if input == 0 {
                    0
                } else {
                    batch.frame_ends[input - 1]
                };
                let stored = &commit.body[span.start as usize + saved_start
                    ..span.start as usize + span.ends[saved] as usize];
                if stored != &batch.framed_records[input_start..batch.frame_ends[input]] {
                    return Err(self.invalid("an evidence retry has conflicting record content"));
                }
                retained[input] = true;
            }
        }
        let mut commit = RawCommit {
            revision,
            cpu: batch.cpu_id,
            intake: batch.intake_utc_ns,
            spans: Vec::new(),
            body: prost::bytes::Bytes::new(),
        };
        let mut body = Vec::new();
        let mut start = 0;
        let mut ordinal = 0;
        for (index, &end) in batch.frame_ends.iter().enumerate() {
            let cursor = batch.first_cursor + index as u64;
            if !retained[index] {
                if cursor <= contiguous {
                    return Err(self.invalid("an acknowledged evidence record is not retained"));
                }
                if commit
                    .spans
                    .last()
                    .is_none_or(|span| span.last.checked_add(1) != Some(cursor))
                {
                    commit.spans.push(RawSpan {
                        first: cursor,
                        last: cursor,
                        start: body.len() as u32,
                        ends: Vec::new(),
                        ordinal,
                    });
                }
                body.extend_from_slice(&batch.framed_records[start..end]);
                let span = commit
                    .spans
                    .last_mut()
                    .ok_or_else(|| self.invalid("the pending raw span is absent"))?;
                span.last = cursor;
                span.ends.push(body.len() as u32 - span.start);
                ordinal += 1;
            }
            start = end;
        }
        commit.body = body.into();
        Ok(commit)
    }

    pub(super) fn append(
        &mut self,
        identity: &EvidenceIntakeIdentityV1,
        commit: RawCommit,
    ) -> Result<()> {
        commit.validate(&self.root)?;
        let key = source_key(identity);
        let (stream, sequence) = self.next_position(identity)?;
        let body_bytes = commit.body.len();
        let payload = commit.encode_to_vec();
        let length = u32::try_from(payload.len())
            .map_err(|_| self.invalid("the raw commit is too large"))?;
        let mut frame = Vec::with_capacity(payload.len() + 8);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        let end = frame.len();
        let written = self.segments.write_frames(
            identity,
            stream,
            sequence,
            sequence,
            frame.into(),
            vec![end],
        )?;
        let [written] = written.as_slice() else {
            return Err(self.invalid("one raw commit crossed segment boundaries"));
        };
        if written.first_cursor != sequence || written.last_cursor != sequence {
            return Err(self.invalid("the raw writer returned a different commit sequence"));
        }
        let reference = written.segment;
        let body_start = reference.offset - 4 - body_bytes as u64;
        self.publish(RawEntry {
            identity: identity.clone(),
            commit,
            reference,
            stream,
            sequence,
            body_start,
            body_bytes,
            digests: Vec::new(),
        })?;
        self.refresh_source(&key)?;
        Ok(())
    }

    fn next_position(&self, identity: &EvidenceIntakeIdentityV1) -> Result<(u64, u64)> {
        let key = source_key(identity);
        let stream = match self.sources.get(&key).filter(|source| source.stream != 0) {
            Some(source) => source.stream,
            None => self
                .sources
                .values()
                .map(|source| source.stream)
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| self.invalid("the raw stream identity is exhausted"))?,
        };
        let sequence = self
            .sources
            .get(&key)
            .map_or(0, |source| source.sequence)
            .checked_add(1)
            .ok_or_else(|| self.invalid("the raw stream sequence is exhausted"))?;
        Ok((stream, sequence))
    }

    fn publish(&mut self, mut entry: RawEntry) -> Result<()> {
        if !super::valid_source_identity(&entry.identity) {
            return Err(self.invalid("the raw source identity is invalid"));
        }
        let key = source_key(&entry.identity);
        let revision = entry.commit.revision;
        if self.entries.contains_key(&revision) {
            return Err(self.invalid("the raw revision is duplicated"));
        }
        if !self.sources.contains_key(&key)
            && self.sources.values().any(|source| {
                let saved = &source.receipt.identity;
                saved.tenant_id == entry.identity.tenant_id
                    && saved.node_id == entry.identity.node_id
                    && saved.source_id == entry.identity.source_id
                    && saved.source_epoch == entry.identity.source_epoch
                    && saved != &entry.identity
            })
        {
            return Err(self.invalid("one raw source epoch changed its boot or label"));
        }
        for span in &entry.commit.spans {
            if self
                .ranges
                .range((key, 0)..=(key, span.last))
                .next_back()
                .is_some_and(|(_, &(prior, offset))| {
                    self.entries[&prior].commit.spans[offset].last >= span.first
                })
            {
                return Err(self.invalid("raw cursor ranges overlap"));
            }
            let mut digest = Sha256::new();
            digest.update((span.ends.len() as u64).to_be_bytes());
            for end in &span.ends {
                digest.update(u64::from(*end).to_be_bytes());
            }
            let start = span.start as usize;
            digest.update(
                &entry.commit.body[start..start + *span.ends.last().unwrap_or(&0) as usize],
            );
            entry.digests.push(digest.finalize().into());
        }
        let source = self.sources.entry(key).or_insert_with(|| RawSource {
            receipt: AnalysisSourceReceiptV1 {
                identity: entry.identity.clone(),
                cpu_id: entry.commit.cpu,
                contiguous_cursor: 0,
                coverage_revision: 0,
                retained_floor: 0,
            },
            stream: entry.stream,
            sequence: 0,
        });
        if source.stream == 0 {
            source.stream = entry.stream;
        }
        if source.receipt.identity != entry.identity
            || source.receipt.cpu_id != entry.commit.cpu
            || source.stream != entry.stream
        {
            return Err(self.invalid("the recovered raw source binding conflicts"));
        }
        source.sequence = source.sequence.max(entry.sequence);
        self.revision = self.revision.max(revision);
        for (index, span) in entry.commit.spans.iter().enumerate() {
            self.ranges.insert((key, span.first), (revision, index));
        }
        entry.commit.body = prost::bytes::Bytes::new();
        self.entries.insert(revision, entry);
        Ok(())
    }

    fn refresh_source(&mut self, key: &[u8; 32]) -> Result<()> {
        let mut contiguous = self
            .sources
            .get(key)
            .map_or(0, |source| source.receipt.contiguous_cursor);
        for (_, &(revision, index)) in self
            .ranges
            .range((*key, contiguous.saturating_add(1))..=(*key, u64::MAX))
        {
            let span = &self.entries[&revision].commit.spans[index];
            if span.first > contiguous.saturating_add(1) {
                break;
            }
            contiguous = contiguous.max(span.last);
        }
        if let Some(source) = self.sources.get_mut(key) {
            source.receipt.contiguous_cursor = contiguous;
        }
        Ok(())
    }

    pub(super) fn refresh_receipts(&mut self) -> Result<()> {
        let keys: Vec<_> = self.sources.keys().copied().collect();
        for key in keys {
            self.refresh_source(&key)?;
        }
        Ok(())
    }

    pub(super) fn outcome(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        last: u64,
    ) -> EvidenceStoreOutcomeV1 {
        if self
            .sources
            .get(&source_key(identity))
            .is_some_and(|source| source.receipt.contiguous_cursor >= last)
        {
            EvidenceStoreOutcomeV1::Accepted
        } else {
            EvidenceStoreOutcomeV1::Pending
        }
    }

    pub(super) fn reader(
        &self,
        id: u64,
        stream: u64,
        sequence: u64,
    ) -> Result<EvidenceSegmentReadV1> {
        self.segments
            .open_read(
                id,
                EvidenceSegmentKindV1::Records {
                    stream_id: stream,
                    first_cursor: sequence,
                    last_cursor: sequence,
                },
                1,
                crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES + 65544,
            )?
            .ok_or_else(|| self.invalid("the raw commit exceeds its read bound"))
    }

    pub(super) fn read_entry(&self, entry: &RawEntry) -> Result<RawCommit> {
        let mut commits = self
            .reader(entry.reference.id, entry.stream, entry.sequence)?
            .decode::<RawCommit>()?;
        let commit = commits
            .pop()
            .ok_or_else(|| self.invalid("the raw commit is absent"))?;
        commit.validate(&self.root)?;
        if commit.revision != entry.commit.revision
            || commit.cpu != entry.commit.cpu
            || commit.intake != entry.commit.intake
            || commit.spans != entry.commit.spans
            || commit.body.len() != entry.body_bytes
        {
            return Err(self.invalid("the raw commit changed its metadata"));
        }
        Ok(commit)
    }

    pub(super) fn invalid(&self, reason: &str) -> crate::Error {
        crate::AnalysisStateSnafu {
            path: &self.root,
            reason,
        }
        .build()
    }
}

impl RawCommit {
    fn validate(&self, root: &Path) -> Result<()> {
        let mut end = 0_u32;
        let mut ordinal = 0_usize;
        let mut prior = 0;
        for span in &self.spans {
            if span.first == 0
                || span.first <= prior
                || span.last < span.first
                || span.last - span.first + 1 != span.ends.len() as u64
                || span.start != end
                || span.ordinal as usize != ordinal
                || span.ends.is_empty()
                || span.ends.windows(2).any(|pair| pair[0] >= pair[1])
                || span.ends[0] == 0
            {
                return AnalysisStore::reject_path(root, "the raw commit range is invalid");
            }
            end = span
                .start
                .checked_add(*span.ends.last().unwrap_or(&0))
                .ok_or_else(|| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the raw commit offset is exhausted",
                    }
                    .build()
                })?;
            ordinal += span.ends.len();
            prior = span.last;
        }
        if self.revision == 0
            || self.intake == 0
            || ordinal == 0
            || ordinal > crate::MAX_EVIDENCE_BATCH_RECORDS
            || self.body.len() != end as usize
            || self.body.len() > crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES
        {
            return AnalysisStore::reject_path(root, "the raw commit bounds are invalid");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::FileExt as _;

    #[test]
    fn raw_acceptance_defers_catalogue() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        for cursor in 1..=4 {
            let outcome = store.accept_validated_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: cursor,
                    framed_records: vec![cursor as u8].into(),
                    frame_ends: vec![1],
                },
            )?;
            assert_eq!(outcome, EvidenceStoreOutcomeV1::Accepted);
            assert_eq!(
                store
                    .source_receipt(&identity)?
                    .ok_or("receipt absent")?
                    .contiguous_cursor,
                cursor
            );
            assert_eq!(
                store.source_binding(
                    identity.tenant_id,
                    &identity.node_id,
                    identity.source_id,
                    identity.source_epoch
                )?,
                Some(identity.clone())
            );
            assert_eq!(
                store.read_page(&identity, 1)?.records.len(),
                cursor as usize
            );
            let guard = store.writer.lock().map_err(|_| "writer lock poisoned")?;
            let writer = guard.as_ref().ok_or("writer closed")?;
            assert_eq!(
                writer.query_row("SELECT COUNT(*) FROM batch_ranges", [], |row| row
                    .get::<_, u64>(0))?,
                0
            );
            assert_eq!(
                writer.query_row("SELECT commit_revision FROM store_meta", [], |row| row
                    .get::<_, u64>(0))?,
                0
            );
        }
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, 4);
        let page = store.read_page(&identity, 1)?;
        assert_eq!(page.records.len(), 4);
        for (index, record) in page.records.iter().enumerate() {
            assert_eq!(record.cursor, index as u64 + 1);
            assert_eq!(record.framed_record, [index as u8 + 1]);
        }
        Ok(())
    }

    #[test]
    fn raw_recovers_without_database() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        AnalysisStore::segment_directory(root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let batch = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 2,
            last_cursor: 2,
            intake_utc_ns: 10,
            framed_records: prost::bytes::Bytes::from_static(b"b"),
            frame_ends: vec![1],
        };
        let mut journal = RawJournal::open(root, 64 * 1024 * 1024, &BTreeMap::new())?;
        let commit = journal.prepare(&identity, &batch, 1)?;
        journal.append(&identity, commit)?;
        assert_eq!(
            journal.outcome(&identity, 2),
            EvidenceStoreOutcomeV1::Pending
        );
        let batch = ValidatedEvidenceBatchV1 {
            first_cursor: 1,
            last_cursor: 3,
            framed_records: prost::bytes::Bytes::from_static(b"abc"),
            frame_ends: vec![1, 2, 3],
            ..batch
        };
        let commit = journal.prepare(&identity, &batch, 2)?;
        assert_eq!(commit.spans.len(), 2);
        journal.append(&identity, commit)?;
        assert_eq!(
            journal.outcome(&identity, 3),
            EvidenceStoreOutcomeV1::Accepted
        );
        let file = journal.segments.file_path(1)?.to_path_buf();
        let length = std::fs::metadata(&file)?.len();
        drop(journal);

        let mut tail = std::fs::OpenOptions::new().append(true).open(&file)?;
        tail.write_all(&[0, 0])?;
        tail.sync_all()?;
        drop(tail);
        let journal = RawJournal::open(root, 64 * 1024 * 1024, &BTreeMap::new())?;
        assert_eq!(std::fs::metadata(&file)?.len(), length);
        assert_eq!(
            journal.sources[&source_key(&identity)]
                .receipt
                .contiguous_cursor,
            3
        );
        assert_eq!(journal.revision, 2);
        assert!(journal.prepare(&identity, &batch, 3)?.spans.is_empty());
        let mut conflict = batch.clone();
        conflict.framed_records = prost::bytes::Bytes::from_static(b"axc");
        assert!(journal.prepare(&identity, &conflict, 3).is_err());
        conflict = batch;
        conflict.cpu_id = 1;
        assert!(journal.prepare(&identity, &conflict, 3).is_err());
        let entry = &journal.entries[&2];
        let body = journal.read_entry(entry)?.body;
        let stored =
            super::super::SegmentFile::reader(&file)?.read(entry.body_start, entry.body_bytes)?;
        assert_eq!(stored.as_slice(), body.as_ref());
        assert!(!root.join("analysis.duckdb").exists());
        drop(journal);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(file)?;
        let mut byte = [0];
        file.read_exact_at(&mut byte, length - 1)?;
        byte[0] ^= 1;
        file.write_all_at(&byte, length - 1)?;
        file.sync_all()?;
        assert!(RawJournal::open(root, 64 * 1024 * 1024, &BTreeMap::new()).is_err());
        Ok(())
    }
}
