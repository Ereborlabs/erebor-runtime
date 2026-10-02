use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::raw_segments::{
    EvidenceSegmentBoundsV1, EvidenceSegmentOwner, EvidenceSegmentReadV1, EvidenceSegmentRefV1,
};
use super::{source_key, AnalysisSourceReceiptV1, AnalysisStore, ValidatedEvidenceBatchV1};
use crate::{EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, Result};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum AnalysisStreamIdentityV1 {
    Evidence(EvidenceIntakeIdentityV1),
    Diagnostic(crate::TraceIdentityV1),
}

pub(super) use AnalysisStreamIdentityV1 as RawIdentity;

impl From<EvidenceIntakeIdentityV1> for RawIdentity {
    fn from(identity: EvidenceIntakeIdentityV1) -> Self {
        Self::Evidence(identity)
    }
}

impl From<crate::TraceIdentityV1> for RawIdentity {
    fn from(identity: crate::TraceIdentityV1) -> Self {
        Self::Diagnostic(identity)
    }
}

impl PartialEq<EvidenceIntakeIdentityV1> for RawIdentity {
    fn eq(&self, identity: &EvidenceIntakeIdentityV1) -> bool {
        matches!(self, Self::Evidence(saved) if saved == identity)
    }
}

impl RawIdentity {
    pub(super) fn key(&self) -> [u8; 32] {
        match self {
            Self::Evidence(identity) => source_key(identity),
            Self::Diagnostic(identity) => {
                let mut hash = Sha256::new();
                hash.update(b"ARAPHOR-DIAGNOSTIC-STREAM-V1\0");
                hash.update(identity.tenant_id);
                hash.update(identity.execution_id);
                hash.finalize().into()
            }
        }
    }

    pub(super) fn tenant(&self) -> [u8; 16] {
        match self {
            Self::Evidence(identity) => identity.tenant_id,
            Self::Diagnostic(identity) => identity.tenant_id,
        }
    }

    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Evidence(_) => "records",
            Self::Diagnostic(_) => "diagnostic",
        }
    }

    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Evidence(identity) => identity.valid(),
            Self::Diagnostic(identity) => identity.validate().is_ok(),
        }
    }

    pub(super) fn evidence(&self) -> Option<&EvidenceIntakeIdentityV1> {
        match self {
            Self::Evidence(identity) => Some(identity),
            Self::Diagnostic(_) => None,
        }
    }

    pub(super) fn json(&self, root: &Path) -> Result<String> {
        match self {
            Self::Evidence(identity) => serde_json::to_string(identity),
            Self::Diagnostic(identity) => serde_json::to_string(identity),
        }
        .context(crate::JsonSnafu { path: root })
    }

    pub(super) fn parse(kind: &str, json: &str, root: &Path) -> Result<Self> {
        match kind {
            "records" => serde_json::from_str(json).map(Self::Evidence),
            "diagnostic" => serde_json::from_str(json).map(Self::Diagnostic),
            _ => return AnalysisStore::reject_path(root, "the raw stream kind is invalid"),
        }
        .context(crate::JsonSnafu { path: root })
    }
}

struct RawBatch {
    kind: RawKind,
    first_cursor: u64,
    last_cursor: u64,
    intake_utc_ns: u64,
    framed_records: prost::bytes::Bytes,
    frame_ends: Vec<usize>,
    terminal_bytes: usize,
}

impl From<ValidatedEvidenceBatchV1> for RawBatch {
    fn from(batch: ValidatedEvidenceBatchV1) -> Self {
        Self {
            kind: RawKind::Evidence(batch.cpu_id),
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            intake_utc_ns: batch.intake_utc_ns,
            framed_records: batch.framed_records,
            frame_ends: batch.frame_ends,
            terminal_bytes: 0,
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct TraceRecord {
    #[prost(oneof = "TracePayload", tags = "1, 2, 3, 4")]
    payload: Option<TracePayload>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
enum TracePayload {
    #[prost(bytes, tag = "1")]
    Metadata(Vec<u8>),
    #[prost(bytes, tag = "2")]
    Data(Vec<u8>),
    #[prost(bytes, tag = "3")]
    Diagnostic(Vec<u8>),
    #[prost(bytes, tag = "4")]
    Terminal(Vec<u8>),
}

impl TraceRecord {
    fn read(bytes: &[u8], root: &Path) -> Result<TracePayload> {
        let record = Self::decode(bytes).map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace record is invalid",
            }
            .build()
        })?;
        if record.encode_to_vec() != bytes {
            return AnalysisStore::reject_path(root, "the trace record is not canonical");
        }
        record.payload.ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the trace record kind is absent",
            }
            .build()
        })
    }

    fn terminal(bytes: &[u8], root: &Path) -> Result<crate::TraceTerminalV1> {
        if bytes.len() > 4096 {
            return AnalysisStore::reject_path(root, "the trace terminal exceeds its reserve");
        }
        let terminal: crate::TraceTerminalV1 = serde_json::from_slice(bytes).map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace terminal is invalid",
            }
            .build()
        })?;
        terminal.validate().map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace terminal is invalid",
            }
            .build()
        })?;
        if serde_json::to_vec(&terminal).context(crate::JsonSnafu { path: root })? != bytes {
            return AnalysisStore::reject_path(root, "the trace terminal is not canonical");
        }
        Ok(terminal)
    }
}

impl RawBatch {
    fn trace(batch: &crate::TraceBatchV1, intake: u64, root: &Path) -> Result<Self> {
        batch.validate()?;
        if intake == 0 {
            return crate::TraceInvalidSnafu {
                reason: "the trace intake time is absent",
            }
            .fail();
        }
        let first = batch
            .frames
            .first()
            .map(|frame| frame.sequence)
            .or_else(|| {
                batch
                    .terminal
                    .as_ref()
                    .map(|terminal| terminal.last_sequence + 1)
            })
            .ok_or_else(|| {
                crate::TraceInvalidSnafu {
                    reason: "the trace batch is empty",
                }
                .build()
            })?;
        let mut bytes = Vec::new();
        let mut terminal_bytes = 0;
        let mut ends =
            Vec::with_capacity(batch.frames.len() + usize::from(batch.terminal.is_some()));
        for frame in &batch.frames {
            let payload = match frame.kind {
                crate::TraceFrameKindV1::Metadata => TracePayload::Metadata(frame.bytes.clone()),
                crate::TraceFrameKindV1::Data => TracePayload::Data(frame.bytes.clone()),
                crate::TraceFrameKindV1::Diagnostic => {
                    TracePayload::Diagnostic(frame.bytes.clone())
                }
            };
            TraceRecord {
                payload: Some(payload),
            }
            .encode(&mut bytes)
            .map_err(|_| {
                crate::TraceInvalidSnafu {
                    reason: "trace record encoding failed",
                }
                .build()
            })?;
            ends.push(bytes.len());
        }
        if let Some(terminal) = &batch.terminal {
            if batch
                .frames
                .last()
                .is_some_and(|frame| frame.sequence != terminal.last_sequence)
            {
                return crate::TraceInvalidSnafu {
                    reason: "the trace terminal skips output",
                }
                .fail();
            }
            let json = serde_json::to_vec(terminal).context(crate::JsonSnafu { path: root })?;
            terminal_bytes = json.len();
            if json.len() > 4096 {
                return crate::TraceInvalidSnafu {
                    reason: "the trace terminal exceeds its reserve",
                }
                .fail();
            }
            TraceRecord {
                payload: Some(TracePayload::Terminal(json)),
            }
            .encode(&mut bytes)
            .map_err(|_| {
                crate::TraceInvalidSnafu {
                    reason: "trace terminal encoding failed",
                }
                .build()
            })?;
            ends.push(bytes.len());
        }
        Ok(Self {
            kind: RawKind::Diagnostic(RawTraceMeta::default()),
            first_cursor: first,
            last_cursor: first + ends.len() as u64 - 1,
            intake_utc_ns: intake,
            framed_records: bytes.into(),
            frame_ends: ends,
            terminal_bytes,
        })
    }
}

impl AnalysisStore {
    pub fn read_page_cancel(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        control: &super::AnalysisReadControl,
    ) -> Result<super::AnalysisReadPageV1> {
        self.read_raw(
            &identity.clone().into(),
            first_cursor,
            control,
            super::MAX_ANALYSIS_PAGE_RECORDS,
            super::MAX_ANALYSIS_PAGE_BYTES,
        )
    }

    fn read_raw(
        &self,
        identity: &RawIdentity,
        first_cursor: u64,
        control: &super::AnalysisReadControl,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<super::AnalysisReadPageV1> {
        control.check()?;
        let _permit = self
            .read_slots
            .try_acquire()
            .map_err(|_| crate::AnalysisBusySnafu { resource: "reader" }.build())?;
        let coordinator = self.raw_coordinator(control)?;
        let _snapshot = control.lock(|| self.maintenance.try_read())?;
        let raw = control.lock(|| self.raw.try_lock())?;
        let key = identity.key();
        let source = raw
            .sources
            .get(&key)
            .filter(|source| source.receipt.matches(identity))
            .ok_or_else(|| self.state_error("the raw source is absent"))?;
        let receipt = &source.receipt;
        if first_cursor == 0 || first_cursor > receipt.cursor().saturating_add(1) {
            return self.reject("the evidence read cursor is outside the accepted range");
        }
        let expired = raw
            .budget
            .expired
            .range((key, 0)..=(key, first_cursor))
            .next_back()
            .map(|(_, &last)| last)
            .filter(|last| *last >= first_cursor);
        if first_cursor <= receipt.floor() || expired.is_some() {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor,
                last_cursor: expired.unwrap_or(receipt.floor()),
            }
            .fail();
        }
        let expiry = raw
            .budget
            .expired
            .range((key, first_cursor)..=(key, u64::MAX))
            .next()
            .map(|((_, first), _)| *first)
            .filter(|first| *first <= receipt.cursor());
        let page_end = expiry.map_or(receipt.cursor(), |first| first - 1);
        let mut frozen = Vec::new();
        let mut count = 0;
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
                let available = max_records - count;
                let last = span
                    .last
                    .min(page_end)
                    .min(first.saturating_add(available as u64 - 1));
                count += (last - first + 1) as usize;
                frozen.push(raw.freeze(entry, index, first, last)?);
                bounded = count == max_records;
                if bounded {
                    break;
                }
            }
        }
        let next_cursor = first_cursor.checked_add(count as u64);
        if next_cursor.is_some_and(|next| next <= page_end) && !bounded {
            return self.reject("the accepted evidence range has a missing record");
        }
        let accepted = receipt.cursor();
        let read_revision = *self.revision.borrow();
        drop(raw);
        drop(coordinator);
        #[cfg(any(test, feature = "test-fixtures"))]
        if matches!(identity, RawIdentity::Diagnostic(_)) {
            self.run_commit_hook(super::AnalysisCommitStage::AfterTraceFreeze)?;
        }
        let mut records = Vec::with_capacity(count);
        let mut encoded_bytes = 0;
        'pages: for range in frozen {
            control.check()?;
            for record in range.read(&self.root)? {
                if encoded_bytes + record.framed_record.len() > max_bytes {
                    if records.is_empty() {
                        return self.reject("one evidence frame exceeds the read page bound");
                    }
                    break 'pages;
                }
                encoded_bytes += record.framed_record.len();
                records.push(record);
            }
        }
        let next_cursor = first_cursor
            .checked_add(records.len() as u64)
            .filter(|next| *next <= accepted);
        control.check()?;
        Ok(super::AnalysisReadPageV1 {
            first_cursor,
            records,
            encoded_bytes,
            next_cursor,
            read_revision,
        })
    }

    pub fn append_trace(
        &self,
        identity: &crate::TraceIdentityV1,
        batch: &crate::TraceBatchV1,
        intake_utc_ns: u64,
    ) -> Result<TraceOutputReceiptV1> {
        identity.validate()?;
        if batch.execution_id != identity.execution_id {
            return crate::TraceInvalidSnafu {
                reason: "the trace batch execution differs",
            }
            .fail();
        }
        let input = RawBatch::trace(batch, intake_utc_ns, &self.root)?;
        let first = input.first_cursor;
        let last = input.last_cursor;
        let (outcome, receipt) = self.commit_raw(identity.clone().into(), input)?;
        let RawReceipt::Diagnostic(receipt) = receipt else {
            return self.reject("the durable trace receipt has the wrong kind");
        };
        if outcome == EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
            && batch.frames.is_empty()
            && receipt.terminal != batch.terminal
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if outcome == EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
            && !(batch.frames.is_empty() && receipt.terminal == batch.terminal)
        {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: first,
                last_cursor: last,
            }
            .fail();
        }
        Ok(receipt)
    }

    pub fn trace_receipt(
        &self,
        identity: &crate::TraceIdentityV1,
    ) -> Result<Option<TraceOutputReceiptV1>> {
        identity.validate()?;
        let _writer = self.raw_access()?;
        let raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        let source = RawIdentity::Diagnostic(identity.clone());
        Ok(raw
            .sources
            .get(&source.key())
            .and_then(|source| match &source.receipt {
                RawReceipt::Diagnostic(receipt) if &receipt.identity == identity => {
                    Some(receipt.clone())
                }
                _ => None,
            }))
    }

    pub fn read_trace(
        &self,
        identity: &crate::TraceIdentityV1,
        first_cursor: u64,
        control: &super::AnalysisReadControl,
    ) -> Result<TraceOutputPageV1> {
        identity.validate()?;
        let page = self.read_raw(
            &identity.clone().into(),
            first_cursor,
            control,
            201,
            crate::MAX_TRACE_FRAME_BYTES + 201 * 8 + 4096,
        )?;
        let mut output = TraceOutputPageV1 {
            frames: Vec::new(),
            terminal: None,
            positions: Vec::new(),
            terminal_position: None,
            next_cursor: page.next_cursor,
            read_revision: page.read_revision,
        };
        let mut bytes = 0;
        for record in page.records {
            control.check()?;
            let payload = TraceRecord::read(&record.framed_record, &self.root)?;
            let (kind, data) = match payload {
                TracePayload::Metadata(data) => (crate::TraceFrameKindV1::Metadata, data),
                TracePayload::Data(data) => (crate::TraceFrameKindV1::Data, data),
                TracePayload::Diagnostic(data) => (crate::TraceFrameKindV1::Diagnostic, data),
                TracePayload::Terminal(data) => {
                    output.terminal = Some(TraceRecord::terminal(&data, &self.root)?);
                    output.terminal_position = Some(record.position);
                    continue;
                }
            };
            if output.frames.len() == 200 || bytes + data.len() > crate::MAX_TRACE_FRAME_BYTES {
                output.next_cursor = Some(record.cursor);
                break;
            }
            bytes += data.len();
            output.positions.push(record.position);
            output.frames.push(crate::TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: record.cursor,
                kind,
                bytes: data,
            });
        }
        Ok(output)
    }

    pub(super) fn commit_evidence(
        &self,
        identity: EvidenceIntakeIdentityV1,
        batch: ValidatedEvidenceBatchV1,
    ) -> Result<EvidenceStoreOutcomeV1> {
        self.validate_batch(&identity, &batch)?;
        self.commit_raw(identity.into(), batch.into())
            .map(|(outcome, _)| outcome)
    }

    fn commit_raw(
        &self,
        identity: RawIdentity,
        batch: RawBatch,
    ) -> Result<(EvidenceStoreOutcomeV1, RawReceipt)> {
        let writer = self.raw_access()?;
        let mut raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        self.require_retention()?;
        let key = identity.key();
        let tenant = identity.tenant();
        if let RawIdentity::Diagnostic(trace) = &identity {
            if raw
                .sources
                .get(&key)
                .is_none_or(|source| source.stream == 0)
            {
                let (_, intent) = Self::read_trace_intent(
                    writer.get()?,
                    &self.root,
                    trace.tenant_id,
                    trace.request_id,
                )?
                .ok_or_else(|| {
                    crate::TraceInvalidSnafu {
                        reason: "the diagnostic execution is not admitted",
                    }
                    .build()
                })?;
                if !intent
                    .bindings
                    .iter()
                    .any(|binding| binding.identity == *trace)
                {
                    return crate::AnalysisConflictSnafu.fail();
                }
            }
        }
        if let Some(source) = raw.sources.get(&key) {
            if source.receipt.cpu() != batch.kind.cpu() || !source.receipt.matches(&identity) {
                if matches!(identity, RawIdentity::Diagnostic(_)) {
                    return crate::AnalysisConflictSnafu.fail();
                }
                return self.reject("the evidence source changed its identity or CPU");
            }
            if batch.first_cursor <= source.receipt.floor() {
                if batch.last_cursor <= source.receipt.floor() {
                    return Ok((
                        EvidenceStoreOutcomeV1::AlreadyAcceptedExpired,
                        source.receipt.clone(),
                    ));
                }
                if matches!(identity, RawIdentity::Diagnostic(_)) {
                    return crate::RetainedRangeExpiredSnafu {
                        first_cursor: batch.first_cursor,
                        last_cursor: source.receipt.floor(),
                    }
                    .fail();
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
                return Ok((
                    EvidenceStoreOutcomeV1::AlreadyAcceptedExpired,
                    raw.sources[&key].receipt.clone(),
                ));
            }
            if matches!(identity, RawIdentity::Diagnostic(_)) {
                return crate::RetainedRangeExpiredSnafu {
                    first_cursor: batch.first_cursor.max(*first),
                    last_cursor: *last,
                }
                .fail();
            }
            return self.reject("an evidence retry crosses an expired range boundary");
        }
        let revision = (*self.revision.borrow())
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        let commit = raw.prepare(&identity, &batch, revision)?;
        if commit.spans.is_empty() {
            return Ok((
                raw.outcome(&identity, batch.last_cursor),
                raw.sources[&key].receipt.clone(),
            ));
        }
        let (stream, sequence) = raw.next_position(&identity)?;
        let (id, added, created) = raw.segments.append_plan(
            &identity,
            stream,
            sequence,
            commit.encoded_len() as u64 + 8,
        )?;
        let json = identity.json(&self.root)?;
        let mut charge = added;
        if created {
            charge += 256 + json.len() as u64;
        }
        if !raw.sources.contains_key(&key) {
            charge += 512 + json.len() as u64;
        }
        let diagnostic = matches!(identity, RawIdentity::Diagnostic(_));
        let terminal =
            matches!(&commit.kind, Some(RawKind::Diagnostic(progress)) if progress.terminal);
        let released_reserve = if terminal {
            super::quota::TRACE_RESERVE
        } else {
            0
        };
        if terminal {
            charge += batch.terminal_bytes as u64;
        }
        let prepaid = charge <= released_reserve
            && matches!(&commit.kind, Some(RawKind::Diagnostic(progress)) if progress.terminal
                && commit.spans.len() == 1 && commit.spans[0].first == progress.last_sequence + 1);
        let initial = diagnostic
            && !raw
                .segments
                .descriptors()
                .any(|segment| segment.bounds.stream_id == stream);
        let released_slots = if terminal {
            if initial {
                2
            } else {
                1
            }
        } else {
            usize::from(initial && created)
        };
        let trace_slots = raw
            .budget
            .trace_slots
            .checked_sub(released_slots)
            .ok_or_else(|| self.state_error("the diagnostic slot reserve underflows"))?;
        let trace_reserve = raw
            .budget
            .trace_reserve
            .checked_sub(released_reserve)
            .ok_or_else(|| self.state_error("the diagnostic byte reserve underflows"))?;
        let scoped = raw.budget.usage.get(&tenant).copied().unwrap_or(0);
        if scoped
            .checked_add(charge)
            .and_then(|bytes| bytes.checked_sub(released_reserve))
            .is_none_or(|bytes| {
                bytes
                    > self.storage.tenant_max_bytes
                        - if prepaid {
                            0
                        } else {
                            self.storage.tenant_max_bytes / 4
                        }
            })
        {
            return crate::StorageCapacitySnafu {
                resource: "tenant logical bytes",
            }
            .fail();
        }
        if raw
            .budget
            .total
            .checked_add(charge)
            .and_then(|bytes| bytes.checked_sub(released_reserve))
            .is_none_or(|bytes| {
                bytes
                    > self.storage.logical_max_bytes
                        - if prepaid {
                            0
                        } else {
                            self.storage.logical_max_bytes / 4
                        }
            })
        {
            return crate::StorageCapacitySnafu {
                resource: "global logical bytes",
            }
            .fail();
        }
        if diagnostic {
            let tenant_bytes = raw.budget.diagnostics.get(&tenant).copied().unwrap_or(0);
            if tenant_bytes
                .checked_add(charge)
                .and_then(|bytes| bytes.checked_sub(released_reserve))
                .is_none_or(|bytes| bytes > self.storage.tenant_max_bytes / 8)
                || raw
                    .budget
                    .diagnostic_total
                    .checked_add(charge)
                    .and_then(|bytes| bytes.checked_sub(released_reserve))
                    .is_none_or(|bytes| bytes > self.storage.logical_max_bytes / 8)
            {
                return crate::StorageCapacitySnafu {
                    resource: "diagnostic logical bytes",
                }
                .fail();
            }
        }
        let required = raw.budget.required.contains_key(&key);
        if required {
            if raw.budget.oldest.get(&key).is_some_and(|time| {
                batch.intake_utc_ns.saturating_sub(*time) >= self.retention.raw_max_age_ns
            }) {
                return crate::ProtectedInputCapacitySnafu { resource: "age" }.fail();
            }
            let protected = raw.budget.protected.get(&tenant).copied().unwrap_or(0);
            if protected
                .checked_add(commit.body.len() as u64)
                .is_none_or(|bytes| bytes > self.retention.raw_max_bytes)
            {
                return crate::ProtectedInputCapacitySnafu { resource: "bytes" }.fail();
            }
        }
        let mut witnesses = raw.budget.contexts.get(&tenant).copied().unwrap_or(0);
        for descriptor in raw.segments.descriptors() {
            if raw
                .budget
                .pins
                .get(&descriptor.reference.id)
                .is_some_and(|(tenant, expiry)| {
                    *tenant == identity.tenant() && *expiry > batch.intake_utc_ns
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
        let usage = self.storage_with_reserve(
            usize::from(created && !diagnostic),
            trace_slots + usize::from(created && diagnostic),
        )?;
        let projected = added
            .checked_add(trace_reserve)
            .ok_or_else(|| self.state_error("the diagnostic physical reserve is exhausted"))?;
        if prepaid {
            self.storage.check_terminal(usage, projected)?;
        } else {
            self.storage.check_append(usage, projected)?;
        }
        let _rotation = if created
            && raw
                .sources
                .get(&key)
                .is_some_and(|source| source.stream != 0)
        {
            drop(raw);
            #[cfg(any(test, feature = "test-fixtures"))]
            self.run_commit_hook(super::AnalysisCommitStage::BeforeRotation)?;
            let rotation = self
                .maintenance
                .write()
                .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?;
            raw = self
                .raw
                .lock()
                .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
            Some(rotation)
        } else {
            None
        };
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::BeforeAppend)?;
        self.write_ready.store(false, Ordering::Release);
        #[cfg(test)]
        self.crash_at("evidence.before");
        let body_bytes = commit.body.len() as u64;
        let prior_cursor = raw
            .sources
            .get(&key)
            .map_or(0, |source| source.receipt.cursor());
        raw.append(&identity, commit)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::AnalysisCommitStage::AfterSync)?;
        #[cfg(test)]
        self.crash_at("evidence.after");
        raw.budget.total += charge;
        raw.budget.total -= released_reserve;
        *raw.budget.usage.entry(tenant).or_default() += charge;
        *raw.budget.usage.entry(tenant).or_default() -= released_reserve;
        raw.budget.trace_slots = trace_slots;
        raw.budget.trace_reserve = trace_reserve;
        if diagnostic {
            raw.budget.diagnostic_total += charge;
            raw.budget.diagnostic_total -= released_reserve;
            *raw.budget.diagnostics.entry(tenant).or_default() += charge;
            *raw.budget.diagnostics.entry(tenant).or_default() -= released_reserve;
        }
        if required {
            *raw.budget.protected.entry(tenant).or_default() += body_bytes;
            let floor = raw.budget.required[&key];
            let contiguous = raw.sources[&key].receipt.cursor();
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
        Ok((
            raw.outcome(&identity, batch.last_cursor),
            raw.sources[&key].receipt.clone(),
        ))
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
    #[prost(oneof = "RawKind", tags = "2, 6")]
    pub kind: Option<RawKind>,
    #[prost(uint64, tag = "3")]
    pub intake: u64,
    #[prost(message, repeated, tag = "4")]
    pub spans: Vec<RawSpan>,
    #[prost(bytes = "bytes", tag = "7")]
    pub body: prost::bytes::Bytes,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(super) enum RawKind {
    #[prost(uint32, tag = "2")]
    Evidence(u32),
    #[prost(message, tag = "6")]
    Diagnostic(RawTraceMeta),
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct RawTraceMeta {
    #[prost(uint64, tag = "1")]
    pub last_sequence: u64,
    #[prost(uint64, tag = "2")]
    pub output_bytes: u64,
    #[prost(bool, tag = "3")]
    pub terminal: bool,
}

impl RawKind {
    pub(super) fn cpu(&self) -> Option<u32> {
        match self {
            Self::Evidence(cpu) => Some(*cpu),
            Self::Diagnostic(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceOutputReceiptV1 {
    pub identity: crate::TraceIdentityV1,
    pub last_sequence: u64,
    pub output_bytes: u64,
    pub terminal: Option<crate::TraceTerminalV1>,
    pub retained_floor: u64,
    pub commit_revision: u64,
}

impl TraceOutputReceiptV1 {
    pub(super) fn cursor(&self) -> u64 {
        self.last_sequence + u64::from(self.terminal.is_some())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceOutputPageV1 {
    pub frames: Vec<crate::TraceFrameV1>,
    pub terminal: Option<crate::TraceTerminalV1>,
    pub positions: Vec<super::StorePositionV1>,
    pub terminal_position: Option<super::StorePositionV1>,
    pub next_cursor: Option<u64>,
    pub read_revision: u64,
}

#[derive(Clone, Debug)]
pub(super) enum RawReceipt {
    Evidence(AnalysisSourceReceiptV1),
    Diagnostic(TraceOutputReceiptV1),
}

impl RawReceipt {
    pub(super) fn matches(&self, identity: &RawIdentity) -> bool {
        match (self, identity) {
            (Self::Evidence(receipt), RawIdentity::Evidence(identity)) => {
                &receipt.identity == identity
            }
            (Self::Diagnostic(receipt), RawIdentity::Diagnostic(identity)) => {
                &receipt.identity == identity
            }
            _ => false,
        }
    }

    pub(super) fn cursor(&self) -> u64 {
        match self {
            Self::Evidence(receipt) => receipt.contiguous_cursor,
            Self::Diagnostic(receipt) => receipt.cursor(),
        }
    }

    pub(super) fn floor(&self) -> u64 {
        match self {
            Self::Evidence(receipt) => receipt.retained_floor,
            Self::Diagnostic(receipt) => receipt.retained_floor,
        }
    }

    pub(super) fn set_floor(&mut self, floor: u64) {
        match self {
            Self::Evidence(receipt) => receipt.retained_floor = floor,
            Self::Diagnostic(receipt) => receipt.retained_floor = floor,
        }
    }

    pub(super) fn evidence(&self) -> Option<&AnalysisSourceReceiptV1> {
        match self {
            Self::Evidence(receipt) => Some(receipt),
            Self::Diagnostic(_) => None,
        }
    }

    pub(super) fn cpu(&self) -> Option<u32> {
        self.evidence().map(|receipt| receipt.cpu_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RawRange {
    pub first: u64,
    pub last: u64,
    pub start: u32,
    pub bytes: u32,
    pub ordinal: u32,
}

impl From<&RawSpan> for RawRange {
    fn from(span: &RawSpan) -> Self {
        Self {
            first: span.first,
            last: span.last,
            start: span.start,
            bytes: *span.ends.last().unwrap_or(&0),
            ordinal: span.ordinal,
        }
    }
}

#[derive(Clone)]
pub(super) struct RawMeta {
    pub revision: u64,
    pub kind: RawKind,
    pub intake: u64,
    pub spans: Vec<RawRange>,
}

impl TryFrom<&RawCommit> for RawMeta {
    type Error = crate::Error;

    fn try_from(commit: &RawCommit) -> Result<Self> {
        Ok(Self {
            revision: commit.revision,
            kind: commit.kind.clone().ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: Path::new("<raw-commit>"),
                    reason: "the raw commit kind is absent",
                }
                .build()
            })?,
            intake: commit.intake,
            spans: commit.spans.iter().map(RawRange::from).collect(),
        })
    }
}

#[derive(Clone)]
pub(super) struct RawEntry {
    pub identity: RawIdentity,
    pub commit: RawMeta,
    pub reference: EvidenceSegmentRefV1,
    pub stream: u64,
    pub sequence: u64,
    pub body_start: u64,
    pub body_bytes: usize,
    pub frame_bytes: usize,
}

pub(super) struct RawSource {
    pub receipt: RawReceipt,
    pub stream: u64,
    pub sequence: u64,
}

impl From<AnalysisSourceReceiptV1> for RawSource {
    fn from(receipt: AnalysisSourceReceiptV1) -> Self {
        Self {
            receipt: RawReceipt::Evidence(receipt),
            stream: 0,
            sequence: 0,
        }
    }
}

pub(super) struct RawRead {
    reader: EvidenceSegmentReadV1,
    span: RawRange,
    revision: u64,
    kind: RawKind,
    intake: u64,
    first: u64,
    last: u64,
}

impl RawRead {
    pub(super) fn read(&self, root: &Path) -> Result<Vec<super::AnalysisRecordV1>> {
        let commit = self.reader.decode::<RawCommit>()?.pop().ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the frozen raw commit is absent",
            }
            .build()
        })?;
        commit.validate(root)?;
        let span = commit
            .spans
            .iter()
            .find(|span| RawRange::from(*span) == self.span);
        if commit.revision != self.revision
            || commit.kind.as_ref() != Some(&self.kind)
            || commit.intake != self.intake
            || span.is_none()
        {
            return AnalysisStore::reject_path(root, "the frozen raw commit changed its metadata");
        }
        let span = span.ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the frozen raw span is absent",
            }
            .build()
        })?;
        let bytes =
            &commit.body[span.start as usize..span.start as usize + self.span.bytes as usize];
        let mut records = Vec::new();
        for cursor in self.first..=self.last {
            let index = (cursor - self.span.first) as usize;
            let start = if index == 0 {
                0
            } else {
                span.ends[index - 1] as usize
            };
            let end = span.ends[index] as usize;
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
    fn prepare_trace(&self, identity: &RawIdentity, commit: &mut RawCommit) -> Result<()> {
        let RawIdentity::Diagnostic(identity) = identity else {
            return Ok(());
        };
        if commit.spans.is_empty() {
            return Ok(());
        }
        let saved = self
            .sources
            .get(&RawIdentity::Diagnostic(identity.clone()).key())
            .and_then(|source| match &source.receipt {
                RawReceipt::Diagnostic(receipt) => Some(receipt),
                RawReceipt::Evidence(_) => None,
            });
        let mut progress = RawTraceMeta {
            last_sequence: saved.map_or(0, |receipt| receipt.last_sequence),
            output_bytes: saved.map_or(0, |receipt| receipt.output_bytes),
            terminal: saved.is_some_and(|receipt| receipt.terminal.is_some()),
        };
        for (cursor, bytes) in commit.records() {
            if progress.terminal {
                return crate::AnalysisConflictSnafu.fail();
            }
            if cursor != progress.last_sequence + 1 {
                return crate::TraceInvalidSnafu {
                    reason: "the diagnostic output skips a sequence",
                }
                .fail();
            }
            match TraceRecord::read(bytes, &self.root)? {
                TracePayload::Metadata(bytes)
                | TracePayload::Data(bytes)
                | TracePayload::Diagnostic(bytes) => {
                    if bytes.is_empty() || bytes.len() > crate::MAX_TRACE_FRAME_BYTES {
                        return crate::TraceInvalidSnafu {
                            reason: "the diagnostic frame size is invalid",
                        }
                        .fail();
                    }
                    progress.last_sequence = cursor;
                    progress.output_bytes += bytes.len() as u64;
                }
                TracePayload::Terminal(bytes) => {
                    let terminal = TraceRecord::terminal(&bytes, &self.root)?;
                    if terminal.execution_id != identity.execution_id
                        || terminal.last_sequence != progress.last_sequence
                        || terminal.output_bytes != progress.output_bytes
                    {
                        return crate::TraceInvalidSnafu {
                            reason: "the diagnostic terminal differs from accepted output",
                        }
                        .fail();
                    }
                    progress.terminal = true;
                }
            }
            if progress.last_sequence > 4096
                || progress.output_bytes > crate::MAX_TRACE_OUTPUT_BYTES
            {
                return crate::TraceInvalidSnafu {
                    reason: "the diagnostic execution exceeds its output bound",
                }
                .fail();
            }
        }
        commit.kind = Some(RawKind::Diagnostic(progress));
        Ok(())
    }

    pub(super) fn commit_receipt(
        &self,
        entry: &RawEntry,
        commit: &RawCommit,
    ) -> Result<RawReceipt> {
        match (&entry.identity, &entry.commit.kind) {
            (RawIdentity::Evidence(identity), RawKind::Evidence(cpu)) => {
                Ok(RawReceipt::Evidence(AnalysisSourceReceiptV1 {
                    identity: identity.clone(),
                    cpu_id: *cpu,
                    contiguous_cursor: 0,
                    coverage_revision: 0,
                    retained_floor: 0,
                }))
            }
            (RawIdentity::Diagnostic(identity), RawKind::Diagnostic(progress)) => {
                if commit.spans.len() != 1 {
                    return Err(self.invalid("the diagnostic commit has disjoint output"));
                }
                let mut terminal = None;
                let mut added = 0_u64;
                let mut frames = 0_u64;
                let mut last = 0;
                for (cursor, bytes) in commit.records() {
                    if terminal.is_some() {
                        return Err(self.invalid("the diagnostic terminal is not last"));
                    }
                    last = cursor;
                    match TraceRecord::read(bytes, &self.root)? {
                        TracePayload::Metadata(bytes)
                        | TracePayload::Data(bytes)
                        | TracePayload::Diagnostic(bytes) => {
                            if bytes.is_empty()
                                || bytes.len() > crate::MAX_TRACE_FRAME_BYTES
                                || cursor > progress.last_sequence
                            {
                                return Err(
                                    self.invalid("the recovered diagnostic frame is invalid")
                                );
                            }
                            added += bytes.len() as u64;
                            frames += 1;
                        }
                        TracePayload::Terminal(bytes) => {
                            let value = TraceRecord::terminal(&bytes, &self.root)?;
                            if value.execution_id != identity.execution_id
                                || value.last_sequence != progress.last_sequence
                                || value.output_bytes != progress.output_bytes
                                || cursor != value.last_sequence + 1
                            {
                                return Err(
                                    self.invalid("the recovered diagnostic terminal conflicts")
                                );
                            }
                            terminal = Some(value);
                        }
                    }
                }
                if progress.last_sequence > 4096
                    || progress.output_bytes > crate::MAX_TRACE_OUTPUT_BYTES
                    || progress.output_bytes < added
                    || progress.output_bytes < progress.last_sequence
                    || progress.terminal != terminal.is_some()
                    || last != progress.last_sequence + u64::from(progress.terminal)
                {
                    return Err(self.invalid("the recovered diagnostic progress is invalid"));
                }
                let saved =
                    self.sources.get(&entry.identity.key()).and_then(|source| {
                        match &source.receipt {
                            RawReceipt::Diagnostic(receipt) => Some(receipt),
                            RawReceipt::Evidence(_) => None,
                        }
                    });
                let first = commit.spans[0].first;
                let prior_cursor = saved.map_or(0, TraceOutputReceiptV1::cursor);
                if first == prior_cursor + 1
                    && (saved.map_or(0, |receipt| receipt.last_sequence) + frames
                        != progress.last_sequence
                        || saved.map_or(0, |receipt| receipt.output_bytes) + added
                            != progress.output_bytes)
                {
                    return Err(
                        self.invalid("the diagnostic cumulative counters differ from output")
                    );
                }
                let retained_floor = self
                    .sources
                    .get(&entry.identity.key())
                    .map_or(0, |source| source.receipt.floor());
                Ok(RawReceipt::Diagnostic(TraceOutputReceiptV1 {
                    identity: identity.clone(),
                    last_sequence: progress.last_sequence,
                    output_bytes: progress.output_bytes,
                    terminal,
                    retained_floor,
                    commit_revision: entry.commit.revision,
                }))
            }
            _ => Err(self.invalid("the raw commit kind differs from its stream")),
        }
    }

    pub(super) fn selection_revision(
        &self,
        selection: &super::AnalysisSelectionV1,
        revision: u64,
        control: &super::AnalysisReadControl,
    ) -> Result<u64> {
        let Some((from, until)) = selection.time_range() else {
            return Ok(0);
        };
        let mut latest = 0;
        for identity in &selection.sources {
            control.check()?;
            let key = source_key(identity);
            for (_, &(id, _)) in self.ranges.range((key, 0)..=(key, u64::MAX)) {
                control.check()?;
                if id > revision || id <= latest {
                    continue;
                }
                let entry = &self.entries[&id];
                if &entry.identity == identity
                    && entry.commit.intake >= from
                    && entry.commit.intake <= until
                {
                    latest = id;
                }
            }
        }
        Ok(latest)
    }

    pub(super) fn select_position(
        &self,
        selection: &super::AnalysisSelectionV1,
        after: Option<super::StorePositionV1>,
        revision: u64,
        limit: usize,
        control: &super::AnalysisReadControl,
    ) -> Result<Option<(EvidenceIntakeIdentityV1, u32, super::segments::SegmentRange)>> {
        let Some((from, until)) = selection.time_range() else {
            return Ok(None);
        };
        if selection.sources.is_empty() || limit == 0 {
            return Ok(None);
        }
        let first = after.map_or(0, |position| position.commit_revision);
        for (&id, entry) in self.entries.range(first..=revision) {
            control.check()?;
            if !entry
                .identity
                .evidence()
                .is_some_and(|identity| selection.sources.contains(identity))
                || entry.commit.intake < from
                || entry.commit.intake > until
            {
                continue;
            }
            for (index, span) in entry.commit.spans.iter().enumerate() {
                let last = super::StorePositionV1 {
                    commit_revision: id,
                    ordinal: span.ordinal + (span.last - span.first) as u32,
                };
                if after.is_some_and(|position| position >= last) {
                    continue;
                }
                let skipped = after
                    .filter(|position| position.commit_revision == id)
                    .map_or(0, |position| {
                        (u64::from(position.ordinal) + 1).saturating_sub(u64::from(span.ordinal))
                    });
                let first = span.first + skipped;
                let last = span.last.min(first.saturating_add(limit as u64 - 1));
                return Ok(Some((
                    entry
                        .identity
                        .evidence()
                        .cloned()
                        .ok_or_else(|| self.invalid("the selected source is not evidence"))?,
                    entry
                        .commit
                        .kind
                        .cpu()
                        .ok_or_else(|| self.invalid("the evidence CPU is absent"))?,
                    super::segments::SegmentRange {
                        segment_id: entry.reference.id,
                        byte_start: entry.body_start + u64::from(span.start),
                        byte_end: entry.body_start + u64::from(span.start) + u64::from(span.bytes),
                        first_cursor: first,
                        scan_bytes: entry.frame_bytes,
                        intake: entry.commit.intake,
                        reader: self.freeze(entry, index, first, last)?,
                    },
                )));
            }
        }
        Ok(None)
    }

    pub(super) fn pending_gaps(
        &self,
        receipt: &AnalysisSourceReceiptV1,
        revision: u64,
        control: &super::AnalysisReadControl,
    ) -> Result<Vec<super::AnalysisGapV1>> {
        let Some(mut next) = receipt.contiguous_cursor.checked_add(1) else {
            return Ok(Vec::new());
        };
        let key = source_key(&receipt.identity);
        let mut gaps = Vec::new();
        for (_, &(id, index)) in self.ranges.range((key, next)..=(key, u64::MAX)) {
            control.check()?;
            if id > revision {
                continue;
            }
            let span = &self.entries[&id].commit.spans[index];
            if span.first > next {
                gaps.push(super::AnalysisGapV1 {
                    first_cursor: next,
                    last_cursor: span.first - 1,
                    commit_revision: revision,
                });
            }
            let Some(end) = span.last.checked_add(1) else {
                break;
            };
            next = end;
        }
        Ok(gaps)
    }

    pub(super) fn forget_segment(&mut self, id: u64) -> Result<()> {
        self.segments.forget(id);
        self.entries.retain(|_, entry| entry.reference.id != id);
        self.ranges
            .retain(|_, (revision, _)| self.entries.contains_key(revision));
        Ok(())
    }

    pub(super) fn locate(
        &self,
        key: [u8; 32],
        cursor: u64,
        revision: u64,
    ) -> Result<(&RawEntry, usize)> {
        let (_, &(id, index)) = self
            .ranges
            .range((key, 0)..=(key, cursor))
            .next_back()
            .ok_or_else(|| self.invalid("the raw witness range is absent"))?;
        let entry = &self.entries[&id];
        if id > revision || cursor > entry.commit.spans[index].last {
            return Err(self.invalid("the raw witness cursor is absent"));
        }
        Ok((entry, index))
    }

    pub(super) fn select_ranges(
        &self,
        identity: &RawIdentity,
        first: u64,
        last: u64,
        revision: u64,
        time: Option<(u64, u64)>,
        limit: usize,
    ) -> Result<Vec<super::segments::SegmentRange>> {
        if first > last || limit == 0 {
            return Ok(Vec::new());
        }
        let key = identity.key();
        let start = self
            .ranges
            .range((key, 0)..=(key, first))
            .next_back()
            .filter(|(_, (id, index))| self.entries[id].commit.spans[*index].last >= first)
            .map_or(first, |((_, start), _)| *start);
        let mut ranges = Vec::new();
        for (_, &(id, index)) in self.ranges.range((key, start)..=(key, last)) {
            let entry = &self.entries[&id];
            if &entry.identity != identity
                || id > revision
                || time.is_some_and(|(from, until)| {
                    entry.commit.intake < from || entry.commit.intake > until
                })
            {
                continue;
            }
            let span = &entry.commit.spans[index];
            ranges.push(super::segments::SegmentRange {
                segment_id: entry.reference.id,
                byte_start: entry.body_start + u64::from(span.start),
                byte_end: entry.body_start + u64::from(span.start) + u64::from(span.bytes),
                first_cursor: span.first,
                scan_bytes: entry.frame_bytes,
                intake: entry.commit.intake,
                reader: self.freeze(entry, index, span.first, span.last)?,
            });
            if ranges.len() == limit {
                break;
            }
        }
        Ok(ranges)
    }

    pub(super) fn record_count(&self, key: [u8; 32], first: u64, last: u64, revision: u64) -> u64 {
        if first > last {
            return 0;
        }
        let start = self
            .ranges
            .range((key, 0)..=(key, first))
            .next_back()
            .filter(|(_, (id, index))| self.entries[id].commit.spans[*index].last >= first)
            .map_or(first, |((_, start), _)| *start);
        self.ranges
            .range((key, start)..=(key, last))
            .filter_map(|(_, &(id, index))| {
                let span = &self.entries[&id].commit.spans[index];
                (id <= revision).then(|| span.last.min(last) - span.first.max(first) + 1)
            })
            .sum()
    }

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
            revision: entry.commit.revision,
            kind: entry.commit.kind.clone(),
            intake: entry.commit.intake,
            first,
            last,
        })
    }
    pub(super) fn open(root: &Path, committed: &BTreeMap<u64, u64>) -> Result<Self> {
        let segments = EvidenceSegmentOwner::open(&root.join("segments"), committed)?;
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
            let EvidenceSegmentBoundsV1 {
                stream_id,
                first_cursor,
                last_cursor,
            } = descriptor.bounds;
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
                journal.publish(
                    RawEntry {
                        identity: identity.clone(),
                        commit: RawMeta::try_from(&commit)?,
                        reference,
                        stream: stream_id,
                        sequence,
                        body_start,
                        body_bytes,
                        frame_bytes: commit.encoded_len() + 8,
                    },
                    &commit,
                )?;
            }
        }
        journal.refresh_receipts()?;
        Ok(journal)
    }

    fn prepare(
        &self,
        identity: &RawIdentity,
        batch: &RawBatch,
        revision: u64,
    ) -> Result<RawCommit> {
        let key = identity.key();
        let source = self.sources.get(&key);
        if let Some(source) = source {
            if !source.receipt.matches(identity) || source.receipt.cpu() != batch.kind.cpu() {
                if matches!(identity, RawIdentity::Diagnostic(_)) {
                    return crate::AnalysisConflictSnafu.fail();
                }
                return Err(self.invalid("the raw source changed its identity or CPU"));
            }
        } else {
            if self
                .sources
                .values()
                .filter(|source| {
                    source.receipt.evidence().is_some() == identity.evidence().is_some()
                })
                .count()
                >= if identity.evidence().is_some() {
                    4096
                } else {
                    1024
                }
            {
                return crate::StorageCapacitySnafu {
                    resource: "source bindings",
                }
                .fail();
            }
            if identity.evidence().is_some_and(|identity| {
                self.sources
                    .values()
                    .filter_map(|source| source.receipt.evidence())
                    .any(|source| {
                        let saved = &source.identity;
                        saved.tenant_id == identity.tenant_id
                            && saved.node_id == identity.node_id
                            && saved.source_id == identity.source_id
                            && saved.source_epoch == identity.source_epoch
                            && saved != identity
                    })
            }) {
                return Err(self.invalid("one raw source epoch changed its boot or label"));
            }
        }
        let contiguous = source.map_or(0, |source| source.receipt.cursor());
        if identity.evidence().is_none() && batch.first_cursor > contiguous.saturating_add(1) {
            return crate::TraceInvalidSnafu {
                reason: "the diagnostic output skips a sequence",
            }
            .fail();
        }
        if batch.first_cursor > contiguous.saturating_add(1)
            && batch.last_cursor > contiguous.saturating_add(crate::MAX_PENDING_EVIDENCE_RECORDS)
        {
            return Err(self.invalid("out-of-order evidence exceeds the pending window"));
        }
        let overlap = self
            .ranges
            .range((key, 0)..=(key, batch.last_cursor))
            .next_back()
            .is_some_and(|(_, &(id, index))| {
                self.entries[&id].commit.spans[index].last >= batch.first_cursor
            });
        if !overlap && batch.first_cursor > contiguous {
            let mut commit = RawCommit {
                revision,
                kind: Some(batch.kind.clone()),
                intake: batch.intake_utc_ns,
                spans: vec![RawSpan {
                    first: batch.first_cursor,
                    last: batch.last_cursor,
                    start: 0,
                    ends: batch.frame_ends.iter().map(|end| *end as u32).collect(),
                    ordinal: 0,
                }],
                body: batch.framed_records.clone(),
            };
            self.prepare_trace(identity, &mut commit)?;
            return Ok(commit);
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
            let saved_span = &commit.spans[index];
            for cursor in span.first.max(batch.first_cursor)..=span.last.min(batch.last_cursor) {
                let saved = (cursor - span.first) as usize;
                let input = (cursor - batch.first_cursor) as usize;
                let saved_start = if saved == 0 {
                    0
                } else {
                    saved_span.ends[saved - 1] as usize
                };
                let input_start = if input == 0 {
                    0
                } else {
                    batch.frame_ends[input - 1]
                };
                let stored = &commit.body[span.start as usize + saved_start
                    ..span.start as usize + saved_span.ends[saved] as usize];
                if stored != &batch.framed_records[input_start..batch.frame_ends[input]] {
                    if matches!(identity, RawIdentity::Diagnostic(_)) {
                        return crate::AnalysisConflictSnafu.fail();
                    }
                    return Err(self.invalid("an evidence retry has conflicting record content"));
                }
                retained[input] = true;
            }
        }
        let mut commit = RawCommit {
            revision,
            kind: Some(batch.kind.clone()),
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
        self.prepare_trace(identity, &mut commit)?;
        Ok(commit)
    }

    pub(super) fn append(&mut self, identity: &RawIdentity, commit: RawCommit) -> Result<()> {
        commit.validate(&self.root)?;
        let key = identity.key();
        let (stream, sequence) = self.next_position(identity)?;
        let body_bytes = commit.body.len();
        let length = u32::try_from(commit.encoded_len())
            .map_err(|_| self.invalid("the raw commit is too large"))?;
        let mut frame = Vec::with_capacity(length as usize + 8);
        frame.extend_from_slice(&length.to_be_bytes());
        commit
            .encode(&mut frame)
            .map_err(|_| self.invalid("the raw commit encoding failed"))?;
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
        self.publish(
            RawEntry {
                identity: identity.clone(),
                commit: RawMeta::try_from(&commit)?,
                reference,
                stream,
                sequence,
                body_start,
                body_bytes,
                frame_bytes: end,
            },
            &commit,
        )?;
        self.refresh_source(&key)?;
        Ok(())
    }

    fn next_position(&self, identity: &RawIdentity) -> Result<(u64, u64)> {
        let key = identity.key();
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

    fn publish(&mut self, entry: RawEntry, commit: &RawCommit) -> Result<()> {
        if !entry.identity.valid() {
            return Err(self.invalid("the raw source identity is invalid"));
        }
        let key = entry.identity.key();
        let revision = entry.commit.revision;
        if self.entries.contains_key(&revision) {
            return Err(self.invalid("the raw revision is duplicated"));
        }
        if !self.sources.contains_key(&key)
            && entry.identity.evidence().is_some_and(|identity| {
                self.sources
                    .values()
                    .filter_map(|source| source.receipt.evidence())
                    .any(|source| {
                        let saved = &source.identity;
                        saved.tenant_id == identity.tenant_id
                            && saved.node_id == identity.node_id
                            && saved.source_id == identity.source_id
                            && saved.source_epoch == identity.source_epoch
                            && saved != identity
                    })
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
        }
        let receipt = self.commit_receipt(&entry, commit)?;
        let source = self.sources.entry(key).or_insert_with(|| RawSource {
            receipt: receipt.clone(),
            stream: entry.stream,
            sequence: 0,
        });
        if source.stream == 0 {
            source.stream = entry.stream;
        }
        if !source.receipt.matches(&entry.identity)
            || source.receipt.cpu() != entry.commit.kind.cpu()
            || source.stream != entry.stream
        {
            return Err(self.invalid("the recovered raw source binding conflicts"));
        }
        if let RawReceipt::Diagnostic(next) = receipt {
            let RawReceipt::Diagnostic(saved) = &source.receipt else {
                return Err(crate::AnalysisStateSnafu {
                    path: &self.root,
                    reason: "the raw source kind changed",
                }
                .build());
            };
            if next.last_sequence < saved.last_sequence
                || next.output_bytes < saved.output_bytes
                || saved
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| next.terminal.as_ref() != Some(terminal))
            {
                return Err(crate::AnalysisStateSnafu {
                    path: &self.root,
                    reason: "the raw diagnostic receipt regressed",
                }
                .build());
            }
            source.receipt = RawReceipt::Diagnostic(next);
        }
        source.sequence = source.sequence.max(entry.sequence);
        self.revision = self.revision.max(revision);
        for (index, span) in entry.commit.spans.iter().enumerate() {
            self.ranges.insert((key, span.first), (revision, index));
        }
        self.entries.insert(revision, entry);
        Ok(())
    }

    fn refresh_source(&mut self, key: &[u8; 32]) -> Result<()> {
        let mut contiguous = self
            .sources
            .get(key)
            .map_or(0, |source| source.receipt.cursor());
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
            if let RawReceipt::Evidence(receipt) = &mut source.receipt {
                receipt.contiguous_cursor = contiguous;
            }
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

    pub(super) fn outcome(&self, identity: &RawIdentity, last: u64) -> EvidenceStoreOutcomeV1 {
        if self
            .sources
            .get(&identity.key())
            .is_some_and(|source| source.receipt.cursor() >= last)
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
                EvidenceSegmentBoundsV1 {
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
            || commit.kind.as_ref() != Some(&entry.commit.kind)
            || commit.intake != entry.commit.intake
            || commit.spans.iter().map(RawRange::from).collect::<Vec<_>>() != entry.commit.spans
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
    fn records(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.spans.iter().flat_map(move |span| {
            span.ends.iter().enumerate().map(move |(index, end)| {
                let start = span.start as usize
                    + if index == 0 {
                        0
                    } else {
                        span.ends[index - 1] as usize
                    };
                (
                    span.first + index as u64,
                    &self.body[start..span.start as usize + *end as usize],
                )
            })
        })
    }

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
        if self.kind.is_none()
            || self.revision == 0
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
pub(super) mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::FileExt as _;

    pub(crate) fn trace_intent() -> crate::Result<super::super::TraceIntentV1> {
        let source = crate::TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        Ok(super::super::TraceIntentV1 {
            tenant_id: [1; 16],
            request_id: [3; 16],
            bindings: vec![super::super::TraceBindingV1 {
                identity: crate::TraceIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node-a".into(),
                    node_boot_id: [2; 16],
                    request_id: [3; 16],
                    execution_id: [4; 16],
                    source_sha256: source.sha256,
                },
                namespace_uid: "namespace-a".into(),
            }],
            source,
            authority: b"accepted".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 10_000,
            host_sensitive: false,
        })
    }

    pub(crate) fn trace_terminal(sequence: u64, bytes: u64) -> crate::TraceTerminalV1 {
        crate::TraceTerminalV1 {
            execution_id: [4; 16],
            reason: crate::TraceTerminalReasonV1::Completed,
            last_sequence: sequence,
            output_bytes: bytes,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: crate::TraceCleanupV1::Unknown,
        }
    }

    #[test]
    fn observability_raw_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        let state = store.accept_trace(&intent)?;
        let control = super::super::AnalysisReadControl::default();
        assert!(store.read_trace(identity, 1, &control)?.frames.is_empty());
        let frame = crate::TraceFrameV1 {
            execution_id: identity.execution_id,
            sequence: 1,
            kind: crate::TraceFrameKindV1::Metadata,
            bytes: b"metadata".to_vec(),
        };
        let batch = crate::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![frame.clone()],
            terminal: None,
        };
        let receipt = store.append_trace(identity, &batch, 200)?;
        assert_eq!((receipt.last_sequence, receipt.output_bytes), (1, 8));
        assert_eq!(store.append_trace(identity, &batch, 201)?, receipt);
        let page = store.read_trace(identity, 1, &control)?;
        assert_eq!(page.frames, vec![frame.clone()]);
        assert_eq!(page.positions.len(), 1);
        assert_eq!(page.next_cursor, None);
        {
            let writer = store.writer.lock().map_err(|_| "writer poisoned")?;
            let connection = writer.as_ref().ok_or("writer absent")?;
            assert_eq!(
                AnalysisStore::read_meta_from(connection, &root)?.commit_revision,
                state.revision
            );
            let stored: u64 =
                connection.query_row("SELECT last_sequence FROM trace_receipts", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(stored, 0);
        }
        let mut conflict = batch.clone();
        conflict.frames[0].kind = crate::TraceFrameKindV1::Data;
        assert!(matches!(
            store.append_trace(identity, &conflict, 202),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let mut gap = batch.clone();
        gap.frames[0].sequence = 3;
        assert!(matches!(
            store.append_trace(identity, &gap, 202),
            Err(crate::Error::TraceInvalid { .. })
        ));
        let invalid = crate::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(1, 9)),
        };
        assert!(matches!(
            store.append_trace(identity, &invalid, 202),
            Err(crate::Error::TraceInvalid { .. })
        ));
        let terminal = trace_terminal(1, 8);
        let combined = crate::TraceBatchV1 {
            terminal: Some(terminal.clone()),
            ..batch
        };
        let receipt = store.append_trace(identity, &combined, 203)?;
        assert_eq!(receipt.terminal, Some(terminal.clone()));
        assert_eq!(store.append_trace(identity, &combined, 204)?, receipt);
        assert!(matches!(
            store.append_trace(identity, &gap, 204),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        let mut changed = combined.clone();
        changed.terminal.as_mut().ok_or("terminal absent")?.reason =
            crate::TraceTerminalReasonV1::Cancelled;
        assert!(matches!(
            store.append_trace(identity, &changed, 204),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert!(matches!(
            TraceRecord::read(&[0], &root),
            Err(crate::Error::AnalysisState { .. })
        ));
        let page = store.read_trace(identity, 2, &control)?;
        assert!(page.frames.is_empty());
        assert_eq!(page.terminal, Some(terminal.clone()));
        assert!(page.terminal_position.is_some());
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.trace_receipt(identity)?, Some(receipt));
        let page = store.read_trace(identity, 1, &control)?;
        assert_eq!(page.frames, vec![frame]);
        assert_eq!(page.terminal, Some(terminal));
        Ok(())
    }

    #[test]
    fn observability_empty_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        let store = AnalysisStore::open(&root)?;
        let batch = crate::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(0, 0)),
        };
        assert!(store.append_trace(identity, &batch, 100).is_err());
        store.accept_trace(&intent)?;
        let receipt = store.append_trace(identity, &batch, 200)?;
        assert_eq!((receipt.last_sequence, receipt.output_bytes), (0, 0));
        assert!(receipt.terminal.is_some());
        let page = store.read_trace(identity, 1, &super::super::AnalysisReadControl::default())?;
        assert!(page.frames.is_empty());
        assert_eq!(page.terminal, batch.terminal);
        assert_eq!(page.next_cursor, None);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.append_trace(identity, &batch, 201)?, receipt);
        assert_eq!(store.trace_receipt(identity)?, Some(receipt));
        Ok(())
    }

    #[test]
    fn observability_frame_bound() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let frame = crate::TraceFrameV1 {
            execution_id: identity.execution_id,
            sequence: 1,
            kind: crate::TraceFrameKindV1::Data,
            bytes: vec![7; crate::MAX_TRACE_FRAME_BYTES],
        };
        let batch = crate::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![frame.clone()],
            terminal: Some(trace_terminal(1, crate::MAX_TRACE_FRAME_BYTES as u64)),
        };
        store.append_trace(identity, &batch, 200)?;
        let page = store.read_trace(identity, 1, &super::super::AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame]);
        assert_eq!(page.terminal, batch.terminal);
        let mut changed = identity.clone();
        changed.node_boot_id = [9; 16];
        assert!(store.append_trace(&changed, &batch, 201).is_err());
        assert!(store
            .read_trace(&changed, 1, &super::super::AnalysisReadControl::default())
            .is_err());
        Ok(())
    }

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
                writer.query_row("SELECT COUNT(*) FROM segments", [], |row| row
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
        let mut journal = RawJournal::open(root, &BTreeMap::new())?;
        let raw = RawIdentity::Evidence(identity.clone());
        let commit = journal.prepare(&raw, &batch.clone().into(), 1)?;
        journal.append(&raw, commit)?;
        assert_eq!(journal.outcome(&raw, 2), EvidenceStoreOutcomeV1::Pending);
        let batch = ValidatedEvidenceBatchV1 {
            first_cursor: 1,
            last_cursor: 3,
            framed_records: prost::bytes::Bytes::from_static(b"abc"),
            frame_ends: vec![1, 2, 3],
            ..batch
        };
        let commit = journal.prepare(&raw, &batch.clone().into(), 2)?;
        assert_eq!(commit.spans.len(), 2);
        journal.append(&raw, commit)?;
        assert_eq!(journal.outcome(&raw, 3), EvidenceStoreOutcomeV1::Accepted);
        let file = journal.segments.file_path(1)?.to_path_buf();
        let length = std::fs::metadata(&file)?.len();
        drop(journal);

        let mut tail = std::fs::OpenOptions::new().append(true).open(&file)?;
        tail.write_all(&[0, 0])?;
        tail.sync_all()?;
        drop(tail);
        let journal = RawJournal::open(root, &BTreeMap::new())?;
        assert_eq!(std::fs::metadata(&file)?.len(), length);
        assert_eq!(journal.sources[&source_key(&identity)].receipt.cursor(), 3);
        assert_eq!(journal.revision, 2);
        assert!(journal
            .prepare(&raw, &batch.clone().into(), 3)?
            .spans
            .is_empty());
        let mut conflict = batch.clone();
        conflict.framed_records = prost::bytes::Bytes::from_static(b"axc");
        assert!(journal.prepare(&raw, &conflict.into(), 3).is_err());
        conflict = batch;
        conflict.cpu_id = 1;
        assert!(journal.prepare(&raw, &conflict.into(), 3).is_err());
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
        assert!(RawJournal::open(root, &BTreeMap::new()).is_err());
        Ok(())
    }
}
