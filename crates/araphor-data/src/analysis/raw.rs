use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod budget;
mod index;
pub(in crate::analysis) use budget::RawBudget;
mod page;

pub(super) use index::{RawExpiry, RawIndex};

use prost::Message as _;
use snafu::ResultExt as _;

use super::raw_segments::{DirectoryStamp, RawSegment};
use super::{AnalysisSourceReceiptV1, SegmentFile, StorageUsageV1, ValidatedEvidenceBatchV1};
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
    pub(super) fn key(&self) -> Vec<u8> {
        match self {
            Self::Evidence(identity) => identity.key(),
            Self::Diagnostic(identity) => {
                let mut key = Vec::with_capacity(33);
                key.push(1);
                key.extend_from_slice(&identity.tenant_id);
                key.extend_from_slice(&identity.execution_id);
                key
            }
        }
    }

    pub(super) fn valid_key(key: &[u8]) -> bool {
        match key.first() {
            Some(0) if (68..=195).contains(&key.len()) => {
                key.len() == 67 + usize::from(u16::from_be_bytes([key[65], key[66]]))
                    && key[1..17] != [0; 16]
                    && key[17..33] != [0; 16]
                    && key[33..49] != [0; 16]
                    && key[49..57] != [0; 8]
                    && key[57..65] != [0; 8]
                    && std::str::from_utf8(&key[67..]).is_ok_and(crate::node_id_is_valid)
            }
            Some(1) => key.len() == 33 && key[1..17] != [0; 16] && key[17..] != [0; 16],
            _ => false,
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
            _ => return crate::Error::reject_path(root, "the raw stream kind is invalid"),
        }
        .context(crate::JsonSnafu { path: root })
    }
}

pub(super) struct RawBatch {
    pub(in crate::analysis) kind: RawKind,
    pub(in crate::analysis) first_cursor: u64,
    pub(in crate::analysis) last_cursor: u64,
    intake_utc_ns: u64,
    framed_records: prost::bytes::Bytes,
    frame_ends: Vec<usize>,
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
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct TraceRecord {
    #[prost(oneof = "TracePayload", tags = "1, 2, 3, 4")]
    payload: Option<TracePayload>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(super) enum TracePayload {
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
    pub(super) fn read(bytes: &[u8], root: &Path) -> Result<TracePayload> {
        let record = Self::decode(bytes).map_err(|_| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the stored trace record is invalid",
            }
            .build()
        })?;
        if record.encode_to_vec() != bytes {
            return crate::Error::reject_path(root, "the trace record is not canonical");
        }
        record.payload.ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the trace record kind is absent",
            }
            .build()
        })
    }

    pub(super) fn terminal(bytes: &[u8], root: &Path) -> Result<crate::TraceTerminalV1> {
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
            return crate::Error::reject_path(root, "the trace terminal is not canonical");
        }
        Ok(terminal)
    }
}

impl RawBatch {
    pub(in crate::analysis) fn trace(
        batch: &crate::TraceBatchV1,
        intake: u64,
        root: &Path,
    ) -> Result<Self> {
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
                    .and_then(|terminal| terminal.last_sequence.checked_add(1))
            })
            .ok_or_else(|| {
                crate::TraceInvalidSnafu {
                    reason: "the trace batch is empty",
                }
                .build()
            })?;
        let mut bytes = Vec::new();
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
            last_cursor: first.checked_add(ends.len() as u64 - 1).ok_or_else(|| {
                crate::TraceInvalidSnafu {
                    reason: "the trace batch cursor overflowed",
                }
                .build()
            })?,
            intake_utc_ns: intake,
            framed_records: bytes.into(),
            frame_ends: ends,
        })
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

#[derive(Clone, PartialEq, prost::Oneof, serde::Deserialize, serde::Serialize)]
pub(super) enum RawKind {
    #[prost(uint32, tag = "2")]
    Evidence(u32),
    #[prost(message, tag = "6")]
    Diagnostic(RawTraceMeta),
}

#[derive(Clone, PartialEq, prost::Message, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
pub(super) struct RawLocation {
    pub id: u64,
    pub offset: u64,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct RawEntry {
    pub identity: RawIdentity,
    pub commit: RawMeta,
    pub reference: RawLocation,
    pub body_start: u64,
    pub body_bytes: usize,
    pub frame_bytes: usize,
}

#[derive(Clone)]
pub(super) struct RawSource {
    pub receipt: RawReceipt,
    pub written: bool,
    pub active: Option<u64>,
}

impl From<AnalysisSourceReceiptV1> for RawSource {
    fn from(receipt: AnalysisSourceReceiptV1) -> Self {
        Self {
            receipt: RawReceipt::Evidence(receipt),
            written: false,
            active: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct RawRead {
    file: std::sync::Arc<SegmentFile>,
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    frame_start: u64,
    frame_bytes: usize,
    span: RawRange,
    revision: u64,
    kind: RawKind,
    intake: u64,
    first: u64,
    last: u64,
    available_last: u64,
}

impl RawRead {
    pub(super) fn window(
        &self,
        after: Option<super::StorePositionV1>,
        limit: usize,
    ) -> Option<Self> {
        if limit == 0 || after.is_some_and(|after| after.commit_revision > self.revision) {
            return None;
        }
        let first = after
            .filter(|after| after.commit_revision == self.revision)
            .map_or(self.first, |after| {
                self.span
                    .first
                    .saturating_add(
                        (u64::from(after.ordinal) + 1).saturating_sub(u64::from(self.span.ordinal)),
                    )
                    .max(self.first)
            });
        if first > self.available_last {
            return None;
        }
        let mut next = self.clone();
        next.first = first;
        next.last = self
            .available_last
            .min(first.saturating_add(limit as u64 - 1));
        Some(next)
    }

    pub(super) fn end(&self) -> super::StorePositionV1 {
        super::StorePositionV1 {
            commit_revision: self.revision,
            ordinal: self.span.ordinal + (self.available_last - self.span.first) as u32,
        }
    }

    pub(super) fn first(&self) -> u64 {
        self.first
    }

    pub(super) fn metadata_bytes(&self) -> usize {
        std::mem::size_of::<SegmentFile>() + self.file.path().as_os_str().len()
    }

    pub(super) fn read(&self, root: &Path) -> Result<(Vec<super::AnalysisRecordV1>, usize, usize)> {
        self.check_live()?;
        let commit = RawCommit::read(&self.file, self.frame_start, self.frame_bytes)?;
        self.check_live()?;
        let span = commit
            .spans
            .iter()
            .find(|span| RawRange::from(*span) == self.span);
        if commit.revision != self.revision
            || commit.kind.as_ref() != Some(&self.kind)
            || commit.intake != self.intake
            || span.is_none()
        {
            return crate::Error::reject_path(root, "the frozen raw commit changed its metadata");
        }
        let span = span.ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the frozen raw span is absent",
            }
            .build()
        })?;
        let frame_rows = commit.spans.iter().map(|span| span.ends.len()).sum();
        let body_bytes = commit.body.len();
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
        Ok((records, frame_rows, body_bytes))
    }

    fn check_live(&self) -> Result<()> {
        if !self.live.load(std::sync::atomic::Ordering::Acquire) {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: self.first,
                last_cursor: self.last,
            }
            .fail();
        }
        Ok(())
    }
}

pub(super) struct RawSourceState {
    pub covered: u64,
    pub pending: Vec<super::AnalysisGapV1>,
}

pub(super) struct RawJournal {
    pub root: PathBuf,
    pub segments: BTreeMap<u64, RawSegment>,
    pub next_segment: u64,
    pub usage: StorageUsageV1,
    pub diagnostics: usize,
    pub directory: Cell<Option<DirectoryStamp>>,
    pub index: RawIndex,
    pub budget: RawBudget,
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
            .index
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
            if progress.last_sequence.checked_add(1) != Some(cursor) {
                return crate::TraceInvalidSnafu {
                    reason: "the diagnostic output skips a sequence",
                }
                .fail();
            }
            match TraceRecord::read(bytes, &self.root)? {
                TracePayload::Metadata(bytes)
                | TracePayload::Data(bytes)
                | TracePayload::Diagnostic(bytes) => {
                    if bytes.is_empty() || cursor.checked_add(1).is_none() {
                        return crate::TraceInvalidSnafu {
                            reason: "the diagnostic frame size is invalid",
                        }
                        .fail();
                    }
                    progress.last_sequence = cursor;
                    progress.output_bytes = progress
                        .output_bytes
                        .checked_add(bytes.len() as u64)
                        .ok_or_else(|| {
                        crate::TraceInvalidSnafu {
                            reason: "the diagnostic output byte count overflowed",
                        }
                        .build()
                    })?;
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
                                || cursor.checked_add(1).is_none()
                                || cursor > progress.last_sequence
                            {
                                return Err(
                                    self.invalid("the recovered diagnostic frame is invalid")
                                );
                            }
                            added = added.checked_add(bytes.len() as u64).ok_or_else(|| {
                                self.invalid("the recovered diagnostic byte count overflowed")
                            })?;
                            frames = frames.checked_add(1).ok_or_else(|| {
                                self.invalid("the recovered diagnostic frame count overflowed")
                            })?;
                        }
                        TracePayload::Terminal(bytes) => {
                            let value = TraceRecord::terminal(&bytes, &self.root)?;
                            if value.execution_id != identity.execution_id
                                || value.last_sequence != progress.last_sequence
                                || value.output_bytes != progress.output_bytes
                                || value.last_sequence.checked_add(1) != Some(cursor)
                            {
                                return Err(
                                    self.invalid("the recovered diagnostic terminal conflicts")
                                );
                            }
                            terminal = Some(value);
                        }
                    }
                }
                if progress.output_bytes < added
                    || progress.output_bytes < progress.last_sequence
                    || progress.terminal != terminal.is_some()
                    || progress
                        .last_sequence
                        .checked_add(u64::from(progress.terminal))
                        != Some(last)
                {
                    return Err(self.invalid("the recovered diagnostic progress is invalid"));
                }
                let saved = self
                    .index
                    .sources
                    .get(&entry.identity.key())
                    .and_then(|source| match &source.receipt {
                        RawReceipt::Diagnostic(receipt) => Some(receipt),
                        RawReceipt::Evidence(_) => None,
                    });
                let first = commit.spans[0].first;
                let prior_cursor = saved.map_or(0, TraceOutputReceiptV1::cursor);
                if prior_cursor.checked_add(1) == Some(first)
                    && (saved
                        .map_or(0, |receipt| receipt.last_sequence)
                        .checked_add(frames)
                        != Some(progress.last_sequence)
                        || saved
                            .map_or(0, |receipt| receipt.output_bytes)
                            .checked_add(added)
                            != Some(progress.output_bytes))
                {
                    return Err(
                        self.invalid("the diagnostic cumulative counters differ from output")
                    );
                }
                let retained_floor = self
                    .index
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

    pub(super) fn select_position(
        &self,
        selection: &super::AnalysisSelectionV1,
        after: Option<super::StorePositionV1>,
        revision: u64,
        limit: usize,
        control: &super::AnalysisReadControl,
    ) -> Result<Option<(RawIdentity, Option<u32>, super::segments::InputRange)>> {
        self.select_position_at(
            &self.index,
            selection,
            after,
            revision,
            limit,
            None,
            control,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::analysis) fn select_position_at(
        &self,
        captured: &RawIndex,
        selection: &super::AnalysisSelectionV1,
        after: Option<super::StorePositionV1>,
        revision: u64,
        limit: usize,
        event_ranges: Option<&[(u64, u64)]>,
        control: &super::AnalysisReadControl,
    ) -> Result<Option<(RawIdentity, Option<u32>, super::segments::InputRange)>> {
        if (selection.sources.as_slice().is_empty() && selection.traces.as_slice().is_empty())
            || limit == 0
        {
            return Ok(None);
        }
        let first = after.map_or(0, |position| position.commit_revision);
        for (&id, entry) in captured.entries.range(first..=revision) {
            control.check()?;
            let selected = match &entry.identity {
                RawIdentity::Evidence(identity) => {
                    selection.sources.as_slice().contains(identity)
                        && selection.time_range().is_some_and(|(from, until)| {
                            entry.commit.intake >= from && entry.commit.intake <= until
                        })
                }
                RawIdentity::Diagnostic(identity) => selection.traces.as_slice().contains(identity),
            };
            if !selected {
                continue;
            }
            let expired = self.index.expired.get(&entry.reference.id);
            if expired.is_some_and(|expired| expired.revision <= revision) {
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
                let (first, last) = if entry.identity.evidence().is_some() {
                    let Some((lower, upper)) = selection.cursor_range() else {
                        continue;
                    };
                    (first.max(lower), span.last.min(upper))
                } else {
                    (first, span.last)
                };
                if first > last {
                    continue;
                }
                if expired.is_some() {
                    if entry.identity.evidence().is_some()
                        && event_ranges.is_some_and(|ranges| {
                            !ranges.iter().any(|(first, last)| {
                                (*first..=*last).contains(&entry.commit.intake)
                            })
                        })
                    {
                        continue;
                    }
                    return crate::RetainedRangeExpiredSnafu {
                        first_cursor: first,
                        last_cursor: last,
                    }
                    .fail();
                }
                let available_last = last;
                let last = last.min(first.saturating_add(limit as u64 - 1));
                let mut reader = self.freeze(entry, index, first, last)?;
                reader.available_last = available_last;
                return Ok(Some((
                    entry.identity.clone(),
                    entry.commit.kind.cpu(),
                    super::segments::InputRange::diagnostic(
                        reader,
                        entry.body_start + u64::from(span.start),
                        entry.body_start + u64::from(span.start) + u64::from(span.bytes),
                        entry.frame_bytes,
                        entry.commit.intake,
                    ),
                )));
            }
        }
        Ok(None)
    }

    pub(super) fn segment_entries(
        &self,
        id: u64,
        first: u64,
        last: u64,
        intake: u64,
        end: u64,
    ) -> Result<Vec<&RawEntry>> {
        if first == 0 || first > last || intake == 0 || end == 0 {
            return Err(self.invalid("the retention segment bounds are invalid"));
        }
        let segment = self
            .segments
            .get(&id)
            .ok_or_else(|| self.invalid("the retention segment is absent"))?;
        let revisions: std::collections::BTreeSet<_> = self
            .index
            .ranges
            .range((segment.source.clone(), first)..=(segment.source.clone(), last))
            .map(|(_, (revision, _))| *revision)
            .filter(|revision| self.index.entries[revision].reference.id == id)
            .collect();
        let entries: Vec<_> = revisions
            .iter()
            .map(|revision| &self.index.entries[revision])
            .collect();
        let identity = &entries
            .first()
            .ok_or_else(|| self.invalid("the retention segment has no entries"))?
            .identity;
        let mut bytes = SegmentFile::encode_raw(identity)?.len() as u64;
        let mut bounds = (u64::MAX, 0, 0);
        for entry in &entries {
            bytes = bytes
                .checked_add(entry.frame_bytes as u64)
                .ok_or_else(|| self.invalid("the retention frame bytes overflow"))?;
            for span in &entry.commit.spans {
                bounds.0 = bounds.0.min(span.first);
                bounds.1 = bounds.1.max(span.last);
            }
            bounds.2 = bounds.2.max(entry.commit.intake);
        }
        if bounds != (first, last, intake) || bytes != end || end != segment.end {
            return Err(self.invalid("the retention metadata differs from the durable segment"));
        }
        Ok(entries)
    }

    pub(super) fn forget_segments(&mut self, ids: impl IntoIterator<Item = u64>) -> Result<()> {
        let ids: std::collections::BTreeSet<_> = ids.into_iter().collect();
        for id in &ids {
            self.forget_segment(*id)?;
        }
        let revisions: Vec<_> = self
            .index
            .entries
            .iter()
            .filter(|(_, entry)| ids.contains(&entry.reference.id))
            .map(|(revision, _)| *revision)
            .collect();
        for revision in revisions {
            let entry = &self.index.entries[&revision];
            let key = entry.identity.key();
            for span in &entry.commit.spans {
                self.index.ranges.remove_mut(&(key.clone(), span.first));
            }
            self.index.entries.remove_mut(&revision);
        }
        Ok(())
    }

    pub(super) fn locate(
        &self,
        key: &[u8],
        cursor: u64,
        revision: u64,
    ) -> Result<(&RawEntry, usize)> {
        self.locate_retained(key, cursor, revision)
            .ok_or_else(|| self.invalid("the raw witness cursor is absent"))
    }

    pub(super) fn locate_retained(
        &self,
        key: &[u8],
        cursor: u64,
        revision: u64,
    ) -> Option<(&RawEntry, usize)> {
        let (_, &(id, index)) = self
            .index
            .ranges
            .range((key.to_vec(), 0)..=(key.to_vec(), cursor))
            .next_back()?;
        let entry = &self.index.entries[&id];
        if id > revision || cursor > entry.commit.spans[index].last {
            return None;
        }
        Some((entry, index))
    }

    pub(in crate::analysis) fn witness_entry(
        &self,
        witness: &super::AnalysisWitnessV1,
        revision: u64,
    ) -> Result<&RawEntry> {
        let (entry, slot) = self.locate(&witness.identity.key(), witness.cursor, revision)?;
        let span = &entry.commit.spans[slot];
        if entry.identity != witness.identity
            || witness.cursor == 0
            || !(span.first..=span.last).contains(&witness.cursor)
            || entry.commit.revision == 0
            || entry.commit.revision > revision
        {
            return Err(self.invalid("the witness differs from its original raw range"));
        }
        Ok(entry)
    }

    pub(super) fn record_position(
        &self,
        record: &crate::DiscoveryRecordIdV1,
        cut: u64,
    ) -> Option<super::StorePositionV1> {
        let (entry, index) =
            self.locate_retained(&record.stream.key(), record.durable_cursor, cut)?;
        let span = entry.commit.spans.get(index)?;
        if entry.identity != record.stream
            || entry.commit.kind.cpu() != Some(record.cpu_id)
            || entry.commit.revision == 0
            || entry.commit.revision > cut
            || !(span.first..=span.last).contains(&record.durable_cursor)
        {
            return None;
        }
        let offset = u32::try_from(record.durable_cursor.checked_sub(span.first)?).ok()?;
        Some(super::StorePositionV1 {
            commit_revision: entry.commit.revision,
            ordinal: span.ordinal.checked_add(offset)?,
        })
    }

    pub(super) fn select_ranges(
        &self,
        identity: &RawIdentity,
        first: u64,
        last: u64,
        revision: u64,
        time: Option<(u64, u64)>,
        limit: usize,
    ) -> Result<Vec<super::segments::InputRange>> {
        if first > last || limit == 0 {
            return Ok(Vec::new());
        }
        let key = identity.key();
        let start = self
            .index
            .ranges
            .range((key.clone(), 0)..=(key.clone(), first))
            .next_back()
            .filter(|(_, (id, index))| self.index.entries[id].commit.spans[*index].last >= first)
            .map_or(first, |((_, start), _)| *start);
        let mut ranges = Vec::new();
        for (_, &(id, index)) in self.index.ranges.range((key.clone(), start)..=(key, last)) {
            let entry = &self.index.entries[&id];
            if &entry.identity != identity
                || id > revision
                || time.is_some_and(|(from, until)| {
                    entry.commit.intake < from || entry.commit.intake > until
                })
            {
                continue;
            }
            let span = &entry.commit.spans[index];
            ranges.push(super::segments::InputRange::diagnostic(
                self.freeze(entry, index, span.first, span.last)?,
                entry.body_start + u64::from(span.start),
                entry.body_start + u64::from(span.start) + u64::from(span.bytes),
                entry.frame_bytes,
                entry.commit.intake,
            ));
            if ranges.len() == limit {
                break;
            }
        }
        Ok(ranges)
    }

    #[cfg(test)]
    pub(super) fn record_count(&self, key: &[u8], first: u64, last: u64, revision: u64) -> u64 {
        if first > last {
            return 0;
        }
        let start = self
            .index
            .ranges
            .range((key.to_vec(), 0)..=(key.to_vec(), first))
            .next_back()
            .filter(|(_, (id, index))| self.index.entries[id].commit.spans[*index].last >= first)
            .map_or(first, |((_, start), _)| *start);
        self.index
            .ranges
            .range((key.to_vec(), start)..=(key.to_vec(), last))
            .filter_map(|(_, &(id, index))| {
                let span = &self.index.entries[&id].commit.spans[index];
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
        self.check_live(entry)?;
        Ok(RawRead {
            file: std::sync::Arc::new(SegmentFile::reader(self.segment_path(entry.reference.id)?)?),
            live: std::sync::Arc::clone(&self.segments[&entry.reference.id].live),
            frame_start: entry.reference.offset - entry.frame_bytes as u64,
            frame_bytes: entry.frame_bytes,
            span: entry.commit.spans[index].clone(),
            revision: entry.commit.revision,
            kind: entry.commit.kind.clone(),
            intake: entry.commit.intake,
            first,
            last,
            available_last: last,
        })
    }
    pub(super) fn prepare(
        &self,
        identity: &RawIdentity,
        batch: &RawBatch,
        revision: u64,
    ) -> Result<RawCommit> {
        let key = identity.key();
        let source = self.index.sources.get(&key);
        if let Some(source) = source {
            if !source.receipt.matches(identity) || source.receipt.cpu() != batch.kind.cpu() {
                if matches!(identity, RawIdentity::Diagnostic(_)) {
                    return crate::AnalysisConflictSnafu.fail();
                }
                return Err(self.invalid("the raw source changed its identity or CPU"));
            }
        } else {
            if identity.evidence().is_some_and(|identity| {
                self.index
                    .sources
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
        let overlap = self
            .index
            .ranges
            .range((key.clone(), 0)..=(key.clone(), batch.last_cursor))
            .next_back()
            .is_some_and(|(_, &(id, index))| {
                self.index.entries[&id].commit.spans[index].last >= batch.first_cursor
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
                    ends: batch
                        .frame_ends
                        .iter()
                        .map(|end| {
                            u32::try_from(*end).map_err(|_| {
                                self.invalid("the raw frame offset is not representable")
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                    ordinal: 0,
                }],
                body: batch.framed_records.clone(),
            };
            self.prepare_trace(identity, &mut commit)?;
            return Ok(commit);
        }
        let mut retained = vec![false; batch.frame_ends.len()];
        for (_, &(stored_revision, index)) in self
            .index
            .ranges
            .range((key.clone(), 0)..=(key, batch.last_cursor))
            .rev()
        {
            let entry = &self.index.entries[&stored_revision];
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
        let mut ordinal = 0_u32;
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
                        start: u32::try_from(body.len()).map_err(|_| {
                            self.invalid("the raw body offset is not representable")
                        })?,
                        ends: Vec::new(),
                        ordinal,
                    });
                }
                let frame = &batch.framed_records[start..end];
                let body_end = body
                    .len()
                    .checked_add(frame.len())
                    .and_then(|end| u32::try_from(end).ok())
                    .ok_or_else(|| self.invalid("the raw body offset is not representable"))?;
                body.extend_from_slice(frame);
                let span = commit
                    .spans
                    .last_mut()
                    .ok_or_else(|| self.invalid("the pending raw span is absent"))?;
                span.last = cursor;
                span.ends.push(
                    body_end
                        .checked_sub(span.start)
                        .ok_or_else(|| self.invalid("the raw frame end precedes its start"))?,
                );
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or_else(|| self.invalid("the raw ordinal is exhausted"))?;
            }
            start = end;
        }
        commit.body = body.into();
        self.prepare_trace(identity, &mut commit)?;
        Ok(commit)
    }

    pub(super) fn prepare_index(&self, entry: RawEntry, commit: &RawCommit) -> Result<RawIndex> {
        let receipt = self.commit_receipt(&entry, commit)?;
        self.index.prepare(entry, receipt, &self.root)
    }

    pub(super) fn publish(&mut self, entry: RawEntry, commit: &RawCommit) -> Result<()> {
        self.index = self.prepare_index(entry, commit)?;
        Ok(())
    }

    pub(super) fn outcome(&self, identity: &RawIdentity, last: u64) -> EvidenceStoreOutcomeV1 {
        if self
            .index
            .sources
            .get(&identity.key())
            .is_some_and(|source| source.receipt.cursor() >= last)
        {
            EvidenceStoreOutcomeV1::Accepted
        } else {
            EvidenceStoreOutcomeV1::Pending
        }
    }

    pub(super) fn read_entry(&self, entry: &RawEntry) -> Result<RawCommit> {
        self.check_live(entry)?;
        let commit = RawCommit::read(
            &SegmentFile::reader(self.segment_path(entry.reference.id)?)?,
            entry.reference.offset - entry.frame_bytes as u64,
            entry.frame_bytes,
        )?;
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

    fn check_live(&self, entry: &RawEntry) -> Result<()> {
        if self.index.expired.contains_key(&entry.reference.id) {
            return crate::RetainedRangeExpiredSnafu {
                first_cursor: entry.commit.spans.first().map_or(0, |span| span.first),
                last_cursor: entry.commit.spans.last().map_or(0, |span| span.last),
            }
            .fail();
        }
        Ok(())
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
    pub(super) fn records(&self) -> impl Iterator<Item = (u64, &[u8])> {
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

    pub(super) fn validate(&self, root: &Path) -> Result<()> {
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
                return crate::Error::reject_path(root, "the raw commit range is invalid");
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
            ordinal = ordinal.checked_add(span.ends.len()).ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the raw ordinal is exhausted",
                }
                .build()
            })?;
            prior = span.last;
        }
        if self.kind.is_none()
            || self.revision == 0
            || self.intake == 0
            || ordinal == 0
            || self.body.len() != end as usize
        {
            return crate::Error::reject_path(root, "the raw commit bounds are invalid");
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
                binding_id: [9; 16],
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
    fn observability_keys_bind_execution() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        let key = RawIdentity::Diagnostic(identity.clone()).key();
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], 1);
        assert_eq!(key[1..17], identity.tenant_id);
        assert_eq!(key[17..], identity.execution_id);
        assert!(RawIdentity::valid_key(&key));
        for changed in [
            crate::TraceIdentityV1 {
                node_id: "node-b".into(),
                ..identity.clone()
            },
            crate::TraceIdentityV1 {
                node_boot_id: [9; 16],
                ..identity.clone()
            },
            crate::TraceIdentityV1 {
                request_id: [9; 16],
                ..identity.clone()
            },
            crate::TraceIdentityV1 {
                source_sha256: [9; 32],
                ..identity.clone()
            },
        ] {
            assert_ne!(&changed, identity);
            assert_eq!(RawIdentity::Diagnostic(changed).key(), key);
        }
        for changed in [
            crate::TraceIdentityV1 {
                tenant_id: [9; 16],
                ..identity.clone()
            },
            crate::TraceIdentityV1 {
                execution_id: [9; 16],
                ..identity.clone()
            },
        ] {
            assert_ne!(RawIdentity::Diagnostic(changed).key(), key);
        }
        assert!(!RawIdentity::valid_key(&key[..32]));
        let mut invalid = key;
        invalid[0] = 0;
        assert!(!RawIdentity::valid_key(&invalid));
        assert!(matches!(
            TraceRecord::read(&[0], directory.path()),
            Err(crate::Error::AnalysisState { .. })
        ));
        Ok(())
    }

    #[test]
    fn raw_recovers_without_database() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        RawJournal::directory(root)?;
        let identity = crate::analysis::tests::identity();
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
        let append = journal.prepare_append(&raw, commit)?;
        journal.append(&raw, append)?;
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
        let append = journal.prepare_append(&raw, commit)?;
        journal.append(&raw, append)?;
        assert_eq!(journal.outcome(&raw, 3), EvidenceStoreOutcomeV1::Accepted);
        let file = journal.segment_path(1)?.to_path_buf();
        let length = std::fs::metadata(&file)?.len();
        drop(journal);

        let mut tail = std::fs::OpenOptions::new().append(true).open(&file)?;
        tail.write_all(&[0, 0])?;
        tail.sync_all()?;
        drop(tail);
        let saved = std::fs::read(&file)?;
        assert!(RawJournal::read_sealed(root, &BTreeMap::new()).is_err());
        assert_eq!(std::fs::read(&file)?, saved);
        let journal = RawJournal::open(root, &BTreeMap::new())?;
        assert_eq!(std::fs::metadata(&file)?.len(), length);
        assert_eq!(journal.index.sources[&identity.key()].receipt.cursor(), 3);
        assert_eq!(journal.index.revision, 2);
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
        let entry = &journal.index.entries[&2];
        let body = journal.read_entry(entry)?.body;
        let stored =
            super::super::SegmentFile::reader(&file)?.read(entry.body_start, entry.body_bytes)?;
        assert_eq!(stored.as_slice(), body.as_ref());
        assert!(!root.join("analysis.duckdb").exists());
        let first_end = journal.index.entries[&1].reference.offset;
        let mut journal = journal;
        journal.seal_all()?;
        let file = journal.segment_path(1)?.to_path_buf();
        let sealed = std::fs::read(&file)?;
        drop(journal);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file)?
            .set_len(first_end)?;
        let shortened = std::fs::read(&file)?;
        assert!(RawJournal::read_sealed(root, &BTreeMap::new()).is_err());
        assert_eq!(std::fs::read(&file)?, shortened);
        std::fs::write(&file, &sealed)?;
        let journal = RawJournal::read_sealed(root, &BTreeMap::new())?;
        assert_eq!(journal.index.sources[&identity.key()].receipt.cursor(), 3);
        assert_eq!(journal.read_entry(&journal.index.entries[&2])?.body, body);
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

impl TraceOutputPageV1 {
    pub(in crate::analysis) fn decode(
        page: super::AnalysisReadPageV1,
        identity: &crate::TraceIdentityV1,
        root: &Path,
        control: &super::AnalysisReadControl,
    ) -> Result<Self> {
        let mut output = TraceOutputPageV1 {
            frames: Vec::new(),
            terminal: None,
            positions: Vec::new(),
            terminal_position: None,
            next_cursor: page.next_cursor,
            read_revision: page.read_revision,
        };
        let mut bytes = 0_usize;
        for record in page.records {
            control.check()?;
            let payload = TraceRecord::read(&record.framed_record, root)?;
            let (kind, data) = match payload {
                TracePayload::Metadata(data) => (crate::TraceFrameKindV1::Metadata, data),
                TracePayload::Data(data) => (crate::TraceFrameKindV1::Data, data),
                TracePayload::Diagnostic(data) => (crate::TraceFrameKindV1::Diagnostic, data),
                TracePayload::Terminal(data) => {
                    output.terminal = Some(TraceRecord::terminal(&data, root)?);
                    output.terminal_position = Some(record.position);
                    continue;
                }
            };
            if output.frames.len() == 200
                || (!output.frames.is_empty()
                    && bytes
                        .checked_add(data.len())
                        .is_none_or(|bytes| bytes > 1024 * 1024))
            {
                output.next_cursor = Some(record.cursor);
                break;
            }
            bytes = bytes.checked_add(data.len()).ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the trace page byte count overflowed",
                }
                .build()
            })?;
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
}
