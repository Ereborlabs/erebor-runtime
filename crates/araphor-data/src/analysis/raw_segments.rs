use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use prost::Message;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::raw::RawIdentity;
use crate::Result;
use crate::{AnalysisStateSnafu, IoSnafu};

pub(crate) const MAX_SEGMENT_BYTES: u64 = crate::MAX_EVIDENCE_SEGMENT_BYTES as u64;
const FRAME_OVERHEAD_BYTES: usize = 8;
const RAW_COMMIT_LIMIT: usize = crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES + 65536;

#[derive(Clone, Debug)]
pub(super) struct StoredEvidenceBatchV1 {
    pub(super) first_cursor: u64,
    pub(super) last_cursor: u64,
    pub(super) segment: EvidenceSegmentRefV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSegmentRefV1 {
    pub(crate) id: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceSegmentBoundsV1 {
    pub(crate) stream_id: u64,
    pub(crate) first_cursor: u64,
    pub(crate) last_cursor: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceSegmentDescriptorV1 {
    pub(crate) reference: EvidenceSegmentRefV1,
    pub(crate) bounds: EvidenceSegmentBoundsV1,
}

#[derive(Clone, Copy, Debug)]
struct EvidenceFrameIndexV1 {
    payload_start: usize,
    payload_end: usize,
    end: usize,
}

pub(crate) struct EvidenceSegmentReadV1 {
    file: super::SegmentFile,
    path: PathBuf,
    frames: Vec<EvidenceFrameIndexV1>,
}

impl EvidenceSegmentReadV1 {
    pub(crate) fn decode<M: Message + Default>(&self) -> Result<Vec<M>> {
        let mut records = Vec::with_capacity(self.frames.len());
        for frame in &self.frames {
            let bytes = self.read_frame(frame)?;
            let record = M::decode(&bytes[4..bytes.len() - 4]).map_err(|error| {
                AnalysisStateSnafu {
                    path: self.path.clone(),
                    reason: format!("a frozen evidence frame failed decoding: {error}"),
                }
                .build()
            })?;
            if record.encode_to_vec() != bytes[4..bytes.len() - 4] {
                return super::AnalysisStore::reject_path(
                    &self.path,
                    "the raw commit encoding is not canonical",
                );
            }
            records.push(record);
        }
        Ok(records)
    }

    fn read_frame(&self, frame: &EvidenceFrameIndexV1) -> Result<Vec<u8>> {
        let start = frame.payload_start - 4;
        let bytes = self.file.read(start as u64, frame.end - start)?;
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()) as usize;
        let checksum_start = bytes.len() - 4;
        let checksum = u32::from_be_bytes(bytes[checksum_start..].try_into().unwrap_or_default());
        if length != frame.payload_end - frame.payload_start
            || crc32c::crc32c(&bytes[..checksum_start]) != checksum
        {
            return AnalysisStateSnafu {
                path: self.path.clone(),
                reason: "a frozen evidence frame changed length or checksum".to_owned(),
            }
            .fail();
        }
        Ok(bytes)
    }
}

struct EncodedEvidenceFramesV1 {
    bytes: prost::bytes::Bytes,
    frames: Vec<EvidenceFrameIndexV1>,
}

impl EncodedEvidenceFramesV1 {
    fn validated(bytes: prost::bytes::Bytes, frame_ends: Vec<usize>) -> Result<Self> {
        let mut start = 0_usize;
        let mut frames = Vec::with_capacity(frame_ends.len());
        for end in frame_ends {
            if end <= start + FRAME_OVERHEAD_BYTES || end > bytes.len() {
                return AnalysisStateSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: "the validated evidence frame index is invalid".to_owned(),
                }
                .fail();
            }
            frames.push(EvidenceFrameIndexV1 {
                payload_start: start + 4,
                payload_end: end - 4,
                end,
            });
            start = end;
        }
        if start != bytes.len() {
            return AnalysisStateSnafu {
                path: PathBuf::from("<evidence-record>"),
                reason: "the validated evidence frames are incomplete".to_owned(),
            }
            .fail();
        }
        Ok(Self { bytes, frames })
    }

    fn split_to(&mut self, record_count: usize) -> Self {
        let byte_count = self.frames[record_count - 1].end;
        let bytes = self.bytes.split_to(byte_count);
        let frames = self.frames.drain(..record_count).collect();
        for frame in &mut self.frames {
            frame.payload_start -= byte_count;
            frame.payload_end -= byte_count;
            frame.end -= byte_count;
        }
        Self { bytes, frames }
    }
}

#[derive(Debug)]
struct EvidenceSegmentStateV1 {
    descriptor: EvidenceSegmentDescriptorV1,
    identity: RawIdentity,
    path: PathBuf,
    frames: Vec<EvidenceFrameIndexV1>,
    active: bool,
}

impl EvidenceSegmentStateV1 {
    fn active_path(
        root: &Path,
        id: u64,
        stream: u64,
        first: u64,
        identity: &RawIdentity,
    ) -> PathBuf {
        let kind = if identity.evidence().is_some() {
            "r"
        } else {
            "d"
        };
        root.join(format!("{id:016x}.{kind}.{stream:016x}.{first:016x}.open"))
    }

    fn sealed_path(&self, root: &Path) -> PathBuf {
        let id = self.descriptor.reference.id;
        let bounds = self.descriptor.bounds;
        let stream = bounds.stream_id;
        let first = bounds.first_cursor;
        let last = bounds.last_cursor;
        let kind = if self.identity.evidence().is_some() {
            "r"
        } else {
            "d"
        };
        root.join(format!(
            "{id:016x}.{kind}.{stream:016x}.{first:016x}.{last:016x}.seg"
        ))
    }

    fn parse_name(path: &Path) -> Result<(u64, u64, u64, Option<u64>, &'static str)> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let fields = name.split('.').collect::<Vec<_>>();
        let (id, stream_id, first, last) = match fields.as_slice() {
            [id, "r" | "d", stream_id, first, "open"] => (
                Self::field(id, path)?,
                Self::field(stream_id, path)?,
                Self::field(first, path)?,
                None,
            ),
            [id, "r" | "d", stream_id, first, last, "seg"] => (
                Self::field(id, path)?,
                Self::field(stream_id, path)?,
                Self::field(first, path)?,
                Some(Self::field(last, path)?),
            ),
            _ => {
                return AnalysisStateSnafu {
                    path: path.to_owned(),
                    reason: "the evidence segment name is invalid".to_owned(),
                }
                .fail();
            }
        };
        if id == 0 || stream_id == 0 || first == 0 || last.is_some_and(|last| last < first) {
            return AnalysisStateSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index is invalid".to_owned(),
            }
            .fail();
        }
        let kind = if fields[1] == "r" {
            "records"
        } else {
            "diagnostic"
        };
        Ok((id, stream_id, first, last, kind))
    }

    fn field(value: &str, path: &Path) -> Result<u64> {
        if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return AnalysisStateSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index field is invalid".to_owned(),
            }
            .fail();
        }
        u64::from_str_radix(value, 16).map_err(|error| {
            AnalysisStateSnafu {
                path: path.to_owned(),
                reason: format!("the evidence segment index is invalid: {error}"),
            }
            .build()
        })
    }

    fn read(
        path: PathBuf,
        id: u64,
        stream: u64,
        first: u64,
        sealed_last: Option<u64>,
        committed_end: u64,
        kind: &str,
    ) -> Result<Option<Self>> {
        let file = super::SegmentFile::open(&path)?;
        let mut bytes = file.read(0, file.length()? as usize)?;
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return AnalysisStateSnafu {
                path,
                reason: "the evidence segment exceeds 16 MiB".to_owned(),
            }
            .fail();
        }
        let (identity, header_bytes) = super::SegmentFile::decode_raw(kind, &bytes, &path)?;
        let active = sealed_last.is_none();
        let mut frames = Vec::new();
        let mut offset = header_bytes;
        let mut incomplete = false;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            if remaining < 4 {
                incomplete = true;
                break;
            }
            let payload_bytes =
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap_or_default())
                    as usize;
            if payload_bytes == 0 || payload_bytes > RAW_COMMIT_LIMIT {
                return AnalysisStateSnafu {
                    path,
                    reason: "the evidence segment contains a record outside its size bound"
                        .to_owned(),
                }
                .fail();
            }
            let frame_bytes = payload_bytes
                .checked_add(FRAME_OVERHEAD_BYTES)
                .ok_or_else(|| {
                    AnalysisStateSnafu {
                        path: path.clone(),
                        reason: "the evidence segment frame size overflowed".to_owned(),
                    }
                    .build()
                })?;
            let end = offset.checked_add(frame_bytes).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: path.clone(),
                    reason: "the evidence segment frame end overflowed".to_owned(),
                }
                .build()
            })?;
            if end > bytes.len() {
                incomplete = true;
                break;
            }
            let checksum_start = end - 4;
            let expected =
                u32::from_be_bytes(bytes[checksum_start..end].try_into().unwrap_or_default());
            if crc32c::crc32c(&bytes[offset..checksum_start]) != expected {
                return AnalysisStateSnafu {
                    path,
                    reason: "the evidence segment record checksum is invalid".to_owned(),
                }
                .fail();
            }
            let payload_start = offset + 4;
            frames.push(EvidenceFrameIndexV1 {
                payload_start,
                payload_end: checksum_start,
                end,
            });
            offset = end;
        }
        if (offset as u64) < committed_end {
            return super::AnalysisStore::reject_path(
                &path,
                "the raw segment lost a catalogued commit",
            );
        }
        if incomplete {
            if !active {
                return AnalysisStateSnafu {
                    path,
                    reason: "the sealed evidence segment has an incomplete record tail".to_owned(),
                }
                .fail();
            }
            file.discard_tail(offset as u64)?;
            bytes.truncate(offset);
        }
        if frames.is_empty() {
            if active {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                return Ok(None);
            }
            return AnalysisStateSnafu {
                path,
                reason: "a sealed evidence segment is empty".to_owned(),
            }
            .fail();
        }
        let last = first.checked_add(frames.len() as u64 - 1).ok_or_else(|| {
            AnalysisStateSnafu {
                path: path.clone(),
                reason: "the evidence segment range is exhausted".to_owned(),
            }
            .build()
        })?;
        if sealed_last.is_some_and(|sealed| sealed != last) {
            return AnalysisStateSnafu {
                path,
                reason: "the evidence segment range does not match its name".to_owned(),
            }
            .fail();
        }
        let bounds = EvidenceSegmentBoundsV1 {
            stream_id: stream,
            first_cursor: first,
            last_cursor: last,
        };
        Ok(Some(Self {
            descriptor: EvidenceSegmentDescriptorV1 {
                reference: EvidenceSegmentRefV1 {
                    id,
                    offset: bytes.len() as u64,
                },
                bounds,
            },
            identity,
            path,
            frames,
            active,
        }))
    }

    fn seal(&mut self, root: &Path) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let path = self.sealed_path(root);
        fs::rename(&self.path, &path).context(IoSnafu { path: &path })?;
        self.path = path;
        self.active = false;
        Ok(())
    }

    fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .context(IoSnafu { path })
    }
}

pub(crate) struct EvidenceSegmentOwner {
    root: PathBuf,
    segments: BTreeMap<u64, EvidenceSegmentStateV1>,
    active: BTreeMap<u64, u64>,
    identities: BTreeMap<u64, RawIdentity>,
    next_id: u64,
}

impl EvidenceSegmentOwner {
    pub(super) fn seal_all(&mut self) -> Result<()> {
        for id in self.active.values() {
            let state = self.segments.get_mut(id).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: &self.root,
                    reason: "the active raw segment is absent",
                }
                .build()
            })?;
            state.seal(&self.root)?;
        }
        self.active.clear();
        EvidenceSegmentStateV1::sync_directory(&self.root)
    }

    pub(super) fn append_plan(
        &self,
        identity: &RawIdentity,
        stream: u64,
        sequence: u64,
        bytes: u64,
        force_new: bool,
    ) -> Result<(u64, u64, bool)> {
        if let Some(state) = self
            .active
            .get(&stream)
            .and_then(|id| self.segments.get(id))
            .filter(|state| {
                !force_new
                    && state.descriptor.bounds.last_cursor.checked_add(1) == Some(sequence)
                    && state
                        .descriptor
                        .reference
                        .offset
                        .checked_add(bytes)
                        .is_some_and(|end| end <= MAX_SEGMENT_BYTES)
            })
        {
            return Ok((state.descriptor.reference.id, bytes, false));
        }
        Ok((
            self.next_id,
            bytes + super::SegmentFile::encode_raw(identity)?.len() as u64,
            true,
        ))
    }

    pub(super) fn seal_stream(&mut self, stream: u64) -> Result<()> {
        if let Some(id) = self.active.get(&stream).copied() {
            self.segments
                .get_mut(&id)
                .ok_or_else(|| {
                    AnalysisStateSnafu {
                        path: &self.root,
                        reason: "the active raw segment is absent",
                    }
                    .build()
                })?
                .seal(&self.root)?;
            self.active.remove(&stream);
        }
        Ok(())
    }

    pub(super) fn file_path(&self, id: u64) -> Result<&Path> {
        self.segments
            .get(&id)
            .map(|state| state.path.as_path())
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: &self.root,
                    reason: "the raw segment is absent",
                }
                .build()
            })
    }

    pub(super) fn next_id(&self) -> u64 {
        self.next_id
    }

    pub(super) fn advance_id(&mut self, next: u64) {
        self.next_id = self.next_id.max(next);
    }

    pub(super) fn forget(&mut self, id: u64) {
        self.segments.remove(&id);
        self.active.retain(|_, active| *active != id);
    }

    pub(crate) fn open(raw_root: &Path, committed: &BTreeMap<u64, u64>) -> Result<Self> {
        let root = raw_root.to_path_buf();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let mut segments = BTreeMap::new();
        let mut active = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut next_id = 1_u64;
        let mut directory_changed = false;
        let mut diagnostic_count = 0;
        let mut evidence_count = 0;
        for (count, entry) in fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .enumerate()
        {
            if count
                >= super::capacity::MAX_STORAGE_ENTRIES + super::capacity::MAX_DIAGNOSTIC_ENTRIES
            {
                return super::AnalysisStore::reject_path(
                    &root,
                    "the raw segment directory exceeds its entry bound",
                );
            }
            let entry = entry.context(IoSnafu { path: &root })?;
            let path = entry.path();
            let metadata = entry.metadata().context(IoSnafu { path: &path })?;
            if !metadata.is_file() {
                return AnalysisStateSnafu {
                    path,
                    reason: "the evidence segment directory contains a non-file entry".to_owned(),
                }
                .fail();
            }
            let (id, stream, first, sealed_last, kind) = EvidenceSegmentStateV1::parse_name(&path)?;
            if kind == "diagnostic" {
                diagnostic_count += 1;
            } else {
                evidence_count += 1;
            }
            if diagnostic_count > super::capacity::MAX_DIAGNOSTIC_ENTRIES
                || evidence_count > super::capacity::MAX_STORAGE_ENTRIES
            {
                return super::AnalysisStore::reject_path(
                    &root,
                    "the raw stream kind exceeds its entry bound",
                );
            }
            next_id = next_id.max(id.checked_add(1).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: root.clone(),
                    reason: "the evidence segment sequence is exhausted".to_owned(),
                }
                .build()
            })?);
            let Some(segment) = EvidenceSegmentStateV1::read(
                path,
                id,
                stream,
                first,
                sealed_last,
                committed.get(&id).copied().unwrap_or(0),
                kind,
            )?
            else {
                directory_changed = true;
                continue;
            };
            if identities
                .insert(stream, segment.identity.clone())
                .is_some_and(|existing| existing != segment.identity)
            {
                return AnalysisStateSnafu {
                    path: segment.path,
                    reason: "one evidence stream identifier has conflicting identities".to_owned(),
                }
                .fail();
            }
            if segment.active && active.insert(stream, id).is_some() {
                return AnalysisStateSnafu {
                    path: segment.path,
                    reason: "one evidence stream has multiple active segments".to_owned(),
                }
                .fail();
            }
            if segments.insert(id, segment).is_some() {
                return AnalysisStateSnafu {
                    path: root,
                    reason: "the evidence segment sequence is duplicated".to_owned(),
                }
                .fail();
            }
        }
        if directory_changed {
            EvidenceSegmentStateV1::sync_directory(&root)?;
        }
        Ok(Self {
            root,
            segments,
            active,
            identities,
            next_id,
        })
    }

    pub(crate) fn write_frames(
        &mut self,
        identity: &RawIdentity,
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
        framed_records: prost::bytes::Bytes,
        frame_ends: Vec<usize>,
    ) -> Result<Vec<StoredEvidenceBatchV1>> {
        let expected = last_cursor
            .checked_sub(first_cursor)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok());
        if stream_id == 0 || first_cursor == 0 || expected != Some(frame_ends.len()) {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the evidence record range is invalid".to_owned(),
            }
            .fail();
        }
        let mut frames = EncodedEvidenceFramesV1::validated(framed_records, frame_ends)?;
        let stream = stream_id;
        let mut first = first_cursor;
        let mut last_written = 0;
        let mut batches = Vec::new();
        while !frames.frames.is_empty() {
            let first_frame_bytes = frames.frames[0].end;
            let capacity = self.append_capacity(identity, stream, first, first_frame_bytes)?;
            let record_count = frames.frames.partition_point(|frame| frame.end <= capacity);
            let chunk = frames.split_to(record_count);
            let last = first.checked_add(record_count as u64 - 1).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment cursor range is exhausted".to_owned(),
                }
                .build()
            })?;
            let segment = self.append_without_sync(identity, stream, first, last, chunk)?;
            batches.push(StoredEvidenceBatchV1 {
                first_cursor: first,
                last_cursor: last,
                segment,
            });
            last_written = last;
            if !frames.frames.is_empty() {
                first = last.checked_add(1).ok_or_else(|| {
                    AnalysisStateSnafu {
                        path: self.root.clone(),
                        reason: "the evidence segment cursor range is exhausted".to_owned(),
                    }
                    .build()
                })?;
            }
        }
        if last_written != last_cursor {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the evidence segment group range is incomplete".to_owned(),
            }
            .fail();
        }
        #[cfg(test)]
        super::AnalysisStore::crash_path(
            self.root.parent().unwrap_or(&self.root),
            "segment.appended",
        );
        self.sync()?;
        #[cfg(test)]
        super::AnalysisStore::crash_path(
            self.root.parent().unwrap_or(&self.root),
            "segment.synced",
        );
        Ok(batches)
    }

    pub(crate) fn open_read(
        &self,
        segment_id: u64,
        expected: EvidenceSegmentBoundsV1,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Option<EvidenceSegmentReadV1>> {
        let state = self.segments.get(&segment_id).ok_or_else(|| {
            AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the evidence read selected an absent segment".to_owned(),
            }
            .build()
        })?;
        let actual = state.descriptor.bounds;
        if expected.stream_id != actual.stream_id
            || expected.first_cursor < actual.first_cursor
            || expected.first_cursor > actual.last_cursor
            || expected.last_cursor < expected.first_cursor
        {
            return AnalysisStateSnafu {
                path: state.path.clone(),
                reason: "the evidence read selected a foreign or invalid range".to_owned(),
            }
            .fail();
        }
        let start =
            usize::try_from(expected.first_cursor - actual.first_cursor).map_err(|error| {
                AnalysisStateSnafu {
                    path: state.path.clone(),
                    reason: format!("the evidence read start exceeds local bounds: {error}"),
                }
                .build()
            })?;
        let count = usize::try_from(
            expected.last_cursor.min(actual.last_cursor) - expected.first_cursor + 1,
        )
        .unwrap_or(usize::MAX)
        .min(maximum_records);
        let selected = state
            .frames
            .get(start..start.saturating_add(count))
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: state.path.clone(),
                    reason: "the evidence read exceeds its frame index".to_owned(),
                }
                .build()
            })?;
        let mut frames = Vec::with_capacity(count);
        let mut encoded_bytes = 0;
        for frame in selected {
            let length = frame.end - (frame.payload_start - 4);
            if length > maximum_bytes - encoded_bytes {
                break;
            }
            frames.push(*frame);
            encoded_bytes += length;
        }
        if frames.is_empty() {
            return Ok(None);
        }
        let file = super::SegmentFile::reader(&state.path)?;
        Ok(Some(EvidenceSegmentReadV1 {
            file,
            path: state.path.clone(),
            frames,
        }))
    }

    pub(crate) fn descriptors(&self) -> impl Iterator<Item = EvidenceSegmentDescriptorV1> + '_ {
        self.segments.values().map(|state| state.descriptor)
    }

    pub(crate) fn identities(&self) -> impl Iterator<Item = (u64, &RawIdentity)> + '_ {
        self.identities
            .iter()
            .map(|(stream_id, identity)| (*stream_id, identity))
    }

    pub(crate) fn reference_at(
        &self,
        segment_id: u64,
        position: u64,
    ) -> Result<EvidenceSegmentRefV1> {
        let state = self.segments.get(&segment_id).ok_or_else(|| {
            AnalysisStateSnafu {
                path: self.root.clone(),
                reason: format!("evidence segment {segment_id} is missing"),
            }
            .build()
        })?;
        let index = position
            .checked_sub(state.descriptor.bounds.first_cursor)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: state.path.clone(),
                    reason: "the evidence segment position precedes its range".to_owned(),
                }
                .build()
            })?;
        let frame = state.frames.get(index).ok_or_else(|| {
            AnalysisStateSnafu {
                path: state.path.clone(),
                reason: "the evidence segment position exceeds its range".to_owned(),
            }
            .build()
        })?;
        Ok(EvidenceSegmentRefV1 {
            id: segment_id,
            offset: frame.end as u64,
        })
    }

    fn append_capacity(
        &self,
        identity: &RawIdentity,
        stream: u64,
        first: u64,
        first_frame_bytes: usize,
    ) -> Result<usize> {
        let active_capacity = self
            .active
            .get(&stream)
            .and_then(|id| self.segments.get(id))
            .filter(|state| state.descriptor.bounds.last_cursor.checked_add(1) == Some(first))
            .and_then(|state| {
                MAX_SEGMENT_BYTES
                    .checked_sub(state.descriptor.reference.offset)
                    .and_then(|capacity| usize::try_from(capacity).ok())
            })
            .filter(|capacity| *capacity >= first_frame_bytes);
        if let Some(capacity) = active_capacity {
            return Ok(capacity);
        }
        let identity_bytes = super::SegmentFile::encode_raw(identity)?.len();
        let capacity = crate::MAX_EVIDENCE_SEGMENT_BYTES
            .checked_sub(identity_bytes)
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment identity exceeds its size bound".to_owned(),
                }
                .build()
            })?;
        if first_frame_bytes > capacity {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "one evidence record exceeds the segment size bound".to_owned(),
            }
            .fail();
        }
        Ok(capacity)
    }

    fn append_without_sync(
        &mut self,
        identity: &RawIdentity,
        stream: u64,
        first: u64,
        last: u64,
        frames: EncodedEvidenceFramesV1,
    ) -> Result<EvidenceSegmentRefV1> {
        let count = last
            .checked_sub(first)
            .and_then(|count| count.checked_add(1));
        if frames.frames.is_empty() || count != Some(frames.frames.len() as u64) {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the evidence append range is invalid".to_owned(),
            }
            .fail();
        }
        if self
            .identities
            .get(&stream)
            .is_some_and(|existing| existing != identity)
        {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the evidence append crossed a stream identity".to_owned(),
            }
            .fail();
        }
        let frame_bytes = frames.bytes.len() as u64;
        let identity_bytes = super::SegmentFile::encode_raw(identity)?;
        let new_segment_bytes = frame_bytes
            .checked_add(identity_bytes.len() as u64)
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment size is exhausted".to_owned(),
                }
                .build()
            })?;
        if new_segment_bytes > MAX_SEGMENT_BYTES {
            return AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "one evidence append exceeds 16 MiB".to_owned(),
            }
            .fail();
        }
        let active_id = self.active.get(&stream).copied();
        let active_fits = active_id
            .and_then(|id| self.segments.get(&id))
            .is_some_and(|state| {
                state.descriptor.bounds.last_cursor.checked_add(1) == Some(first)
                    && state
                        .descriptor
                        .reference
                        .offset
                        .checked_add(frame_bytes)
                        .is_some_and(|bytes| bytes <= MAX_SEGMENT_BYTES)
            });
        if !active_fits {
            if let Some(id) = active_id {
                let state = self.segments.get_mut(&id).ok_or_else(|| {
                    AnalysisStateSnafu {
                        path: self.root.clone(),
                        reason: "the active evidence segment is missing".to_owned(),
                    }
                    .build()
                })?;
                state.seal(&self.root)?;
                self.active.remove(&stream);
            }
        }

        let id = if active_fits {
            active_id.unwrap_or_default()
        } else {
            let id = self.next_id;
            self.next_id = self.next_id.checked_add(1).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment sequence is exhausted".to_owned(),
                }
                .build()
            })?;
            id
        };
        if active_fits {
            let state = self.segments.get_mut(&id).ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the selected evidence segment is missing".to_owned(),
                }
                .build()
            })?;
            let start = state.descriptor.reference.offset as usize;
            let file = super::SegmentFile::open(&state.path)?;
            file.append(state.descriptor.reference.offset, &frames.bytes)?;
            Self::extend_frames(&mut state.frames, start, &frames.frames);
            state.descriptor.bounds.last_cursor = last;
            state.descriptor.reference.offset += frame_bytes;
        } else {
            let path = EvidenceSegmentStateV1::active_path(&self.root, id, stream, first, identity);
            let file = super::SegmentFile::create(&path, &identity_bytes)?;
            #[cfg(test)]
            super::AnalysisStore::crash_path(
                self.root.parent().unwrap_or(&self.root),
                "segment.reserved",
            );
            file.append(identity_bytes.len() as u64, &frames.bytes)?;
            let bounds = EvidenceSegmentBoundsV1 {
                stream_id: stream,
                first_cursor: first,
                last_cursor: last,
            };
            let mut indexes = Vec::with_capacity(frames.frames.len());
            Self::extend_frames(&mut indexes, identity_bytes.len(), &frames.frames);
            self.segments.insert(
                id,
                EvidenceSegmentStateV1 {
                    descriptor: EvidenceSegmentDescriptorV1 {
                        reference: EvidenceSegmentRefV1 {
                            id,
                            offset: new_segment_bytes,
                        },
                        bounds,
                    },
                    identity: identity.clone(),
                    path,
                    frames: indexes,
                    active: true,
                },
            );
            self.active.insert(stream, id);
            self.identities
                .entry(stream)
                .or_insert_with(|| identity.clone());
        }
        self.segments
            .get(&id)
            .map(|state| state.descriptor.reference)
            .ok_or_else(|| {
                AnalysisStateSnafu {
                    path: self.root.clone(),
                    reason: "the appended evidence segment is missing".to_owned(),
                }
                .build()
            })
    }

    fn sync(&self) -> Result<()> {
        let directory = File::open(&self.root).context(IoSnafu { path: &self.root })?;
        rustix::fs::syncfs(&directory)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &self.root })
    }

    fn extend_frames(
        indexes: &mut Vec<EvidenceFrameIndexV1>,
        start: usize,
        frames: &[EvidenceFrameIndexV1],
    ) {
        indexes.extend(frames.iter().map(|frame| EvidenceFrameIndexV1 {
            payload_start: start + frame.payload_start,
            payload_end: start + frame.payload_end,
            end: start + frame.end,
        }));
    }
}
