use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use prost::Message;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{ControlStoreSnafu, IoSnafu};
use crate::Result;

pub(crate) const MAX_SEGMENT_BYTES: u64 = crate::MAX_EVIDENCE_SEGMENT_BYTES as u64;
const FRAME_OVERHEAD_BYTES: usize = 8;
const IDENTITY_FIXED_BYTES: usize = 70;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStoreCapacityPolicyV1 {
    #[default]
    Block,
    Retain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStoreLimitsV1 {
    pub maximum_retained_bytes: u64,
    pub maximum_retained_records: u64,
    #[serde(default)]
    pub capacity_policy: EvidenceStoreCapacityPolicyV1,
}

impl EvidenceStoreLimitsV1 {
    pub fn validate(self) -> Result<()> {
        if self.maximum_retained_bytes < MAX_SEGMENT_BYTES || self.maximum_retained_records == 0 {
            return ControlStoreSnafu {
                path: PathBuf::from("<evidence-store-limits>"),
                reason: "evidence store bounds are zero or smaller than one segment".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl Default for EvidenceStoreLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_retained_bytes: 1_024 * 1_024 * 1_024,
            maximum_retained_records: 1_000_000,
            capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSegmentRefV1 {
    pub(crate) id: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSegmentPositionV1 {
    pub(crate) id: u64,
    pub(crate) offset: u64,
}

impl EvidenceSegmentPositionV1 {
    pub(crate) fn include(&mut self, reference: EvidenceSegmentRefV1) {
        let position = Self {
            id: reference.id,
            offset: reference.offset,
        };
        if position > *self {
            *self = position;
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum EvidenceSegmentStreamKindV1 {
    Records,
    Coverage,
}

impl EvidenceSegmentStreamKindV1 {
    fn field(self) -> &'static str {
        match self {
            Self::Records => "r",
            Self::Coverage => "c",
        }
    }

    fn parse(value: &str, path: &Path) -> Result<Self> {
        match value {
            "r" => Ok(Self::Records),
            "c" => Ok(Self::Coverage),
            _ => ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment kind is invalid".to_owned(),
            }
            .fail(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceSegmentStreamV1 {
    pub(crate) stream_id: u64,
    pub(crate) kind: EvidenceSegmentStreamKindV1,
}

impl EvidenceSegmentStreamV1 {
    pub(crate) fn records(stream_id: u64) -> Self {
        Self {
            stream_id,
            kind: EvidenceSegmentStreamKindV1::Records,
        }
    }

    pub(crate) fn coverage(stream_id: u64) -> Self {
        Self {
            stream_id,
            kind: EvidenceSegmentStreamKindV1::Coverage,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceSegmentKindV1 {
    Records {
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
    },
    Coverage {
        stream_id: u64,
        first_revision: u64,
        last_revision: u64,
    },
}

impl EvidenceSegmentKindV1 {
    pub(crate) fn stream(self) -> EvidenceSegmentStreamV1 {
        match self {
            Self::Records { stream_id, .. } => EvidenceSegmentStreamV1::records(stream_id),
            Self::Coverage { stream_id, .. } => EvidenceSegmentStreamV1::coverage(stream_id),
        }
    }

    pub(crate) fn stream_id(self) -> u64 {
        self.stream().stream_id
    }

    fn first(self) -> u64 {
        match self {
            Self::Records { first_cursor, .. } => first_cursor,
            Self::Coverage { first_revision, .. } => first_revision,
        }
    }

    fn last(self) -> u64 {
        match self {
            Self::Records { last_cursor, .. } => last_cursor,
            Self::Coverage { last_revision, .. } => last_revision,
        }
    }

    fn retained_records(self) -> u64 {
        match self {
            Self::Records {
                first_cursor,
                last_cursor,
                ..
            } => last_cursor - first_cursor + 1,
            Self::Coverage { .. } => 0,
        }
    }

    fn with_last(self, last: u64) -> Self {
        match self {
            Self::Records {
                stream_id,
                first_cursor,
                ..
            } => Self::Records {
                stream_id,
                first_cursor,
                last_cursor: last,
            },
            Self::Coverage {
                stream_id,
                first_revision,
                ..
            } => Self::Coverage {
                stream_id,
                first_revision,
                last_revision: last,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceSegmentDescriptorV1 {
    pub(crate) reference: EvidenceSegmentRefV1,
    pub(crate) kind: EvidenceSegmentKindV1,
}

#[derive(Clone, Copy, Debug)]
struct EvidenceFrameIndexV1 {
    payload_start: usize,
    payload_end: usize,
    end: usize,
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
                return ControlStoreSnafu {
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
            return ControlStoreSnafu {
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
    identity: crate::EvidenceIntakeIdentityV1,
    path: PathBuf,
    frames: Vec<EvidenceFrameIndexV1>,
    active: bool,
}

impl EvidenceSegmentStateV1 {
    fn encode_identity(identity: &crate::EvidenceIntakeIdentityV1) -> Result<Vec<u8>> {
        let node_id_bytes = identity.node_id.as_bytes();
        let node_id_len = u16::try_from(node_id_bytes.len()).map_err(|error| {
            ControlStoreSnafu {
                path: PathBuf::from("<evidence-stream-identity>"),
                reason: format!("the evidence stream node identity is too long: {error}"),
            }
            .build()
        })?;
        let mut bytes = Vec::with_capacity(IDENTITY_FIXED_BYTES + node_id_bytes.len());
        bytes.extend_from_slice(&identity.tenant_id);
        bytes.extend_from_slice(&identity.node_boot_id);
        bytes.extend_from_slice(&identity.source_id);
        bytes.extend_from_slice(&identity.label_epoch.to_be_bytes());
        bytes.extend_from_slice(&identity.source_epoch.to_be_bytes());
        bytes.extend_from_slice(&node_id_len.to_be_bytes());
        bytes.extend_from_slice(node_id_bytes);
        let checksum = crc32c::crc32c(&bytes);
        bytes.extend_from_slice(&checksum.to_be_bytes());
        Ok(bytes)
    }

    fn decode_identity(
        bytes: &[u8],
        path: &Path,
    ) -> Result<(crate::EvidenceIntakeIdentityV1, usize)> {
        if bytes.len() < IDENTITY_FIXED_BYTES {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity is truncated".to_owned(),
            }
            .fail();
        }
        let node_id_len = u16::from_be_bytes(bytes[64..66].try_into().unwrap_or_default()) as usize;
        let header_bytes = IDENTITY_FIXED_BYTES
            .checked_add(node_id_len)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the evidence segment stream identity size overflowed".to_owned(),
                }
                .build()
            })?;
        if bytes.len() < header_bytes {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity is incomplete".to_owned(),
            }
            .fail();
        }
        let checksum_start = header_bytes - 4;
        let expected = u32::from_be_bytes(
            bytes[checksum_start..header_bytes]
                .try_into()
                .unwrap_or_default(),
        );
        if crc32c::crc32c(&bytes[..checksum_start]) != expected {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment stream identity checksum is invalid".to_owned(),
            }
            .fail();
        }
        let node_id = std::str::from_utf8(&bytes[66..checksum_start])
            .map_err(|error| {
                ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: format!("the evidence segment node identity is invalid: {error}"),
                }
                .build()
            })?
            .to_owned();
        Ok((
            crate::EvidenceIntakeIdentityV1 {
                tenant_id: bytes[..16].try_into().unwrap_or_default(),
                node_id,
                node_boot_id: bytes[16..32].try_into().unwrap_or_default(),
                label_epoch: u64::from_be_bytes(bytes[48..56].try_into().unwrap_or_default()),
                source_id: bytes[32..48].try_into().unwrap_or_default(),
                source_epoch: u64::from_be_bytes(bytes[56..64].try_into().unwrap_or_default()),
            },
            header_bytes,
        ))
    }

    fn active_path(root: &Path, id: u64, stream: EvidenceSegmentStreamV1, first: u64) -> PathBuf {
        root.join(format!(
            "{id:016x}.{}.{:016x}.{first:016x}.open",
            stream.kind.field(),
            stream.stream_id
        ))
    }

    fn sealed_path(&self, root: &Path) -> PathBuf {
        let id = self.descriptor.reference.id;
        let kind = self.descriptor.kind;
        let stream = kind.stream();
        let first = kind.first();
        let last = kind.last();
        root.join(format!(
            "{id:016x}.{}.{:016x}.{first:016x}.{last:016x}.seg",
            stream.kind.field(),
            stream.stream_id
        ))
    }

    fn parse_name(path: &Path) -> Result<(u64, EvidenceSegmentStreamV1, u64, Option<u64>)> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let fields = name.split('.').collect::<Vec<_>>();
        let (id, kind, stream_id, first, last) = match fields.as_slice() {
            [id, kind, stream_id, first, "open"] => (
                Self::field(id, path)?,
                EvidenceSegmentStreamKindV1::parse(kind, path)?,
                Self::field(stream_id, path)?,
                Self::field(first, path)?,
                None,
            ),
            [id, kind, stream_id, first, last, "seg"] => (
                Self::field(id, path)?,
                EvidenceSegmentStreamKindV1::parse(kind, path)?,
                Self::field(stream_id, path)?,
                Self::field(first, path)?,
                Some(Self::field(last, path)?),
            ),
            _ => {
                return ControlStoreSnafu {
                    path: path.to_owned(),
                    reason: "the evidence segment name is invalid".to_owned(),
                }
                .fail();
            }
        };
        if id == 0 || stream_id == 0 || first == 0 || last.is_some_and(|last| last < first) {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index is invalid".to_owned(),
            }
            .fail();
        }
        Ok((id, EvidenceSegmentStreamV1 { stream_id, kind }, first, last))
    }

    fn field(value: &str, path: &Path) -> Result<u64> {
        if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return ControlStoreSnafu {
                path: path.to_owned(),
                reason: "the evidence segment index field is invalid".to_owned(),
            }
            .fail();
        }
        u64::from_str_radix(value, 16).map_err(|error| {
            ControlStoreSnafu {
                path: path.to_owned(),
                reason: format!("the evidence segment index is invalid: {error}"),
            }
            .build()
        })
    }

    fn read(
        path: PathBuf,
        id: u64,
        stream: EvidenceSegmentStreamV1,
        first: u64,
        sealed_last: Option<u64>,
    ) -> Result<Option<Self>> {
        let mut bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return ControlStoreSnafu {
                path,
                reason: "the evidence segment exceeds 16 MiB".to_owned(),
            }
            .fail();
        }
        let (identity, header_bytes) = Self::decode_identity(&bytes, &path)?;
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
            let maximum_payload = match stream.kind {
                EvidenceSegmentStreamKindV1::Records => crate::MAX_EVIDENCE_RECORD_BYTES,
                EvidenceSegmentStreamKindV1::Coverage => crate::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES,
            };
            if payload_bytes == 0 || payload_bytes > maximum_payload {
                return ControlStoreSnafu {
                    path,
                    reason: "the evidence segment contains a record outside its size bound"
                        .to_owned(),
                }
                .fail();
            }
            let frame_bytes = payload_bytes
                .checked_add(FRAME_OVERHEAD_BYTES)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: path.clone(),
                        reason: "the evidence segment frame size overflowed".to_owned(),
                    }
                    .build()
                })?;
            let end = offset.checked_add(frame_bytes).ok_or_else(|| {
                ControlStoreSnafu {
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
                return ControlStoreSnafu {
                    path,
                    reason: "the evidence segment record checksum is invalid".to_owned(),
                }
                .fail();
            }
            let payload_start = offset + 4;
            match stream.kind {
                EvidenceSegmentStreamKindV1::Records => {
                    crate::EvidenceRecord::decode(&bytes[payload_start..checksum_start]).map_err(
                        |error| {
                            ControlStoreSnafu {
                                path: path.clone(),
                                reason: format!(
                                    "the evidence segment record protobuf is invalid: {error}"
                                ),
                            }
                            .build()
                        },
                    )?;
                }
                EvidenceSegmentStreamKindV1::Coverage => {
                    crate::CoverageReport::decode(&bytes[payload_start..checksum_start]).map_err(
                        |error| {
                            ControlStoreSnafu {
                                path: path.clone(),
                                reason: format!(
                                    "the evidence segment coverage protobuf is invalid: {error}"
                                ),
                            }
                            .build()
                        },
                    )?;
                }
            }
            frames.push(EvidenceFrameIndexV1 {
                payload_start,
                payload_end: checksum_start,
                end,
            });
            offset = end;
        }
        if incomplete {
            if !active {
                return ControlStoreSnafu {
                    path,
                    reason: "the sealed evidence segment has an incomplete record tail".to_owned(),
                }
                .fail();
            }
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .context(IoSnafu { path: &path })?;
            file.set_len(offset as u64)
                .context(IoSnafu { path: &path })?;
            file.sync_data().context(IoSnafu { path: &path })?;
            bytes.truncate(offset);
        }
        if frames.is_empty() {
            if active {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                return Ok(None);
            }
            return ControlStoreSnafu {
                path,
                reason: "a sealed evidence segment is empty".to_owned(),
            }
            .fail();
        }
        let last = first.checked_add(frames.len() as u64 - 1).ok_or_else(|| {
            ControlStoreSnafu {
                path: path.clone(),
                reason: "the evidence segment range is exhausted".to_owned(),
            }
            .build()
        })?;
        if sealed_last.is_some_and(|sealed| sealed != last) {
            return ControlStoreSnafu {
                path,
                reason: "the evidence segment range does not match its name".to_owned(),
            }
            .fail();
        }
        let kind = match stream.kind {
            EvidenceSegmentStreamKindV1::Records => EvidenceSegmentKindV1::Records {
                stream_id: stream.stream_id,
                first_cursor: first,
                last_cursor: last,
            },
            EvidenceSegmentStreamKindV1::Coverage => EvidenceSegmentKindV1::Coverage {
                stream_id: stream.stream_id,
                first_revision: first,
                last_revision: last,
            },
        };
        Ok(Some(Self {
            descriptor: EvidenceSegmentDescriptorV1 {
                reference: EvidenceSegmentRefV1 {
                    id,
                    offset: bytes.len() as u64,
                },
                kind,
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
    active: BTreeMap<EvidenceSegmentStreamV1, u64>,
    identities: BTreeMap<u64, crate::EvidenceIntakeIdentityV1>,
    retained_bytes: u64,
    retained_records: u64,
    next_id: u64,
    limits: EvidenceStoreLimitsV1,
}

impl EvidenceSegmentOwner {
    pub(crate) fn open(control_root: &Path, limits: EvidenceStoreLimitsV1) -> Result<Self> {
        limits.validate()?;
        let root = control_root.join("evidence").join("segments-v2");
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let mut segments = BTreeMap::new();
        let mut active = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut retained_bytes = 0_u64;
        let mut retained_records = 0_u64;
        let mut next_id = 1_u64;
        let mut directory_changed = false;
        for entry in fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: &root })?
        {
            let path = entry.path();
            let metadata = entry.metadata().context(IoSnafu { path: &path })?;
            if !metadata.is_file() {
                return ControlStoreSnafu {
                    path,
                    reason: "the evidence segment directory contains a non-file entry".to_owned(),
                }
                .fail();
            }
            let (id, stream, first, sealed_last) = EvidenceSegmentStateV1::parse_name(&path)?;
            next_id = next_id.max(id.checked_add(1).ok_or_else(|| {
                ControlStoreSnafu {
                    path: root.clone(),
                    reason: "the evidence segment sequence is exhausted".to_owned(),
                }
                .build()
            })?);
            let Some(segment) = EvidenceSegmentStateV1::read(path, id, stream, first, sealed_last)?
            else {
                directory_changed = true;
                continue;
            };
            if identities
                .insert(stream.stream_id, segment.identity.clone())
                .is_some_and(|existing| existing != segment.identity)
            {
                return ControlStoreSnafu {
                    path: segment.path,
                    reason: "one evidence stream identifier has conflicting identities".to_owned(),
                }
                .fail();
            }
            retained_bytes = retained_bytes
                .checked_add(segment.descriptor.reference.offset)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: root.clone(),
                        reason: "the retained evidence byte count is exhausted".to_owned(),
                    }
                    .build()
                })?;
            retained_records = retained_records
                .checked_add(segment.descriptor.kind.retained_records())
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: root.clone(),
                        reason: "the retained evidence record count is exhausted".to_owned(),
                    }
                    .build()
                })?;
            if segment.active && active.insert(stream, id).is_some() {
                return ControlStoreSnafu {
                    path: segment.path,
                    reason: "one evidence stream has multiple active segments".to_owned(),
                }
                .fail();
            }
            if segments.insert(id, segment).is_some() {
                return ControlStoreSnafu {
                    path: root,
                    reason: "the evidence segment sequence is duplicated".to_owned(),
                }
                .fail();
            }
        }
        if directory_changed {
            EvidenceSegmentStateV1::sync_directory(&root)?;
        }
        let owner = Self {
            root,
            segments,
            active,
            identities,
            retained_bytes,
            retained_records,
            next_id,
            limits,
        };
        owner.validate_retention()?;
        Ok(owner)
    }

    pub(crate) fn write_frames(
        &mut self,
        identity: &crate::EvidenceIntakeIdentityV1,
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
        framed_records: prost::bytes::Bytes,
        frame_ends: Vec<usize>,
    ) -> Result<Vec<crate::StoredEvidenceBatchV1>> {
        let expected = last_cursor
            .checked_sub(first_cursor)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok());
        if stream_id == 0 || first_cursor == 0 || expected != Some(frame_ends.len()) {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence record range is invalid".to_owned(),
            }
            .fail();
        }
        let mut frames = EncodedEvidenceFramesV1::validated(framed_records, frame_ends)?;
        let stream = EvidenceSegmentStreamV1::records(stream_id);
        let mut first = first_cursor;
        let mut last_written = 0;
        let mut batches = Vec::new();
        while !frames.frames.is_empty() {
            let first_frame_bytes = frames.frames[0].end;
            let capacity = self.append_capacity(identity, stream, first, first_frame_bytes)?;
            let record_count = frames.frames.partition_point(|frame| frame.end <= capacity);
            let chunk = frames.split_to(record_count);
            let last = first.checked_add(record_count as u64 - 1).ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment cursor range is exhausted".to_owned(),
                }
                .build()
            })?;
            let segment = self.append_without_sync(identity, stream, first, last, chunk)?;
            batches.push(crate::StoredEvidenceBatchV1 {
                first_cursor: first,
                last_cursor: last,
                segment,
            });
            last_written = last;
            if !frames.frames.is_empty() {
                first = last.checked_add(1).ok_or_else(|| {
                    ControlStoreSnafu {
                        path: self.root.clone(),
                        reason: "the evidence segment cursor range is exhausted".to_owned(),
                    }
                    .build()
                })?;
            }
        }
        if last_written != last_cursor {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence segment group range is incomplete".to_owned(),
            }
            .fail();
        }
        self.sync()?;
        Ok(batches)
    }

    #[cfg(test)]
    pub(crate) fn write_records(
        &mut self,
        identity: &crate::EvidenceIntakeIdentityV1,
        stream_id: u64,
        first_cursor: u64,
        last_cursor: u64,
        records: &crate::EvidenceRecords,
    ) -> Result<EvidenceSegmentRefV1> {
        let expected = last_cursor
            .checked_sub(first_cursor)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| usize::try_from(count).ok());
        if stream_id == 0 || first_cursor == 0 || expected != Some(records.records.len()) {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence record range is invalid".to_owned(),
            }
            .fail();
        }
        let frames = Self::encode_frames(&records.records, crate::MAX_EVIDENCE_RECORD_BYTES)?;
        let reference = self.append_without_sync(
            identity,
            EvidenceSegmentStreamV1::records(stream_id),
            first_cursor,
            last_cursor,
            frames,
        )?;
        self.sync()?;
        Ok(reference)
    }

    pub(crate) fn write_coverage(
        &mut self,
        identity: &crate::EvidenceIntakeIdentityV1,
        stream_id: u64,
        revision: u64,
        report: &crate::CoverageReport,
    ) -> Result<EvidenceSegmentRefV1> {
        if stream_id == 0 || revision == 0 {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence coverage range is invalid".to_owned(),
            }
            .fail();
        }
        let reference = self.append_without_sync(
            identity,
            EvidenceSegmentStreamV1::coverage(stream_id),
            revision,
            revision,
            Self::encode_frames(
                std::slice::from_ref(report),
                crate::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES,
            )?,
        )?;
        self.sync()?;
        Ok(reference)
    }

    pub(crate) fn read_records(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
    ) -> Result<crate::EvidenceRecords> {
        let EvidenceSegmentKindV1::Records {
            stream_id,
            first_cursor,
            last_cursor,
        } = expected
        else {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "an evidence record read used a coverage range".to_owned(),
            }
            .fail();
        };
        let payloads = self.read_payloads(reference, expected)?;
        let records = payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                crate::EvidenceRecord::decode(payload.as_slice()).map_err(|error| {
                    ControlStoreSnafu {
                        path: self.root.clone(),
                        reason: format!(
                            "evidence record {}:{} protobuf decoding failed: {error}",
                            stream_id,
                            first_cursor.saturating_add(index as u64)
                        ),
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if records.len() as u64 != last_cursor - first_cursor + 1 {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence record range is incomplete".to_owned(),
            }
            .fail();
        }
        Ok(crate::EvidenceRecords { records })
    }

    pub(crate) fn read_record_frames(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
    ) -> Result<Vec<u8>> {
        let state = self.segments.get(&reference.id).ok_or_else(|| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: format!("evidence segment {} is missing", reference.id),
            }
            .build()
        })?;
        let actual = state.descriptor.kind;
        if actual.stream() != expected.stream()
            || expected.first() < actual.first()
            || expected.last() > actual.last()
        {
            return ControlStoreSnafu {
                path: state.path.clone(),
                reason: "evidence segment metadata does not contain its index range".to_owned(),
            }
            .fail();
        }
        let first_index = usize::try_from(expected.first() - actual.first()).map_err(|error| {
            ControlStoreSnafu {
                path: state.path.clone(),
                reason: format!("the evidence segment start is invalid: {error}"),
            }
            .build()
        })?;
        let count = usize::try_from(expected.last() - expected.first() + 1).map_err(|error| {
            ControlStoreSnafu {
                path: state.path.clone(),
                reason: format!("the evidence segment range is invalid: {error}"),
            }
            .build()
        })?;
        let selected = state
            .frames
            .get(first_index..first_index.saturating_add(count))
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: state.path.clone(),
                    reason: "the evidence segment index exceeds its record frames".to_owned(),
                }
                .build()
            })?;
        let start = selected
            .first()
            .map(|frame| frame.payload_start - 4)
            .unwrap_or_default();
        let end = selected.last().map_or(0, |frame| frame.end);
        let bytes = fs::read(&state.path).context(IoSnafu { path: &state.path })?;
        Ok(bytes[start..end].to_vec())
    }

    pub(crate) fn read_coverage(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
    ) -> Result<crate::CoverageReport> {
        let payloads = self.read_payloads(reference, expected)?;
        let [payload] = payloads.as_slice() else {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "a coverage read did not select one report".to_owned(),
            }
            .fail();
        };
        crate::CoverageReport::decode(payload.as_slice()).map_err(|error| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: format!("evidence coverage protobuf decoding failed: {error}"),
            }
            .build()
        })
    }

    pub(crate) fn descriptors(&self) -> impl Iterator<Item = EvidenceSegmentDescriptorV1> + '_ {
        self.segments.values().map(|state| state.descriptor)
    }

    pub(crate) fn identities(
        &self,
    ) -> impl Iterator<Item = (u64, &crate::EvidenceIntakeIdentityV1)> + '_ {
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
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: format!("evidence segment {segment_id} is missing"),
            }
            .build()
        })?;
        let index = position
            .checked_sub(state.descriptor.kind.first())
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: state.path.clone(),
                    reason: "the evidence segment position precedes its range".to_owned(),
                }
                .build()
            })?;
        let frame = state.frames.get(index).ok_or_else(|| {
            ControlStoreSnafu {
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

    pub(crate) fn positions(
        &self,
    ) -> impl Iterator<Item = (EvidenceSegmentStreamV1, EvidenceSegmentPositionV1)> + '_ {
        let mut positions: BTreeMap<EvidenceSegmentStreamV1, EvidenceSegmentPositionV1> =
            BTreeMap::new();
        for state in self.segments.values() {
            let position = positions.entry(state.descriptor.kind.stream()).or_default();
            position.include(state.descriptor.reference);
        }
        positions.into_iter()
    }

    pub(crate) fn reclaim_unreferenced(
        &mut self,
        references: &BTreeSet<EvidenceSegmentRefV1>,
    ) -> Result<()> {
        let retained_ids = references
            .iter()
            .map(|reference| reference.id)
            .collect::<BTreeSet<_>>();
        let discarded = self
            .segments
            .keys()
            .copied()
            .filter(|id| !retained_ids.contains(id))
            .collect::<Vec<_>>();
        if discarded.is_empty() {
            return Ok(());
        }
        for id in discarded {
            let state = self.segments.remove(&id).ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the reclaimed evidence segment disappeared".to_owned(),
                }
                .build()
            })?;
            fs::remove_file(&state.path).context(IoSnafu { path: &state.path })?;
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(state.descriptor.reference.offset)
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: self.root.clone(),
                        reason: "the reclaimed evidence byte count exceeds retained storage"
                            .to_owned(),
                    }
                    .build()
                })?;
            self.retained_records = self
                .retained_records
                .checked_sub(state.descriptor.kind.retained_records())
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: self.root.clone(),
                        reason: "the reclaimed evidence record count exceeds retained storage"
                            .to_owned(),
                    }
                    .build()
                })?;
            self.active.retain(|_stream, active_id| *active_id != id);
        }
        EvidenceSegmentStateV1::sync_directory(&self.root)
    }

    pub(crate) fn validate_retention(&self) -> Result<()> {
        if self.limits.capacity_policy == EvidenceStoreCapacityPolicyV1::Block
            && (self.retained_bytes > self.limits.maximum_retained_bytes
                || self.retained_records > self.limits.maximum_retained_records)
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence store exceeds its configured retention capacity".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn append_capacity(
        &self,
        identity: &crate::EvidenceIntakeIdentityV1,
        stream: EvidenceSegmentStreamV1,
        first: u64,
        first_frame_bytes: usize,
    ) -> Result<usize> {
        let active_capacity = self
            .active
            .get(&stream)
            .and_then(|id| self.segments.get(id))
            .filter(|state| state.descriptor.kind.last().checked_add(1) == Some(first))
            .and_then(|state| {
                MAX_SEGMENT_BYTES
                    .checked_sub(state.descriptor.reference.offset)
                    .and_then(|capacity| usize::try_from(capacity).ok())
            })
            .filter(|capacity| *capacity >= first_frame_bytes);
        if let Some(capacity) = active_capacity {
            return Ok(capacity);
        }
        let identity_bytes = EvidenceSegmentStateV1::encode_identity(identity)?.len();
        let capacity = crate::MAX_EVIDENCE_SEGMENT_BYTES
            .checked_sub(identity_bytes)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment identity exceeds its size bound".to_owned(),
                }
                .build()
            })?;
        if first_frame_bytes > capacity {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "one evidence record exceeds the segment size bound".to_owned(),
            }
            .fail();
        }
        Ok(capacity)
    }

    fn append_without_sync(
        &mut self,
        identity: &crate::EvidenceIntakeIdentityV1,
        stream: EvidenceSegmentStreamV1,
        first: u64,
        last: u64,
        frames: EncodedEvidenceFramesV1,
    ) -> Result<EvidenceSegmentRefV1> {
        let count = last
            .checked_sub(first)
            .and_then(|count| count.checked_add(1));
        if frames.frames.is_empty() || count != Some(frames.frames.len() as u64) {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence append range is invalid".to_owned(),
            }
            .fail();
        }
        if self
            .identities
            .get(&stream.stream_id)
            .is_some_and(|existing| existing != identity)
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence append crossed a stream identity".to_owned(),
            }
            .fail();
        }
        let frame_bytes = frames.bytes.len() as u64;
        let identity_bytes = EvidenceSegmentStateV1::encode_identity(identity)?;
        let new_segment_bytes = frame_bytes
            .checked_add(identity_bytes.len() as u64)
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment size is exhausted".to_owned(),
                }
                .build()
            })?;
        if new_segment_bytes > MAX_SEGMENT_BYTES {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "one evidence append exceeds 16 MiB".to_owned(),
            }
            .fail();
        }
        let added_records = if stream.kind == EvidenceSegmentStreamKindV1::Records {
            frames.frames.len() as u64
        } else {
            0
        };
        let active_id = self.active.get(&stream).copied();
        let active_fits = active_id
            .and_then(|id| self.segments.get(&id))
            .is_some_and(|state| {
                state.descriptor.kind.last().checked_add(1) == Some(first)
                    && state
                        .descriptor
                        .reference
                        .offset
                        .checked_add(frame_bytes)
                        .is_some_and(|bytes| bytes <= MAX_SEGMENT_BYTES)
            });
        let appended_bytes = if active_fits {
            frame_bytes
        } else {
            new_segment_bytes
        };
        let next_bytes = self.retained_bytes.checked_add(appended_bytes);
        let next_records = self.retained_records.checked_add(added_records);
        if self.limits.capacity_policy == EvidenceStoreCapacityPolicyV1::Block
            && (next_bytes.is_none_or(|bytes| bytes > self.limits.maximum_retained_bytes)
                || next_records
                    .is_none_or(|records| records > self.limits.maximum_retained_records))
        {
            return ControlStoreSnafu {
                path: self.root.clone(),
                reason: "the evidence store retention capacity is exhausted".to_owned(),
            }
            .fail();
        }
        if !active_fits {
            if let Some(id) = active_id {
                let state = self.segments.get_mut(&id).ok_or_else(|| {
                    ControlStoreSnafu {
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
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the evidence segment sequence is exhausted".to_owned(),
                }
                .build()
            })?;
            id
        };
        if active_fits {
            let state = self.segments.get_mut(&id).ok_or_else(|| {
                ControlStoreSnafu {
                    path: self.root.clone(),
                    reason: "the selected evidence segment is missing".to_owned(),
                }
                .build()
            })?;
            let start = state.descriptor.reference.offset as usize;
            let mut file = OpenOptions::new()
                .append(true)
                .open(&state.path)
                .context(IoSnafu { path: &state.path })?;
            file.write_all(&frames.bytes)
                .context(IoSnafu { path: &state.path })?;
            Self::extend_frames(&mut state.frames, start, &frames.frames);
            state.descriptor.kind = state.descriptor.kind.with_last(last);
            state.descriptor.reference.offset += frame_bytes;
        } else {
            let path = EvidenceSegmentStateV1::active_path(&self.root, id, stream, first);
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .context(IoSnafu { path: &path })?;
            file.write_all(&identity_bytes)
                .context(IoSnafu { path: &path })?;
            file.write_all(&frames.bytes)
                .context(IoSnafu { path: &path })?;
            let kind = match stream.kind {
                EvidenceSegmentStreamKindV1::Records => EvidenceSegmentKindV1::Records {
                    stream_id: stream.stream_id,
                    first_cursor: first,
                    last_cursor: last,
                },
                EvidenceSegmentStreamKindV1::Coverage => EvidenceSegmentKindV1::Coverage {
                    stream_id: stream.stream_id,
                    first_revision: first,
                    last_revision: last,
                },
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
                        kind,
                    },
                    identity: identity.clone(),
                    path,
                    frames: indexes,
                    active: true,
                },
            );
            self.active.insert(stream, id);
            self.identities
                .entry(stream.stream_id)
                .or_insert_with(|| identity.clone());
        }
        self.retained_bytes = next_bytes.unwrap_or(u64::MAX);
        self.retained_records = next_records.unwrap_or(u64::MAX);
        self.segments
            .get(&id)
            .map(|state| state.descriptor.reference)
            .ok_or_else(|| {
                ControlStoreSnafu {
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

    fn read_payloads(
        &self,
        reference: EvidenceSegmentRefV1,
        expected: EvidenceSegmentKindV1,
    ) -> Result<Vec<Vec<u8>>> {
        let state = self.segments.get(&reference.id).ok_or_else(|| {
            ControlStoreSnafu {
                path: self.root.clone(),
                reason: format!("evidence segment {} is missing", reference.id),
            }
            .build()
        })?;
        let actual = state.descriptor.kind;
        if actual.stream() != expected.stream()
            || expected.first() < actual.first()
            || expected.last() > actual.last()
        {
            return ControlStoreSnafu {
                path: state.path.clone(),
                reason: "evidence segment metadata does not contain its index range".to_owned(),
            }
            .fail();
        }
        let first_index = usize::try_from(expected.first() - actual.first()).map_err(|error| {
            ControlStoreSnafu {
                path: state.path.clone(),
                reason: format!("the evidence segment start is invalid: {error}"),
            }
            .build()
        })?;
        let count = usize::try_from(expected.last() - expected.first() + 1).map_err(|error| {
            ControlStoreSnafu {
                path: state.path.clone(),
                reason: format!("the evidence segment range is invalid: {error}"),
            }
            .build()
        })?;
        let selected = state
            .frames
            .get(first_index..first_index.saturating_add(count))
            .ok_or_else(|| {
                ControlStoreSnafu {
                    path: state.path.clone(),
                    reason: "the evidence segment index exceeds its record frames".to_owned(),
                }
                .build()
            })?;
        let expected_offset = selected.last().map_or(0, |frame| frame.end as u64);
        if reference.offset != expected_offset {
            return ControlStoreSnafu {
                path: state.path.clone(),
                reason: "the evidence segment committed offset is invalid".to_owned(),
            }
            .fail();
        }
        let bytes = fs::read(&state.path).context(IoSnafu { path: &state.path })?;
        Ok(selected
            .iter()
            .map(|frame| bytes[frame.payload_start..frame.payload_end].to_vec())
            .collect())
    }

    fn encode_frames<M: Message>(
        messages: &[M],
        maximum_payload_bytes: usize,
    ) -> Result<EncodedEvidenceFramesV1> {
        let capacity = messages.iter().try_fold(0_usize, |total, message| {
            let payload_bytes = message.encoded_len();
            if payload_bytes == 0 || payload_bytes > maximum_payload_bytes {
                return ControlStoreSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: "the evidence record is outside its size bound".to_owned(),
                }
                .fail();
            }
            total
                .checked_add(payload_bytes)
                .and_then(|bytes| bytes.checked_add(FRAME_OVERHEAD_BYTES))
                .ok_or_else(|| {
                    ControlStoreSnafu {
                        path: PathBuf::from("<evidence-record>"),
                        reason: "the evidence record length is not representable".to_owned(),
                    }
                    .build()
                })
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut frames = Vec::with_capacity(messages.len());
        for message in messages {
            let start = bytes.len();
            let payload_bytes = message.encoded_len();
            let length = u32::try_from(payload_bytes).map_err(|error| {
                ControlStoreSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: format!("the evidence record length is not representable: {error}"),
                }
                .build()
            })?;
            bytes.extend_from_slice(&length.to_be_bytes());
            message.encode(&mut bytes).map_err(|error| {
                ControlStoreSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: format!("the evidence record encoding failed: {error}"),
                }
                .build()
            })?;
            let payload_end = bytes.len();
            let checksum = crc32c::crc32c(&bytes[start..payload_end]);
            bytes.extend_from_slice(&checksum.to_be_bytes());
            frames.push(EvidenceFrameIndexV1 {
                payload_start: start + 4,
                payload_end,
                end: bytes.len(),
            });
        }
        Ok(EncodedEvidenceFramesV1 {
            bytes: bytes.into(),
            frames,
        })
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

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use tempfile::TempDir;

    use super::{EvidenceSegmentKindV1, EvidenceStoreCapacityPolicyV1, EvidenceStoreLimitsV1};

    fn record(value: u64) -> crate::EvidenceRecord {
        crate::EvidenceRecord {
            observed_boottime_ns: value,
            task_cookie: value,
            coverage_interval_id: vec![3; 16].into(),
            reason: 1,
            decision: 1,
            effect_family: 1,
            operation: 1,
            configured_errno: -13,
            kernel_result: -13,
            temporal_coverage: crate::EvidenceTemporalCoverage::Complete as i32,
            ..crate::EvidenceRecord::default()
        }
    }

    fn identity() -> crate::EvidenceIntakeIdentityV1 {
        crate::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
    }

    #[test]
    fn records_append_to_one_segment_with_one_crc_frame_each(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let mut owner =
            super::EvidenceSegmentOwner::open(directory.path(), EvidenceStoreLimitsV1::default())?;
        let first = crate::EvidenceRecords {
            records: vec![record(1), record(2)],
        };
        let second = crate::EvidenceRecords {
            records: vec![record(3)],
        };

        let first_reference = owner.write_records(&identity(), 1, 1, 2, &first)?;
        let second_reference = owner.write_records(&identity(), 1, 3, 3, &second)?;

        assert_eq!(first_reference.id, second_reference.id);
        assert!(second_reference.offset > first_reference.offset);
        assert_eq!(owner.descriptors().count(), 1);
        assert_eq!(
            owner.read_records(
                first_reference,
                EvidenceSegmentKindV1::Records {
                    stream_id: 1,
                    first_cursor: 1,
                    last_cursor: 2,
                },
            )?,
            first
        );
        assert_eq!(
            owner.read_records(
                second_reference,
                EvidenceSegmentKindV1::Records {
                    stream_id: 1,
                    first_cursor: 3,
                    last_cursor: 3,
                },
            )?,
            second
        );
        Ok(())
    }

    #[test]
    fn one_commit_group_spans_segments_and_restart_recovers_each_range(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let records = (1..=150)
            .map(|cursor| crate::EvidenceRecord {
                process_lineage_id: vec![7; 120 * 1_024].into(),
                ..record(cursor)
            })
            .collect::<Vec<_>>();
        let input = crate::EvidenceBatchInputV1::encode(1, records)?;
        let batches = {
            let mut owner = super::EvidenceSegmentOwner::open(
                directory.path(),
                EvidenceStoreLimitsV1::default(),
            )?;
            let batches = owner.write_frames(
                &identity(),
                1,
                input.first_cursor,
                input.last_cursor,
                input.framed_records,
                input.frame_ends,
            )?;
            assert_eq!(batches.len(), 2);
            assert!(owner
                .segments
                .values()
                .all(|segment| segment.descriptor.reference.offset <= super::MAX_SEGMENT_BYTES));
            batches
        };

        let owner =
            super::EvidenceSegmentOwner::open(directory.path(), EvidenceStoreLimitsV1::default())?;
        assert_eq!(owner.descriptors().count(), 2);
        let recovered_records = batches.iter().try_fold(0_usize, |count, batch| {
            owner
                .read_records(
                    batch.segment,
                    EvidenceSegmentKindV1::Records {
                        stream_id: 1,
                        first_cursor: batch.first_cursor,
                        last_cursor: batch.last_cursor,
                    },
                )
                .map(|records| count + records.records.len())
        })?;
        assert_eq!(recovered_records, 150);
        Ok(())
    }

    #[test]
    fn restart_appends_without_changing_the_active_segment_prefix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        {
            let mut owner = super::EvidenceSegmentOwner::open(
                directory.path(),
                EvidenceStoreLimitsV1::default(),
            )?;
            owner.write_records(
                &identity(),
                1,
                1,
                1,
                &crate::EvidenceRecords {
                    records: vec![record(1)],
                },
            )?;
        }
        let path = std::fs::read_dir(directory.path().join("evidence/segments-v2"))?
            .next()
            .ok_or("missing active segment")??
            .path();
        let retained_prefix = std::fs::read(&path)?;

        let mut owner =
            super::EvidenceSegmentOwner::open(directory.path(), EvidenceStoreLimitsV1::default())?;
        owner.write_records(
            &identity(),
            1,
            2,
            2,
            &crate::EvidenceRecords {
                records: vec![record(2)],
            },
        )?;

        let current = std::fs::read(path)?;
        assert!(current.starts_with(&retained_prefix));
        assert!(current.len() > retained_prefix.len());
        Ok(())
    }

    #[test]
    fn restart_truncates_only_an_incomplete_active_tail() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let reference = {
            let mut owner = super::EvidenceSegmentOwner::open(
                directory.path(),
                EvidenceStoreLimitsV1::default(),
            )?;
            owner.write_records(
                &identity(),
                1,
                1,
                1,
                &crate::EvidenceRecords {
                    records: vec![record(1)],
                },
            )?
        };
        let root = directory.path().join("evidence/segments-v2");
        let path = std::fs::read_dir(&root)?
            .next()
            .ok_or("missing segment")??
            .path();
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(&[0, 0, 0])?;
        file.sync_all()?;

        let owner =
            super::EvidenceSegmentOwner::open(directory.path(), EvidenceStoreLimitsV1::default())?;
        assert_eq!(std::fs::metadata(path)?.len(), reference.offset);
        assert_eq!(owner.descriptors().count(), 1);
        Ok(())
    }

    #[test]
    fn restart_rejects_a_complete_frame_with_an_invalid_crc32c(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let reference = {
            let mut owner = super::EvidenceSegmentOwner::open(
                directory.path(),
                EvidenceStoreLimitsV1::default(),
            )?;
            owner.write_records(
                &identity(),
                1,
                1,
                1,
                &crate::EvidenceRecords {
                    records: vec![record(1)],
                },
            )?
        };
        let path = std::fs::read_dir(directory.path().join("evidence/segments-v2"))?
            .next()
            .ok_or("missing segment")??
            .path();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        file.seek(std::io::SeekFrom::Start(reference.offset - 5))?;
        file.write_all(&[0xff])?;
        file.sync_all()?;

        let error = match super::EvidenceSegmentOwner::open(
            directory.path(),
            EvidenceStoreLimitsV1::default(),
        ) {
            Ok(_) => return Err("corrupt segment was accepted".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("record checksum is invalid"));
        Ok(())
    }

    #[test]
    fn restart_rejects_an_incomplete_sealed_tail() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        {
            let mut owner = super::EvidenceSegmentOwner::open(
                directory.path(),
                EvidenceStoreLimitsV1::default(),
            )?;
            owner.write_records(
                &identity(),
                1,
                1,
                1,
                &crate::EvidenceRecords {
                    records: vec![record(1)],
                },
            )?;
            owner.write_records(
                &identity(),
                1,
                3,
                3,
                &crate::EvidenceRecords {
                    records: vec![record(3)],
                },
            )?;
        }
        let root = directory.path().join("evidence/segments-v2");
        let path = std::fs::read_dir(&root)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| path.extension().is_some_and(|extension| extension == "seg"))
            .ok_or("missing sealed segment")?;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(&[0, 0, 0])?;
        file.sync_all()?;

        let error = match super::EvidenceSegmentOwner::open(
            directory.path(),
            EvidenceStoreLimitsV1::default(),
        ) {
            Ok(_) => return Err("incomplete sealed segment was accepted".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("incomplete record tail"));
        Ok(())
    }

    #[test]
    fn block_rejects_and_retain_exceeds_the_soft_record_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let limits = EvidenceStoreLimitsV1 {
            maximum_retained_bytes: super::MAX_SEGMENT_BYTES,
            maximum_retained_records: 1,
            capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
        };
        let mut owner = super::EvidenceSegmentOwner::open(directory.path(), limits)?;
        owner.write_records(
            &identity(),
            1,
            1,
            1,
            &crate::EvidenceRecords {
                records: vec![record(1)],
            },
        )?;
        assert!(owner
            .write_records(
                &identity(),
                1,
                2,
                2,
                &crate::EvidenceRecords {
                    records: vec![record(2)],
                },
            )
            .is_err());

        let retained = TempDir::new()?;
        let mut owner = super::EvidenceSegmentOwner::open(
            retained.path(),
            EvidenceStoreLimitsV1 {
                capacity_policy: EvidenceStoreCapacityPolicyV1::Retain,
                ..limits
            },
        )?;
        owner.write_records(
            &identity(),
            1,
            1,
            2,
            &crate::EvidenceRecords {
                records: vec![record(1), record(2)],
            },
        )?;
        assert_eq!(owner.descriptors().count(), 1);
        Ok(())
    }
}
