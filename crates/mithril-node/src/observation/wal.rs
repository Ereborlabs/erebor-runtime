use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::persistence::{atomic_write, sync_directory};
use super::ObservationEnvelopeV1;
use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::Result;

const ACK_FILE: &str = "acknowledged.bin";
const ACK_BYTES: usize = 12;
const SEGMENT_HEADER_BYTES: usize = 64;
const SEGMENT_MAX_BYTES: u64 = 16 * 1_024 * 1_024;
const RECORD_OVERHEAD_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceWalCapacityPolicyV1 {
    #[default]
    Block,
    Retain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceWalLimits {
    pub maximum_record_bytes: u64,
    pub maximum_retained_bytes: u64,
    pub maximum_retained_records: usize,
    pub maximum_batch_records: usize,
    pub capacity_policy: EvidenceWalCapacityPolicyV1,
}

impl EvidenceWalLimits {
    pub fn validate(self) -> Result<()> {
        if self.maximum_record_bytes == 0
            || self.maximum_record_bytes > mithril_control::MAX_EVIDENCE_RECORD_BYTES as u64
            || self.maximum_retained_bytes < self.maximum_record_bytes
            || self.maximum_retained_records == 0
            || self.maximum_batch_records == 0
            || self.maximum_batch_records > mithril_control::MAX_EVIDENCE_BATCH_RECORDS
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL bounds are zero or inconsistent".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl Default for EvidenceWalLimits {
    fn default() -> Self {
        Self {
            maximum_record_bytes: mithril_control::MAX_EVIDENCE_RECORD_BYTES as u64,
            maximum_retained_bytes: 256 * 1_024 * 1_024,
            maximum_retained_records: 100_000,
            maximum_batch_records: mithril_control::DEFAULT_EVIDENCE_BATCH_RECORDS,
            capacity_policy: EvidenceWalCapacityPolicyV1::Block,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceRecordV1 {
    pub cursor: u64,
    frame: Vec<u8>,
}

impl EvidenceRecordV1 {
    fn new(cursor: u64, observation: &ObservationEnvelopeV1) -> Result<Self> {
        Ok(Self {
            cursor,
            frame: EvidenceWalCodecV1::encode_record(&observation.to_wire_record()?)?,
        })
    }

    pub fn decode(&self) -> Result<mithril_control::EvidenceRecord> {
        EvidenceWalCodecV1::decode_record_payload(&self.frame, self.cursor)
    }

    fn validate(&self, expected_cursor: u64, identity: EvidenceWalStreamIdentityV1) -> Result<()> {
        if self.cursor != expected_cursor {
            return EvidenceStateSnafu {
                reason: format!("evidence WAL record {expected_cursor} is out of order"),
            }
            .fail();
        }
        let record = self.decode()?;
        let observation = ObservationEnvelopeV1::from_wire_record(
            identity.tenant_id.into(),
            identity.node_boot_id.into(),
            identity.source_id.into(),
            identity.source_epoch,
            self.cursor,
            identity.cpu_id,
            &record,
        )?;
        observation.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceWalStreamIdentityV1 {
    tenant_id: [u8; 16],
    node_boot_id: [u8; 16],
    source_id: [u8; 16],
    source_epoch: u64,
    cpu_id: u32,
}

impl EvidenceWalStreamIdentityV1 {
    fn from_observation(observation: &ObservationEnvelopeV1) -> Result<Self> {
        let identity = Self {
            tenant_id: observation.tenant_id.to_be_bytes(),
            node_boot_id: observation.node_boot_id.to_be_bytes(),
            source_id: observation.source_id.to_be_bytes(),
            source_epoch: observation.source_epoch,
            cpu_id: observation.cpu_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(self) -> Result<()> {
        if self.tenant_id == [0; 16]
            || self.node_boot_id == [0; 16]
            || self.source_id == [0; 16]
            || self.source_epoch == 0
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL stream identity is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }

    fn directory_name(self) -> String {
        format!(
            "{}-{:020}-{}-{:010}",
            hex::encode(self.source_id),
            self.source_epoch,
            hex::encode(self.node_boot_id),
            self.cpu_id,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    framed_records: Vec<u8>,
    stream_identity: EvidenceWalStreamIdentityV1,
}

impl EvidenceBatchV1 {
    #[must_use]
    pub fn record_count(&self) -> usize {
        usize::try_from(self.last_cursor - self.first_cursor + 1).unwrap_or(usize::MAX)
    }

    pub fn decode_records(&self) -> Result<Vec<mithril_control::EvidenceRecord>> {
        let mut offset = 0_usize;
        let mut records = Vec::with_capacity(self.record_count());
        while offset < self.framed_records.len() {
            let payload_bytes = u32::from_be_bytes(
                self.framed_records[offset..offset + 4]
                    .try_into()
                    .unwrap_or_default(),
            ) as usize;
            let end = offset + payload_bytes + RECORD_OVERHEAD_BYTES;
            records.push(EvidenceWalCodecV1::decode_record_payload(
                &self.framed_records[offset..end],
                self.first_cursor + records.len() as u64,
            )?);
            offset = end;
        }
        Ok(records)
    }
}

impl From<EvidenceBatchV1> for mithril_control::EvidenceBatch {
    fn from(batch: EvidenceBatchV1) -> Self {
        Self {
            node_boot_id: batch.stream_identity.node_boot_id.to_vec(),
            source_id: batch.stream_identity.source_id.to_vec(),
            source_epoch: batch.stream_identity.source_epoch,
            cpu_id: batch.stream_identity.cpu_id,
            first_cursor: batch.first_cursor,
            framed_records: batch.framed_records.into(),
            commit_group_tail: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceAckV1 {
    pub contiguous_cursor: u64,
}

impl TryFrom<mithril_control::EvidenceAck> for EvidenceAckV1 {
    type Error = crate::Error;

    fn try_from(ack: mithril_control::EvidenceAck) -> Result<Self> {
        if ack.contiguous_cursor == 0 {
            return EvidenceStateSnafu {
                reason: "Control returned a zero evidence cursor".to_owned(),
            }
            .fail();
        }
        Ok(Self {
            contiguous_cursor: ack.contiguous_cursor,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AckStateV1 {
    contiguous_cursor: u64,
}

struct EvidenceWalCodecV1;

impl EvidenceWalCodecV1 {
    fn encode_segment_header(identity: EvidenceWalStreamIdentityV1) -> [u8; SEGMENT_HEADER_BYTES] {
        let mut bytes = [0_u8; SEGMENT_HEADER_BYTES];
        bytes[..16].copy_from_slice(&identity.tenant_id);
        bytes[16..32].copy_from_slice(&identity.node_boot_id);
        bytes[32..48].copy_from_slice(&identity.source_id);
        bytes[48..56].copy_from_slice(&identity.source_epoch.to_be_bytes());
        bytes[56..60].copy_from_slice(&identity.cpu_id.to_be_bytes());
        let checksum = crc32c::crc32c(&bytes[..60]);
        bytes[60..].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    fn decode_segment_header(bytes: &[u8], name: &str) -> Result<EvidenceWalStreamIdentityV1> {
        if bytes.len() < SEGMENT_HEADER_BYTES {
            return EvidenceStateSnafu {
                reason: format!("{name} has a truncated stream identity"),
            }
            .fail();
        }
        let expected = u32::from_be_bytes(bytes[60..64].try_into().unwrap_or_default());
        if crc32c::crc32c(&bytes[..60]) != expected {
            return EvidenceStateSnafu {
                reason: format!("{name} stream identity checksum does not match"),
            }
            .fail();
        }
        let identity = EvidenceWalStreamIdentityV1 {
            tenant_id: bytes[..16].try_into().unwrap_or_default(),
            node_boot_id: bytes[16..32].try_into().unwrap_or_default(),
            source_id: bytes[32..48].try_into().unwrap_or_default(),
            source_epoch: u64::from_be_bytes(bytes[48..56].try_into().unwrap_or_default()),
            cpu_id: u32::from_be_bytes(bytes[56..60].try_into().unwrap_or_default()),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn encode_record(record: &mithril_control::EvidenceRecord) -> Result<Vec<u8>> {
        let payload = record.encode_to_vec();
        let length = u32::try_from(payload.len()).map_err(|_| {
            EvidenceStateSnafu {
                reason: "evidence WAL record size is not representable".to_owned(),
            }
            .build()
        })?;
        let mut frame = Vec::with_capacity(payload.len().saturating_add(RECORD_OVERHEAD_BYTES));
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        let checksum = crc32c::crc32c(&frame);
        frame.extend_from_slice(&checksum.to_be_bytes());
        Ok(frame)
    }

    fn decode_record_payload(frame: &[u8], cursor: u64) -> Result<mithril_control::EvidenceRecord> {
        let payload_end = frame.len().checked_sub(4).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL record frame is truncated".to_owned(),
            }
            .build()
        })?;
        let expected = u32::from_be_bytes(frame[payload_end..].try_into().unwrap_or_default());
        if crc32c::crc32c(&frame[..payload_end]) != expected {
            return EvidenceStateSnafu {
                reason: format!("evidence WAL record {cursor} checksum does not match"),
            }
            .fail();
        }
        mithril_control::EvidenceRecord::decode(&frame[4..payload_end]).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("evidence WAL record {cursor} protobuf is invalid: {error}"),
            }
            .build()
        })
    }

    fn decode_record(frame: &[u8], cursor: u64) -> Result<EvidenceRecordV1> {
        Self::decode_record_payload(frame, cursor)?;
        Ok(EvidenceRecordV1 {
            cursor,
            frame: frame.to_vec(),
        })
    }

    fn encode_ack(state: AckStateV1) -> [u8; ACK_BYTES] {
        let mut bytes = [0_u8; ACK_BYTES];
        bytes[..8].copy_from_slice(&state.contiguous_cursor.to_be_bytes());
        let checksum = crc32c::crc32c(&bytes[..8]);
        bytes[8..].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    fn decode_ack(bytes: &[u8]) -> Result<AckStateV1> {
        if bytes.len() != ACK_BYTES {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement state has an invalid size".to_owned(),
            }
            .fail();
        }
        let expected = u32::from_be_bytes(bytes[8..].try_into().unwrap_or_default());
        if crc32c::crc32c(&bytes[..8]) != expected {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement state checksum does not match".to_owned(),
            }
            .fail();
        }
        Ok(AckStateV1 {
            contiguous_cursor: u64::from_be_bytes(bytes[..8].try_into().unwrap_or_default()),
        })
    }
}

#[derive(Debug)]
struct EvidenceWalSegment {
    path: PathBuf,
    first_cursor: u64,
    last_cursor: Option<u64>,
    record_count: usize,
    bytes: u64,
    active: bool,
}

impl EvidenceWalSegment {
    fn active_path(root: &Path, first_cursor: u64) -> PathBuf {
        root.join(format!("{first_cursor:020}.open"))
    }

    fn sealed_path(root: &Path, first_cursor: u64, last_cursor: u64) -> PathBuf {
        root.join(format!("{first_cursor:020}-{last_cursor:020}.seg"))
    }

    fn parse_name(path: &Path) -> Result<(u64, Option<u64>)> {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        if extension == "open" {
            return Ok((Self::parse_cursor(stem, path)?, None));
        }
        if extension == "seg" {
            let Some((first, last)) = stem.split_once('-') else {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL segment `{}` has an invalid name",
                        path.display()
                    ),
                }
                .fail();
            };
            return Ok((
                Self::parse_cursor(first, path)?,
                Some(Self::parse_cursor(last, path)?),
            ));
        }
        EvidenceStateSnafu {
            reason: format!("evidence WAL entry `{}` is not a segment", path.display()),
        }
        .fail()
    }

    fn parse_cursor(value: &str, path: &Path) -> Result<u64> {
        if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return EvidenceStateSnafu {
                reason: format!(
                    "evidence WAL segment `{}` has an invalid cursor",
                    path.display()
                ),
            }
            .fail();
        }
        value.parse::<u64>().map_err(|error| {
            EvidenceStateSnafu {
                reason: format!(
                    "evidence WAL segment `{}` has an invalid cursor: {error}",
                    path.display()
                ),
            }
            .build()
        })
    }

    fn read(
        path: PathBuf,
        first_cursor: u64,
        sealed_last_cursor: Option<u64>,
        limits: EvidenceWalLimits,
    ) -> Result<(Self, EvidenceWalStreamIdentityV1, Vec<EvidenceRecordV1>)> {
        let mut bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        if bytes.len() as u64 > SEGMENT_MAX_BYTES {
            return EvidenceStateSnafu {
                reason: format!("evidence WAL segment `{}` exceeds 16 MiB", path.display()),
            }
            .fail();
        }
        let name = format!("evidence WAL segment `{}`", path.display());
        let identity = EvidenceWalCodecV1::decode_segment_header(&bytes, &name)?;
        let active = sealed_last_cursor.is_none();
        let mut offset = SEGMENT_HEADER_BYTES;
        let mut records = Vec::new();
        let mut truncated = false;
        while offset < bytes.len() {
            let frame_start = offset;
            let remaining = bytes.len() - offset;
            if remaining < 4 {
                if active {
                    truncated = true;
                    break;
                }
                return EvidenceStateSnafu {
                    reason: format!("{name} has an incomplete record length"),
                }
                .fail();
            }
            let payload_bytes =
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap_or_default())
                    as usize;
            if payload_bytes == 0 || payload_bytes as u64 > limits.maximum_record_bytes {
                return EvidenceStateSnafu {
                    reason: format!("{name} contains a record outside its size bound"),
                }
                .fail();
            }
            let frame_bytes = payload_bytes
                .checked_add(RECORD_OVERHEAD_BYTES)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: format!("{name} record size overflowed"),
                    }
                    .build()
                })?;
            let frame_end = frame_start.checked_add(frame_bytes).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: format!("{name} record end overflowed"),
                }
                .build()
            })?;
            if frame_end > bytes.len() {
                if active {
                    truncated = true;
                    break;
                }
                return EvidenceStateSnafu {
                    reason: format!("{name} has an incomplete record payload"),
                }
                .fail();
            }
            let cursor = first_cursor
                .checked_add(records.len() as u64)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: format!("{name} cursor is exhausted"),
                    }
                    .build()
                })?;
            let record = EvidenceWalCodecV1::decode_record(&bytes[frame_start..frame_end], cursor)?;
            record.validate(cursor, identity)?;
            records.push(record);
            offset = frame_end;
        }
        if truncated {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .context(IoSnafu { path: &path })?;
            file.set_len(offset as u64)
                .context(IoSnafu { path: &path })?;
            file.sync_all().context(IoSnafu { path: &path })?;
            bytes.truncate(offset);
        }
        let last_cursor = records
            .len()
            .checked_sub(1)
            .map(|index| first_cursor.saturating_add(index as u64));
        if let Some(expected_last) = sealed_last_cursor {
            if last_cursor != Some(expected_last) {
                return EvidenceStateSnafu {
                    reason: format!("{name} cursor range does not match its name"),
                }
                .fail();
            }
        }
        Ok((
            Self {
                path,
                first_cursor,
                last_cursor,
                record_count: records.len(),
                bytes: bytes.len() as u64,
                active,
            },
            identity,
            records,
        ))
    }

    fn create_empty(
        root: &Path,
        identity: EvidenceWalStreamIdentityV1,
        first_cursor: u64,
    ) -> Result<Self> {
        let path = Self::active_path(root, first_cursor);
        if path.exists() {
            return EvidenceStateSnafu {
                reason: format!("evidence WAL segment `{}` already exists", path.display()),
            }
            .fail();
        }
        atomic_write(&path, &EvidenceWalCodecV1::encode_segment_header(identity))?;
        Ok(Self {
            path,
            first_cursor,
            last_cursor: None,
            record_count: 0,
            bytes: SEGMENT_HEADER_BYTES as u64,
            active: true,
        })
    }

    fn seal(&mut self, root: &Path) -> Result<()> {
        let last_cursor = self.last_cursor.ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "an empty evidence WAL segment cannot be sealed".to_owned(),
            }
            .build()
        })?;
        let sealed = Self::sealed_path(root, self.first_cursor, last_cursor);
        fs::rename(&self.path, &sealed).context(IoSnafu { path: &sealed })?;
        sync_directory(root)?;
        self.path = sealed;
        self.active = false;
        Ok(())
    }

    fn append(&mut self, frame: &[u8], cursor: u64) -> Result<()> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .context(IoSnafu { path: &self.path })?;
        file.write_all(frame)
            .context(IoSnafu { path: &self.path })?;
        file.sync_all().context(IoSnafu { path: &self.path })?;
        self.last_cursor = Some(cursor);
        self.record_count = self.record_count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(frame.len() as u64);
        Ok(())
    }
}

pub struct EvidenceWal {
    root: PathBuf,
    limits: EvidenceWalLimits,
    stream_identity: Option<EvidenceWalStreamIdentityV1>,
    records: Vec<EvidenceRecordV1>,
    segments: Vec<EvidenceWalSegment>,
    retained_bytes: u64,
    retained_records: usize,
    acknowledged: AckStateV1,
}

pub(super) struct EvidenceWalAppendFailure {
    pub error: Box<crate::Error>,
    pub capacity: bool,
}

impl From<crate::Error> for EvidenceWalAppendFailure {
    fn from(error: crate::Error) -> Self {
        Self {
            error: Box::new(error),
            capacity: false,
        }
    }
}

pub(super) struct EvidenceWalOwner {
    root: PathBuf,
    limits: EvidenceWalLimits,
    streams: BTreeMap<EvidenceWalStreamIdentityV1, EvidenceWal>,
    in_flight: Option<(EvidenceWalStreamIdentityV1, Vec<EvidenceBatchV1>)>,
    last_acknowledged_stream: Option<EvidenceWalStreamIdentityV1>,
}

impl EvidenceWalOwner {
    pub(super) fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        limits.validate()?;
        let root = root.into();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let mut streams = BTreeMap::new();
        for entry in fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: &root })?
        {
            let path = entry.path();
            if !path.is_dir() {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL entry `{}` is not a stream directory",
                        path.display()
                    ),
                }
                .fail();
            }
            let wal = EvidenceWal::open(&path, limits)?;
            let identity = wal.stream_identity.ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL stream `{}` has no durable identity",
                        path.display()
                    ),
                }
                .build()
            })?;
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                != identity.directory_name()
            {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL stream `{}` has an invalid identity name",
                        path.display()
                    ),
                }
                .fail();
            }
            if streams.insert(identity, wal).is_some() {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL stream `{}` has more than one directory",
                        identity.directory_name()
                    ),
                }
                .fail();
            }
        }
        let owner = Self {
            root,
            limits,
            streams,
            in_flight: None,
            last_acknowledged_stream: None,
        };
        owner.validate_retention()?;
        Ok(owner)
    }

    pub(super) fn append_classified(
        &mut self,
        observation: &ObservationEnvelopeV1,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        let identity = EvidenceWalStreamIdentityV1::from_observation(observation)
            .map_err(EvidenceWalAppendFailure::from)?;
        if !self.streams.contains_key(&identity) {
            let path = self.root.join(identity.directory_name());
            let wal =
                EvidenceWal::open(path, self.limits).map_err(EvidenceWalAppendFailure::from)?;
            self.streams.insert(identity, wal);
        }
        let (retained_records, retained_bytes) =
            self.retention().map_err(EvidenceWalAppendFailure::from)?;
        let wal = self.streams.get_mut(&identity).ok_or_else(|| {
            EvidenceWalAppendFailure::from(
                EvidenceStateSnafu {
                    reason: "the evidence WAL stream is missing after identity selection"
                        .to_owned(),
                }
                .build(),
            )
        })?;
        if self.limits.capacity_policy == EvidenceWalCapacityPolicyV1::Block {
            wal.limits.maximum_retained_records = wal.retained_records
                + self
                    .limits
                    .maximum_retained_records
                    .saturating_sub(retained_records);
            wal.limits.maximum_retained_bytes = wal.retained_bytes
                + self
                    .limits
                    .maximum_retained_bytes
                    .saturating_sub(retained_bytes);
        } else {
            wal.limits.maximum_retained_records = usize::MAX;
            wal.limits.maximum_retained_bytes = u64::MAX;
        }
        let result = wal.append_classified(observation);
        wal.limits = self.limits;
        result
    }

    pub(super) fn next_batch(&mut self) -> Option<EvidenceBatchV1> {
        if let Some((_identity, batches)) = &self.in_flight {
            return batches.first().cloned();
        }
        let identity = self.next_identity()?;
        let batch = self.streams.get(&identity)?.next_batch()?;
        self.in_flight = Some((identity, vec![batch.clone()]));
        Some(batch)
    }

    pub(super) fn next_batches(&mut self) -> Vec<EvidenceBatchV1> {
        if let Some((_identity, batches)) = &self.in_flight {
            return batches.clone();
        }
        let Some(identity) = self.next_identity() else {
            return Vec::new();
        };
        let Some(wal) = self.streams.get(&identity) else {
            return Vec::new();
        };
        let batches = wal.next_batches();
        if !batches.is_empty() {
            self.in_flight = Some((identity, batches.clone()));
        }
        batches
    }

    pub(super) fn acknowledge(&mut self, ack: EvidenceAckV1) -> Result<bool> {
        let (identity, batches) = self.in_flight.as_ref().ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence acknowledgement has no in-flight source item".to_owned(),
            }
            .build()
        })?;
        let acknowledged_batches = batches
            .iter()
            .position(|batch| batch.last_cursor == ack.contiguous_cursor)
            .and_then(|position| position.checked_add(1))
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence acknowledgement is not an in-flight batch boundary"
                        .to_owned(),
                }
                .build()
            })?;
        let identity = *identity;
        let wal = self.streams.get_mut(&identity).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence acknowledgement source is not retained".to_owned(),
            }
            .build()
        })?;
        wal.acknowledge(ack)?;
        let (_identity, batches) = self.in_flight.as_mut().unwrap_or_else(|| {
            unreachable!("the in-flight group was validated before acknowledgement")
        });
        batches.drain(..acknowledged_batches);
        if batches.is_empty() {
            self.in_flight = None;
            self.last_acknowledged_stream = Some(identity);
        }
        Ok(self.in_flight.is_none())
    }

    fn next_identity(&self) -> Option<EvidenceWalStreamIdentityV1> {
        self.streams
            .keys()
            .copied()
            .filter(|identity| {
                self.last_acknowledged_stream
                    .is_none_or(|last| identity > &last)
            })
            .chain(self.streams.keys().copied())
            .find(|identity| {
                self.streams
                    .get(identity)
                    .is_some_and(|wal| wal.next_batch().is_some())
            })
    }

    fn retention(&self) -> Result<(usize, u64)> {
        self.streams
            .values()
            .try_fold((0_usize, 0_u64), |(records, bytes), wal| {
                Ok((
                    records.checked_add(wal.retained_records).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL retained record count overflowed".to_owned(),
                        }
                        .build()
                    })?,
                    bytes.checked_add(wal.retained_bytes).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL retained byte count overflowed".to_owned(),
                        }
                        .build()
                    })?,
                ))
            })
    }

    pub(super) fn pending_records(&self) -> usize {
        self.streams.values().fold(0_usize, |total, wal| {
            total.saturating_add(wal.pending_records())
        })
    }

    fn validate_retention(&self) -> Result<()> {
        let (retained_records, retained_bytes) = self.retention()?;
        if self.limits.capacity_policy == EvidenceWalCapacityPolicyV1::Block
            && (retained_records > self.limits.maximum_retained_records
                || retained_bytes > self.limits.maximum_retained_bytes)
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL streams exceed their shared retention bounds".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl EvidenceWal {
    pub fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        let root = root.into();
        limits.validate()?;
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let acknowledged = Self::read_ack(&root)?;
        let paths = Self::recover_directory(&root)?;
        let mut decoded = Vec::with_capacity(paths.len());
        let mut stream_identity = None;
        for (path, first_cursor, last_cursor) in paths {
            let (segment, identity, records) =
                EvidenceWalSegment::read(path, first_cursor, last_cursor, limits)?;
            if stream_identity.is_some_and(|current| current != identity) {
                return EvidenceStateSnafu {
                    reason: "evidence WAL segments cross a stream identity boundary".to_owned(),
                }
                .fail();
            }
            stream_identity = Some(identity);
            decoded.push((segment, records));
        }
        Self::validate_segment_order(&decoded, acknowledged)?;
        if acknowledged.contiguous_cursor > 0 && stream_identity.is_none() {
            return EvidenceStateSnafu {
                reason: "acknowledged evidence WAL has no durable stream identity".to_owned(),
            }
            .fail();
        }

        let mut records = decoded
            .iter()
            .flat_map(|(_segment, records)| records.iter().cloned())
            .filter(|record| record.cursor > acknowledged.contiguous_cursor)
            .collect::<Vec<_>>();
        records.sort_unstable_by_key(|record| record.cursor);
        let mut segments = decoded
            .into_iter()
            .map(|(segment, _)| segment)
            .collect::<Vec<_>>();
        if let Some(identity) = stream_identity {
            let needs_active = segments.last().is_none_or(|segment| {
                !segment.active
                    || segment
                        .last_cursor
                        .is_some_and(|cursor| cursor <= acknowledged.contiguous_cursor)
            });
            if needs_active {
                let first_cursor = segments
                    .last()
                    .and_then(|segment| segment.last_cursor)
                    .unwrap_or(acknowledged.contiguous_cursor)
                    .max(acknowledged.contiguous_cursor)
                    .checked_add(1)
                    .ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL cursor is exhausted".to_owned(),
                        }
                        .build()
                    })?;
                segments.push(EvidenceWalSegment::create_empty(
                    &root,
                    identity,
                    first_cursor,
                )?);
            }
        }

        let mut changed = false;
        for segment in &segments {
            if segment
                .last_cursor
                .is_some_and(|cursor| cursor <= acknowledged.contiguous_cursor)
            {
                fs::remove_file(&segment.path).context(IoSnafu {
                    path: &segment.path,
                })?;
                changed = true;
            }
        }
        segments.retain(|segment| {
            !segment
                .last_cursor
                .is_some_and(|cursor| cursor <= acknowledged.contiguous_cursor)
        });
        if changed {
            sync_directory(&root)?;
        }

        let retained_bytes = segments.iter().try_fold(0_u64, |total, segment| {
            total.checked_add(segment.bytes).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained byte count overflowed".to_owned(),
                }
                .build()
            })
        })?;
        let retained_records = segments.iter().try_fold(0_usize, |total, segment| {
            total.checked_add(segment.record_count).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained record count overflowed".to_owned(),
                }
                .build()
            })
        })?;
        if limits.capacity_policy == EvidenceWalCapacityPolicyV1::Block
            && (retained_records > limits.maximum_retained_records
                || retained_bytes > limits.maximum_retained_bytes)
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL exceeds its configured retention bounds".to_owned(),
            }
            .fail();
        }
        Ok(Self {
            root,
            limits,
            stream_identity,
            records,
            segments,
            retained_bytes,
            retained_records,
            acknowledged,
        })
    }

    fn validate_segment_order(
        decoded: &[(EvidenceWalSegment, Vec<EvidenceRecordV1>)],
        acknowledged: AckStateV1,
    ) -> Result<()> {
        let mut expected_first = None;
        for (index, (segment, _records)) in decoded.iter().enumerate() {
            if expected_first.is_some_and(|expected| segment.first_cursor != expected) {
                return EvidenceStateSnafu {
                    reason: "evidence WAL segment ranges are not contiguous".to_owned(),
                }
                .fail();
            }
            if segment.active
                && index + 1 != decoded.len()
                && !segment
                    .last_cursor
                    .is_some_and(|cursor| cursor <= acknowledged.contiguous_cursor)
            {
                return EvidenceStateSnafu {
                    reason: "only the evidence WAL tail segment can be active".to_owned(),
                }
                .fail();
            }
            expected_first = match segment.last_cursor {
                Some(cursor) => Some(cursor.checked_add(1).ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL cursor is exhausted".to_owned(),
                    }
                    .build()
                })?),
                None if index + 1 == decoded.len() => Some(segment.first_cursor),
                None => {
                    return EvidenceStateSnafu {
                        reason: "an empty evidence WAL segment is not the tail".to_owned(),
                    }
                    .fail()
                }
            };
        }
        if let Some((first, _)) = decoded.first() {
            if first.first_cursor > acknowledged.contiguous_cursor.saturating_add(1) {
                return EvidenceStateSnafu {
                    reason: "evidence WAL starts after its acknowledged cursor".to_owned(),
                }
                .fail();
            }
        }
        Ok(())
    }

    fn recover_directory(root: &Path) -> Result<Vec<(PathBuf, u64, Option<u64>)>> {
        let mut paths = Vec::new();
        let mut changed = false;
        for entry in fs::read_dir(root)
            .context(IoSnafu { path: root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: root })?
        {
            let path = entry.path();
            if path.file_name().and_then(|name| name.to_str()) == Some(ACK_FILE) {
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) == Some("tmp") {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                changed = true;
                continue;
            }
            let (first, last) = EvidenceWalSegment::parse_name(&path)?;
            paths.push((path, first, last));
        }
        paths.sort_unstable_by_key(|(_path, first, _last)| *first);
        if changed {
            sync_directory(root)?;
        }
        Ok(paths)
    }

    fn read_ack(root: &Path) -> Result<AckStateV1> {
        let path = root.join(ACK_FILE);
        match fs::read(&path) {
            Ok(bytes) => EvidenceWalCodecV1::decode_ack(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AckStateV1::default()),
            Err(source) => Err(crate::Error::Io {
                path,
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    pub fn append(&mut self, observation: &ObservationEnvelopeV1) -> Result<u64> {
        self.append_classified(observation)
            .map_err(|failure| *failure.error)
    }

    pub(super) fn append_classified(
        &mut self,
        observation: &ObservationEnvelopeV1,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        let identity = EvidenceWalStreamIdentityV1::from_observation(observation)?;
        if self
            .stream_identity
            .is_some_and(|current| current != identity)
        {
            return Err(EvidenceStateSnafu {
                reason: "evidence WAL append crossed a boot, CPU, source, or source-epoch boundary"
                    .to_owned(),
            }
            .build()
            .into());
        }
        let cursor = self.next_cursor()?;
        let record = EvidenceRecordV1::new(cursor, observation)?;
        let payload_bytes = record.frame.len().saturating_sub(RECORD_OVERHEAD_BYTES) as u64;
        let active_fits = self.segments.last().is_some_and(|segment| {
            segment.active && segment.bytes + record.frame.len() as u64 <= SEGMENT_MAX_BYTES
        });
        let added_bytes = record.frame.len() as u64
            + if active_fits {
                0
            } else {
                SEGMENT_HEADER_BYTES as u64
            };
        let retained_bytes = self
            .retained_bytes
            .checked_add(added_bytes)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained byte count overflowed".to_owned(),
                }
                .build()
            })?;
        if payload_bytes > self.limits.maximum_record_bytes
            || record.frame.len() as u64 + SEGMENT_HEADER_BYTES as u64 > SEGMENT_MAX_BYTES
        {
            return Err(EvidenceWalAppendFailure {
                error: Box::new(
                    EvidenceStateSnafu {
                        reason: "evidence WAL retention or record capacity is exhausted".to_owned(),
                    }
                    .build(),
                ),
                capacity: false,
            });
        }
        if self.limits.capacity_policy == EvidenceWalCapacityPolicyV1::Block
            && (self.retained_records == self.limits.maximum_retained_records
                || retained_bytes > self.limits.maximum_retained_bytes)
        {
            return Err(EvidenceWalAppendFailure {
                error: Box::new(
                    EvidenceStateSnafu {
                        reason: "evidence WAL retention or record capacity is exhausted".to_owned(),
                    }
                    .build(),
                ),
                capacity: true,
            });
        }

        if !active_fits {
            if let Some(active) = self.segments.last_mut().filter(|segment| segment.active) {
                active.seal(&self.root)?;
            }
            self.segments.push(EvidenceWalSegment::create_empty(
                &self.root, identity, cursor,
            )?);
            self.retained_bytes = self
                .retained_bytes
                .checked_add(SEGMENT_HEADER_BYTES as u64)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL retained byte count overflowed".to_owned(),
                    }
                    .build()
                })?;
        }
        let active = self.segments.last_mut().ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL has no active segment after selection".to_owned(),
            }
            .build()
        })?;
        active.append(&record.frame, cursor)?;
        self.stream_identity = Some(identity);
        self.retained_bytes = self
            .retained_bytes
            .checked_add(record.frame.len() as u64)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained byte count overflowed".to_owned(),
                }
                .build()
            })?;
        self.retained_records = self.retained_records.checked_add(1).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL retained record count overflowed".to_owned(),
            }
            .build()
        })?;
        self.records.push(record);
        Ok(cursor)
    }

    fn next_cursor(&self) -> Result<u64> {
        if let Some(segment) = self.segments.last() {
            return match segment.last_cursor {
                Some(cursor) => cursor.checked_add(1).ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL cursor is exhausted".to_owned(),
                    }
                    .build()
                }),
                None => Ok(segment.first_cursor),
            };
        }
        self.acknowledged
            .contiguous_cursor
            .checked_add(1)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL cursor is exhausted".to_owned(),
                }
                .build()
            })
    }

    #[must_use]
    pub fn next_batch(&self) -> Option<EvidenceBatchV1> {
        self.batch_from(0)
    }

    #[must_use]
    fn next_batches(&self) -> Vec<EvidenceBatchV1> {
        let mut batches = Vec::new();
        let mut record_offset = 0_usize;
        let mut framed_bytes = 0_usize;
        while let Some(batch) = self.batch_from(record_offset) {
            let batch_bytes = batch.framed_records.len();
            if !batches.is_empty()
                && framed_bytes.saturating_add(batch_bytes)
                    > mithril_control::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES
            {
                break;
            }
            framed_bytes += batch_bytes;
            record_offset += batch.record_count();
            batches.push(batch);
        }
        batches
    }

    fn batch_from(&self, record_offset: usize) -> Option<EvidenceBatchV1> {
        let first_cursor = self.records.get(record_offset)?.cursor;
        if first_cursor
            != self
                .acknowledged
                .contiguous_cursor
                .checked_add(record_offset as u64 + 1)?
        {
            return None;
        }
        let stream_identity = self.stream_identity?;
        let maximum_frame_bytes =
            mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES.saturating_sub(128);
        let mut framed_records = Vec::new();
        let mut last_cursor = None;
        for record in self
            .records
            .iter()
            .skip(record_offset)
            .take(self.limits.maximum_batch_records)
        {
            if framed_records.len().saturating_add(record.frame.len()) > maximum_frame_bytes {
                break;
            }
            framed_records.extend_from_slice(&record.frame);
            last_cursor = Some(record.cursor);
        }
        let batch = EvidenceBatchV1 {
            first_cursor,
            last_cursor: last_cursor?,
            framed_records,
            stream_identity,
        };
        debug_assert!({
            let wire: mithril_control::EvidenceBatch = batch.clone().into();
            wire.encoded_len() <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES
        });
        Some(batch)
    }

    pub fn acknowledge(&mut self, ack: EvidenceAckV1) -> Result<()> {
        let record_count = ack
            .contiguous_cursor
            .checked_sub(self.acknowledged.contiguous_cursor)
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence acknowledgement did not advance the durable cursor"
                        .to_owned(),
                }
                .build()
            })?;
        if self.records.get(..record_count).is_none_or(|records| {
            records.first().map(|record| record.cursor)
                != self.acknowledged.contiguous_cursor.checked_add(1)
                || records.last().map(|record| record.cursor) != Some(ack.contiguous_cursor)
        }) {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement is not a retained WAL prefix".to_owned(),
            }
            .fail();
        }
        let state = AckStateV1 {
            contiguous_cursor: ack.contiguous_cursor,
        };
        atomic_write(
            &self.root.join(ACK_FILE),
            &EvidenceWalCodecV1::encode_ack(state),
        )?;
        let identity = self.stream_identity.ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL acknowledgement has no stream identity".to_owned(),
            }
            .build()
        })?;
        let needs_active = self.segments.last().is_some_and(|segment| {
            segment
                .last_cursor
                .is_some_and(|cursor| cursor <= state.contiguous_cursor)
        });
        if needs_active {
            let next = state.contiguous_cursor.checked_add(1).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL cursor is exhausted".to_owned(),
                }
                .build()
            })?;
            self.segments.push(EvidenceWalSegment::create_empty(
                &self.root, identity, next,
            )?);
        }
        let mut removed_bytes = 0_u64;
        let mut removed_records = 0_usize;
        for segment in &self.segments {
            if segment
                .last_cursor
                .is_some_and(|cursor| cursor <= state.contiguous_cursor)
            {
                fs::remove_file(&segment.path).context(IoSnafu {
                    path: &segment.path,
                })?;
                removed_bytes = removed_bytes.saturating_add(segment.bytes);
                removed_records = removed_records.saturating_add(segment.record_count);
            }
        }
        self.segments.retain(|segment| {
            !segment
                .last_cursor
                .is_some_and(|cursor| cursor <= state.contiguous_cursor)
        });
        sync_directory(&self.root)?;
        self.records.drain(..record_count);
        self.retained_bytes = self
            .retained_bytes
            .saturating_add(if needs_active {
                SEGMENT_HEADER_BYTES as u64
            } else {
                0
            })
            .saturating_sub(removed_bytes);
        self.retained_records = self.retained_records.saturating_sub(removed_records);
        self.acknowledged = state;
        Ok(())
    }

    #[must_use]
    pub const fn acknowledged_cursor(&self) -> u64 {
        self.acknowledged.contiguous_cursor
    }

    #[must_use]
    pub fn pending_records(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    use super::{
        EvidenceAckV1, EvidenceWal, EvidenceWalCapacityPolicyV1, EvidenceWalLimits,
        EvidenceWalOwner, EvidenceWalSegment, OpenOptions, SEGMENT_HEADER_BYTES,
    };
    use crate::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn observation(sequence: u64) -> crate::Result<crate::ObservationEnvelopeV1> {
        observation_for_stream(sequence, 1, 5, EvidenceIdV1::new(6, 7))
    }

    fn observation_for_stream(
        sequence: u64,
        cpu_id: u32,
        source_epoch: u64,
        node_boot_id: EvidenceIdV1,
    ) -> crate::Result<crate::ObservationEnvelopeV1> {
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            source_epoch,
            node_boot_id,
        )?
        .normalize_kernel(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: sequence,
                source_sequence: sequence,
                source_cpu_id: cpu_id,
                task_cookie: 10,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 2,
                configured_errno: -13,
                kernel_result: -13,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            },
            EvidenceIdV1::new(8, 9),
            TemporalCoverageV1::Complete,
            100,
        )
    }

    fn limits() -> EvidenceWalLimits {
        EvidenceWalLimits {
            maximum_record_bytes: 64 * 1_024,
            maximum_retained_bytes: 256 * 1_024,
            maximum_retained_records: 4,
            maximum_batch_records: 2,
            capacity_policy: EvidenceWalCapacityPolicyV1::Block,
        }
    }

    fn active_segment(
        root: &std::path::Path,
    ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let paths = std::fs::read_dir(root)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths
            .into_iter()
            .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("open"))
            .ok_or_else(|| "WAL has no active segment".into())
    }

    #[test]
    fn wal_replays_and_keeps_a_partially_acknowledged_segment_unchanged(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        wal.append(&observation(2)?)?;
        wal.append(&observation(3)?)?;
        let segment = active_segment(directory.path())?;
        let before_ack = std::fs::read(&segment)?;

        let first = wal.next_batch().ok_or("first batch does not exist")?;
        assert_eq!((first.first_cursor, first.last_cursor), (1, 2));
        assert_eq!(first.record_count(), 2);
        let wire: mithril_control::EvidenceBatch = first.into();
        assert_eq!(wire.first_cursor, 1);
        assert!(!wire.framed_records.is_empty());
        wal.acknowledge(EvidenceAckV1 {
            contiguous_cursor: 2,
        })?;
        assert_eq!(std::fs::read(&segment)?, before_ack);
        drop(wal);

        let mut reopened = EvidenceWal::open(directory.path(), limits())?;
        let remaining = reopened
            .next_batch()
            .ok_or("remaining batch does not exist")?;
        assert_eq!((remaining.first_cursor, remaining.last_cursor), (3, 3));
        reopened.acknowledge(EvidenceAckV1 {
            contiguous_cursor: 3,
        })?;
        assert_eq!(reopened.acknowledged_cursor(), 3);
        assert_eq!(reopened.pending_records(), 0);
        assert_eq!(
            std::fs::metadata(active_segment(directory.path())?)?.len(),
            SEGMENT_HEADER_BYTES as u64
        );
        Ok(())
    }

    #[test]
    fn wal_owner_pipelines_batches_and_applies_cumulative_acknowledgements(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = EvidenceWalOwner::open(
            directory.path(),
            EvidenceWalLimits {
                maximum_retained_records: 5,
                ..limits()
            },
        )?;
        for sequence in 1..=5 {
            owner
                .append_classified(&observation(sequence)?)
                .map_err(|failure| failure.error)?;
        }

        let batches = owner.next_batches();
        assert_eq!(
            batches
                .iter()
                .map(|batch| (batch.first_cursor, batch.last_cursor))
                .collect::<Vec<_>>(),
            [(1, 2), (3, 4), (5, 5)]
        );
        assert!(!owner.acknowledge(EvidenceAckV1 {
            contiguous_cursor: 4,
        })?);
        assert_eq!(
            owner
                .next_batches()
                .iter()
                .map(|batch| (batch.first_cursor, batch.last_cursor))
                .collect::<Vec<_>>(),
            [(5, 5)]
        );
        assert!(owner.acknowledge(EvidenceAckV1 {
            contiguous_cursor: 5,
        })?);
        assert!(owner.next_batches().is_empty());
        Ok(())
    }

    #[test]
    fn acknowledgement_deletes_only_fully_acknowledged_segments(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(
            directory.path(),
            EvidenceWalLimits {
                maximum_batch_records: 1,
                ..limits()
            },
        )?;
        wal.append(&observation(1)?)?;
        wal.segments
            .last_mut()
            .ok_or("first segment does not exist")?
            .seal(directory.path())?;
        let sealed = EvidenceWalSegment::sealed_path(directory.path(), 1, 1);
        wal.append(&observation(2)?)?;
        let active = active_segment(directory.path())?;
        let active_before_ack = std::fs::read(&active)?;

        wal.acknowledge(EvidenceAckV1 {
            contiguous_cursor: 1,
        })?;

        assert!(!sealed.exists());
        assert_eq!(std::fs::read(active)?, active_before_ack);
        assert_eq!(wal.pending_records(), 1);
        Ok(())
    }

    #[test]
    fn wal_rejects_a_complete_record_with_a_bad_crc32c() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        drop(wal);
        let path = active_segment(directory.path())?;
        let mut bytes = std::fs::read(&path)?;
        *bytes.last_mut().ok_or("record has no checksum")? ^= 1;
        std::fs::write(path, bytes)?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn wal_truncates_only_an_incomplete_active_tail() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        drop(wal);
        let path = active_segment(directory.path())?;
        let complete = std::fs::read(&path)?;
        OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(&[0, 0, 0])?;

        let reopened = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(reopened.pending_records(), 1);
        assert_eq!(std::fs::read(path)?, complete);
        Ok(())
    }

    #[test]
    fn wal_rejects_an_incomplete_sealed_segment() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        drop(wal);
        let active = active_segment(directory.path())?;
        let sealed = EvidenceWalSegment::sealed_path(directory.path(), 1, 1);
        std::fs::rename(&active, &sealed)?;
        OpenOptions::new()
            .append(true)
            .open(&sealed)?
            .write_all(&[0, 0, 0])?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn wal_rejects_stream_crossing_and_corrupt_segment_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        assert!(wal
            .append(&observation_for_stream(2, 2, 5, EvidenceIdV1::new(6, 7))?)
            .is_err());
        drop(wal);

        let path = active_segment(directory.path())?;
        let mut bytes = std::fs::read(&path)?;
        bytes[0] ^= 1;
        std::fs::write(path, bytes)?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn segmented_wal_uses_one_allocation_for_many_records() -> Result<(), Box<dyn std::error::Error>>
    {
        const RECORDS: u64 = 32;
        const LEGACY_BYTES_PER_RECORD: u64 = 16_776;

        let directory = tempfile::tempdir()?;
        let compact_limits = EvidenceWalLimits {
            maximum_retained_records: RECORDS as usize,
            maximum_batch_records: RECORDS as usize,
            ..limits()
        };
        let mut wal = EvidenceWal::open(directory.path(), compact_limits)?;
        for sequence in 1..=RECORDS {
            wal.append(&observation(sequence)?)?;
        }
        let files = std::fs::read_dir(directory.path())?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(files.len(), 1);
        let allocated_bytes = files[0].metadata()?.blocks() * 512;
        assert!(allocated_bytes * 100 <= LEGACY_BYTES_PER_RECORD * RECORDS);
        Ok(())
    }

    #[test]
    fn retain_keeps_every_unacknowledged_record_beyond_the_soft_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let retain_limits = EvidenceWalLimits {
            maximum_retained_records: 2,
            maximum_batch_records: 1,
            capacity_policy: EvidenceWalCapacityPolicyV1::Retain,
            ..limits()
        };
        let mut owner = EvidenceWalOwner::open(directory.path(), retain_limits)?;
        for sequence in 1..=3 {
            owner
                .append_classified(&observation(sequence)?)
                .map_err(|failure| failure.error)?;
        }
        assert_eq!(owner.retention()?.0, 3);
        drop(owner);

        let mut reopened = EvidenceWalOwner::open(directory.path(), retain_limits)?;
        for cursor in 1..=3 {
            let batch = reopened
                .next_batch()
                .ok_or("retained record did not upload")?;
            assert_eq!((batch.first_cursor, batch.last_cursor), (cursor, cursor));
            reopened.acknowledge(EvidenceAckV1 {
                contiguous_cursor: cursor,
            })?;
        }
        assert!(reopened.next_batch().is_none());
        Ok(())
    }

    #[test]
    fn block_refuses_a_record_beyond_the_configured_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(
            directory.path(),
            EvidenceWalLimits {
                maximum_retained_records: 1,
                maximum_batch_records: 1,
                ..limits()
            },
        )?;
        wal.append(&observation(1)?)?;
        assert!(wal.append(&observation(2)?).is_err());
        assert_eq!(wal.pending_records(), 1);
        Ok(())
    }

    #[test]
    fn restart_preserves_segment_bytes_before_appending_new_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let retain_limits = EvidenceWalLimits {
            maximum_retained_records: 2,
            maximum_batch_records: 1,
            capacity_policy: EvidenceWalCapacityPolicyV1::Retain,
            ..limits()
        };
        let mut wal = EvidenceWal::open(directory.path(), retain_limits)?;
        for sequence in 1..=4 {
            wal.append(&observation(sequence)?)?;
        }
        let path = active_segment(directory.path())?;
        let before_restart = std::fs::read(&path)?;
        drop(wal);

        let mut restarted = EvidenceWal::open(directory.path(), retain_limits)?;
        assert_eq!(std::fs::read(&path)?, before_restart);
        restarted.append(&observation(5)?)?;
        let after_restart = std::fs::read(path)?;
        assert_eq!(&after_restart[..before_restart.len()], before_restart);
        assert_eq!(restarted.pending_records(), 5);
        Ok(())
    }

    #[test]
    fn stream_directories_include_cpu_identity() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        owner
            .append_classified(&observation_for_stream(1, 1, 5, EvidenceIdV1::new(6, 7))?)
            .map_err(|failure| failure.error)?;
        owner
            .append_classified(&observation_for_stream(1, 2, 5, EvidenceIdV1::new(6, 7))?)
            .map_err(|failure| failure.error)?;
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 2);
        drop(owner);
        assert_eq!(
            EvidenceWalOwner::open(directory.path(), limits())?
                .streams
                .len(),
            2
        );
        Ok(())
    }
}
