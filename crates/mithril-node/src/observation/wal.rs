use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{CoverageGapReasonV1, EvidenceDigestV1, ObservationEnvelopeV1};
use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::Result;

use super::persistence::{atomic_write, sync_directory};

const WAL_FRAME_MAGIC: [u8; 8] = *b"MITHWAL\0";
const WAL_FRAME_VERSION: u16 = 1;
const WAL_FRAME_HEADER_BYTES: usize = 52;
const WAL_FRAME_RECORD: u8 = 1;
const WAL_FRAME_ACK: u8 = 2;
const WAL_FRAME_GAP: u8 = 3;
const WAL_FRAME_STREAM: u8 = 4;
const ACK_FILE: &str = "acknowledged.bin";
const GAP_FILE: &str = "gap.bin";
const STREAM_FILE: &str = "stream.bin";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceWalCapacityPolicyV1 {
    #[default]
    Block,
    Rewrite,
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
            || self.maximum_batch_records > self.maximum_retained_records
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
            maximum_batch_records: mithril_control::MAX_EVIDENCE_BATCH_RECORDS,
            capacity_policy: EvidenceWalCapacityPolicyV1::Block,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceRecordV1 {
    pub cursor: u64,
    pub record: mithril_control::EvidenceRecord,
}

impl EvidenceRecordV1 {
    fn new(cursor: u64, observation: &ObservationEnvelopeV1) -> Result<Self> {
        Ok(Self {
            cursor,
            record: observation.to_wire_record()?,
        })
    }

    fn validate(&self, expected_cursor: u64, identity: EvidenceWalStreamIdentityV1) -> Result<()> {
        if self.cursor != expected_cursor {
            return EvidenceStateSnafu {
                reason: format!("evidence WAL record {expected_cursor} is out of order"),
            }
            .fail();
        }
        let observation = ObservationEnvelopeV1::from_wire_record(
            identity.tenant_id.into(),
            identity.node_boot_id.into(),
            identity.source_id.into(),
            identity.source_epoch,
            self.cursor,
            identity.cpu_id,
            &self.record,
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
            "{}-{:020}-{}",
            hex::encode(self.source_id),
            self.source_epoch,
            hex::encode(self.node_boot_id)
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub records: Vec<EvidenceRecordV1>,
    stream_identity: EvidenceWalStreamIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGapV1 {
    pub node_boot_id: [u8; 16],
    pub source_id: [u8; 16],
    pub source_epoch: u64,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub discarded_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceUploadV1 {
    Batch(EvidenceBatchV1),
    Gap(EvidenceGapV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceUploadAckV1 {
    Batch(EvidenceAckV1),
    Gap(EvidenceGapAckV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceGapAckV1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceWalRewriteV1 {
    pub discarded_records: u64,
    pub discarded_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceWalAppendV1 {
    pub cursor: u64,
    pub rewrite: EvidenceWalRewriteV1,
}

impl EvidenceGapV1 {
    fn from_record(
        identity: EvidenceWalStreamIdentityV1,
        record: &EvidenceRecordV1,
        discarded_bytes: u64,
    ) -> Result<Self> {
        let gap = Self {
            node_boot_id: identity.node_boot_id,
            source_id: identity.source_id,
            source_epoch: identity.source_epoch,
            first_cursor: record.cursor,
            last_cursor: record.cursor,
            discarded_bytes,
        };
        gap.validate()?;
        Ok(gap)
    }

    fn extend(&self, record: &EvidenceRecordV1, discarded_bytes: u64) -> Result<Self> {
        if record.cursor != self.last_cursor.checked_add(1).unwrap_or(0) {
            return EvidenceStateSnafu {
                reason: "evidence WAL rewrite cannot cross an identity or cursor boundary"
                    .to_owned(),
            }
            .fail();
        }
        let mut extended = self.clone();
        extended.last_cursor = record.cursor;
        extended.discarded_bytes = extended
            .discarded_bytes
            .checked_add(discarded_bytes)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL rewritten byte count overflowed".to_owned(),
                }
                .build()
            })?;
        Ok(extended)
    }

    fn validate(&self) -> Result<()> {
        let cursor_count = self
            .last_cursor
            .checked_sub(self.first_cursor)
            .and_then(|span| span.checked_add(1));
        if self.node_boot_id == [0; 16]
            || self.source_id == [0; 16]
            || self.source_epoch == 0
            || self.first_cursor == 0
            || cursor_count.is_none()
            || self.discarded_bytes == 0
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL gap identity or range is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl From<EvidenceRecordV1> for mithril_control::EvidenceRecord {
    fn from(record: EvidenceRecordV1) -> Self {
        record.record
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
            records: batch.records.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<EvidenceGapV1> for mithril_control::EvidenceGap {
    fn from(gap: EvidenceGapV1) -> Self {
        Self {
            node_boot_id: gap.node_boot_id.to_vec(),
            source_id: gap.source_id.to_vec(),
            source_epoch: gap.source_epoch,
            first_cursor: gap.first_cursor,
            last_cursor: gap.last_cursor,
            discarded_bytes: gap.discarded_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceAckV1;

impl TryFrom<mithril_control::EvidenceAck> for EvidenceAckV1 {
    type Error = crate::Error;

    fn try_from(_ack: mithril_control::EvidenceAck) -> Result<Self> {
        Ok(Self)
    }
}

impl TryFrom<mithril_control::EvidenceGapAck> for EvidenceGapAckV1 {
    type Error = crate::Error;

    fn try_from(_ack: mithril_control::EvidenceGapAck) -> Result<Self> {
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AckStateV1 {
    contiguous_cursor: u64,
}

struct EvidenceWalCodecV1;

impl EvidenceWalCodecV1 {
    fn encode_frame(kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let payload_len = u64::try_from(payload.len()).map_err(|_| {
            EvidenceStateSnafu {
                reason: "evidence WAL binary payload size is not representable".to_owned(),
            }
            .build()
        })?;
        let capacity = WAL_FRAME_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL binary frame size overflowed".to_owned(),
                }
                .build()
            })?;
        let mut frame = Vec::with_capacity(capacity);
        frame.extend_from_slice(&WAL_FRAME_MAGIC);
        frame.extend_from_slice(&WAL_FRAME_VERSION.to_be_bytes());
        frame.push(kind);
        frame.push(0);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        let mut digest = Sha256::new();
        digest.update(&frame[WAL_FRAME_MAGIC.len()..]);
        digest.update(payload);
        frame.extend_from_slice(&digest.finalize());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    fn decode_frame<'a>(bytes: &'a [u8], expected_kind: u8, name: &str) -> Result<&'a [u8]> {
        if bytes.len() < WAL_FRAME_HEADER_BYTES || bytes[..8] != WAL_FRAME_MAGIC {
            return EvidenceStateSnafu {
                reason: format!("{name} has an invalid binary frame header"),
            }
            .fail();
        }
        let version = u16::from_be_bytes(bytes[8..10].try_into().unwrap_or_default());
        let kind = bytes[10];
        let flags = bytes[11];
        let payload_len = u64::from_be_bytes(bytes[12..20].try_into().unwrap_or_default());
        let payload_len = usize::try_from(payload_len).map_err(|_| {
            EvidenceStateSnafu {
                reason: format!("{name} binary payload size is not representable"),
            }
            .build()
        })?;
        let expected_len = WAL_FRAME_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: format!("{name} binary frame size overflowed"),
                }
                .build()
            })?;
        if version != WAL_FRAME_VERSION
            || kind != expected_kind
            || flags != 0
            || bytes.len() != expected_len
        {
            return EvidenceStateSnafu {
                reason: format!("{name} has an invalid binary frame version, kind, flags, or size"),
            }
            .fail();
        }
        let payload = &bytes[WAL_FRAME_HEADER_BYTES..];
        let mut digest = Sha256::new();
        digest.update(&bytes[WAL_FRAME_MAGIC.len()..20]);
        digest.update(payload);
        let actual: EvidenceDigestV1 = digest.finalize().into();
        if bytes[20..WAL_FRAME_HEADER_BYTES] != actual {
            return EvidenceStateSnafu {
                reason: format!("{name} binary frame checksum does not match"),
            }
            .fail();
        }
        Ok(payload)
    }

    fn take_binary<'a>(bytes: &mut &'a [u8], count: usize, name: &str) -> Result<&'a [u8]> {
        if bytes.len() < count {
            return EvidenceStateSnafu {
                reason: format!("{name} binary payload is truncated"),
            }
            .fail();
        }
        let (value, remaining) = bytes.split_at(count);
        *bytes = remaining;
        Ok(value)
    }

    fn take_binary_array<const N: usize>(bytes: &mut &[u8], name: &str) -> Result<[u8; N]> {
        Self::take_binary(bytes, N, name)?.try_into().map_err(|_| {
            EvidenceStateSnafu {
                reason: format!("{name} binary field has an invalid size"),
            }
            .build()
        })
    }

    fn take_binary_u64(bytes: &mut &[u8], name: &str) -> Result<u64> {
        Ok(u64::from_be_bytes(Self::take_binary_array(bytes, name)?))
    }

    fn finish_binary(bytes: &[u8], name: &str) -> Result<()> {
        if !bytes.is_empty() {
            return EvidenceStateSnafu {
                reason: format!("{name} binary payload has trailing bytes"),
            }
            .fail();
        }
        Ok(())
    }

    fn encode_record(record: &EvidenceRecordV1) -> Result<Vec<u8>> {
        let encoded = record.record.encode_to_vec();
        let mut payload = Vec::with_capacity(8_usize.saturating_add(encoded.len()));
        payload.extend_from_slice(&record.cursor.to_be_bytes());
        payload.extend_from_slice(&encoded);
        Self::encode_frame(WAL_FRAME_RECORD, &payload)
    }

    fn decode_record(bytes: &[u8]) -> Result<EvidenceRecordV1> {
        let name = "evidence WAL record";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_RECORD, name)?;
        let cursor = Self::take_binary_u64(&mut payload, name)?;
        let record = mithril_control::EvidenceRecord::decode(payload).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("evidence WAL record protobuf is invalid: {error}"),
            }
            .build()
        })?;
        Ok(EvidenceRecordV1 { cursor, record })
    }

    fn encode_ack(state: &AckStateV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&state.contiguous_cursor.to_be_bytes());
        Self::encode_frame(WAL_FRAME_ACK, &payload)
    }

    fn decode_ack(bytes: &[u8]) -> Result<AckStateV1> {
        let name = "evidence acknowledgement state";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_ACK, name)?;
        let state = AckStateV1 {
            contiguous_cursor: Self::take_binary_u64(&mut payload, name)?,
        };
        Self::finish_binary(payload, name)?;
        Ok(state)
    }

    fn encode_gap(gap: &EvidenceGapV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(72);
        payload.extend_from_slice(&gap.node_boot_id);
        payload.extend_from_slice(&gap.source_id);
        payload.extend_from_slice(&gap.source_epoch.to_be_bytes());
        payload.extend_from_slice(&gap.first_cursor.to_be_bytes());
        payload.extend_from_slice(&gap.last_cursor.to_be_bytes());
        payload.extend_from_slice(&gap.discarded_bytes.to_be_bytes());
        Self::encode_frame(WAL_FRAME_GAP, &payload)
    }

    fn decode_gap(bytes: &[u8]) -> Result<EvidenceGapV1> {
        let name = "evidence WAL gap";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_GAP, name)?;
        let gap = EvidenceGapV1 {
            node_boot_id: Self::take_binary_array(&mut payload, name)?,
            source_id: Self::take_binary_array(&mut payload, name)?,
            source_epoch: Self::take_binary_u64(&mut payload, name)?,
            first_cursor: Self::take_binary_u64(&mut payload, name)?,
            last_cursor: Self::take_binary_u64(&mut payload, name)?,
            discarded_bytes: Self::take_binary_u64(&mut payload, name)?,
        };
        Self::finish_binary(payload, name)?;
        Ok(gap)
    }

    fn encode_stream(identity: EvidenceWalStreamIdentityV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(60);
        payload.extend_from_slice(&identity.tenant_id);
        payload.extend_from_slice(&identity.node_boot_id);
        payload.extend_from_slice(&identity.source_id);
        payload.extend_from_slice(&identity.source_epoch.to_be_bytes());
        payload.extend_from_slice(&identity.cpu_id.to_be_bytes());
        Self::encode_frame(WAL_FRAME_STREAM, &payload)
    }

    fn decode_stream(bytes: &[u8]) -> Result<EvidenceWalStreamIdentityV1> {
        let name = "evidence WAL stream identity";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_STREAM, name)?;
        let identity = EvidenceWalStreamIdentityV1 {
            tenant_id: Self::take_binary_array(&mut payload, name)?,
            node_boot_id: Self::take_binary_array(&mut payload, name)?,
            source_id: Self::take_binary_array(&mut payload, name)?,
            source_epoch: Self::take_binary_u64(&mut payload, name)?,
            cpu_id: u32::from_be_bytes(Self::take_binary_array(&mut payload, name)?),
        };
        Self::finish_binary(payload, name)?;
        identity.validate()?;
        Ok(identity)
    }
}

pub struct EvidenceWal {
    root: PathBuf,
    limits: EvidenceWalLimits,
    stream_identity: Option<EvidenceWalStreamIdentityV1>,
    records: Vec<EvidenceRecordV1>,
    retained_bytes: u64,
    acknowledged: AckStateV1,
    gap: Option<EvidenceGapV1>,
    gap_bytes: u64,
}

pub(super) struct EvidenceWalAppendFailure {
    pub error: Box<crate::Error>,
    pub gap_reason: CoverageGapReasonV1,
    pub rewrite: EvidenceWalRewriteV1,
}

impl From<crate::Error> for EvidenceWalAppendFailure {
    fn from(error: crate::Error) -> Self {
        Self {
            error: Box::new(error),
            gap_reason: CoverageGapReasonV1::WalFailure,
            rewrite: EvidenceWalRewriteV1::default(),
        }
    }
}

pub(super) struct EvidenceWalOwner {
    root: PathBuf,
    limits: EvidenceWalLimits,
    streams: BTreeMap<EvidenceWalStreamIdentityV1, EvidenceWal>,
    in_flight: Option<(EvidenceWalStreamIdentityV1, EvidenceUploadV1)>,
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
            if !stream_directory_matches(&path, identity) {
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
    ) -> std::result::Result<EvidenceWalAppendV1, EvidenceWalAppendFailure> {
        let identity = EvidenceWalStreamIdentityV1::from_observation(observation)
            .map_err(EvidenceWalAppendFailure::from)?;
        if !self.streams.contains_key(&identity) {
            let path = self.root.join(identity.directory_name());
            let wal =
                EvidenceWal::open(path, self.limits).map_err(EvidenceWalAppendFailure::from)?;
            self.streams.insert(identity, wal);
        }
        let mut rewrite = EvidenceWalRewriteV1::default();
        loop {
            let (retained_records, retained_bytes) =
                self.retention().map_err(EvidenceWalAppendFailure::from)?;
            let result = {
                let wal = self.streams.get_mut(&identity).ok_or_else(|| {
                    EvidenceWalAppendFailure::from(
                        EvidenceStateSnafu {
                            reason: "the evidence WAL stream is missing after identity selection"
                                .to_owned(),
                        }
                        .build(),
                    )
                })?;
                // The configured retention bounds apply to all source streams together.
                wal.limits.maximum_retained_records = wal.records.len()
                    + self
                        .limits
                        .maximum_retained_records
                        .saturating_sub(retained_records);
                wal.limits.maximum_retained_bytes = wal.retained_bytes
                    + self
                        .limits
                        .maximum_retained_bytes
                        .saturating_sub(retained_bytes);
                let result = wal.append_classified(observation);
                wal.limits = self.limits;
                result
            };
            match result {
                Ok(cursor) => return Ok(EvidenceWalAppendV1 { cursor, rewrite }),
                Err(failure)
                    if failure.gap_reason == CoverageGapReasonV1::WalCapacity
                        && self.limits.capacity_policy == EvidenceWalCapacityPolicyV1::Rewrite =>
                {
                    let discarded =
                        self.rewrite_oldest_record()
                            .map_err(|error| EvidenceWalAppendFailure {
                                error: Box::new(error),
                                gap_reason: CoverageGapReasonV1::WalCapacity,
                                rewrite,
                            })?;
                    let Some(discarded) = discarded else {
                        return Err(EvidenceWalAppendFailure { rewrite, ..failure });
                    };
                    rewrite.discarded_records = rewrite
                        .discarded_records
                        .saturating_add(discarded.discarded_records);
                    rewrite.discarded_bytes = rewrite
                        .discarded_bytes
                        .saturating_add(discarded.discarded_bytes);
                }
                Err(failure) => return Err(EvidenceWalAppendFailure { rewrite, ..failure }),
            }
        }
    }

    pub(super) fn next_batch(&mut self) -> Option<EvidenceBatchV1> {
        if let Some((_identity, upload)) = &self.in_flight {
            return match upload {
                EvidenceUploadV1::Batch(batch) => Some(batch.clone()),
                EvidenceUploadV1::Gap(_) => None,
            };
        }
        let identity = self.streams.keys().copied().find(|identity| {
            self.streams
                .get(identity)
                .is_some_and(|wal| wal.next_batch().is_some())
        })?;
        let batch = self.streams.get(&identity)?.next_batch()?;
        self.in_flight = Some((identity, EvidenceUploadV1::Batch(batch.clone())));
        Some(batch)
    }

    pub(super) fn next_upload(&mut self) -> Option<EvidenceUploadV1> {
        if let Some((_identity, upload)) = &self.in_flight {
            return Some(upload.clone());
        }
        let identity = self
            .streams
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
                    .is_some_and(EvidenceWal::has_pending_upload)
            })?;
        let upload = self.streams.get(&identity)?.next_upload()?;
        self.in_flight = Some((identity, upload.clone()));
        Some(upload)
    }

    pub(super) fn acknowledge(&mut self, ack: EvidenceAckV1) -> Result<()> {
        self.acknowledge_upload(EvidenceUploadAckV1::Batch(ack))
    }

    pub(super) fn acknowledge_upload(&mut self, ack: EvidenceUploadAckV1) -> Result<()> {
        let (identity, upload) = self.in_flight.as_ref().ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence acknowledgement has no in-flight source item".to_owned(),
            }
            .build()
        })?;
        let wal = self.streams.get_mut(identity).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence acknowledgement source is not retained".to_owned(),
            }
            .build()
        })?;
        match (ack, upload) {
            (EvidenceUploadAckV1::Batch(ack), EvidenceUploadV1::Batch(batch)) => {
                wal.acknowledge_batch(ack, batch)?;
            }
            (EvidenceUploadAckV1::Gap(ack), EvidenceUploadV1::Gap(gap)) => {
                wal.acknowledge_gap(ack, gap)?;
            }
            _ => {
                return EvidenceStateSnafu {
                    reason: "evidence acknowledgement type does not match its in-flight item"
                        .to_owned(),
                }
                .fail();
            }
        }
        let identity = *identity;
        self.in_flight = None;
        self.last_acknowledged_stream = Some(identity);
        Ok(())
    }

    fn rewrite_oldest_record(&mut self) -> Result<Option<EvidenceWalRewriteV1>> {
        let candidate = self
            .streams
            .iter()
            .filter_map(|(source_id, wal)| {
                let in_flight = self
                    .in_flight
                    .as_ref()
                    .filter(|(active_source, _upload)| active_source == source_id)
                    .map(|(_source, upload)| upload);
                wal.rewrite_candidate(in_flight)
                    .map(|record| (record.record.ingested_utc_ns, *source_id, record.cursor))
            })
            .min();
        let Some((_ingested_utc_ns, source_id, cursor)) = candidate else {
            return Ok(None);
        };
        self.streams
            .get_mut(&source_id)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "the selected evidence rewrite stream disappeared".to_owned(),
                }
                .build()
            })?
            .rewrite_record(cursor)
            .map(Some)
    }

    fn retention(&self) -> Result<(usize, u64)> {
        self.streams
            .values()
            .try_fold((0_usize, 0_u64), |(records, bytes), wal| {
                Ok((
                    records.checked_add(wal.pending_records()).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL retained record count overflowed".to_owned(),
                        }
                        .build()
                    })?,
                    bytes.checked_add(wal.retained_bytes()).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL retained byte count overflowed".to_owned(),
                        }
                        .build()
                    })?,
                ))
            })
    }

    fn validate_retention(&self) -> Result<()> {
        let (retained_records, retained_bytes) = self.retention()?;
        if retained_records > self.limits.maximum_retained_records
            || retained_bytes > self.limits.maximum_retained_bytes
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL streams exceed their shared retention bounds".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

fn stream_directory_matches(path: &Path, identity: EvidenceWalStreamIdentityV1) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    name == identity.directory_name()
}

impl EvidenceWal {
    pub fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        let root = root.into();
        limits.validate()?;
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let persisted_stream_identity = read_stream_identity(&root)?;
        let acknowledged = read_ack(&root)?;
        let gap = read_gap(&root, acknowledged)?;
        let mut paths = recover_directory(&root, acknowledged, gap.as_ref())?;
        paths.sort_unstable();
        if persisted_stream_identity.is_none()
            && (!paths.is_empty() || gap.is_some() || acknowledged.contiguous_cursor > 0)
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL data has no durable stream identity".to_owned(),
            }
            .fail();
        }

        let mut records = Vec::with_capacity(paths.len());
        let mut expected_cursor =
            acknowledged
                .contiguous_cursor
                .checked_add(1)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "acknowledged evidence cursor is exhausted".to_owned(),
                    }
                    .build()
                })?;
        let mut retained_bytes = 0_u64;
        for path in paths {
            let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
            if bytes.len() as u64 > limits.maximum_record_bytes {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL segment `{}` exceeds the record bound",
                        path.display()
                    ),
                }
                .fail();
            }
            let record = EvidenceWalCodecV1::decode_record(&bytes)?;
            if let Some(gap) = &gap {
                apply_gap_boundary(gap, &mut expected_cursor, record.cursor)?;
            }
            let identity = persisted_stream_identity.ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL record has no stream identity".to_owned(),
                }
                .build()
            })?;
            record.validate(expected_cursor, identity)?;
            let stored_bytes = bytes.len();
            retained_bytes = retained_bytes
                .checked_add(stored_bytes as u64)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL retained byte count overflowed".to_owned(),
                    }
                    .build()
                })?;
            expected_cursor = expected_cursor.checked_add(1).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL cursor is exhausted".to_owned(),
                }
                .build()
            })?;
            records.push(record);
        }
        if let Some(gap) = &gap {
            apply_gap_boundary(gap, &mut expected_cursor, u64::MAX)?;
            if expected_cursor <= gap.last_cursor {
                return EvidenceStateSnafu {
                    reason: "evidence WAL gap has a missing retained prefix".to_owned(),
                }
                .fail();
            }
        }
        let gap_bytes = gap
            .as_ref()
            .map(EvidenceWalCodecV1::encode_gap)
            .transpose()?
            .map_or(0, |bytes| bytes.len() as u64);
        retained_bytes = retained_bytes.checked_add(gap_bytes).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL retained byte count overflowed".to_owned(),
            }
            .build()
        })?;
        if records.len() > limits.maximum_retained_records
            || retained_bytes > limits.maximum_retained_bytes
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL exceeds its configured retention bounds".to_owned(),
            }
            .fail();
        }
        Ok(Self {
            root,
            limits,
            stream_identity: persisted_stream_identity,
            records,
            retained_bytes,
            acknowledged,
            gap,
            gap_bytes,
        })
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
        match self.stream_identity {
            Some(current) if current != identity => {
                return Err(EvidenceStateSnafu {
                    reason: "evidence WAL append crossed a boot, source, or source-epoch boundary"
                        .to_owned(),
                }
                .build()
                .into());
            }
            Some(_) => {}
            None => {
                atomic_write(
                    &self.root.join(STREAM_FILE),
                    &EvidenceWalCodecV1::encode_stream(identity)?,
                )?;
                self.stream_identity = Some(identity);
            }
        }
        let record_tail = self.records.last().map(|record| record.cursor);
        let gap_tail = self.gap.as_ref().map(|gap| gap.last_cursor);
        let tail_cursor = record_tail
            .into_iter()
            .chain(gap_tail)
            .max()
            .unwrap_or(self.acknowledged.contiguous_cursor);
        let cursor = tail_cursor.checked_add(1).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL cursor is exhausted".to_owned(),
            }
            .build()
        })?;
        let record = EvidenceRecordV1::new(cursor, observation)?;
        let bytes = EvidenceWalCodecV1::encode_record(&record)?;
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
            EvidenceStateSnafu {
                reason: "evidence WAL segment size is not representable".to_owned(),
            }
            .build()
        })?;
        let retained_bytes = self.retained_bytes.checked_add(bytes_len).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL retained byte count overflowed".to_owned(),
            }
            .build()
        })?;
        if bytes_len > self.limits.maximum_record_bytes
            || self.records.len() == self.limits.maximum_retained_records
            || retained_bytes > self.limits.maximum_retained_bytes
        {
            return Err(EvidenceWalAppendFailure {
                error: Box::new(
                    EvidenceStateSnafu {
                        reason: "evidence WAL retention or record capacity is exhausted".to_owned(),
                    }
                    .build(),
                ),
                gap_reason: CoverageGapReasonV1::WalCapacity,
                rewrite: EvidenceWalRewriteV1::default(),
            });
        }
        let path = segment_path(&self.root, cursor);
        if path.exists() {
            return Err(EvidenceStateSnafu {
                reason: format!("evidence WAL segment `{}` already exists", path.display()),
            }
            .build()
            .into());
        }
        atomic_write(&path, &bytes)?;
        self.retained_bytes = retained_bytes;
        self.records.push(record);
        Ok(cursor)
    }

    #[must_use]
    pub fn next_batch(&self) -> Option<EvidenceBatchV1> {
        let first_cursor = self.records.first()?.cursor;
        if first_cursor != self.acknowledged.contiguous_cursor.checked_add(1)? {
            return None;
        }
        let stream_identity = self.stream_identity?;
        let mut records = Vec::new();
        let mut wire = mithril_control::EvidenceBatch {
            node_boot_id: stream_identity.node_boot_id.to_vec(),
            source_id: stream_identity.source_id.to_vec(),
            source_epoch: stream_identity.source_epoch,
            cpu_id: stream_identity.cpu_id,
            first_cursor,
            records: Vec::new(),
        };
        for record in self
            .records
            .iter()
            .take_while(|record| {
                self.gap
                    .as_ref()
                    .is_none_or(|gap| record.cursor < gap.first_cursor)
            })
            .take(self.limits.maximum_batch_records)
        {
            records.push(record.clone());
            wire.records.push(record.clone().into());
            if wire.encoded_len() > mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES {
                records.pop();
                break;
            }
        }
        let last_cursor = records.last()?.cursor;
        Some(EvidenceBatchV1 {
            first_cursor,
            last_cursor,
            records,
            stream_identity,
        })
    }

    fn next_upload(&self) -> Option<EvidenceUploadV1> {
        if let Some(batch) = self.next_batch() {
            return Some(EvidenceUploadV1::Batch(batch));
        }
        self.gap
            .as_ref()
            .filter(|gap| {
                gap.first_cursor
                    == self
                        .acknowledged
                        .contiguous_cursor
                        .checked_add(1)
                        .unwrap_or(0)
            })
            .cloned()
            .map(EvidenceUploadV1::Gap)
    }

    fn has_pending_upload(&self) -> bool {
        self.next_upload().is_some()
    }

    fn rewrite_candidate(&self, in_flight: Option<&EvidenceUploadV1>) -> Option<&EvidenceRecordV1> {
        if matches!(in_flight, Some(EvidenceUploadV1::Gap(_))) {
            return None;
        }
        if let Some(gap) = &self.gap {
            return self
                .records
                .iter()
                .find(|record| record.cursor == gap.last_cursor.saturating_add(1));
        }
        let protected_cursor = match in_flight {
            Some(EvidenceUploadV1::Batch(batch)) => batch.last_cursor,
            _ => self.acknowledged.contiguous_cursor,
        };
        self.records
            .iter()
            .find(|record| record.cursor > protected_cursor)
    }

    fn rewrite_record(&mut self, cursor: u64) -> Result<EvidenceWalRewriteV1> {
        let position = self
            .records
            .iter()
            .position(|record| record.cursor == cursor)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "the selected evidence rewrite record disappeared".to_owned(),
                }
                .build()
            })?;
        let record = &self.records[position];
        let record_bytes = EvidenceWalCodecV1::encode_record(record)?;
        let discarded_bytes = record_bytes.len() as u64;
        let gap = match &self.gap {
            Some(gap) => gap.extend(record, discarded_bytes)?,
            None => EvidenceGapV1::from_record(
                self.stream_identity.ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL rewrite has no stream identity".to_owned(),
                    }
                    .build()
                })?,
                record,
                discarded_bytes,
            )?,
        };
        let gap_bytes = EvidenceWalCodecV1::encode_gap(&gap)?;
        atomic_write(&self.root.join(GAP_FILE), &gap_bytes)?;
        let path = segment_path(&self.root, cursor);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        }
        sync_directory(&self.root)?;
        self.retained_bytes = self
            .retained_bytes
            .checked_sub(discarded_bytes)
            .and_then(|bytes| bytes.checked_sub(self.gap_bytes))
            .and_then(|bytes| bytes.checked_add(gap_bytes.len() as u64))
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained byte accounting underflowed or overflowed"
                        .to_owned(),
                }
                .build()
            })?;
        self.gap_bytes = gap_bytes.len() as u64;
        self.gap = Some(gap);
        self.records.remove(position);
        Ok(EvidenceWalRewriteV1 {
            discarded_records: 1,
            discarded_bytes,
        })
    }

    pub fn acknowledge(&mut self, ack: EvidenceAckV1) -> Result<()> {
        let Some(batch) = self.next_batch() else {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement has no pending batch".to_owned(),
            }
            .fail();
        };
        self.acknowledge_batch(ack, &batch)
    }

    fn acknowledge_batch(&mut self, _ack: EvidenceAckV1, batch: &EvidenceBatchV1) -> Result<()> {
        if self.records.get(..batch.records.len()) != Some(batch.records.as_slice()) {
            return EvidenceStateSnafu {
                reason: "the in-flight evidence batch is not a retained WAL prefix".to_owned(),
            }
            .fail();
        }
        let state = AckStateV1 {
            contiguous_cursor: batch.last_cursor,
        };
        let bytes = EvidenceWalCodecV1::encode_ack(&state)?;
        atomic_write(&self.root.join(ACK_FILE), &bytes)?;
        let acknowledged_count = batch.records.len();
        let remaining_bytes = self
            .records
            .iter()
            .skip(acknowledged_count)
            .try_fold(0_u64, |total, record| {
                let bytes = EvidenceWalCodecV1::encode_record(record)?;
                total.checked_add(bytes.len() as u64).ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL retained byte count overflowed".to_owned(),
                    }
                    .build()
                })
            })?
            .checked_add(self.gap_bytes)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL retained byte count overflowed".to_owned(),
                }
                .build()
            })?;
        for record in self.records.iter().take(acknowledged_count) {
            let path = segment_path(&self.root, record.cursor);
            match fs::metadata(&path) {
                Ok(_metadata) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(crate::Error::Io {
                        path,
                        source,
                        location: snafu::Location::default(),
                    });
                }
            }
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(crate::Error::Io {
                        path,
                        source,
                        location: snafu::Location::default(),
                    });
                }
            }
        }
        sync_directory(&self.root)?;
        self.records.drain(..acknowledged_count);
        self.retained_bytes = remaining_bytes;
        self.acknowledged = state;
        Ok(())
    }

    fn acknowledge_gap(&mut self, _ack: EvidenceGapAckV1, gap: &EvidenceGapV1) -> Result<()> {
        if self.gap.as_ref() != Some(gap) {
            return EvidenceStateSnafu {
                reason: "evidence gap acknowledgement does not match the pending durable gap"
                    .to_owned(),
            }
            .fail();
        }
        let state = AckStateV1 {
            contiguous_cursor: gap.last_cursor,
        };
        let bytes = EvidenceWalCodecV1::encode_ack(&state)?;
        atomic_write(&self.root.join(ACK_FILE), &bytes)?;
        let path = self.root.join(GAP_FILE);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        }
        sync_directory(&self.root)?;
        self.retained_bytes = self
            .retained_bytes
            .checked_sub(self.gap_bytes)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL gap byte accounting underflowed".to_owned(),
                }
                .build()
            })?;
        self.gap = None;
        self.gap_bytes = 0;
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

fn read_stream_identity(root: &Path) -> Result<Option<EvidenceWalStreamIdentityV1>> {
    read_optional_file(&root.join(STREAM_FILE))?
        .map(|bytes| EvidenceWalCodecV1::decode_stream(&bytes))
        .transpose()
}

fn read_ack(root: &Path) -> Result<AckStateV1> {
    let path = root.join(ACK_FILE);
    let state = read_optional_file(&path)?
        .map(|bytes| EvidenceWalCodecV1::decode_ack(&bytes))
        .transpose()?
        .unwrap_or_default();
    Ok(state)
}

fn recover_directory(
    root: &Path,
    acknowledged: AckStateV1,
    gap: Option<&EvidenceGapV1>,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let mut changed = false;
    for entry in fs::read_dir(root)
        .context(IoSnafu { path: root })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context(IoSnafu { path: root })?
    {
        let path = entry.path();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("wal") => {
                let cursor = segment_cursor(&path)?;
                if cursor <= acknowledged.contiguous_cursor
                    || gap
                        .is_some_and(|gap| cursor >= gap.first_cursor && cursor <= gap.last_cursor)
                {
                    fs::remove_file(&path).context(IoSnafu { path: &path })?;
                    changed = true;
                } else {
                    paths.push(path);
                }
            }
            Some("tmp") if is_owned_temporary(&path) => {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
                changed = true;
            }
            _ => {}
        }
    }
    if changed {
        sync_directory(root)?;
    }
    Ok(paths)
}

fn read_gap(root: &Path, acknowledged: AckStateV1) -> Result<Option<EvidenceGapV1>> {
    let path = root.join(GAP_FILE);
    let Some(gap) = read_optional_file(&path)?
        .map(|bytes| EvidenceWalCodecV1::decode_gap(&bytes))
        .transpose()?
    else {
        return Ok(None);
    };
    gap.validate()?;
    if gap.last_cursor <= acknowledged.contiguous_cursor {
        remove_optional_file(&path)?;
        sync_directory(root)?;
        return Ok(None);
    }
    if gap.first_cursor <= acknowledged.contiguous_cursor {
        return EvidenceStateSnafu {
            reason: "evidence WAL gap overlaps its acknowledged cursor".to_owned(),
        }
        .fail();
    }
    Ok(Some(gap))
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(crate::Error::Io {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }),
    }
}

fn remove_optional_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(crate::Error::Io {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }),
    }
}

fn apply_gap_boundary(
    gap: &EvidenceGapV1,
    expected_cursor: &mut u64,
    next_record_cursor: u64,
) -> Result<()> {
    if *expected_cursor != gap.first_cursor || next_record_cursor <= gap.last_cursor {
        return Ok(());
    }
    *expected_cursor = gap.last_cursor.checked_add(1).ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "evidence WAL gap exhausted its cursor".to_owned(),
        }
        .build()
    })?;
    Ok(())
}

fn segment_cursor(path: &Path) -> Result<u64> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if stem.len() != 20 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL segment `{}` has an invalid name",
                path.display()
            ),
        }
        .fail();
    }
    stem.parse::<u64>().map_err(|error| {
        EvidenceStateSnafu {
            reason: format!(
                "evidence WAL segment `{}` has an invalid cursor: {error}",
                path.display()
            ),
        }
        .build()
    })
}

fn is_owned_temporary(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    stem == "acknowledged"
        || stem == "gap"
        || stem == "stream"
        || (stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit()))
}

fn segment_path(root: &Path, cursor: u64) -> PathBuf {
    root.join(format!("{cursor:020}.wal"))
}

#[cfg(test)]
mod tests {
    use super::{
        segment_path, EvidenceAckV1, EvidenceGapAckV1, EvidenceUploadAckV1, EvidenceUploadV1,
        EvidenceWal, EvidenceWalCapacityPolicyV1, EvidenceWalLimits, EvidenceWalOwner, STREAM_FILE,
        WAL_FRAME_MAGIC,
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

    #[test]
    fn wal_replays_and_acknowledges_only_the_current_prefix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        wal.append(&observation(2)?)?;
        wal.append(&observation(3)?)?;

        let first = wal.next_batch().expect("first batch must exist");
        assert_eq!((first.first_cursor, first.last_cursor), (1, 2));
        let wire: mithril_control::EvidenceBatch = first.into();
        assert_eq!(wire.first_cursor, 1);
        assert_eq!(wire.records.len(), 2);
        assert_eq!(wire.node_boot_id, EvidenceIdV1::new(6, 7).to_be_bytes());

        wal.acknowledge(EvidenceAckV1)?;
        assert_eq!(wal.acknowledged_cursor(), 2);
        assert!(!segment_path(directory.path(), 1).exists());
        assert!(!segment_path(directory.path(), 2).exists());
        assert!(segment_path(directory.path(), 3).exists());
        drop(wal);

        let mut reopened = EvidenceWal::open(directory.path(), limits())?;
        let remaining = reopened.next_batch().expect("remaining batch must exist");
        assert_eq!((remaining.first_cursor, remaining.last_cursor), (3, 3));
        reopened.acknowledge(EvidenceAckV1)?;
        assert_eq!(reopened.acknowledged_cursor(), 3);
        assert_eq!(reopened.pending_records(), 0);
        assert!(reopened.acknowledge(EvidenceAckV1).is_err());
        Ok(())
    }

    #[test]
    fn wal_rejects_corrupt_binary_frames() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        drop(wal);

        let path = segment_path(directory.path(), 1);
        let mut bytes = std::fs::read(&path)?;
        assert_eq!(bytes[..WAL_FRAME_MAGIC.len()], WAL_FRAME_MAGIC);
        let last = bytes.last_mut().expect("WAL frame must contain a payload");
        *last ^= 1;
        std::fs::write(path, bytes)?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn wal_requires_one_durable_identity_and_rejects_stream_crossing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&observation(1)?)?;
        assert!(wal
            .append(&observation_for_stream(2, 1, 6, EvidenceIdV1::new(6, 7))?)
            .is_err());
        drop(wal);

        std::fs::remove_file(directory.path().join(STREAM_FILE))?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn binary_wal_is_more_than_100x_smaller_than_the_legacy_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        let stored_bytes = std::fs::read_dir(directory.path())?.try_fold(
            0_u64,
            |total, entry| -> Result<u64, std::io::Error> {
                Ok(total.saturating_add(entry?.metadata()?.len()))
            },
        )?;
        eprintln!(
            "stored {RECORDS} node WAL records in {stored_bytes} bytes ({:.1} bytes per record)",
            stored_bytes as f64 / RECORDS as f64
        );
        assert!(stored_bytes * 100 <= LEGACY_BYTES_PER_RECORD * RECORDS);
        Ok(())
    }

    #[test]
    fn rewrite_persists_and_uploads_an_exact_gap_before_later_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let rewrite_limits = EvidenceWalLimits {
            maximum_retained_records: 2,
            maximum_batch_records: 1,
            capacity_policy: EvidenceWalCapacityPolicyV1::Rewrite,
            ..limits()
        };
        let mut owner = EvidenceWalOwner::open(directory.path(), rewrite_limits)?;
        owner
            .append_classified(&observation(1)?)
            .map_err(|failure| failure.error)?;
        owner
            .append_classified(&observation(2)?)
            .map_err(|failure| failure.error)?;
        let first = owner.next_upload().expect("first upload must exist");
        assert!(matches!(
            first,
            EvidenceUploadV1::Batch(ref batch)
                if (batch.first_cursor, batch.last_cursor) == (1, 1)
        ));

        let append = owner
            .append_classified(&observation(3)?)
            .map_err(|failure| failure.error)?;
        assert_eq!(append.rewrite.discarded_records, 1);
        owner.acknowledge_upload(EvidenceUploadAckV1::Batch(EvidenceAckV1))?;
        drop(owner);

        let mut reopened = EvidenceWalOwner::open(directory.path(), rewrite_limits)?;
        let gap = reopened
            .next_upload()
            .expect("durable gap must be uploaded");
        assert!(matches!(
            gap,
            EvidenceUploadV1::Gap(ref gap)
                if (gap.first_cursor, gap.last_cursor) == (2, 2)
                    && gap.discarded_bytes > 0
        ));
        reopened.acknowledge_upload(EvidenceUploadAckV1::Gap(EvidenceGapAckV1))?;

        let last = reopened
            .next_upload()
            .expect("record after the gap must remain");
        assert!(matches!(
            last,
            EvidenceUploadV1::Batch(ref batch)
                if (batch.first_cursor, batch.last_cursor) == (3, 3)
        ));
        reopened.acknowledge_upload(EvidenceUploadAckV1::Batch(EvidenceAckV1))?;
        assert!(reopened.next_upload().is_none());
        Ok(())
    }

    #[test]
    fn wal_removes_owned_torn_writes_on_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let temporary = directory.path().join("00000000000000000001.tmp");
        std::fs::write(&temporary, b"torn")?;

        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        assert!(!temporary.exists());
        assert_eq!(wal.append(&observation(1)?)?, 1);
        Ok(())
    }
}
