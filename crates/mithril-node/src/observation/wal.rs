use std::collections::{BTreeMap, BTreeSet};
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

const WAL_FORMAT_VERSION: u32 = 1;
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
const LEGACY_ACK_FILE: &str = "acknowledged.json";
const LEGACY_GAP_FILE: &str = "gap.json";
const LEGACY_SOURCE_FILE: &str = "source-id";
const LEGACY_MIGRATION_FORMAT_VERSION: u32 = 1;
const LEGACY_MIGRATION_FILE: &str = ".legacy-migration-v1.json";

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecordV1 {
    pub format_version: u32,
    pub cursor: u64,
    pub observation_id: EvidenceDigestV1,
    pub payload: Vec<u8>,
    pub payload_sha256: EvidenceDigestV1,
    pub previous_record_sha256: EvidenceDigestV1,
    pub record_sha256: EvidenceDigestV1,
}

impl EvidenceRecordV1 {
    fn new(
        cursor: u64,
        observation: &ObservationEnvelopeV1,
        previous_record_sha256: EvidenceDigestV1,
    ) -> Result<Self> {
        let payload = observation.wire_bytes()?;
        let payload_sha256 = Sha256::digest(&payload).into();
        let mut record = Self {
            format_version: WAL_FORMAT_VERSION,
            cursor,
            observation_id: observation.observation_id,
            payload,
            payload_sha256,
            previous_record_sha256,
            record_sha256: [0; 32],
        };
        record.record_sha256 = record.digest();
        Ok(record)
    }

    fn digest(&self) -> EvidenceDigestV1 {
        let mut digest = Sha256::new();
        digest.update(self.format_version.to_be_bytes());
        digest.update(self.cursor.to_be_bytes());
        digest.update(self.observation_id);
        digest.update(self.payload_sha256);
        digest.update(self.previous_record_sha256);
        digest.finalize().into()
    }

    fn validate(&self, expected_cursor: u64, previous: EvidenceDigestV1) -> Result<()> {
        let payload_sha256: EvidenceDigestV1 = Sha256::digest(&self.payload).into();
        let observation = ObservationEnvelopeV1::from_wire_bytes(&self.payload)?;
        if self.format_version != WAL_FORMAT_VERSION
            || self.cursor != expected_cursor
            || self.observation_id != observation.observation_id
            || self.payload_sha256 != payload_sha256
            || self.previous_record_sha256 != previous
            || self.record_sha256 != self.digest()
        {
            return EvidenceStateSnafu {
                reason: format!(
                    "evidence WAL record {expected_cursor} failed identity, order, or integrity validation"
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn stream_identity(&self) -> Result<EvidenceWalStreamIdentityV1> {
        EvidenceWalStreamIdentityV1::from_observation(&ObservationEnvelopeV1::from_wire_bytes(
            &self.payload,
        )?)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EvidenceWalStreamIdentityV1 {
    node_boot_id: [u8; 16],
    source_id: [u8; 16],
    source_epoch: u64,
}

impl EvidenceWalStreamIdentityV1 {
    fn from_observation(observation: &ObservationEnvelopeV1) -> Result<Self> {
        let node_boot_id = observation.node_boot_id.ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL observation has no node boot identity".to_owned(),
            }
            .build()
        })?;
        let identity = Self {
            node_boot_id: node_boot_id.to_be_bytes(),
            source_id: observation.source_id.to_be_bytes(),
            source_epoch: observation.source_epoch,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(self) -> Result<()> {
        if self.node_boot_id == [0; 16] || self.source_id == [0; 16] || self.source_epoch == 0 {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub records: Vec<EvidenceRecordV1>,
    pub batch_sha256: EvidenceDigestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGapV1 {
    pub node_boot_id: [u8; 16],
    pub source_id: [u8; 16],
    pub source_epoch: u64,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub previous_record_sha256: EvidenceDigestV1,
    pub last_record_sha256: EvidenceDigestV1,
    pub discarded_records: u64,
    pub discarded_bytes: u64,
    pub gap_sha256: EvidenceDigestV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceUploadV1 {
    Batch(EvidenceBatchV1),
    Gap(EvidenceGapV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceUploadAckV1 {
    Batch(EvidenceAckV1),
    Gap(EvidenceGapAckV1),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGapAckV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub gap_sha256: EvidenceDigestV1,
}

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

impl EvidenceBatchV1 {
    #[must_use]
    pub fn digest(records: &[EvidenceRecordV1]) -> EvidenceDigestV1 {
        let mut digest = Sha256::new();
        for record in records {
            digest.update(record.cursor.to_be_bytes());
            digest.update(record.record_sha256);
        }
        digest.finalize().into()
    }
}

impl EvidenceGapV1 {
    fn stream_identity(&self) -> Result<EvidenceWalStreamIdentityV1> {
        let identity = EvidenceWalStreamIdentityV1 {
            node_boot_id: self.node_boot_id,
            source_id: self.source_id,
            source_epoch: self.source_epoch,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn from_record(record: &EvidenceRecordV1, discarded_bytes: u64) -> Result<Self> {
        let observation = ObservationEnvelopeV1::from_wire_bytes(&record.payload)?;
        let mut gap = Self {
            node_boot_id: observation
                .node_boot_id
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "rewritten evidence has no node boot identity".to_owned(),
                    }
                    .build()
                })?
                .to_be_bytes(),
            source_id: observation.source_id.to_be_bytes(),
            source_epoch: observation.source_epoch,
            first_cursor: record.cursor,
            last_cursor: record.cursor,
            previous_record_sha256: record.previous_record_sha256,
            last_record_sha256: record.record_sha256,
            discarded_records: 1,
            discarded_bytes,
            gap_sha256: [0; 32],
        };
        gap.refresh_digest();
        Ok(gap)
    }

    fn extend(&self, record: &EvidenceRecordV1, discarded_bytes: u64) -> Result<Self> {
        let observation = ObservationEnvelopeV1::from_wire_bytes(&record.payload)?;
        if observation.node_boot_id.map(|id| id.to_be_bytes()) != Some(self.node_boot_id)
            || observation.source_id.to_be_bytes() != self.source_id
            || observation.source_epoch != self.source_epoch
            || record.cursor != self.last_cursor.checked_add(1).unwrap_or(0)
            || record.previous_record_sha256 != self.last_record_sha256
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL rewrite cannot cross an identity or hash-chain boundary"
                    .to_owned(),
            }
            .fail();
        }
        let mut extended = self.clone();
        extended.last_cursor = record.cursor;
        extended.last_record_sha256 = record.record_sha256;
        extended.discarded_records =
            extended.discarded_records.checked_add(1).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL rewritten record count overflowed".to_owned(),
                }
                .build()
            })?;
        extended.discarded_bytes = extended
            .discarded_bytes
            .checked_add(discarded_bytes)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL rewritten byte count overflowed".to_owned(),
                }
                .build()
            })?;
        extended.refresh_digest();
        Ok(extended)
    }

    fn refresh_digest(&mut self) {
        let mut wire: mithril_control::EvidenceGap = self.clone().into();
        wire.gap_sha256.clear();
        self.gap_sha256 = mithril_control::evidence_gap_digest(&wire);
    }

    fn validate(&self) -> Result<()> {
        let cursor_count = self
            .last_cursor
            .checked_sub(self.first_cursor)
            .and_then(|span| span.checked_add(1));
        let mut wire: mithril_control::EvidenceGap = self.clone().into();
        wire.gap_sha256.clear();
        if self.node_boot_id == [0; 16]
            || self.source_id == [0; 16]
            || self.source_epoch == 0
            || self.first_cursor == 0
            || cursor_count != Some(self.discarded_records)
            || self.discarded_bytes == 0
            || self.last_record_sha256 == [0; 32]
            || self.gap_sha256 != mithril_control::evidence_gap_digest(&wire)
        {
            return EvidenceStateSnafu {
                reason: "evidence WAL gap identity, range, count, or digest is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

impl From<EvidenceRecordV1> for mithril_control::EvidenceRecord {
    fn from(record: EvidenceRecordV1) -> Self {
        Self {
            cursor: record.cursor,
            observation_id: record.observation_id.to_vec(),
            payload: record.payload,
            payload_sha256: record.payload_sha256.to_vec(),
            previous_record_sha256: record.previous_record_sha256.to_vec(),
            record_sha256: record.record_sha256.to_vec(),
        }
    }
}

impl From<EvidenceBatchV1> for mithril_control::EvidenceBatch {
    fn from(batch: EvidenceBatchV1) -> Self {
        Self {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            records: batch.records.into_iter().map(Into::into).collect(),
            batch_sha256: batch.batch_sha256.to_vec(),
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
            previous_record_sha256: gap.previous_record_sha256.to_vec(),
            last_record_sha256: gap.last_record_sha256.to_vec(),
            discarded_records: gap.discarded_records,
            discarded_bytes: gap.discarded_bytes,
            gap_sha256: gap.gap_sha256.to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAckV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub batch_sha256: EvidenceDigestV1,
}

impl TryFrom<mithril_control::EvidenceAck> for EvidenceAckV1 {
    type Error = crate::Error;

    fn try_from(ack: mithril_control::EvidenceAck) -> Result<Self> {
        Ok(Self {
            first_cursor: ack.first_cursor,
            last_cursor: ack.last_cursor,
            batch_sha256: ack.batch_sha256.try_into().map_err(|_| {
                EvidenceStateSnafu {
                    reason: "evidence acknowledgement digest is not SHA-256".to_owned(),
                }
                .build()
            })?,
        })
    }
}

impl TryFrom<mithril_control::EvidenceGapAck> for EvidenceGapAckV1 {
    type Error = crate::Error;

    fn try_from(ack: mithril_control::EvidenceGapAck) -> Result<Self> {
        Ok(Self {
            first_cursor: ack.first_cursor,
            last_cursor: ack.last_cursor,
            gap_sha256: ack.gap_sha256.try_into().map_err(|_| {
                EvidenceStateSnafu {
                    reason: "evidence gap acknowledgement digest is not SHA-256".to_owned(),
                }
                .build()
            })?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AckStateV1 {
    contiguous_cursor: u64,
    last_first_cursor: u64,
    last_batch_sha256: EvidenceDigestV1,
    last_record_sha256: EvidenceDigestV1,
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

    fn take_binary_u32(bytes: &mut &[u8], name: &str) -> Result<u32> {
        Ok(u32::from_be_bytes(Self::take_binary_array(bytes, name)?))
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
        let payload_len = u64::try_from(record.payload.len()).map_err(|_| {
            EvidenceStateSnafu {
                reason: "evidence WAL record payload size is not representable".to_owned(),
            }
            .build()
        })?;
        let mut payload = Vec::with_capacity(148_usize.saturating_add(record.payload.len()));
        payload.extend_from_slice(&record.format_version.to_be_bytes());
        payload.extend_from_slice(&record.cursor.to_be_bytes());
        payload.extend_from_slice(&record.observation_id);
        payload.extend_from_slice(&payload_len.to_be_bytes());
        payload.extend_from_slice(&record.payload);
        payload.extend_from_slice(&record.payload_sha256);
        payload.extend_from_slice(&record.previous_record_sha256);
        payload.extend_from_slice(&record.record_sha256);
        Self::encode_frame(WAL_FRAME_RECORD, &payload)
    }

    fn decode_record(bytes: &[u8]) -> Result<EvidenceRecordV1> {
        let name = "evidence WAL record";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_RECORD, name)?;
        let format_version = Self::take_binary_u32(&mut payload, name)?;
        let cursor = Self::take_binary_u64(&mut payload, name)?;
        let observation_id = Self::take_binary_array(&mut payload, name)?;
        let content_len =
            usize::try_from(Self::take_binary_u64(&mut payload, name)?).map_err(|_| {
                EvidenceStateSnafu {
                    reason: "evidence WAL record content size is not representable".to_owned(),
                }
                .build()
            })?;
        let content = Self::take_binary(&mut payload, content_len, name)?.to_vec();
        let payload_sha256 = Self::take_binary_array(&mut payload, name)?;
        let previous_record_sha256 = Self::take_binary_array(&mut payload, name)?;
        let record_sha256 = Self::take_binary_array(&mut payload, name)?;
        Self::finish_binary(payload, name)?;
        Ok(EvidenceRecordV1 {
            format_version,
            cursor,
            observation_id,
            payload: content,
            payload_sha256,
            previous_record_sha256,
            record_sha256,
        })
    }

    fn encode_ack(state: &AckStateV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(80);
        payload.extend_from_slice(&state.contiguous_cursor.to_be_bytes());
        payload.extend_from_slice(&state.last_first_cursor.to_be_bytes());
        payload.extend_from_slice(&state.last_batch_sha256);
        payload.extend_from_slice(&state.last_record_sha256);
        Self::encode_frame(WAL_FRAME_ACK, &payload)
    }

    fn decode_ack(bytes: &[u8]) -> Result<AckStateV1> {
        let name = "evidence acknowledgement state";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_ACK, name)?;
        let state = AckStateV1 {
            contiguous_cursor: Self::take_binary_u64(&mut payload, name)?,
            last_first_cursor: Self::take_binary_u64(&mut payload, name)?,
            last_batch_sha256: Self::take_binary_array(&mut payload, name)?,
            last_record_sha256: Self::take_binary_array(&mut payload, name)?,
        };
        Self::finish_binary(payload, name)?;
        Ok(state)
    }

    fn encode_gap(gap: &EvidenceGapV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(168);
        payload.extend_from_slice(&gap.node_boot_id);
        payload.extend_from_slice(&gap.source_id);
        payload.extend_from_slice(&gap.source_epoch.to_be_bytes());
        payload.extend_from_slice(&gap.first_cursor.to_be_bytes());
        payload.extend_from_slice(&gap.last_cursor.to_be_bytes());
        payload.extend_from_slice(&gap.previous_record_sha256);
        payload.extend_from_slice(&gap.last_record_sha256);
        payload.extend_from_slice(&gap.discarded_records.to_be_bytes());
        payload.extend_from_slice(&gap.discarded_bytes.to_be_bytes());
        payload.extend_from_slice(&gap.gap_sha256);
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
            previous_record_sha256: Self::take_binary_array(&mut payload, name)?,
            last_record_sha256: Self::take_binary_array(&mut payload, name)?,
            discarded_records: Self::take_binary_u64(&mut payload, name)?,
            discarded_bytes: Self::take_binary_u64(&mut payload, name)?,
            gap_sha256: Self::take_binary_array(&mut payload, name)?,
        };
        Self::finish_binary(payload, name)?;
        Ok(gap)
    }

    fn encode_stream(identity: EvidenceWalStreamIdentityV1) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&identity.node_boot_id);
        payload.extend_from_slice(&identity.source_id);
        payload.extend_from_slice(&identity.source_epoch.to_be_bytes());
        Self::encode_frame(WAL_FRAME_STREAM, &payload)
    }

    fn decode_stream(bytes: &[u8]) -> Result<EvidenceWalStreamIdentityV1> {
        let name = "evidence WAL stream identity";
        let mut payload = Self::decode_frame(bytes, WAL_FRAME_STREAM, name)?;
        let identity = EvidenceWalStreamIdentityV1 {
            node_boot_id: Self::take_binary_array(&mut payload, name)?,
            source_id: Self::take_binary_array(&mut payload, name)?,
            source_epoch: Self::take_binary_u64(&mut payload, name)?,
        };
        Self::finish_binary(payload, name)?;
        identity.validate()?;
        Ok(identity)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyMigrationV1 {
    format_version: u32,
    streams: BTreeMap<String, LegacyMigrationStreamV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyMigrationStreamV1 {
    pending_records: u64,
    last_record_sha256: EvidenceDigestV1,
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
        Self::migrate_legacy_streams(&root, limits)?;
        let mut streams = BTreeMap::new();
        let legacy = EvidenceWal::open(&root, limits)?;
        let legacy_is_populated = !legacy.records.is_empty()
            || legacy.acknowledged != AckStateV1::default()
            || legacy.gap.is_some()
            || legacy.stream_identity.is_some();
        if let Some(identity) = legacy.stream_identity {
            streams.insert(identity, legacy);
        } else if legacy_is_populated {
            return EvidenceStateSnafu {
                reason: "a populated flat evidence WAL has no recoverable stream identity"
                    .to_owned(),
            }
            .fail();
        }
        for entry in fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: &root })?
        {
            let path = entry.path();
            if !path.is_dir()
                && (path.file_name().and_then(|name| name.to_str()) == Some(ACK_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(GAP_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(STREAM_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(LEGACY_ACK_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(LEGACY_GAP_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(LEGACY_SOURCE_FILE)
                    || path.extension().and_then(|extension| extension.to_str()) == Some("wal"))
            {
                continue;
            }
            if !path.is_dir() {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL entry `{}` is not an owned stream file or directory",
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

    fn migrate_legacy_streams(root: &Path, limits: EvidenceWalLimits) -> Result<()> {
        if let Some(migration) = Self::read_legacy_migration(root)? {
            return Self::complete_legacy_migration(root, limits, &migration);
        }
        let legacy = EvidenceWal::open_unbound(root, limits)?;
        let mut observations =
            BTreeMap::<EvidenceWalStreamIdentityV1, Vec<ObservationEnvelopeV1>>::new();
        let mut observation_ids = BTreeSet::new();
        for record in &legacy.records {
            let observation = ObservationEnvelopeV1::from_wire_bytes(&record.payload)?;
            if !observation_ids.insert(observation.observation_id) {
                return EvidenceStateSnafu {
                    reason: "the flat evidence WAL repeats an observation identity".to_owned(),
                }
                .fail();
            }
            observations
                .entry(EvidenceWalStreamIdentityV1::from_observation(&observation)?)
                .or_default()
                .push(observation);
        }
        if observations.len() < 2 {
            return Ok(());
        }
        if legacy.gap.is_some() {
            return EvidenceStateSnafu {
                reason: "a multi-stream flat evidence WAL cannot migrate across a rewrite gap"
                    .to_owned(),
            }
            .fail();
        }
        if root
            .join(LEGACY_SOURCE_FILE)
            .try_exists()
            .context(IoSnafu {
                path: root.join(LEGACY_SOURCE_FILE),
            })?
        {
            return EvidenceStateSnafu {
                reason: "the multi-stream flat evidence WAL has a single-source marker".to_owned(),
            }
            .fail();
        }

        let mut streams = BTreeMap::new();
        for (identity, source_observations) in observations {
            let state = Self::publish_legacy_stream(root, limits, identity, &source_observations)?;
            streams.insert(identity.directory_name(), state);
        }
        let migration = LegacyMigrationV1 {
            format_version: LEGACY_MIGRATION_FORMAT_VERSION,
            streams,
        };
        let bytes = serde_json::to_vec(&migration).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("legacy evidence WAL migration encoding failed: {error}"),
            }
            .build()
        })?;
        // The marker switches recovery to the complete per-source layout. The
        // flat files stay authoritative until this durable write succeeds.
        atomic_write(&root.join(LEGACY_MIGRATION_FILE), &bytes)?;
        Self::complete_legacy_migration(root, limits, &migration)
    }

    fn publish_legacy_stream(
        root: &Path,
        limits: EvidenceWalLimits,
        identity: EvidenceWalStreamIdentityV1,
        observations: &[ObservationEnvelopeV1],
    ) -> Result<LegacyMigrationStreamV1> {
        let stream = identity.directory_name();
        let final_path = root.join(&stream);
        let staging_path = root.join(format!(".legacy-migration-{stream}"));
        let final_exists = match fs::symlink_metadata(&final_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(crate::Error::Io {
                    path: final_path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        };
        let staging_exists = match fs::symlink_metadata(&staging_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(crate::Error::Io {
                    path: staging_path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        };
        if final_exists {
            if staging_exists {
                return EvidenceStateSnafu {
                    reason: format!(
                        "legacy evidence WAL migration has both staged and published stream `{stream}`"
                    ),
                }
                .fail();
            }
            let wal = EvidenceWal::open(&final_path, limits)?;
            Self::validate_legacy_stream(&wal, observations, false)?;
            return Self::legacy_migration_stream_state(&wal);
        }

        let mut wal = EvidenceWal::open(&staging_path, limits)?;
        let retained = Self::validate_legacy_stream(&wal, observations, true)?;
        for observation in &observations[retained..] {
            wal.append(observation)?;
        }
        let state = Self::legacy_migration_stream_state(&wal)?;
        drop(wal);
        sync_directory(&staging_path)?;
        sync_directory(root)?;
        fs::rename(&staging_path, &final_path).context(IoSnafu { path: &final_path })?;
        sync_directory(root)?;
        Ok(state)
    }

    fn validate_legacy_stream(
        wal: &EvidenceWal,
        observations: &[ObservationEnvelopeV1],
        allow_prefix: bool,
    ) -> Result<usize> {
        if wal.acknowledged != AckStateV1::default()
            || wal.records.len() > observations.len()
            || (!allow_prefix && wal.records.len() != observations.len())
        {
            return EvidenceStateSnafu {
                reason: "legacy evidence WAL migration stream has inconsistent progress".to_owned(),
            }
            .fail();
        }
        for (record, observation) in wal.records.iter().zip(observations) {
            if record.observation_id != observation.observation_id
                || record.payload != observation.wire_bytes()?
            {
                return EvidenceStateSnafu {
                    reason: "legacy evidence WAL migration stream changed observation identity or payload"
                        .to_owned(),
                }
                .fail();
            }
        }
        Ok(wal.records.len())
    }

    fn legacy_migration_stream_state(wal: &EvidenceWal) -> Result<LegacyMigrationStreamV1> {
        let last_record_sha256 = wal
            .records
            .last()
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "legacy evidence WAL migration produced an empty stream".to_owned(),
                }
                .build()
            })?
            .record_sha256;
        Ok(LegacyMigrationStreamV1 {
            pending_records: u64::try_from(wal.records.len()).map_err(|_| {
                EvidenceStateSnafu {
                    reason: "legacy evidence WAL migration record count is not representable"
                        .to_owned(),
                }
                .build()
            })?,
            last_record_sha256,
        })
    }

    fn read_legacy_migration(root: &Path) -> Result<Option<LegacyMigrationV1>> {
        let path = root.join(LEGACY_MIGRATION_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        };
        let migration = serde_json::from_slice(&bytes).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("legacy evidence WAL migration state is invalid: {error}"),
            }
            .build()
        })?;
        Ok(Some(migration))
    }

    fn complete_legacy_migration(
        root: &Path,
        limits: EvidenceWalLimits,
        migration: &LegacyMigrationV1,
    ) -> Result<()> {
        if migration.format_version != LEGACY_MIGRATION_FORMAT_VERSION
            || migration.streams.len() < 2
        {
            return EvidenceStateSnafu {
                reason: "legacy evidence WAL migration state has an invalid format or stream count"
                    .to_owned(),
            }
            .fail();
        }
        let mut observation_ids = BTreeSet::new();
        for (stream, expected) in &migration.streams {
            let path = root.join(stream);
            let identity = parse_stream_directory_name(stream, &path)?;
            let wal = EvidenceWal::open(&path, limits)?;
            if wal.acknowledged != AckStateV1::default()
                || Self::legacy_migration_stream_state(&wal)? != *expected
                || wal.stream_identity != Some(identity)
                || wal
                    .records
                    .iter()
                    .any(|record| record.stream_identity().ok() != Some(identity))
                || wal
                    .records
                    .iter()
                    .any(|record| !observation_ids.insert(record.observation_id))
            {
                return EvidenceStateSnafu {
                    reason: format!(
                        "legacy evidence WAL migration stream `{stream}` is incomplete or inconsistent"
                    ),
                }
                .fail();
            }
        }

        for entry in fs::read_dir(root)
            .context(IoSnafu { path: root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: root })?
        {
            let path = entry.path();
            let name = path.file_name().and_then(|name| name.to_str());
            if name == Some(ACK_FILE)
                || name == Some(GAP_FILE)
                || name == Some(STREAM_FILE)
                || name == Some(LEGACY_ACK_FILE)
                || name == Some(LEGACY_GAP_FILE)
                || name == Some(LEGACY_SOURCE_FILE)
            {
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("wal") {
                segment_cursor(&path)?;
                fs::remove_file(&path).context(IoSnafu { path: &path })?;
            }
        }
        sync_directory(root)?;
        let migration_path = root.join(LEGACY_MIGRATION_FILE);
        fs::remove_file(&migration_path).context(IoSnafu {
            path: &migration_path,
        })?;
        sync_directory(root)
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
                wal.rewrite_candidate(in_flight).map(|record| {
                    (
                        ObservationEnvelopeV1::from_wire_bytes(&record.payload)
                            .map_or(i64::MAX, |observation| observation.ingested_utc_ns),
                        *source_id,
                        record.cursor,
                    )
                })
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
    name == identity.directory_name() || name == hex::encode(identity.source_id)
}

fn parse_stream_directory_name(value: &str, path: &Path) -> Result<EvidenceWalStreamIdentityV1> {
    let mut fields = value.split('-');
    let source = fields.next().unwrap_or_default();
    let epoch = fields.next().unwrap_or_default();
    let boot = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || epoch.len() != 20
        || !epoch.bytes().all(|byte| byte.is_ascii_digit())
    {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL stream identity `{}` is invalid",
                path.display()
            ),
        }
        .fail();
    }
    let identity = EvidenceWalStreamIdentityV1 {
        node_boot_id: parse_id128(boot, path, "boot")?,
        source_id: parse_source_id(source, path)?,
        source_epoch: epoch.parse().map_err(|error| {
            EvidenceStateSnafu {
                reason: format!(
                    "evidence WAL stream epoch `{}` is invalid: {error}",
                    path.display()
                ),
            }
            .build()
        })?,
    };
    identity.validate()?;
    Ok(identity)
}

fn parse_source_id(value: &str, path: &Path) -> Result<[u8; 16]> {
    parse_id128(value, path, "source")
}

fn parse_id128(value: &str, path: &Path, name: &str) -> Result<[u8; 16]> {
    let identity: Option<[u8; 16]> = hex::decode(value)
        .ok()
        .and_then(|decoded| decoded.try_into().ok());
    let Some(identity) = identity else {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL {name} identity `{}` is invalid",
                path.display()
            ),
        }
        .fail();
    };
    if value.len() != 32 || hex::encode(identity) != value {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL {name} identity `{}` is invalid",
                path.display()
            ),
        }
        .fail();
    }
    Ok(identity)
}

impl EvidenceWal {
    pub fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        Self::open_inner(root.into(), limits, true)
    }

    fn open_unbound(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        Self::open_inner(root.into(), limits, false)
    }

    fn open_inner(
        root: PathBuf,
        limits: EvidenceWalLimits,
        enforce_stream_identity: bool,
    ) -> Result<Self> {
        limits.validate()?;
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let persisted_stream_identity = read_stream_identity(&root)?;
        let acknowledged = read_ack(&root)?;
        let gap = read_gap(&root, acknowledged)?;
        let mut paths = recover_directory(&root, acknowledged, gap.as_ref())?;
        paths.sort_unstable();

        let mut records = Vec::with_capacity(paths.len());
        let mut previous = acknowledged.last_record_sha256;
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
            let (record, migrated_bytes) = if bytes.starts_with(&WAL_FRAME_MAGIC) {
                (EvidenceWalCodecV1::decode_record(&bytes)?, None)
            } else {
                let record = serde_json::from_slice(&bytes).map_err(|error| {
                    EvidenceStateSnafu {
                        reason: format!(
                            "evidence WAL segment `{}` is neither valid binary nor legacy JSON: {error}",
                            path.display()
                        ),
                    }
                    .build()
                })?;
                let encoded = EvidenceWalCodecV1::encode_record(&record)?;
                if encoded.len() as u64 > limits.maximum_record_bytes {
                    return EvidenceStateSnafu {
                        reason: format!(
                            "migrated evidence WAL segment `{}` exceeds the record bound",
                            path.display()
                        ),
                    }
                    .fail();
                }
                (record, Some(encoded))
            };
            if let Some(gap) = &gap {
                apply_gap_boundary(gap, &mut expected_cursor, &mut previous, record.cursor)?;
            }
            record.validate(expected_cursor, previous)?;
            let stored_bytes = if let Some(migrated_bytes) = migrated_bytes {
                atomic_write(&path, &migrated_bytes)?;
                migrated_bytes.len()
            } else {
                bytes.len()
            };
            retained_bytes = retained_bytes
                .checked_add(stored_bytes as u64)
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "evidence WAL retained byte count overflowed".to_owned(),
                    }
                    .build()
                })?;
            previous = record.record_sha256;
            expected_cursor = expected_cursor.checked_add(1).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL cursor is exhausted".to_owned(),
                }
                .build()
            })?;
            records.push(record);
        }
        if let Some(gap) = &gap {
            apply_gap_boundary(gap, &mut expected_cursor, &mut previous, u64::MAX)?;
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
        let derived_stream_identity = enforce_stream_identity
            .then(|| derive_stream_identity(&records, gap.as_ref()))
            .transpose()?
            .flatten();
        let stream_identity = match (persisted_stream_identity, derived_stream_identity) {
            (Some(persisted), Some(derived)) if persisted != derived => {
                return EvidenceStateSnafu {
                    reason: "evidence WAL records do not match their durable stream identity"
                        .to_owned(),
                }
                .fail();
            }
            (Some(persisted), _) => Some(persisted),
            (None, derived) if enforce_stream_identity => {
                if let Some(identity) = derived {
                    atomic_write(
                        &root.join(STREAM_FILE),
                        &EvidenceWalCodecV1::encode_stream(identity)?,
                    )?;
                }
                derived
            }
            (None, _derived) => None,
        };
        Ok(Self {
            root,
            limits,
            stream_identity,
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

    #[cfg(test)]
    fn append_legacy_unbound(&mut self, observation: &ObservationEnvelopeV1) -> Result<u64> {
        self.append_classified_inner(observation, false)
            .map_err(|failure| *failure.error)
    }

    pub(super) fn append_classified(
        &mut self,
        observation: &ObservationEnvelopeV1,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        self.append_classified_inner(observation, true)
    }

    fn append_classified_inner(
        &mut self,
        observation: &ObservationEnvelopeV1,
        enforce_stream_identity: bool,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        if enforce_stream_identity {
            let identity = EvidenceWalStreamIdentityV1::from_observation(observation)?;
            match self.stream_identity {
                Some(current) if current != identity => {
                    return Err(EvidenceStateSnafu {
                        reason:
                            "evidence WAL append crossed a boot, source, or source-epoch boundary"
                                .to_owned(),
                    }
                    .build()
                    .into());
                }
                Some(_) => {}
                None if self.acknowledged != AckStateV1::default() => {
                    return Err(EvidenceStateSnafu {
                        reason: "acknowledged legacy evidence WAL has no durable stream identity"
                            .to_owned(),
                    }
                    .build()
                    .into());
                }
                None => {
                    atomic_write(
                        &self.root.join(STREAM_FILE),
                        &EvidenceWalCodecV1::encode_stream(identity)?,
                    )?;
                    self.stream_identity = Some(identity);
                }
            }
        }
        let record_tail = self
            .records
            .last()
            .map(|record| (record.cursor, record.record_sha256));
        let gap_tail = self
            .gap
            .as_ref()
            .map(|gap| (gap.last_cursor, gap.last_record_sha256));
        let (tail_cursor, previous) = record_tail
            .into_iter()
            .chain(gap_tail)
            .max_by_key(|(cursor, _digest)| *cursor)
            .unwrap_or((
                self.acknowledged.contiguous_cursor,
                self.acknowledged.last_record_sha256,
            ));
        let cursor = tail_cursor.checked_add(1).ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence WAL cursor is exhausted".to_owned(),
            }
            .build()
        })?;
        let record = EvidenceRecordV1::new(cursor, observation, previous)?;
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
        let mut records = Vec::new();
        let mut wire = mithril_control::EvidenceBatch {
            first_cursor,
            last_cursor: first_cursor,
            records: Vec::new(),
            batch_sha256: vec![0; 32],
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
            wire.last_cursor = record.cursor;
            wire.records.push(record.clone().into());
            if wire.encoded_len() > mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES {
                records.pop();
                break;
            }
        }
        let last_cursor = records.last()?.cursor;
        let batch_sha256 = EvidenceBatchV1::digest(&records);
        Some(EvidenceBatchV1 {
            first_cursor,
            last_cursor,
            records,
            batch_sha256,
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
            None => EvidenceGapV1::from_record(record, discarded_bytes)?,
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
        if ack.first_cursor == self.acknowledged.last_first_cursor
            && ack.last_cursor == self.acknowledged.contiguous_cursor
            && ack.batch_sha256 == self.acknowledged.last_batch_sha256
        {
            return Ok(());
        }
        let Some(batch) = self.next_batch() else {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement has no pending batch".to_owned(),
            }
            .fail();
        };
        self.acknowledge_batch(ack, &batch)
    }

    fn acknowledge_batch(&mut self, ack: EvidenceAckV1, batch: &EvidenceBatchV1) -> Result<()> {
        if ack.first_cursor != batch.first_cursor
            || ack.last_cursor != batch.last_cursor
            || ack.batch_sha256 != batch.batch_sha256
        {
            return EvidenceStateSnafu {
                reason: "evidence acknowledgement does not match the pending contiguous batch"
                    .to_owned(),
            }
            .fail();
        }
        if self.records.get(..batch.records.len()) != Some(batch.records.as_slice()) {
            return EvidenceStateSnafu {
                reason: "the in-flight evidence batch is not a retained WAL prefix".to_owned(),
            }
            .fail();
        }
        let state = AckStateV1 {
            contiguous_cursor: ack.last_cursor,
            last_first_cursor: ack.first_cursor,
            last_batch_sha256: ack.batch_sha256,
            last_record_sha256: batch
                .records
                .last()
                .map_or(self.acknowledged.last_record_sha256, |record| {
                    record.record_sha256
                }),
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

    fn acknowledge_gap(&mut self, ack: EvidenceGapAckV1, gap: &EvidenceGapV1) -> Result<()> {
        if ack.first_cursor != gap.first_cursor
            || ack.last_cursor != gap.last_cursor
            || ack.gap_sha256 != gap.gap_sha256
            || self.gap.as_ref() != Some(gap)
        {
            return EvidenceStateSnafu {
                reason: "evidence gap acknowledgement does not match the pending durable gap"
                    .to_owned(),
            }
            .fail();
        }
        let state = AckStateV1 {
            contiguous_cursor: gap.last_cursor,
            last_first_cursor: gap.first_cursor,
            last_batch_sha256: gap.gap_sha256,
            last_record_sha256: gap.last_record_sha256,
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

fn derive_stream_identity(
    records: &[EvidenceRecordV1],
    gap: Option<&EvidenceGapV1>,
) -> Result<Option<EvidenceWalStreamIdentityV1>> {
    let mut identity = gap.map(EvidenceGapV1::stream_identity).transpose()?;
    for record in records {
        let record_identity = record.stream_identity()?;
        if identity.is_some_and(|current| current != record_identity) {
            return EvidenceStateSnafu {
                reason: "one evidence WAL contains more than one stream identity".to_owned(),
            }
            .fail();
        }
        identity = Some(record_identity);
    }
    Ok(identity)
}

fn read_stream_identity(root: &Path) -> Result<Option<EvidenceWalStreamIdentityV1>> {
    read_optional_file(&root.join(STREAM_FILE))?
        .map(|bytes| EvidenceWalCodecV1::decode_stream(&bytes))
        .transpose()
}

fn read_ack(root: &Path) -> Result<AckStateV1> {
    let path = root.join(ACK_FILE);
    let legacy_path = root.join(LEGACY_ACK_FILE);
    let binary = read_optional_file(&path)?
        .map(|bytes| EvidenceWalCodecV1::decode_ack(&bytes))
        .transpose()?;
    let legacy = read_optional_file(&legacy_path)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|error| {
                EvidenceStateSnafu {
                    reason: format!("legacy evidence acknowledgement state is invalid: {error}"),
                }
                .build()
            })
        })
        .transpose()?;
    if binary.is_some() && legacy.is_some() && binary != legacy {
        return EvidenceStateSnafu {
            reason: "binary and legacy evidence acknowledgement states conflict".to_owned(),
        }
        .fail();
    }
    let state = binary.or(legacy).unwrap_or_default();
    validate_ack(&state)?;
    if binary.is_none() && legacy.is_some() {
        atomic_write(&path, &EvidenceWalCodecV1::encode_ack(&state)?)?;
    }
    if legacy.is_some() {
        fs::remove_file(&legacy_path).context(IoSnafu { path: &legacy_path })?;
        sync_directory(root)?;
    }
    Ok(state)
}

fn validate_ack(state: &AckStateV1) -> Result<()> {
    let empty = *state == AckStateV1::default();
    let populated = state.contiguous_cursor > 0
        && state.last_first_cursor > 0
        && state.last_first_cursor <= state.contiguous_cursor
        && state.last_batch_sha256 != [0; 32]
        && state.last_record_sha256 != [0; 32];
    if !empty && !populated {
        return EvidenceStateSnafu {
            reason: "evidence acknowledgement state has inconsistent cursors or digests".to_owned(),
        }
        .fail();
    }
    Ok(())
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
    let legacy_path = root.join(LEGACY_GAP_FILE);
    let binary = read_optional_file(&path)?
        .map(|bytes| EvidenceWalCodecV1::decode_gap(&bytes))
        .transpose()?;
    let legacy = read_optional_file(&legacy_path)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|error| {
                EvidenceStateSnafu {
                    reason: format!("legacy evidence WAL gap is invalid: {error}"),
                }
                .build()
            })
        })
        .transpose()?;
    if binary.is_some() && legacy.is_some() && binary != legacy {
        return EvidenceStateSnafu {
            reason: "binary and legacy evidence WAL gaps conflict".to_owned(),
        }
        .fail();
    }
    let Some(gap) = binary.clone().or(legacy.clone()) else {
        return Ok(None);
    };
    gap.validate()?;
    if gap.last_cursor <= acknowledged.contiguous_cursor {
        remove_optional_file(&path)?;
        remove_optional_file(&legacy_path)?;
        sync_directory(root)?;
        return Ok(None);
    }
    if gap.first_cursor <= acknowledged.contiguous_cursor {
        return EvidenceStateSnafu {
            reason: "evidence WAL gap overlaps its acknowledged cursor".to_owned(),
        }
        .fail();
    }
    if binary.is_none() {
        atomic_write(&path, &EvidenceWalCodecV1::encode_gap(&gap)?)?;
    }
    if legacy.is_some() {
        fs::remove_file(&legacy_path).context(IoSnafu { path: &legacy_path })?;
        sync_directory(root)?;
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
    previous: &mut EvidenceDigestV1,
    next_record_cursor: u64,
) -> Result<()> {
    if *expected_cursor != gap.first_cursor || next_record_cursor <= gap.last_cursor {
        return Ok(());
    }
    if *previous != gap.previous_record_sha256 {
        return EvidenceStateSnafu {
            reason: "evidence WAL gap does not continue its retained hash chain".to_owned(),
        }
        .fail();
    }
    *expected_cursor = gap.last_cursor.checked_add(1).ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "evidence WAL gap exhausted its cursor".to_owned(),
        }
        .build()
    })?;
    *previous = gap.last_record_sha256;
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
    use prost::Message as _;

    use super::{
        segment_path, AckStateV1, EvidenceAckV1, EvidenceGapAckV1, EvidenceRecordV1,
        EvidenceUploadAckV1, EvidenceUploadV1, EvidenceWal, EvidenceWalCapacityPolicyV1,
        EvidenceWalLimits, EvidenceWalOwner, EvidenceWalStreamIdentityV1, ACK_FILE, GAP_FILE,
        LEGACY_ACK_FILE, LEGACY_GAP_FILE, STREAM_FILE, WAL_FORMAT_VERSION, WAL_FRAME_MAGIC,
    };
    use crate::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn kernel_observation(sequence: u64) -> crate::Result<crate::ObservationEnvelopeV1> {
        kernel_observation_for_cpu(sequence, 1)
    }

    fn kernel_observation_for_cpu(
        sequence: u64,
        cpu_id: u32,
    ) -> crate::Result<crate::ObservationEnvelopeV1> {
        kernel_observation_for_stream(sequence, cpu_id, 5, EvidenceIdV1::new(6, 7))
    }

    fn kernel_observation_for_stream(
        sequence: u64,
        cpu_id: u32,
        source_epoch: u64,
        node_boot_id: EvidenceIdV1,
    ) -> crate::Result<crate::ObservationEnvelopeV1> {
        let canonicalizer = ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            source_epoch,
            node_boot_id,
        )?;
        canonicalizer.normalize_kernel(
            erebor_interceptor_abi::EffectObservationV1 {
                source_sequence: sequence,
                source_cpu_id: cpu_id,
                task_cookie: 10,
                reason: 9,
                physical_result: 1,
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
    fn wal_replays_and_removes_only_an_exact_acknowledged_prefix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&kernel_observation(1)?)?;
        wal.append(&kernel_observation(2)?)?;
        wal.append(&kernel_observation(3)?)?;
        let batch = wal.next_batch().ok_or("test batch is missing")?;
        assert_eq!((batch.first_cursor, batch.last_cursor), (1, 2));
        assert!(wal
            .acknowledge(EvidenceAckV1 {
                first_cursor: 1,
                last_cursor: 2,
                batch_sha256: [9; 32],
            })
            .is_err());
        let first_path = segment_path(directory.path(), 1);
        std::fs::remove_file(&first_path)?;
        wal.acknowledge(EvidenceAckV1 {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch.batch_sha256,
        })?;
        drop(wal);
        let wal = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(wal.acknowledged_cursor(), 2);
        assert_eq!(wal.pending_records(), 1);
        assert_eq!(
            wal.retained_bytes(),
            std::fs::metadata(segment_path(directory.path(), 3))?.len()
        );
        assert_eq!(wal.next_batch().map(|batch| batch.first_cursor), Some(3));
        Ok(())
    }

    #[test]
    fn wal_refuses_corruption_and_retention_exhaustion() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        for sequence in 1..=4 {
            wal.append(&kernel_observation(sequence)?)?;
        }
        assert!(wal.append(&kernel_observation(5)?).is_err());
        drop(wal);
        let path = directory.path().join("00000000000000000002.wal");
        let mut bytes = std::fs::read(&path)?;
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(&path, bytes)?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn wal_migrates_legacy_json_state_to_checksummed_binary_frames(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let first = EvidenceRecordV1::new(1, &kernel_observation(1)?, [0; 32])?;
        let first_json = serde_json::to_vec(&first)?;
        let gap = super::EvidenceGapV1::from_record(&first, first_json.len() as u64)?;
        let second = EvidenceRecordV1::new(2, &kernel_observation(2)?, first.record_sha256)?;
        let second_path = segment_path(directory.path(), second.cursor);
        std::fs::write(&second_path, serde_json::to_vec(&second)?)?;
        std::fs::write(
            directory.path().join(LEGACY_ACK_FILE),
            serde_json::to_vec(&AckStateV1::default())?,
        )?;
        std::fs::write(
            directory.path().join(LEGACY_GAP_FILE),
            serde_json::to_vec(&gap)?,
        )?;

        let wal = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(wal.pending_records(), 1);
        assert_eq!(wal.next_upload(), Some(EvidenceUploadV1::Gap(gap)));
        for path in [
            second_path,
            directory.path().join(ACK_FILE),
            directory.path().join(GAP_FILE),
            directory.path().join(STREAM_FILE),
        ] {
            let bytes = std::fs::read(path)?;
            assert!(bytes.starts_with(&WAL_FRAME_MAGIC));
            assert!(!bytes.starts_with(b"{"));
        }
        assert!(!directory.path().join(LEGACY_ACK_FILE).exists());
        assert!(!directory.path().join(LEGACY_GAP_FILE).exists());
        drop(wal);

        let wal = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(wal.pending_records(), 1);
        assert!(matches!(wal.next_upload(), Some(EvidenceUploadV1::Gap(_))));
        Ok(())
    }

    #[test]
    fn rewrite_policy_persists_and_delivers_an_exact_gap_before_later_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let rewrite_limits = EvidenceWalLimits {
            maximum_retained_records: 3,
            maximum_batch_records: 1,
            capacity_policy: EvidenceWalCapacityPolicyV1::Rewrite,
            ..limits()
        };
        let mut owner = EvidenceWalOwner::open(directory.path(), rewrite_limits)?;
        for sequence in 1..=3 {
            let appended = owner
                .append_classified(&kernel_observation(sequence)?)
                .map_err(|failure| failure.error)?;
            assert_eq!(appended.rewrite.discarded_records, 0);
        }
        let Some(EvidenceUploadV1::Batch(in_flight)) = owner.next_upload() else {
            return Err("the first retry batch is missing".into());
        };
        assert_eq!((in_flight.first_cursor, in_flight.last_cursor), (1, 1));
        let appended = owner
            .append_classified(&kernel_observation(4)?)
            .map_err(|failure| failure.error)?;
        assert_eq!(appended.rewrite.discarded_records, 1);
        let identity = EvidenceWalStreamIdentityV1::from_observation(&kernel_observation(1)?)?;
        let stream = owner
            .streams
            .get(&identity)
            .ok_or("rewritten source stream missing")?
            .root
            .clone();
        assert!(stream.join(GAP_FILE).exists());
        assert!(!segment_path(&stream, 2).exists());
        drop(owner);

        let mut replayed = EvidenceWalOwner::open(directory.path(), rewrite_limits)?;
        let EvidenceUploadV1::Batch(first) = replayed.next_upload().ok_or("first batch missing")?
        else {
            return Err("the gap crossed the protected retry batch".into());
        };
        assert_eq!((first.first_cursor, first.last_cursor), (1, 1));
        replayed.acknowledge_upload(EvidenceUploadAckV1::Batch(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        }))?;
        let EvidenceUploadV1::Gap(gap) = replayed.next_upload().ok_or("gap missing")? else {
            return Err("later evidence crossed the durable gap".into());
        };
        assert_eq!((gap.first_cursor, gap.last_cursor), (2, 2));
        assert_eq!(gap.discarded_records, 1);
        replayed.acknowledge_upload(EvidenceUploadAckV1::Gap(EvidenceGapAckV1 {
            first_cursor: gap.first_cursor,
            last_cursor: gap.last_cursor,
            gap_sha256: gap.gap_sha256,
        }))?;
        assert!(!stream.join(GAP_FILE).exists());
        let EvidenceUploadV1::Batch(later) = replayed.next_upload().ok_or("later batch missing")?
        else {
            return Err("the acknowledged gap did not release later evidence".into());
        };
        assert_eq!((later.first_cursor, later.last_cursor), (3, 3));
        Ok(())
    }

    #[test]
    fn rewrite_policy_replaces_the_oldest_record_without_an_in_flight_batch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let rewrite_limits = EvidenceWalLimits {
            maximum_retained_records: 2,
            maximum_batch_records: 2,
            capacity_policy: EvidenceWalCapacityPolicyV1::Rewrite,
            ..limits()
        };
        let mut owner = EvidenceWalOwner::open(directory.path(), rewrite_limits)?;
        for sequence in 1..=2 {
            owner
                .append_classified(&kernel_observation(sequence)?)
                .map_err(|failure| failure.error)?;
        }

        let appended = owner
            .append_classified(&kernel_observation(3)?)
            .map_err(|failure| failure.error)?;
        assert_eq!(appended.rewrite.discarded_records, 1);
        let Some(EvidenceUploadV1::Gap(gap)) = owner.next_upload() else {
            return Err("the oldest rewritten range is missing".into());
        };
        assert_eq!((gap.first_cursor, gap.last_cursor), (1, 1));
        assert_eq!(gap.discarded_records, 1);
        Ok(())
    }

    #[test]
    fn wal_recovers_acknowledged_residue_and_owned_torn_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&kernel_observation(1)?)?;
        wal.append(&kernel_observation(2)?)?;
        let first_path = segment_path(directory.path(), 1);
        let first_bytes = std::fs::read(&first_path)?;
        let batch = wal.next_batch().ok_or("test batch is missing")?;
        let ack = EvidenceAckV1 {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch.batch_sha256,
        };
        wal.acknowledge(ack)?;
        assert!(wal
            .acknowledge(EvidenceAckV1 {
                first_cursor: 2,
                ..ack
            })
            .is_err());
        wal.acknowledge(ack)?;
        drop(wal);

        std::fs::write(&first_path, first_bytes)?;
        let segment_temporary = segment_path(directory.path(), 3).with_extension("tmp");
        std::fs::write(&segment_temporary, b"torn segment")?;
        let ack_temporary = directory.path().join(ACK_FILE).with_extension("tmp");
        std::fs::write(&ack_temporary, b"torn ack")?;

        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(wal.acknowledged_cursor(), 2);
        assert_eq!(wal.pending_records(), 0);
        assert!(!first_path.exists());
        assert!(!segment_temporary.exists());
        assert!(!ack_temporary.exists());
        assert_eq!(wal.append(&kernel_observation(3)?)?, 3);
        Ok(())
    }

    #[test]
    fn wal_owner_recovers_and_acknowledges_each_source_independently(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        owner
            .append_classified(&kernel_observation_for_cpu(1, 0)?)
            .map_err(|failure| failure.error)?;
        owner
            .append_classified(&kernel_observation_for_cpu(1, 1)?)
            .map_err(|failure| failure.error)?;
        owner
            .append_classified(&kernel_observation_for_cpu(2, 0)?)
            .map_err(|failure| failure.error)?;

        let first = owner.next_batch().ok_or("first source batch is missing")?;
        let first_source = first.records[0].stream_identity()?.source_id;
        assert!(first.records.iter().all(|record| record
            .stream_identity()
            .map(|value| value.source_id)
            .ok()
            == Some(first_source)));
        drop(owner);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        assert_eq!(owner.next_batch(), Some(first.clone()));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        })?;
        let second = owner.next_batch().ok_or("second source batch is missing")?;
        let second_source = second.records[0].stream_identity()?.source_id;
        assert_ne!(second_source, first_source);
        assert!(second.records.iter().all(|record| record
            .stream_identity()
            .map(|value| value.source_id)
            .ok()
            == Some(second_source)));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: second.first_cursor,
            last_cursor: second.last_cursor,
            batch_sha256: second.batch_sha256,
        })?;
        assert!(owner.next_batch().is_none());
        Ok(())
    }

    #[test]
    fn wal_owner_starts_a_new_cursor_chain_for_a_new_physical_epoch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        let prior = kernel_observation_for_stream(1, 0, 5, EvidenceIdV1::new(6, 7))?;
        let current = kernel_observation_for_stream(1, 0, 6, EvidenceIdV1::new(6, 8))?;
        assert_eq!(
            owner
                .append_classified(&prior)
                .map_err(|failure| failure.error)?
                .cursor,
            1
        );
        assert_eq!(
            owner
                .append_classified(&current)
                .map_err(|failure| failure.error)?
                .cursor,
            1
        );
        assert_eq!(owner.streams.len(), 2);
        drop(owner);

        let mut reopened = EvidenceWalOwner::open(directory.path(), limits())?;
        let first = reopened
            .next_batch()
            .ok_or("prior stream batch is missing")?;
        assert_eq!((first.first_cursor, first.last_cursor), (1, 1));
        assert_eq!(first.records[0].previous_record_sha256, [0; 32]);
        reopened.acknowledge(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        })?;
        let second = reopened
            .next_batch()
            .ok_or("current stream batch is missing")?;
        assert_eq!((second.first_cursor, second.last_cursor), (1, 1));
        assert_eq!(second.records[0].previous_record_sha256, [0; 32]);
        assert_ne!(
            first.records[0].stream_identity()?,
            second.records[0].stream_identity()?
        );
        Ok(())
    }

    #[test]
    fn wal_owner_reuses_the_exact_in_flight_batch_until_acknowledgement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        owner
            .append_classified(&kernel_observation_for_cpu(1, 0)?)
            .map_err(|failure| failure.error)?;
        let first = owner.next_batch().ok_or("first batch is missing")?;

        owner
            .append_classified(&kernel_observation_for_cpu(2, 0)?)
            .map_err(|failure| failure.error)?;

        assert_eq!(owner.next_batch(), Some(first.clone()));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        })?;
        assert_eq!(
            owner
                .next_batch()
                .map(|batch| (batch.first_cursor, batch.last_cursor)),
            Some((2, 2))
        );
        assert!(owner
            .acknowledge(EvidenceAckV1 {
                first_cursor: first.first_cursor,
                last_cursor: first.last_cursor,
                batch_sha256: first.batch_sha256,
            })
            .is_err());
        assert_eq!(
            owner
                .next_batch()
                .map(|batch| (batch.first_cursor, batch.last_cursor)),
            Some((2, 2))
        );
        Ok(())
    }

    #[test]
    fn wal_owner_preserves_a_flat_single_source_wal() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut legacy = EvidenceWal::open(directory.path(), limits())?;
        legacy.append(&kernel_observation_for_cpu(1, 0)?)?;
        let expected = legacy.next_batch().ok_or("legacy batch is missing")?;
        drop(legacy);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        assert_eq!(owner.next_batch(), Some(expected.clone()));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: expected.first_cursor,
            last_cursor: expected.last_cursor,
            batch_sha256: expected.batch_sha256,
        })?;
        drop(owner);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        owner
            .append_classified(&kernel_observation_for_cpu(2, 0)?)
            .map_err(|failure| failure.error)?;
        let continued = owner.next_batch().ok_or("continued batch is missing")?;
        assert_eq!((continued.first_cursor, continued.last_cursor), (2, 2));
        assert_eq!(
            continued.records[0].stream_identity()?.source_id,
            expected.records[0].stream_identity()?.source_id
        );
        Ok(())
    }

    #[test]
    fn wal_owner_migrates_all_sources_from_a_flat_wal_before_acknowledgement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let observations = [
            kernel_observation_for_cpu(1, 0)?,
            kernel_observation_for_cpu(1, 1)?,
            kernel_observation_for_cpu(2, 0)?,
            kernel_observation_for_cpu(2, 1)?,
        ];
        let expected_ids = observations
            .iter()
            .map(|observation| observation.observation_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut legacy = EvidenceWal::open(directory.path(), limits())?;
        legacy.append_legacy_unbound(&kernel_observation_for_cpu(1, 2)?)?;
        legacy.append_legacy_unbound(&kernel_observation_for_cpu(2, 2)?)?;
        let acknowledged = legacy
            .next_batch()
            .ok_or("legacy acknowledged batch is missing")?;
        legacy.acknowledge(EvidenceAckV1 {
            first_cursor: acknowledged.first_cursor,
            last_cursor: acknowledged.last_cursor,
            batch_sha256: acknowledged.batch_sha256,
        })?;
        for observation in &observations {
            legacy.append_legacy_unbound(observation)?;
        }
        drop(legacy);

        // This is the durable state after one stream rename and before the marker write.
        let published_stream = EvidenceWalStreamIdentityV1::from_observation(&observations[0])?;
        let mut published = EvidenceWal::open(
            directory.path().join(published_stream.directory_name()),
            limits(),
        )?;
        published.append(&observations[0])?;
        published.append(&observations[2])?;
        drop(published);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        let stream_entries =
            std::fs::read_dir(directory.path())?.collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(stream_entries.len(), 2);
        assert!(stream_entries
            .iter()
            .all(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())));
        let first = owner
            .next_batch()
            .ok_or("first migrated batch is missing")?;
        let first_source = first.records[0].stream_identity()?.source_id;
        assert!(first.records.iter().all(|record| record
            .stream_identity()
            .map(|value| value.source_id)
            .ok()
            == Some(first_source)));
        drop(owner);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        assert_eq!(owner.next_batch(), Some(first.clone()));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        })?;
        drop(owner);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        let second = owner
            .next_batch()
            .ok_or("second migrated batch is missing")?;
        let second_source = second.records[0].stream_identity()?.source_id;
        assert_ne!(second_source, first_source);
        assert!(second.records.iter().all(|record| record
            .stream_identity()
            .map(|value| value.source_id)
            .ok()
            == Some(second_source)));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: second.first_cursor,
            last_cursor: second.last_cursor,
            batch_sha256: second.batch_sha256,
        })?;
        let migrated_ids = first
            .records
            .iter()
            .chain(&second.records)
            .map(|record| record.observation_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(migrated_ids, expected_ids);
        assert_eq!(
            first.records.len() + second.records.len(),
            expected_ids.len()
        );
        assert!(owner.next_batch().is_none());
        drop(owner);

        assert!(EvidenceWalOwner::open(directory.path(), limits())?
            .next_batch()
            .is_none());
        Ok(())
    }

    #[test]
    fn next_batch_stays_within_the_control_message_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        let records = (1..=mithril_control::MAX_EVIDENCE_BATCH_RECORDS as u64)
            .map(|cursor| EvidenceRecordV1 {
                format_version: WAL_FORMAT_VERSION,
                cursor,
                observation_id: [1; 32],
                payload: vec![2; 127 * 1_024],
                payload_sha256: [3; 32],
                previous_record_sha256: [4; 32],
                record_sha256: [5; 32],
            })
            .collect::<Vec<_>>();
        let wal = EvidenceWal {
            root: std::path::PathBuf::from("unused-test-WAL"),
            limits: EvidenceWalLimits {
                maximum_retained_bytes: u64::MAX,
                maximum_retained_records: records.len(),
                ..EvidenceWalLimits::default()
            },
            stream_identity: None,
            records,
            retained_bytes: 0,
            acknowledged: AckStateV1::default(),
            gap: None,
            gap_bytes: 0,
        };

        let batch = wal.next_batch().ok_or("bounded test batch is missing")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        assert!(wire.encoded_len() <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES);
        assert!(batch.records.len() < mithril_control::MAX_EVIDENCE_BATCH_RECORDS);
        Ok(())
    }
}
