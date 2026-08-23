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

const WAL_FORMAT_VERSION: u32 = 1;
const ACK_FILE: &str = "acknowledged.json";
const LEGACY_SOURCE_FILE: &str = "source-id";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceWalLimits {
    pub maximum_record_bytes: u64,
    pub maximum_retained_bytes: u64,
    pub maximum_retained_records: usize,
    pub maximum_batch_records: usize,
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

    fn source_id(&self) -> Result<[u8; 16]> {
        Ok(ObservationEnvelopeV1::from_wire_bytes(&self.payload)?
            .source_id
            .to_be_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub records: Vec<EvidenceRecordV1>,
    pub batch_sha256: EvidenceDigestV1,
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AckStateV1 {
    contiguous_cursor: u64,
    last_first_cursor: u64,
    last_batch_sha256: EvidenceDigestV1,
    last_record_sha256: EvidenceDigestV1,
}

pub struct EvidenceWal {
    root: PathBuf,
    limits: EvidenceWalLimits,
    records: Vec<EvidenceRecordV1>,
    retained_bytes: u64,
    acknowledged: AckStateV1,
}

pub(super) struct EvidenceWalAppendFailure {
    pub error: crate::Error,
    pub gap_reason: CoverageGapReasonV1,
}

impl From<crate::Error> for EvidenceWalAppendFailure {
    fn from(error: crate::Error) -> Self {
        Self {
            error,
            gap_reason: CoverageGapReasonV1::WalFailure,
        }
    }
}

pub(super) struct EvidenceWalOwner {
    root: PathBuf,
    limits: EvidenceWalLimits,
    streams: BTreeMap<[u8; 16], EvidenceWal>,
    unbound_legacy: Option<EvidenceWal>,
    in_flight_source: Option<[u8; 16]>,
    last_acknowledged_source: Option<[u8; 16]>,
}

impl EvidenceWalOwner {
    pub(super) fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        limits.validate()?;
        let root = root.into();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let mut streams = BTreeMap::new();
        let legacy = EvidenceWal::open(&root, limits)?;
        let legacy_source = legacy_source_id(&legacy, &root)?;
        let legacy_is_populated = !legacy.records.is_empty()
            || legacy.acknowledged != AckStateV1::default()
            || legacy_source.is_some();
        let mut unbound_legacy = None;
        if let Some(source_id) = legacy_source {
            streams.insert(source_id, legacy);
        } else if legacy_is_populated {
            unbound_legacy = Some(legacy);
        }
        for entry in fs::read_dir(&root)
            .context(IoSnafu { path: &root })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(IoSnafu { path: &root })?
        {
            let path = entry.path();
            if !path.is_dir()
                && (path.file_name().and_then(|name| name.to_str()) == Some(ACK_FILE)
                    || path.file_name().and_then(|name| name.to_str()) == Some(LEGACY_SOURCE_FILE)
                    || path.extension().and_then(|extension| extension.to_str()) == Some("wal"))
            {
                continue;
            }
            let source_id = stream_source_id(&path)?;
            let wal = EvidenceWal::open(&path, limits)?;
            if wal
                .records
                .iter()
                .any(|record| record.source_id().ok() != Some(source_id))
            {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL stream `{}` contains a different source identity",
                        path.display()
                    ),
                }
                .fail();
            }
            if streams.insert(source_id, wal).is_some() {
                return EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL source `{}` has more than one stream directory",
                        hex::encode(source_id)
                    ),
                }
                .fail();
            }
        }
        let owner = Self {
            root,
            limits,
            streams,
            unbound_legacy,
            in_flight_source: None,
            last_acknowledged_source: None,
        };
        owner.validate_retention()?;
        Ok(owner)
    }

    pub(super) fn append_classified(
        &mut self,
        observation: &ObservationEnvelopeV1,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        let source_id = observation.source_id.to_be_bytes();
        let (retained_records, retained_bytes) =
            self.retention().map_err(EvidenceWalAppendFailure::from)?;
        if retained_records >= self.limits.maximum_retained_records
            || retained_bytes >= self.limits.maximum_retained_bytes
        {
            return Err(capacity_failure());
        }
        if !self.streams.contains_key(&source_id) && self.unbound_legacy.is_some() {
            // A flat Phase 6 WAL can continue only after its first source is bound durably.
            atomic_write(
                &self.root.join(LEGACY_SOURCE_FILE),
                hex::encode(source_id).as_bytes(),
            )
            .map_err(EvidenceWalAppendFailure::from)?;
            let Some(legacy) = self.unbound_legacy.take() else {
                return Err(EvidenceStateSnafu {
                    reason: "the flat evidence WAL disappeared before source binding".to_owned(),
                }
                .build()
                .into());
            };
            self.streams.insert(source_id, legacy);
        }
        if !self.streams.contains_key(&source_id) {
            let path = self.root.join(hex::encode(source_id));
            let wal =
                EvidenceWal::open(path, self.limits).map_err(EvidenceWalAppendFailure::from)?;
            self.streams.insert(source_id, wal);
        }
        let Some(wal) = self.streams.get_mut(&source_id) else {
            return Err(EvidenceStateSnafu {
                reason: "the evidence source WAL is missing after source selection".to_owned(),
            }
            .build()
            .into());
        };
        // The configured retention bounds apply to all source streams together.
        wal.limits.maximum_retained_records =
            wal.records.len() + (self.limits.maximum_retained_records - retained_records);
        wal.limits.maximum_retained_bytes =
            wal.retained_bytes + (self.limits.maximum_retained_bytes - retained_bytes);
        let result = wal.append_classified(observation);
        wal.limits = self.limits;
        result
    }

    pub(super) fn next_batch(&mut self) -> Option<EvidenceBatchV1> {
        if let Some(source_id) = self.in_flight_source {
            return self.streams.get(&source_id)?.next_batch();
        }
        let source_id = self
            .streams
            .keys()
            .copied()
            .filter(|source_id| {
                self.last_acknowledged_source
                    .is_none_or(|last| source_id > &last)
            })
            .chain(self.streams.keys().copied())
            .find(|source_id| {
                self.streams
                    .get(source_id)
                    .is_some_and(|wal| wal.pending_records() > 0)
            })?;
        self.in_flight_source = Some(source_id);
        self.streams.get(&source_id)?.next_batch()
    }

    pub(super) fn acknowledge(&mut self, ack: EvidenceAckV1) -> Result<()> {
        let source_id = self.in_flight_source.ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "evidence acknowledgement has no in-flight source batch".to_owned(),
            }
            .build()
        })?;
        self.streams
            .get_mut(&source_id)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence acknowledgement source is not retained".to_owned(),
                }
                .build()
            })?
            .acknowledge(ack)?;
        self.in_flight_source = None;
        self.last_acknowledged_source = Some(source_id);
        Ok(())
    }

    fn retention(&self) -> Result<(usize, u64)> {
        self.streams
            .values()
            .chain(self.unbound_legacy.iter())
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

fn legacy_source_id(wal: &EvidenceWal, root: &Path) -> Result<Option<[u8; 16]>> {
    let marker_path = root.join(LEGACY_SOURCE_FILE);
    let marker = match fs::read_to_string(&marker_path) {
        Ok(value) => Some(parse_source_id(value.trim(), &marker_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(crate::Error::Io {
                path: marker_path,
                source,
                location: snafu::Location::default(),
            })
        }
    };
    let mut record_source = None;
    for record in &wal.records {
        let source_id = record.source_id()?;
        if record_source.is_some_and(|current| current != source_id) {
            return EvidenceStateSnafu {
                reason: "the flat evidence WAL contains more than one source identity".to_owned(),
            }
            .fail();
        }
        record_source = Some(source_id);
    }
    if marker.is_some() && record_source.is_some() && marker != record_source {
        return EvidenceStateSnafu {
            reason: "the flat evidence WAL source marker does not match its records".to_owned(),
        }
        .fail();
    }
    if marker.is_none() {
        if let Some(record_source) = record_source {
            atomic_write(&marker_path, hex::encode(record_source).as_bytes())?;
        }
    }
    Ok(marker.or(record_source))
}

fn stream_source_id(path: &Path) -> Result<[u8; 16]> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let source_id = parse_source_id(name, path);
    if !path.is_dir() || source_id.is_err() {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL entry `{}` is not a source stream directory",
                path.display()
            ),
        }
        .fail();
    }
    source_id
}

fn parse_source_id(value: &str, path: &Path) -> Result<[u8; 16]> {
    let source_id: Option<[u8; 16]> = hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok());
    let Some(source_id) = source_id else {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL source identity `{}` is invalid",
                path.display()
            ),
        }
        .fail();
    };
    if value.len() != 32 || hex::encode(source_id) != value {
        return EvidenceStateSnafu {
            reason: format!(
                "evidence WAL source identity `{}` is invalid",
                path.display()
            ),
        }
        .fail();
    }
    Ok(source_id)
}

fn capacity_failure() -> EvidenceWalAppendFailure {
    EvidenceWalAppendFailure {
        error: EvidenceStateSnafu {
            reason: "evidence WAL retention or record capacity is exhausted".to_owned(),
        }
        .build(),
        gap_reason: CoverageGapReasonV1::WalCapacity,
    }
}

impl EvidenceWal {
    pub fn open(root: impl Into<PathBuf>, limits: EvidenceWalLimits) -> Result<Self> {
        limits.validate()?;
        let root = root.into();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        let acknowledged = read_ack(&root)?;
        let mut paths = recover_directory(&root, acknowledged)?;
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
            let record: EvidenceRecordV1 = serde_json::from_slice(&bytes).map_err(|error| {
                EvidenceStateSnafu {
                    reason: format!(
                        "evidence WAL segment `{}` is not valid JSON: {error}",
                        path.display()
                    ),
                }
                .build()
            })?;
            record.validate(expected_cursor, previous)?;
            retained_bytes = retained_bytes
                .checked_add(bytes.len() as u64)
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
            records,
            retained_bytes,
            acknowledged,
        })
    }

    pub fn append(&mut self, observation: &ObservationEnvelopeV1) -> Result<u64> {
        self.append_classified(observation)
            .map_err(|failure| failure.error)
    }

    pub(super) fn append_classified(
        &mut self,
        observation: &ObservationEnvelopeV1,
    ) -> std::result::Result<u64, EvidenceWalAppendFailure> {
        let cursor = self
            .records
            .last()
            .map_or(self.acknowledged.contiguous_cursor, |record| record.cursor)
            .checked_add(1)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "evidence WAL cursor is exhausted".to_owned(),
                }
                .build()
            })?;
        let previous = self
            .records
            .last()
            .map_or(self.acknowledged.last_record_sha256, |record| {
                record.record_sha256
            });
        let record = EvidenceRecordV1::new(cursor, observation, previous)?;
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("evidence WAL segment encoding failed: {error}"),
            }
            .build()
        })?;
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
                error: EvidenceStateSnafu {
                    reason: "evidence WAL retention or record capacity is exhausted".to_owned(),
                }
                .build(),
                gap_reason: CoverageGapReasonV1::WalCapacity,
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
        let mut records = Vec::new();
        let mut wire = mithril_control::EvidenceBatch {
            first_cursor,
            last_cursor: first_cursor,
            records: Vec::new(),
            batch_sha256: vec![0; 32],
        };
        for record in self.records.iter().take(self.limits.maximum_batch_records) {
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
        let bytes = serde_json::to_vec(&state).map_err(|error| {
            EvidenceStateSnafu {
                reason: format!("evidence acknowledgement encoding failed: {error}"),
            }
            .build()
        })?;
        atomic_write(&self.root.join(ACK_FILE), &bytes)?;
        let acknowledged_count = batch.records.len();
        let remaining_bytes =
            self.records
                .iter()
                .skip(acknowledged_count)
                .try_fold(0_u64, |total, record| {
                    let bytes = serde_json::to_vec(record).map_err(|error| {
                        EvidenceStateSnafu {
                            reason: format!("evidence WAL segment encoding failed: {error}"),
                        }
                        .build()
                    })?;
                    total.checked_add(bytes.len() as u64).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "evidence WAL retained byte count overflowed".to_owned(),
                        }
                        .build()
                    })
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
                    })
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
                    })
                }
            }
        }
        sync_directory(&self.root)?;
        self.records.drain(..acknowledged_count);
        self.retained_bytes = remaining_bytes;
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

fn read_ack(root: &Path) -> Result<AckStateV1> {
    let path = root.join(ACK_FILE);
    if !path.exists() {
        return Ok(AckStateV1::default());
    }
    let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
    let state: AckStateV1 = serde_json::from_slice(&bytes).map_err(|error| {
        EvidenceStateSnafu {
            reason: format!("evidence acknowledgement state is invalid: {error}"),
        }
        .build()
    })?;
    let empty = state == AckStateV1::default();
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
    Ok(state)
}

fn recover_directory(root: &Path, acknowledged: AckStateV1) -> Result<Vec<PathBuf>> {
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
                if cursor <= acknowledged.contiguous_cursor {
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
    stem == "acknowledged" || (stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit()))
}

fn segment_path(root: &Path, cursor: u64) -> PathBuf {
    root.join(format!("{cursor:020}.wal"))
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::{
        segment_path, AckStateV1, EvidenceAckV1, EvidenceRecordV1, EvidenceWal, EvidenceWalLimits,
        EvidenceWalOwner, ACK_FILE, WAL_FORMAT_VERSION,
    };
    use crate::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn kernel_observation(sequence: u64) -> crate::Result<crate::ObservationEnvelopeV1> {
        kernel_observation_for_cpu(sequence, 1)
    }

    fn kernel_observation_for_cpu(
        sequence: u64,
        cpu_id: u32,
    ) -> crate::Result<crate::ObservationEnvelopeV1> {
        let canonicalizer = ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            5,
            EvidenceIdV1::new(6, 7),
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
        let first_source = first.records[0].source_id()?;
        assert!(first
            .records
            .iter()
            .all(|record| record.source_id().ok() == Some(first_source)));
        drop(owner);

        let mut owner = EvidenceWalOwner::open(directory.path(), limits())?;
        assert_eq!(owner.next_batch(), Some(first.clone()));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: first.first_cursor,
            last_cursor: first.last_cursor,
            batch_sha256: first.batch_sha256,
        })?;
        let second = owner.next_batch().ok_or("second source batch is missing")?;
        let second_source = second.records[0].source_id()?;
        assert_ne!(second_source, first_source);
        assert!(second
            .records
            .iter()
            .all(|record| record.source_id().ok() == Some(second_source)));
        owner.acknowledge(EvidenceAckV1 {
            first_cursor: second.first_cursor,
            last_cursor: second.last_cursor,
            batch_sha256: second.batch_sha256,
        })?;
        assert!(owner.next_batch().is_none());
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
            continued.records[0].source_id()?,
            expected.records[0].source_id()?
        );
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
            records,
            retained_bytes: 0,
            acknowledged: AckStateV1::default(),
        };

        let batch = wal.next_batch().ok_or("bounded test batch is missing")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        assert!(wire.encoded_len() <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES);
        assert!(batch.records.len() < mithril_control::MAX_EVIDENCE_BATCH_RECORDS);
        Ok(())
    }
}
