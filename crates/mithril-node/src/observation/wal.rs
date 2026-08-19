use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{CoverageGapReasonV1, EvidenceDigestV1, ObservationEnvelopeV1};
use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::Result;

const WAL_FORMAT_VERSION: u32 = 1;
const ACK_FILE: &str = "acknowledged.json";

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
            || self.maximum_retained_bytes < self.maximum_record_bytes
            || self.maximum_retained_records == 0
            || self.maximum_batch_records == 0
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
            maximum_record_bytes: 128 * 1_024,
            maximum_retained_bytes: 256 * 1_024 * 1_024,
            maximum_retained_records: 100_000,
            maximum_batch_records: 256,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAckV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub batch_sha256: EvidenceDigestV1,
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
        if bytes_len > self.limits.maximum_record_bytes
            || self.records.len() == self.limits.maximum_retained_records
            || self.retained_bytes.saturating_add(bytes_len) > self.limits.maximum_retained_bytes
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
        self.retained_bytes += bytes_len;
        self.records.push(record);
        Ok(cursor)
    }

    #[must_use]
    pub fn next_batch(&self) -> Option<EvidenceBatchV1> {
        let records = self
            .records
            .iter()
            .take(self.limits.maximum_batch_records)
            .cloned()
            .collect::<Vec<_>>();
        let first_cursor = records.first()?.cursor;
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

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    let parent = path.parent().ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "evidence state path has no parent".to_owned(),
        }
        .build()
    })?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .context(IoSnafu { path })?
        .sync_all()
        .context(IoSnafu { path })
}

#[cfg(test)]
mod tests {
    use super::{segment_path, EvidenceAckV1, EvidenceWal, EvidenceWalLimits, ACK_FILE};
    use crate::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn kernel_observation(sequence: u64) -> crate::Result<crate::ObservationEnvelopeV1> {
        let canonicalizer = ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            5,
            EvidenceIdV1::new(6, 7),
        )?;
        canonicalizer.normalize_kernel(
            erebor_interceptor_abi::EffectObservationV1 {
                source_sequence: sequence,
                source_cpu_id: 1,
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
    fn wal_replays_and_removes_only_an_exact_acknowledged_prefix() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: std::path::PathBuf::from("temporary evidence directory"),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&kernel_observation(1)?)?;
        wal.append(&kernel_observation(2)?)?;
        wal.append(&kernel_observation(3)?)?;
        let batch = wal
            .next_batch()
            .ok_or_else(|| crate::Error::EvidenceState {
                reason: "test batch is missing".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        assert_eq!((batch.first_cursor, batch.last_cursor), (1, 2));
        assert!(wal
            .acknowledge(EvidenceAckV1 {
                first_cursor: 1,
                last_cursor: 2,
                batch_sha256: [9; 32],
            })
            .is_err());
        let first_path = segment_path(directory.path(), 1);
        std::fs::remove_file(&first_path).map_err(|source| crate::Error::Io {
            path: first_path,
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
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
            std::fs::metadata(segment_path(directory.path(), 3))
                .map_err(|source| crate::Error::Io {
                    path: segment_path(directory.path(), 3),
                    source,
                    location: snafu::Location::new(file!(), line!(), column!()),
                })?
                .len()
        );
        assert_eq!(wal.next_batch().map(|batch| batch.first_cursor), Some(3));
        Ok(())
    }

    #[test]
    fn wal_refuses_corruption_and_retention_exhaustion() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: std::path::PathBuf::from("temporary evidence directory"),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        for sequence in 1..=4 {
            wal.append(&kernel_observation(sequence)?)?;
        }
        assert!(wal.append(&kernel_observation(5)?).is_err());
        drop(wal);
        let path = directory.path().join("00000000000000000002.wal");
        let mut bytes = std::fs::read(&path).map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(&path, bytes).map_err(|source| crate::Error::Io {
            path: path.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        assert!(EvidenceWal::open(directory.path(), limits()).is_err());
        Ok(())
    }

    #[test]
    fn wal_recovers_acknowledged_residue_and_owned_torn_writes() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: std::path::PathBuf::from("temporary evidence directory"),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        wal.append(&kernel_observation(1)?)?;
        wal.append(&kernel_observation(2)?)?;
        let first_path = segment_path(directory.path(), 1);
        let first_bytes = std::fs::read(&first_path).map_err(|source| crate::Error::Io {
            path: first_path.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let batch = wal
            .next_batch()
            .ok_or_else(|| crate::Error::EvidenceState {
                reason: "test batch is missing".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
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

        std::fs::write(&first_path, first_bytes).map_err(|source| crate::Error::Io {
            path: first_path.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let segment_temporary = segment_path(directory.path(), 3).with_extension("tmp");
        std::fs::write(&segment_temporary, b"torn segment").map_err(|source| crate::Error::Io {
            path: segment_temporary.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;
        let ack_temporary = directory.path().join(ACK_FILE).with_extension("tmp");
        std::fs::write(&ack_temporary, b"torn ack").map_err(|source| crate::Error::Io {
            path: ack_temporary.clone(),
            source,
            location: snafu::Location::new(file!(), line!(), column!()),
        })?;

        let mut wal = EvidenceWal::open(directory.path(), limits())?;
        assert_eq!(wal.acknowledged_cursor(), 2);
        assert_eq!(wal.pending_records(), 0);
        assert!(!first_path.exists());
        assert!(!segment_temporary.exists());
        assert!(!ack_temporary.exists());
        assert_eq!(wal.append(&kernel_observation(3)?)?, 3);
        Ok(())
    }
}
