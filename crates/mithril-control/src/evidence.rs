use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tonic::Status;

use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::{EvidenceAck, EvidenceBatch, EvidenceRecord, Result};

const MAX_BATCH_RECORDS: usize = 256;
const MAX_RECORD_BYTES: usize = 128 * 1_024;

#[derive(Clone)]
pub struct EvidenceIntakeOwner {
    root: Arc<PathBuf>,
    nodes: Arc<Mutex<BTreeMap<String, IntakeStateV1>>>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntakeStateV1 {
    contiguous_cursor: u64,
    last_first_cursor: u64,
    last_batch_sha256: [u8; 32],
    last_record_sha256: [u8; 32],
}

#[derive(Serialize)]
struct StoredRecordV1<'a> {
    cursor: u64,
    observation_id: &'a [u8],
    payload: &'a [u8],
    payload_sha256: &'a [u8],
    previous_record_sha256: &'a [u8],
    record_sha256: &'a [u8],
}

impl EvidenceIntakeOwner {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        Ok(Self {
            root: Arc::new(root),
            nodes: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn receive(
        &self,
        node_id: &str,
        batch: &EvidenceBatch,
    ) -> std::result::Result<EvidenceAck, Status> {
        if node_id.is_empty()
            || node_id.chars().any(char::is_whitespace)
            || node_id.contains('/')
            || batch.records.is_empty()
            || batch.records.len() > MAX_BATCH_RECORDS
            || batch.batch_sha256.len() != 32
        {
            return Err(Status::invalid_argument(
                "evidence batch identity or bounds are invalid",
            ));
        }
        let batch_digest: [u8; 32] = batch.batch_sha256.as_slice().try_into().map_err(|_| {
            Status::invalid_argument("evidence batch digest must be one SHA-256 digest")
        })?;
        let node_root = self.root.join(node_id);
        fs::create_dir_all(&node_root).map_err(|error| {
            Status::internal(format!("evidence node directory failed: {error}"))
        })?;
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| Status::internal("evidence intake state is poisoned"))?;
        let state = match nodes.get(node_id).copied() {
            Some(state) => state,
            None => read_state(&node_root).map_err(internal_status)?,
        };
        if batch.first_cursor == state.last_first_cursor
            && batch.last_cursor == state.contiguous_cursor
            && batch_digest == state.last_batch_sha256
        {
            return Ok(EvidenceAck {
                first_cursor: batch.first_cursor,
                last_cursor: batch.last_cursor,
                batch_sha256: batch.batch_sha256.clone(),
            });
        }
        if batch.first_cursor != state.contiguous_cursor.saturating_add(1)
            || batch.last_cursor < batch.first_cursor
            || batch.last_cursor - batch.first_cursor + 1 != batch.records.len() as u64
        {
            return Err(Status::aborted(
                "evidence batch is not the next contiguous cursor range",
            ));
        }

        let mut previous = state.last_record_sha256;
        for (index, record) in batch.records.iter().enumerate() {
            let cursor = batch.first_cursor + index as u64;
            validate_record(record, cursor, previous)?;
            previous = record.record_sha256.as_slice().try_into().map_err(|_| {
                Status::invalid_argument("evidence record digest must be one SHA-256 digest")
            })?;
        }
        let actual_batch = batch_digest_for(&batch.records);
        if batch.last_cursor != batch.records.last().map_or(0, |record| record.cursor)
            || actual_batch != batch_digest
        {
            return Err(Status::data_loss(
                "evidence batch digest does not match its records",
            ));
        }
        for record in &batch.records {
            persist_record(&node_root, record).map_err(internal_status)?;
        }
        let next_state = IntakeStateV1 {
            contiguous_cursor: batch.last_cursor,
            last_first_cursor: batch.first_cursor,
            last_batch_sha256: batch_digest,
            last_record_sha256: previous,
        };
        persist_state(&node_root, next_state).map_err(internal_status)?;
        nodes.insert(node_id.to_owned(), next_state);
        Ok(EvidenceAck {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch.batch_sha256.clone(),
        })
    }

    pub fn contiguous_cursor(&self, node_id: &str) -> Result<u64> {
        let node_root = self.root.join(node_id);
        Ok(read_state(&node_root)?.contiguous_cursor)
    }
}

#[allow(clippy::result_large_err)]
fn validate_record(
    record: &EvidenceRecord,
    expected_cursor: u64,
    previous: [u8; 32],
) -> std::result::Result<(), Status> {
    if record.cursor != expected_cursor
        || record.observation_id.len() != 32
        || record.payload.is_empty()
        || record.payload.len() > MAX_RECORD_BYTES
        || record.payload_sha256.len() != 32
        || record.previous_record_sha256.as_slice() != previous
        || record.record_sha256.len() != 32
    {
        return Err(Status::invalid_argument(
            "evidence record identity or bounds are invalid",
        ));
    }
    let payload_digest: [u8; 32] = Sha256::digest(&record.payload).into();
    let supplied_payload: [u8; 32] = record.payload_sha256.as_slice().try_into().map_err(|_| {
        Status::invalid_argument("evidence payload digest must be one SHA-256 digest")
    })?;
    let supplied_record: [u8; 32] = record.record_sha256.as_slice().try_into().map_err(|_| {
        Status::invalid_argument("evidence record digest must be one SHA-256 digest")
    })?;
    if payload_digest != supplied_payload
        || record_digest(record, previous) != supplied_record
        || !payload_has_identity(&record.payload, &record.observation_id)
    {
        return Err(Status::data_loss(
            "evidence record content or digest is invalid",
        ));
    }
    Ok(())
}

fn payload_has_identity(payload: &[u8], observation_id: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
        && value
            .get("observation_id")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| {
                values.len() == 32
                    && values.iter().zip(observation_id).all(|(value, byte)| {
                        value
                            .as_u64()
                            .is_some_and(|number| number == u64::from(*byte))
                    })
            })
}

fn record_digest(record: &EvidenceRecord, previous: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(1_u32.to_be_bytes());
    digest.update(record.cursor.to_be_bytes());
    digest.update(&record.observation_id);
    digest.update(&record.payload_sha256);
    digest.update(previous);
    digest.finalize().into()
}

fn batch_digest_for(records: &[EvidenceRecord]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for record in records {
        digest.update(record.cursor.to_be_bytes());
        digest.update(&record.record_sha256);
    }
    digest.finalize().into()
}

fn persist_record(root: &Path, record: &EvidenceRecord) -> Result<()> {
    let path = root.join(format!("{:020}.json", record.cursor));
    let bytes = serde_json::to_vec(&StoredRecordV1 {
        cursor: record.cursor,
        observation_id: &record.observation_id,
        payload: &record.payload,
        payload_sha256: &record.payload_sha256,
        previous_record_sha256: &record.previous_record_sha256,
        record_sha256: &record.record_sha256,
    })
    .map_err(|error| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: format!("record encoding failed: {error}"),
        }
        .build()
    })?;
    if path.exists() {
        let existing = fs::read(&path).context(IoSnafu { path: &path })?;
        if existing == bytes {
            return Ok(());
        }
        return EvidenceStateSnafu {
            path,
            reason: "cursor already contains different evidence".to_owned(),
        }
        .fail();
    }
    atomic_write(&path, &bytes)
}

fn persist_state(root: &Path, state: IntakeStateV1) -> Result<()> {
    let path = root.join("cursor.json");
    let bytes = serde_json::to_vec(&state).map_err(|error| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: format!("cursor encoding failed: {error}"),
        }
        .build()
    })?;
    atomic_replace(&path, &bytes)
}

fn read_state(root: &Path) -> Result<IntakeStateV1> {
    let path = root.join("cursor.json");
    if !path.exists() {
        return Ok(IntakeStateV1::default());
    }
    let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        EvidenceStateSnafu {
            path,
            reason: format!("cursor decoding failed: {error}"),
        }
        .build()
    })
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
    sync_directory(path)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    sync_directory(path)
}

fn sync_directory(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        EvidenceStateSnafu {
            path: path.to_owned(),
            reason: "state path has no parent directory".to_owned(),
        }
        .build()
    })?;
    File::open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}

fn internal_status(error: crate::Error) -> Status {
    Status::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::EvidenceIntakeOwner;
    use crate::{EvidenceBatch, EvidenceRecord};
    use sha2::{Digest as _, Sha256};

    fn record(cursor: u64, previous: [u8; 32]) -> EvidenceRecord {
        let observation_id = [cursor as u8; 32];
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "observation_id": observation_id,
        }))
        .unwrap_or_default();
        let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
        let mut value = EvidenceRecord {
            cursor,
            observation_id: observation_id.to_vec(),
            payload,
            payload_sha256: payload_sha256.to_vec(),
            previous_record_sha256: previous.to_vec(),
            record_sha256: Vec::new(),
        };
        value.record_sha256 = super::record_digest(&value, previous).to_vec();
        value
    }

    fn batch(first: u64, count: u64, mut previous: [u8; 32]) -> EvidenceBatch {
        let mut records = Vec::new();
        for cursor in first..first + count {
            let record = record(cursor, previous);
            previous.copy_from_slice(&record.record_sha256);
            records.push(record);
        }
        EvidenceBatch {
            first_cursor: first,
            last_cursor: first + count - 1,
            batch_sha256: super::batch_digest_for(&records).to_vec(),
            records,
        }
    }

    #[test]
    fn intake_is_contiguous_durable_and_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let first = batch(1, 2, [0; 32]);
        let ack = intake.receive("node-a", &first)?;
        assert_eq!(ack.last_cursor, 2);
        assert_eq!(intake.receive("node-a", &first)?, ack);
        assert_eq!(intake.contiguous_cursor("node-a")?, 2);
        drop(intake);
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let previous = first
            .records
            .last()
            .and_then(|record| record.record_sha256.as_slice().try_into().ok())
            .ok_or("first batch has no final digest")?;
        assert_eq!(
            intake
                .receive("node-a", &batch(3, 1, previous))?
                .last_cursor,
            3
        );
        assert!(intake.receive("node-a", &batch(5, 1, previous)).is_err());
        Ok(())
    }

    #[test]
    fn intake_rejects_payload_and_chain_corruption() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut corrupted = batch(1, 2, [0; 32]);
        corrupted.records[1].payload[0] ^= 1;
        assert!(intake.receive("node-a", &corrupted).is_err());
        assert_eq!(intake.contiguous_cursor("node-a")?, 0);
        Ok(())
    }
}
