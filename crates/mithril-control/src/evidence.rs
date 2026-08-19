use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tonic::Status;

use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::{
    CoverageAck, CoverageCounters, CoverageReport, EvidenceAck, EvidenceBatch, EvidenceRecord,
    Result,
};

const MAX_BATCH_RECORDS: usize = 256;
const MAX_RECORD_BYTES: usize = 128 * 1_024;
const MAX_COVERAGE_INTERVALS: usize = 8_192;

#[derive(Clone)]
pub struct EvidenceIntakeOwner {
    root: Arc<PathBuf>,
    nodes: Arc<Mutex<BTreeMap<String, IntakeStateV1>>>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IntakeStateV1 {
    contiguous_cursor: u64,
    last_first_cursor: u64,
    last_batch_sha256: [u8; 32],
    last_record_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageIntakeStateV1 {
    source_epoch: u64,
    revision: u64,
    report_sha256: [u8; 32],
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
        let duplicate = batch.first_cursor == state.last_first_cursor
            && batch.last_cursor == state.contiguous_cursor
            && batch_digest == state.last_batch_sha256;
        if !duplicate
            && (batch.first_cursor != state.contiguous_cursor.saturating_add(1)
                || batch.last_cursor < batch.first_cursor
                || batch.last_cursor - batch.first_cursor + 1 != batch.records.len() as u64)
        {
            return Err(Status::aborted(
                "evidence batch is not the next contiguous cursor range",
            ));
        }

        let mut previous = if duplicate {
            batch
                .records
                .first()
                .and_then(|record| record.previous_record_sha256.as_slice().try_into().ok())
                .ok_or_else(|| {
                    Status::invalid_argument(
                        "duplicate evidence batch has no valid previous record digest",
                    )
                })?
        } else {
            state.last_record_sha256
        };
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
        if duplicate {
            return Ok(EvidenceAck {
                first_cursor: batch.first_cursor,
                last_cursor: batch.last_cursor,
                batch_sha256: batch.batch_sha256.clone(),
            });
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

    #[allow(clippy::result_large_err)]
    pub fn receive_coverage(
        &self,
        node_id: &str,
        report: &CoverageReport,
    ) -> std::result::Result<CoverageAck, Status> {
        validate_node_id(node_id)?;
        let report_digest: [u8; 32] = report
            .report_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("coverage report digest must be SHA-256"))?;
        let mut unsigned = report.clone();
        unsigned.report_sha256.clear();
        let actual_digest: [u8; 32] = Sha256::digest(unsigned.encode_to_vec()).into();
        if actual_digest != report_digest {
            return Err(Status::data_loss(
                "coverage report digest does not match its content",
            ));
        }
        validate_coverage_report(report)?;

        let node_root = self.root.join(node_id);
        fs::create_dir_all(&node_root).map_err(|error| {
            Status::internal(format!("evidence node directory failed: {error}"))
        })?;
        let state = read_coverage_state(&node_root).map_err(internal_status)?;
        if state.source_epoch == report.source_epoch
            && state.revision == report.revision
            && state.report_sha256 == report_digest
        {
            persist_coverage_report(&node_root, report).map_err(internal_status)?;
            return Ok(coverage_ack(report));
        }
        if report.source_epoch < state.source_epoch
            || (report.source_epoch == state.source_epoch && report.revision <= state.revision)
        {
            return Err(Status::aborted(
                "coverage report epoch or revision is stale",
            ));
        }
        persist_coverage_report(&node_root, report).map_err(internal_status)?;
        persist_coverage_state(
            &node_root,
            CoverageIntakeStateV1 {
                source_epoch: report.source_epoch,
                revision: report.revision,
                report_sha256: report_digest,
            },
        )
        .map_err(internal_status)?;
        Ok(coverage_ack(report))
    }

    pub fn latest_coverage_report(&self, node_id: &str) -> Result<Option<CoverageReport>> {
        let node_root = self.root.join(node_id);
        let state = read_coverage_state(&node_root)?;
        if state.source_epoch == 0 || state.revision == 0 {
            return Ok(None);
        }
        let path = node_root.join("coverage").join(format!(
            "{:020}-{:020}.pb",
            state.source_epoch, state.revision
        ));
        let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
        let report = CoverageReport::decode(bytes.as_slice()).map_err(|error| {
            EvidenceStateSnafu {
                path: path.clone(),
                reason: format!("coverage report decoding failed: {error}"),
            }
            .build()
        })?;
        let supplied_digest: [u8; 32] =
            report.report_sha256.as_slice().try_into().map_err(|_| {
                EvidenceStateSnafu {
                    path: path.clone(),
                    reason: "coverage report digest is not SHA-256".to_owned(),
                }
                .build()
            })?;
        let mut unsigned = report.clone();
        unsigned.report_sha256.clear();
        let actual_digest: [u8; 32] = Sha256::digest(unsigned.encode_to_vec()).into();
        if supplied_digest != state.report_sha256 || actual_digest != state.report_sha256 {
            return EvidenceStateSnafu {
                path,
                reason: "coverage report content does not match its durable cursor".to_owned(),
            }
            .fail();
        }
        Ok(Some(report))
    }
}

#[allow(clippy::result_large_err)]
fn validate_node_id(node_id: &str) -> std::result::Result<(), Status> {
    if node_id.is_empty() || node_id.chars().any(char::is_whitespace) || node_id.contains('/') {
        return Err(Status::invalid_argument(
            "evidence node identity is invalid",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_coverage_report(report: &CoverageReport) -> std::result::Result<(), Status> {
    if report.source_epoch == 0
        || report.revision == 0
        || report.intervals.is_empty()
        || report.intervals.len() > MAX_COVERAGE_INTERVALS
    {
        return Err(Status::invalid_argument(
            "coverage report epoch, revision, or interval bounds are invalid",
        ));
    }
    let mut interval_ids = std::collections::BTreeSet::new();
    let mut current_cpus = std::collections::BTreeSet::new();
    let mut current_healthy = true;
    let mut current_count = 0_usize;
    for interval in &report.intervals {
        let ids_valid = interval.interval_id.len() == 16
            && interval.interval_id.iter().any(|byte| *byte != 0)
            && interval.source_id.len() == 16
            && interval.source_id.iter().any(|byte| *byte != 0)
            && interval_ids.insert(interval.interval_id.as_slice());
        let state_valid = matches!(
            interval.state.as_str(),
            "HEALTHY" | "GAPPED" | "UNKNOWN" | "CLOSED"
        );
        let mut reasons = std::collections::BTreeSet::new();
        let reasons_valid = interval.gap_reasons.iter().all(|reason| {
            reasons.insert(reason.as_str())
                && matches!(
                    reason.as_str(),
                    "SOURCE_SEQUENCE_GAP"
                        | "RING_LOSS"
                        | "CLASSIFIER_MISS"
                        | "UNRESOLVED_EFFECT"
                        | "READER_DELAY"
                        | "READER_STOPPED"
                        | "WAL_FAILURE"
                        | "WAL_CAPACITY"
                        | "CONTROL_DELAY"
                        | "KERNEL_STATE_MISMATCH"
                        | "UNCLEAN_RESTART"
                        | "COUNTER_REGRESSION"
                )
        });
        if !ids_valid
            || !state_valid
            || !reasons_valid
            || interval.source_epoch != report.source_epoch
            || interval.revision == 0
            || !interval
                .opening_counters
                .as_ref()
                .is_some_and(valid_coverage_counters)
            || interval
                .closing_counters
                .as_ref()
                .is_some_and(|counters| !valid_coverage_counters(counters))
        {
            return Err(Status::invalid_argument(
                "coverage interval identity, state, reason, or counters are invalid",
            ));
        }
        if interval.current {
            current_count += 1;
            if !current_cpus.insert(interval.cpu_id) {
                return Err(Status::invalid_argument(
                    "coverage report contains duplicate current CPU state",
                ));
            }
            current_healthy &= interval.state == "HEALTHY" && interval.gap_reasons.is_empty();
        }
    }
    let calculated_negative_eligibility = current_count > 0 && current_healthy;
    if report.negative_claim_eligible != calculated_negative_eligibility {
        return Err(Status::invalid_argument(
            "coverage report negative-claim state does not match current intervals",
        ));
    }
    Ok(())
}

fn valid_coverage_counters(counters: &CoverageCounters) -> bool {
    counters.attempted == counters.suppressed.saturating_add(counters.requested)
        && counters.requested == counters.emitted.saturating_add(counters.lost)
}

fn coverage_ack(report: &CoverageReport) -> CoverageAck {
    CoverageAck {
        source_epoch: report.source_epoch,
        revision: report.revision,
        report_sha256: report.report_sha256.clone(),
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

fn persist_coverage_report(root: &Path, report: &CoverageReport) -> Result<()> {
    let coverage_root = root.join("coverage");
    fs::create_dir_all(&coverage_root).context(IoSnafu {
        path: &coverage_root,
    })?;
    let path = coverage_root.join(format!(
        "{:020}-{:020}.pb",
        report.source_epoch, report.revision
    ));
    let bytes = report.encode_to_vec();
    if path.exists() {
        let existing = fs::read(&path).context(IoSnafu { path: &path })?;
        if existing == bytes {
            return Ok(());
        }
        return EvidenceStateSnafu {
            path,
            reason: "coverage revision already contains different evidence".to_owned(),
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
    let state: IntakeStateV1 = serde_json::from_slice(&bytes).map_err(|error| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: format!("cursor decoding failed: {error}"),
        }
        .build()
    })?;
    let empty = state == IntakeStateV1::default();
    let populated = state.contiguous_cursor > 0
        && state.last_first_cursor > 0
        && state.last_first_cursor <= state.contiguous_cursor
        && state.last_batch_sha256 != [0; 32]
        && state.last_record_sha256 != [0; 32];
    if !empty && !populated {
        return EvidenceStateSnafu {
            path,
            reason: "cursor has inconsistent ranges or digests".to_owned(),
        }
        .fail();
    }
    Ok(state)
}

fn persist_coverage_state(root: &Path, state: CoverageIntakeStateV1) -> Result<()> {
    let path = root.join("coverage-cursor.json");
    let bytes = serde_json::to_vec(&state).map_err(|error| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: format!("coverage cursor encoding failed: {error}"),
        }
        .build()
    })?;
    atomic_replace(&path, &bytes)
}

fn read_coverage_state(root: &Path) -> Result<CoverageIntakeStateV1> {
    let path = root.join("coverage-cursor.json");
    if !path.exists() {
        return Ok(CoverageIntakeStateV1::default());
    }
    let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
    let state: CoverageIntakeStateV1 = serde_json::from_slice(&bytes).map_err(|error| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: format!("coverage cursor decoding failed: {error}"),
        }
        .build()
    })?;
    let empty = state == CoverageIntakeStateV1::default();
    let populated = state.source_epoch > 0 && state.revision > 0 && state.report_sha256 != [0; 32];
    if !empty && !populated {
        return EvidenceStateSnafu {
            path,
            reason: "coverage cursor has inconsistent identity or digest".to_owned(),
        }
        .fail();
    }
    Ok(state)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
        sync_directory(&temporary)?;
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
    use crate::{
        CoverageCounters, CoverageInterval, CoverageReport, EvidenceBatch, EvidenceRecord,
    };
    use prost::Message as _;
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

    fn coverage_report(epoch: u64, revision: u64, state: &str) -> CoverageReport {
        let counters = CoverageCounters {
            attempted: 3,
            requested: 3,
            emitted: 3,
            next_sequence: 3,
            ..CoverageCounters::default()
        };
        let mut report = CoverageReport {
            source_epoch: epoch,
            revision,
            intervals: vec![CoverageInterval {
                interval_id: vec![1; 16],
                source_id: vec![2; 16],
                source_epoch: epoch,
                cpu_id: 0,
                revision: 1,
                state: state.to_owned(),
                first_sequence: 1,
                last_sequence: Some(3),
                opening_counters: Some(CoverageCounters::default()),
                closing_counters: Some(counters),
                gap_reasons: if state == "HEALTHY" {
                    Vec::new()
                } else {
                    vec!["RING_LOSS".to_owned()]
                },
                current: true,
            }],
            negative_claim_eligible: state == "HEALTHY",
            report_sha256: Vec::new(),
        };
        report.report_sha256 = Sha256::digest(report.encode_to_vec()).to_vec();
        report
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

    #[test]
    fn coverage_intake_is_durable_monotonic_and_gap_aware() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let healthy = coverage_report(7, 1, "HEALTHY");
        assert_eq!(
            intake.receive_coverage("node-a", &healthy)?.revision,
            healthy.revision
        );
        assert_eq!(intake.receive_coverage("node-a", &healthy)?.revision, 1);
        let gapped = coverage_report(7, 2, "GAPPED");
        intake.receive_coverage("node-a", &gapped)?;
        assert!(
            !intake
                .latest_coverage_report("node-a")?
                .ok_or("missing coverage report")?
                .negative_claim_eligible
        );
        assert!(intake.receive_coverage("node-a", &healthy).is_err());
        drop(intake);
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        assert_eq!(
            intake
                .latest_coverage_report("node-a")?
                .ok_or("missing recovered coverage report")?
                .revision,
            2
        );
        let path = directory
            .path()
            .join("node-a/coverage/00000000000000000007-00000000000000000002.pb");
        let mut bytes = std::fs::read(&path)?;
        let last = bytes.last_mut().ok_or("empty coverage report")?;
        *last ^= 1;
        std::fs::write(path, bytes)?;
        assert!(intake.latest_coverage_report("node-a").is_err());
        Ok(())
    }

    #[test]
    fn duplicate_delivery_rechecks_the_durable_record() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let first = batch(1, 1, [0; 32]);
        intake.receive("node-a", &first)?;
        let path = directory.path().join("node-a/00000000000000000001.json");
        std::fs::write(&path, b"corrupt durable record")?;
        assert!(intake.receive("node-a", &first).is_err());
        Ok(())
    }

    #[test]
    fn intake_retries_owned_torn_record_and_coverage_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let node_root = directory.path().join("node-a");
        let coverage_root = node_root.join("coverage");
        std::fs::create_dir_all(&coverage_root)?;
        let record_temporary = node_root.join("00000000000000000001.tmp");
        let coverage_temporary =
            coverage_root.join("00000000000000000007-00000000000000000001.tmp");
        std::fs::write(&record_temporary, b"torn record")?;
        std::fs::write(&coverage_temporary, b"torn coverage")?;

        let intake = EvidenceIntakeOwner::open(directory.path())?;
        intake.receive("node-a", &batch(1, 1, [0; 32]))?;
        intake.receive_coverage("node-a", &coverage_report(7, 1, "HEALTHY"))?;
        assert!(!record_temporary.exists());
        assert!(!coverage_temporary.exists());
        Ok(())
    }
}
