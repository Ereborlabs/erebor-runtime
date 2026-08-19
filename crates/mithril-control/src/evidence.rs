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

mod model;

pub use model::*;

pub const MAX_EVIDENCE_BATCH_RECORDS: usize = 256;
pub const MAX_EVIDENCE_RECORD_BYTES: usize = 128 * 1_024;
pub const MAX_EVIDENCE_GRPC_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_EVIDENCE_BATCH_PAYLOAD_BYTES: usize = 3 * 1_024 * 1_024;
const MAX_COVERAGE_INTERVALS: usize = 8_192;

#[derive(Clone)]
pub struct EvidenceIntakeOwner {
    root: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRecordV1 {
    cursor: u64,
    observation_id: Vec<u8>,
    payload: Vec<u8>,
    payload_sha256: Vec<u8>,
    previous_record_sha256: Vec<u8>,
    record_sha256: Vec<u8>,
}

impl From<&EvidenceRecord> for StoredRecordV1 {
    fn from(record: &EvidenceRecord) -> Self {
        Self {
            cursor: record.cursor,
            observation_id: record.observation_id.clone(),
            payload: record.payload.clone(),
            payload_sha256: record.payload_sha256.clone(),
            previous_record_sha256: record.previous_record_sha256.clone(),
            record_sha256: record.record_sha256.clone(),
        }
    }
}

impl From<StoredRecordV1> for EvidenceRecord {
    fn from(record: StoredRecordV1) -> Self {
        Self {
            cursor: record.cursor,
            observation_id: record.observation_id,
            payload: record.payload,
            payload_sha256: record.payload_sha256,
            previous_record_sha256: record.previous_record_sha256,
            record_sha256: record.record_sha256,
        }
    }
}

impl EvidenceIntakeOwner {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).context(IoSnafu { path: &root })?;
        for entry in fs::read_dir(&root).context(IoSnafu { path: &root })? {
            let entry = entry.context(IoSnafu { path: &root })?;
            if !entry.file_type().context(IoSnafu { path: &root })?.is_dir() {
                continue;
            }
            let node_root = entry.path();
            let node_id = entry.file_name();
            let node_id = node_id.to_str().ok_or_else(|| {
                EvidenceStateSnafu {
                    path: node_root.clone(),
                    reason: "evidence node directory is not valid UTF-8".to_owned(),
                }
                .build()
            })?;
            if !crate::node_id_is_valid(node_id) {
                return EvidenceStateSnafu {
                    path: node_root,
                    reason: "evidence node directory has an invalid identity".to_owned(),
                }
                .fail();
            }
            let state = read_state(&entry.path())?;
            if state.contiguous_cursor > 0 {
                verify_record_chain(&entry.path(), state)?;
            }
            let _coverage = read_coverage(&entry.path())?;
        }
        Ok(Self {
            root: Arc::new(root),
            lock: Arc::new(Mutex::new(())),
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn receive(
        &self,
        node_id: &str,
        batch: &EvidenceBatch,
    ) -> std::result::Result<EvidenceAck, Status> {
        validate_node_id(node_id)?;
        if batch.records.is_empty()
            || batch.records.len() > MAX_EVIDENCE_BATCH_RECORDS
            || batch.encoded_len() > MAX_EVIDENCE_BATCH_PAYLOAD_BYTES
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
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Status::internal("evidence intake state is poisoned"))?;
        let state = read_state(&node_root).map_err(internal_status)?;
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
        Ok(EvidenceAck {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch.batch_sha256.clone(),
        })
    }

    pub fn contiguous_cursor(&self, node_id: &str) -> Result<u64> {
        let _guard = self.lock.lock().map_err(|_| {
            EvidenceStateSnafu {
                path: self.root.as_ref().clone(),
                reason: "evidence intake state is poisoned".to_owned(),
            }
            .build()
        })?;
        let node_root = self.node_root(node_id)?;
        Ok(read_state(&node_root)?.contiguous_cursor)
    }

    #[allow(clippy::result_large_err)]
    pub fn receive_coverage(
        &self,
        node_id: &str,
        report: &CoverageReport,
    ) -> std::result::Result<CoverageAck, Status> {
        validate_node_id(node_id)?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Status::internal("evidence intake state is poisoned"))?;
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
        let state = read_coverage(&node_root)
            .map_err(internal_status)?
            .map_or_else(CoverageIntakeStateV1::default, |(state, _report)| state);
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
        let _guard = self.lock.lock().map_err(|_| {
            EvidenceStateSnafu {
                path: self.root.as_ref().clone(),
                reason: "evidence intake state is poisoned".to_owned(),
            }
            .build()
        })?;
        let node_root = self.node_root(node_id)?;
        Ok(read_coverage(&node_root)?.map(|(_state, report)| report))
    }

    fn node_root(&self, node_id: &str) -> Result<PathBuf> {
        if !crate::node_id_is_valid(node_id) {
            return EvidenceStateSnafu {
                path: self.root.as_ref().clone(),
                reason: "evidence node identity is invalid".to_owned(),
            }
            .fail();
        }
        Ok(self.root.join(node_id))
    }
}

#[allow(clippy::result_large_err)]
fn validate_node_id(node_id: &str) -> std::result::Result<(), Status> {
    if !crate::node_id_is_valid(node_id) {
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
        let state = CoverageStateV1::try_from(interval.state.as_str()).ok();
        let mut reasons = std::collections::BTreeSet::new();
        let reasons_valid = interval.gap_reasons.iter().all(|reason| {
            CoverageGapReasonV1::try_from(reason.as_str())
                .ok()
                .is_some_and(|reason| reasons.insert(reason))
        });
        let state_reasons_valid = match state {
            Some(CoverageStateV1::Healthy | CoverageStateV1::Closed) => reasons.is_empty(),
            Some(CoverageStateV1::Gapped) => !reasons.is_empty(),
            Some(CoverageStateV1::Unknown) => reasons.is_empty(),
            None => false,
        } && (!interval.current
            || state != Some(CoverageStateV1::Closed));
        let counter_regression = reasons.contains(&CoverageGapReasonV1::CounterRegression);
        let opening = interval.opening_counters.as_ref();
        let closing = interval.closing_counters.as_ref();
        let counters_valid = opening.is_some_and(valid_coverage_counters)
            && closing.is_none_or(valid_coverage_counters)
            && closing.is_none_or(|closing| {
                opening.is_some_and(|opening| coverage_counters_do_not_regress(opening, closing))
            });
        let exact_regression_record = state == Some(CoverageStateV1::Gapped)
            && counter_regression
            && opening.is_some()
            && closing.is_some();
        if !ids_valid
            || !reasons_valid
            || !state_reasons_valid
            || interval.source_epoch == 0
            || (interval.current && interval.source_epoch != report.source_epoch)
            || (!interval.current && interval.source_epoch > report.source_epoch)
            || interval.revision == 0
            || interval.first_sequence == 0
            || interval
                .last_sequence
                .is_some_and(|last| last < interval.first_sequence)
            || (!counters_valid && !exact_regression_record)
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
            current_healthy &= state == Some(CoverageStateV1::Healthy) && reasons.is_empty();
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

fn coverage_counters_do_not_regress(
    opening: &CoverageCounters,
    closing: &CoverageCounters,
) -> bool {
    closing.attempted >= opening.attempted
        && closing.suppressed >= opening.suppressed
        && closing.requested >= opening.requested
        && closing.emitted >= opening.emitted
        && closing.lost >= opening.lost
        && closing.classifier_miss_count >= opening.classifier_miss_count
        && closing.unresolved >= opening.unresolved
        && closing.next_sequence >= opening.next_sequence
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
        || record.payload.len() > MAX_EVIDENCE_RECORD_BYTES
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
    let Ok(envelope) = ObservationEnvelopeV1::from_wire_bytes(payload) else {
        return false;
    };
    envelope.observation_id.as_slice() == observation_id
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
    let bytes = serde_json::to_vec(&StoredRecordV1::from(record)).map_err(|error| {
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
    atomic_write(&path, &bytes)
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
    if populated {
        verify_last_record(root, state)?;
    }
    Ok(state)
}

fn verify_last_record(root: &Path, state: IntakeStateV1) -> Result<()> {
    let path = root.join(format!("{:020}.json", state.contiguous_cursor));
    let record = read_record(root, state.contiguous_cursor)?;
    let previous = record
        .previous_record_sha256
        .as_slice()
        .try_into()
        .map_err(|_| {
            EvidenceStateSnafu {
                path: path.clone(),
                reason: "last evidence record has an invalid previous digest".to_owned(),
            }
            .build()
        })?;
    let supplied: [u8; 32] = record.record_sha256.as_slice().try_into().map_err(|_| {
        EvidenceStateSnafu {
            path: path.clone(),
            reason: "last evidence record has an invalid digest".to_owned(),
        }
        .build()
    })?;
    if supplied != state.last_record_sha256
        || validate_record(&record, state.contiguous_cursor, previous).is_err()
    {
        return EvidenceStateSnafu {
            path,
            reason: "last evidence record does not match its durable cursor".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn verify_record_chain(root: &Path, state: IntakeStateV1) -> Result<()> {
    let mut previous = [0; 32];
    for cursor in 1..=state.contiguous_cursor {
        let record = read_record(root, cursor)?;
        validate_record(&record, cursor, previous).map_err(|status| {
            EvidenceStateSnafu {
                path: root.join(format!("{cursor:020}.json")),
                reason: format!("evidence record chain is invalid: {}", status.message()),
            }
            .build()
        })?;
        previous = record.record_sha256.as_slice().try_into().map_err(|_| {
            EvidenceStateSnafu {
                path: root.join(format!("{cursor:020}.json")),
                reason: "evidence record digest is not SHA-256".to_owned(),
            }
            .build()
        })?;
    }
    if previous != state.last_record_sha256 {
        return EvidenceStateSnafu {
            path: root.join("cursor.json"),
            reason: "evidence record chain does not match its durable cursor".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn read_record(root: &Path, cursor: u64) -> Result<EvidenceRecord> {
    let path = root.join(format!("{cursor:020}.json"));
    let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
    serde_json::from_slice::<StoredRecordV1>(&bytes)
        .map(Into::into)
        .map_err(|error| {
            EvidenceStateSnafu {
                path,
                reason: format!("evidence record decoding failed: {error}"),
            }
            .build()
        })
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
    atomic_write(&path, &bytes)
}

fn read_coverage(root: &Path) -> Result<Option<(CoverageIntakeStateV1, CoverageReport)>> {
    let path = root.join("coverage-cursor.json");
    if !path.exists() {
        return Ok(None);
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
    if empty {
        return Ok(None);
    }
    if !populated {
        return EvidenceStateSnafu {
            path,
            reason: "coverage cursor has inconsistent identity or digest".to_owned(),
        }
        .fail();
    }
    let report_path = root.join("coverage").join(format!(
        "{:020}-{:020}.pb",
        state.source_epoch, state.revision
    ));
    let bytes = fs::read(&report_path).context(IoSnafu { path: &report_path })?;
    let report = CoverageReport::decode(bytes.as_slice()).map_err(|error| {
        EvidenceStateSnafu {
            path: report_path.clone(),
            reason: format!("coverage report decoding failed: {error}"),
        }
        .build()
    })?;
    let supplied_digest: [u8; 32] = report.report_sha256.as_slice().try_into().map_err(|_| {
        EvidenceStateSnafu {
            path: report_path.clone(),
            reason: "coverage report digest is not SHA-256".to_owned(),
        }
        .build()
    })?;
    let mut unsigned = report.clone();
    unsigned.report_sha256.clear();
    let actual_digest: [u8; 32] = Sha256::digest(unsigned.encode_to_vec()).into();
    let report_valid = validate_coverage_report(&report).is_ok();
    if report.source_epoch != state.source_epoch
        || report.revision != state.revision
        || supplied_digest != state.report_sha256
        || actual_digest != state.report_sha256
        || !report_valid
    {
        return EvidenceStateSnafu {
            path: report_path,
            reason: "coverage report does not match its durable cursor".to_owned(),
        }
        .fail();
    }
    Ok(Some((state, report)))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        EvidenceStateSnafu {
            path: path.to_owned(),
            reason: "state path has no parent directory".to_owned(),
        }
        .build()
    })?;
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
        sync_directory(parent)?;
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
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .context(IoSnafu { path })?
        .sync_all()
        .context(IoSnafu { path })
}

fn internal_status(error: crate::Error) -> Status {
    Status::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::EvidenceIntakeOwner;
    use crate::{
        CoverageCounters, CoverageInterval, CoverageReport, EvidenceBatch, EvidenceFieldKeyV1,
        EvidenceFieldV1, EvidenceIdV1, EvidencePayloadV1, EvidenceRecord, EvidenceSensitivityV1,
        EvidenceValueV1, ObservationEnvelopeV1, ProofQualityV1, TemporalCoverageV1,
    };
    use prost::Message as _;
    use sha2::{Digest as _, Sha256};

    fn observation(cursor: u64) -> Result<ObservationEnvelopeV1, Box<dyn std::error::Error>> {
        let proof_quality = ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete);
        let payload = EvidencePayloadV1::new(
            vec![
                (
                    EvidenceFieldKeyV1::ReasonCode,
                    EvidenceValueV1::ReasonCode(9),
                ),
                (EvidenceFieldKeyV1::Decision, EvidenceValueV1::Decision(1)),
                (
                    EvidenceFieldKeyV1::EffectFamily,
                    EvidenceValueV1::EffectFamily(1),
                ),
                (EvidenceFieldKeyV1::Operation, EvidenceValueV1::Operation(2)),
                (EvidenceFieldKeyV1::Errno, EvidenceValueV1::Errno(-13)),
                (
                    EvidenceFieldKeyV1::KernelResult,
                    EvidenceValueV1::KernelResult(-13),
                ),
                (
                    EvidenceFieldKeyV1::TaskCookie,
                    EvidenceValueV1::TaskCookie(14),
                ),
            ]
            .into_iter()
            .map(|(key, value)| EvidenceFieldV1 {
                key,
                sensitivity: EvidenceSensitivityV1::Internal,
                provenance_observation_ids: Vec::new(),
                proof_quality,
                value,
            })
            .collect(),
        )?;
        Ok(ObservationEnvelopeV1 {
            schema_version: 1,
            tenant_id: EvidenceIdV1::new(1, 2),
            observation_id: [0; 32],
            source_id: EvidenceIdV1::new(3, 4),
            source_epoch: 5,
            source_sequence: cursor,
            stable_provider_event_id: None,
            node_boot_id: Some(EvidenceIdV1::new(6, 7)),
            cpu_id: Some(0),
            hook_or_adapter_id: 1,
            payload_schema_id: 1,
            abi_or_api_version: 1,
            profile_generation_ref_id: Some(8),
            boottime_ns: Some(cursor),
            projected_utc_ns: None,
            time_uncertainty_ns: u64::MAX,
            ingested_utc_ns: 10,
            payload,
            proof_quality,
            coverage_interval_id: EvidenceIdV1::new(11, 12),
            transport_integrity_digest: [13; 32],
            signature_or_batch_digest: None,
        }
        .finalize()?)
    }

    fn record_from_payload(
        cursor: u64,
        observation_id: [u8; 32],
        payload: Vec<u8>,
        previous: [u8; 32],
    ) -> EvidenceRecord {
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

    fn record(
        cursor: u64,
        previous: [u8; 32],
    ) -> Result<EvidenceRecord, Box<dyn std::error::Error>> {
        let observation = observation(cursor)?;
        Ok(record_from_payload(
            cursor,
            observation.observation_id,
            observation.wire_bytes()?,
            previous,
        ))
    }

    fn batch(
        first: u64,
        count: u64,
        mut previous: [u8; 32],
    ) -> Result<EvidenceBatch, Box<dyn std::error::Error>> {
        let mut records = Vec::new();
        for cursor in first..first + count {
            let record = record(cursor, previous)?;
            previous.copy_from_slice(&record.record_sha256);
            records.push(record);
        }
        Ok(EvidenceBatch {
            first_cursor: first,
            last_cursor: first + count - 1,
            batch_sha256: super::batch_digest_for(&records).to_vec(),
            records,
        })
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
        let first = batch(1, 2, [0; 32])?;
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
                .receive("node-a", &batch(3, 1, previous)?)?
                .last_cursor,
            3
        );
        assert!(intake.receive("node-a", &batch(5, 1, previous)?).is_err());
        Ok(())
    }

    #[test]
    fn intake_rejects_payload_and_chain_corruption() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut corrupted = batch(1, 2, [0; 32])?;
        corrupted.records[1].payload[0] ^= 1;
        assert!(intake.receive("node-a", &corrupted).is_err());
        assert_eq!(intake.contiguous_cursor("node-a")?, 0);
        Ok(())
    }

    #[test]
    fn intake_requires_a_complete_self_consistent_envelope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;

        let shallow_id = [1; 32];
        let shallow_payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "observation_id": shallow_id,
        }))?;
        let shallow = record_from_payload(1, shallow_id, shallow_payload, [0; 32]);
        let shallow_batch = EvidenceBatch {
            first_cursor: 1,
            last_cursor: 1,
            batch_sha256: super::batch_digest_for(std::slice::from_ref(&shallow)).to_vec(),
            records: vec![shallow],
        };
        assert!(intake.receive("node-a", &shallow_batch).is_err());

        let mut tampered = observation(1)?;
        tampered.coverage_interval_id = EvidenceIdV1::new(20, 21);
        let tampered_payload = serde_json::to_vec(&tampered)?;
        let tampered = record_from_payload(1, tampered.observation_id, tampered_payload, [0; 32]);
        let tampered_batch = EvidenceBatch {
            first_cursor: 1,
            last_cursor: 1,
            batch_sha256: super::batch_digest_for(std::slice::from_ref(&tampered)).to_vec(),
            records: vec![tampered],
        };
        assert!(intake.receive("node-a", &tampered_batch).is_err());
        assert_eq!(intake.contiguous_cursor("node-a")?, 0);
        Ok(())
    }

    #[test]
    fn intake_rejects_parent_and_current_directory_node_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let valid = batch(1, 1, [0; 32])?;
        assert!(intake.receive(".", &valid).is_err());
        assert!(intake.receive("..", &valid).is_err());
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
        drop(intake);
        assert!(EvidenceIntakeOwner::open(directory.path()).is_err());
        Ok(())
    }

    #[test]
    fn coverage_intake_retains_closed_history_from_an_older_epoch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut report = coverage_report(8, 1, "HEALTHY");
        let mut old = coverage_report(7, 2, "GAPPED").intervals.remove(0);
        old.interval_id = vec![3; 16];
        old.current = false;
        report.intervals.insert(0, old);
        report.report_sha256.clear();
        report.report_sha256 = Sha256::digest(report.encode_to_vec()).to_vec();

        intake.receive_coverage("node-a", &report)?;
        assert_eq!(
            intake
                .latest_coverage_report("node-a")?
                .ok_or("missing coverage report")?
                .intervals
                .len(),
            2
        );
        Ok(())
    }

    #[test]
    fn recovery_rechecks_the_complete_durable_chain() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let first = batch(1, 2, [0; 32])?;
        intake.receive("node-a", &first)?;
        let path = directory.path().join("node-a/00000000000000000001.json");
        std::fs::write(&path, b"corrupt durable record")?;
        drop(intake);
        assert!(EvidenceIntakeOwner::open(directory.path()).is_err());
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
        intake.receive("node-a", &batch(1, 1, [0; 32])?)?;
        intake.receive_coverage("node-a", &coverage_report(7, 1, "HEALTHY"))?;
        assert!(!record_temporary.exists());
        assert!(!coverage_temporary.exists());
        Ok(())
    }

    #[test]
    fn coverage_intake_rejects_inconsistent_healthy_claims(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;

        let mut reasoned_healthy = coverage_report(7, 1, "HEALTHY");
        reasoned_healthy.intervals[0].gap_reasons = vec!["RING_LOSS".to_owned()];
        reasoned_healthy.report_sha256.clear();
        reasoned_healthy.report_sha256 = Sha256::digest(reasoned_healthy.encode_to_vec()).to_vec();
        assert!(intake
            .receive_coverage("node-a", &reasoned_healthy)
            .is_err());

        let mut regressed_healthy = coverage_report(7, 1, "HEALTHY");
        regressed_healthy.intervals[0].opening_counters = Some(CoverageCounters {
            attempted: 4,
            requested: 4,
            emitted: 4,
            next_sequence: 4,
            ..CoverageCounters::default()
        });
        regressed_healthy.report_sha256.clear();
        regressed_healthy.report_sha256 =
            Sha256::digest(regressed_healthy.encode_to_vec()).to_vec();
        assert!(intake
            .receive_coverage("node-a", &regressed_healthy)
            .is_err());
        Ok(())
    }
}
