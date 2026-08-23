use std::path::PathBuf;

use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::Status;

use crate::error::EvidenceStateSnafu;
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
pub(crate) const MAX_PENDING_EVIDENCE_RECORDS: u64 = 4_096;

#[derive(Clone)]
/// Owns evidence validation and delegates atomic persistence to the Control store.
pub struct EvidenceIntakeOwner {
    store: crate::ControlStore,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
/// Separates evidence streams by authenticated tenant, node session, source, and source epoch.
pub struct EvidenceIntakeIdentityV1 {
    pub tenant_id: [u8; 16],
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    pub source_id: [u8; 16],
    pub source_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedEvidenceNodeV1 {
    pub tenant_id: [u8; 16],
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IntakeStateV1 {
    pub contiguous_cursor: u64,
    pub last_first_cursor: u64,
    pub last_batch_sha256: [u8; 32],
    pub last_record_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoverageIntakeStateV1 {
    pub source_epoch: u64,
    pub revision: u64,
    pub report_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRecordV1 {
    pub cursor: u64,
    pub observation_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub payload_sha256: Vec<u8>,
    pub previous_record_sha256: Vec<u8>,
    pub record_sha256: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredEvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub batch_sha256: [u8; 32],
    pub records: Vec<StoredRecordV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCoverageReportV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub state: CoverageIntakeStateV1,
    pub encoded_report: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceStoreOutcomeV1 {
    Accepted,
    Pending,
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
        Ok(Self::from_store(crate::ControlStore::open(root)?))
    }

    #[must_use]
    pub fn from_store(store: crate::ControlStore) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> crate::ControlStore {
        self.store.clone()
    }

    #[allow(clippy::result_large_err)]
    pub fn receive(
        &self,
        authenticated: &AuthenticatedEvidenceNodeV1,
        batch: &EvidenceBatch,
    ) -> std::result::Result<EvidenceAck, Status> {
        validate_authenticated_node(authenticated)?;
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
        if batch.last_cursor < batch.first_cursor
            || batch.last_cursor - batch.first_cursor + 1
                != u64::try_from(batch.records.len()).unwrap_or(u64::MAX)
        {
            return Err(Status::invalid_argument(
                "evidence batch cursor range does not match its record count",
            ));
        }
        let mut previous = batch
            .records
            .first()
            .and_then(|record| record.previous_record_sha256.as_slice().try_into().ok())
            .ok_or_else(|| {
                Status::invalid_argument("evidence batch has no valid previous record digest")
            })?;
        // Every record in a batch must resolve to the same authenticated evidence stream.
        let mut stream_identity = None;
        for (index, record) in batch.records.iter().enumerate() {
            let cursor = batch.first_cursor
                + u64::try_from(index).map_err(|_| {
                    Status::invalid_argument("evidence batch record index exceeds u64")
                })?;
            validate_record(record, cursor, previous)?;
            let envelope = ObservationEnvelopeV1::from_wire_bytes(&record.payload)
                .map_err(|_| Status::invalid_argument("evidence payload schema is invalid"))?;
            let identity = EvidenceIntakeIdentityV1 {
                tenant_id: envelope.tenant_id.to_be_bytes(),
                node_id: authenticated.node_id.clone(),
                node_boot_id: envelope
                    .node_boot_id
                    .ok_or_else(|| Status::invalid_argument("node evidence has no boot identity"))?
                    .to_be_bytes(),
                label_epoch: authenticated.label_epoch,
                source_id: envelope.source_id.to_be_bytes(),
                source_epoch: envelope.source_epoch,
            };
            if identity.tenant_id != authenticated.tenant_id
                || identity.node_boot_id != authenticated.node_boot_id
                || stream_identity
                    .as_ref()
                    .is_some_and(|current| current != &identity)
            {
                return Err(Status::permission_denied(
                    "evidence tenant, boot, source, or label identity is not authenticated",
                ));
            }
            stream_identity = Some(identity);
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
        let identity = stream_identity
            .ok_or_else(|| Status::invalid_argument("evidence batch has no stream identity"))?;
        let stored = StoredEvidenceBatchV1 {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch_digest,
            records: batch.records.iter().map(StoredRecordV1::from).collect(),
        };
        // Pending batches are durable but receive no acknowledgement before the gap closes.
        if self
            .store
            .accept_evidence_batch(identity, stored)
            .map_err(internal_status)?
            == EvidenceStoreOutcomeV1::Pending
        {
            return Err(Status::unavailable(
                "evidence batch is durable but waits for an earlier cursor range",
            ));
        }
        Ok(EvidenceAck {
            first_cursor: batch.first_cursor,
            last_cursor: batch.last_cursor,
            batch_sha256: batch.batch_sha256.clone(),
        })
    }

    pub fn contiguous_cursor(&self, identity: &EvidenceIntakeIdentityV1) -> Result<u64> {
        self.store.evidence_cursor(identity)
    }

    #[allow(clippy::result_large_err)]
    pub fn receive_coverage(
        &self,
        authenticated: &AuthenticatedEvidenceNodeV1,
        report: &CoverageReport,
    ) -> std::result::Result<CoverageAck, Status> {
        validate_authenticated_node(authenticated)?;
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
        // Current intervals must describe one source so the report has one durable cursor.
        let source_ids = report
            .intervals
            .iter()
            .filter(|interval| interval.current)
            .map(|interval| interval.source_id.as_slice())
            .collect::<std::collections::BTreeSet<_>>();
        if source_ids.len() != 1 {
            return Err(Status::invalid_argument(
                "coverage must have exactly one current source identity",
            ));
        }
        let source_id: [u8; 16] = source_ids
            .into_iter()
            .next()
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| Status::invalid_argument("coverage has no current source identity"))?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: authenticated.tenant_id,
            node_id: authenticated.node_id.clone(),
            node_boot_id: authenticated.node_boot_id,
            label_epoch: authenticated.label_epoch,
            source_id,
            source_epoch: report.source_epoch,
        };
        self.store
            .accept_coverage_report(StoredCoverageReportV1 {
                identity,
                state: CoverageIntakeStateV1 {
                    source_epoch: report.source_epoch,
                    revision: report.revision,
                    report_sha256: report_digest,
                },
                encoded_report: report.encode_to_vec(),
            })
            .map_err(internal_status)?;
        Ok(coverage_ack(report))
    }

    pub fn latest_coverage_report(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<CoverageReport>> {
        self.store
            .latest_coverage_report(identity)?
            .map(|stored| {
                CoverageReport::decode(stored.encoded_report.as_slice()).map_err(|error| {
                    EvidenceStateSnafu {
                        path: self.store.root(),
                        reason: format!("stored coverage report decoding failed: {error}"),
                    }
                    .build()
                })
            })
            .transpose()
    }
}

#[allow(clippy::result_large_err)]
fn validate_authenticated_node(
    authenticated: &AuthenticatedEvidenceNodeV1,
) -> std::result::Result<(), Status> {
    if !crate::node_id_is_valid(&authenticated.node_id)
        || authenticated.tenant_id == [0; 16]
        || authenticated.node_boot_id == [0; 16]
        || authenticated.label_epoch == 0
    {
        return Err(Status::invalid_argument(
            "authenticated evidence identity is invalid",
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
    // Negative claims require a current healthy interval for every reported CPU.
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
        // Counter regression is valid only when both counter snapshots preserve the proof.
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
    // Verify both the payload identity and the hash-chain link before persistence.
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

    fn authenticated() -> super::AuthenticatedEvidenceNodeV1 {
        super::AuthenticatedEvidenceNodeV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: EvidenceIdV1::new(6, 7).to_be_bytes(),
            label_epoch: 9,
        }
    }

    fn evidence_identity() -> super::EvidenceIntakeIdentityV1 {
        super::EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: EvidenceIdV1::new(6, 7).to_be_bytes(),
            label_epoch: 9,
            source_id: EvidenceIdV1::new(3, 4).to_be_bytes(),
            source_epoch: 5,
        }
    }

    fn coverage_identity(epoch: u64) -> super::EvidenceIntakeIdentityV1 {
        super::EvidenceIntakeIdentityV1 {
            source_id: [2; 16],
            source_epoch: epoch,
            ..evidence_identity()
        }
    }

    #[test]
    fn intake_promotes_durable_out_of_order_batches_and_is_idempotent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let first = batch(1, 2, [0; 32])?;
        let previous = first
            .records
            .last()
            .and_then(|record| record.record_sha256.as_slice().try_into().ok())
            .ok_or("first batch has no final digest")?;
        let third = batch(3, 1, previous)?;

        let Err(pending) = intake.receive(&authenticated(), &third) else {
            return Err("out-of-order evidence did not wait for its gap".into());
        };
        assert_eq!(pending.code(), tonic::Code::Unavailable);
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 0);

        let ack = intake.receive(&authenticated(), &first)?;
        assert_eq!(ack.last_cursor, 2);
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 3);
        assert_eq!(intake.receive(&authenticated(), &first)?, ack);
        assert_eq!(intake.receive(&authenticated(), &third)?.last_cursor, 3);
        assert_eq!(
            intake
                .store()
                .accepted_evidence_records(&evidence_identity())?
                .len(),
            3
        );

        drop(intake);
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 3);
        assert_eq!(
            intake
                .store()
                .accepted_evidence_records(&evidence_identity())?
                .len(),
            3
        );
        Ok(())
    }

    #[test]
    fn intake_rejects_corruption_and_conflicting_accepted_ranges(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut corrupted = batch(1, 2, [0; 32])?;
        corrupted.records[1].payload[0] ^= 1;
        assert!(intake.receive(&authenticated(), &corrupted).is_err());
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 0);

        let accepted = batch(1, 1, [0; 32])?;
        intake.receive(&authenticated(), &accepted)?;
        let mut different_observation = observation(1)?;
        different_observation.ingested_utc_ns = 11;
        let different_observation = different_observation.finalize()?;
        let different = record_from_payload(
            1,
            different_observation.observation_id,
            different_observation.wire_bytes()?,
            [0; 32],
        );
        let conflicting = EvidenceBatch {
            first_cursor: 1,
            last_cursor: 1,
            batch_sha256: super::batch_digest_for(std::slice::from_ref(&different)).to_vec(),
            records: vec![different],
        };
        assert!(intake.receive(&authenticated(), &conflicting).is_err());
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 1);
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
        assert!(intake.receive(&authenticated(), &shallow_batch).is_err());

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
        assert!(intake.receive(&authenticated(), &tampered_batch).is_err());
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 0);
        Ok(())
    }

    #[test]
    fn intake_binds_enrolled_tenant_boot_and_label_epoch() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let valid = batch(1, 1, [0; 32])?;
        let mut wrong_tenant = authenticated();
        wrong_tenant.tenant_id = [20; 16];
        let Err(wrong_tenant) = intake.receive(&wrong_tenant, &valid) else {
            return Err("cross-tenant evidence was accepted".into());
        };
        assert_eq!(wrong_tenant.code(), tonic::Code::PermissionDenied);
        let mut wrong_boot = authenticated();
        wrong_boot.node_boot_id = [21; 16];
        let Err(wrong_boot) = intake.receive(&wrong_boot, &valid) else {
            return Err("evidence from another boot was accepted".into());
        };
        assert_eq!(wrong_boot.code(), tonic::Code::PermissionDenied);
        intake.receive(&authenticated(), &valid)?;
        let mut next_label = authenticated();
        next_label.label_epoch += 1;
        assert!(intake.receive(&next_label, &valid).is_err());
        Ok(())
    }

    #[test]
    fn coverage_intake_is_durable_monotonic_and_gap_aware() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let healthy = coverage_report(7, 1, "HEALTHY");
        assert_eq!(
            intake
                .receive_coverage(&authenticated(), &healthy)?
                .revision,
            healthy.revision
        );
        assert_eq!(
            intake
                .receive_coverage(&authenticated(), &healthy)?
                .revision,
            1
        );
        let gapped = coverage_report(7, 2, "GAPPED");
        intake.receive_coverage(&authenticated(), &gapped)?;
        assert!(
            !intake
                .latest_coverage_report(&coverage_identity(7))?
                .ok_or("missing coverage report")?
                .negative_claim_eligible
        );
        assert!(intake.receive_coverage(&authenticated(), &healthy).is_err());
        drop(intake);
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        assert_eq!(
            intake
                .latest_coverage_report(&coverage_identity(7))?
                .ok_or("missing recovered coverage report")?
                .revision,
            2
        );
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

        intake.receive_coverage(&authenticated(), &report)?;
        assert_eq!(
            intake
                .latest_coverage_report(&coverage_identity(8))?
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
        intake.receive(&authenticated(), &first)?;
        let path = directory.path().join("commits/00000000000000000001.json");
        std::fs::write(&path, b"corrupt durable record")?;
        drop(intake);
        assert!(EvidenceIntakeOwner::open(directory.path()).is_err());
        Ok(())
    }

    #[test]
    fn intake_removes_owned_torn_commit_writes() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let commits = directory.path().join("commits");
        std::fs::create_dir_all(&commits)?;
        let temporary = commits.join("00000000000000000001.tmp");
        std::fs::write(&temporary, b"torn commit")?;

        let intake = EvidenceIntakeOwner::open(directory.path())?;
        intake.receive(&authenticated(), &batch(1, 1, [0; 32])?)?;
        assert!(!temporary.exists());
        assert!(commits.join("00000000000000000001.json").exists());
        Ok(())
    }

    #[test]
    fn storage_failure_does_not_advance_the_acknowledged_cursor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let blocked_temporary = directory.path().join("commits/00000000000000000001.tmp");
        std::fs::create_dir(&blocked_temporary)?;
        let first = batch(1, 1, [0; 32])?;

        assert!(intake.receive(&authenticated(), &first).is_err());
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 0);
        assert_eq!(intake.store().commit_index(), 0);

        std::fs::remove_dir(blocked_temporary)?;
        assert_eq!(intake.receive(&authenticated(), &first)?.last_cursor, 1);
        assert_eq!(intake.contiguous_cursor(&evidence_identity())?, 1);
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
            .receive_coverage(&authenticated(), &reasoned_healthy)
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
            .receive_coverage(&authenticated(), &regressed_healthy)
            .is_err());
        Ok(())
    }
}
