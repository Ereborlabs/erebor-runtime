use std::path::PathBuf;

use prost::Message as _;
use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::evidence_segment::EvidenceSegmentRefV1;
use crate::{
    CoverageAck, CoverageCounters, CoverageReport, EvidenceAck, EvidenceBatch, EvidenceRecord,
    Result,
};

mod model;

pub use model::*;

pub const MAX_EVIDENCE_BATCH_RECORDS: usize = 4_096;
pub const DEFAULT_EVIDENCE_BATCH_RECORDS: usize = MAX_EVIDENCE_BATCH_RECORDS;
pub const MAX_EVIDENCE_RECORD_BYTES: usize = 128 * 1_024;
pub const MAX_EVIDENCE_GRPC_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_EVIDENCE_BATCH_PAYLOAD_BYTES: usize = 3 * 1_024 * 1_024;
pub const MAX_EVIDENCE_SEGMENT_BYTES: usize = 16 * 1_024 * 1_024;
pub const MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_COVERAGE_INTERVALS: usize = 8_192;
pub(crate) const MAX_PENDING_EVIDENCE_RECORDS: u64 = 4_096;

#[derive(Clone)]
/// Owns evidence validation and delegates atomic persistence to the Control store.
pub struct EvidenceIntakeOwner {
    store: crate::ControlStore,
}

#[derive(Clone)]
/// Owns the durable boundary after which retained evidence can be reclaimed.
pub struct EvidenceRetentionOwner {
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
/// Records the highest source positions that a durable consumer has incorporated.
pub struct EvidenceConsumptionWatermarkV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub evidence_cursor: u64,
    pub coverage_revision: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceConsumptionStateV1 {
    pub evidence_cursor: u64,
    pub coverage_revision: u64,
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
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoverageIntakeStateV1 {
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EvidenceBatchInputV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub framed_records: prost::bytes::Bytes,
    pub frame_ends: Vec<usize>,
}

impl EvidenceBatchInputV1 {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn encode(first_cursor: u64, records: Vec<EvidenceRecord>) -> Result<Self> {
        let mut framed_records = Vec::new();
        let mut frame_ends = Vec::with_capacity(records.len());
        for record in records {
            let payload = record.encode_to_vec();
            let length = u32::try_from(payload.len()).map_err(|error| {
                crate::error::ControlStoreSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: format!("the evidence record length is not representable: {error}"),
                }
                .build()
            })?;
            let start = framed_records.len();
            framed_records.extend_from_slice(&length.to_be_bytes());
            framed_records.extend_from_slice(&payload);
            let checksum = crc32c::crc32c(&framed_records[start..]);
            framed_records.extend_from_slice(&checksum.to_be_bytes());
            frame_ends.push(framed_records.len());
        }
        let last_cursor = first_cursor
            .checked_add(frame_ends.len() as u64)
            .and_then(|cursor| cursor.checked_sub(1))
            .ok_or_else(|| {
                crate::error::ControlStoreSnafu {
                    path: PathBuf::from("<evidence-record>"),
                    reason: "the evidence batch cursor range is exhausted".to_owned(),
                }
                .build()
            })?;
        Ok(Self {
            first_cursor,
            last_cursor,
            framed_records: framed_records.into(),
            frame_ends,
        })
    }

    pub(crate) fn record_count(&self) -> usize {
        self.frame_ends.len()
    }

    pub(crate) fn split_off(&mut self, record_index: usize) -> Self {
        let byte_index = record_index
            .checked_sub(1)
            .and_then(|index| self.frame_ends.get(index).copied())
            .unwrap_or_default();
        let framed_records = self.framed_records.split_off(byte_index);
        let frame_ends = self
            .frame_ends
            .split_off(record_index)
            .into_iter()
            .map(|end| end - byte_index)
            .collect();
        Self {
            first_cursor: self.first_cursor + record_index as u64,
            last_cursor: self.last_cursor,
            framed_records,
            frame_ends,
        }
    }

    pub(crate) fn prefix_bytes(&self, record_count: usize) -> &[u8] {
        let end = record_count
            .checked_sub(1)
            .and_then(|index| self.frame_ends.get(index).copied())
            .unwrap_or_default();
        &self.framed_records[..end]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredEvidenceBatchV1 {
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub segment: EvidenceSegmentRefV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCoverageReportV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub state: CoverageIntakeStateV1,
    pub segment: EvidenceSegmentRefV1,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CoverageReportInputV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub report: CoverageReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceStoreOutcomeV1 {
    Accepted,
    Pending,
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
    pub(crate) fn authenticate_retained_batch(
        &self,
        tenant_id: [u8; 16],
        node_id: &str,
        batch: &EvidenceBatch,
    ) -> std::result::Result<AuthenticatedEvidenceNodeV1, Status> {
        let node_boot_id: [u8; 16] = batch
            .node_boot_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("evidence boot identity is not Id128"))?;
        let source_id: [u8; 16] = batch
            .source_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("evidence source identity is not Id128"))?;
        // Current mTLS and trust authenticate the sender. The retained record selects
        // the exact durable session that originally owned its immutable stream.
        let session = self
            .store
            .evidence_session_for_stream(
                tenant_id,
                node_id,
                node_boot_id,
                source_id,
                batch.source_epoch,
            )
            .map_err(|_| {
                Status::permission_denied(
                    "evidence stream does not name one authenticated node session",
                )
            })?;
        Ok(AuthenticatedEvidenceNodeV1 {
            tenant_id,
            node_id: node_id.to_owned(),
            node_boot_id,
            label_epoch: session.label_epoch,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn receive(
        &self,
        authenticated: &AuthenticatedEvidenceNodeV1,
        batch: EvidenceBatch,
    ) -> std::result::Result<EvidenceAck, Status> {
        self.receive_group(vec![(authenticated.clone(), batch)])
    }

    #[allow(clippy::result_large_err)]
    pub fn receive_group(
        &self,
        batches: Vec<(AuthenticatedEvidenceNodeV1, EvidenceBatch)>,
    ) -> std::result::Result<EvidenceAck, Status> {
        let mut group_identity = None;
        let mut group_first_cursor: Option<u64> = None;
        let mut group_last_cursor: Option<u64> = None;
        let mut framed_records = Vec::new();
        let mut frame_ends = Vec::new();
        for (authenticated, batch) in batches {
            let (identity, input) = self.validate_batch(&authenticated, batch)?;
            if group_identity
                .as_ref()
                .is_some_and(|group| group != &identity)
                || group_last_cursor
                    .and_then(|cursor| cursor.checked_add(1))
                    .is_some_and(|next| next != input.first_cursor)
                || framed_records
                    .len()
                    .saturating_add(input.framed_records.len())
                    > MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES
            {
                return Err(Status::invalid_argument(
                    "an evidence commit group crossed its stream, cursor, or segment bound",
                ));
            }
            let byte_offset = framed_records.len();
            framed_records.extend_from_slice(&input.framed_records);
            frame_ends.extend(input.frame_ends.into_iter().map(|end| end + byte_offset));
            group_first_cursor.get_or_insert(input.first_cursor);
            group_last_cursor = Some(input.last_cursor);
            group_identity.get_or_insert(identity);
        }
        let identity = group_identity
            .ok_or_else(|| Status::invalid_argument("an evidence commit group is empty"))?;
        let stored = EvidenceBatchInputV1 {
            first_cursor: group_first_cursor.unwrap_or_default(),
            last_cursor: group_last_cursor.unwrap_or_default(),
            framed_records: framed_records.into(),
            frame_ends,
        };
        // Pending batches are durable but receive no acknowledgement before the gap closes.
        if self
            .store
            .accept_evidence_batch(identity.clone(), stored)
            .map_err(internal_status)?
            == EvidenceStoreOutcomeV1::Pending
        {
            return Err(Status::unavailable(
                "evidence batch is durable but waits for an earlier cursor range",
            ));
        }
        Ok(EvidenceAck {
            contiguous_cursor: self
                .store
                .evidence_cursor(&identity)
                .map_err(internal_status)?,
        })
    }

    #[allow(clippy::result_large_err)]
    fn validate_batch(
        &self,
        authenticated: &AuthenticatedEvidenceNodeV1,
        batch: EvidenceBatch,
    ) -> std::result::Result<(EvidenceIntakeIdentityV1, EvidenceBatchInputV1), Status> {
        validate_authenticated_node(authenticated)?;
        let node_boot_id: [u8; 16] = batch
            .node_boot_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("evidence boot identity is not Id128"))?;
        let source_id: [u8; 16] = batch
            .source_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("evidence source identity is not Id128"))?;
        if batch.framed_records.is_empty()
            || batch.encoded_len() > MAX_EVIDENCE_BATCH_PAYLOAD_BYTES
            || node_boot_id == [0; 16]
            || source_id == [0; 16]
            || batch.source_epoch == 0
            || batch.node_boot_id.as_slice() != authenticated.node_boot_id
        {
            return Err(Status::invalid_argument(
                "evidence batch identity or bounds are invalid",
            ));
        }
        if batch.first_cursor == 0 {
            return Err(Status::invalid_argument(
                "evidence batch cursor range does not match its record count",
            ));
        }
        let mut frame_ends = Vec::new();
        let mut offset = 0_usize;
        while offset < batch.framed_records.len() {
            let length_end = offset.checked_add(4).ok_or_else(|| {
                Status::invalid_argument("evidence record frame length is exhausted")
            })?;
            if length_end > batch.framed_records.len() {
                return Err(Status::invalid_argument(
                    "evidence record frame length is incomplete",
                ));
            }
            let payload_bytes = u32::from_be_bytes(
                batch.framed_records[offset..length_end]
                    .try_into()
                    .unwrap_or_default(),
            ) as usize;
            if payload_bytes == 0 || payload_bytes > MAX_EVIDENCE_RECORD_BYTES {
                return Err(Status::invalid_argument(
                    "evidence record frame is outside its size bound",
                ));
            }
            let payload_end = length_end
                .checked_add(payload_bytes)
                .ok_or_else(|| Status::invalid_argument("evidence record frame is exhausted"))?;
            let frame_end = payload_end
                .checked_add(4)
                .ok_or_else(|| Status::invalid_argument("evidence record frame is exhausted"))?;
            if frame_end > batch.framed_records.len() {
                return Err(Status::invalid_argument(
                    "evidence record frame payload is incomplete",
                ));
            }
            let expected = u32::from_be_bytes(
                batch.framed_records[payload_end..frame_end]
                    .try_into()
                    .unwrap_or_default(),
            );
            if crc32c::crc32c(&batch.framed_records[offset..payload_end]) != expected {
                return Err(Status::invalid_argument(
                    "evidence record frame checksum is invalid",
                ));
            }
            let record =
                EvidenceRecord::decode(batch.framed_records.slice(length_end..payload_end))
                    .map_err(|_| Status::invalid_argument("evidence record protobuf is invalid"))?;
            let index = frame_ends.len();
            let cursor = batch.first_cursor
                + u64::try_from(index).map_err(|_| {
                    Status::invalid_argument("evidence batch record index exceeds u64")
                })?;
            ObservationEnvelopeV1::from_wire_record(
                authenticated.tenant_id.into(),
                node_boot_id.into(),
                source_id.into(),
                batch.source_epoch,
                cursor,
                batch.cpu_id,
                &record,
            )
            .map_err(|_| Status::invalid_argument("evidence record is invalid"))?;
            frame_ends.push(frame_end);
            offset = frame_end;
        }
        if frame_ends.len() > MAX_EVIDENCE_BATCH_RECORDS {
            return Err(Status::invalid_argument(
                "evidence batch exceeds the record bound",
            ));
        }
        let last_cursor = batch
            .first_cursor
            .checked_add(u64::try_from(frame_ends.len()).unwrap_or(u64::MAX))
            .and_then(|cursor| cursor.checked_sub(1))
            .ok_or_else(|| Status::invalid_argument("evidence batch cursor range overflowed"))?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: authenticated.tenant_id,
            node_id: authenticated.node_id.clone(),
            node_boot_id,
            label_epoch: authenticated.label_epoch,
            source_id,
            source_epoch: batch.source_epoch,
        };
        let stored = EvidenceBatchInputV1 {
            first_cursor: batch.first_cursor,
            last_cursor,
            framed_records: batch.framed_records,
            frame_ends,
        };
        Ok((identity, stored))
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
        let source_id: [u8; 16] = report
            .source_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("coverage source identity is not Id128"))?;
        validate_coverage_report(report)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: authenticated.tenant_id,
            node_id: authenticated.node_id.clone(),
            node_boot_id: authenticated.node_boot_id,
            label_epoch: authenticated.label_epoch,
            source_id,
            source_epoch: report.source_epoch,
        };
        self.store
            .accept_coverage_report(CoverageReportInputV1 {
                identity,
                report: report.clone(),
            })
            .map_err(internal_status)?;
        Ok(CoverageAck {})
    }

    pub fn latest_coverage_report(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<Option<CoverageReport>> {
        self.store.latest_coverage_report(identity)
    }
}

impl EvidenceRetentionOwner {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::from_store(crate::ControlStore::open(root)?))
    }

    #[must_use]
    pub fn from_store(store: crate::ControlStore) -> Self {
        Self { store }
    }

    pub fn acknowledge(&self, watermark: EvidenceConsumptionWatermarkV1) -> Result<u64> {
        self.store.acknowledge_evidence_consumption(watermark)
    }

    pub fn watermark(
        &self,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<EvidenceConsumptionWatermarkV1> {
        let state = self.store.evidence_consumption(identity)?;
        Ok(EvidenceConsumptionWatermarkV1 {
            identity: identity.clone(),
            evidence_cursor: state.evidence_cursor,
            coverage_revision: state.coverage_revision,
        })
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
        || report.source_id.len() != 16
        || report.source_id.iter().all(|byte| *byte == 0)
        || report.revision == 0
        || report.intervals.is_empty()
        || report.intervals.len() > MAX_COVERAGE_INTERVALS
    {
        return Err(Status::invalid_argument(
            "coverage report epoch, revision, or interval bounds are invalid",
        ));
    }
    let mut interval_ids = std::collections::BTreeSet::new();
    let mut current_count = 0_usize;
    for interval in &report.intervals {
        let ids_valid = interval.interval_id.len() == 16
            && interval.interval_id.iter().any(|byte| *byte != 0)
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
        }
    }
    if current_count != 1 {
        return Err(Status::invalid_argument(
            "coverage report must contain one current interval",
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

fn internal_status(error: crate::Error) -> Status {
    Status::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use crate::{
        CoverageCounters, CoverageInterval, CoverageReport, EvidenceBatch, EvidenceIdV1,
        EvidenceRecord, KernelEffectEvidenceV1, ObservationEnvelopeV1, TemporalCoverageV1,
    };

    use super::{AuthenticatedEvidenceNodeV1, EvidenceIntakeIdentityV1, EvidenceIntakeOwner};

    fn authenticated() -> AuthenticatedEvidenceNodeV1 {
        AuthenticatedEvidenceNodeV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: EvidenceIdV1::new(6, 7).to_be_bytes(),
            label_epoch: 9,
        }
    }

    fn identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: authenticated().tenant_id,
            node_id: authenticated().node_id,
            node_boot_id: authenticated().node_boot_id,
            label_epoch: authenticated().label_epoch,
            source_id: EvidenceIdV1::new(3, 4).to_be_bytes(),
            source_epoch: 5,
        }
    }

    fn observation(sequence: u64) -> ObservationEnvelopeV1 {
        ObservationEnvelopeV1 {
            tenant_id: EvidenceIdV1::from(authenticated().tenant_id),
            node_boot_id: EvidenceIdV1::from(authenticated().node_boot_id),
            source_id: EvidenceIdV1::from(identity().source_id),
            source_epoch: identity().source_epoch,
            source_sequence: sequence,
            cpu_id: 0,
            observed_boottime_ns: sequence,
            ingested_utc_ns: 10,
            coverage_interval_id: EvidenceIdV1::new(11, 12),
            profile_generation_ref_id: Some(8),
            temporal_coverage: TemporalCoverageV1::Complete,
            effect: KernelEffectEvidenceV1 {
                task_cookie: 14,
                target_task_cookie: None,
                process_lineage_id: Some(EvidenceIdV1::new(15, 16)),
                authority_domain_id: Some(EvidenceIdV1::new(17, 18)),
                execution_set_id: Some(EvidenceIdV1::new(19, 20)),
                exact_object_id: Some(EvidenceIdV1::new(21, 22)),
                destination_id: None,
                policy_rule_id: Some(23),
                reason: 9,
                decision: 1,
                effect_family: 1,
                operation: 2,
                operation_argument: None,
                configured_errno: -13,
                kernel_result: -13,
            },
        }
    }

    fn batch(first_cursor: u64, count: u64) -> Result<EvidenceBatch, Box<dyn std::error::Error>> {
        let records = (first_cursor..first_cursor + count)
            .map(|cursor| observation(cursor).to_wire_record())
            .collect::<Result<Vec<EvidenceRecord>, _>>()?;
        batch_from_records(first_cursor, records)
    }

    fn batch_from_records(
        first_cursor: u64,
        records: Vec<EvidenceRecord>,
    ) -> Result<EvidenceBatch, Box<dyn std::error::Error>> {
        let framed = super::EvidenceBatchInputV1::encode(first_cursor, records)?;
        Ok(EvidenceBatch {
            node_boot_id: identity().node_boot_id.to_vec(),
            source_id: identity().source_id.to_vec(),
            source_epoch: identity().source_epoch,
            cpu_id: 0,
            first_cursor,
            framed_records: framed.framed_records,
            commit_group_tail: false,
        })
    }

    fn coverage_report(revision: u64, state: &str) -> CoverageReport {
        let closing = CoverageCounters {
            attempted: 3,
            requested: 3,
            emitted: 3,
            next_sequence: 4,
            ..CoverageCounters::default()
        };
        CoverageReport {
            source_id: vec![2; 16],
            cpu_id: 0,
            source_epoch: 7,
            revision,
            intervals: vec![CoverageInterval {
                interval_id: vec![1; 16],
                source_epoch: 7,
                revision: 1,
                state: state.to_owned(),
                first_sequence: 1,
                last_sequence: Some(3),
                opening_counters: Some(CoverageCounters::default()),
                closing_counters: Some(closing),
                gap_reasons: (state == "GAPPED")
                    .then(|| "RING_LOSS".to_owned())
                    .into_iter()
                    .collect(),
                current: true,
            }],
        }
    }

    fn coverage_identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            source_id: [2; 16],
            source_epoch: 7,
            ..identity()
        }
    }

    #[test]
    fn intake_promotes_out_of_order_batches_and_recovers_exact_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let first = batch(1, 2)?;
        let third = batch(3, 1)?;

        let pending = match intake.receive(&authenticated(), third.clone()) {
            Ok(_) => return Err("out-of-order evidence was acknowledged".into()),
            Err(status) => status,
        };
        assert_eq!(pending.code(), tonic::Code::Unavailable);
        assert_eq!(intake.contiguous_cursor(&identity())?, 0);

        intake.receive(&authenticated(), first.clone())?;
        assert_eq!(intake.contiguous_cursor(&identity())?, 3);
        intake.receive(&authenticated(), first.clone())?;
        intake.receive(&authenticated(), third.clone())?;
        assert_eq!(
            intake.store().accepted_evidence_records(&identity())?,
            (1..=3)
                .map(|cursor| observation(cursor).to_wire_record())
                .collect::<Result<Vec<_>, _>>()?
        );

        drop(intake);
        let reopened = EvidenceIntakeOwner::open(directory.path())?;
        assert_eq!(reopened.contiguous_cursor(&identity())?, 3);
        assert_eq!(
            reopened
                .store()
                .accepted_evidence_records(&identity())?
                .len(),
            3
        );
        Ok(())
    }

    #[test]
    fn intake_commits_twenty_ready_batches_with_one_cumulative_ack(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut batches = Vec::new();
        for cursor in 1..=20 {
            batches.push((authenticated(), batch(cursor, 1)?));
        }

        let acknowledgement = intake.receive_group(batches)?;

        assert_eq!(acknowledgement.contiguous_cursor, 20);
        assert_eq!(intake.contiguous_cursor(&identity())?, 20);
        assert_eq!(
            std::fs::read_dir(directory.path().join("evidence/segments-v2"))?.count(),
            1
        );
        drop(intake);
        assert_eq!(
            EvidenceIntakeOwner::open(directory.path())?.contiguous_cursor(&identity())?,
            20
        );
        Ok(())
    }

    #[test]
    fn intake_rejects_invalid_records_and_conflicting_retries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let accepted = batch(1, 1)?;
        intake.receive(&authenticated(), accepted.clone())?;

        let mut invalid_record = observation(2).to_wire_record()?;
        invalid_record.reason = u32::from(u8::MAX) + 1;
        let invalid = batch_from_records(2, vec![invalid_record])?;
        assert!(intake.receive(&authenticated(), invalid).is_err());

        let mut conflicting_record = observation(1).to_wire_record()?;
        conflicting_record.ingested_utc_ns += 1;
        let conflicting = batch_from_records(1, vec![conflicting_record])?;
        assert!(intake.receive(&authenticated(), conflicting).is_err());
        assert_eq!(intake.contiguous_cursor(&identity())?, 1);
        Ok(())
    }

    #[test]
    fn intake_rejects_bad_crc_and_invalid_protobuf_frames() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;

        let mut bad_crc = batch(1, 1)?;
        let mut frames = bad_crc.framed_records.to_vec();
        frames[4] ^= 0xff;
        bad_crc.framed_records = frames.into();
        let status = match intake.receive(&authenticated(), bad_crc) {
            Ok(_) => return Err("a bad frame CRC was accepted".into()),
            Err(status) => status,
        };
        assert!(status.message().contains("checksum is invalid"));

        let mut invalid_protobuf = batch(1, 1)?;
        let frame_bytes = invalid_protobuf.framed_records.len();
        let mut frames = vec![0, 0, 0, 1, 0xff];
        let checksum = crc32c::crc32c(&frames);
        frames.extend_from_slice(&checksum.to_be_bytes());
        assert!(frames.len() < frame_bytes);
        invalid_protobuf.framed_records = frames.into();
        let status = match intake.receive(&authenticated(), invalid_protobuf) {
            Ok(_) => return Err("an invalid protobuf with a valid CRC was accepted".into()),
            Err(status) => status,
        };
        assert!(status.message().contains("protobuf is invalid"));
        Ok(())
    }

    #[test]
    fn coverage_intake_is_durable_monotonic_and_gap_aware() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let healthy = coverage_report(1, "HEALTHY");
        intake.receive_coverage(&authenticated(), &healthy)?;
        intake.receive_coverage(&authenticated(), &healthy)?;

        let gapped = coverage_report(2, "GAPPED");
        intake.receive_coverage(&authenticated(), &gapped)?;
        assert!(intake.receive_coverage(&authenticated(), &healthy).is_err());

        drop(intake);
        let reopened = EvidenceIntakeOwner::open(directory.path())?;
        let recovered = reopened
            .latest_coverage_report(&coverage_identity())?
            .ok_or("coverage report did not survive restart")?;
        assert_eq!(recovered, gapped);
        Ok(())
    }

    #[test]
    fn coverage_intake_rejects_inconsistent_healthy_claims(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let intake = EvidenceIntakeOwner::open(directory.path())?;
        let mut report = coverage_report(1, "HEALTHY");
        report.intervals[0].gap_reasons = vec!["RING_LOSS".to_owned()];
        assert!(intake.receive_coverage(&authenticated(), &report).is_err());

        let mut regressed = coverage_report(1, "HEALTHY");
        regressed.intervals[0].opening_counters = Some(CoverageCounters {
            attempted: 4,
            requested: 4,
            emitted: 4,
            next_sequence: 5,
            ..CoverageCounters::default()
        });
        assert!(intake
            .receive_coverage(&authenticated(), &regressed)
            .is_err());
        Ok(())
    }
}
