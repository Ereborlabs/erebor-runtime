use std::collections::VecDeque;
use std::mem;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
    EffectPhysicalResultV1, Id128V1,
};
use erebor_runtime_ipc::v1::MithrilEffectObservation;
use zerocopy::FromBytes as _;

mod coverage;
mod model;
mod persistence;
mod wal;
mod window;

pub use coverage::{
    CoverageCountersV1, CoverageHealthOwner, CoverageIntervalV1, CoverageSnapshotV1,
    EffectObservationCpuHealth,
};
pub use model::{
    CoverageGapReasonV1, CoverageStateV1, EvidenceDigestV1, EvidenceFieldKeyV1, EvidenceIdV1,
    IntegrityV1, LocalSubjectBindingV1, ObservationCanonicalizer, ObservationEnvelopeV1,
    OperationResultAuthorityV1, ProofQualityV1, RemoteSubjectBindingV1, SensitivityV1,
    SourceAuthorityV1, TemporalCoverageV1,
};
use wal::EvidenceWalOwner;
pub use wal::{
    EvidenceAckV1, EvidenceBatchV1, EvidenceGapAckV1, EvidenceGapV1, EvidenceRecordV1,
    EvidenceUploadAckV1, EvidenceUploadV1, EvidenceWal, EvidenceWalAppendV1,
    EvidenceWalCapacityPolicyV1, EvidenceWalLimits, EvidenceWalRewriteV1,
};
pub use window::{
    DeterministicLocalWindowOwner, LocalFindingWindowSpecV1, LocalFindingWindowStateV1,
    LocalFindingWindowV1,
};

const DEFAULT_RECENT_EFFECT_CAPACITY: usize = 1_024;

#[derive(Clone)]
pub struct EffectObservationStore {
    inner: Arc<Inner>,
}

struct Inner {
    recent: Mutex<RecentEffects>,
    capacity: usize,
    decoder_errors: AtomicU64,
    evidence_errors: AtomicU64,
    first_evidence_error: Mutex<Option<String>>,
    wal_capacity_error: AtomicBool,
    first_wal_capacity_error: Mutex<Option<String>>,
    wal_capacity_blocked: AtomicU64,
    wal_rewritten_records: AtomicU64,
    wal_rewritten_bytes: AtomicU64,
    reader_queue_pending_records: AtomicU64,
    reader_queue_dropped_events: AtomicU64,
    persisted_reader_queue_dropped_events: AtomicU64,
    durable: Option<Mutex<DurableEvidence>>,
}

struct DurableEvidence {
    canonicalizer: ObservationCanonicalizer,
    wal: EvidenceWalOwner,
    coverage: CoverageHealthOwner,
}

struct RecentEffects {
    events: VecDeque<MithrilEffectObservation>,
    cursor: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectObservationHealth {
    pub attempted: u64,
    pub suppressed: u64,
    pub requested: u64,
    pub emitted: u64,
    pub lost: u64,
    pub classifier_miss_count: u64,
    pub unresolved: u64,
    pub decoder_errors: u64,
    pub evidence_errors: u64,
    pub wal_capacity_blocked: u64,
    pub wal_rewritten_records: u64,
    pub wal_rewritten_bytes: u64,
    pub reader_queue_dropped_events: u64,
}

pub(crate) struct EffectObservationIngress {
    sender: SyncSender<Box<[u8]>>,
    observations: EffectObservationStore,
}

pub(crate) struct EffectObservationWorker {
    receiver: Receiver<Box<[u8]>>,
    observations: EffectObservationStore,
}

impl EffectObservationIngress {
    pub(crate) fn record_bytes(&self, bytes: &[u8]) {
        self.observations
            .inner
            .reader_queue_pending_records
            .fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(bytes.to_vec().into_boxed_slice()) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.observations
                    .inner
                    .reader_queue_pending_records
                    .fetch_sub(1, Ordering::Relaxed);
                self.observations
                    .inner
                    .reader_queue_dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl EffectObservationWorker {
    pub(crate) fn run(self) {
        while let Ok(bytes) = self.receiver.recv() {
            self.observations.record_bytes(&bytes);
            self.observations
                .inner
                .reader_queue_pending_records
                .fetch_sub(1, Ordering::Relaxed);
            self.observations.persist_reader_queue_loss();
        }
        self.observations.persist_reader_queue_loss();
    }
}

impl Default for EffectObservationStore {
    fn default() -> Self {
        Self::new(DEFAULT_RECENT_EFFECT_CAPACITY)
    }
}

impl EffectObservationStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                recent: Mutex::new(RecentEffects {
                    events: VecDeque::with_capacity(capacity),
                    cursor: 0,
                }),
                capacity,
                decoder_errors: AtomicU64::new(0),
                evidence_errors: AtomicU64::new(0),
                first_evidence_error: Mutex::new(None),
                wal_capacity_error: AtomicBool::new(false),
                first_wal_capacity_error: Mutex::new(None),
                wal_capacity_blocked: AtomicU64::new(0),
                wal_rewritten_records: AtomicU64::new(0),
                wal_rewritten_bytes: AtomicU64::new(0),
                reader_queue_pending_records: AtomicU64::new(0),
                reader_queue_dropped_events: AtomicU64::new(0),
                persisted_reader_queue_dropped_events: AtomicU64::new(0),
                durable: None,
            }),
        }
    }

    pub fn durable(
        capacity: usize,
        wal_root: PathBuf,
        limits: EvidenceWalLimits,
        canonicalizer: ObservationCanonicalizer,
    ) -> crate::Result<Self> {
        let coverage_path = wal_root
            .parent()
            .unwrap_or(&wal_root)
            .join("evidence-coverage-v1.json");
        Ok(Self {
            inner: Arc::new(Inner {
                recent: Mutex::new(RecentEffects {
                    events: VecDeque::with_capacity(capacity),
                    cursor: 0,
                }),
                capacity,
                decoder_errors: AtomicU64::new(0),
                evidence_errors: AtomicU64::new(0),
                first_evidence_error: Mutex::new(None),
                wal_capacity_error: AtomicBool::new(false),
                first_wal_capacity_error: Mutex::new(None),
                wal_capacity_blocked: AtomicU64::new(0),
                wal_rewritten_records: AtomicU64::new(0),
                wal_rewritten_bytes: AtomicU64::new(0),
                reader_queue_pending_records: AtomicU64::new(0),
                reader_queue_dropped_events: AtomicU64::new(0),
                persisted_reader_queue_dropped_events: AtomicU64::new(0),
                durable: Some(Mutex::new(DurableEvidence {
                    canonicalizer,
                    wal: EvidenceWalOwner::open(&wal_root, limits)?,
                    coverage: CoverageHealthOwner::open(coverage_path, canonicalizer)?,
                })),
            }),
        })
    }

    pub fn record_bytes(&self, bytes: &[u8]) {
        let Ok(event) = EffectObservationV1::read_from_bytes(bytes) else {
            self.inner.decoder_errors.fetch_add(1, Ordering::Relaxed);
            if let Some(durable) = &self.inner.durable {
                self.record_evidence_error("effect observation bytes are invalid");
                let _result = durable
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .coverage
                    .mark_all_gapped(CoverageGapReasonV1::DecoderError);
            }
            return;
        };
        {
            let mut recent = self.lock_recent();
            recent.cursor = recent.cursor.saturating_add(1);
            if self.inner.capacity > 0 {
                if recent.events.len() == self.inner.capacity {
                    recent.events.pop_front();
                }
                recent.events.push_back(to_ipc(event));
            }
        }
        if let Some(durable) = &self.inner.durable {
            let result: std::result::Result<
                Option<EvidenceWalAppendV1>,
                (Box<crate::Error>, bool, EvidenceWalRewriteV1),
            > = (|| {
                let mut durable = durable.lock().unwrap_or_else(PoisonError::into_inner);
                let Some((coverage_interval_id, temporal_coverage)) = durable
                    .coverage
                    .observe(event.source_cpu_id, event.source_sequence)
                    .map_err(|error| (Box::new(error), false, EvidenceWalRewriteV1::default()))?
                else {
                    erebor_telemetry::debug!(
                        "ignored a replayed effect observation",
                        cpu_id = %event.source_cpu_id,
                        source_sequence = %event.source_sequence
                    );
                    return Ok(None);
                };
                let observation = durable
                    .canonicalizer
                    .normalize_kernel(event, coverage_interval_id, temporal_coverage, utc_now_ns())
                    .map_err(|error| (Box::new(error), false, EvidenceWalRewriteV1::default()))?;
                match durable.wal.append_classified(&observation) {
                    Ok(appended) => {
                        if appended.rewrite.discarded_records > 0 {
                            durable
                                .coverage
                                .mark_all_gapped(CoverageGapReasonV1::WalCapacity)
                                .map_err(|error| (Box::new(error), false, appended.rewrite))?;
                        }
                        Ok(Some(appended))
                    }
                    Err(failure) => {
                        let rewrite = failure.rewrite;
                        durable
                            .coverage
                            .mark_all_gapped(failure.gap_reason)
                            .map_err(|error| (Box::new(error), false, rewrite))?;
                        let capacity = failure.gap_reason == CoverageGapReasonV1::WalCapacity;
                        Err((failure.error, capacity, rewrite))
                    }
                }
            })();
            let rewrite = match &result {
                Ok(Some(appended)) => appended.rewrite,
                Ok(None) => EvidenceWalRewriteV1::default(),
                Err((_error, _capacity, rewrite)) => *rewrite,
            };
            if rewrite.discarded_records > 0 {
                self.inner
                    .wal_rewritten_records
                    .fetch_add(rewrite.discarded_records, Ordering::Relaxed);
                self.inner
                    .wal_rewritten_bytes
                    .fetch_add(rewrite.discarded_bytes, Ordering::Relaxed);
            }
            match result {
                Ok(_appended) => self.clear_wal_capacity_error(),
                Err((error, true, _rewrite)) => {
                    self.inner
                        .wal_capacity_blocked
                        .fetch_add(1, Ordering::Relaxed);
                    self.record_wal_capacity_error(error.to_string());
                }
                Err((error, false, _rewrite)) => self.record_evidence_error(error.to_string()),
            }
        }
    }

    pub(crate) fn bounded_ingestion_queue(
        &self,
        capacity: usize,
    ) -> crate::Result<(EffectObservationIngress, EffectObservationWorker)> {
        if capacity == 0 {
            return Err(crate::Error::EvidenceState {
                reason: "effect observation reader queue capacity must be nonzero".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            });
        }
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Ok((
            EffectObservationIngress {
                sender,
                observations: self.clone(),
            },
            EffectObservationWorker {
                receiver,
                observations: self.clone(),
            },
        ))
    }

    pub fn next_evidence_batch(&self) -> Option<EvidenceBatchV1> {
        let batch = self
            .inner
            .durable
            .as_ref()
            .and_then(|durable| durable.lock().ok()?.wal.next_batch());
        if let Some(batch) = &batch {
            erebor_telemetry::debug!(
                "prepared an evidence batch",
                first_cursor = %batch.first_cursor,
                last_cursor = %batch.last_cursor,
                count = %batch.records.len()
            );
        }
        batch
    }

    pub fn next_evidence_upload(&self) -> Option<EvidenceUploadV1> {
        let upload = self
            .inner
            .durable
            .as_ref()
            .and_then(|durable| durable.lock().ok()?.wal.next_upload());
        match &upload {
            Some(EvidenceUploadV1::Batch(batch)) => erebor_telemetry::debug!(
                "prepared an evidence batch",
                first_cursor = %batch.first_cursor,
                last_cursor = %batch.last_cursor,
                count = %batch.records.len()
            ),
            Some(EvidenceUploadV1::Gap(gap)) => erebor_telemetry::warn!(
                "prepared a durable evidence gap",
                first_cursor = %gap.first_cursor,
                last_cursor = %gap.last_cursor,
                discarded_bytes = %gap.discarded_bytes
            ),
            None => {}
        }
        upload
    }

    pub fn acknowledge_evidence(&self, ack: EvidenceAckV1) -> crate::Result<()> {
        self.lock_durable()?.wal.acknowledge(ack)?;
        erebor_telemetry::debug!("acknowledged an evidence batch");
        Ok(())
    }

    pub fn acknowledge_evidence_upload(&self, ack: EvidenceUploadAckV1) -> crate::Result<()> {
        self.lock_durable()?.wal.acknowledge_upload(ack)?;
        match ack {
            EvidenceUploadAckV1::Batch(_) => {
                erebor_telemetry::debug!("acknowledged an evidence batch");
            }
            EvidenceUploadAckV1::Gap(_) => {
                erebor_telemetry::warn!("acknowledged a durable evidence gap");
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence_errors(&self) -> u64 {
        self.inner.evidence_errors.load(Ordering::Relaxed)
            + u64::from(self.inner.wal_capacity_error.load(Ordering::Relaxed))
    }

    #[must_use]
    pub fn first_evidence_error(&self) -> Option<String> {
        let permanent = self
            .inner
            .first_evidence_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        permanent.or_else(|| {
            self.inner
                .first_wal_capacity_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        })
    }

    #[must_use]
    pub fn evidence_failure_gap_reason(&self) -> Option<CoverageGapReasonV1> {
        if self.inner.evidence_errors.load(Ordering::Relaxed) > 0 {
            Some(CoverageGapReasonV1::WalFailure)
        } else if self.inner.wal_capacity_error.load(Ordering::Relaxed) {
            Some(CoverageGapReasonV1::WalCapacity)
        } else {
            None
        }
    }

    pub fn sample_coverage_health(&self, per_cpu_bytes: &[u8]) -> crate::Result<()> {
        let samples =
            decode_cpu_health(per_cpu_bytes).ok_or_else(|| crate::Error::EvidenceState {
                reason: "effect observation health bytes are invalid".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        self.lock_durable()?.coverage.sample_health(&samples)
    }

    pub fn transient_coverage_reader_delivery_pending(
        &self,
        per_cpu_bytes: &[u8],
    ) -> crate::Result<bool> {
        let samples =
            decode_cpu_health(per_cpu_bytes).ok_or_else(|| crate::Error::EvidenceState {
                reason: "effect observation health bytes are invalid".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        Ok(self
            .lock_durable()?
            .coverage
            .transient_reader_delivery_pending(&samples))
    }

    #[must_use]
    pub fn reader_queue_pending_records(&self) -> u64 {
        self.inner
            .reader_queue_pending_records
            .load(Ordering::Relaxed)
    }

    pub fn recover_coverage_after_prior_probe(&self, per_cpu_bytes: &[u8]) -> crate::Result<bool> {
        let samples =
            decode_cpu_health(per_cpu_bytes).ok_or_else(|| crate::Error::EvidenceState {
                reason: "effect observation health bytes are invalid".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        let durable = self.lock_durable()?;
        match durable.coverage.recover_after_prior_probe(&samples)? {
            coverage::RecoveryProbeStatus::Pending => Ok(false),
            coverage::RecoveryProbeStatus::Recovered => {
                erebor_telemetry::info!(
                    "recovered evidence coverage",
                    count = %samples.len()
                );
                Ok(true)
            }
            coverage::RecoveryProbeStatus::Resample => {
                durable.coverage.sample_health(&samples)?;
                Ok(false)
            }
        }
    }

    pub fn mark_coverage_gapped(&self, reason: CoverageGapReasonV1) -> crate::Result<()> {
        let durable = self.lock_durable()?;
        let current = durable.coverage.snapshot().current_intervals();
        if !current.is_empty()
            && current.iter().all(|interval| {
                interval.state == CoverageStateV1::Gapped && interval.gap_reasons.contains(&reason)
            })
        {
            return Ok(());
        }
        durable.coverage.mark_all_gapped(reason)?;
        if reason == CoverageGapReasonV1::ReaderStopped {
            erebor_telemetry::debug!(
                "marked evidence coverage as gapped",
                reason = %reason.as_str()
            );
        } else {
            erebor_telemetry::warn!(
                "marked evidence coverage as gapped",
                reason = %reason.as_str()
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn coverage_snapshot(&self) -> Option<CoverageSnapshotV1> {
        self.inner.durable.as_ref().and_then(|durable| {
            durable
                .lock()
                .ok()
                .map(|durable| durable.coverage.snapshot())
        })
    }

    #[must_use]
    pub fn recent(&self) -> Vec<MithrilEffectObservation> {
        self.lock_recent().events.iter().cloned().collect()
    }

    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.lock_recent().cursor
    }

    #[must_use]
    pub fn recent_since(&self, cursor: u64) -> Vec<MithrilEffectObservation> {
        let recent = self.lock_recent();
        let first_cursor = recent.cursor - recent.events.len() as u64;
        let skip = cursor.saturating_sub(first_cursor);
        if skip >= recent.events.len() as u64 {
            return Vec::new();
        }
        recent.events.iter().skip(skip as usize).cloned().collect()
    }

    #[must_use]
    pub fn health(&self, per_cpu_bytes: Option<&[u8]>) -> EffectObservationHealth {
        let mut health = EffectObservationHealth {
            decoder_errors: self.inner.decoder_errors.load(Ordering::Relaxed),
            evidence_errors: self.evidence_errors(),
            wal_capacity_blocked: self.inner.wal_capacity_blocked.load(Ordering::Relaxed),
            wal_rewritten_records: self.inner.wal_rewritten_records.load(Ordering::Relaxed),
            wal_rewritten_bytes: self.inner.wal_rewritten_bytes.load(Ordering::Relaxed),
            reader_queue_dropped_events: self
                .inner
                .reader_queue_dropped_events
                .load(Ordering::Relaxed),
            ..EffectObservationHealth::default()
        };
        let Some(bytes) = per_cpu_bytes else {
            return health;
        };
        let Some(cpus) = decode_cpu_health(bytes) else {
            health.decoder_errors = health.decoder_errors.saturating_add(1);
            return health;
        };
        for cpu in cpus {
            health.attempted = health.attempted.saturating_add(cpu.counters.attempted);
            health.suppressed = health.suppressed.saturating_add(cpu.counters.suppressed);
            health.requested = health.requested.saturating_add(cpu.counters.requested);
            health.emitted = health.emitted.saturating_add(cpu.counters.emitted);
            health.lost = health.lost.saturating_add(cpu.counters.lost);
            health.classifier_miss_count = health
                .classifier_miss_count
                .saturating_add(cpu.counters.classifier_miss_count);
            health.unresolved = health.unresolved.saturating_add(cpu.counters.unresolved);
        }
        health
    }

    fn lock_recent(&self) -> MutexGuard<'_, RecentEffects> {
        self.inner
            .recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_durable(&self) -> crate::Result<MutexGuard<'_, DurableEvidence>> {
        Ok(self
            .inner
            .durable
            .as_ref()
            .ok_or_else(|| crate::Error::EvidenceState {
                reason: "node has no durable evidence owner".to_owned(),
                location: snafu::Location::new(file!(), line!(), column!()),
            })?
            .lock()
            .unwrap_or_else(PoisonError::into_inner))
    }

    fn record_evidence_error(&self, error: impl Into<String>) {
        self.inner.evidence_errors.fetch_add(1, Ordering::Relaxed);
        let mut first = self
            .inner
            .first_evidence_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Keep the first failure because it identifies the stage that closed evidence claims.
        if first.is_none() {
            let error = error.into();
            erebor_telemetry::error!(
                "durable evidence operation failed",
                error = %error
            );
            *first = Some(error);
        }
    }

    fn persist_reader_queue_loss(&self) {
        let dropped = self
            .inner
            .reader_queue_dropped_events
            .load(Ordering::Relaxed);
        if dropped
            <= self
                .inner
                .persisted_reader_queue_dropped_events
                .load(Ordering::Relaxed)
            || self.inner.durable.is_none()
        {
            return;
        }
        match self.mark_coverage_gapped(CoverageGapReasonV1::ReaderQueueOverflow) {
            Ok(()) => self
                .inner
                .persisted_reader_queue_dropped_events
                .store(dropped, Ordering::Relaxed),
            Err(error) => self.record_evidence_error(error.to_string()),
        }
    }

    fn record_wal_capacity_error(&self, error: impl Into<String>) {
        if self.inner.wal_capacity_error.swap(true, Ordering::Relaxed) {
            return;
        }
        *self
            .inner
            .first_wal_capacity_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(error.into());
    }

    fn clear_wal_capacity_error(&self) {
        if !self.inner.wal_capacity_error.swap(false, Ordering::Relaxed) {
            return;
        }
        *self
            .inner
            .first_wal_capacity_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn decode_cpu_health(bytes: &[u8]) -> Option<Vec<EffectObservationCpuHealth>> {
    let width = mem::size_of::<EffectObservationHealthV1>();
    if bytes.is_empty() || !bytes.len().is_multiple_of(width) {
        return None;
    }
    bytes
        .chunks_exact(width)
        .enumerate()
        .map(|(cpu_id, chunk)| {
            let cpu = EffectObservationHealthV1::read_from_bytes(chunk).ok()?;
            Some(EffectObservationCpuHealth {
                cpu_id: u32::try_from(cpu_id).ok()?,
                counters: CoverageCountersV1 {
                    attempted: cpu.attempted,
                    suppressed: cpu.suppressed,
                    requested: cpu.requested,
                    emitted: cpu.emitted,
                    lost: cpu.lost,
                    classifier_miss_count: cpu.classifier_miss_count,
                    unresolved: cpu.unresolved,
                    next_sequence: cpu.next_sequence,
                },
            })
        })
        .collect()
}

fn utc_now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
        .unwrap_or(i64::MAX)
}

fn to_ipc(event: EffectObservationV1) -> MithrilEffectObservation {
    MithrilEffectObservation {
        observed_boottime_ns: event.observed_boottime_ns,
        source_sequence: event.source_sequence,
        source_cpu_id: event.source_cpu_id,
        admitted_entry_rule_id: event.admitted_entry_rule_id,
        task_cookie: event.task_cookie,
        profile_generation_ref_id: event.profile_generation_ref_id,
        process_lineage_id: id_hex(event.process_lineage_id),
        process_instance_id: id_hex(event.process_instance_id),
        entry_instance_id: id_hex(event.entry_instance_id),
        authority_domain_id: id_hex(event.authority_domain_id),
        binding_id: id_hex(event.binding_id),
        execution_set_id: id_hex(event.execution_set_id),
        mount_namespace_inode: event.file_object.mount_namespace_inode,
        mount_id_unique: event.file_object.mount_id_unique,
        filesystem_device: event.file_object.filesystem_device,
        inode: event.file_object.inode,
        inode_generation: event.file_object.inode_generation,
        exact_object_key_id: event.exact_object_key_id,
        composite_atom_id: event.composite_atom_id,
        active_role_id: event.active_role_id,
        process_state_vector_id: event.process_state_vector_id,
        effect_family: u32::from(event.effect_family),
        operation: u32::from(event.operation),
        configured_errno: i32::from(event.configured_errno),
        kernel_result: event.kernel_result,
        reason_code: u32::from(event.reason),
        reason: reason_name(event.reason).to_owned(),
        physical_result_code: u32::from(event.physical_result),
        physical_result: physical_result_name(event.physical_result).to_owned(),
        stage: observation_stage(event.physical_result).to_owned(),
        controller_process_state_id: id_hex(event.controller_process_state_id),
        controller_transition_version: event.controller_transition_version,
        target_task_cookie: event.target_task_cookie,
        target_profile_generation_ref_id: event.target_profile_generation_ref_id,
        target_process_state_id: id_hex(event.target_process_state_id),
        target_transition_version: event.target_transition_version,
        target_role_id: event.target_role_id,
        target_process_state_vector_id: event.target_process_state_vector_id,
        operation_argument: event.operation_argument,
        network_socket_key_id: event.network_socket_key_id,
        network_socket_generation: event.network_socket_generation,
        network_flow_generation: event.network_flow_generation,
        network_destination_policy_handle: event.network_destination_policy_handle,
        network_namespace_address: event.network_namespace.network_namespace_address,
        network_namespace_inode: event.network_namespace.network_namespace_inode,
        network_current_namespace_address: event
            .network_current_namespace
            .network_namespace_address,
        network_current_namespace_inode: event.network_current_namespace.network_namespace_inode,
        network_creator_profile_generation_ref_id: event.network_creator_profile_generation_ref_id,
        network_peer_address: event.network_peer_address.to_vec(),
        network_peer_port: u32::from(event.network_peer_port),
        network_address_family: u32::from(event.network_address_family),
        network_protocol: u32::from(event.network_protocol),
        network_socket_state: u32::from(event.network_socket_state),
        network_response_scope: u32::from(event.network_response_scope),
        network_flow_authorization_id: id_hex(event.network_flow_authorization_id),
        network_creator_destination_policy_handle: event.network_creator_destination_policy_handle,
        network_flow_authorizer_profile_generation_ref_id: event
            .network_flow_authorizer_profile_generation_ref_id,
        network_parent_socket_key_id: event.network_parent_socket_key_id,
        network_parent_socket_generation: event.network_parent_socket_generation,
        io_uring_ring_id: id_hex(event.io_uring_ring_id),
        io_uring_ring_generation: event.io_uring_ring_generation,
        io_uring_submission_sequence: event.io_uring_submission_sequence,
        io_uring_user_data: event.io_uring_user_data,
        io_uring_file_offset: event.io_uring_file_offset,
        io_uring_buffer_address: event.io_uring_buffer_address,
        io_uring_file_cookie: event.io_uring_file_cookie,
        io_uring_executor_pid_tgid: event.io_uring_executor_pid_tgid,
        io_uring_byte_length: event.io_uring_byte_length,
        io_uring_sqe_index: event.io_uring_sqe_index,
        io_uring_request_flags: event.io_uring_request_flags,
        io_uring_rw_flags: event.io_uring_rw_flags,
        io_uring_opcode: u32::from(event.io_uring_opcode),
    }
}

fn id_hex(id: Id128V1) -> String {
    hex::encode(id.to_be_bytes())
}

const fn reason_name(reason: u8) -> &'static str {
    match reason {
        value if value == EffectObservationReasonV1::ExactPolicyAllow as u8 => "EXACT_POLICY_ALLOW",
        value if value == EffectObservationReasonV1::ExactPolicyAuditAllow as u8 => {
            "EXACT_POLICY_AUDIT_ALLOW"
        }
        value if value == EffectObservationReasonV1::WouldDeny as u8 => "WOULD_DENY",
        value if value == EffectObservationReasonV1::PriorLsmDenial as u8 => "PRIOR_LSM_DENIAL",
        value if value == EffectObservationReasonV1::MissingIdentity as u8 => "MISSING_IDENTITY",
        value if value == EffectObservationReasonV1::CorruptIdentityOrGeneration as u8 => {
            "CORRUPT_IDENTITY_OR_GENERATION"
        }
        value if value == EffectObservationReasonV1::UnresolvedObject as u8 => "UNRESOLVED_OBJECT",
        value if value == EffectObservationReasonV1::UnsupportedObject as u8 => {
            "UNSUPPORTED_OBJECT"
        }
        value if value == EffectObservationReasonV1::ExactPolicyDeny as u8 => "EXACT_POLICY_DENY",
        value if value == EffectObservationReasonV1::ExceptionUnavailable as u8 => {
            "EXCEPTION_UNAVAILABLE"
        }
        value if value == EffectObservationReasonV1::PathTreePolicyDeny as u8 => {
            "PATH_TREE_POLICY_DENY"
        }
        value if value == EffectObservationReasonV1::NetworkResponseFence as u8 => {
            "NETWORK_RESPONSE_FENCE"
        }
        value if value == EffectObservationReasonV1::PreparedRuntimeInfrastructure as u8 => {
            "PREPARED_RUNTIME_INFRASTRUCTURE"
        }
        value if value == EffectObservationReasonV1::ApplicationDefaultAllow as u8 => {
            "APPLICATION_DEFAULT_ALLOW"
        }
        value if value == EffectObservationReasonV1::RuntimeEntryInfrastructure as u8 => {
            "RUNTIME_ENTRY_INFRASTRUCTURE"
        }
        _ => "UNKNOWN",
    }
}

const fn physical_result_name(result: u8) -> &'static str {
    match result {
        value if value == EffectPhysicalResultV1::UnknownAfterPreEffect as u8 => {
            "UNKNOWN_AFTER_PRE_EFFECT"
        }
        value if value == EffectPhysicalResultV1::DeniedBeforeEffect as u8 => {
            "DENIED_BEFORE_EFFECT"
        }
        value if value == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u8 => {
            "PACKET_DROPPED_AFTER_REWRITE"
        }
        _ => "UNKNOWN",
    }
}

const fn observation_stage(result: u8) -> &'static str {
    if result == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u8 {
        "FINAL_PACKET_V1"
    } else {
        "LOCAL_PRE_EFFECT_V1"
    }
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{
        EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
        EffectPhysicalResultV1, Id128V1, NetworkNamespaceGenerationV1,
    };
    use zerocopy::IntoBytes as _;

    use super::{
        reason_name, CoverageGapReasonV1, EffectObservationStore, EvidenceAckV1, EvidenceIdV1,
        EvidenceWalCapacityPolicyV1, EvidenceWalLimits, ObservationCanonicalizer,
    };

    #[test]
    fn enforcement_denial_reasons_are_not_downgraded_to_unknown() {
        assert_eq!(
            reason_name(EffectObservationReasonV1::ExactPolicyDeny as u8),
            "EXACT_POLICY_DENY"
        );
        assert_eq!(
            reason_name(EffectObservationReasonV1::ExceptionUnavailable as u8),
            "EXCEPTION_UNAVAILABLE"
        );
        assert_eq!(
            reason_name(EffectObservationReasonV1::PreparedRuntimeInfrastructure as u8),
            "PREPARED_RUNTIME_INFRASTRUCTURE"
        );
        assert_eq!(
            reason_name(EffectObservationReasonV1::ApplicationDefaultAllow as u8),
            "APPLICATION_DEFAULT_ALLOW"
        );
        assert_eq!(
            reason_name(EffectObservationReasonV1::RuntimeEntryInfrastructure as u8),
            "RUNTIME_ENTRY_INFRASTRUCTURE"
        );
    }

    #[test]
    fn records_exact_events_and_bounds_recent_history() {
        let store = EffectObservationStore::new(1);
        for task_cookie in [7, 8] {
            let event = EffectObservationV1 {
                source_sequence: task_cookie + 100,
                source_cpu_id: 3,
                task_cookie,
                process_lineage_id: Id128V1::new(1, 2),
                controller_process_state_id: Id128V1::new(3, 4),
                controller_transition_version: 5,
                target_task_cookie: 6,
                target_profile_generation_ref_id: 7,
                target_process_state_id: Id128V1::new(8, 9),
                target_transition_version: 10,
                target_role_id: 11,
                target_process_state_vector_id: 12,
                operation_argument: 13,
                network_namespace: NetworkNamespaceGenerationV1 {
                    network_namespace_address: 28,
                    network_namespace_inode: 29,
                    reserved: 0,
                },
                network_current_namespace: NetworkNamespaceGenerationV1 {
                    network_namespace_address: 30,
                    network_namespace_inode: 31,
                    reserved: 0,
                },
                io_uring_ring_id: Id128V1::new(14, 15),
                io_uring_ring_generation: 16,
                io_uring_submission_sequence: 17,
                io_uring_user_data: 18,
                io_uring_file_offset: 19,
                io_uring_buffer_address: 20,
                io_uring_file_cookie: 21,
                io_uring_executor_pid_tgid: 22,
                io_uring_byte_length: 23,
                io_uring_sqe_index: 24,
                io_uring_request_flags: 25,
                io_uring_rw_flags: 26,
                io_uring_opcode: 27,
                reason: EffectObservationReasonV1::WouldDeny as u8,
                physical_result: EffectPhysicalResultV1::UnknownAfterPreEffect as u8,
                ..EffectObservationV1::default()
            };
            store.record_bytes(event.as_bytes());
        }
        let recent = store.recent();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].task_cookie, 8);
        assert_eq!(recent[0].source_sequence, 108);
        assert_eq!(recent[0].source_cpu_id, 3);
        assert_eq!(
            recent[0].process_lineage_id,
            "00000000000000010000000000000002"
        );
        assert_eq!(recent[0].reason, "WOULD_DENY");
        assert_eq!(
            recent[0].controller_process_state_id,
            "00000000000000030000000000000004"
        );
        assert_eq!(recent[0].controller_transition_version, 5);
        assert_eq!(recent[0].target_task_cookie, 6);
        assert_eq!(recent[0].target_profile_generation_ref_id, 7);
        assert_eq!(
            recent[0].target_process_state_id,
            "00000000000000080000000000000009"
        );
        assert_eq!(recent[0].target_transition_version, 10);
        assert_eq!(recent[0].target_role_id, 11);
        assert_eq!(recent[0].target_process_state_vector_id, 12);
        assert_eq!(recent[0].operation_argument, 13);
        assert_eq!(recent[0].network_namespace_address, 28);
        assert_eq!(recent[0].network_namespace_inode, 29);
        assert_eq!(recent[0].network_current_namespace_address, 30);
        assert_eq!(recent[0].network_current_namespace_inode, 31);
        assert_eq!(
            recent[0].io_uring_ring_id,
            "000000000000000e000000000000000f"
        );
        assert_eq!(recent[0].io_uring_ring_generation, 16);
        assert_eq!(recent[0].io_uring_submission_sequence, 17);
        assert_eq!(recent[0].io_uring_user_data, 18);
        assert_eq!(recent[0].io_uring_file_offset, 19);
        assert_eq!(recent[0].io_uring_buffer_address, 20);
        assert_eq!(recent[0].io_uring_file_cookie, 21);
        assert_eq!(recent[0].io_uring_executor_pid_tgid, 22);
        assert_eq!(recent[0].io_uring_byte_length, 23);
        assert_eq!(recent[0].io_uring_sqe_index, 24);
        assert_eq!(recent[0].io_uring_request_flags, 25);
        assert_eq!(recent[0].io_uring_rw_flags, 26);
        assert_eq!(recent[0].io_uring_opcode, 27);
    }

    #[test]
    fn bounded_reader_queue_drops_only_after_capacity() -> crate::Result<()> {
        let store = EffectObservationStore::new(2);
        let (ingress, worker) = store.bounded_ingestion_queue(1)?;
        ingress.record_bytes(
            EffectObservationV1 {
                source_sequence: 1,
                ..EffectObservationV1::default()
            }
            .as_bytes(),
        );
        assert_eq!(store.reader_queue_pending_records(), 1);
        assert_eq!(store.health(None).reader_queue_dropped_events, 0);

        ingress.record_bytes(
            EffectObservationV1 {
                source_sequence: 2,
                ..EffectObservationV1::default()
            }
            .as_bytes(),
        );
        assert_eq!(store.reader_queue_pending_records(), 1);
        assert_eq!(store.health(None).reader_queue_dropped_events, 1);

        drop(ingress);
        worker.run();
        assert_eq!(store.reader_queue_pending_records(), 0);
        assert_eq!(store.recent().len(), 1);
        assert_eq!(store.recent()[0].source_sequence, 1);
        Ok(())
    }

    #[test]
    fn reader_queue_overflow_is_a_durable_coverage_gap() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = EffectObservationStore::durable(
            2,
            directory.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )?,
        )?;
        store.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        let (ingress, worker) = store.bounded_ingestion_queue(1)?;
        for source_sequence in [1, 2] {
            ingress.record_bytes(
                EffectObservationV1 {
                    observed_boottime_ns: source_sequence,
                    source_sequence,
                    task_cookie: 1,
                    reason: EffectObservationReasonV1::ExactPolicyDeny as u8,
                    physical_result: EffectPhysicalResultV1::DeniedBeforeEffect as u8,
                    kernel_result: -13,
                    effect_family: 1,
                    operation: 1,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        }
        drop(ingress);
        worker.run();

        assert_eq!(store.health(None).reader_queue_dropped_events, 1);
        assert!(store.coverage_snapshot().is_some_and(|snapshot| {
            !snapshot.supports_negative_claim()
                && snapshot.current_intervals()[0]
                    .gap_reasons
                    .contains(&CoverageGapReasonV1::ReaderQueueOverflow)
        }));
        Ok(())
    }

    #[test]
    fn cursor_excludes_pre_marker_events_after_recent_history_rolls() {
        let store = EffectObservationStore::new(2);
        let record = |task_cookie| {
            store.record_bytes(
                EffectObservationV1 {
                    task_cookie,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        };

        record(1);
        let after_first = store.cursor();
        record(2);
        let after_second = store.cursor();
        record(3);

        assert_eq!(
            store
                .recent_since(after_first)
                .iter()
                .map(|event| event.task_cookie)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(
            store
                .recent_since(after_second)
                .iter()
                .map(|event| event.task_cookie)
                .collect::<Vec<_>>(),
            [3]
        );
    }

    #[test]
    fn sums_per_cpu_health_and_counts_decoder_errors() {
        let store = EffectObservationStore::default();
        store.record_bytes(&[1, 2, 3]);
        let first = EffectObservationHealthV1 {
            attempted: 4,
            suppressed: 0,
            requested: 4,
            emitted: 3,
            lost: 1,
            classifier_miss_count: 1,
            unresolved: 2,
            next_sequence: 4,
        };
        let second = EffectObservationHealthV1 {
            attempted: 6,
            suppressed: 1,
            requested: 5,
            emitted: 5,
            lost: 0,
            classifier_miss_count: 2,
            unresolved: 4,
            next_sequence: 6,
        };
        let bytes = [first.as_bytes(), second.as_bytes()].concat();
        let health = store.health(Some(&bytes));
        assert_eq!(health.attempted, 10);
        assert_eq!(health.suppressed, 1);
        assert_eq!(health.requested, 9);
        assert_eq!(health.emitted, 8);
        assert_eq!(health.lost, 1);
        assert_eq!(health.classifier_miss_count, 3);
        assert_eq!(health.unresolved, 6);
        assert_eq!(health.decoder_errors, 1);
    }

    #[test]
    fn wal_capacity_closes_negative_coverage_without_changing_effect_events(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = EffectObservationStore::durable(
            4,
            directory.path().join("wal"),
            EvidenceWalLimits {
                maximum_retained_records: 1,
                maximum_batch_records: 1,
                ..EvidenceWalLimits::default()
            },
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )?,
        )?;
        store.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        for source_sequence in [1, 2] {
            store.record_bytes(
                EffectObservationV1 {
                    observed_boottime_ns: source_sequence,
                    source_sequence,
                    task_cookie: 1,
                    reason: EffectObservationReasonV1::ExactPolicyDeny as u8,
                    physical_result: EffectPhysicalResultV1::DeniedBeforeEffect as u8,
                    kernel_result: -13,
                    effect_family: 1,
                    operation: 1,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        }
        assert_eq!(store.recent().len(), 2);
        assert_eq!(store.evidence_errors(), 1);
        assert_eq!(store.health(None).wal_capacity_blocked, 1);
        assert_eq!(store.health(None).wal_rewritten_records, 0);
        assert!(store
            .first_evidence_error()
            .is_some_and(|error| error.contains("retention or record capacity is exhausted")));
        let snapshot = store
            .coverage_snapshot()
            .ok_or("coverage snapshot missing")?;
        assert!(!snapshot.supports_negative_claim());
        assert!(snapshot.current_intervals()[0]
            .gap_reasons
            .contains(&CoverageGapReasonV1::WalCapacity));

        let batch = store
            .next_evidence_batch()
            .ok_or("evidence batch missing")?;
        assert_eq!((batch.first_cursor, batch.last_cursor), (1, 1));
        store.acknowledge_evidence(EvidenceAckV1)?;
        store.record_bytes(
            EffectObservationV1 {
                observed_boottime_ns: 3,
                source_sequence: 3,
                task_cookie: 1,
                reason: EffectObservationReasonV1::ExactPolicyDeny as u8,
                physical_result: EffectPhysicalResultV1::DeniedBeforeEffect as u8,
                kernel_result: -13,
                effect_family: 1,
                operation: 1,
                ..EffectObservationV1::default()
            }
            .as_bytes(),
        );
        assert_eq!(store.evidence_errors(), 0);
        assert_eq!(store.first_evidence_error(), None);
        assert!(store.recover_coverage_after_prior_probe(
            EffectObservationHealthV1 {
                attempted: 3,
                requested: 3,
                emitted: 3,
                next_sequence: 3,
                ..EffectObservationHealthV1::default()
            }
            .as_bytes(),
        )?);
        assert!(store
            .coverage_snapshot()
            .is_some_and(|snapshot| snapshot.supports_negative_claim()));
        Ok(())
    }

    #[test]
    fn wal_rewrite_metrics_and_gap_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = EffectObservationStore::durable(
            4,
            directory.path().join("wal"),
            EvidenceWalLimits {
                maximum_retained_records: 3,
                maximum_batch_records: 1,
                capacity_policy: EvidenceWalCapacityPolicyV1::Rewrite,
                ..EvidenceWalLimits::default()
            },
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )?,
        )?;
        store.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        for source_sequence in 1..=4 {
            store.record_bytes(
                EffectObservationV1 {
                    observed_boottime_ns: source_sequence,
                    source_sequence,
                    task_cookie: 1,
                    reason: EffectObservationReasonV1::ExactPolicyDeny as u8,
                    physical_result: EffectPhysicalResultV1::DeniedBeforeEffect as u8,
                    kernel_result: -13,
                    effect_family: 1,
                    operation: 1,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        }

        let health = store.health(None);
        assert_eq!(health.wal_capacity_blocked, 0);
        assert_eq!(health.wal_rewritten_records, 1);
        assert!(health.wal_rewritten_bytes > 0);
        assert_eq!(health.evidence_errors, 0);
        assert!(store.coverage_snapshot().is_some_and(|snapshot| {
            !snapshot.supports_negative_claim()
                && snapshot.current_intervals()[0]
                    .gap_reasons
                    .contains(&CoverageGapReasonV1::WalCapacity)
        }));
        Ok(())
    }

    #[test]
    fn durable_store_does_not_append_ring_replays_after_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let wal_root = directory.path().join("wal");
        let canonicalizer = || {
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )
        };
        let store = EffectObservationStore::durable(
            8,
            wal_root.clone(),
            EvidenceWalLimits::default(),
            canonicalizer()?,
        )?;
        store.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        for source_sequence in 1..=4 {
            store.record_bytes(
                EffectObservationV1 {
                    observed_boottime_ns: source_sequence,
                    source_sequence,
                    task_cookie: 1,
                    effect_family: 1,
                    operation: 1,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        }
        store.sample_coverage_health(
            EffectObservationHealthV1 {
                next_sequence: 4,
                ..EffectObservationHealthV1::default()
            }
            .as_bytes(),
        )?;
        drop(store);

        let restarted = EffectObservationStore::durable(
            8,
            wal_root,
            EvidenceWalLimits::default(),
            canonicalizer()?,
        )?;
        assert!(restarted.recover_coverage_after_prior_probe(
            EffectObservationHealthV1 {
                next_sequence: 6,
                ..EffectObservationHealthV1::default()
            }
            .as_bytes(),
        )?);
        let before_replay = restarted
            .next_evidence_batch()
            .ok_or("evidence batch missing before replay")?;
        restarted.record_bytes(
            EffectObservationV1 {
                observed_boottime_ns: 4,
                source_sequence: 4,
                task_cookie: 1,
                effect_family: 1,
                operation: 1,
                ..EffectObservationV1::default()
            }
            .as_bytes(),
        );
        let after_replay = restarted
            .next_evidence_batch()
            .ok_or("evidence batch missing after replay")?;

        assert_eq!(after_replay.records.len(), 4);
        assert_eq!(after_replay.last_cursor, before_replay.last_cursor);
        assert_eq!(after_replay.records, before_replay.records);
        assert_eq!(restarted.evidence_errors(), 0);
        assert!(restarted
            .coverage_snapshot()
            .is_some_and(|snapshot| snapshot.supports_negative_claim()));
        Ok(())
    }

    #[test]
    fn evidence_gap_transition_emits_one_owned_warning() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = EffectObservationStore::durable(
            4,
            directory.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                EvidenceIdV1::new(5, 6),
            )?,
        )?;
        store.sample_coverage_health(EffectObservationHealthV1::default().as_bytes())?;
        let telemetry = erebor_telemetry::JsonlTelemetry::open(
            directory.path().join("observation-logs"),
            16 * 1_024,
        )?;

        telemetry.emit(|| store.mark_coverage_gapped(CoverageGapReasonV1::ControlDelay))??;
        telemetry.emit(|| store.mark_coverage_gapped(CoverageGapReasonV1::ControlDelay))??;

        let records = telemetry.records_after(0, 4)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, "mithril_node::observation");
        assert_eq!(records[0].level, "WARN");
        assert_eq!(records[0].message, "marked evidence coverage as gapped");
        assert_eq!(
            records[0].fields.get("reason").map(String::as_str),
            Some("CONTROL_DELAY")
        );
        Ok(())
    }
}
