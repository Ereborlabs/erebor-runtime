use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{
    CoverageGapReasonV1, CoverageStateV1, EvidenceIdV1, ObservationCanonicalizer,
    TemporalCoverageV1,
};
use crate::error::{EvidenceStateSnafu, IoSnafu};
use crate::Result;

use super::persistence::atomic_write;

const COVERAGE_SCHEMA_VERSION: u32 = 1;
const MAX_COVERAGE_HISTORY: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCountersV1 {
    pub attempted: u64,
    pub suppressed: u64,
    pub requested: u64,
    pub emitted: u64,
    pub lost: u64,
    pub classifier_miss_count: u64,
    pub unresolved: u64,
    pub next_sequence: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectObservationCpuHealth {
    pub cpu_id: u32,
    pub counters: CoverageCountersV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryProbeStatus {
    Pending,
    Recovered,
    Resample,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageIntervalV1 {
    pub interval_id: EvidenceIdV1,
    pub source_id: EvidenceIdV1,
    pub source_epoch: u64,
    pub cpu_id: u32,
    pub revision: u64,
    pub state: CoverageStateV1,
    pub first_sequence: u64,
    pub last_sequence: Option<u64>,
    pub opening_counters: CoverageCountersV1,
    pub closing_counters: Option<CoverageCountersV1>,
    pub gap_reasons: Vec<CoverageGapReasonV1>,
}

impl CoverageIntervalV1 {
    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        matches!(
            self.state,
            CoverageStateV1::Healthy | CoverageStateV1::Closed
        ) && self.gap_reasons.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceCoverageV1 {
    source_id: EvidenceIdV1,
    cpu_id: u32,
    last_observed_sequence: Option<u64>,
    last_health: Option<CoverageCountersV1>,
    current: CoverageIntervalV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSnapshotV1 {
    pub schema_version: u32,
    pub source_epoch: u64,
    pub revision: u64,
    pub history: Vec<CoverageIntervalV1>,
    sources: BTreeMap<u32, SourceCoverageV1>,
}

impl CoverageSnapshotV1 {
    #[must_use]
    pub fn current_intervals(&self) -> Vec<CoverageIntervalV1> {
        self.sources
            .values()
            .map(|source| source.current.clone())
            .collect()
    }

    #[must_use]
    pub fn all_intervals(&self) -> Vec<CoverageIntervalV1> {
        self.history
            .iter()
            .cloned()
            .chain(self.current_intervals())
            .collect()
    }

    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        !self.sources.is_empty()
            && self
                .sources
                .values()
                .all(|source| source.current.supports_negative_claim())
    }

    pub(crate) fn waits_only_for_reader_delivery(&self) -> bool {
        let mut waiting = false;
        for source in self.sources.values() {
            match source.current.state {
                CoverageStateV1::Healthy if source.current.gap_reasons.is_empty() => {}
                CoverageStateV1::Gapped
                    if !source.current.gap_reasons.is_empty()
                        && source
                            .current
                            .gap_reasons
                            .iter()
                            .all(|reason| *reason == CoverageGapReasonV1::ReaderDelay) =>
                {
                    waiting = true;
                }
                _ => return false,
            }
        }
        waiting
    }
}

#[derive(Clone)]
pub struct CoverageHealthOwner {
    inner: Arc<Mutex<CoverageInner>>,
}

struct CoverageInner {
    path: PathBuf,
    canonicalizer: ObservationCanonicalizer,
    snapshot: CoverageSnapshotV1,
}

impl CoverageInner {
    fn commit<T>(&mut self, change: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let original = self.snapshot.clone();
        let value = match change(self) {
            Ok(value) => value,
            Err(error) => {
                self.snapshot = original;
                return Err(error);
            }
        };
        if self.snapshot == original {
            return Ok(value);
        }
        if let Err(error) = bump_and_persist(self) {
            self.snapshot = original;
            return Err(error);
        }
        Ok(value)
    }
}

struct IntervalStart {
    state: CoverageStateV1,
    first_sequence: u64,
    counters: CoverageCountersV1,
    gap_reasons: Vec<CoverageGapReasonV1>,
}

impl CoverageHealthOwner {
    pub fn open(path: impl Into<PathBuf>, canonicalizer: ObservationCanonicalizer) -> Result<Self> {
        let path = path.into();
        let source_epoch = canonicalizer.source_epoch();
        let snapshot = if path.exists() {
            let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
            let mut prior: CoverageSnapshotV1 =
                serde_json::from_slice(&bytes).map_err(|error| {
                    EvidenceStateSnafu {
                        reason: format!("coverage state decoding failed: {error}"),
                    }
                    .build()
                })?;
            validate_snapshot(&prior)?;
            if prior.source_epoch == source_epoch {
                for source in prior.sources.values_mut() {
                    source.current.state = CoverageStateV1::Gapped;
                    insert_reason(
                        &mut source.current.gap_reasons,
                        CoverageGapReasonV1::UncleanRestart,
                    );
                }
                prior.revision = prior.revision.checked_add(1).ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "coverage revision is exhausted".to_owned(),
                    }
                    .build()
                })?;
                prior
            } else {
                let sources = std::mem::take(&mut prior.sources);
                for source in sources.into_values() {
                    let mut interval = source.current;
                    interval.state = CoverageStateV1::Gapped;
                    insert_reason(
                        &mut interval.gap_reasons,
                        CoverageGapReasonV1::UncleanRestart,
                    );
                    prior.history.push(interval);
                }
                if prior.history.len() > MAX_COVERAGE_HISTORY {
                    return EvidenceStateSnafu {
                        reason: "coverage history capacity is exhausted".to_owned(),
                    }
                    .fail();
                }
                CoverageSnapshotV1 {
                    schema_version: COVERAGE_SCHEMA_VERSION,
                    source_epoch,
                    revision: prior.revision.checked_add(1).ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "coverage revision is exhausted".to_owned(),
                        }
                        .build()
                    })?,
                    history: prior.history,
                    sources: BTreeMap::new(),
                }
            }
        } else {
            CoverageSnapshotV1 {
                schema_version: COVERAGE_SCHEMA_VERSION,
                source_epoch,
                revision: 0,
                history: Vec::new(),
                sources: BTreeMap::new(),
            }
        };
        let inner = Self {
            inner: Arc::new(Mutex::new(CoverageInner {
                path,
                canonicalizer,
                snapshot,
            })),
        };
        inner.persist()?;
        Ok(inner)
    }

    pub fn sample_health(&self, samples: &[EffectObservationCpuHealth]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.commit(|inner| {
            for sample in samples {
                let completed = {
                    let source = ensure_source(inner, *sample)?;
                    let counters = sample.counters;
                    let first_health_sample = source.last_health.is_none();
                    let accounting_valid = counters_are_valid(counters);
                    let mut gaps = Vec::new();
                    if let Some(previous) = source.last_health {
                        if counters.attempted < previous.attempted
                            || counters.suppressed < previous.suppressed
                            || counters.requested < previous.requested
                            || counters.emitted < previous.emitted
                            || counters.lost < previous.lost
                            || counters.classifier_miss_count < previous.classifier_miss_count
                            || counters.unresolved < previous.unresolved
                            || counters.next_sequence < previous.next_sequence
                            || !accounting_valid
                        {
                            gaps.push(CoverageGapReasonV1::CounterRegression);
                        } else {
                            if counters.lost > previous.lost {
                                gaps.push(CoverageGapReasonV1::RingLoss);
                            }
                            if counters.classifier_miss_count > previous.classifier_miss_count {
                                gaps.push(CoverageGapReasonV1::ClassifierMiss);
                            }
                            if counters.unresolved > previous.unresolved {
                                gaps.push(CoverageGapReasonV1::UnresolvedEffect);
                            }
                        }
                    } else if !accounting_valid {
                        gaps.push(CoverageGapReasonV1::CounterRegression);
                    }
                    source.last_health = Some(counters);
                    let mut completed = mark_source_gaps(source, gaps, counters);
                    if completed.is_none()
                        && source.current.state != CoverageStateV1::Gapped
                        && first_health_sample
                        && source.last_observed_sequence.unwrap_or(0) == counters.next_sequence
                        && source.current.state == CoverageStateV1::Unknown
                    {
                        completed = Some(rotate_interval(
                            source,
                            CoverageStateV1::Healthy,
                            counters.next_sequence.saturating_add(1),
                            counters,
                            Vec::new(),
                        ));
                    } else if completed.is_none()
                        && source.current.state != CoverageStateV1::Gapped
                        && source.last_observed_sequence.unwrap_or(0) < counters.next_sequence
                        && (first_health_sample || source.current.state == CoverageStateV1::Healthy)
                    {
                        completed =
                            mark_source_gap(source, CoverageGapReasonV1::ReaderDelay, counters);
                    }
                    source.current.closing_counters = Some(counters);
                    completed
                };
                append_history(inner, completed)?;
            }
            Ok(())
        })
    }

    pub fn observe(
        &self,
        cpu_id: u32,
        sequence: u64,
    ) -> Result<(EvidenceIdV1, TemporalCoverageV1)> {
        if sequence == 0 {
            return EvidenceStateSnafu {
                reason: "coverage observation sequence must be nonzero".to_owned(),
            }
            .fail();
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.commit(|inner| {
            let baseline = EffectObservationCpuHealth {
                cpu_id,
                counters: CoverageCountersV1 {
                    next_sequence: sequence - 1,
                    ..CoverageCountersV1::default()
                },
            };
            let (completed, interval_id, coverage) = {
                let source = ensure_source(inner, baseline)?;
                let expected = source
                    .last_observed_sequence
                    .unwrap_or(source.current.opening_counters.next_sequence)
                    .checked_add(1);
                let completed = if expected != Some(sequence) {
                    mark_source_gap(
                        source,
                        CoverageGapReasonV1::SourceSequenceGap,
                        source.last_health.unwrap_or_default(),
                    )
                } else {
                    None
                };
                source.last_observed_sequence = Some(sequence);
                source.current.last_sequence = Some(sequence);
                let interval_id = source.current.interval_id;
                let coverage = if source.current.supports_negative_claim() {
                    TemporalCoverageV1::Complete
                } else {
                    TemporalCoverageV1::Gapped
                };
                (completed, interval_id, coverage)
            };
            append_history(inner, completed)?;
            Ok((interval_id, coverage))
        })
    }

    pub fn mark_all_gapped(&self, reason: CoverageGapReasonV1) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.commit(|inner| {
            let mut completed = Vec::new();
            for source in inner.snapshot.sources.values_mut() {
                if let Some(interval) =
                    mark_source_gap(source, reason, source.last_health.unwrap_or_default())
                {
                    completed.push(interval);
                }
            }
            for interval in completed {
                append_history(inner, Some(interval))?;
            }
            Ok(())
        })
    }

    pub fn recover_after_probe(&self, samples: &[EffectObservationCpuHealth]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.snapshot.sources.is_empty() {
            return EvidenceStateSnafu {
                reason: "coverage recovery requires an existing source".to_owned(),
            }
            .fail();
        }
        let sample_count = samples.len();
        let samples = samples
            .iter()
            .map(|sample| (sample.cpu_id, sample.counters))
            .collect::<BTreeMap<_, _>>();
        if samples.len() != sample_count || samples.len() != inner.snapshot.sources.len() {
            return EvidenceStateSnafu {
                reason: "coverage recovery requires one probe for every source".to_owned(),
            }
            .fail();
        }
        for (cpu_id, source) in &inner.snapshot.sources {
            let counters = samples.get(cpu_id).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "coverage recovery is missing a source probe".to_owned(),
                }
                .build()
            })?;
            if !counters_are_valid(*counters)
                || source.last_health != Some(*counters)
                || source.last_observed_sequence.unwrap_or(0) != counters.next_sequence
                || (source.current.state == CoverageStateV1::Gapped
                    && source
                        .current
                        .gap_reasons
                        .contains(&CoverageGapReasonV1::CounterRegression))
            {
                return EvidenceStateSnafu {
                    reason: "coverage recovery probe is incomplete or inconsistent".to_owned(),
                }
                .fail();
            }
        }
        let recovering = inner
            .snapshot
            .sources
            .values()
            .filter(|source| source.current.state == CoverageStateV1::Gapped)
            .count();
        if inner.snapshot.history.len().saturating_add(recovering) > MAX_COVERAGE_HISTORY {
            return EvidenceStateSnafu {
                reason: "coverage history capacity is exhausted".to_owned(),
            }
            .fail();
        }

        inner.commit(|inner| {
            let mut completed = Vec::with_capacity(recovering);
            for source in inner.snapshot.sources.values_mut() {
                if source.current.state != CoverageStateV1::Gapped {
                    continue;
                }
                let counters = samples[&source.cpu_id];
                let first_sequence = counters.next_sequence.checked_add(1).ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "coverage recovery sequence is exhausted".to_owned(),
                    }
                    .build()
                })?;
                completed.push(rotate_interval(
                    source,
                    CoverageStateV1::Healthy,
                    first_sequence,
                    counters,
                    Vec::new(),
                ));
            }
            inner.snapshot.history.extend(completed);
            Ok(())
        })
    }

    pub(super) fn recover_after_prior_probe(
        &self,
        samples: &[EffectObservationCpuHealth],
    ) -> Result<RecoveryProbeStatus> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.snapshot.sources.is_empty() {
            return Ok(RecoveryProbeStatus::Resample);
        }
        let sample_count = samples.len();
        let samples = samples
            .iter()
            .map(|sample| (sample.cpu_id, sample.counters))
            .collect::<BTreeMap<_, _>>();
        if samples.len() != sample_count || samples.len() != inner.snapshot.sources.len() {
            return EvidenceStateSnafu {
                reason: "coverage recovery requires one probe for every source".to_owned(),
            }
            .fail();
        }

        let mut pending = false;
        for (cpu_id, source) in &inner.snapshot.sources {
            let current = samples.get(cpu_id).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "coverage recovery is missing a source probe".to_owned(),
                }
                .build()
            })?;
            let Some(prior) = source.last_health else {
                return Ok(RecoveryProbeStatus::Resample);
            };
            if !counters_are_valid(*current)
                || current.attempted < prior.attempted
                || current.suppressed < prior.suppressed
                || current.requested < prior.requested
                || current.emitted < prior.emitted
                || current.lost < prior.lost
                || current.classifier_miss_count < prior.classifier_miss_count
                || current.unresolved < prior.unresolved
                || current.next_sequence < prior.next_sequence
                || current.lost > prior.lost
                || current.classifier_miss_count > prior.classifier_miss_count
                || current.unresolved > prior.unresolved
            {
                return Ok(RecoveryProbeStatus::Resample);
            }
            if source.current.state == CoverageStateV1::Gapped
                && source
                    .current
                    .gap_reasons
                    .contains(&CoverageGapReasonV1::CounterRegression)
            {
                return EvidenceStateSnafu {
                    reason: "coverage cannot recover after a counter regression".to_owned(),
                }
                .fail();
            }
            if source.last_observed_sequence.unwrap_or(0) < prior.next_sequence {
                pending = true;
            }
        }
        if pending {
            return Ok(RecoveryProbeStatus::Pending);
        }

        let recovering = inner
            .snapshot
            .sources
            .values()
            .filter(|source| source.current.state == CoverageStateV1::Gapped)
            .count();
        if inner.snapshot.history.len().saturating_add(recovering) > MAX_COVERAGE_HISTORY {
            return EvidenceStateSnafu {
                reason: "coverage history capacity is exhausted".to_owned(),
            }
            .fail();
        }

        inner.commit(|inner| {
            let mut completed = Vec::with_capacity(recovering);
            for source in inner.snapshot.sources.values_mut() {
                let counters = samples[&source.cpu_id];
                source.last_health = Some(counters);
                source.current.closing_counters = Some(counters);
                if source.current.state != CoverageStateV1::Gapped {
                    continue;
                }
                let first_sequence = source
                    .last_observed_sequence
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| {
                        EvidenceStateSnafu {
                            reason: "coverage recovery sequence is exhausted".to_owned(),
                        }
                        .build()
                    })?;
                completed.push(rotate_interval(
                    source,
                    CoverageStateV1::Healthy,
                    first_sequence,
                    counters,
                    Vec::new(),
                ));
            }
            inner.snapshot.history.extend(completed);
            Ok(RecoveryProbeStatus::Recovered)
        })
    }

    pub fn snapshot(&self) -> CoverageSnapshotV1 {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .snapshot
            .clone()
    }

    fn persist(&self) -> Result<()> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        persist_snapshot(&inner.path, &inner.snapshot)
    }
}

fn ensure_source(
    inner: &mut CoverageInner,
    sample: EffectObservationCpuHealth,
) -> Result<&mut SourceCoverageV1> {
    if !inner.snapshot.sources.contains_key(&sample.cpu_id) {
        let source_id = inner.canonicalizer.cpu_source_id(sample.cpu_id);
        let revision = inner.snapshot.revision.saturating_add(1);
        let interval = interval(
            source_id,
            inner.snapshot.source_epoch,
            sample.cpu_id,
            revision,
            IntervalStart {
                state: CoverageStateV1::Unknown,
                first_sequence: sample.counters.next_sequence.saturating_add(1),
                counters: sample.counters,
                gap_reasons: Vec::new(),
            },
        );
        inner.snapshot.sources.insert(
            sample.cpu_id,
            SourceCoverageV1 {
                source_id,
                cpu_id: sample.cpu_id,
                last_observed_sequence: None,
                last_health: None,
                current: interval,
            },
        );
    }
    inner
        .snapshot
        .sources
        .get_mut(&sample.cpu_id)
        .ok_or_else(|| {
            EvidenceStateSnafu {
                reason: "coverage source insertion did not persist".to_owned(),
            }
            .build()
        })
}

fn counters_are_valid(counters: CoverageCountersV1) -> bool {
    counters.attempted == counters.suppressed.saturating_add(counters.requested)
        && counters.requested == counters.emitted.saturating_add(counters.lost)
}

fn mark_source_gap(
    source: &mut SourceCoverageV1,
    reason: CoverageGapReasonV1,
    counters: CoverageCountersV1,
) -> Option<CoverageIntervalV1> {
    if source.current.state == CoverageStateV1::Healthy {
        let first_unobserved = source
            .last_observed_sequence
            .map_or(source.current.first_sequence, |sequence| {
                sequence.saturating_add(1)
            });
        Some(rotate_interval(
            source,
            CoverageStateV1::Gapped,
            first_unobserved,
            counters,
            vec![reason],
        ))
    } else {
        source.current.state = CoverageStateV1::Gapped;
        source.current.closing_counters = Some(counters);
        insert_reason(&mut source.current.gap_reasons, reason);
        None
    }
}

fn mark_source_gaps(
    source: &mut SourceCoverageV1,
    reasons: impl IntoIterator<Item = CoverageGapReasonV1>,
    counters: CoverageCountersV1,
) -> Option<CoverageIntervalV1> {
    let mut completed = None;
    for reason in reasons {
        if let Some(interval) = mark_source_gap(source, reason, counters) {
            completed = Some(interval);
        }
    }
    completed
}

fn rotate_interval(
    source: &mut SourceCoverageV1,
    state: CoverageStateV1,
    first_sequence: u64,
    counters: CoverageCountersV1,
    reasons: Vec<CoverageGapReasonV1>,
) -> CoverageIntervalV1 {
    let revision = source.current.revision.saturating_add(1);
    let next = interval(
        source.source_id,
        source.current.source_epoch,
        source.cpu_id,
        revision,
        IntervalStart {
            state,
            first_sequence,
            counters,
            gap_reasons: reasons,
        },
    );
    let mut completed = std::mem::replace(&mut source.current, next);
    completed.closing_counters = Some(counters);
    completed.state = if completed.state == CoverageStateV1::Healthy {
        CoverageStateV1::Closed
    } else {
        completed.state
    };
    completed
}

fn append_history(inner: &mut CoverageInner, interval: Option<CoverageIntervalV1>) -> Result<()> {
    if let Some(interval) = interval {
        if inner.snapshot.history.len() == MAX_COVERAGE_HISTORY {
            return EvidenceStateSnafu {
                reason: "coverage history capacity is exhausted".to_owned(),
            }
            .fail();
        }
        inner.snapshot.history.push(interval);
    }
    Ok(())
}

fn interval(
    source_id: EvidenceIdV1,
    source_epoch: u64,
    cpu_id: u32,
    revision: u64,
    start: IntervalStart,
) -> CoverageIntervalV1 {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-COVERAGE-INTERVAL-V1\0");
    digest.update(source_id.to_be_bytes());
    digest.update(source_epoch.to_be_bytes());
    digest.update(cpu_id.to_be_bytes());
    digest.update(revision.to_be_bytes());
    digest.update(start.first_sequence.to_be_bytes());
    CoverageIntervalV1 {
        interval_id: <[u8; 32]>::from(digest.finalize()).into(),
        source_id,
        source_epoch,
        cpu_id,
        revision,
        state: start.state,
        first_sequence: start.first_sequence,
        last_sequence: None,
        opening_counters: start.counters,
        closing_counters: None,
        gap_reasons: start.gap_reasons,
    }
}

fn insert_reason(reasons: &mut Vec<CoverageGapReasonV1>, reason: CoverageGapReasonV1) {
    if let Err(index) = reasons.binary_search(&reason) {
        reasons.insert(index, reason);
    }
}

fn bump_and_persist(inner: &mut CoverageInner) -> Result<()> {
    inner.snapshot.revision = inner.snapshot.revision.checked_add(1).ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "coverage revision is exhausted".to_owned(),
        }
        .build()
    })?;
    if inner.snapshot.history.len() > MAX_COVERAGE_HISTORY {
        return EvidenceStateSnafu {
            reason: "coverage history capacity is exhausted".to_owned(),
        }
        .fail();
    }
    persist_snapshot(&inner.path, &inner.snapshot)
}

fn validate_snapshot(snapshot: &CoverageSnapshotV1) -> Result<()> {
    let mut interval_ids = std::collections::BTreeSet::new();
    if snapshot.schema_version != COVERAGE_SCHEMA_VERSION
        || snapshot.source_epoch == 0
        || snapshot.history.len() > MAX_COVERAGE_HISTORY
        || snapshot.history.iter().any(|interval| {
            interval.source_epoch > snapshot.source_epoch
                || !interval_ids.insert(interval.interval_id)
                || !interval_is_valid(interval, false)
        })
        || snapshot.sources.iter().any(|(cpu, source)| {
            *cpu != source.cpu_id
                || source.source_id.is_zero()
                || !interval_ids.insert(source.current.interval_id)
                || source.current.source_epoch != snapshot.source_epoch
                || source.current.source_id != source.source_id
                || !interval_is_valid(&source.current, true)
                || source.last_observed_sequence == Some(0)
                || source.last_health.is_some_and(|counters| {
                    !counters_are_valid(counters)
                        && !source
                            .current
                            .gap_reasons
                            .contains(&CoverageGapReasonV1::CounterRegression)
                })
        })
    {
        return EvidenceStateSnafu {
            reason: "coverage state version, identity, or bounds are invalid".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn interval_is_valid(interval: &CoverageIntervalV1, current: bool) -> bool {
    let gap_reasons_valid = !interval
        .gap_reasons
        .windows(2)
        .any(|pair| pair[0] >= pair[1]);
    let state_valid = match interval.state {
        CoverageStateV1::Healthy | CoverageStateV1::Closed => interval.gap_reasons.is_empty(),
        CoverageStateV1::Gapped => !interval.gap_reasons.is_empty(),
        CoverageStateV1::Unknown => interval.gap_reasons.is_empty(),
    } && (!current || interval.state != CoverageStateV1::Closed);
    let counter_regression = interval
        .gap_reasons
        .contains(&CoverageGapReasonV1::CounterRegression);
    let counters_valid = (counters_are_valid(interval.opening_counters)
        && interval.closing_counters.is_none_or(counters_are_valid))
        || (interval.state == CoverageStateV1::Gapped && counter_regression);
    !interval.interval_id.is_zero()
        && !interval.source_id.is_zero()
        && interval.source_epoch > 0
        && interval.revision > 0
        && interval.first_sequence > 0
        && interval
            .last_sequence
            .is_none_or(|last| last >= interval.first_sequence)
        && gap_reasons_valid
        && state_valid
        && counters_valid
}

fn persist_snapshot(path: &Path, snapshot: &CoverageSnapshotV1) -> Result<()> {
    validate_snapshot(snapshot)?;
    let parent = path.parent().ok_or_else(|| {
        EvidenceStateSnafu {
            reason: "coverage state path has no parent".to_owned(),
        }
        .build()
    })?;
    fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
    let bytes = serde_json::to_vec(snapshot).map_err(|error| {
        EvidenceStateSnafu {
            reason: format!("coverage state encoding failed: {error}"),
        }
        .build()
    })?;
    atomic_write(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageCountersV1, CoverageGapReasonV1, CoverageHealthOwner, EffectObservationCpuHealth,
        RecoveryProbeStatus,
    };
    use crate::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn open_owner(path: &std::path::Path, epoch: u64) -> crate::Result<CoverageHealthOwner> {
        CoverageHealthOwner::open(
            path,
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                epoch,
                EvidenceIdV1::new(5, 6),
            )?,
        )
    }

    fn health(next_sequence: u64, lost: u64) -> EffectObservationCpuHealth {
        EffectObservationCpuHealth {
            cpu_id: 2,
            counters: CoverageCountersV1 {
                attempted: next_sequence,
                requested: next_sequence,
                emitted: next_sequence.saturating_sub(lost),
                lost,
                next_sequence,
                ..CoverageCountersV1::default()
            },
        }
    }

    #[test]
    fn sequence_and_loss_gaps_cannot_support_negative_claims(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let skipped = open_owner(&directory.path().join("skipped.json"), 1)?;
        skipped.sample_health(&[health(0, 0)])?;
        let (_, coverage) = skipped.observe(2, 2)?;
        assert_eq!(coverage, TemporalCoverageV1::Gapped);

        let path = directory.path().join("coverage.json");
        let owner = open_owner(&path, 1)?;
        owner.sample_health(&[health(0, 0)])?;
        let (_, coverage) = owner.observe(2, 1)?;
        assert_eq!(coverage, TemporalCoverageV1::Complete);
        owner.sample_health(&[health(1, 0)])?;
        let (_, coverage) = owner.observe(2, 3)?;
        assert_eq!(coverage, TemporalCoverageV1::Gapped);
        assert!(!owner.snapshot().supports_negative_claim());
        owner.sample_health(&[health(4, 1)])?;
        assert!(owner.snapshot().current_intervals()[0]
            .gap_reasons
            .contains(&CoverageGapReasonV1::RingLoss));
        owner.observe(2, 4)?;
        owner.sample_health(&[health(4, 1)])?;
        assert!(!owner.snapshot().supports_negative_claim());
        Ok(())
    }

    #[test]
    fn reader_delay_accepts_queued_records_without_reopening_coverage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = open_owner(&directory.path().join("coverage.json"), 1)?;
        owner.sample_health(&[health(0, 0)])?;

        // The kernel counters can advance before the ring reader delivers the records.
        owner.sample_health(&[health(8, 0)])?;
        assert!(owner.snapshot().waits_only_for_reader_delivery());
        for sequence in 1..=8 {
            let (_, coverage) = owner.observe(2, sequence)?;
            assert_eq!(coverage, TemporalCoverageV1::Gapped);
        }

        let current = &owner.snapshot().current_intervals()[0];
        assert_eq!(current.first_sequence, 1);
        assert_eq!(current.last_sequence, Some(8));
        assert!(current
            .gap_reasons
            .contains(&CoverageGapReasonV1::ReaderDelay));
        Ok(())
    }

    #[test]
    fn recovery_waits_for_the_original_reader_delay_probe() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let owner = open_owner(&directory.path().join("coverage.json"), 1)?;
        owner.sample_health(&[health(0, 0)])?;
        owner.sample_health(&[health(8, 0)])?;
        for sequence in 1..=4 {
            owner.observe(2, sequence)?;
        }

        assert_eq!(
            owner.recover_after_prior_probe(&[health(10, 0)])?,
            RecoveryProbeStatus::Pending
        );
        for sequence in 5..=8 {
            owner.observe(2, sequence)?;
        }
        assert_eq!(
            owner.recover_after_prior_probe(&[health(12, 0)])?,
            RecoveryProbeStatus::Recovered
        );

        let snapshot = owner.snapshot();
        assert!(!snapshot.waits_only_for_reader_delivery());
        assert!(snapshot.supports_negative_claim());
        assert_eq!(snapshot.current_intervals()[0].first_sequence, 9);
        Ok(())
    }

    #[test]
    fn restart_preserves_epoch_and_marks_a_new_epoch_unclean(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("coverage.json");
        let owner = open_owner(&path, 1)?;
        owner.sample_health(&[health(0, 0)])?;
        owner.observe(2, 1)?;
        drop(owner);
        let same_epoch = open_owner(&path, 1)?;
        assert_eq!(same_epoch.snapshot().source_epoch, 1);
        same_epoch.sample_health(&[health(1, 0)])?;
        same_epoch.recover_after_probe(&[health(1, 0)])?;
        let recovered = same_epoch.snapshot();
        assert!(recovered.supports_negative_claim());
        assert!(recovered.history.iter().any(|interval| interval
            .gap_reasons
            .contains(&CoverageGapReasonV1::UncleanRestart)));
        drop(same_epoch);
        let restarted = open_owner(&path, 2)?;
        assert_eq!(restarted.snapshot().source_epoch, 2);
        assert!(restarted.snapshot().history.iter().any(|interval| interval
            .gap_reasons
            .contains(&CoverageGapReasonV1::UncleanRestart)));
        Ok(())
    }

    #[test]
    fn exact_probe_opens_a_new_healthy_interval_without_rewriting_a_gap(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = open_owner(&directory.path().join("coverage.json"), 1)?;
        owner.sample_health(&[health(0, 0)])?;
        owner.observe(2, 1)?;
        owner.sample_health(&[health(2, 1)])?;
        assert!(owner.recover_after_probe(&[health(2, 1)]).is_err());

        owner.observe(2, 3)?;
        owner.sample_health(&[health(3, 1)])?;
        owner.recover_after_probe(&[health(3, 1)])?;

        let snapshot = owner.snapshot();
        assert!(snapshot.supports_negative_claim());
        assert!(snapshot.history.iter().any(|interval| {
            interval.state == crate::CoverageStateV1::Gapped
                && interval
                    .gap_reasons
                    .contains(&CoverageGapReasonV1::RingLoss)
                && interval
                    .gap_reasons
                    .contains(&CoverageGapReasonV1::SourceSequenceGap)
        }));
        let current = &snapshot.current_intervals()[0];
        assert_eq!(current.state, crate::CoverageStateV1::Healthy);
        assert_eq!(current.first_sequence, 4);
        assert!(current.gap_reasons.is_empty());
        Ok(())
    }

    #[test]
    fn reopen_rejects_a_healthy_interval_that_retains_a_gap_reason(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("coverage.json");
        let owner = open_owner(&path, 1)?;
        owner.sample_health(&[health(0, 0)])?;
        drop(owner);

        let mut snapshot: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        snapshot["sources"]["2"]["current"]["gap_reasons"] = serde_json::json!(["RING_LOSS"]);
        std::fs::write(&path, serde_json::to_vec(&snapshot)?)?;
        assert!(open_owner(&path, 1).is_err());
        Ok(())
    }

    #[test]
    fn one_health_sample_records_each_increased_gap_counter(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = open_owner(&directory.path().join("coverage.json"), 1)?;
        owner.sample_health(&[health(0, 0)])?;
        owner.sample_health(&[EffectObservationCpuHealth {
            cpu_id: 2,
            counters: CoverageCountersV1 {
                attempted: 1,
                requested: 1,
                emitted: 1,
                classifier_miss_count: 1,
                unresolved: 1,
                next_sequence: 1,
                ..CoverageCountersV1::default()
            },
        }])?;

        let interval = &owner.snapshot().current_intervals()[0];
        assert!(interval
            .gap_reasons
            .contains(&CoverageGapReasonV1::ClassifierMiss));
        assert!(interval
            .gap_reasons
            .contains(&CoverageGapReasonV1::UnresolvedEffect));
        Ok(())
    }

    #[test]
    fn failed_persistence_does_not_publish_a_coverage_change(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = open_owner(&directory.path().join("coverage.json"), 1)?;
        owner.sample_health(&[health(0, 0)])?;
        let before = owner.snapshot();
        let blocked_path = directory.path().join("blocked");
        std::fs::create_dir(&blocked_path)?;
        owner
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .path = blocked_path;

        assert!(owner.observe(2, 1).is_err());
        assert_eq!(owner.snapshot(), before);
        Ok(())
    }
}
