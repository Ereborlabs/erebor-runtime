use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{CoverageIntervalV1, CoverageSnapshotV1, EvidenceDigestV1, EvidenceIdV1};
use crate::error::EvidenceStateSnafu;
use crate::{ObservationEnvelopeV1, Result};

const LOCAL_WINDOW_SCHEMA_VERSION: u32 = 1;
const MAX_LOCAL_WINDOWS: usize = 4_096;
const MAX_WINDOW_OBSERVATIONS: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFindingWindowSpecV1 {
    pub package_id: String,
    pub package_version: u32,
    pub sequence_width: u64,
}

impl LocalFindingWindowSpecV1 {
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.package_id.len() > 128
            || !self
                .package_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.package_version == 0
            || self.sequence_width == 0
            || self.sequence_width > MAX_WINDOW_OBSERVATIONS as u64
        {
            return EvidenceStateSnafu {
                reason: "local window package identity or sequence bound is invalid".to_owned(),
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalFindingWindowStateV1 {
    Open = 0,
    Ready = 1,
    CoverageInsufficient = 2,
    Contradicted = 3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFindingWindowV1 {
    pub schema_version: u32,
    pub window_id: EvidenceDigestV1,
    pub package_id: String,
    pub package_version: u32,
    pub source_id: EvidenceIdV1,
    pub source_epoch: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub revision_digest: EvidenceDigestV1,
    pub state: LocalFindingWindowStateV1,
    pub observation_ids: Vec<EvidenceDigestV1>,
    pub coverage_interval_ids: Vec<EvidenceIdV1>,
}

impl LocalFindingWindowV1 {
    #[must_use]
    pub fn supports_negative_claim(&self) -> bool {
        self.state == LocalFindingWindowStateV1::Ready
    }
}

pub struct DeterministicLocalWindowOwner {
    spec: LocalFindingWindowSpecV1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WindowKey {
    source_id: EvidenceIdV1,
    source_epoch: u64,
    first_sequence: u64,
}

#[derive(Default)]
struct WindowInputs {
    observations: BTreeMap<u64, BTreeSet<EvidenceDigestV1>>,
    coverage_incomplete: bool,
}

impl DeterministicLocalWindowOwner {
    pub fn new(spec: LocalFindingWindowSpecV1) -> Result<Self> {
        spec.validate()?;
        Ok(Self { spec })
    }

    pub fn build(
        &self,
        observations: &[ObservationEnvelopeV1],
        coverage: &CoverageSnapshotV1,
    ) -> Result<Vec<LocalFindingWindowV1>> {
        let intervals = coverage.all_intervals();
        let mut intervals_by_id = BTreeMap::new();
        for interval in &intervals {
            if intervals_by_id
                .insert(interval.interval_id, interval)
                .is_some()
            {
                return EvidenceStateSnafu {
                    reason: "local window coverage contains a repeated interval identity"
                        .to_owned(),
                }
                .fail();
            }
        }
        let mut grouped = BTreeMap::<WindowKey, WindowInputs>::new();
        for observation in observations {
            observation.validate()?;
            if observation.source_epoch != coverage.source_epoch {
                return EvidenceStateSnafu {
                    reason: "local window observation and coverage epochs differ".to_owned(),
                }
                .fail();
            }
            let offset = observation.source_sequence.checked_sub(1).ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "local window observation has sequence zero".to_owned(),
                }
                .build()
            })?;
            let first_sequence = offset
                .checked_div(self.spec.sequence_width)
                .and_then(|window| window.checked_mul(self.spec.sequence_width))
                .and_then(|start| start.checked_add(1))
                .ok_or_else(|| {
                    EvidenceStateSnafu {
                        reason: "local window sequence calculation overflowed".to_owned(),
                    }
                    .build()
                })?;
            let key = WindowKey {
                source_id: observation.source_id,
                source_epoch: observation.source_epoch,
                first_sequence,
            };
            let inputs = grouped.entry(key).or_default();
            let exact_coverage = intervals_by_id
                .get(&observation.coverage_interval_id)
                .is_some_and(|interval| {
                    interval.source_id == observation.source_id
                        && interval.source_epoch == observation.source_epoch
                        && interval.first_sequence <= observation.source_sequence
                        && interval_upper_sequence(interval) >= observation.source_sequence
                });
            inputs
                .observations
                .entry(observation.source_sequence)
                .or_default()
                .insert(observation.observation_id);
            inputs.coverage_incomplete |= !observation.supports_negative_claim() || !exact_coverage;
        }
        if grouped.len() > MAX_LOCAL_WINDOWS
            || grouped.values().any(|window| {
                window
                    .observations
                    .values()
                    .map(BTreeSet::len)
                    .sum::<usize>()
                    > MAX_WINDOW_OBSERVATIONS
            })
        {
            return EvidenceStateSnafu {
                reason: "local window count or observation capacity is exhausted".to_owned(),
            }
            .fail();
        }
        grouped
            .into_iter()
            .map(|(key, inputs)| self.build_window(key, inputs, coverage))
            .collect()
    }

    fn build_window(
        &self,
        key: WindowKey,
        inputs: WindowInputs,
        coverage: &CoverageSnapshotV1,
    ) -> Result<LocalFindingWindowV1> {
        let last_sequence = key
            .first_sequence
            .checked_add(self.spec.sequence_width - 1)
            .ok_or_else(|| {
                EvidenceStateSnafu {
                    reason: "local window upper sequence overflowed".to_owned(),
                }
                .build()
            })?;
        let intervals = coverage
            .all_intervals()
            .into_iter()
            .filter(|interval| {
                interval.source_id == key.source_id
                    && interval.source_epoch == key.source_epoch
                    && interval_upper_sequence(interval) >= key.first_sequence
                    && interval.first_sequence <= last_sequence
            })
            .collect::<Vec<_>>();
        let contradicted = inputs
            .observations
            .values()
            .any(|observations| observations.len() > 1);
        let observations_complete = inputs.observations.len() as u64 == self.spec.sequence_width
            && inputs
                .observations
                .keys()
                .copied()
                .eq(key.first_sequence..=last_sequence);
        let coverage_incomplete = inputs.coverage_incomplete
            || intervals
                .iter()
                .any(|interval| !interval.supports_negative_claim());
        let ready = eligible_coverage_spans(&intervals, key.first_sequence, last_sequence);
        let state = if contradicted {
            LocalFindingWindowStateV1::Contradicted
        } else if coverage_incomplete {
            LocalFindingWindowStateV1::CoverageInsufficient
        } else if ready && observations_complete {
            LocalFindingWindowStateV1::Ready
        } else {
            LocalFindingWindowStateV1::Open
        };
        let observation_ids = inputs
            .observations
            .into_values()
            .flatten()
            .collect::<Vec<_>>();
        let coverage_interval_ids = intervals
            .iter()
            .map(|interval| interval.interval_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let window_id = window_id(&self.spec, key, last_sequence);
        let revision_digest =
            revision_digest(window_id, state, &observation_ids, &coverage_interval_ids);
        Ok(LocalFindingWindowV1 {
            schema_version: LOCAL_WINDOW_SCHEMA_VERSION,
            window_id,
            package_id: self.spec.package_id.clone(),
            package_version: self.spec.package_version,
            source_id: key.source_id,
            source_epoch: key.source_epoch,
            first_sequence: key.first_sequence,
            last_sequence,
            revision_digest,
            state,
            observation_ids,
            coverage_interval_ids,
        })
    }
}

fn interval_upper_sequence(interval: &CoverageIntervalV1) -> u64 {
    interval
        .closing_counters
        .unwrap_or(interval.opening_counters)
        .next_sequence
        .max(interval.last_sequence.unwrap_or(0))
}

fn eligible_coverage_spans(
    intervals: &[CoverageIntervalV1],
    first_sequence: u64,
    last_sequence: u64,
) -> bool {
    let mut ranges = intervals
        .iter()
        .filter(|interval| interval.supports_negative_claim())
        .map(|interval| (interval.first_sequence, interval_upper_sequence(interval)))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    let mut next = first_sequence;
    for (start, end) in ranges {
        if end < next {
            continue;
        }
        if start > next {
            return false;
        }
        if end >= last_sequence {
            return true;
        }
        next = end.saturating_add(1);
    }
    false
}

fn window_id(
    spec: &LocalFindingWindowSpecV1,
    key: WindowKey,
    last_sequence: u64,
) -> EvidenceDigestV1 {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-LOCAL-WINDOW-V1\0");
    digest.update((spec.package_id.len() as u64).to_be_bytes());
    digest.update(spec.package_id.as_bytes());
    digest.update(spec.package_version.to_be_bytes());
    digest.update(key.source_id.to_be_bytes());
    digest.update(key.source_epoch.to_be_bytes());
    digest.update(key.first_sequence.to_be_bytes());
    digest.update(last_sequence.to_be_bytes());
    digest.finalize().into()
}

fn revision_digest(
    window_id: EvidenceDigestV1,
    state: LocalFindingWindowStateV1,
    observation_ids: &[EvidenceDigestV1],
    coverage_interval_ids: &[EvidenceIdV1],
) -> EvidenceDigestV1 {
    let mut digest = Sha256::new();
    digest.update(b"MITHRIL-LOCAL-WINDOW-REVISION-V1\0");
    digest.update(window_id);
    digest.update([state as u8]);
    digest.update((observation_ids.len() as u64).to_be_bytes());
    for observation_id in observation_ids {
        digest.update(observation_id);
    }
    digest.update((coverage_interval_ids.len() as u64).to_be_bytes());
    for coverage_id in coverage_interval_ids {
        digest.update(coverage_id.to_be_bytes());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::EffectObservationV1;

    use super::{
        DeterministicLocalWindowOwner, LocalFindingWindowSpecV1, LocalFindingWindowStateV1,
    };
    use crate::{
        CoverageCountersV1, CoverageHealthOwner, EffectObservationCpuHealth, EvidenceIdV1,
        ObservationCanonicalizer,
    };

    fn canonicalizer() -> crate::Result<ObservationCanonicalizer> {
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::new(5, 6),
        )
    }

    fn health(next_sequence: u64) -> EffectObservationCpuHealth {
        EffectObservationCpuHealth {
            cpu_id: 0,
            counters: CoverageCountersV1 {
                attempted: next_sequence,
                requested: next_sequence,
                emitted: next_sequence,
                next_sequence,
                ..CoverageCountersV1::default()
            },
        }
    }

    fn owner() -> crate::Result<DeterministicLocalWindowOwner> {
        DeterministicLocalWindowOwner::new(LocalFindingWindowSpecV1 {
            package_id: "HF-PROC-001".to_owned(),
            package_version: 1,
            sequence_width: 4,
        })
    }

    #[test]
    fn window_width_cannot_exceed_owner_capacity() {
        assert!(
            DeterministicLocalWindowOwner::new(LocalFindingWindowSpecV1 {
                package_id: "HF-PROC-001".to_owned(),
                package_version: 1,
                sequence_width: 4_097,
            })
            .is_err()
        );
    }

    #[test]
    fn delivery_order_and_duplicates_produce_identical_terminal_windows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let canonicalizer = canonicalizer()?;
        let coverage =
            CoverageHealthOwner::open(directory.path().join("coverage.json"), canonicalizer)?;
        coverage.sample_health(&[health(0)])?;
        let mut observations = Vec::new();
        for sequence in 1..=4 {
            let (coverage_id, temporal) = coverage.observe(0, sequence)?;
            observations.push(canonicalizer.normalize_kernel(
                EffectObservationV1 {
                    source_sequence: sequence,
                    source_cpu_id: 0,
                    task_cookie: 7,
                    reason: u8::try_from(sequence)?,
                    physical_result: 1,
                    ..EffectObservationV1::default()
                },
                coverage_id,
                temporal,
                1,
            )?);
        }
        coverage.sample_health(&[health(4)])?;
        let expected = owner()?.build(&observations, &coverage.snapshot())?;
        let mut reordered = observations.clone();
        reordered.reverse();
        reordered.push(observations[0].clone());
        let actual = owner()?.build(&reordered, &coverage.snapshot())?;
        assert_eq!(actual, expected);
        assert_eq!(actual[0].state, LocalFindingWindowStateV1::Ready);
        assert!(actual[0].supports_negative_claim());

        let partial = owner()?.build(&observations[..3], &coverage.snapshot())?;
        assert_eq!(partial[0].state, LocalFindingWindowStateV1::Open);
        assert!(!partial[0].supports_negative_claim());

        let mut wrong_interval = observations.clone();
        wrong_interval[0].coverage_interval_id = EvidenceIdV1::new(99, 100);
        wrong_interval[0] = wrong_interval[0].clone().finalize()?;
        let inconsistent = owner()?.build(&wrong_interval, &coverage.snapshot())?;
        assert_eq!(
            inconsistent[0].state,
            LocalFindingWindowStateV1::CoverageInsufficient
        );
        assert!(!inconsistent[0].supports_negative_claim());
        Ok(())
    }

    #[test]
    fn gaps_and_contradictions_have_stable_revisions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let canonicalizer = canonicalizer()?;
        let coverage =
            CoverageHealthOwner::open(directory.path().join("coverage.json"), canonicalizer)?;
        coverage.sample_health(&[health(0)])?;
        let (first_coverage, first_temporal) = coverage.observe(0, 1)?;
        let first = canonicalizer.normalize_kernel(
            EffectObservationV1 {
                source_sequence: 1,
                source_cpu_id: 0,
                task_cookie: 7,
                reason: 1,
                physical_result: 1,
                ..EffectObservationV1::default()
            },
            first_coverage,
            first_temporal,
            1,
        )?;
        let (third_coverage, third_temporal) = coverage.observe(0, 3)?;
        let third = canonicalizer.normalize_kernel(
            EffectObservationV1 {
                source_sequence: 3,
                source_cpu_id: 0,
                task_cookie: 7,
                reason: 3,
                physical_result: 1,
                ..EffectObservationV1::default()
            },
            third_coverage,
            third_temporal,
            1,
        )?;
        coverage.sample_health(&[health(3)])?;
        let gapped = owner()?.build(&[first.clone(), third], &coverage.snapshot())?;
        assert_eq!(
            gapped[0].state,
            LocalFindingWindowStateV1::CoverageInsufficient
        );
        assert!(!gapped[0].supports_negative_claim());

        let contradictory = canonicalizer.normalize_kernel(
            EffectObservationV1 {
                source_sequence: 1,
                source_cpu_id: 0,
                task_cookie: 7,
                reason: 9,
                physical_result: 1,
                ..EffectObservationV1::default()
            },
            first_coverage,
            first_temporal,
            1,
        )?;
        let first_build = owner()?.build(
            &[first.clone(), contradictory.clone()],
            &coverage.snapshot(),
        )?;
        let second_build = owner()?.build(&[contradictory, first], &coverage.snapshot())?;
        assert_eq!(first_build, second_build);
        assert_eq!(
            first_build[0].state,
            LocalFindingWindowStateV1::Contradicted
        );
        Ok(())
    }
}
