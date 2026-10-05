use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectPhysicalResultV1, KernelEffectFamilyV1,
    KernelEffectOperationV1,
};
use erebor_runtime_ipc::v1::{MithrilEffectObservation, MithrilObservationSnapshot};
use zerocopy::FromBytes as _;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{Platform, Task, TestResult};

pub(crate) struct EffectCheck {
    task: Task,
    seen: BTreeSet<(u32, u64)>,
}

impl EffectCheck {
    pub(crate) fn new<P: Platform>(env: &P, task: Task) -> TestResult<Self> {
        let seen = env
            .snapshot()?
            .recent_effects
            .into_iter()
            .map(|event| (event.source_cpu_id, event.source_sequence))
            .collect();
        Ok(Self { task, seen })
    }

    fn fresh(&self, event: &MithrilEffectObservation) -> bool {
        !self
            .seen
            .contains(&(event.source_cpu_id, event.source_sequence))
    }

    pub(crate) fn capture<P: Platform + Sync, T>(
        &self,
        env: &P,
        action: impl FnOnce() -> TestResult<T>,
    ) -> TestResult<(T, Vec<MithrilEffectObservation>)> {
        let (end, ended) =
            mpsc::channel::<Result<(Vec<EffectObservationHealthV1>, Instant), String>>();
        let (ready, started) = mpsc::sync_channel(1);
        thread::scope(move |scope| {
            let capture = scope.spawn(move || -> Result<_, String> {
                let mut events = BTreeMap::new();
                let snapshot = env.snapshot().map_err(|error| error.to_string())?;
                let faults = Self::faults(&snapshot);
                let opening = Self::health(env)?;
                let mut health = opening.clone();
                ready.send(()).map_err(|error| error.to_string())?;
                let mut closing: Option<(Vec<EffectObservationHealthV1>, Instant)> = None;
                let mut failure = None;
                loop {
                    let snapshot = env.snapshot().map_err(|error| error.to_string())?;
                    if Self::faults(&snapshot) != faults {
                        failure.get_or_insert_with(|| {
                            format!(
                                "effect capture reader faults: {faults:?} -> {:?}",
                                Self::faults(&snapshot)
                            )
                        });
                    }
                    for event in snapshot.recent_effects {
                        events.insert((event.source_cpu_id, event.source_sequence), event);
                    }
                    let current = Self::health(env)?;
                    if let Err(error) = Self::check_health(&health, &current) {
                        failure.get_or_insert(error);
                    }
                    if let Some((target, deadline)) = &closing {
                        if let Err(error) = Self::check_health(target, &current) {
                            failure.get_or_insert(error);
                        }
                        let delivered = Self::progress(
                            &opening,
                            events.keys().copied().filter(|(cpu, sequence)| {
                                target
                                    .get(*cpu as usize)
                                    .is_none_or(|cpu| *sequence <= cpu.next_sequence)
                            }),
                        );
                        if delivered
                            .as_ref()
                            .is_ok_and(|last| Self::complete(last, target))
                        {
                            return Self::captured(&opening, target, events, failure);
                        }
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            let timeout = format!(
                                "effect capture delivery timeout: delivered={delivered:?}, \
                                 closing={target:?}, current={current:?}"
                            );
                            let error = failure.map_or_else(
                                || timeout.clone(),
                                |error| format!("{error}; {timeout}"),
                            );
                            return Self::captured(&opening, target, events, Some(error));
                        }
                    }
                    health = current;
                    match ended.try_recv() {
                        Ok(boundary) => {
                            let (target, deadline) = boundary?;
                            if let Err(error) = Self::check_health(&opening, &target) {
                                failure.get_or_insert(error);
                            }
                            closing = Some((target, deadline));
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(error) => return Err(format!("effect capture end boundary: {error}")),
                    }
                }
            });
            let result = match started.recv_timeout(Duration::from_secs(30)) {
                Ok(()) => action(),
                Err(error) => Err(format!(
                    "{}: effect capture readiness: {error}",
                    env.maps().0.display()
                )
                .into()),
            };
            let closing =
                Self::health(env).map(|health| (health, Instant::now() + Duration::from_secs(30)));
            let sent = end.send(closing);
            let events = capture
                .join()
                .map_err(|_| "effect capture panicked")?
                .map_err(|error| format!("{}: {error}", env.maps().0.display()))?;
            sent.map_err(|error| format!("effect capture end boundary: {error}"))?;
            Ok((result?, events))
        })
    }

    fn captured(
        opening: &[EffectObservationHealthV1],
        closing: &[EffectObservationHealthV1],
        events: BTreeMap<(u32, u64), MithrilEffectObservation>,
        mut failure: Option<String>,
    ) -> Result<Vec<MithrilEffectObservation>, String> {
        let events = events
            .into_iter()
            .filter(|((cpu, sequence), _)| {
                opening
                    .get(*cpu as usize)
                    .is_some_and(|cpu| *sequence > cpu.next_sequence)
                    && closing
                        .get(*cpu as usize)
                        .is_some_and(|cpu| *sequence <= cpu.next_sequence)
            })
            .collect::<BTreeMap<_, _>>();
        if failure.is_none() {
            failure = Self::check_reasons(opening, closing, events.values()).err();
        }
        if let Some(error) = failure {
            let hard = events
                .values()
                .filter(|event| {
                    matches!(
                        event.reason.as_str(),
                        "UNRESOLVED_OBJECT" | "UNSUPPORTED_OBJECT"
                    )
                })
                .map(|event| {
                    (
                        event.source_cpu_id,
                        event.source_sequence,
                        &event.reason,
                        event.kernel_result,
                    )
                })
                .collect::<Vec<_>>();
            return Err(format!(
                "{error}; captured hard results (CPU, sequence, reason, result): {hard:?}"
            ));
        }
        Ok(events.into_values().collect())
    }

    fn faults(snapshot: &MithrilObservationSnapshot) -> [u64; 4] {
        [
            snapshot.decoder_errors,
            snapshot.evidence_errors,
            snapshot.wal_capacity_blocked,
            snapshot.reader_queue_dropped_events,
        ]
    }

    fn health<P: Platform>(env: &P) -> Result<Vec<EffectObservationHealthV1>, String> {
        let bytes = env
            .maps()
            .1
            .lookup("effect_observation_health", &0u32.to_ne_bytes())
            .map_err(|error| error.to_string())?
            .ok_or("effect capture health is missing")?;
        Self::decode_health(&bytes)
    }

    fn decode_health(bytes: &[u8]) -> Result<Vec<EffectObservationHealthV1>, String> {
        let width = size_of::<EffectObservationHealthV1>();
        if bytes.is_empty() || !bytes.len().is_multiple_of(width) {
            return Err(format!(
                "invalid effect capture health length: {}",
                bytes.len()
            ));
        }
        bytes
            .chunks_exact(width)
            .map(|chunk| {
                EffectObservationHealthV1::read_from_bytes(chunk).map_err(|error| error.to_string())
            })
            .collect()
    }

    fn check_health(
        opening: &[EffectObservationHealthV1],
        current: &[EffectObservationHealthV1],
    ) -> Result<(), String> {
        if opening.len() != current.len() {
            return Err("effect capture CPU count changed".into());
        }
        for (cpu, (before, after)) in opening.iter().zip(current).enumerate() {
            if after.attempted < before.attempted
                || after.suppressed < before.suppressed
                || after.requested < before.requested
                || after.emitted < before.emitted
                || after.next_sequence < before.next_sequence
                || after.lost != before.lost
                || after.classifier_miss_count < before.classifier_miss_count
                || after.unresolved < before.unresolved
            {
                return Err(format!(
                    "effect capture health changed on CPU {cpu}: {before:?} -> {after:?}"
                ));
            }
        }
        Ok(())
    }

    fn progress(
        opening: &[EffectObservationHealthV1],
        sequences: impl IntoIterator<Item = (u32, u64)>,
    ) -> Result<Vec<u64>, String> {
        let mut delivered = opening
            .iter()
            .map(|cpu| cpu.next_sequence)
            .collect::<Vec<_>>();
        for (cpu, sequence) in sequences {
            let last = delivered
                .get_mut(cpu as usize)
                .ok_or_else(|| format!("effect capture has unknown CPU {cpu}"))?;
            if sequence <= *last {
                continue;
            }
            if last.checked_add(1) != Some(sequence) {
                return Err(format!(
                    "effect capture gap on CPU {cpu}: {last} -> {sequence}"
                ));
            }
            *last = sequence;
        }
        Ok(delivered)
    }

    fn check_reasons<'a>(
        opening: &[EffectObservationHealthV1],
        closing: &[EffectObservationHealthV1],
        events: impl IntoIterator<Item = &'a MithrilEffectObservation>,
    ) -> Result<(), String> {
        Self::check_health(opening, closing)?;
        let mut counts = vec![0_u64; opening.len()];
        for event in events {
            if event.physical_result_code == EffectPhysicalResultV1::DeniedBeforeEffect as u32
                && matches!(
                    event.reason.as_str(),
                    "UNRESOLVED_OBJECT" | "UNSUPPORTED_OBJECT"
                )
            {
                let count = counts
                    .get_mut(event.source_cpu_id as usize)
                    .ok_or_else(|| {
                        format!("effect capture has unknown CPU {}", event.source_cpu_id)
                    })?;
                *count += 1;
            }
        }
        for (cpu, ((before, after), count)) in opening.iter().zip(closing).zip(counts).enumerate() {
            if after.unresolved.checked_sub(before.unresolved) != Some(count)
                || after
                    .classifier_miss_count
                    .checked_sub(before.classifier_miss_count)
                    != Some(count)
            {
                return Err(format!(
                    "effect capture reason accounting changed on CPU {cpu}: \
                     {before:?} -> {after:?}; captured misses={count}"
                ));
            }
        }
        Ok(())
    }

    fn complete(delivered: &[u64], closing: &[EffectObservationHealthV1]) -> bool {
        delivered.len() == closing.len()
            && delivered
                .iter()
                .zip(closing)
                .all(|(sequence, cpu)| *sequence >= cpu.next_sequence)
    }

    pub(crate) fn wait<P: Platform>(
        &self,
        env: &P,
        reason: &str,
        family: KernelEffectFamilyV1,
        operation: KernelEffectOperationV1,
        result: i32,
        name: &str,
    ) -> TestResult<MithrilEffectObservation> {
        Ok(self
            .wait_many(env, reason, (family, operation), result, 1, name)?
            .remove(0))
    }

    pub(super) fn wait_many<P: Platform>(
        &self,
        env: &P,
        reason: &str,
        effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
        result: i32,
        count: usize,
        name: &str,
    ) -> TestResult<Vec<MithrilEffectObservation>> {
        self.wait_where(env, count, name, |event| {
            self.task
                .matches_effect(event, reason, effect.0, effect.1, result)
        })
    }

    pub(crate) fn wait_match<P: Platform>(
        &self,
        env: &P,
        name: &str,
        check: impl Fn(&MithrilEffectObservation) -> bool,
    ) -> TestResult<MithrilEffectObservation> {
        Ok(self.wait_where(env, 1, name, check)?.remove(0))
    }

    fn wait_where<P: Platform>(
        &self,
        env: &P,
        count: usize,
        name: &str,
        check: impl Fn(&MithrilEffectObservation) -> bool,
    ) -> TestResult<Vec<MithrilEffectObservation>> {
        assert!(count > 0);
        let path = env.maps().0.to_owned();
        let last = RefCell::new(Vec::new());
        Ok(wait_for(
            &path,
            name,
            Duration::from_secs(30),
            || {
                let snapshot = env.snapshot().map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                let fresh = snapshot
                    .recent_effects
                    .into_iter()
                    .filter(|event| self.fresh(event))
                    .collect::<Vec<_>>();
                *last.borrow_mut() = fresh
                    .iter()
                    .rev()
                    .take(8)
                    .map(|event| {
                        (
                            event.reason.clone(),
                            event.effect_family,
                            event.operation,
                            event.kernel_result,
                            event.task_cookie,
                            event.active_role_id,
                            event.admitted_entry_rule_id,
                            event.profile_generation_ref_id,
                            event.composite_atom_id,
                            event.exact_object_key_id,
                        )
                    })
                    .collect();
                let matched = fresh
                    .into_iter()
                    .filter(|event| check(event))
                    .collect::<Vec<_>>();
                Ok((matched.len() >= count).then_some(matched))
            },
            || format!("last new effects: {:?}", last.borrow()),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes as _;

    use super::*;

    #[test]
    fn capture_checks_each_cpu() -> Result<(), String> {
        let opening = vec![EffectObservationHealthV1::default(); 2];
        let closing = vec![
            EffectObservationHealthV1 {
                next_sequence: 2,
                ..Default::default()
            },
            EffectObservationHealthV1 {
                next_sequence: 1,
                ..Default::default()
            },
        ];
        assert!(EffectCheck::check_health(&opening, &closing).is_ok());
        let delivered = EffectCheck::progress(&opening, [(0, 1), (1, 1)])?;
        assert!(!EffectCheck::complete(&delivered, &closing));
        let delivered = EffectCheck::progress(&opening, [(0, 1), (0, 2), (1, 1)])?;
        assert!(EffectCheck::complete(&delivered, &closing));
        assert!(EffectCheck::progress(&opening, [(1, 2)]).is_err());
        assert!(EffectCheck::progress(&opening, [(0, 1), (0, 3)]).is_err());
        assert!(EffectCheck::progress(&opening, [(2, 1)]).is_err());

        let opening = vec![EffectObservationHealthV1 {
            next_sequence: 4,
            ..Default::default()
        }];
        assert_eq!(EffectCheck::progress(&opening, [(0, 4)])?, [4]);
        assert_eq!(EffectCheck::progress(&opening, [(0, 2), (0, 5)])?, [5]);
        assert!(EffectCheck::progress(&opening, [(0, 6)]).is_err());

        let bytes = closing.as_slice().as_bytes();
        assert_eq!(EffectCheck::decode_health(bytes)?, closing);
        assert!(EffectCheck::decode_health(&[]).is_err());
        assert!(EffectCheck::decode_health(&bytes[..bytes.len() - 1]).is_err());
        assert!(EffectCheck::check_health(
            &[EffectObservationHealthV1::default()],
            &[EffectObservationHealthV1 {
                lost: 1,
                ..Default::default()
            }]
        )
        .is_err());
        for after in [
            EffectObservationHealthV1 {
                unresolved: 1,
                ..Default::default()
            },
            EffectObservationHealthV1 {
                classifier_miss_count: 1,
                ..Default::default()
            },
        ] {
            assert!(
                EffectCheck::check_health(&[EffectObservationHealthV1::default()], &[after])
                    .is_ok()
            );
        }
        assert!(EffectCheck::check_health(&closing, &[]).is_err());
        assert!(
            EffectCheck::check_health(&closing, &[EffectObservationHealthV1::default(); 2])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn capture_keeps_failure() -> Result<(), String> {
        let before = [EffectObservationHealthV1::default()];
        let after = [EffectObservationHealthV1 {
            lost: 1,
            classifier_miss_count: 2,
            unresolved: 2,
            next_sequence: 2,
            ..Default::default()
        }];
        let failure = EffectCheck::check_health(&before, &after)
            .err()
            .ok_or("the source fault was accepted")?;
        EffectCheck::check_health(&after, &after)?;
        let events = ["UNRESOLVED_OBJECT", "UNSUPPORTED_OBJECT"]
            .into_iter()
            .enumerate()
            .map(|(index, reason)| {
                let sequence = index as u64 + 1;
                (
                    (0, sequence),
                    MithrilEffectObservation {
                        reason: reason.into(),
                        source_sequence: sequence,
                        physical_result_code: EffectPhysicalResultV1::DeniedBeforeEffect as u32,
                        ..Default::default()
                    },
                )
            })
            .collect();
        let error = match EffectCheck::captured(&before, &after, events, Some(failure)) {
            Err(error) => error,
            Ok(_) => return Err("diagnostic drain discarded the source fault".into()),
        };
        assert!(error.contains("effect capture health changed"));
        assert!(error.contains("UNRESOLVED_OBJECT"));
        assert!(error.contains("UNSUPPORTED_OBJECT"));
        Ok(())
    }

    #[test]
    fn capture_bounds_and_reasons() -> Result<(), String> {
        let opening = [EffectObservationHealthV1 {
            next_sequence: 4,
            unresolved: 1,
            classifier_miss_count: 1,
            ..Default::default()
        }];
        let closing = [EffectObservationHealthV1 {
            next_sequence: 5,
            unresolved: 2,
            classifier_miss_count: 2,
            ..Default::default()
        }];
        for reason in ["UNSUPPORTED_OBJECT", "UNRESOLVED_OBJECT"] {
            let events = [
                (2, "UNRESOLVED_OBJECT"),
                (4, "UNRESOLVED_OBJECT"),
                (5, reason),
                (6, "UNRESOLVED_OBJECT"),
            ]
            .into_iter()
            .map(|(sequence, reason)| {
                (
                    (0, sequence),
                    MithrilEffectObservation {
                        reason: reason.into(),
                        source_sequence: sequence,
                        physical_result_code: EffectPhysicalResultV1::DeniedBeforeEffect as u32,
                        ..Default::default()
                    },
                )
            })
            .collect();
            let events = EffectCheck::captured(&opening, &closing, events, None)?;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].source_sequence, 5);
            assert_eq!(events[0].reason, reason);
            assert_eq!(
                events
                    .iter()
                    .all(|event| event.reason != "UNRESOLVED_OBJECT"),
                reason == "UNSUPPORTED_OBJECT"
            );
            assert!(EffectCheck::check_reasons(&opening, &closing, []).is_err());
            let mut changed = closing;
            changed[0].classifier_miss_count += 1;
            assert!(EffectCheck::check_reasons(&opening, &changed, &events).is_err());
            changed = closing;
            changed[0].unresolved += 1;
            assert!(EffectCheck::check_reasons(&opening, &changed, &events).is_err());
        }
        let closing = [EffectObservationHealthV1 {
            next_sequence: 5,
            ..opening[0]
        }];
        let event = MithrilEffectObservation {
            reason: "UNRESOLVED_OBJECT".into(),
            source_sequence: 5,
            physical_result_code: EffectPhysicalResultV1::PacketDroppedAfterRewrite as u32,
            ..Default::default()
        };
        let events =
            EffectCheck::captured(&opening, &closing, BTreeMap::from([((0, 5), event)]), None)?;
        assert_eq!(events[0].reason, "UNRESOLVED_OBJECT");
        Ok(())
    }
}
