use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    time::Duration,
};

use erebor_interceptor_abi::{
    ExceptionReceiptStateV1, ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1,
    ExceptionUseReceiptV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
    TaskCoordinateV1,
};
use erebor_runtime_ipc::v1::MithrilEffectObservation;
use zerocopy::TryFromBytes as _;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

const FILES: [&str; 6] = [
    "bounded-secret",
    "expired-secret",
    "thread-ids",
    "race-result",
    "again-result",
    "expired-result",
];
const STATE_MAP: &str = "exception_runtime_states";
const COORD_MAP: &str = "task_coordinates";
type Coord = TaskCoordinateV1;
type State = ExceptionRuntimeStateV1;

#[platform_test(host)]
#[lifecycle = exception]
fn bounded_exception_is_exact<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-exact")?;
    env.start_control()?;
    env.start_node()?;
    for name in FILES {
        fs::write(env.work().join(name), b"")?;
    }
    env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["race"])?;
    let text = actor.wait_text(&env.work().join("thread-ids"), "exception worker IDs")?;
    let tids: Vec<u32> = serde_json::from_str(&text)?;
    let root = env.task(actor.id(), "exception actor identity")?;
    let mut coords = BTreeMap::new();
    for key in env.maps().1.keys(COORD_MAP)? {
        if let Some(coord) = env.state::<Coord>(COORD_MAP, &key, "task coordinate")? {
            coords.insert(coord.host_tid, coord);
        }
    }
    let mut cookies = Vec::new();
    for ns_tid in tids {
        let tid = actor.wait_thread(ns_tid, "exception worker")?;
        let coord = coords.remove(&tid).ok_or("worker identity is missing")?;
        assert_eq!(coord.process_state_id, root.coordinate.process_state_id);
        cookies.push(coord.task_cookie);
    }
    env.install_policy("bounded_exception.json")?;
    actor.send(b"race\n")?;
    let text = actor.wait_text(&env.work().join("race-result"), "exception race result")?;
    let errors: Vec<i32> = serde_json::from_str(&text)?;
    let allowed = errors.iter().filter(|&&code| code == 0).count();
    let denied = errors.iter().filter(|&&code| code == libc::EACCES).count();
    assert_eq!((errors.len(), allowed, denied), (8, 2, 6));
    let matches = |event: &MithrilEffectObservation, cookie: u64, code: i32| {
        event.task_cookie == cookie
            && event.reason
                == if code == 0 {
                    "EXACT_POLICY_ALLOW"
                } else {
                    "EXCEPTION_UNAVAILABLE"
                }
            && event.effect_family == u32::from(F::File as u16)
            && event.operation == u32::from(O::OpenWrite as u16)
            && event.active_role_id == root.snapshot.active_role_id
            && event.admitted_entry_rule_id == root.snapshot.admitted_entry_rule_id
            && event.kernel_result == -code
            && event.composite_atom_id != 0
            && event.exact_object_key_id == 0
    };
    let path = env.maps().0.to_owned();
    let last = RefCell::new(0);
    let snapshot = wait_for(
        &path,
        "bounded exception evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let found = cookies
                .iter()
                .zip(&errors)
                .filter(|(cookie, code)| {
                    snapshot
                        .recent_effects
                        .iter()
                        .any(|event| matches(event, **cookie, **code))
                })
                .count();
            *last.borrow_mut() = found;
            Ok((found == 8).then_some(snapshot))
        },
        || format!("attributed worker decisions: {} of 8", last.borrow()),
    )?;
    let mut counts = [0, 0, 0];
    let mut atom = 0;
    for event in snapshot.recent_effects.iter().filter(|event| {
        cookies.iter().any(|cookie| *cookie == event.task_cookie)
            && event.effect_family == u32::from(F::File as u16)
            && event.operation == u32::from(O::OpenWrite as u16)
            && event.composite_atom_id != 0
            && event.exact_object_key_id == 0
    }) {
        counts[match event.reason.as_str() {
            "EXACT_POLICY_ALLOW" => 0,
            "EXCEPTION_UNAVAILABLE" => 1,
            _ => 2,
        }] += 1;
        assert!(atom == 0 || atom == event.composite_atom_id);
        atom = event.composite_atom_id;
    }
    assert_eq!(counts, [2, 6, 0]);
    assert_ne!(atom, 0);
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}

#[platform_test(host)]
#[lifecycle = exception]
fn exhaustion_survives_restart<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-restart")?;
    env.start_control()?;
    env.start_node()?;
    for name in FILES {
        fs::write(env.work().join(name), b"")?;
    }
    env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["race"])?;
    let old: BTreeSet<_> = env.maps().1.keys(STATE_MAP)?.into_iter().collect();
    env.install_policy("restart_exception.json")?;
    let keys = env.maps().1.keys(STATE_MAP)?;
    let new: Vec<_> = keys.iter().filter(|key| !old.contains(*key)).collect();
    assert_eq!(new.len(), 1);
    let key = new[0];
    actor.send(b"race\n")?;
    let text = actor.wait_text(&env.work().join("race-result"), "exception race result")?;
    let errors: Vec<i32> = serde_json::from_str(&text)?;
    assert_eq!(errors.iter().filter(|&&code| code == 0).count(), 2);
    assert_eq!(
        errors.iter().filter(|&&code| code == libc::EACCES).count(),
        6
    );
    let before = env
        .state::<State>(STATE_MAP, key, "exception state")?
        .ok_or("the exception state is missing")?;
    assert_eq!(before.maximum_uses, 2);
    assert_eq!(before.consumed_uses, 2);
    assert_eq!(before.state, ExceptionRuntimeStateKindV1::Exhausted);

    let mut ordinals = Vec::new();
    let reader = env.maps().1;
    for receipt_key in reader
        .keys("exception_use_receipts")?
        .into_iter()
        .filter(|receipt_key| receipt_key.starts_with(key))
    {
        let bytes = reader
            .lookup("exception_use_receipts", &receipt_key)?
            .ok_or("the exception receipt is missing")?;
        let receipt = ExceptionUseReceiptV1::try_read_from_bytes(&bytes)
            .map_err(|source| format!("the exception receipt is invalid: {source}"))?;
        assert_eq!(receipt.state, ExceptionReceiptStateV1::Consumed);
        ordinals.push(receipt.consumed_ordinal);
    }
    ordinals.sort_unstable();
    assert_eq!(ordinals, [1, 2]);
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    let task = env.task(actor.id(), "post-restart actor identity")?;
    let after = env
        .state::<State>(STATE_MAP, key, "exception state")?
        .ok_or("the recovered exception state is missing")?;
    assert_eq!(after, before);
    actor.send(b"again\n")?;
    let text = actor.wait_text(&env.work().join("again-result"), "post-restart result")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);
    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "post-restart exception evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            Ok(snapshot.recent_effects.into_iter().find(|event| {
                task.matches_effect(
                    event,
                    "EXCEPTION_UNAVAILABLE",
                    F::File,
                    O::OpenWrite,
                    -libc::EACCES,
                ) && event.composite_atom_id != 0
                    && event.exact_object_key_id == 0
            }))
        },
        || "no attributed post-restart denial observed".to_owned(),
    )?;
    assert_eq!(
        env.state::<State>(STATE_MAP, key, "exception state")?,
        Some(before)
    );
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}

#[platform_test(host)]
#[lifecycle = exception]
fn unused_exception_expires<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-expiry")?;
    env.start_control()?;
    env.start_node()?;
    for name in FILES {
        fs::write(env.work().join(name), b"")?;
    }
    env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["expired"])?;
    let task = env.task(actor.id(), "exception actor identity")?;
    let old: BTreeSet<_> = env.maps().1.keys(STATE_MAP)?.into_iter().collect();
    env.install_policy("expired_exception.json")?;
    let keys = env.maps().1.keys(STATE_MAP)?;
    let new: Vec<_> = keys.iter().filter(|key| !old.contains(*key)).collect();
    assert_eq!(new.len(), 1);
    let key = new[0];
    let active = env
        .state::<State>(STATE_MAP, key, "exception state")?
        .ok_or("the exception state is missing")?;
    assert_eq!(active.maximum_uses, 1);
    assert_eq!(active.consumed_uses, 0);
    assert_eq!(active.transition_version, 1);
    assert_eq!(active.state, ExceptionRuntimeStateKindV1::Active);

    let deadline = active.deadline_boottime_ns;
    wait_for(
        env.maps().0,
        "exception deadline",
        Duration::from_secs(12),
        || {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            let seconds = u64::try_from(now.tv_sec).unwrap_or(u64::MAX);
            let nanos = seconds
                .saturating_mul(1_000_000_000)
                .saturating_add(u64::try_from(now.tv_nsec).unwrap_or_default());
            Ok((nanos > deadline).then_some(()))
        },
        || format!("deadline: {deadline}"),
    )?;

    actor.send(b"expired\n")?;
    let text = actor.wait_text(&env.work().join("expired-result"), "expired result")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);
    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "expired exception evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            Ok(snapshot.recent_effects.into_iter().find(|event| {
                task.matches_effect(
                    event,
                    "EXCEPTION_UNAVAILABLE",
                    F::File,
                    O::OpenWrite,
                    -libc::EACCES,
                ) && event.composite_atom_id != 0
                    && event.exact_object_key_id == 0
            }))
        },
        || "no attributed expiry denial observed".to_owned(),
    )?;
    let expired = env
        .state::<State>(STATE_MAP, key, "exception state")?
        .ok_or("the expired exception state is missing")?;
    assert_eq!(expired.maximum_uses, 1);
    assert_eq!(expired.consumed_uses, 0);
    assert_eq!(expired.transition_version, 2);
    assert_eq!(expired.state, ExceptionRuntimeStateKindV1::Expired);
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
