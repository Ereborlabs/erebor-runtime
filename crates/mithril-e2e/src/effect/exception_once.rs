use std::{cell::Cell, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use erebor_runtime_ipc::v1::MithrilEffectObservation as Effect;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = exception]
fn one_use_after_replace<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-once")?;
    env.start_control()?;
    env.start_node()?;
    let secret = env.work().join("expired-secret");
    fs::write(&secret, b"")?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["single"])?;
    let initial = env.task(actor.id(), "initial exception actor")?;
    let old = initial.snapshot.profile_generation_ref_id;

    env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let held = env.task(actor.id(), "held exception actor")?;
    assert_eq!(held.snapshot.task_cookie, initial.snapshot.task_cookie);
    assert_eq!(held.snapshot.profile_generation_ref_id, old);
    actor.send(b"before\n")?;
    let text = actor.wait_text(&env.work().join("expired-result"), "ungranted open")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);
    let active = env.task(actor.id(), "replacement exception actor")?;
    assert_eq!(active.snapshot.task_cookie, initial.snapshot.task_cookie);
    assert_eq!(
        active.snapshot.process_state_id,
        initial.snapshot.process_state_id
    );

    env.install_policy("one_use_exception.json")?;
    actor.send(b"first\n")?;
    let text = actor.wait_text(&env.work().join("again-result"), "one allowed open")?;
    assert_eq!(text.trim().parse::<i32>()?, 0);
    actor.send(b"second\n")?;
    let text = actor.wait_text(&env.work().join("race-result"), "exhausted open")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);

    let path = env.maps().0.to_owned();
    let last = Cell::new((0, 0, 0));
    wait_for(
        &path,
        "one-use exception evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let matches = |event: &Effect, reason: &str, result: i32| {
                active.matches_effect(event, reason, F::File, O::OpenWrite, result)
            };
            let atom = snapshot
                .recent_effects
                .iter()
                .find(|event| {
                    matches(event, "EXCEPTION_UNAVAILABLE", -libc::EACCES)
                        && event.profile_generation_ref_id > old
                        && event.composite_atom_id != 0
                })
                .map_or(0, |event| event.composite_atom_id);
            let effects = snapshot.recent_effects.iter().filter(|event| {
                event.composite_atom_id == atom
                    && atom != 0
                    && event.profile_generation_ref_id > old
                    && event.exact_object_key_id == 0
            });
            let mut allowed = 0;
            let mut denied = 0;
            for event in effects {
                allowed += usize::from(matches(event, "EXACT_POLICY_ALLOW", 0));
                denied += usize::from(matches(event, "EXCEPTION_UNAVAILABLE", -libc::EACCES));
            }
            last.set((atom, allowed, denied));
            Ok((atom != 0 && allowed == 1 && denied >= 2).then_some(()))
        },
        || format!("secret atom, allow, and deny counts: {:?}", last.get()),
    )?;

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
