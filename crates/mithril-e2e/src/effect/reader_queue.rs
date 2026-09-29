use std::{cell::RefCell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn reader_burst_keeps_events<P: Platform>() -> TestResult<()> {
    const COUNT: u64 = 70_000;

    let mut env = P::setup("reader-queue")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    fs::write(env.work().join("application.denied"), b"deny\n")?;
    let mut actor = env.start_actor("runtime_exec.py", &[], &labels)?;
    let task = env.task(actor.id(), "reader-queue actor")?;
    let before = env.snapshot()?;

    actor.send(format!("burst {COUNT}\n").as_bytes())?;
    let result = actor.wait_text(&env.work().join("burst"), "effect burst")?;
    assert_eq!(result.trim(), COUNT.to_string());

    let pin = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let snapshot = || {
        env.snapshot().map_err(|source| {
            InvalidInputSnafu {
                path: &pin,
                reason: source.to_string(),
            }
            .build()
        })
    };
    let drained = wait_for(
        &pin,
        "reader queue drain",
        Duration::from_secs(30),
        || {
            let state = snapshot()?;
            *last.borrow_mut() = format!(
                "attempted={}; pending={}; dropped={}",
                state.attempted_effects,
                state.pending_evidence_records,
                state.reader_queue_dropped_events,
            );
            Ok((state.attempted_effects >= before.attempted_effects + COUNT
                && state.pending_evidence_records == 0)
                .then_some(state))
        },
        || last.borrow().clone(),
    )?;
    let seen = drained
        .recent_effects
        .iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"exec\n")?;
    let result = actor.wait_text(&env.work().join("exec"), "post-drain exec")?;
    assert_eq!(result.trim(), "allowed");
    let after = wait_for(
        &pin,
        "post-drain exec evidence",
        Duration::from_secs(30),
        || {
            let state = snapshot()?;
            Ok(state
                .recent_effects
                .iter()
                .any(|event| {
                    !seen.contains(&(event.source_cpu_id, event.source_sequence))
                        && event.reason == "APPLICATION_DEFAULT_ALLOW"
                        && event.effect_family == u32::from(F::Exec as u16)
                        && event.operation == u32::from(O::Execute as u16)
                        && event.active_role_id == task.snapshot.active_role_id
                        && event.admitted_entry_rule_id == task.snapshot.admitted_entry_rule_id
                        && event.kernel_result == 0
                })
                .then_some(state))
        },
        || "no matching application exec".to_owned(),
    )?;
    assert_eq!(
        after.reader_queue_dropped_events,
        before.reader_queue_dropped_events
    );
    assert_eq!(after.lost_effects, before.lost_effects);
    assert_eq!(after.decoder_errors, before.decoder_errors);
    assert_eq!(after.evidence_errors, before.evidence_errors);
    assert_eq!(after.wal_capacity_blocked, before.wal_capacity_blocked);

    actor.stop()?;
    env.stop()
}
