use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use super::lifetime_result::LifetimeState;
use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn running_task_uses_new_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("policy-replace")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_recovery.py", &[])?;
    let root = env.task(actor.id(), "initial policy identity")?;
    let old = root.snapshot.profile_generation_ref_id;
    let refs = LifetimeState::profile_refs(&env, &root)?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let held = env.task(actor.id(), "retained policy identity")?;
    assert_eq!(held.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(held.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(
        held.snapshot.admitted_entry_rule_id,
        root.snapshot.admitted_entry_rule_id
    );
    assert_eq!(held.snapshot.profile_generation_ref_id, old);
    assert_eq!(LifetimeState::profile_refs(&env, &root)?, refs);

    let mut entry = env.add_actor("cat", &[])?;
    let next = env.task(entry.id(), "replacement policy entry")?;
    assert!(next.snapshot.profile_generation_ref_id > old);
    actor.send(b"effect\n")?;
    assert_eq!(
        env.actor_code(&mut actor, "replacement effect", Duration::from_secs(5))?,
        1
    );

    let exec = u32::from(KernelEffectFamilyV1::Exec as u16);
    let op = u32::from(KernelEffectOperationV1::Execute as u16);
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let event = wait_for(
        &path,
        "replacement effect evidence",
        Duration::from_secs(30),
        || {
            let events = env
                .snapshot()
                .map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?
                .recent_effects;
            *last.borrow_mut() = format!("{:?}", events.iter().rev().take(16).collect::<Vec<_>>());
            Ok(events.into_iter().find(|event| {
                !seen.contains(&(event.source_cpu_id, event.source_sequence))
                    && event.reason == "APPLICATION_DEFAULT_ALLOW"
                    && event.effect_family == exec
                    && event.operation == op
                    && event.profile_generation_ref_id > old
                    && event.task_cookie != root.snapshot.task_cookie
                    && event.active_role_id == root.snapshot.active_role_id
                    && event.admitted_entry_rule_id == root.snapshot.admitted_entry_rule_id
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(
        event.profile_generation_ref_id,
        next.snapshot.profile_generation_ref_id
    );

    entry.stop()?;
    actor.stop()?;
    env.stop()
}
