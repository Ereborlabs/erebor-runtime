use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn denied_read_is_observed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-observe")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["read"])?;
    let task = env.task(actor.id(), "Observe file actor")?;
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let cookie = task.snapshot.task_cookie;
    let entry = task.snapshot.entry_instance_id;
    let gen = task.snapshot.profile_generation_ref_id;
    env.install_policy("file_observe.json")?;
    env.node_ready()?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"read\n")?;
    let text = actor.wait_text(&env.work().join("expired-result"), "observed read")?;
    assert_eq!(text.trim().parse::<i32>()?, 0);
    let last = RefCell::new(Vec::new());
    let event = wait_for(
        env.maps().0,
        "Observe-mode secret open",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: env.maps().0,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let fresh = snapshot
                .recent_effects
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            *last.borrow_mut() = fresh
                .iter()
                .rev()
                .take(8)
                .map(|event| (event.reason.clone(), event.task_cookie, event.operation))
                .collect();
            Ok(fresh.into_iter().find(|event| {
                event.task_cookie == cookie
                    && event.reason == "WOULD_DENY"
                    && event.effect_family == F::File as u32
                    && event.operation == O::OpenRead as u32
                    && event.kernel_result == 0
            }))
        },
        || format!("last new effects: {:?}", last.borrow()),
    )?;
    assert_eq!(event.entry_instance_id, entry);
    assert_ne!(event.profile_generation_ref_id, gen);
    assert_ne!(event.active_role_id, 0);
    assert_ne!(event.admitted_entry_rule_id, 0);
    assert_ne!(event.exact_object_key_id, 0);
    assert_ne!(event.composite_atom_id, 0);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
