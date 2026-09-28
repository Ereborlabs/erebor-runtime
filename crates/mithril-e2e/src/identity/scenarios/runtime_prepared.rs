use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn prepared_start_emits_effect<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-prepared")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    let mut actor = env.start_actor("runtime_exec.py", &[], &labels)?;
    let task = env.task(actor.id(), "prepared application")?;
    let binding = task
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("the prepared actor has no runtime binding")?;
    assert_eq!(binding.lifecycle_state, "active");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let event = wait_for(
        &path,
        "prepared runtime effect",
        Duration::from_secs(30),
        || {
            let effects = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            *last.borrow_mut() = format!("{:?}", effects.recent_effects.iter().rev().take(8));
            Ok(effects.recent_effects.into_iter().find(|event| {
                !seen.contains(&(event.source_cpu_id, event.source_sequence))
                    && event.reason == "PREPARED_RUNTIME_INFRASTRUCTURE"
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(event.reason, "PREPARED_RUNTIME_INFRASTRUCTURE");

    actor.stop()?;
    env.stop()
}
