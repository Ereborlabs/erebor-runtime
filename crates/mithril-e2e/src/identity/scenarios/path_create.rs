use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = mount_late]
fn protected_child_create_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("path-create")?;
    env.start_control()?;
    let mut actor = env.start_actor("path_wildcards.py", &["deny-create"])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("path_wildcards_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let task = env.recovered(pid, "create actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"create\n")?;
    actor.close();
    let status = actor.wait_exit("protected child create", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("wildcard-result.json"))?)?;
    assert_eq!(result["created"], libc::EACCES);
    assert!(!env
        .work()
        .join("wildcard/create-denied/actor-created")
        .exists());
    assert_eq!(result["allowed"], "allowed control\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "create effects",
        Duration::from_secs(30),
        || {
            let events = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let fresh = events
                .recent_effects
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            *last.borrow_mut() = format!("{:?}", fresh.iter().rev().take(8));
            let matches = |reason: &str, operation, result| {
                fresh
                    .iter()
                    .any(|event| task.matches_effect(event, reason, F::File, operation, result))
            };
            Ok((matches("PATH_TREE_POLICY_DENY", O::Create, -libc::EACCES)
                && matches("EXACT_POLICY_ALLOW", O::OpenRead, 0))
            .then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    env.stop()
}
