use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_alias]
fn preexisting_bind_keeps_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-alias")?;
    env.start_control()?;
    let mut actor = env.start_actor("mount_alias.py", &[])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let task = env.recovered(pid, "bind mount actor")?;
    let binding = task
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("the bind mount actor has no runtime binding")?;
    assert_eq!(binding.lifecycle_state, "active_recovered");
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("bind alias reads", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "{status}; stderr: {stderr:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "bind alias effects",
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
            let matches = |reason: &str, result| {
                fresh.iter().any(|event| {
                    task.matches_effect(
                        event,
                        reason,
                        KernelEffectFamilyV1::File,
                        KernelEffectOperationV1::OpenRead,
                        result,
                    )
                })
            };
            Ok((matches("PATH_TREE_POLICY_DENY", -libc::EACCES)
                && matches("EXACT_POLICY_ALLOW", 0))
            .then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    env.stop()
}
