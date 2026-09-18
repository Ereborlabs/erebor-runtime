use std::{cell::RefCell, collections::BTreeSet, os::unix::fs::MetadataExt, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = mount_alias]
fn future_mount_namespace_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-future")?;
    env.start_control()?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;

    let host_ns = std::fs::metadata("/proc/self/ns/mnt")?.ino();
    let mut actor = env.start_actor("mount_alias.py", &["future"])?;
    let pid = actor.id();
    let task = env.task(pid, "future namespace actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("future namespace read", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    let actor_ns = result["mount_namespace"]
        .as_u64()
        .ok_or("the actor mount namespace inode is missing")?;
    assert_ne!(actor_ns, host_ns);
    assert_eq!(result["mount"], libc::EACCES);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "future namespace effects",
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
                    task.matches_effect(event, reason, F::File, O::OpenRead, result)
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
