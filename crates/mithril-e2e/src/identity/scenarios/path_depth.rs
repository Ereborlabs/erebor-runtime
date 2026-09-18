use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O, MAX_CANONICAL_PATH_COMPONENTS_V1,
};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = mount_late]
fn maximum_depth_child_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("path-depth")?;
    env.start_control()?;
    let mut actor = env.start_actor("path_wildcards.py", &["max-depth"])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("path_wildcards_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let task = env.recovered(pid, "maximum-depth actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("maximum-depth read", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("wildcard-result.json"))?)?;
    assert_eq!(
        result["floor_components"],
        MAX_CANONICAL_PATH_COMPONENTS_V1 - 1
    );
    assert_eq!(result["components"], MAX_CANONICAL_PATH_COMPONENTS_V1);
    assert_eq!(result["depth"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed control\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "maximum-depth effects",
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
                fresh
                    .iter()
                    .any(|event| task.matches_effect(event, reason, F::File, O::OpenRead, result))
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
