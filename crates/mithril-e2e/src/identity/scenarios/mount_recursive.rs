use std::{cell::RefCell, collections::BTreeSet, os::unix::fs::MetadataExt as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use snafu::ResultExt as _;

use crate::error::{InterceptorSnafu, InvalidInputSnafu};
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = mount_late]
fn recursive_bind_keeps_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-recursive")?;
    env.start_control()?;
    let mut actor = env.start_actor("mount_alias.py", &["recursive"])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let task = env.recovered(pid, "recursive mount actor")?;
    let path = env.maps().0.to_owned();
    let ns = u32::try_from(std::fs::metadata(format!("/proc/{pid}/ns/mnt"))?.ino())?;
    let key = ns.to_ne_bytes();
    wait_for(
        &path,
        "mount security view",
        Duration::from_secs(30),
        || {
            Ok(env
                .maps()
                .1
                .lookup("mount_security_view_locks", &key)
                .context(InterceptorSnafu)?
                .map(drop))
        },
        || format!("mount namespace {ns} has no security-view lock"),
    )?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"mount-read\n")?;
    actor.close();
    let status = actor.wait_exit("recursive bind reads", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "{status}; stderr: {stderr:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "recursive bind effects",
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
                    event.task_cookie == task.snapshot.task_cookie
                        && event.reason == reason
                        && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::OpenRead as u16)
                        && event.active_role_id == task.snapshot.active_role_id
                        && event.admitted_entry_rule_id == task.snapshot.admitted_entry_rule_id
                        && event.kernel_result == result
                })
            };
            Ok((matches("PATH_TREE_POLICY_DENY", -libc::EACCES)
                && matches("EXACT_POLICY_ALLOW", 0))
            .then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(result["mount"], 0);
    assert_eq!(result["allowed_mount"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    actor.stop()?;
    env.stop()
}
