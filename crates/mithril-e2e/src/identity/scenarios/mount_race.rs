use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = mount_alias]
fn protected_mount_race_is_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-race")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor = env.add_actor("python3", &["/fixtures/mount_alias.py", "/work", "race"])?;
    actor.ready()?;
    let pid = actor.id();
    env.install_policy("mount_race_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    let task = env.recovered(pid, "mount race actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"race\n")?;
    actor.close();
    let status = actor.wait_exit("protected mount race", Duration::from_secs(5))?;
    assert!(
        status.success(),
        "{status}; stderr: {:?}; result: {:?}",
        actor.stderr()?,
        std::fs::read_to_string(env.work().join("mount-result.json"))
    );
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    assert_eq!(result["mount_allowed"], 0);
    assert_eq!(result["mount_denied"], 8);
    assert_eq!(result["mount_other"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "mount race effects",
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
            let mount = fresh.iter().any(|event| {
                event.reason == "UNSUPPORTED_OBJECT"
                    && event.effect_family == u32::from(F::Mount as u16)
                    && event.operation == u32::from(O::Mount as u16)
                    && matches!(event.kernel_result, value if value == -libc::EACCES || value == -libc::EPERM)
            });
            let file = |reason: &str, result| {
                fresh
                    .iter()
                    .any(|event| task.matches_effect(event, reason, F::File, O::OpenRead, result))
            };
            let deny = file("EXACT_POLICY_DENY", -libc::EACCES);
            let allow = file("EXACT_POLICY_ALLOW", 0);
            *last.borrow_mut() = format!(
                "mount={mount} deny={deny} allow={allow}; {:?}",
                fresh
                    .iter()
                    .map(|event| (
                        &event.reason,
                        event.effect_family,
                        event.operation,
                        event.kernel_result,
                    ))
                    .collect::<Vec<_>>()
            );
            Ok((mount && deny && allow).then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}
