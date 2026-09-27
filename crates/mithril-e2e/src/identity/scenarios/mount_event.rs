use std::{collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn bind_emits_mount_event<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-event")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("mount_alias.py", &["runtime"], &labels)?;
    let task = env.task(actor.id(), "bind actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"mount\n")?;
    let path = env.work().join("mount-result.json");
    let result: serde_json::Value = wait_for(
        &path,
        "successful bind mount",
        Duration::from_secs(30),
        || {
            Ok(fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .filter(|value: &serde_json::Value| value["phase"] == "mounted"))
        },
        || {
            format!(
                "result: {:?}; stderr: {:?}",
                fs::read_to_string(&path),
                actor.stderr()
            )
        },
    )?;
    assert_eq!(result["mount"], 0);

    let pin = env.maps().0.to_owned();
    wait_for(
        &pin,
        "actor mount effect",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &pin,
                    reason: source.to_string(),
                }
                .build()
            })?;
            Ok(snapshot
                .recent_effects
                .iter()
                .any(|event| {
                    !seen.contains(&(event.source_cpu_id, event.source_sequence))
                        && event.task_cookie == task.snapshot.task_cookie
                        && event.effect_family == u32::from(F::Mount as u16)
                        && event.operation == u32::from(O::Mount as u16)
                        && event.kernel_result == 0
                })
                .then_some(()))
        },
        || {
            format!(
                "recent effects: {:?}; stderr: {:?}",
                env.snapshot().map(|snapshot| snapshot
                    .recent_effects
                    .into_iter()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()),
                actor.stderr()
            )
        },
    )?;

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("bind actor exit", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    actor.stop()?;
    env.stop()
}
