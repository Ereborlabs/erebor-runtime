use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn protected_bind_denies_alias<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-protected")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("mount_alias.py", &["runtime"], &labels)?;
    let task = env.task(actor.id(), "protected bind actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );

    actor.send(b"mount-read\n")?;
    actor.close();
    let status = actor.wait_exit("protected bind and reads", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    assert_eq!(result["mount"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "protected bind denial evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            *last.borrow_mut() = format!("{:?}", snapshot.recent_effects.iter().rev().take(8));
            Ok(snapshot
                .recent_effects
                .iter()
                .any(|event| {
                    task.matches_effect(
                        event,
                        "PATH_TREE_POLICY_DENY",
                        F::File,
                        O::OpenRead,
                        -libc::EACCES,
                    )
                })
                .then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    env.stop()
}
