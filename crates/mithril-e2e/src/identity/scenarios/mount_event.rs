use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
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
    let effects = EffectCheck::new(&env, task)?;

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

    effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Mount,
        O::Mount,
        0,
        "actor mount effect",
    )?;

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("bind actor exit", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    actor.stop()?;
    env.stop()
}
