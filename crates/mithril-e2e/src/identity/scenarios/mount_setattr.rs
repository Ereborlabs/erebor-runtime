use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::effect::EffectCheck;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_setattr]
fn mount_setattr_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-setattr")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/mount_race_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    let mut actor = env.add_actor("python3", &["/fixtures/mount_alias.py", "/work", "setattr"])?;
    actor.ready()?;

    let pid = actor.id();
    env.install_policy("mount_race_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    let task = env.recovered(pid, "mount setattr actor")?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"setattr\n")?;
    actor.close();
    let path = env.work().join("mount-result.json");
    let result: serde_json::Value = wait_for(
        &path,
        "mount_setattr result",
        Duration::from_secs(5),
        || {
            Ok(fs::read(&path)
                .ok()
                .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
                .filter(|value| value["phase"] == "setattr"))
        },
        || {
            format!(
                "last result: {:?}; stderr: {:?}",
                fs::read_to_string(&path),
                actor.stderr()
            )
        },
    )?;
    let code = i32::try_from(result["errno"].as_i64().ok_or("missing mount errno")?)?;
    assert!(
        matches!(code, libc::EACCES | libc::EPERM),
        "{result:?}; stderr: {:?}",
        actor.stderr()?
    );
    effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Privilege,
        O::Capability,
        -libc::EACCES,
        "mount_setattr denial",
    )?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
