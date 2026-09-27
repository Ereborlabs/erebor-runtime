use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
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
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"mount-read\n")?;
    actor.close();
    let status = actor.wait_exit("protected bind and reads", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    assert_eq!(result["mount"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    effects.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "protected bind denial evidence",
    )?;

    actor.stop()?;
    env.stop()
}
