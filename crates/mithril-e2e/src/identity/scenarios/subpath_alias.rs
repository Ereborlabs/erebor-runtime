use std::fs;
use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(kubernetes)]
#[lifecycle = mount_late]
fn subpath_aliases_keep_denial<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("subpath-alias")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;

    let tree = env.work().join("path-tree/models");
    fs::create_dir_all(&tree)?;
    fs::write(tree.join("secret"), b"restricted\n")?;
    let mut actor = env.start_actor("mount_alias.py", &["subpath"], &labels)?;
    let task = env.task(actor.id(), "Kubernetes subPath actor")?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("subPath reads", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value =
        serde_json::from_slice(&fs::read(env.work().join("mount-result.json"))?)?;
    assert_eq!(result["source"], libc::EACCES);
    assert_eq!(result["older"], libc::EACCES);
    assert_eq!(result["newer"], libc::EACCES);
    effects.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "subPath denial evidence",
    )?;

    actor.stop()?;
    env.stop()
}
