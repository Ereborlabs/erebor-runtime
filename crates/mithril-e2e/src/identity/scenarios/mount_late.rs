use mithril_control::WorkloadProtectionPolicy as Policy;

use std::{os::unix::fs::MetadataExt as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use snafu::ResultExt as _;

use crate::effect::EffectCheck;
use crate::error::InterceptorSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn late_bind_keeps_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-late")?;
    env.start_control()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/mount_alias_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("mount_alias.py", &["late"], &labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let task = env.recovered(pid, "late mount actor")?;
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
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"mount-read\n")?;
    actor.close();
    let status = actor.wait_exit("late bind reads", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "{status}; stderr: {stderr:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.work().join("mount-result.json"))?)?;
    effects.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        KernelEffectFamilyV1::File,
        KernelEffectOperationV1::OpenRead,
        -libc::EACCES,
        "late bind denial",
    )?;
    effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        KernelEffectFamilyV1::File,
        KernelEffectOperationV1::OpenRead,
        0,
        "late bind control",
    )?;
    assert_eq!(result["mount"], 0);
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");

    actor.stop()?;
    env.stop()
}
