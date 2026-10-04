use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
use crate::physical::mount_cache::MountCache;
use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(runc)]
#[lifecycle = identity]
fn cold_runtime_builds_cache<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-cold-view")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("mount_alias.py", &["overlap"], &labels)?;
    let pid = actor.id();
    let task = env.task(pid, "cold-cache actor")?;
    let effects = EffectCheck::new(&env, task)?;
    actor.send(b"mount\nread\n")?;
    actor.wait_name(pid, "overlap-warm", "warm cache", Duration::from_secs(5))?;
    effects.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "warm denial",
    )?;
    let cache = MountCache::new(&env, pid)?;
    let script = actor_script(env.source(), "proc_read.py")?;
    let mut probe = ProcessFixture::python(&script, [env.work()])?;
    env.place(probe.id())?;
    let before = cache.snapshot()?;
    assert!(!before.keys.is_empty(), "{before:?}");
    assert_eq!(cache.snapshot()?, before);

    fs::write(env.work().join("act"), b"read\n")?;
    probe.wait_name(
        probe.id(),
        "proc-read-0",
        "cold runtime read",
        Duration::from_secs(5),
    )?;
    let after = cache.snapshot()?;
    assert_eq!(after.namespace, before.namespace);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.mountinfo, before.mountinfo);
    assert!(
        after.keys.is_superset(&before.keys),
        "{before:?} -> {after:?}"
    );
    assert_eq!(
        after.keys.len(),
        before.keys.len() + 1,
        "{before:?} -> {after:?}"
    );
    fs::write(env.work().join("release"), b"stop\n")?;
    assert!(probe
        .wait_exit("cold read exit", Duration::from_secs(5))?
        .success());
    probe.stop()?;
    actor.stop()?;
    env.stop()
}
