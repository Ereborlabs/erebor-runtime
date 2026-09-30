use std::{collections::BTreeSet, fs};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
use crate::physical::mount_cache::MountCache;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn stale_cache_keeps_deny<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cache-rebuild")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("read_path.py", &[], &labels)?;
    let task = env.task(actor.id(), "cache actor")?;
    let cookie = task.snapshot.task_cookie;
    let control = EffectCheck::new(&env, task)?;
    let directory = env.work().join("mount/secret");
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("blocked"), b"protected cache control\n")?;

    actor.send(b"/work/mount/secret/blocked\n")?;
    let result = actor.wait_text(&env.work().join("0.json"), "cache control read")?;
    assert_eq!(
        serde_json::from_str::<(i32, usize)>(&result)?,
        (libc::EACCES, 0)
    );
    control.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "cache control denial",
    )?;
    let cache = MountCache::new(&env, actor.id())?;
    let before = cache.snapshot()?;
    assert!(!before.keys.is_empty(), "{before:?}");
    let task = env.task(actor.id(), "stable cache actor")?;
    let effects = EffectCheck::new(&env, task)?;
    let seen: BTreeSet<_> = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect();

    cache.stale(&before)?;
    actor.send(b"/work/mount/secret/blocked\n")?;
    let result = actor.wait_text(&env.work().join("1.json"), "rebuilt cache read")?;
    assert_eq!(
        serde_json::from_str::<(i32, usize)>(&result)?,
        (libc::EACCES, 0)
    );
    let denied = effects.wait(
        &env,
        "PATH_TREE_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "rebuilt cache denial",
    )?;
    assert_eq!(denied.task_cookie, cookie);
    assert!(env
        .snapshot()?
        .recent_effects
        .iter()
        .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
        .all(|event| event.reason != "UNRESOLVED_OBJECT"));
    let after = cache.snapshot()?;
    assert!(!after.keys.is_empty(), "{after:?}");
    assert!(
        after.generation > before.generation,
        "{before:?} -> {after:?}"
    );
    assert_ne!(after.keys, before.keys);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.namespace, before.namespace);
    assert_eq!(after.mountinfo, before.mountinfo);

    actor.stop()?;
    env.stop()
}
