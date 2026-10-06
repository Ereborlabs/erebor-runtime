use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::{KubernetesPolicyModeV1 as Mode, WorkloadProtectionPolicy as Policy};

use super::check::EffectCheck;
use crate::physical::mount_cache::MountCache;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = mount_alias]
fn bind_rebuilds_ready_cache<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-mount-snapshot")?;
    env.start_control()?;
    env.stop_node()?;
    let mut policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/file_mount_change_policy.json"
    ))?;
    let labels = &policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("exception.py", &["bind"], labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let root = env.recovered(pid, "bind actor")?.snapshot.root_class;
    assert_eq!(root.as_deref(), Some("recovered_application_root"));
    let cache = MountCache::new(&env, pid)?;
    let file = env.work().join("bind-snapshot-policy.json");
    let wait = Duration::from_secs(5);

    for (mode, reason, result) in [
        (Mode::Protect, "EXACT_POLICY_DENY", -libc::EACCES),
        (Mode::Observe, "WOULD_DENY", 0),
    ] {
        policy.spec.mode = mode;
        fs::write(&file, serde_json::to_vec(&policy)?)?;
        env.install_policy(file.to_str().ok_or("invalid policy path")?)?;
        env.node_ready()?;
        actor.send(b"base\n")?;
        let mark = format!("link-base-{}", -result);
        actor.wait_name(pid, &mark, "source read", wait)?;
        let task = env.task(pid, "bind actor")?;
        let source = EffectCheck::new(&env, task)?;
        actor.send(b"confirm\n")?;
        let mark = format!("link-confirm-{}", -result);
        actor.wait_name(pid, &mark, "source confirmation", wait)?;
        let original = source.wait(&env, reason, F::File, O::OpenRead, result, "source read")?;
        assert_ne!(original.mount_id_unique, 0);
        assert_ne!(original.exact_object_key_id, 0);
        assert_ne!(original.composite_atom_id, 0);
        let before = cache.snapshot()?;
        assert!(!before.keys.is_empty(), "{mode:?}: {before:?}");

        let task = env.task(pid, "bind actor")?;
        let changed = EffectCheck::new(&env, task)?;
        actor.send(b"cache\n")?;
        let mark = format!("link-cache-0-{}", -result);
        actor.wait_name(pid, &mark, "first new bind read", wait)?;
        let alias = changed.wait(&env, reason, F::File, O::OpenRead, result, "alias read")?;
        let after = cache.snapshot()?;
        assert!(
            after.epoch > before.epoch,
            "{mode:?}: {before:?} -> {after:?}"
        );
        assert_eq!(after.namespace, before.namespace);
        assert_ne!(after.mountinfo, before.mountinfo);
        assert!(
            after.keys.difference(&before.keys).next().is_some(),
            "{mode:?}: {before:?} -> {after:?}"
        );
        assert_ne!(alias.mount_id_unique, original.mount_id_unique);
        assert_eq!(alias.exact_object_key_id, original.exact_object_key_id);
        assert_eq!(alias.composite_atom_id, original.composite_atom_id);
        assert_eq!(alias.task_cookie, original.task_cookie);
        assert_eq!(
            alias.profile_generation_ref_id,
            original.profile_generation_ref_id
        );
    }

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
