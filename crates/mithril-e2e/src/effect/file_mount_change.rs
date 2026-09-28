use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = mount_alias]
fn first_bind_read_keeps_deny<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-mount-change")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/file_mount_change_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("exception.py", &["bind"], &labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let root = env.recovered(pid, "bind actor")?.snapshot.root_class;
    assert_eq!(root.as_deref(), Some("recovered_application_root"));
    env.install_policy("file_mount_change_policy.json")?;
    env.node_ready()?;

    let wait = Duration::from_secs(5);
    actor.send(b"base\n")?;
    actor.wait_name(pid, "link-base-13", "base denial", wait)?;
    let task = env.task(pid, "bind actor")?;
    let base = EffectCheck::new(&env, task)?;
    actor.send(b"confirm\n")?;
    actor.wait_name(pid, "link-confirm-13", "source denial", wait)?;
    let original = base.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "source exact denial",
    )?;
    let task = env.task(pid, "bind actor")?;
    let aliases = EffectCheck::new(&env, task)?;
    for name in ["first", "second"] {
        actor.send(format!("{name}\n").as_bytes())?;
        actor.wait_name(pid, &format!("link-{name}-13"), "alias denial", wait)?;
    }
    let events = aliases.wait_many(
        &env,
        "EXACT_POLICY_DENY",
        (F::File, O::OpenRead),
        -libc::EACCES,
        2,
        "existing bind denials",
    )?;
    assert!(events
        .iter()
        .all(|event| event.exact_object_key_id == original.exact_object_key_id));

    let key = 0_u32.to_ne_bytes();
    let before = env
        .state::<u64>("mount_global_mutation_epoch", &key, "mount epoch")?
        .ok_or("mount epoch is missing")?;
    let task = env.task(pid, "bind actor")?;
    let changed = EffectCheck::new(&env, task)?;
    actor.send(b"mount\n")?;
    actor.wait_name(pid, "link-change-13", "late bind read", wait)?;
    let mount = env.work().join("bind-change-mount");
    assert_eq!(fs::read_to_string(mount)?, "0");
    let alias = changed.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "first new bind denial",
    )?;
    let after = env
        .state::<u64>("mount_global_mutation_epoch", &key, "mount epoch")?
        .ok_or("mount epoch is missing")?;
    assert!(after > before, "mount epoch {before}->{after}");
    assert_ne!(alias.mount_id_unique, original.mount_id_unique);
    assert_eq!(alias.exact_object_key_id, original.exact_object_key_id);
    assert_eq!(alias.composite_atom_id, original.composite_atom_id);
    assert_eq!(alias.task_cookie, original.task_cookie);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
