use std::{fs, os::unix::fs::PermissionsExt as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = deleted_recovery]
fn deleted_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exec-deleted")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../fixtures/process/exec_deny_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let mut actor = env.add_actor(
        "python",
        &[
            "/fixtures/exec_on_release.py",
            "/usr/bin/sleep",
            "fork-deleted",
            "/work",
        ],
    )?;
    actor.ready()?;
    let mut image = None;
    for entry in fs::read_dir(format!("/proc/{}/fd", actor.id()))? {
        let path = entry?.path();
        if fs::read_link(&path)?
            .to_string_lossy()
            .ends_with("/exec-image (deleted)")
        {
            image = Some(path);
            break;
        }
    }
    let image = image.ok_or("the actor has no deleted executable descriptor")?;
    assert!(fs::read(&image)?.starts_with(b"\x7fELF"));
    assert_ne!(fs::metadata(&image)?.permissions().mode() & 0o111, 0);
    assert!(!env.work().join("exec-image").exists());
    env.place(actor.id())?;
    env.install_policy("exec_deny_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "deleted exec workload")?;
    let root = env.task(actor.id(), "external exec parent")?;
    assert_eq!(root.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(root.snapshot.active_role_id, 2);

    actor.send(b"exec\n")?;
    let pid = actor.wait_child(actor.id(), "deleted exec child")?;
    actor.track(pid)?;
    let child = env.task(pid, "deleted exec child identity")?;
    assert_ne!(child.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(child.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, child)?;

    fs::write(env.work().join("exec"), b"exec\n")?;
    actor.wait_name(
        pid,
        &format!("exec-{}", libc::EACCES),
        "deleted descriptor exec errno",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Exec,
        O::Execute,
        -libc::EACCES,
        "deleted descriptor exec denial",
    )?;
    assert_eq!(denied.composite_atom_id, 0);
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.inode, 0);
    assert_eq!(denied.inode_generation, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(actor.id(), "deleted exec parent exit")?;
    actor.wait_gone(pid, "deleted exec child exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
