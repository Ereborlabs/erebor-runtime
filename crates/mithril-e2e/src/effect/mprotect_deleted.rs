use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = deleted_map_recovery]
fn deleted_mprotect_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mprotect-deleted")?;
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
            "mprotect-deleted",
            "/work",
        ],
    )?;
    actor.ready()?;
    let pid = actor.id();
    let mut image = None;
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let path = entry?.path();
        if fs::read_link(&path)?
            .to_string_lossy()
            .ends_with("/exec-image (deleted)")
        {
            image = Some(path);
            break;
        }
    }
    let image = image.ok_or("the actor has no deleted image descriptor")?;
    assert!(fs::read(&image)?.starts_with(b"\x7fELF"));
    assert!(!env.work().join("exec-image").exists());
    let maps = format!("/proc/{pid}/maps");
    let before = fs::read_to_string(&maps)?;
    let region = before
        .lines()
        .find(|line| line.ends_with("/exec-image (deleted)"))
        .ok_or("the actor has no deleted image mapping")?;
    assert_eq!(region.split_whitespace().nth(1), Some("r--p"));
    env.place(pid)?;
    env.install_policy("exec_deny_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "deleted image mapping workload")?;
    let task = env.task(pid, "deleted image mapping actor")?;
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 2);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"protect\n")?;
    let name = format!("protect-{}", libc::EACCES);
    actor.wait_name(pid, &name, "deleted mprotect errno", Duration::from_secs(5))?;
    let denied = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Exec,
        O::Mprotect,
        -libc::EACCES,
        "deleted image mprotect denial",
    )?;
    assert_eq!(denied.composite_atom_id, 0);
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.inode, 0);
    assert_eq!(denied.inode_generation, 0);
    assert!(!fs::read_to_string(&maps)?
        .lines()
        .any(|line| line.ends_with("/exec-image (deleted)")));
    assert!(!image.exists());

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "deleted image mapping actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
