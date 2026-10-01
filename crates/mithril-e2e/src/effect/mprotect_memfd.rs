use std::{fs, io::Read as _, io::Seek as _, os::unix::fs::PermissionsExt as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = memfd_map_recovery]
fn memfd_mprotect_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mprotect-memfd")?;
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
            "mprotect-memfd",
            "/work",
        ],
    )?;
    actor.ready()?;
    let pid = actor.id();
    let name = "/memfd:mithril-exec-fixture (deleted)";
    let mut image = None;
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let path = entry?.path();
        if fs::read_link(&path)?.as_os_str() == name {
            image = Some(path);
            break;
        }
    }
    let image = image.ok_or("the actor has no executable memfd descriptor")?;
    assert!(fs::read(&image)?.starts_with(b"\x7fELF"));
    assert_ne!(fs::metadata(&image)?.permissions().mode() & 0o111, 0);
    let mut maps = fs::File::open(format!("/proc/{pid}/maps"))?;
    let mut state = String::new();
    maps.read_to_string(&mut state)?;
    let region = state
        .lines()
        .find(|line| line.ends_with(name))
        .ok_or("the actor has no memfd image mapping")?;
    assert_eq!(region.split_whitespace().nth(1), Some("r--p"));
    env.place(pid)?;
    env.install_policy("exec_deny_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "memfd image mapping workload")?;
    let task = env.task(pid, "memfd image mapping actor")?;
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 2);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"protect\n")?;
    actor.wait_name(
        pid,
        &format!("protect-{}", libc::EACCES),
        "memfd mprotect errno",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Exec,
        O::Mprotect,
        -libc::EACCES,
        "memfd image mprotect denial",
    )?;
    assert_eq!(denied.composite_atom_id, 0);
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.inode, 0);
    assert_eq!(denied.inode_generation, 0);
    maps.rewind()?;
    state.clear();
    maps.read_to_string(&mut state)?;
    assert!(!state.lines().any(|line| line.ends_with(name)));
    assert!(!image.try_exists()?);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "memfd image mapping actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
