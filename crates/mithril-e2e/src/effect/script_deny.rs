use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{actor_script, platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = script_recovery]
fn forked_script_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("script-deny")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/script_deny_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    fs::copy(
        actor_script(env.source(), "exec_target.py")?,
        env.work().join("exec_target.py"),
    )?;
    let mut control = env.add_actor(
        "python",
        &["/fixtures/exec_on_release.py", "/work/exec_target.py"],
    )?;
    control.ready()?;
    control.send(b"exec\n")?;
    assert!(control
        .wait_exit("script control", Duration::from_secs(5))?
        .success());
    control.stop()?;
    let marker = env.work().join("script-ran");
    assert!(marker.is_file());
    fs::remove_file(&marker)?;
    let mut actor = env.add_actor(
        "python",
        &[
            "/fixtures/exec_on_release.py",
            "/work/exec_target.py",
            "fork-path",
            "/work",
        ],
    )?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("script_deny_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "script workload")?;
    let root = env.task(actor.id(), "external script parent")?;
    assert_eq!(root.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(root.snapshot.active_role_id, 2);

    actor.send(b"exec\n")?;
    let pid = actor.wait_child(actor.id(), "script exec child")?;
    actor.track(pid)?;
    let child = env.task(pid, "script exec child identity")?;
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
        "script exec errno",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::Exec,
        O::Execute,
        -libc::EACCES,
        "signed script exec denial",
    )?;
    assert_ne!(denied.composite_atom_id, 0);
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.inode, 0);
    assert_eq!(denied.inode_generation, 0);
    assert!(!marker.exists());

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(actor.id(), "script exec parent exit")?;
    actor.wait_gone(pid, "script exec child exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
