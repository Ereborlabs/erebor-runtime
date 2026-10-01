use std::fs;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = exec_observe_recovery]
fn forked_fd_exec_is_observed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exec-fd-observe")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/exec_observe_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let mut actor = env.add_actor(
        "python",
        &[
            "/fixtures/exec_on_release.py",
            "/usr/bin/sleep",
            "fork-fd",
            "/work",
        ],
    )?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("exec_observe_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "Observe exec workload")?;
    let root = env.task(actor.id(), "external exec parent")?;
    assert_eq!(root.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(root.snapshot.active_role_id, 2);

    actor.send(b"exec\n")?;
    let pid = actor.wait_child(actor.id(), "descriptor exec child")?;
    actor.track(pid)?;
    let child = env.task(pid, "descriptor exec child identity")?;
    assert_ne!(child.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(child.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, child)?;

    fs::write(env.work().join("exec"), b"exec\n")?;
    let observed = effects.wait(
        &env,
        "WOULD_DENY",
        F::Exec,
        O::Execute,
        0,
        "Observe file-descriptor exec decision",
    )?;
    assert_eq!(observed.configured_errno, -libc::EACCES);
    assert_ne!(observed.composite_atom_id, 0);
    assert_eq!(observed.exact_object_key_id, 0);
    assert_eq!(observed.inode, 0);
    assert_eq!(observed.inode_generation, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(actor.id(), "Observe exec parent exit")?;
    actor.wait_gone(pid, "Observe exec child exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
