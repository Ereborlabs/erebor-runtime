use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc)]
#[lifecycle = thread_deny_recovery]
fn thread_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exec-thread")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../fixtures/process/exec_deny_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let args = [
        "/fixtures/exec_on_release.py",
        "/usr/bin/sleep",
        "fork-thread",
        "/work",
    ];
    let mut actor = env.add_actor("python", &args)?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("exec_deny_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "thread exec workload")?;
    let parent = actor.id();
    let root = env.task(parent, "external exec parent")?;
    assert_eq!(root.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(root.snapshot.active_role_id, 2);

    let first = env.next_id()?;
    actor.send(b"exec\n")?;
    let pid = actor.wait_child(parent, "thread exec child")?;
    actor.set_actor(pid)?;
    let child = env.task(pid, "thread exec child identity")?;
    assert_ne!(child.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(child.snapshot.admitted_entry_rule_id, 0);
    let tid = actor.wait_thread(None, "worker host TID")?;
    let ns_tid = ProcessFixture::namespace_pid(tid)?;
    actor.set_actor(parent)?;
    assert_ne!(tid, pid);
    let thread = env.thread(tid, ns_tid, first, "exec worker identity")?;
    assert_ne!(thread.coordinate.task_cookie, child.snapshot.task_cookie);
    assert_eq!(thread.edge.creator_task_cookie, child.snapshot.task_cookie);
    assert_eq!(thread.coordinate.host_tgid, pid);
    assert_eq!(
        thread.coordinate.process_state_id,
        child.coordinate.process_state_id
    );
    let effects = EffectCheck::new(&env, child)?;

    fs::write(env.work().join("exec"), b"exec\n")?;
    let name = format!("exec-{}", libc::EACCES);
    actor.wait_name(tid, &name, "thread exec errno", Duration::from_secs(5))?;
    let denied = effects.wait_match(&env, "signed worker exec denial", |event| {
        event.task_cookie == thread.coordinate.task_cookie
            && event.reason == "EXACT_POLICY_DENY"
            && event.effect_family == u32::from(F::Exec as u16)
            && event.operation == u32::from(O::Execute as u16)
    })?;
    assert_eq!(denied.kernel_result, -libc::EACCES);
    assert_eq!(denied.active_role_id, root.snapshot.active_role_id);
    assert_eq!(denied.admitted_entry_rule_id, 0);
    assert_eq!(
        denied.profile_generation_ref_id,
        root.snapshot.profile_generation_ref_id
    );
    assert_ne!(denied.composite_atom_id, 0);
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.inode, 0);
    assert_eq!(denied.inode_generation, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(parent, "thread exec parent exit")?;
    actor.wait_gone(pid, "thread exec child exit")?;
    actor.wait_gone(tid, "exec worker exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
