use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = exec_fd_recovery]
fn exec_fd_allow_cannot_admit<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exec-fd-allow")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/exec_allow_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let mut actor = env.add_actor(
        "python",
        &["/fixtures/exec_on_release.py", "/usr/bin/sleep", "fd"],
    )?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("exec_allow_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "exec workload")?;
    let task = env.task(actor.id(), "external exec actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 2);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"exec\n")?;
    actor.close();
    let status = actor.wait_exit("file-descriptor exec denial", Duration::from_secs(5))?;
    assert_eq!(status.code(), Some(libc::EACCES));
    let allowed = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Exec,
        O::Execute,
        0,
        "signed file-descriptor exec Allow",
    )?;
    assert_ne!(allowed.composite_atom_id, 0);
    assert_eq!(allowed.exact_object_key_id, 0);
    assert_eq!(allowed.inode, 0);
    assert_eq!(allowed.inode_generation, 0);
    let denied = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Exec,
        O::Execute,
        -libc::EACCES,
        "unadmitted file-descriptor exec",
    )?;
    assert_eq!(denied.task_cookie, allowed.task_cookie);
    assert_eq!(denied.admitted_entry_rule_id, 0);

    actor.stop()?;
    init.stop()?;
    env.stop()
}
