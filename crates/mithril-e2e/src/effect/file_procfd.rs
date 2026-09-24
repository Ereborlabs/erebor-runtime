use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn proc_fd_keeps_exact_deny<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-procfd")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["procfd"])?;
    let pid = actor.id();
    env.install_policy("file_protect.json")?;
    env.node_ready()?;

    actor.send(b"base\n")?;
    actor.wait_name(
        pid,
        &format!("link-base-{}", libc::EACCES),
        "base denial",
        Duration::from_secs(5),
    )?;
    let task = env.task(pid, "proc-fd actor")?;
    assert_ne!(task.snapshot.active_role_id, 0);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let first = EffectCheck::new(&env, task)?;

    actor.send(b"confirm\n")?;
    actor.wait_name(
        pid,
        &format!("link-confirm-{}", libc::EACCES),
        "exact file denial",
        Duration::from_secs(5),
    )?;
    let original = first.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "exact denial evidence",
    )?;
    assert_ne!(original.exact_object_key_id, 0);
    assert_ne!(original.composite_atom_id, 0);
    let task = env.task(pid, "proc-fd actor")?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"fd\n")?;
    actor.wait_name(
        pid,
        &format!("link-fd-{}", libc::EACCES),
        "proc-fd denial",
        Duration::from_secs(5),
    )?;
    let reopened = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "proc-fd denial evidence",
    )?;
    assert_eq!(reopened.exact_object_key_id, original.exact_object_key_id);
    assert_eq!(reopened.composite_atom_id, original.composite_atom_id);
    assert_eq!(reopened.task_cookie, original.task_cookie);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
