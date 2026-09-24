use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = sqpoll_recovery]
fn sqpoll_setup_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("sqpoll-setup")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/sqpoll.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "SQPOLL workload")?;
    let pid = actor.id();
    let task = env.task(pid, "SQPOLL actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        &format!("sqpoll-{}", libc::EACCES),
        "SQPOLL setup result",
        Duration::from_secs(5),
    )?;
    let effect = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Privilege,
        O::IoUringSqpoll,
        -libc::EACCES,
        "SQPOLL denial evidence",
    )?;
    assert_eq!(effect.exact_object_key_id, 0);
    assert_eq!(effect.composite_atom_id, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "SQPOLL actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
