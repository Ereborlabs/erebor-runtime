use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = memory_recovery]
fn anonymous_exec_is_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("executable-memory")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/executable_memory.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "executable-memory workload")?;
    let pid = actor.id();
    let task = env.task(pid, "executable-memory actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"run\n")?;
    actor.wait_name(
        pid,
        "m-13-13-0-13-0",
        "anonymous memory results",
        Duration::from_secs(5),
    )?;

    let mapped = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Exec,
        O::MmapExec,
        -libc::EACCES,
        "anonymous executable mmap",
    )?;
    let protected = effects.wait_many(
        &env,
        "UNSUPPORTED_OBJECT",
        (F::Exec, O::Mprotect),
        -libc::EACCES,
        2,
        "anonymous executable protections",
    )?;
    assert_eq!(protected.len(), 2, "Mprotect effects: {protected:?}");
    for event in protected.iter().chain(std::iter::once(&mapped)) {
        assert_eq!(event.exact_object_key_id, 0);
        assert_eq!(event.composite_atom_id, 0);
    }

    std::fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "executable-memory actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
