use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::effect::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = ipc_recovery]
fn ipc_stat_is_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("ipc-stat")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../../fixtures/process/python_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/ipc_stat.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "SysV workload recovery")?;
    let task = env.recovered(actor.id(), "SysV actor recovery")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 2);
    let effects = EffectCheck::new(&env, task)?;

    actor
        .send(b"stat\n")
        .map_err(|error| format!("IPC_STAT command: {error}; stderr: {:?}", actor.stderr()))?;
    actor.wait_name(
        actor.id(),
        &format!("ipc-{}", libc::EACCES),
        "SysV IPC_STAT result",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Ipc,
        O::IpcAccess,
        -libc::EACCES,
        "SysV permission denial",
    )?;
    assert_eq!(denied.exact_object_key_id, 0);
    assert_eq!(denied.composite_atom_id, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_name(
        actor.id(),
        "ipc-clean",
        "SysV segment detach",
        Duration::from_secs(5),
    )?;
    fs::write(env.work().join("finish"), b"finish\n")?;
    actor.wait_gone(actor.id(), "SysV actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
