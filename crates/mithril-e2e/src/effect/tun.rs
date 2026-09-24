use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = tun_recovery]
fn tun_setup_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tun-setup")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/tun.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "TUN workload")?;
    let pid = actor.id();
    let task = env.task(pid, "TUN actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        "tun-open-13",
        "TUN open denial",
        Duration::from_secs(5),
    )?;
    let effect = effects.wait(
        &env,
        "UNRESOLVED_OBJECT",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "TUN open evidence",
    )?;
    assert_eq!(effect.exact_object_key_id, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "TUN actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
