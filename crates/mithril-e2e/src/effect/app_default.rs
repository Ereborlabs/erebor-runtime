use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn application_read_uses_default<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("application-read")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("runtime_exec.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "application actor")?;
    assert_eq!(task.snapshot.active_role_id, 3);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    let effects = EffectCheck::new(&env, task)?;
    actor.send(b"read\n")?;
    actor.wait_name(
        pid,
        "app-read-0",
        "application read",
        Duration::from_secs(5),
    )?;
    let effect = effects.wait(
        &env,
        "APPLICATION_DEFAULT_ALLOW",
        F::File,
        O::Read,
        0,
        "application read evidence",
    )?;
    assert_eq!(effect.composite_atom_id, 0);
    assert_eq!(effect.exact_object_key_id, 0);

    actor.stop()?;
    env.stop()
}
