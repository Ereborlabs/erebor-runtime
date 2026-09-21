use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::platform::{platform_test, Platform, TestResult};

use super::check::EffectCheck;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = file_create]
fn unknown_create_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unknown-create")?;
    env.start_control()?;
    env.stop_node()?;
    let target = env.work().join("forbidden-create");
    let mut actor = env.start_actor("file_mutation.py", &["create", "/work/forbidden-create"])?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(actor.id())?;
    env.recovered(actor.id(), "file-create actor")?;
    let task = env.task(actor.id(), "file-create actor")?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"create\n")?;
    actor.wait_name(
        actor.id(),
        &format!("effect-{}", libc::EACCES),
        "file-create result",
        Duration::from_secs(5),
    )?;
    assert!(!target.exists(), "denied create left {}", target.display());

    let effect = effects.wait(
        &env,
        "UNRESOLVED_OBJECT",
        F::File,
        O::Create,
        -libc::EACCES,
        "file-create evidence",
    )?;
    assert_eq!(effect.exact_object_key_id, 0);
    assert_eq!(effect.composite_atom_id, 0);

    actor.send(b"release\n")?;
    actor.wait_gone(actor.id(), "file-create actor exit")?;
    actor.stop()?;
    env.stop()
}
