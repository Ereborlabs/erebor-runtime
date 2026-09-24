use std::fs;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = exception]
fn inactive_grant_denies<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-inactive")?;
    env.start_control()?;
    env.start_node()?;
    fs::write(env.work().join("expired-secret"), b"")?;
    env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["expired"])?;
    let task = env.task(actor.id(), "initial exception actor")?;
    let generation = task.snapshot.profile_generation_ref_id;
    assert_ne!(generation, 0);
    let check = EffectCheck::new(&env, task)?;

    actor.send(b"expired\n")?;
    let text = actor.wait_text(&env.work().join("expired-result"), "inactive grant result")?;
    assert_eq!(text.trim().parse::<i32>()?, libc::EACCES);
    let event = check.wait(
        &env,
        "EXCEPTION_UNAVAILABLE",
        F::File,
        O::OpenWrite,
        -libc::EACCES,
        "initial inactive grant denial",
    )?;
    assert_eq!(event.profile_generation_ref_id, generation);
    assert_ne!(event.composite_atom_id, 0);
    assert_eq!(event.exact_object_key_id, 0);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
