use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn retained_descriptor_is_enforced<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("retained-descriptor")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("retained_descriptor.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "retained descriptor actor")?;

    env.install_policy("retained_descriptor_policy.json")?;
    env.node_ready()?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        &format!("fd-0-{0}-{0}-0-0", libc::EACCES),
        "retained descriptor results",
        Duration::from_secs(5),
    )?;
    effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::OpenRead,
        0,
        "exact read control",
    )?;
    let denied_read = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::Read,
        -libc::EACCES,
        "retained read denial",
    )?;
    let denied_mmap = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::MmapRead,
        -libc::EACCES,
        "retained mmap denial",
    )?;
    let allowed_read = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::Read,
        0,
        "retained read control",
    )?;
    let allowed_mmap = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::MmapRead,
        0,
        "retained mmap control",
    )?;
    let denied = denied_read.exact_object_key_id;
    let allowed = allowed_read.exact_object_key_id;
    assert_ne!(denied, 0);
    assert_ne!(allowed, 0);
    assert_eq!(denied_mmap.exact_object_key_id, denied);
    assert_eq!(allowed_mmap.exact_object_key_id, allowed);
    assert_ne!(denied, allowed);

    actor.send(b"release\n")?;
    actor.wait_gone(pid, "retained descriptor actor exit")?;
    actor.stop()?;
    env.stop()
}
