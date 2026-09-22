use std::{fs, os::unix::fs::PermissionsExt as _, time::Duration};

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
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let args = [
        "/fixtures/file_mutation.py",
        "/work",
        "create",
        "/work/forbidden-create",
    ];
    let mut actor = env.add_actor("python", &args)?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "file-mutation workload")?;
    let task = env.task(actor.id(), "file-create actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
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
    init.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = file_chmod]
fn unknown_chmod_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unknown-chmod")?;
    env.start_control()?;
    env.stop_node()?;
    let target = env.work().join("setattr-target");
    fs::write(&target, b"protected\n")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let args = [
        "/fixtures/file_mutation.py",
        "/work",
        "chmod",
        "/work/setattr-target",
    ];
    let mut actor = env.add_actor("python", &args)?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "file-mutation workload")?;
    let task = env.task(actor.id(), "chmod actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"chmod\n")?;
    actor.wait_name(
        actor.id(),
        &format!("effect-{}", libc::EACCES),
        "chmod result",
        Duration::from_secs(5),
    )?;
    assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o600);

    let effect = effects.wait(
        &env,
        "UNRESOLVED_OBJECT",
        F::File,
        O::Setattr,
        -libc::EACCES,
        "chmod evidence",
    )?;
    assert_eq!(effect.exact_object_key_id, 0);
    assert_eq!(effect.composite_atom_id, 0);

    actor.send(b"release\n")?;
    actor.wait_gone(actor.id(), "chmod actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
