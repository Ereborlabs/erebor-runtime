use std::{fs, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn exited_peer_loses_authority<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-pass-allowed")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("socket_pass_allowed_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("socket_pass.py", &["main-stale"])?;
    let root = env.task(main.id(), "Unix socket owner")?;
    assert_ne!(root.snapshot.admitted_entry_rule_id, 0);
    let mut peer = env.add_actor("python", &["/fixtures/socket_pass.py", "/work", "stale"])?;
    peer.ready()?;
    let task = env.task(peer.id(), "Unix socket peer")?;
    assert_eq!(task.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_ne!(task.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, root)?;

    peer.send(b"listen\n")?;
    peer.wait_name(
        peer.id(),
        "pass-listening",
        "Unix peer listener",
        Duration::from_secs(5),
    )?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        "peer-ready",
        "Unix peer payload",
        Duration::from_secs(5),
    )?;
    peer.wait_gone(peer.id(), "Unix peer exit")?;
    main.send(b"probe\n")?;
    main.wait_name(
        main.id(),
        &format!("stale-{}", libc::EACCES),
        "stale Unix send",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "CORRUPT_IDENTITY_OR_GENERATION",
        F::Ipc,
        O::IpcAccess,
        -libc::EACCES,
        "stale Unix peer evidence",
    )?;
    assert_eq!(denied.operation_argument, IpcOperationV1::Send as u32);

    fs::write(env.work().join("release"), b"release\n")?;
    main.wait_gone(main.id(), "Unix socket owner exit")?;
    peer.stop()?;
    main.stop()?;
    env.stop()
}
