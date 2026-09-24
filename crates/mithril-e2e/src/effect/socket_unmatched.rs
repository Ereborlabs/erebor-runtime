use std::{fs, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn new_peer_needs_relation<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-unmatched")?;
    env.start_control()?;
    let mut main = env.start_actor("socket_pass.py", &["main-unmatched"])?;
    env.install_policy("socket_unmatched_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(main.id())?;
    let root = env.recovered(main.id(), "Unix socket owner")?;
    let role = root.snapshot.active_role_id;
    let relation = EffectCheck::new(&env, root)?;
    let args = ["/fixtures/socket_pass.py", "/work", "stale"];
    let mut peer = env.add_actor("python", &args)?;
    peer.ready()?;
    let approved = env.task(peer.id(), "approved Unix peer")?;
    assert_eq!(approved.snapshot.active_role_id, role);
    peer.send(b"listen\n")?;
    peer.wait_name(
        peer.id(),
        "pass-listening",
        "approved listener",
        Duration::from_secs(5),
    )?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        "peer-ready",
        "approved payload",
        Duration::from_secs(5),
    )?;
    peer.wait_name(
        peer.id(),
        "fd1-ok",
        "approved descriptor",
        Duration::from_secs(5),
    )?;
    peer.wait_gone(peer.id(), "approved Unix peer exit")?;
    let allowed = relation.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Ipc,
        O::IpcAccess,
        0,
        "approved peer",
    )?;
    assert_eq!(allowed.operation_argument, IpcOperationV1::Connect as u32);

    let args = ["/fixtures/socket_pass.py", "/work", "unmatched"];
    let mut other = env.add_actor("python-external", &args)?;
    other.ready()?;
    let task = env.task(other.id(), "unmatched Unix peer")?;
    assert_ne!(task.snapshot.task_cookie, approved.snapshot.task_cookie);
    assert_ne!(task.snapshot.active_role_id, role);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    other.send(b"listen\n")?;
    other.wait_name(
        other.id(),
        "pass-listening",
        "new Unix listener",
        Duration::from_secs(5),
    )?;
    main.send(b"probe\n")?;
    main.wait_name(
        main.id(),
        &format!("unmatch-{}", libc::EACCES),
        "unmatched Unix connect",
        Duration::from_secs(5),
    )?;
    let denied = relation.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::Ipc,
        O::IpcAccess,
        -libc::EACCES,
        "unmatched Unix peer evidence",
    )?;
    assert_eq!(denied.operation_argument, IpcOperationV1::Connect as u32);

    fs::write(env.work().join("release"), b"release\n")?;
    other.wait_gone(other.id(), "unmatched Unix peer exit")?;
    main.wait_gone(main.id(), "Unix socket owner exit")?;
    other.stop()?;
    peer.stop()?;
    main.stop()?;
    env.stop()
}
