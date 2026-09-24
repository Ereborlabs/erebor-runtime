use std::{fs, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn fork_child_cannot_borrow_socket<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-pass-allowed")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("socket_pass_allowed_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("socket_pass.py", &["main-inherit"])?;
    let root = env.task(main.id(), "Unix socket owner")?;
    assert_ne!(root.snapshot.admitted_entry_rule_id, 0);
    let mut peer = env.add_actor("python", &["/fixtures/socket_pass.py", "/work", "approved"])?;
    peer.ready()?;
    let receiver = env.task(peer.id(), "Unix socket receiver")?;
    assert_eq!(
        receiver.snapshot.active_role_id,
        root.snapshot.active_role_id
    );
    assert_ne!(receiver.snapshot.task_cookie, root.snapshot.task_cookie);

    peer.send(b"listen\n")?;
    peer.wait_name(
        peer.id(),
        "pass-listening",
        "Unix listener",
        Duration::from_secs(5),
    )?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        "peer-ok",
        "allowed Unix payload",
        Duration::from_secs(5),
    )?;
    main.send(b"fork\n")?;
    main.wait_name(
        main.id(),
        "fork-ready",
        "forked borrower",
        Duration::from_secs(5),
    )?;
    let pid = main.wait_child(main.id(), "inherited Unix child")?;
    let child = env.task(pid, "inherited Unix child")?;
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_ne!(child.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    let effects = EffectCheck::new(&env, child)?;
    main.send(b"probe\n")?;
    let denied_name = format!("fork-{}", libc::EACCES);
    main.wait_name(
        main.id(),
        &denied_name,
        "inherited send denial",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "CORRUPT_IDENTITY_OR_GENERATION",
        F::Ipc,
        O::IpcAccess,
        -libc::EACCES,
        "forked Unix send evidence",
    )?;
    assert_eq!(denied.operation_argument, IpcOperationV1::Send as u32);

    fs::write(env.work().join("release"), b"release\n")?;
    peer.wait_gone(peer.id(), "Unix receiver exit")?;
    main.wait_gone(main.id(), "Unix owner exit")?;
    peer.stop()?;
    main.stop()?;
    env.stop()
}
