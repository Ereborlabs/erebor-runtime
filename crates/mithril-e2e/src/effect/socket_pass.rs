use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = socket_pass_recovery]
fn passed_socket_stays_restricted<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-pass")?;
    env.start_control()?;
    env.stop_node()?;
    let mut main = env.start_actor("socket_pass.py", &["main"])?;
    env.place(main.id())?;
    let mut receiver =
        env.add_actor("python", &["/fixtures/socket_pass.py", "/work", "receiver"])?;
    receiver.ready()?;
    env.place(receiver.id())?;
    env.install_policy("socket_pass_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(main.id())?;
    let root = env.recovered(main.id(), "socket owner")?;
    let task = env.task(receiver.id(), "restricted receiver")?;
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(task.snapshot.active_role_id, root.snapshot.active_role_id);
    let effects = EffectCheck::new(&env, task)?;

    receiver.send(b"listen\n")?;
    receiver.wait_name(
        receiver.id(),
        "pass-listening",
        "Unix receiver readiness",
        Duration::from_secs(5),
    )?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        "peer-empty",
        "no forbidden bytes",
        Duration::from_secs(5),
    )?;
    receiver.wait_name(
        receiver.id(),
        "fd1-13-13",
        "passed socket denial",
        Duration::from_secs(5),
    )?;
    let sent = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Network,
        O::Send,
        -libc::EACCES,
        "passed socket send",
    )?;
    let read = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Network,
        O::Receive,
        -libc::EACCES,
        "passed socket receive",
    )?;
    assert_ne!(sent.network_socket_key_id, 0);
    assert_eq!(sent.network_socket_key_id, read.network_socket_key_id);
    assert_eq!(
        sent.network_socket_generation,
        read.network_socket_generation
    );

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(receiver.id(), "restricted receiver exit")?;
    receiver.stop()?;
    main.stop()?;
    env.stop()
}
