use std::{fs, os::unix::fs::MetadataExt, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = socket_cross_recovery]
fn cross_namespace_socket_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-cross")?;
    env.start_control()?;
    env.stop_node()?;
    let mut main = env.start_actor("socket_pass.py", &["main-net"])?;
    env.place(main.id())?;
    let mut receiver = env.add_actor(
        "python",
        &["/fixtures/socket_pass.py", "/work", "receiver-net"],
    )?;
    receiver.ready()?;
    env.place(receiver.id())?;
    let main_ns = fs::metadata(format!("/proc/{}/ns/net", main.id()))?.ino();
    let rx_ns = fs::metadata(format!("/proc/{}/ns/net", receiver.id()))?.ino();
    assert_ne!(main_ns, rx_ns);
    env.install_policy("socket_cross_policy.json")?;
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
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(task.snapshot.active_role_id, root.snapshot.active_role_id);
    let effects = EffectCheck::new(&env, task)?;

    receiver.send(b"listen\n")?;
    if let Err(error) = receiver.wait_name(
        receiver.id(),
        "pass-listening",
        "Unix receiver readiness",
        Duration::from_secs(5),
    ) {
        eprintln!(
            "last effect: {:?}",
            env.snapshot()
                .map(|state| state.recent_effects.into_iter().last())
        );
        return Err(error.into());
    }
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
    for event in [&sent, &read] {
        assert_eq!(event.network_namespace_inode, main_ns as u32);
        assert_eq!(event.network_current_namespace_inode, rx_ns as u32);
    }

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(receiver.id(), "restricted receiver exit")?;
    receiver.stop()?;
    main.stop()?;
    env.stop()
}
