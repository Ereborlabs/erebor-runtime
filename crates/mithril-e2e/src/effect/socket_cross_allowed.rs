use std::{fs, os::unix::fs::MetadataExt, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = socket_cross_recovery]
fn cross_namespace_socket_is_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-cross-allowed")?;
    env.start_control()?;
    env.stop_node()?;
    let mut main = env.start_actor("socket_pass.py", &["main-approved-net"])?;
    env.place(main.id())?;
    let mut holder = env.add_actor(
        "python",
        &["/fixtures/socket_pass.py", "/work", "namespace-holder"],
    )?;
    holder.ready()?;
    env.place(holder.id())?;
    let host = holder.id().to_string();
    let status = fs::read_to_string(format!("/proc/{host}/status"))?;
    let local = status
        .lines()
        .find(|line| line.starts_with("NSpid:"))
        .and_then(|line| line.split_whitespace().last())
        .ok_or("missing namespace PID")?;
    let holder_ns = fs::metadata(format!("/proc/{host}/ns/net"))?.ino();
    let namespace = format!("{host}:{local}:{holder_ns}");
    env.install_policy("socket_cross_allowed_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(main.id())?;
    let root = env.recovered(main.id(), "socket owner")?;
    let mut receiver = env.add_actor(
        "python",
        &[
            "/fixtures/socket_pass.py",
            "/work",
            "approved-net",
            &namespace,
        ],
    )?;
    receiver.ready()?;
    let task = env.task(receiver.id(), "approved receiver")?;
    let owner_ns = u32::try_from(fs::metadata(format!("/proc/{}/ns/net", main.id()))?.ino())?;
    let entry_ns = u32::try_from(fs::metadata(format!("/proc/{}/ns/net", receiver.id()))?.ino())?;
    assert_ne!(owner_ns, entry_ns);
    assert_eq!(entry_ns, u32::try_from(holder_ns)?);
    let rx = &task.snapshot;
    let tx = &root.snapshot;
    assert_eq!(tx.root_class.as_deref(), Some("recovered_application_root"));
    assert_eq!(rx.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        rx.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(rx.active_role_id, tx.active_role_id);
    assert_ne!(rx.task_cookie, tx.task_cookie);
    assert_ne!(rx.process_state_id, tx.process_state_id);
    assert_ne!(rx.active_execution_id, tx.active_execution_id);
    assert_ne!(rx.admitted_entry_rule_id, 0);
    assert_ne!(rx.admitted_entry_rule_id, tx.admitted_entry_rule_id);
    let effects = EffectCheck::new(&env, task)?;
    let peer = receiver.id();
    let t = Duration::from_secs(5);

    receiver.send(b"listen\n")?;
    receiver.wait_name(peer, "pass-listening", "Unix", t)?;
    main.send(b"act\n")?;
    main.wait_name(main.id(), "peer-ok", "payload", t)?;
    receiver.wait_name(peer, "fd1-ok", "descriptor", t)?;
    let sent = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "allowed send",
    )?;
    assert_ne!(sent.network_socket_key_id, 0);
    assert_ne!(sent.network_destination_policy_handle, 0);
    assert_eq!(sent.network_namespace_inode, owner_ns);
    assert_eq!(sent.network_current_namespace_inode, entry_ns);

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(peer, "approved receiver exit")?;
    receiver.stop()?;
    holder.stop()?;
    main.stop()?;
    env.stop()
}
