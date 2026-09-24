use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use serde_json::json;

use super::{check::EffectCheck, network_peer::LocalTcpPeer};
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn delegated_egress_keeps_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("network-delegate")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("network_delegate_policy.json")?;
    env.node_ready()?;
    let mut requester = env.start_actor("network_delegate.py", &["requester"])?;
    let root = env.task(requester.id(), "network requester")?;
    let args = ["/fixtures/network_delegate.py", "/work", "delegate"];
    let mut delegate = env.add_actor("python", &args)?;
    delegate.ready()?;
    let task = env.task(delegate.id(), "network delegate")?;
    assert_ne!(root.snapshot.task_cookie, task.snapshot.task_cookie);
    assert_eq!(root.snapshot.active_role_id, task.snapshot.active_role_id);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;
    let peer = LocalTcpPeer::bind(requester.id())?;

    delegate.send(b"listen\n")?;
    let ready = env.work().join("delegate-ready");
    assert_eq!(delegate.wait_text(&ready, "delegate listener")?, "ready\n");
    requester.send(b"deny\n")?;
    delegate.send(b"once\n")?;
    let denied: serde_json::Value = serde_json::from_str(
        &delegate.wait_text(&env.work().join("deny-1.json"), "denied request result")?,
    )?;
    assert_eq!(
        denied,
        json!({
            "id": "deny-1", "requested": "127.0.0.53", "final": "127.0.0.53",
            "port": 19120, "connect": libc::EACCES, "send": null,
        })
    );
    assert!(
        peer.denied_absent()?,
        "forbidden delegated connection reached its peer"
    );
    let blocked = effects.wait(
        &env,
        "UNRESOLVED_OBJECT",
        F::Network,
        O::Connect,
        -libc::EACCES,
        "denied delegate connect",
    )?;
    assert_eq!(&blocked.network_peer_address[..4], &[127, 0, 0, 53]);
    assert_eq!(blocked.network_peer_port, 19120);

    requester.send(b"allow\n")?;
    delegate.send(b"once\n")?;
    let allowed: serde_json::Value = serde_json::from_str(
        &delegate.wait_text(&env.work().join("allow-1.json"), "allowed request result")?,
    )?;
    assert_eq!(
        allowed,
        json!({
            "id": "allow-1", "requested": "127.0.0.1", "final": "127.0.0.1",
            "port": 19120, "connect": 0, "send": 0,
        })
    );
    assert_eq!(peer.receive(9)?, b"delegated");
    let connect = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Connect,
        0,
        "allowed delegate connect",
    )?;
    let send = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "allowed delegate send",
    )?;
    assert_eq!(&connect.network_peer_address[..4], &[127, 0, 0, 1]);
    assert_eq!(connect.network_peer_port, 19120);
    assert_ne!(connect.network_destination_policy_handle, 0);
    assert_eq!(send.network_socket_key_id, connect.network_socket_key_id);
    assert_eq!(
        send.network_destination_policy_handle,
        connect.network_destination_policy_handle
    );

    delegate.stop()?;
    requester.stop()?;
    env.stop()
}
