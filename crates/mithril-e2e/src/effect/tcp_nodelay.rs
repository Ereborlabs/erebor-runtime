use std::time::Duration;

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O, NetworkAddressFamilyV1,
    NetworkProtocolV1,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn tcp_nodelay_uses_network_role<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tcp-nodelay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "TCP actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;
    actor.send(b"nodelay\n")?;
    actor.wait_name(pid, "nodelay-0", "TCP result", Duration::from_secs(5))?;
    let effect = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Connect,
        0,
        "TCP evidence",
    )?;
    assert_eq!(&effect.network_peer_address[..4], &[127, 0, 0, 1]);
    assert!(effect.network_peer_address[4..]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(effect.network_peer_port, 9);
    assert_eq!(
        effect.network_address_family,
        u32::from(NetworkAddressFamilyV1::Ipv4 as u8)
    );
    assert_eq!(
        effect.network_protocol,
        u32::from(NetworkProtocolV1::Tcp as u8)
    );
    assert_ne!(effect.network_destination_policy_handle, 0);
    assert_eq!(effect.exact_object_key_id, 0);

    actor.send(b"release\n")?;
    actor.wait_gone(pid, "TCP actor exit")?;
    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn tcp_roundtrip_uses_network_role<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tcp-nodelay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "TCP actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"roundtrip\n")?;
    let status = actor.wait_exit("TCP roundtrip", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "TCP actor exited with {status}: {stderr}");
    assert!(stderr.is_empty(), "TCP roundtrip failed: {stderr}");
    let connect = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Connect,
        0,
        "TCP connect evidence",
    )?;
    let send = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "TCP send evidence",
    )?;
    let receive = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Receive,
        0,
        "TCP receive evidence",
    )?;
    assert_eq!(&connect.network_peer_address[..4], &[127, 0, 0, 1]);
    assert_eq!(connect.network_peer_port, 19091);
    assert_eq!(
        connect.network_protocol,
        u32::from(NetworkProtocolV1::Tcp as u8)
    );
    assert_ne!(connect.network_destination_policy_handle, 0);
    assert_eq!(
        send.network_destination_policy_handle,
        connect.network_destination_policy_handle
    );
    assert_eq!(
        receive.network_destination_policy_handle,
        connect.network_destination_policy_handle
    );

    actor.stop()?;
    env.stop()
}
