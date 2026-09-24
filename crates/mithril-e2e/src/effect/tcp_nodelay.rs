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

#[platform_test(host, runc)]
#[lifecycle = identity]
fn tcp_ipv6_is_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tcp-nodelay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "IPv6 TCP actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"ipv6\n")?;
    let status = actor.wait_exit("IPv6 TCP", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "TCP actor exited with {status}: {stderr}");
    let connect = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Connect,
        0,
        "IPv6 TCP connect",
    )?;
    let send = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "IPv6 TCP send",
    )?;
    for event in [&connect, &send] {
        assert_eq!(&event.network_peer_address[..15], &[0; 15]);
        assert_eq!(event.network_peer_address[15], 1);
        assert_eq!(event.network_peer_port, 19094);
        assert_eq!(
            event.network_address_family,
            u32::from(NetworkAddressFamilyV1::Ipv6 as u8)
        );
        assert_eq!(
            event.network_protocol,
            u32::from(NetworkProtocolV1::Tcp as u8)
        );
        assert_ne!(event.network_destination_policy_handle, 0);
    }
    assert_eq!(
        connect.network_destination_policy_handle,
        send.network_destination_policy_handle
    );

    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn tcp_send_variants_are_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tcp-nodelay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "TCP actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    actor.send(b"variants\n")?;
    let status = actor.wait_exit("TCP send variants", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "TCP actor exited with {status}: {stderr}");

    let snapshot = env.snapshot()?;
    let sends = snapshot
        .recent_effects
        .iter()
        .filter(|event| task.matches_effect(event, "EXACT_POLICY_ALLOW", F::Network, O::Send, 0))
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 3, "send evidence: {sends:?}");
    for event in &sends {
        assert_eq!(&event.network_peer_address[..4], &[127, 0, 0, 1]);
        assert_eq!(event.network_peer_port, 19092);
        assert_eq!(
            event.network_protocol,
            u32::from(NetworkProtocolV1::Tcp as u8)
        );
        assert_ne!(event.network_destination_policy_handle, 0);
    }
    assert!(sends.iter().all(|event| {
        event.network_destination_policy_handle == sends[0].network_destination_policy_handle
    }));

    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn tcp_inherited_socket_is_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tcp-nodelay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let root = env.task(pid, "TCP actor")?;
    assert_ne!(root.snapshot.admitted_entry_rule_id, 0);

    actor.send(b"inherit\n")?;
    actor.wait_name(
        pid,
        "inherit-ready",
        "socket preparation",
        Duration::from_secs(5),
    )?;
    let child_pid = actor.wait_child(pid, "forked TCP sender")?;
    actor.track(child_pid)?;
    let child = env.task(child_pid, "forked TCP sender")?;
    assert_ne!(child.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    let root_generation = root.snapshot.profile_generation_ref_id;
    let root_effects = EffectCheck::new(&env, root)?;
    let child_effects = EffectCheck::new(&env, child)?;

    actor.send(b"send\n")?;
    actor.wait_name(pid, "inherit-0", "socket sends", Duration::from_secs(5))?;
    let root_send = root_effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "duplicate socket Send",
    )?;
    let child_send = child_effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "forked socket Send",
    )?;
    for event in [&root_send, &child_send] {
        assert_eq!(&event.network_peer_address[..4], &[127, 0, 0, 1]);
        assert_eq!(event.network_peer_port, 19093);
        assert_ne!(event.network_destination_policy_handle, 0);
        assert_eq!(
            event.network_creator_profile_generation_ref_id,
            root_generation
        );
    }
    assert_eq!(
        root_send.network_socket_key_id,
        child_send.network_socket_key_id
    );
    assert_eq!(
        root_send.network_socket_generation,
        child_send.network_socket_generation
    );

    actor.send(b"release\n")?;
    let status = actor.wait_exit("TCP inheritance", Duration::from_secs(5))?;
    assert!(status.success(), "TCP actor exited with {status}");
    actor.stop()?;
    env.stop()
}
