use std::time::Duration;

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O, NetworkAddressFamilyV1,
    NetworkProtocolV1,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn udp_paths_are_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("udp-paths")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("tcp_nodelay_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("tcp_nodelay.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "UDP actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    let mut v4 = [0_u8; 16];
    v4[..4].copy_from_slice(&[127, 0, 0, 1]);
    let mut v6 = [0_u8; 16];
    v6[15] = 1;
    let cases = [
        (
            b"u4\n",
            "u4-0",
            NetworkAddressFamilyV1::Ipv4,
            v4,
            19095,
            false,
        ),
        (
            b"c4\n",
            "c4-0",
            NetworkAddressFamilyV1::Ipv4,
            v4,
            19095,
            true,
        ),
        (
            b"u6\n",
            "u6-0",
            NetworkAddressFamilyV1::Ipv6,
            v6,
            19096,
            false,
        ),
        (
            b"c6\n",
            "c6-0",
            NetworkAddressFamilyV1::Ipv6,
            v6,
            19096,
            true,
        ),
    ];
    for (command, name, family, address, port, connected) in cases {
        let task = env.task(pid, "UDP actor")?;
        let effects = EffectCheck::new(&env, task)?;
        actor.send(command)?;
        actor.wait_name(pid, name, "UDP payload", Duration::from_secs(5))?;
        let send = effects.wait(&env, "EXACT_POLICY_ALLOW", F::Network, O::Send, 0, name)?;
        assert_eq!(send.network_peer_address, address);
        assert_eq!(send.network_peer_port, port);
        assert_eq!(send.network_address_family, u32::from(family as u8));
        assert_eq!(
            send.network_protocol,
            u32::from(NetworkProtocolV1::Udp as u8)
        );
        assert_ne!(send.network_destination_policy_handle, 0);
        if connected {
            let connect = effects.wait(
                &env,
                "EXACT_POLICY_ALLOW",
                F::Network,
                O::Connect,
                0,
                "UDP connect",
            )?;
            assert_eq!(connect.network_peer_address, address);
            assert_eq!(connect.network_peer_port, port);
            assert_eq!(
                connect.network_destination_policy_handle,
                send.network_destination_policy_handle
            );
        }
    }

    actor.send(b"release\n")?;
    actor.wait_gone(pid, "UDP actor exit")?;
    actor.stop()?;
    env.stop()
}
