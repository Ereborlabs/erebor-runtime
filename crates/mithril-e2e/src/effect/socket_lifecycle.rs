use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn socket_generation_is_fresh<P: Platform>() -> TestResult<()> {
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

    actor.send(b"lifecycle\n")?;
    let status = actor.wait_exit("two TCP sockets", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "TCP actor exited with {status}: {stderr}");
    let connects = effects.wait_many(
        &env,
        "EXACT_POLICY_ALLOW",
        (F::Network, O::Connect),
        0,
        2,
        "both TCP connects",
    )?;
    let sends = effects.wait_many(
        &env,
        "EXACT_POLICY_ALLOW",
        (F::Network, O::Send),
        0,
        2,
        "both TCP sends",
    )?;
    assert_eq!(connects.len(), 2, "TCP connects: {connects:?}");
    assert_eq!(sends.len(), 2, "TCP sends: {sends:?}");
    for connect in &connects {
        assert_eq!(&connect.network_peer_address[..4], &[127, 0, 0, 1]);
        assert_eq!(connect.network_peer_port, 19091);
        assert_ne!(connect.network_destination_policy_handle, 0);
        assert_ne!(connect.network_socket_key_id, 0);
        assert!(sends.iter().any(|send| {
            send.network_socket_key_id == connect.network_socket_key_id
                && send.network_socket_generation == connect.network_socket_generation
                && send.network_destination_policy_handle
                    == connect.network_destination_policy_handle
        }));
    }
    assert_ne!(
        connects[0].network_socket_generation, connects[1].network_socket_generation,
        "new TCP socket reused the previous generation: {connects:?}"
    );

    actor.stop()?;
    env.stop()
}
