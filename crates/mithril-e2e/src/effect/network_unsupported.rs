use std::{cell::Cell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = network_unsupported]
fn unsupported_sockets_are_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unsupported-sockets")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/tcp_nodelay.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "socket workload")?;
    let pid = actor.id();
    let task = env.task(pid, "socket actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|effect| (effect.source_cpu_id, effect.source_sequence))
        .collect::<BTreeSet<_>>();

    let sockets = [
        (libc::AF_PACKET, libc::SOCK_RAW, 0),
        (libc::AF_NETLINK, libc::SOCK_RAW, 0),
        (libc::AF_VSOCK, libc::SOCK_STREAM, 0),
        (27, libc::SOCK_RAW, 0),
        (44, libc::SOCK_RAW, 0),
        (libc::AF_INET, libc::SOCK_STREAM, 132),
        (libc::AF_INET6, libc::SOCK_STREAM, 262),
    ];
    let mut commands = String::new();
    for (index, (family, kind, protocol)) in sockets.iter().enumerate() {
        commands.push_str(&format!("socket {index} {family} {kind} {protocol}\n"));
    }
    actor.send(commands.as_bytes())?;
    actor.wait_name(pid, "socket-6-13", "socket denials", Duration::from_secs(5))?;
    let path = env.maps().0.to_owned();
    let last = Cell::new(0);
    let denied = wait_for(
        &path,
        "unsupported socket evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let effects = snapshot
                .recent_effects
                .into_iter()
                .filter(|effect| {
                    !seen.contains(&(effect.source_cpu_id, effect.source_sequence))
                        && task.matches_effect(
                            effect,
                            "UNSUPPORTED_OBJECT",
                            F::Network,
                            O::SocketCreate,
                            -libc::EACCES,
                        )
                })
                .collect::<Vec<_>>();
            last.set(effects.len());
            Ok((effects.len() >= sockets.len()).then_some(effects))
        },
        || format!("{} of {} socket denials", last.get(), sockets.len()),
    )?;
    assert_eq!(denied.len(), sockets.len());
    for effect in denied {
        assert_eq!(effect.network_destination_policy_handle, 0);
        assert_eq!(effect.exact_object_key_id, 0);
    }

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(pid, "socket actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
