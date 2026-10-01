use std::{collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1 as I, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};
use mithril_control::ContainerKindV1 as Kind;

use super::check::EffectCheck;
use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn unix_stream_is_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unix-stream")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("unix_stream_policy.json")?;
    env.node_ready()?;
    let worker = GroupActor {
        name: "worker",
        script: Some("unix_stream.py"),
        args: &["client"],
        kind: Kind::Application,
    };
    let peer = GroupActor {
        name: "peer",
        args: &["server"],
        ..worker
    };
    let mut group = env.start_actor_group(&[worker, peer], &labels, |_, _| Ok(()))?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    let wait = Duration::from_secs(5);
    for (actor, _) in &mut group {
        actor.send(b"prepare\n")?;
        actor.wait_name(actor.id(), "unix-ready", "Unix socket preparation", wait)?;
    }
    let client = env.task(group[0].0.id(), "Unix client")?;
    let server = env.task(group[1].0.id(), "Unix server")?;
    let (tx, rx) = (&client.snapshot, &server.snapshot);
    let net = |pid| std::fs::read_link(format!("/proc/{pid}/ns/net"));
    assert_eq!(net(client.pid)?, net(server.pid)?);
    assert_ne!(tx.task_cookie, rx.task_cookie);
    assert_ne!(tx.active_role_id, rx.active_role_id);
    let state = env.process(&tx.process_state_id)?;
    let peer_state = env.process(&rx.process_state_id)?;
    assert_eq!(
        state.active_profile_generation_ref_id,
        peer_state.active_profile_generation_ref_id
    );
    let client_bind = tx.runtime_binding.as_ref().ok_or("client binding")?;
    let server_bind = rx.runtime_binding.as_ref().ok_or("server binding")?;
    assert_ne!(client_bind.binding_id, server_bind.binding_id);
    assert_ne!(client_bind.root_cgroup_id, server_bind.root_cgroup_id);
    let effects = EffectCheck::new(&env, client)?;

    group[1].0.send(b"exchange\n")?;
    group[0].0.send(b"exchange\n")?;
    for (actor, _) in &mut group {
        actor.wait_name(actor.id(), "unix-ok", "Unix byte exchange", wait)?;
    }
    let allowed = effects.wait_many(
        &env,
        "EXACT_POLICY_ALLOW",
        (F::Ipc, O::IpcAccess),
        0,
        3,
        "Unix-stream policy result",
    )?;
    let mut ops = BTreeSet::new();
    for event in &allowed {
        ops.insert(event.operation_argument);
        assert_eq!(
            event.profile_generation_ref_id,
            state.active_profile_generation_ref_id
        );
    }
    assert_eq!(
        BTreeSet::<u32>::from([I::Connect as u32, I::Send as u32, I::Receive as u32]),
        ops
    );
    assert!(
        !env.snapshot()?.recent_effects.iter().any(|event| {
            !seen.contains(&(event.source_cpu_id, event.source_sequence))
                && event.effect_family == u32::from(F::File as u16)
                && event.operation == u32::from(O::Create as u16)
        }),
        "abstract Unix stream reached file creation"
    );

    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
