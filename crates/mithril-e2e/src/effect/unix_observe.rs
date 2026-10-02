use std::{collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1 as I, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};
use mithril_control::{ContainerKindV1 as Kind, WorkloadProtectionPolicy as Policy};

use super::check::EffectCheck;
use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = bpf_recovery]
fn unix_stream_is_observed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unix-observe")?;
    env.start_control()?;
    env.start_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/unix_observe_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let peer = GroupActor {
        name: "peer",
        script: Some("unix_stream.py"),
        args: &["server"],
        kind: Kind::Application,
    };
    let worker = GroupActor {
        name: "worker",
        script: Some("ready.py"),
        args: &[],
        ..peer
    };
    let mut group = env.start_actor_group(&[peer, worker], &labels, |_, _| Ok(()))?;
    let mut actor = env.add_actor("python", &["/fixtures/unix_stream.py", "/work", "client"])?;
    actor.ready()?;
    let net = |pid| std::fs::read_link(format!("/proc/{pid}/ns/net"));
    assert_eq!(net(actor.id())?, net(group[0].0.id())?);
    let wait = Duration::from_secs(5);
    assert_eq!(env.install_policy("unix_observe_policy.json")?, labels);
    env.sync_policy()?;
    env.node_ready()?;
    let seen = env.snapshot()?.recent_effects;
    let client = env.recovered(actor.id(), "Unix client recovery")?;
    let server = env.recovered(group[0].0.id(), "Unix server recovery")?;
    let (tx, rx) = (&client.snapshot, &server.snapshot);
    assert_eq!(tx.admitted_entry_rule_id, 0);
    assert_eq!(tx.root_class.as_deref(), Some("restored_or_unknown_root"));
    assert!(rx.admitted_entry_rule_id > 0);
    assert_ne!(tx.task_cookie, rx.task_cookie);
    assert_ne!(tx.active_role_id, rx.active_role_id);
    let client_bind = tx.runtime_binding.as_ref().ok_or("client binding")?;
    let server_bind = rx.runtime_binding.as_ref().ok_or("server binding")?;
    assert_ne!(client_bind.binding_id, server_bind.binding_id);
    assert_ne!(client_bind.root_cgroup_id, server_bind.root_cgroup_id);
    let generation = env
        .process(&tx.process_state_id)?
        .active_profile_generation_ref_id;
    let effects = EffectCheck::new(&env, client)?;

    group[0].0.send(b"prepare\n")?;
    group[0]
        .0
        .wait_name(server.pid, "unix-ready", "Unix socket preparation", wait)?;
    group[0].0.send(b"exchange\n")?;
    actor.send(b"roundtrip\n")?;
    let ipc = (F::Ipc, O::IpcAccess);
    let observed = effects.wait_many(&env, "WOULD_DENY", ipc, 0, 3, "Unix Observe results")?;
    for process in [&mut actor, &mut group[0].0] {
        process.wait_name(process.id(), "unix-ok", "Unix byte exchange", wait)?;
    }
    let peer_state = env.process(&rx.process_state_id)?;
    assert_eq!(generation, peer_state.active_profile_generation_ref_id);
    let mut ops = BTreeSet::new();
    for event in &observed {
        ops.insert(event.operation_argument);
        assert_eq!(event.configured_errno, -libc::EACCES);
        assert_eq!(event.profile_generation_ref_id, generation);
    }
    assert_eq!(
        BTreeSet::<u32>::from([I::Connect as u32, I::Send as u32, I::Receive as u32]),
        ops
    );
    assert!(
        !env.snapshot()?.recent_effects.iter().any(|event| {
            !seen.contains(event)
                && event.effect_family == u32::from(F::File as u16)
                && event.operation == u32::from(O::Create as u16)
        }),
        "abstract Unix stream reached file creation"
    );

    actor.stop()?;
    for (process, _) in &mut group {
        process.stop()?;
    }
    env.stop()
}
