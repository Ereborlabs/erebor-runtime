use std::{collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = process_recovery]
fn bpf_map_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("bpf-map")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let args = ["/fixtures/bpf_map.py"];
    let mut actor = env.add_actor("python", &args)?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "BPF workload")?;
    let task = env.task(actor.id(), "BPF actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);

    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"act\n")?;
    let status = actor.wait_exit("BPF actor exit", Duration::from_secs(5))?;
    assert_eq!(status.code(), Some(libc::EACCES));

    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "BPF denial evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            Ok(snapshot.recent_effects.into_iter().find(|event| {
                !seen.contains(&(event.source_cpu_id, event.source_sequence))
                    && task.matches_effect(
                        event,
                        "UNSUPPORTED_OBJECT",
                        F::Privilege,
                        O::Bpf,
                        -libc::EACCES,
                    )
                    && event.exact_object_key_id == 0
                    && event.composite_atom_id == 0
            }))
        },
        || "no attributed BPF denial observed".to_owned(),
    )?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}
