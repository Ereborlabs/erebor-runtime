use std::{cell::RefCell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = process_recovery]
fn managed_proc_read_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("managed-proc-read")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let args = ["/fixtures/proc_read.py", "/work"];
    let mut actor = env.add_actor("python", &args)?;
    actor.ready()?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "proc workload")?;
    let task = env.task(actor.id(), "proc actor")?;
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
    fs::write(env.work().join("act"), b"act\n")?;
    let comm = format!("/proc/{}/comm", actor.id());
    let last = RefCell::new(String::from("<unread>"));
    wait_for(
        comm.as_ref(),
        "managed proc read",
        Duration::from_secs(5),
        || {
            let value = fs::read_to_string(&comm).unwrap_or_else(|error| format!("<{error}>"));
            *last.borrow_mut() = value.clone();
            Ok((value.trim() == format!("proc-read-{}", libc::EACCES)).then_some(()))
        },
        || format!("last task name: {}", last.borrow()),
    )?;

    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "managed proc evidence",
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
                        "UNRESOLVED_OBJECT",
                        F::File,
                        O::OpenRead,
                        -libc::EACCES,
                    )
                    && event.exact_object_key_id == 0
                    && event.composite_atom_id == 0
            }))
        },
        || "no attributed managed proc denial observed".to_owned(),
    )?;

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(actor.id(), "proc actor exit")?;
    actor.stop()?;
    init.stop()?;
    env.stop()
}
