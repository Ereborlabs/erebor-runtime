use std::{cell::RefCell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = file_create]
fn unknown_create_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unknown-create")?;
    env.start_control()?;
    env.stop_node()?;
    let target = env.work().join("forbidden-create");
    let mut actor = env.start_actor("file_create.py", &["/work/forbidden-create"])?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(actor.id())?;
    env.recovered(actor.id(), "file-create actor")?;
    let task = env.task(actor.id(), "file-create actor")?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();

    actor.send(b"create\n")?;
    let comm = format!("/proc/{}/comm", actor.id());
    let last = RefCell::new(String::from("<unread>"));
    wait_for(
        comm.as_ref(),
        "file-create result",
        Duration::from_secs(5),
        || {
            let value = fs::read_to_string(&comm).unwrap_or_else(|error| format!("<{error}>"));
            *last.borrow_mut() = value.clone();
            Ok((value.trim() == format!("file-create-{}", libc::EACCES)).then_some(()))
        },
        || format!("last task name: {}", last.borrow()),
    )?;
    assert!(!target.exists(), "denied create left {}", target.display());

    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "file-create evidence",
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
                        O::Create,
                        -libc::EACCES,
                    )
                    && event.exact_object_key_id == 0
                    && event.composite_atom_id == 0
            }))
        },
        || "no attributed file-create denial observed".to_owned(),
    )?;

    actor.send(b"release\n")?;
    actor.wait_gone(actor.id(), "file-create actor exit")?;
    actor.stop()?;
    env.stop()
}
