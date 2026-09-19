use std::{cell::RefCell, collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn protected_ptrace_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("process-ptrace")?;
    env.start_control()?;
    env.stop_node()?;
    let mut actor = env.start_actor("process_control.py", &["ptrace"])?;
    env.install_policy("process_control_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(actor.id())?;
    let parent = env.recovered(actor.id(), "ptrace controller")?;
    actor.ensure_running("recovered ptrace actor")?;

    fs::write(env.work().join("spawn"), b"spawn\n")?;
    let pid = actor.wait_child(actor.id(), "ptrace target")?;
    actor.track(pid)?;
    let target = env.task(pid, "ptrace target identity")?;
    let parent_state = &parent.snapshot;
    let target_state = &target.snapshot;
    assert_eq!(
        target_state.creator_task_cookie,
        Some(parent_state.task_cookie)
    );
    assert_eq!(
        target_state.profile_generation_ref_id,
        parent_state.profile_generation_ref_id
    );
    assert_eq!(target_state.active_role_id, parent_state.active_role_id);
    assert_ne!(target_state.task_cookie, parent_state.task_cookie);
    assert_ne!(target_state.process_state_id, parent_state.process_state_id);

    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    fs::write(env.work().join("act"), b"act\n")?;
    let result_path = env.work().join("control-result");
    let denied = actor.wait_text(&result_path, "ptrace result")?;
    assert_eq!(denied.trim(), libc::EACCES.to_string());

    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "denied ptrace evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            let fresh = snapshot
                .recent_effects
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            Ok(fresh.into_iter().find(|event| {
                parent.matches_effect(
                    event,
                    "EXACT_POLICY_DENY",
                    F::Privilege,
                    O::Ptrace,
                    -libc::EACCES,
                ) && event.operation_argument == 18
                    && event.profile_generation_ref_id == parent_state.profile_generation_ref_id
                    && event.controller_process_state_id == parent_state.process_state_id
                    && event.process_state_vector_id > 0
                    && event.target_task_cookie == target_state.task_cookie
                    && event.target_profile_generation_ref_id
                        == target_state.profile_generation_ref_id
                    && event.target_role_id == target_state.active_role_id
                    && event.target_process_state_id == target_state.process_state_id
                    && event.target_process_state_vector_id > 0
            }))
        },
        || "no exact ptrace denial observed".to_owned(),
    )?;

    fs::write(env.work().join("release"), b"release\n")?;
    let status = actor.wait_exit("denied ptrace", Duration::from_secs(5))?;
    assert_eq!(status.code(), Some(libc::EACCES), "{:?}", actor.stderr()?);
    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc)]
#[lifecycle = identity]
fn signal_zero_is_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("process-signal-zero")?;
    env.start_control()?;
    env.stop_node()?;
    let mut actor = env.start_actor("process_control.py", &["signal-zero"])?;
    env.install_policy("process_control_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(actor.id())?;
    let parent = env.recovered(actor.id(), "signal controller")?;
    actor.ensure_running("recovered signal actor")?;

    fs::write(env.work().join("spawn"), b"spawn\n")?;
    let pid = actor.wait_child(actor.id(), "signal target")?;
    actor.track(pid)?;
    let target = env.task(pid, "signal target identity")?;
    let parent_state = &parent.snapshot;
    let target_state = &target.snapshot;
    assert_eq!(
        target_state.creator_task_cookie,
        Some(parent_state.task_cookie)
    );
    assert_eq!(
        target_state.profile_generation_ref_id,
        parent_state.profile_generation_ref_id
    );
    assert_eq!(target_state.active_role_id, parent_state.active_role_id);
    assert_ne!(target_state.task_cookie, parent_state.task_cookie);
    assert_ne!(target_state.process_state_id, parent_state.process_state_id);

    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    fs::write(env.work().join("act"), b"act\n")?;
    let result = actor.wait_text(&env.work().join("control-result"), "signal result")?;
    assert_eq!(result.trim(), "0");

    let path = env.maps().0.to_owned();
    wait_for(
        &path,
        "allowed signal evidence",
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
                    && parent.matches_effect(
                        event,
                        "EXACT_POLICY_ALLOW",
                        F::Privilege,
                        O::Signal,
                        0,
                    )
                    && event.operation_argument == 0
                    && event.profile_generation_ref_id == parent_state.profile_generation_ref_id
                    && event.controller_process_state_id == parent_state.process_state_id
                    && event.process_state_vector_id > 0
                    && event.target_task_cookie == target_state.task_cookie
                    && event.target_profile_generation_ref_id
                        == target_state.profile_generation_ref_id
                    && event.target_role_id == target_state.active_role_id
                    && event.target_process_state_id == target_state.process_state_id
                    && event.target_process_state_vector_id > 0
            }))
        },
        || "no exact signal allow observed".to_owned(),
    )?;

    fs::write(env.work().join("release"), b"release\n")?;
    let status = actor.wait_exit("allowed signal", Duration::from_secs(5))?;
    assert_eq!(status.code(), Some(0), "{:?}", actor.stderr()?);
    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn unmatched_ptrace_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("process-ptrace-unmatched")?;
    env.start_control()?;
    env.stop_node()?;
    let mut init = env.start_actor("ready.py", &[])?;
    env.place(init.id())?;
    let args = [
        "/fixtures/process_control.py",
        "/work",
        "ptrace",
        "no-result",
    ];
    let mut actor = env.add_actor("python", &args)?;
    env.place(actor.id())?;
    env.install_policy("python_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "ptrace workload")?;
    let parent = env.task(actor.id(), "ptrace controller")?;
    let root = parent.snapshot.root_class.as_deref();
    assert_eq!(root, Some("restored_or_unknown_root"));
    assert_eq!(parent.snapshot.admitted_entry_rule_id, 0);

    fs::write(env.work().join("spawn"), b"spawn\n")?;
    let pid = actor.wait_child(actor.id(), "ptrace target")?;
    actor.track(pid)?;
    let target = env.task(pid, "ptrace target identity")?;
    let parent_state = &parent.snapshot;
    let target_state = &target.snapshot;
    assert_eq!(
        target_state.creator_task_cookie,
        Some(parent_state.task_cookie)
    );
    assert_eq!(target_state.active_role_id, parent_state.active_role_id);
    assert_ne!(target_state.task_cookie, parent_state.task_cookie);
    assert_ne!(target_state.process_state_id, parent_state.process_state_id);
    let path = env.maps().0.to_owned();
    fs::write(env.work().join("act"), b"act\n")?;
    let comm = std::path::PathBuf::from(format!("/proc/{}/comm", actor.id()));
    let expected = format!("ptrace-{}", libc::EACCES);
    let state = RefCell::new(String::from("<unread>"));
    wait_for(
        &comm,
        "ptrace completion",
        Duration::from_secs(5),
        || {
            let value = fs::read_to_string(&comm).unwrap_or_else(|error| format!("<{error}>"));
            *state.borrow_mut() = value.clone();
            Ok((value.trim() == expected).then_some(()))
        },
        || format!("last task name: {}", state.borrow()),
    )?;
    let last = RefCell::new(BTreeSet::new());
    let effect = wait_for(
        &path,
        "unmatched ptrace evidence",
        Duration::from_secs(30),
        || {
            let snapshot = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            last.borrow_mut().extend(
                snapshot
                    .recent_effects
                    .iter()
                    .filter(|event| event.operation == O::Ptrace as u32)
                    .filter(|event| event.operation_argument != 9)
                    .map(|event| format!("{event:?}")),
            );
            Ok(snapshot.recent_effects.into_iter().find(|event| {
                parent.matches_effect(
                    event,
                    "UNSUPPORTED_OBJECT",
                    F::Privilege,
                    O::Ptrace,
                    -libc::EACCES,
                ) && event.operation_argument == 18
                    && event.controller_process_state_id == parent_state.process_state_id
                    && event.target_task_cookie == target_state.task_cookie
                    && event.target_role_id == target_state.active_role_id
                    && event.target_process_state_id == target_state.process_state_id
            }))
        },
        || format!("non-recovery ptrace effects: {:?}", last.borrow()),
    );

    fs::write(env.work().join("release"), b"release\n")?;
    actor.wait_gone(actor.id(), "unmatched ptrace exit")?;
    actor.stop()?;
    effect?;
    init.stop()?;
    env.stop()
}
