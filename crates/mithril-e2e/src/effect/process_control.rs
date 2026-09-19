use std::{collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn protected_ptrace_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("process-ptrace")?;
    env.start_control()?;
    env.stop_node()?;
    let mut actor = env.start_actor("process_ptrace.py", &[])?;
    env.install_policy("process_ptrace_policy.json")?;
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
    fs::write(env.work().join("ptrace"), b"ptrace\n")?;
    let result_path = env.work().join("ptrace-result");
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
