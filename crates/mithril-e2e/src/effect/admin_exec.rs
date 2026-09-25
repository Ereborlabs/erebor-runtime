use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{
    ExecutionApprovalSlotStateV1, ExecutionArgvChunkKeyV1, ExecutionArgvChunkV1,
    KernelEffectFamilyV1, KernelEffectOperationV1,
    EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1,
    EXECUTION_APPROVAL_TRACE_STAGE_EXECVEAT_ENTRY_V1,
    EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1,
};
use zerocopy::IntoBytes as _;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn approved_exec_consumes_once<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("admin-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_sleep_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let root = env.task(init.id(), "administrative target")?;

    let unapproved = match env.add_actor("sleep", &["0.5"]) {
        Err(error) => error,
        Ok(_) => return Err("unapproved administrative exec succeeded".into()),
    };
    let denied = unapproved.to_string().to_lowercase();
    assert!(
        denied.contains("status: 13")
            || denied.contains("exit code 13")
            || denied.contains("permission denied"),
        "unapproved actor did not reach runtime enforcement: {denied}"
    );

    env.node_ready()?;
    env.approve("sleep", &["0.5"])?;
    let mismatch = match env.add_actor("sleep", &["1"]) {
        Err(error) => error,
        Ok(_) => return Err("argv-mismatched administrative exec succeeded".into()),
    };
    let denied = mismatch.to_string().to_lowercase();
    assert!(
        denied.contains("status: 13")
            || denied.contains("denied")
            || denied.contains("400 bad request")
            || denied.contains("403 forbidden"),
        "{denied}"
    );

    let mut actor = env.add_actor("sleep", &["0.5"])?;
    let consumed = env.approval(&root)?.ok_or("consumed slot is missing")?;
    let task = env.task(actor.id(), "approved administrative actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("approved_administrative_role"),
        "approval: {consumed:?}; task: {:?}",
        task.snapshot
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 3);
    assert_eq!(
        task.snapshot.profile_generation_ref_id,
        root.snapshot.profile_generation_ref_id
    );
    assert_eq!(
        consumed.state,
        ExecutionApprovalSlotStateV1::Consumed,
        "task: {:?}",
        task.snapshot
    );

    actor.close();
    assert_eq!(
        actor
            .wait_exit("approved administrative actor", Duration::from_secs(30))?
            .code(),
        Some(0)
    );
    env.wait_slot(&root)?;
    for chunk_index in 0..consumed.expected_argv.chunk_count {
        let key = ExecutionArgvChunkKeyV1 {
            snapshot_id: consumed.expected_argv.snapshot_id,
            chunk_index,
            reserved: 0,
        };
        assert!(env
            .state::<ExecutionArgvChunkV1>(
                "execution_argv_expected_chunks",
                key.as_bytes(),
                "expected argv chunk",
            )?
            .is_none());
    }
    assert!(env.add_actor("sleep", &["0.5"]).is_err());
    init.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn consumed_exec_is_restricted<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("admin-replay")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_sleep_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let root = env.task(init.id(), "administrative target")?;
    env.approve("sleep", &["0.5"])?;
    let mut actor = env.add_actor("sleep", &["0.5"])?;
    actor.close();
    assert_eq!(
        actor
            .wait_exit("approved administrative actor", Duration::from_secs(30))?
            .code(),
        Some(0)
    );
    env.wait_slot(&root)?;
    let since = env
        .snapshot()?
        .recent_effects
        .iter()
        .map(|event| event.observed_boottime_ns)
        .max()
        .unwrap_or_default();
    assert!(env.add_actor("sleep", &["0.5"]).is_err());

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let effect = wait_for(
        &path,
        "restricted administrative replay",
        Duration::from_secs(30),
        || {
            let events = env
                .snapshot()
                .map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?
                .recent_effects;
            *last.borrow_mut() = format!("{:?}", events.iter().rev().take(16).collect::<Vec<_>>());
            Ok(events.into_iter().find(|event| {
                event.observed_boottime_ns > since
                    && event.reason == "UNSUPPORTED_OBJECT"
                    && event.effect_family == KernelEffectFamilyV1::Exec as u32
                    && event.operation == KernelEffectOperationV1::Execute as u32
                    && event.kernel_result == -libc::EACCES
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(effect.reason, "UNSUPPORTED_OBJECT");
    assert_eq!(effect.effect_family, KernelEffectFamilyV1::Exec as u32);
    assert_eq!(effect.operation, KernelEffectOperationV1::Execute as u32);
    assert_eq!(effect.active_role_id, 2);
    assert_eq!(effect.admitted_entry_rule_id, 0);
    assert_eq!(effect.kernel_result, -libc::EACCES);
    init.stop()?;
    env.stop()
}

#[platform_test(host, runc)]
#[lifecycle = identity]
fn approval_argv_mismatch_traced<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("admin-argv")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_sleep_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let root = env.task(init.id(), "administrative target")?;
    env.approve("sleep", &["0.5"])?;
    let armed = env.approval(&root)?.ok_or("approval slot is missing")?;
    assert_eq!(armed.state, ExecutionApprovalSlotStateV1::Armed);
    assert!(armed.expected_argv.is_valid() && armed.expected_argv.chunk_count == 1);
    let chunk = ExecutionArgvChunkKeyV1 {
        snapshot_id: armed.expected_argv.snapshot_id,
        chunk_index: 0,
        reserved: 0,
    };
    let chunk_exists = |env: &P| {
        env.state::<ExecutionArgvChunkV1>(
            "execution_argv_expected_chunks",
            chunk.as_bytes(),
            "expected argv chunk",
        )
        .map(|chunk| chunk.is_some())
    };
    assert!(chunk_exists(&env)?);
    if env.add_actor("sleep", &["1"]).is_ok() {
        return Err("argv-mismatched administrative exec succeeded".into());
    }
    let armed = env.approval(&root)?.ok_or("approval slot disappeared")?;
    assert_eq!(armed.state, ExecutionApprovalSlotStateV1::Armed);
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let (trace, denied) = wait_for(
        &path,
        "administrative argv mismatch trace",
        Duration::from_secs(30),
        || {
            let events = env
                .snapshot()
                .map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?
                .recent_effects;
            *last.borrow_mut() = format!("{:?}", events.iter().rev().take(16).collect::<Vec<_>>());
            let trace = events.iter().find(|event| {
                event.execution_approval_failed_checks
                    == EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1
                    && event.execution_approval_slot_state
                        == ExecutionApprovalSlotStateV1::Armed as u32
            });
            let denied = trace.and_then(|trace| {
                events.iter().find(|event| {
                    event.task_cookie == trace.task_cookie
                        && event.reason == "UNSUPPORTED_OBJECT"
                        && event.effect_family == KernelEffectFamilyV1::Exec as u32
                        && event.operation == KernelEffectOperationV1::Execute as u32
                })
            });
            Ok(trace.cloned().zip(denied.cloned()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert!(trace.execution_approval_exec_attempt_sequence > 0);
    assert!(
        trace.execution_approval_trace_stage
            == u32::from(EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1)
            || trace.execution_approval_trace_stage
                == u32::from(EXECUTION_APPROVAL_TRACE_STAGE_EXECVEAT_ENTRY_V1)
    );
    let expected = (
        trace.execution_approval_expected_mount_namespace_inode,
        trace.execution_approval_expected_mount_id,
        trace.execution_approval_expected_filesystem_device,
        trace.execution_approval_expected_inode,
        trace.execution_approval_expected_inode_generation,
    );
    let observed = (
        trace.execution_approval_observed_mount_namespace_inode,
        trace.execution_approval_observed_mount_id,
        trace.execution_approval_observed_filesystem_device,
        trace.execution_approval_observed_inode,
        trace.execution_approval_observed_inode_generation,
    );
    assert!(expected.0 > 0);
    assert_eq!(expected, observed);
    assert_eq!(denied.active_role_id, 2);
    assert_eq!(denied.admitted_entry_rule_id, 0);
    assert_eq!(denied.kernel_result, -libc::EACCES);
    assert!(env.pending_exec(trace.task_cookie)?.is_none());
    assert!(chunk_exists(&env)?);
    init.stop()?;
    env.stop()
}
