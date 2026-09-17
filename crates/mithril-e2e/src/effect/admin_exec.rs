use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{
    ExecutionApprovalSlotStateV1, EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1,
};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
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
    assert!(denied.contains("status: 13") || denied.contains("permission denied"));

    env.approve("sleep", &["0.5"])?;
    let armed = env.approval(&root)?.ok_or("approval slot is missing")?;
    assert_eq!(armed.state, ExecutionApprovalSlotStateV1::Armed);

    let mismatch = match env.add_actor("sleep", &["1"]) {
        Err(error) => error,
        Ok(_) => return Err("argv-mismatched administrative exec succeeded".into()),
    };
    let denied = mismatch.to_string().to_lowercase();
    assert!(denied.contains("status: 13") || denied.contains("permission denied"));
    assert_eq!(
        env.approval(&root)?
            .ok_or("approval slot disappeared")?
            .state,
        ExecutionApprovalSlotStateV1::Armed
    );

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    let trace = wait_for(
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
            Ok(events.into_iter().find(|event| {
                event.execution_approval_failed_checks
                    == EXECUTION_APPROVAL_TRACE_FAILURE_PREPARE_ARGV_V1
                    && event.execution_approval_slot_state
                        == ExecutionApprovalSlotStateV1::Armed as u32
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert!(trace.execution_approval_exec_attempt_sequence > 0);

    let mut actor = env.add_actor("sleep", &["0.5"])?;
    let task = env.task(actor.id(), "approved administrative actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("approved_administrative_role")
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.snapshot.active_role_id, 3);
    assert_eq!(
        env.approval(&root)?
            .ok_or("consumed slot is missing")?
            .state,
        ExecutionApprovalSlotStateV1::Consumed
    );

    actor.stop()?;
    env.wait_slot(&root)?;
    assert!(env.add_actor("sleep", &["0.5"]).is_err());
    init.stop()?;
    env.stop()
}
