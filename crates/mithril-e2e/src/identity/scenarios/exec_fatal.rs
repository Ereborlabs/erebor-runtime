use std::time::Duration;

use erebor_interceptor_abi::{
    ExecGuardStateV1, PendingExecStateV1, ProcessExecutionStateV1, ProcessSecurityStateKindV1,
    ReferenceTombstoneStateV1, TaskCoordinateStateV1, TASK_REFERENCE_ALL_V1,
};

use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
fn fatal_exec_is_terminal<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("fatal-exec")?;
    let target = env.work().join("post-ponr-execfail");
    ProcessFixture::fatal_exec(&target)?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_fatal_exec.py", &["/work/post-ponr-execfail"])?;

    let root_pid = actor.id();
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "fatal exec root")?;
    actor.send(b"root\n")?;

    let ns_pid = actor.wait_pid(&env.work().join("fatal-child"), "fatal exec child")?;
    let pid = actor.wait_child(root_pid, "fatal exec host PID")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "fatal exec stop")?;
    let before = env.task(pid, "fatal exec identity")?;
    let pre = &before.snapshot;
    assert_eq!(before.ns_pid, ns_pid);
    assert_eq!(pre.creator_task_cookie, Some(root.snapshot.task_cookie));
    assert_eq!(pre.active_role_id, root.snapshot.active_role_id);
    assert_eq!(pre.exec_guard_state, ExecGuardStateV1::None as u8);
    assert!(!env.pending(pre.task_cookie)?);

    actor.send(b"continue\n")?;
    let status = actor.wait_exit("fatal exec", Duration::from_secs(30))?;
    assert!(!status.success(), "fatal exec actor returned {status}");
    actor.wait_gone(pid, "fatal exec task removal")?;
    let coord = env.task_exit(pre.task_cookie, "fatal exec exit")?;
    let tomb = env.task_release(pre.task_cookie, "fatal exec release")?;
    let pending = env
        .pending_exec(pre.task_cookie)?
        .ok_or("fatal pending exec is missing")?;
    let process = env.process(&pre.process_state_id)?;
    let source = env.execution(pending.source_execution_id)?;
    let target = env.execution(pending.target_execution_id)?;

    assert_eq!(pending.state, PendingExecStateV1::PostPonrFatal);
    assert_eq!(process.exec_guard_state, ExecGuardStateV1::OutcomeUnknown);
    assert_eq!(process.state, ProcessSecurityStateKindV1::Reclaimable);
    assert_eq!(process.live_thread_refs, 0);
    assert_eq!(coord.state, TaskCoordinateStateV1::Exited);
    assert_eq!(tomb.task_free_observed, 1);
    assert_eq!(tomb.released_bits, TASK_REFERENCE_ALL_V1);
    assert_eq!(tomb.state, ReferenceTombstoneStateV1::Released);
    assert_eq!(source.state, ProcessExecutionStateV1::Complete);
    assert_eq!(target.state, ProcessExecutionStateV1::OutcomeUnknown);
    assert_eq!(process.active_role_id, pre.active_role_id);
    assert_eq!(process.active_execution_id, pending.source_execution_id);
    assert_eq!(pending.source_role_id, pre.active_role_id);
    assert_eq!(coord.task_cookie, pre.task_cookie);
    assert_eq!(tomb.task_cookie, pre.task_cookie);
    assert_eq!(
        source.process_execution_instance_id,
        pending.source_execution_id
    );
    assert_eq!(
        target.process_execution_instance_id,
        pending.target_execution_id
    );

    actor.stop()?;
    env.stop()
}
