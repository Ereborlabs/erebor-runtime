use crate::platform::{platform_test, Platform, Task, TestResult};
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use std::fs;
#[platform_test(host, runc, kubernetes)]
fn double_fork_keeps_identity<P: Platform>() -> TestResult<()> {
    let active = |task: &Task| {
        let got = &task.snapshot;
        assert_eq!(
            (
                got.process_execution_state,
                got.process_state_vector_state,
                task.coordinate.state,
                got.exec_guard_state,
            ),
            (
                ProcessExecutionStateV1::Active as u8,
                ProcessStateVectorStateV1::Active as u8,
                TaskCoordinateStateV1::Runnable,
                ExecGuardStateV1::None as u8,
            ),
        );
    };
    let child = |got: &Task, parent: &Task| {
        assert_eq!(
            (
                got.snapshot.creator_task_cookie,
                got.snapshot.real_parent_task_cookie,
                got.snapshot.real_parent_host_tid,
                got.snapshot.real_parent_host_tgid,
                got.snapshot.active_role_id,
            ),
            (
                Some(parent.snapshot.task_cookie),
                parent.snapshot.task_cookie,
                parent.snapshot.host_tid,
                parent.snapshot.host_tgid,
                parent.snapshot.active_role_id,
            ),
        );
        assert!(got.snapshot.root_class.is_none());
        assert!(got.snapshot.installed_role_class.is_none());
        active(got);
    };
    let mut env = P::setup("double-fork")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor = env.add_actor("double_fork.py", &[])?;
    let root = env.task(actor.id(), "double-fork root")?;
    assert!(root.snapshot.creator_task_cookie.is_none());
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    active(&root);
    fs::write(env.work().join("double-fork-start"), b"start\n")?;
    let mid_pid = actor.wait_child(actor.id(), "double-fork middle")?;
    actor.track(mid_pid)?;
    let child_pid = actor.wait_child(mid_pid, "double-fork child")?;
    actor.track(child_pid)?;
    let middle = env.task(mid_pid, "double-fork middle identity")?;
    let before = env.task(child_pid, "double-fork child identity")?;
    child(&middle, &root);
    child(&before, &middle);
    fs::write(env.work().join("double-fork-exit"), b"exit\n")?;
    actor.wait_gone(mid_pid, "double-fork middle exit")?;
    fs::write(env.work().join("double-fork-exec"), b"exec\n")?;
    let after = env.wait_exec(
        &mut actor,
        child_pid,
        before.snapshot.task_cookie,
        &before,
        "double-fork child exec",
    )?;
    let got = &after.snapshot;
    assert_eq!(got.task_cookie, before.snapshot.task_cookie);
    assert_eq!(got.creator_task_cookie, Some(middle.snapshot.task_cookie));
    assert_ne!(got.real_parent_task_cookie, middle.snapshot.task_cookie);
    assert!(got.real_parent_interval_sequence > before.snapshot.real_parent_interval_sequence);
    assert_ne!(got.active_execution_id, before.snapshot.active_execution_id);
    assert_eq!(got.active_role_id, root.snapshot.active_role_id);
    assert!(got.root_class.is_none() && got.installed_role_class.is_none());
    active(&after);
    init.stop()?;
    actor.stop()?;
    env.stop()
}
