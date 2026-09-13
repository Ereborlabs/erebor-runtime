use std::{fs, time::Duration};

use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

use crate::platform::{platform_test, Platform, Task, TestResult};

#[platform_test(host, runc, kubernetes)]
fn orphan_keeps_identity<P: Platform>() -> TestResult<()> {
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
    let mut env = P::setup("orphan")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor = env.add_actor("native_orphan.py", &[])?;

    let parent_pid = actor.id();
    assert_ne!(parent_pid, init.id());
    env.place(parent_pid)?;
    let initial = env.task(init.id(), "initial actor identity")?;
    let parent = env.task(parent_pid, "orphan parent identity")?;
    assert_eq!(
        parent.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        parent.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(
        parent.snapshot.active_role_id,
        initial.snapshot.active_role_id
    );
    active(&parent);

    fs::write(env.work().join("orphan-fork"), b"fork\n")?;
    let child_pid = actor.wait_child(parent_pid, "orphan child host PID")?;
    actor.track(child_pid)?;
    let before = env.task(child_pid, "orphan child identity")?;
    let pre = &before.snapshot;
    assert_ne!(before.ns_pid, 1);
    assert_eq!(pre.creator_task_cookie, Some(parent.snapshot.task_cookie));
    assert_eq!(pre.real_parent_task_cookie, parent.snapshot.task_cookie);
    assert_eq!(pre.real_parent_host_tid, parent.snapshot.host_tid);
    assert_eq!(pre.real_parent_host_tgid, parent.snapshot.host_tgid);
    assert_eq!(pre.active_role_id, parent.snapshot.active_role_id);
    assert!(pre.root_class.is_none());
    assert!(pre.installed_role_class.is_none());
    active(&before);

    fs::write(env.work().join("orphan-exit"), b"exit\n")?;
    assert!(actor
        .wait_exit("orphan parent exit", Duration::from_secs(30))?
        .success());
    let after = env.wait_exec(
        &mut actor,
        child_pid,
        pre.task_cookie,
        &before,
        "orphan child exec",
    )?;
    let post = &after.snapshot;
    assert_eq!(post.task_cookie, pre.task_cookie);
    assert_eq!(post.creator_task_cookie, pre.creator_task_cookie);
    assert_ne!(post.real_parent_task_cookie, pre.real_parent_task_cookie);
    assert!(post.real_parent_interval_sequence > pre.real_parent_interval_sequence);
    assert_ne!(post.active_execution_id, pre.active_execution_id);
    assert_eq!(post.active_role_id, pre.active_role_id);
    assert!(post.root_class.is_none());
    assert!(post.installed_role_class.is_none());
    active(&after);

    actor.stop()?;
    init.stop()?;
    env.stop()
}
