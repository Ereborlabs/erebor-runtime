use crate::platform::{platform_test, Platform, Task, TestResult};
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

#[platform_test(host, runc, kubernetes)]
fn child_exec_keeps_identity<P: Platform>() -> TestResult<()> {
    let active = |task: &Task| {
        let state = &task.snapshot;
        assert_eq!(
            (
                state.process_execution_state,
                state.process_state_vector_state,
                task.coordinate.state,
                state.exec_guard_state,
            ),
            (
                ProcessExecutionStateV1::Active as u8,
                ProcessStateVectorStateV1::Active as u8,
                TaskCoordinateStateV1::Runnable,
                ExecGuardStateV1::None as u8,
            )
        );
    };
    let mut env = P::setup("child-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_child_exec.py", &[])?;

    let root_pid = actor.id();
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "application parent identity")?;
    let initial = &root.snapshot;
    assert_eq!(initial.creator_task_cookie, None);
    assert_eq!(
        initial.root_class.as_deref(),
        Some("initial_container_root")
    );
    assert_eq!(
        initial.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert!(initial.active_role_id > 0);
    active(&root);

    let next = env.next_id()?;
    let failures = env.health()?.allocation_failures;
    actor.send(b"fork\n")?;
    let ns_pid = actor.wait_pid(&env.work().join("child"), "native child creation")?;
    let pid = actor.wait_child(root_pid, "native child host PID")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "native child stop")?;
    let before = env.task(pid, "native child identity")?;
    let pre = &before.snapshot;
    assert_eq!(before.ns_pid, ns_pid);
    assert_eq!(pre.creator_task_cookie, Some(initial.task_cookie));
    assert_eq!(pre.real_parent_task_cookie, initial.task_cookie);
    assert_ne!(pre.task_cookie, initial.task_cookie);
    assert_eq!(pre.active_role_id, initial.active_role_id);
    assert_eq!(pre.image_provenance_id, initial.image_provenance_id);
    assert_eq!(
        (pre.root_class.as_ref(), pre.installed_role_class.as_ref()),
        (None, None)
    );
    assert!(pre.image_candidate_count > 0 && env.next_id()? > next);
    assert_eq!(env.health()?.allocation_failures, failures);
    active(&before);

    actor.send(b"continue\n")?;
    let after = env.wait_exec(&mut actor, pid, &before, "native child exec")?;
    let post = &after.snapshot;
    assert_eq!(post.task_cookie, pre.task_cookie);
    assert_eq!(post.creator_task_cookie, pre.creator_task_cookie);
    assert_eq!(post.real_parent_task_cookie, pre.real_parent_task_cookie);
    assert_ne!(post.active_execution_id, pre.active_execution_id);
    assert_ne!(post.image_provenance_id, pre.image_provenance_id);
    assert_eq!(post.active_role_id, pre.active_role_id);
    active(&after);

    actor.stop()?;
    env.stop()
}
