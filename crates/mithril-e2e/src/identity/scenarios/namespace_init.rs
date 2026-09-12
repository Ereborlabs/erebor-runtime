use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

#[platform_test(host)]
fn namespace_init_reparents_child<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("namespace-init")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_namespace_init.py", &[])?;

    let root_pid = actor.id();
    assert_eq!(ProcessFixture::namespace_pid(root_pid)?, 1);
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "namespace init identity")?;
    let init = &root.snapshot;
    assert_eq!(init.creator_task_cookie, None);
    assert_eq!(init.root_class.as_deref(), Some("initial_container_root"));
    assert_eq!(init.installed_role_class.as_deref(), Some("initial_role"));

    actor.send(b"fork\n")?;
    let mid_pid = actor.wait_pid(&env.work().join("namespace-mid-ready"), "middle process")?;
    actor.track(mid_pid)?;
    actor.wait_stop(mid_pid, "middle process stop")?;
    let middle = env.task(mid_pid, "middle process identity")?;
    let mid = &middle.snapshot;
    assert_eq!(mid.creator_task_cookie, Some(init.task_cookie));
    assert_eq!(mid.real_parent_task_cookie, init.task_cookie);

    actor.send(b"continue\n")?;
    let child_pid = actor.wait_pid(&env.work().join("namespace-exec-ready"), "child process")?;
    actor.track(child_pid)?;
    actor.wait_stop(child_pid, "child process stop")?;
    let before = env.task(child_pid, "child identity")?;
    let pre = &before.snapshot;
    assert_eq!(pre.creator_task_cookie, Some(mid.task_cookie));
    assert_eq!(pre.real_parent_task_cookie, mid.task_cookie);
    assert_eq!(pre.active_role_id, init.active_role_id);

    actor.send(b"reparent\n")?;
    actor.wait_gone(mid_pid, "middle process exit")?;
    env.task_exit(mid.task_cookie, "middle task exit")?;
    let after = env.wait_exec(
        &mut actor,
        child_pid,
        pre.task_cookie,
        &before,
        "reparented child exec",
    )?;
    let post = &after.snapshot;
    assert_eq!(post.creator_task_cookie, pre.creator_task_cookie);
    assert_eq!(post.real_parent_task_cookie, 0);
    assert_eq!(post.real_parent_host_tid, init.host_tid);
    assert_eq!(post.real_parent_host_tgid, init.host_tgid);
    assert_ne!(post.active_execution_id, pre.active_execution_id);
    assert_eq!(post.active_role_id, init.active_role_id);
    assert_eq!(after.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(
        post.process_execution_state,
        ProcessExecutionStateV1::Active as u8
    );
    assert_eq!(
        post.process_state_vector_state,
        ProcessStateVectorStateV1::Active as u8
    );
    assert_eq!(post.exec_guard_state, ExecGuardStateV1::None as u8);

    actor.stop()?;
    env.task_release(mid.task_cookie, "middle task release")?;
    env.stop()
}
