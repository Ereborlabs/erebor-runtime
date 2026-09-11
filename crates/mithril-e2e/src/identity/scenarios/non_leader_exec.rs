use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

use crate::platform::{platform_test, Platform, Task, TestResult};

#[platform_test(host)]
fn non_leader_exec<P: Platform>() -> TestResult<()> {
    let active = |task: &Task| {
        assert_eq!(
            (
                task.snapshot.process_execution_state,
                task.snapshot.process_state_vector_state,
                task.coordinate.state,
                task.snapshot.exec_guard_state,
            ),
            (
                ProcessExecutionStateV1::Active as u8,
                ProcessStateVectorStateV1::Active as u8,
                TaskCoordinateStateV1::Runnable,
                ExecGuardStateV1::None as u8,
            )
        );
    };
    let mut env = P::setup("non-leader-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_non_leader_exec.py", &[])?;

    let root_pid = actor.id();
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "thread-group root identity")?;
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
    active(&root);

    let next = env.next_id()?;
    actor.send(b"root\n")?;
    let ns_tid = actor.wait_pid(&env.work().join("thread"), "non-leader namespace TID")?;
    let tid = actor.wait_thread(ns_tid, "non-leader host TID")?;
    let thread = env.thread(tid, ns_tid, next, "non-leader thread identity")?;
    assert_ne!(tid, root_pid);
    assert_ne!(ns_tid, root.ns_pid);
    assert_eq!((thread.pid, thread.ns_tid), (tid, ns_tid));
    assert_eq!(thread.coordinate.task_cookie, next);
    assert_eq!(thread.coordinate.host_tgid, root_pid);
    assert_eq!(
        thread.coordinate.process_state_id,
        root.coordinate.process_state_id
    );
    assert_eq!(thread.edge.creator_task_cookie, initial.task_cookie);
    let after_id = next.checked_add(2).ok_or("identity ID overflow")?;
    assert_eq!(env.next_id()?, after_id);

    actor.send(b"exec\n")?;
    let after = match env.wait_exec(&mut actor, root_pid, &root, "non-leader thread exec") {
        Ok(after) => after,
        Err(source) => {
            let health = env.health()?;
            return Err(format!("{source}; identity health: {health:?}").into());
        }
    };
    let post = &after.snapshot;
    assert_eq!(post.task_cookie, next);
    assert_eq!(post.creator_task_cookie, Some(initial.task_cookie));
    assert_eq!(post.process_state_id, initial.process_state_id);
    assert_ne!(post.active_execution_id, initial.active_execution_id);
    assert_ne!(post.image_provenance_id, initial.image_provenance_id);
    assert_eq!(post.active_role_id, initial.active_role_id);
    assert_eq!(
        (post.root_class.as_ref(), post.installed_role_class.as_ref()),
        (None, None)
    );
    assert_eq!((post.host_tid, post.host_tgid), (root_pid, root_pid));
    active(&after);

    actor.stop()?;
    env.stop()
}
