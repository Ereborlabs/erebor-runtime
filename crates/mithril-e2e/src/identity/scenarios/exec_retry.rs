use std::time::Duration;

use crate::platform::{platform_test, Platform, Task, TestResult};
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

#[platform_test(host, runc, kubernetes)]
#[scope = "identity"]
fn failed_exec_restores<P: Platform>() -> TestResult<()> {
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
    let mut env = P::setup("exec-retry")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("exec_retry/policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor = env.add_actor("python", &["/fixtures/native_exec_retry.py", "/work"])?;

    let root_pid = actor.id();
    let root = env.task(root_pid, "exec parent identity")?;
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    active(&root);

    actor.send(b"root\n")?;
    let ns_pid = actor.wait_pid(&env.work().join("child"), "failed exec child")?;
    let pid = actor.wait_child(root_pid, "failed exec host PID")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "pre-exec stop")?;
    let before = env.task(pid, "pre-exec child identity")?;
    let pre = &before.snapshot;
    assert_eq!(before.ns_pid, ns_pid);
    assert_eq!(pre.creator_task_cookie, Some(root.snapshot.task_cookie));
    assert_eq!(pre.real_parent_task_cookie, root.snapshot.task_cookie);
    assert_eq!(pre.active_role_id, root.snapshot.active_role_id);
    assert!(pre.root_class.is_none() && pre.installed_role_class.is_none());
    assert!(!env.pending(pre.task_cookie)?);
    active(&before);

    actor.send(b"continue\n")?;
    let failed = actor.wait_pid(&env.work().join("failed"), "failed exec result")?;
    assert_eq!(failed, ns_pid);
    let restored = env.task(pid, "restored child identity")?;
    let same = &restored.snapshot;
    assert_eq!(same.task_cookie, pre.task_cookie);
    assert_eq!(same.creator_task_cookie, pre.creator_task_cookie);
    assert_eq!(same.real_parent_task_cookie, pre.real_parent_task_cookie);
    assert_eq!(same.active_execution_id, pre.active_execution_id);
    assert_eq!(same.image_provenance_id, pre.image_provenance_id);
    assert_eq!(same.active_role_id, pre.active_role_id);
    assert!(same.root_class.is_none() && same.installed_role_class.is_none());
    assert!(!env.pending(same.task_cookie)?);
    active(&restored);

    actor.wait_stop(pid, "retry exec stop")?;
    actor.send(b"continue\n")?;
    let after = env.wait_exec(&mut actor, pid, pre.task_cookie, &restored, "retry exec")?;
    let post = &after.snapshot;
    assert_eq!(post.task_cookie, same.task_cookie);
    assert_eq!(post.creator_task_cookie, same.creator_task_cookie);
    assert_eq!(post.real_parent_task_cookie, same.real_parent_task_cookie);
    assert_ne!(post.active_execution_id, same.active_execution_id);
    assert_ne!(post.image_provenance_id, same.image_provenance_id);
    assert_eq!(post.active_role_id, same.active_role_id);
    assert!(post.root_class.is_none() && post.installed_role_class.is_none());
    assert!(!env.pending(post.task_cookie)?);
    active(&after);

    let status = actor.wait_exit("failed-exec actor exit", Duration::from_secs(10))?;
    assert!(status.success(), "actor exited with {status}");
    actor.stop()?;
    init.stop()?;
    env.stop()
}
