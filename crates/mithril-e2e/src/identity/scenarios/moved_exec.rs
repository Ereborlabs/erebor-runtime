use std::time::Duration;

use erebor_interceptor_abi::TaskCoordinateStateV1;
use rustix::io::Errno;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
fn moved_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("moved-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_moved_exec.py", &["/usr/bin/true"])?;

    let root_pid = actor.id();
    actor.track(root_pid)?;
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "moved actor root")?;
    actor.send(b"start\n")?;

    let ns_pid = actor.wait_pid(&env.work().join("moved-child"), "moved child")?;
    let pid = actor.wait_child(root_pid, "moved child host PID")?;
    actor.track(pid)?;
    let before = env.task(pid, "moved child identity")?;
    assert_eq!(before.ns_pid, ns_pid);
    assert_eq!(
        before.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(
        before.snapshot.real_parent_task_cookie,
        root.snapshot.task_cookie
    );
    assert_ne!(before.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);

    let old = env.health()?;
    let moved = env.move_task(pid, "moved child fail closed")?;
    let move_health = env.health()?;
    assert_eq!(moved.snapshot.task_cookie, before.snapshot.task_cookie);
    assert_eq!(
        moved.snapshot.creator_task_cookie,
        before.snapshot.creator_task_cookie
    );
    assert_eq!(
        moved.snapshot.real_parent_task_cookie,
        before.snapshot.real_parent_task_cookie
    );
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    assert_eq!(moved.snapshot.root_class, None);
    assert_eq!(moved.snapshot.installed_role_class, None);
    assert!(move_health.placement_mismatches > old.placement_mismatches);

    actor.send(b"exec\n")?;
    let code = env.actor_code(&mut actor, "moved exec denial", Duration::from_secs(5))?;
    assert_eq!(code, Errno::ACCESS.raw_os_error());
    let denied = env.health()?;
    assert!(denied.placement_mismatches > move_health.placement_mismatches);
    env.stop()
}
