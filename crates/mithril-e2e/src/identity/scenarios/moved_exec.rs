use std::time::Duration;

use erebor_interceptor_abi::TaskCoordinateStateV1;
use rustix::io::Errno;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn moved_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("moved-exec")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor = env.add_actor(
        "python",
        &["/fixtures/native_moved_exec.py", "/work", "/usr/bin/true"],
    )?;

    let root_pid = actor.id();
    let root = env.task(root_pid, "moved actor root")?;
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
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
    actor.close();
    let code = actor
        .wait_exit("moved exec denial", Duration::from_secs(5))?
        .code()
        .ok_or("the actor exited without an exit code")?;
    assert_eq!(code, Errno::ACCESS.raw_os_error());
    let denied = env.health()?;
    assert!(denied.placement_mismatches > move_health.placement_mismatches);
    actor.stop()?;
    init.stop()?;
    env.stop()
}
