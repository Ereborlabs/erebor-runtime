use std::iter;
use std::time::Duration;

use erebor_interceptor_abi::TaskCoordinateStateV1;
use rustix::io::Errno;

use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc)]
fn moved_parent_fork_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-fork")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let mut actor =
        ProcessFixture::python(env.source(), "moved_parent_fork.py", iter::empty::<&str>())?;
    env.place(actor.id())?;

    let before = env.task(actor.id(), "fork actor identity")?;
    assert_eq!(before.snapshot.creator_task_cookie, None);
    assert_eq!(
        before.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        before.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);

    let old = env.health()?;
    let moved = env.move_task(actor.id(), "moved parent fail closed")?;
    let changed = env.health()?;
    assert_eq!(moved.snapshot.task_cookie, before.snapshot.task_cookie);
    assert_eq!(moved.snapshot.creator_task_cookie, None);
    assert_eq!(moved.snapshot.root_class, before.snapshot.root_class);
    assert_eq!(
        moved.snapshot.installed_role_class,
        before.snapshot.installed_role_class
    );
    assert_eq!(
        moved.snapshot.active_role_id,
        before.snapshot.active_role_id
    );
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    assert!(changed.placement_mismatches > old.placement_mismatches);

    actor.send(b"fork\n")?;
    let code = env.actor_code(&mut actor, "moved parent fork", Duration::from_secs(5))?;
    assert_eq!(code, Errno::ACCESS.raw_os_error());
    assert!(env.health()?.placement_mismatches > changed.placement_mismatches);

    actor.stop()?;
    init.stop()?;
    env.stop()
}
