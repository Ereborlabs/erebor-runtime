use std::time::Duration;

use erebor_interceptor_abi::TaskCoordinateStateV1;

use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
fn moved_parent_fork_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-fork")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start(&group)?;
    let pid = actor.root_pid();

    let before = env.task(pid, "clone actor identity")?;
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
    let moved = env.move_task(pid, "moved parent fail closed")?;
    let changed = env.health()?;
    assert_eq!(moved.snapshot.task_cookie, before.snapshot.task_cookie);
    assert_eq!(moved.snapshot.creator_task_cookie, None);
    assert_eq!(moved.snapshot.root_class, before.snapshot.root_class);
    assert_eq!(
        moved.snapshot.installed_role_class,
        before.snapshot.installed_role_class
    );
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    assert!(changed.placement_mismatches > old.placement_mismatches);

    actor.release_root()?;
    wait_for(
        &group,
        "moved parent fork denial",
        Duration::from_secs(5),
        || actor.moved_parent_fork_denied(),
        || format!("clone root PID {pid} is still running"),
    )?;
    assert!(env.health()?.placement_mismatches > changed.placement_mismatches);

    actor.stop();
    init.stop()?;
    env.stop()
}
