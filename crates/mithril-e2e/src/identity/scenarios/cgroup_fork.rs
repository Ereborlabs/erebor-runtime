use std::path::Path;
use std::time::Duration;

use erebor_interceptor_abi::{
    ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[scope = "identity"]
fn unmoved_first_open_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-open-control")?;
    let path = Path::new("/etc/hostname");
    env.start_control()?;
    env.start_node()?;
    env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start_with_root_first_effect(&group, path)?;
    let pid = actor.root_pid();
    let task = env.task(pid, "unmoved root identity")?;

    assert_eq!(task.snapshot.creator_task_cookie, None);
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(task.snapshot.active_role_id, 0);
    assert_eq!(task.coordinate.state, TaskCoordinateStateV1::Runnable);

    actor.release_root()?;
    wait_for(
        path,
        "unmoved first open",
        Duration::from_secs(5),
        || actor.root_first_effect_allowed(),
        || format!("clone root PID {pid} is still running"),
    )?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}

#[platform_test(host)]
#[scope = "identity"]
fn child_first_open_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-child-open")?;
    let path = Path::new("/etc/hostname");
    env.start_control()?;
    env.start_node()?;
    env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start_with_native_child_first_effect(&group, path)?;
    let root_pid = actor.root_pid();

    let root = env.task(root_pid, "first-effect root")?;
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(root.snapshot.active_role_id, 0);
    assert_eq!(root.coordinate.state, TaskCoordinateStateV1::Runnable);

    actor.release_root()?;
    let pid = wait_for(
        &group,
        "native child creation",
        Duration::from_secs(5),
        || actor.child_pid(),
        || format!("clone root PID {root_pid} has no child"),
    )?;
    let child = env.task(pid, "first-effect child")?;
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(
        child.snapshot.real_parent_task_cookie,
        root.snapshot.task_cookie
    );
    assert_eq!(child.snapshot.root_class, None);
    assert_eq!(child.snapshot.installed_role_class, None);
    assert_eq!(child.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(child.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(
        child.snapshot.process_execution_state,
        ProcessExecutionStateV1::Active as u8
    );
    assert_eq!(
        child.snapshot.process_state_vector_state,
        ProcessStateVectorStateV1::Active as u8
    );

    actor.release_child_first_effect()?;
    wait_for(
        path,
        "native child first open",
        Duration::from_secs(5),
        || actor.native_child_first_effect_allowed(),
        || format!("native child PID {pid} did not report its first open"),
    )?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}

#[platform_test(host)]
#[scope = "identity"]
fn moved_first_open_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-open-denial")?;
    let path = Path::new("/etc/hostname");
    env.start_control()?;
    env.start_node()?;
    env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start_with_root_first_effect(&group, path)?;
    let pid = actor.root_pid();

    let before = env.task(pid, "root before movement")?;
    assert_eq!(before.snapshot.creator_task_cookie, None);
    assert_eq!(
        before.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        before.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(before.snapshot.active_role_id, 0);
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);

    let old = env.health()?;
    let moved = env.move_task(pid, "moved root fail closed")?;
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

    actor.release_root()?;
    wait_for(
        path,
        "moved first open denial",
        Duration::from_secs(5),
        || actor.moved_root_first_effect_denied(),
        || format!("clone root PID {pid} is still running"),
    )?;
    assert!(env.health()?.placement_mismatches > changed.placement_mismatches);

    actor.stop()?;
    init.stop()?;
    env.stop()
}

#[platform_test(host)]
#[scope = "identity"]
fn moved_root_stops<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-stop")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start(&group)?;
    let pid = actor.root_pid();

    let moved = env.move_task(pid, "moved root cleanup")?;
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    init.stop()?;
    env.stop()
}

#[platform_test(host)]
#[scope = "cgroup-fork"]
fn moved_parent_fork_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-fork")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("external_read_policy.json")?;
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

    actor.stop()?;
    init.stop()?;
    env.stop()
}
