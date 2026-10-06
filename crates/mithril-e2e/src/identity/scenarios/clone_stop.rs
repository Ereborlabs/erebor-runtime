use std::path::Path;

use erebor_interceptor_abi::TaskCoordinateStateV1;

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn moved_root_stops<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clone-root-stop")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;

    let script = actor_script(env.source(), "clone_cgroup.py")?;
    let file = Path::new("/etc/hostname");
    let path = env.work().join("clone.pid");
    let group = init.group_path().ok_or("missing actor cgroup")?;
    let mut actor = ProcessFixture::python(
        &script,
        [group.as_os_str(), file.as_os_str(), path.as_os_str()],
    )?;
    let launcher = actor.id();
    let pid = actor.wait_pid(&path, "clone root PID")?;
    actor.set_actor(pid)?;
    let before = env.task(pid, "root before movement")?;
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);
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

    let moved = env.move_task(pid, "moved root cleanup")?;
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
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

    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    assert!(!Path::new(&format!("/proc/{launcher}")).exists());
    init.ensure_running("initial actor after root cleanup")?;
    init.stop()?;
    env.stop()
}
