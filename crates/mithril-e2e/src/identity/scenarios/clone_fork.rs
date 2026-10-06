use std::{fs, path::Path, time::Duration};

use erebor_interceptor_abi::{ExecutionSetBindingStateV1, TaskCoordinateStateV1};

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn moved_parent_fork_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clone-fork-denial")?;
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
    let pid = actor.wait_pid(&path, "clone root PID")?;
    actor.set_actor(pid)?;
    let before = env.task(pid, "root before movement")?;
    let root = &before.snapshot;
    assert_eq!(root.creator_task_cookie, None);
    assert_eq!(root.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        root.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(root.active_role_id, 0);
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);
    let key = root
        .runtime_binding
        .as_ref()
        .ok_or("missing runtime binding")?
        .root_cgroup_id
        .to_ne_bytes();
    let binding = env
        .state::<ExecutionSetBindingStateV1>("execution_set_bindings", &key, "clone binding")?
        .ok_or("missing clone binding")?;
    assert_eq!(root.active_role_id, binding.external_role_id);

    let old = env.health()?;
    let moved = env.move_task(pid, "moved parent fail closed")?;
    let changed = env.health()?;
    let now = &moved.snapshot;
    assert_eq!(now.task_cookie, root.task_cookie);
    assert_eq!(now.creator_task_cookie, root.creator_task_cookie);
    assert_eq!(now.root_class, root.root_class);
    assert_eq!(now.installed_role_class, root.installed_role_class);
    assert_eq!(now.active_role_id, root.active_role_id);
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    assert!(changed.placement_mismatches > old.placement_mismatches);

    actor.send(b"fork\n")?;
    let status = actor.wait_exit("moved parent fork", Duration::from_secs(5))?;
    assert_eq!(
        status.code(),
        Some(libc::EACCES),
        "{status}; stderr: {:?}",
        actor.stderr()?
    );
    assert_eq!(
        fs::read_to_string(path.with_extension("fork"))?.trim(),
        "-1",
        "native fork created a child"
    );
    assert!(env.health()?.placement_mismatches > changed.placement_mismatches);

    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    init.stop()?;
    env.stop()
}
