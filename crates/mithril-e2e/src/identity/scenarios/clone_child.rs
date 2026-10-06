use std::{path::Path, time::Duration};

use erebor_interceptor_abi::{
    ExecutionSetBindingStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1,
    TaskCoordinateStateV1,
};

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn child_first_open_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clone-child-open")?;
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
    let root_pid = actor.wait_pid(&path, "clone root PID")?;
    actor.set_actor(root_pid)?;
    let parent = env.task(root_pid, "first-effect root")?;
    let root = &parent.snapshot;
    assert_eq!(root.creator_task_cookie, None);
    assert_eq!(root.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        root.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(root.active_role_id, 0);
    assert_eq!(parent.coordinate.state, TaskCoordinateStateV1::Runnable);
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

    actor.send(b"fork\n")?;
    let pid = actor.wait_child(root_pid, "native child creation")?;
    actor.set_actor(pid)?;
    let task = env.task(pid, "first-effect child")?;
    let child = &task.snapshot;
    assert_eq!(child.creator_task_cookie, Some(root.task_cookie));
    assert_eq!(child.real_parent_task_cookie, root.task_cookie);
    assert_eq!(child.root_class, None);
    assert_eq!(child.installed_role_class, None);
    assert_eq!(child.active_role_id, root.active_role_id);
    assert_eq!(task.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(
        child.process_execution_state,
        ProcessExecutionStateV1::Active as u8
    );
    assert_eq!(
        child.process_state_vector_state,
        ProcessStateVectorStateV1::Active as u8
    );

    actor.send(b"open\n")?;
    let status = actor.wait_exit("native child first open", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);

    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    assert!(!Path::new(&format!("/proc/{root_pid}")).exists());
    init.stop()?;
    env.stop()
}
