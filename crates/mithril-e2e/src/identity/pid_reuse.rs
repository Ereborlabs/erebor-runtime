#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use crate::platform::{platform_test, Platform, TestResult};

#[cfg(test)]
#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn pid_reuse_is_fresh<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("pid-reuse")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("python_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_pid_reuse.py", &[])?;

    let root_pid = actor.id();
    actor.track(root_pid)?;
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    actor.ensure_running("namespace root identity")?;
    let root = env.task(root_pid, "namespace root identity")?;
    let first_path = env.work().join("first");
    assert!(!first_path.exists(), "actor ran before release");
    fs::write(env.work().join("start"), b"start\n")?;

    let first_ns = actor.wait_pid(&first_path, "first namespace PID")?;
    let first_pid = actor.wait_child(root_pid, "first reused PID")?;
    actor.track(first_pid)?;
    actor.ensure_running("first reused identity")?;
    let first = env.task(first_pid, "first reused identity")?;
    fs::write(env.work().join("release-first"), b"release\n")?;

    let second_ns = actor.wait_pid(&env.work().join("second"), "second namespace PID")?;
    let second_pid = actor.wait_child(root_pid, "second reused PID")?;
    actor.track(second_pid)?;
    actor.ensure_running("second reused identity")?;
    let second = env.task(second_pid, "second reused identity")?;
    fs::write(env.work().join("release-second"), b"release\n")?;
    let status = actor.wait_exit("PID-reuse actor exit", Duration::from_secs(5))?;
    assert!(status.success(), "actor exited with {status}");

    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert!(first_ns > 1);
    assert_eq!(second_ns, first_ns);
    assert_eq!(first.ns_pid, first_ns);
    assert_eq!(second.ns_pid, first_ns);
    assert_ne!(first.pid, second.pid);
    assert_ne!(first.snapshot.task_cookie, second.snapshot.task_cookie);
    assert_ne!(
        first.snapshot.process_state_id,
        second.snapshot.process_state_id
    );
    assert_ne!(
        first.snapshot.active_execution_id,
        second.snapshot.active_execution_id
    );
    assert_eq!(
        first.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(
        second.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(
        first.coordinate.pid_namespace_inode,
        second.coordinate.pid_namespace_inode
    );
    assert_ne!(
        first.coordinate.task_start_boottime_ns,
        second.coordinate.task_start_boottime_ns
    );
    env.stop()
}
