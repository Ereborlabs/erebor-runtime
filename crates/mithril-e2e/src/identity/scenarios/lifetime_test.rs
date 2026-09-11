use std::fs;
use std::time::Duration;

use rustix::process::{pidfd_open, Pid, PidfdFlags};

use super::lifetime_result::LifetimeState;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
fn leader_exit_keeps_worker<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("leader-lifetime")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_leader_first.py", &[])?;

    let root_pid = actor.id();
    actor.track(root_pid)?;
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "leader root identity")?;

    let next = env.next_id()?;
    actor.send(b"root\n")?;
    let worker_ns = actor.wait_pid(&env.work().join("leader-first-ready"), "worker TID")?;
    let worker_pid = actor.wait_thread(worker_ns, "worker host TID")?;
    let worker = env.thread(worker_pid, worker_ns, next, "worker identity")?;
    let pid = Pid::from_raw(i32::try_from(worker_pid)?).ok_or("worker TID is zero")?;

    assert!(pidfd_open(pid, PidfdFlags::empty()).is_err());
    assert_eq!(worker.coordinate.task_cookie, next);
    assert_eq!(worker.coordinate.host_tgid, root.snapshot.host_tgid);
    assert_eq!(
        worker.coordinate.process_state_id,
        root.coordinate.process_state_id
    );
    assert_eq!(worker.edge.creator_task_cookie, root.snapshot.task_cookie);
    assert_eq!(env.next_id()?, next + 2);

    let live = LifetimeState::wait_live(&env, &root, &worker)?;
    live.assert_live(root.snapshot.active_role_id);

    fs::write(env.work().join("leader-first-release"), b"release\n")?;
    let status = actor.wait_exit("worker exit", Duration::from_secs(5))?;
    assert!(status.success(), "actor exited with {status}");
    LifetimeState::wait_dead(&env, &root, &worker)?.assert_dead();
    env.stop()
}
