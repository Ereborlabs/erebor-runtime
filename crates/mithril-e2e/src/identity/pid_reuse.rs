mod result;

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::time::Duration;

pub(super) use result::read;

#[cfg(test)]
use self::result::ReuseResult;
#[cfg(test)]
use crate::platform::{platform_test, Platform, TestResult};

#[cfg(test)]
#[platform_test(host, runc, kubernetes)]
fn pid_reuse_is_fresh<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("pid-reuse")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_pid_reuse.py", &[])?;

    let root_pid = actor.id();
    actor.track(root_pid)?;
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    actor.ensure_running("namespace root identity")?;
    let root = env.task(root_pid, "namespace root identity")?;
    actor.send(b"start\n")?;

    let first_ns = actor.wait_pid(&env.work().join("first"), "first namespace PID")?;
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

    let result = ReuseResult::new(first_ns, second_ns, root, first, second);
    result.assert_fresh();
    result.write(&env.output().join("pid-reuse.json"))?;
    env.stop()
}
