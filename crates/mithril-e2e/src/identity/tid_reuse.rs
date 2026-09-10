mod result;

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::time::Duration;

pub(super) use result::read;

#[cfg(test)]
use erebor_interceptor_abi::{
    ReferenceTombstoneStateV1, TaskCoordinateStateV1, TASK_REFERENCE_ALL_V1,
};

#[cfg(test)]
use self::result::ReuseResult;
#[cfg(test)]
use crate::platform::{platform_test, Platform, TestResult};

#[cfg(test)]
#[platform_test(host, runc, kubernetes)]
fn tid_reuse_is_fresh<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("tid-reuse")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut actor = env.start_actor("native_tid_reuse.py", &[])?;

    let root_pid = actor.id();
    actor.track(root_pid)?;
    env.place(root_pid)?;
    env.stage()?;
    env.admit(root_pid)?;
    let root = env.task(root_pid, "TID namespace root")?;

    let first_id = env.next_id()?;
    actor.send(b"first\n")?;
    let first_ns = actor.wait_pid(&env.work().join("first"), "first namespace TID")?;
    let first_tid = actor.wait_thread(first_ns, "first host TID")?;
    let first = env.thread(first_tid, first_ns, first_id, "first thread identity")?;
    assert_eq!(first.coordinate.task_cookie, first_id);
    assert_eq!(env.next_id()?, first_id + 2);
    fs::write(env.work().join("release-first"), b"release\n")?;
    let first_exit = env.task_exit(first_id, "first thread exit")?;
    assert_eq!(first_exit.state, TaskCoordinateStateV1::Exited);

    let second_id = env.next_id()?;
    actor.send(b"second\n")?;
    let second_ns = actor.wait_pid(&env.work().join("second"), "second namespace TID")?;
    let second_tid = actor.wait_thread(second_ns, "second host TID")?;
    let second = env.thread(second_tid, second_ns, second_id, "second thread identity")?;
    assert_eq!(second.coordinate.task_cookie, second_id);
    assert_eq!(env.next_id()?, second_id + 2);
    fs::write(env.work().join("release-second"), b"release\n")?;
    let status = actor.wait_exit("TID actor exit", Duration::from_secs(5))?;
    assert!(status.success(), "actor exited with {status}");
    let released = env.task_release(second_id, "second thread release")?;
    assert_eq!(released.task_free_observed, 1);
    assert_eq!(released.released_bits, TASK_REFERENCE_ALL_V1);
    assert_eq!(released.state, ReferenceTombstoneStateV1::Released);

    let result = ReuseResult::new(first_ns, second_ns, root, first, second);
    result.assert_fresh();
    result.write(&env.output().join("tid-reuse.json"))?;
    env.stop()
}
