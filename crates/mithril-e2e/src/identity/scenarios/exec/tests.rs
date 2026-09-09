use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::time::Duration;

use rustix::process::Signal;
use snafu::ResultExt as _;

use crate::error::IoSnafu;
use crate::identity::IdentityTestRunner;
use crate::process::ProcessFixture;

#[test]
fn thread_execs_process() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("thread exec actor"),
    })?;
    let ready = temp.path().join("ready");
    let mut actor = ProcessFixture::python(&root, "native_non_leader_exec.py", [&ready])?;
    let pid = actor.id();

    actor.send(b"root\n")?;
    let tid = actor.wait_pid(&ready, "non-leader thread creation")?;
    assert_ne!(tid, pid);
    assert!(PathBuf::from(format!("/proc/{pid}/task/{tid}")).is_dir());

    actor.send(b"exec\n")?;
    actor.wait_comm(pid, "sleep", "non-leader thread exec")?;
    actor.stop()
}

#[test]
fn child_execs() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("child exec actor"),
    })?;
    let ready = temp.path().join("ready");
    let mut actor = ProcessFixture::python(&root, "native_child_exec.py", [&ready])?;

    actor.send(b"root\n")?;
    let pid = actor.wait_pid(&ready, "native child creation")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "native child stop")?;
    actor.signal(pid, Signal::CONT)?;
    actor.wait_comm(pid, "sleep", "native child exec")?;
    actor.stop()?;
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    Ok(())
}

#[test]
fn threads_race_exec() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("thread race actor"),
    })?;
    let ready = temp.path().join("ready");
    let mut actor = ProcessFixture::python(&root, "native_concurrent_thread_exec.py", [&ready])?;
    let pid = actor.id();

    actor.send(b"root\n")?;
    let [a, b] = actor.wait_pair(&ready, "concurrent thread creation")?;
    assert!(a != pid && b != pid);
    assert!(PathBuf::from(format!("/proc/{pid}/task/{a}")).is_dir());
    assert!(PathBuf::from(format!("/proc/{pid}/task/{b}")).is_dir());

    actor.send(b"exec\n")?;
    actor.wait_comm(pid, "sleep", "concurrent thread exec")?;
    actor.stop()
}

#[test]
fn exec_failure_stops() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("exec failure actor"),
    })?;
    let ready = temp.path().join("ready");
    let failed = temp.path().join("failed");
    let mut actor = ProcessFixture::python(
        &root,
        "native_exec_retry.py",
        [
            &ready,
            &failed,
            std::path::Path::new("/missing-native-exec"),
        ],
    )?;

    actor.send(b"root\n")?;
    let pid = actor.wait_pid(&ready, "failed exec child")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "pre-exec stop")?;
    actor.signal(pid, Signal::CONT)?;
    actor.wait_path(
        &failed,
        "exec failure",
        Duration::from_secs(5),
        || Ok(failed.exists().then_some(())),
        || "the failure marker is absent".to_owned(),
    )?;
    actor.wait_stop(pid, "failed exec stop")?;
    actor.stop()
}

#[test]
fn exec_recovers() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("exec retry actor"),
    })?;
    let ready = temp.path().join("ready");
    let failed = temp.path().join("failed");
    let mut actor = ProcessFixture::python(
        &root,
        "native_exec_retry.py",
        [
            &ready,
            &failed,
            std::path::Path::new("/missing-native-exec"),
        ],
    )?;

    actor.send(b"root\n")?;
    let pid = actor.wait_pid(&ready, "retry exec child")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "pre-exec stop")?;
    actor.signal(pid, Signal::CONT)?;
    actor.wait_path(
        &failed,
        "exec failure",
        Duration::from_secs(5),
        || Ok(failed.exists().then_some(())),
        || "the failure marker is absent".to_owned(),
    )?;
    actor.wait_stop(pid, "failed exec stop")?;
    actor.signal(pid, Signal::CONT)?;
    actor.wait_comm(pid, "sleep", "exec recovery")?;
    actor.stop()
}

#[test]
fn fatal_exec_kills_actor() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("fatal exec actor"),
    })?;
    let ready = temp.path().join("ready");
    let target = temp.path().join("execfail");
    IdentityTestRunner::materialize_post_ponr_execfail(&target)?;
    let mut actor = ProcessFixture::python(&root, "native_fatal_exec.py", [&ready, &target])?;

    actor.send(b"root\n")?;
    let pid = actor.wait_pid(&ready, "fatal exec child")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "fatal exec stop")?;
    actor.signal(pid, Signal::CONT)?;
    let status = actor.wait_exit("fatal exec", Duration::from_secs(5))?;
    assert!(status.signal().is_some());
    actor.stop()
}
