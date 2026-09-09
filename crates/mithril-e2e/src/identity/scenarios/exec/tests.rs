use std::path::PathBuf;

use snafu::ResultExt as _;

use crate::error::IoSnafu;
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
