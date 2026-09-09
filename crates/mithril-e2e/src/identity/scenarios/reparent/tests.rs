use std::path::PathBuf;

use rustix::process::Signal;
use snafu::ResultExt as _;

use crate::error::IoSnafu;
use crate::process::ProcessFixture;

#[test]
fn child_execs_after_subreaper() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("subreaper actor"),
    })?;
    let ready = temp.path().join("ready");
    let mut actor = ProcessFixture::python(&root, "native_subreaper.py", [&ready])?;
    let outer = actor.id();

    actor.send(b"root\n")?;
    let [mid, pid] = actor.wait_pair(&ready, "subreaper children")?;
    actor.track(mid)?;
    actor.track(pid)?;
    actor.wait_stop(pid, "subreaper child stop")?;
    assert_eq!(actor.parent(pid)?, Some(mid));
    actor.signal(mid, Signal::TERM)?;
    actor.wait_gone(mid, "subreaper middle exit")?;
    assert_eq!(actor.parent(pid)?, Some(outer));
    actor.signal(pid, Signal::CONT)?;
    actor.wait_comm(pid, "sleep", "subreaper child exec")?;
    actor.stop()
}

#[test]
fn child_execs_after_namespace_init() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("namespace actor"),
    })?;
    let init_path = temp.path().join("init");
    let mid_path = temp.path().join("middle");
    let child_path = temp.path().join("child");
    let ready = [
        init_path.as_path(),
        mid_path.as_path(),
        child_path.as_path(),
    ];
    let mut actor = ProcessFixture::unshare(&root, "native_namespace_init.py", ready)?;

    let init = actor.wait_pid(&init_path, "namespace init")?;
    actor.track(init)?;
    assert_eq!(super::super::super::pid_in_own_namespace(init)?, 1);
    actor.send(b"root\n")?;
    let mid = actor.wait_pid(&mid_path, "namespace middle")?;
    actor.track(mid)?;
    actor.wait_stop(mid, "namespace middle stop")?;
    actor.signal(mid, Signal::CONT)?;
    let pid = actor.wait_pid(&child_path, "namespace child")?;
    actor.track(pid)?;
    actor.wait_stop(pid, "namespace child stop")?;
    assert_eq!(actor.parent(pid)?, Some(mid));
    actor.signal(mid, Signal::TERM)?;
    actor.wait_gone(mid, "namespace middle exit")?;
    assert_eq!(actor.parent(pid)?, Some(init));
    actor.signal(pid, Signal::CONT)?;
    actor.wait_comm(pid, "sleep", "namespace child exec")?;
    actor.stop()
}
