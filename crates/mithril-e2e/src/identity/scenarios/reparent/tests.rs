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
