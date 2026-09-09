use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use snafu::ResultExt as _;

use crate::error::IoSnafu;
use crate::process::ProcessFixture;

#[test]
fn worker_lives_after_leader() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().context(IoSnafu {
        path: std::path::Path::new("leader-first actor"),
    })?;
    let ready = temp.path().join("ready");
    let release = temp.path().join("release");
    let mut actor = ProcessFixture::python(&root, "native_leader_first.py", [&ready, &release])?;
    let pid = actor.id();

    actor.send(b"root\n")?;
    let tid = actor.wait_pid(&ready, "leader-first worker")?;
    assert_ne!(tid, pid);
    assert!(PathBuf::from(format!("/proc/{pid}/task/{tid}")).is_dir());
    fs::write(&release, b"release\n").context(IoSnafu { path: &release })?;
    assert!(actor
        .wait_exit("leader-first worker exit", Duration::from_secs(5))?
        .success());
    actor.stop()
}
