use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use snafu::ResultExt as _;

use super::ProcessFixture;
use crate::error::{InvalidInputSnafu, IoSnafu};

#[test]
fn python_start_stop() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut actor = ProcessFixture::python(&root, "ready.py", std::iter::empty::<&str>())?;

    actor.send(b"stop\n")?;
    assert!(actor
        .wait_exit("the ready actor to exit", Duration::from_secs(5))?
        .success());
    actor.stop()?;
    actor.stop()
}

#[test]
fn stop_kills_actor() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut actor = ProcessFixture::python(&root, "ready.py", std::iter::empty::<&str>())?;

    actor.stop()?;
    actor.stop()
}

#[test]
fn stop_kills_child_after_exit() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().context(IoSnafu {
        path: "temporary directory",
    })?;
    let ready = dir.path().join("orphan.pid");
    let mut actor = ProcessFixture::python(&root, "native_orphan.py", [&ready])?;
    actor.set_group(&dir.path().join("removed-cgroup"));
    let root_pid = actor.id();
    actor.track(root_pid)?;
    actor.send(b"fork\n")?;
    let child_pid = actor.wait_pid(&ready, "actor child")?;
    actor.track(child_pid)?;
    actor.wait_stop(child_pid, "actor child stop")?;
    actor.send(b"exit\n")?;
    assert!(actor
        .wait_exit("parent exit", Duration::from_secs(5))?
        .success());

    actor.stop()?;
    actor.stop()
}

#[test]
fn fatal_exec_dies() -> crate::Result<()> {
    let dir = tempfile::tempdir().context(IoSnafu {
        path: "temporary directory",
    })?;
    let path = dir.path().join("post-ponr-execfail");
    ProcessFixture::fatal_exec(&path)?;

    let status = Command::new(&path)
        .status()
        .context(IoSnafu { path: &path })?;
    assert!(status.signal().is_some());
    Ok(())
}

#[test]
fn exit_reports_stderr() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = ProcessFixture::script(&root, "process_exit.py")?;
    let child = Command::new("python3")
        .arg(&script)
        .args(["17", "actor failed"])
        .stderr(Stdio::piped())
        .spawn()
        .context(IoSnafu { path: &script })?;
    let mut actor = ProcessFixture::new(child, &script);
    let missing = root.join("missing-process-ready");

    let error = match actor.wait_path(
        &missing,
        "the actor result",
        Duration::from_secs(5),
        || Ok(missing.exists().then_some(())),
        || "result is absent".to_owned(),
    ) {
        Err(error) => error,
        Ok(()) => {
            return InvalidInputSnafu {
                path: &missing,
                reason: "the actor reported a missing result",
            }
            .fail()
        }
    };

    let message = error.to_string();
    assert!(message.contains("exit status: 17"), "{message}");
    assert!(message.contains("actor failed"), "{message}");
    Ok(())
}
