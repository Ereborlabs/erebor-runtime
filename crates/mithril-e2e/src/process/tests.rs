use std::fs::{self, File};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use snafu::ResultExt as _;

use super::ProcessFixture;
use crate::error::{InvalidInputSnafu, IoSnafu};

#[test]
fn gone_accepts_esrch() {
    assert!(super::process_gone(&std::io::Error::from_raw_os_error(
        libc::ESRCH
    )));
    assert!(!super::process_gone(&std::io::Error::from_raw_os_error(
        libc::EACCES
    )));
}

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
    let work = dir.path();
    let mut actor = ProcessFixture::python(&root, "native_orphan.py", [work])?;
    actor.set_group(&dir.path().join("removed-cgroup"));
    let root_pid = actor.id();
    actor.track(root_pid)?;
    let fork = work.join("orphan-fork");
    fs::write(&fork, b"fork\n").context(IoSnafu { path: &fork })?;
    let child_pid = actor.wait_child(root_pid, "actor child")?;
    actor.track(child_pid)?;
    let release = work.join("orphan-exit");
    fs::write(&release, b"exit\n").context(IoSnafu { path: &release })?;
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

#[test]
fn external_wait_has_no_exit_status() -> crate::Result<()> {
    let path = Path::new("/dev/null");
    let input = File::options()
        .write(true)
        .open(path)
        .context(IoSnafu { path })?;
    let mut actor = ProcessFixture::from_pid(std::process::id(), input, Path::new("/proc/self"));
    let mut polled = false;

    actor.wait_path(
        Path::new("/proc/self"),
        "external process state",
        Duration::from_secs(1),
        || Ok(std::mem::replace(&mut polled, true).then_some(())),
        || "state is not ready".to_owned(),
    )
}

#[test]
fn actor_survives_input_loss() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().context(IoSnafu {
        path: "temporary directory",
    })?;
    let mut actor = ProcessFixture::python(&root, "recovery_tree.py", [dir.path()])?;
    actor.send(b"fork\n")?;
    let child = actor.wait_child(actor.id(), "recovery actor child")?;
    actor.track(child)?;

    actor.close();
    std::thread::sleep(Duration::from_millis(50));
    actor.ensure_running("detached recovery actor")?;
    let stop = dir.path().join("recovery-stop");
    fs::write(&stop, b"stop\n").context(IoSnafu { path: &stop })?;
    actor.wait_gone(actor.id(), "detached actor exit")?;
    actor.stop()
}
