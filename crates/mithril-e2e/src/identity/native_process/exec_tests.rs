use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use super::super::IdentityTestRunner;
use super::{test_support, NativeProcessFixture};

#[test]
fn native_process_fixture_waits_for_stopped_child_before_exec() -> crate::Result<()> {
    let mut fixture = NativeProcessFixture::start()?;
    fixture.release_root()?;
    let native_pid = fixture.wait_for_native_child("native child creation")?;

    fixture.release_exec(native_pid)?;
    fixture.wait_for_executable(native_pid, "sleep", "native child exec")?;
    Ok(())
}

#[test]
fn post_ponr_fixture_terminates_the_exec_process() -> crate::Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create post-PONR test directory: {error}"))
    })?;
    let executable = temporary.path().join("post-ponr-execfail");
    IdentityTestRunner::materialize_post_ponr_execfail(&executable)?;
    let status = test_support::runner().wait_for(
        "post-PONR fixture executable release",
        &executable,
        || match Command::new(&executable).status() {
            Ok(status) => Ok(Some(status)),
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => Ok(None),
            Err(error) => Err(super::invalid_state(format!(
                "execute post-PONR fixture: {error}"
            ))),
        },
    )?;
    assert!(!status.success());
    assert!(status.signal().is_some());
    Ok(())
}

#[test]
fn native_process_fixture_reports_failed_exec() -> crate::Result<()> {
    let mut fixture = NativeProcessFixture::start_with_script(
        "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /missing-native-exec) & wait \"$!\"",
        false,
    )?;
    fixture.release_root()?;
    let native_pid = fixture.wait_for_native_child("failed native child creation")?;

    fixture.release_exec(native_pid)?;
    fixture.wait_for_native_exec_failure()
}

#[test]
fn native_process_fixture_recovers_from_bash_execfail() -> crate::Result<()> {
    let runner = test_support::runner();
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create exec-failure test directory: {error}"))
    })?;
    let execfail = temporary.path().join("execfail");
    let ready = temporary.path().join("execfail-ready");
    runner.materialize_execfail(&execfail)?;

    let mut fixture = NativeProcessFixture::start_with_failed_exec(&execfail, &ready)?;
    fixture.release_root()?;
    let native_pid = fixture.wait_for_native_child("Bash execfail child creation")?;

    fixture.release_exec(native_pid)?;
    let comm_path = std::path::PathBuf::from(format!("/proc/{native_pid}/comm"));
    runner.wait_for("Bash execfail recovery", &ready, || {
        if !ready.exists() {
            fixture.native_child_pid()?;
            return Ok(None);
        }
        fs::read_to_string(&comm_path)
            .map(|name| (name.trim() == "bash").then_some(()))
            .map_err(|error| super::invalid_state(format!("read {}: {error}", comm_path.display())))
    })?;
    fixture.release_exec(native_pid)?;
    fixture.wait_for_executable(native_pid, "sleep", "Bash execfail later normal exec")?;
    Ok(())
}
