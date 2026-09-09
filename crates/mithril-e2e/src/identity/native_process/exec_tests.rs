use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use super::super::IdentityTestRunner;
use super::test_support;

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
