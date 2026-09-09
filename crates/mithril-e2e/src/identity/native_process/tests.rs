use std::path::Path;
use std::process::Command;

use super::test_support;
use super::NativeProcessFixture;
use crate::error::InvalidInputSnafu;
use crate::process::process_program;

#[test]
fn startup_reports_shared_process_program_failure() -> crate::Result<()> {
    let repo_root = test_support::runner().repo_root;
    let script = process_program(&repo_root, "process_exit.py")?;
    let mut command = Command::new("python3");
    command.arg(&script).args(["17", "shared process failed"]);

    let error = match NativeProcessFixture::start_command(
        &mut command,
        false,
        Path::new("python3"),
        &script,
    ) {
        Err(error) => error,
        Ok(mut fixture) => {
            fixture.stop();
            return InvalidInputSnafu {
                path: &script,
                reason: "the failing process fixture reported readiness",
            }
            .fail();
        }
    };
    let message = error.to_string();
    assert!(message.contains("exit status: 17"), "{message}");
    assert!(message.contains("shared process failed"), "{message}");
    Ok(())
}
