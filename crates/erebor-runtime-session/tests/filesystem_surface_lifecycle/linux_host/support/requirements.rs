use std::{io, process::Command};

pub(crate) fn require_ostree(test_name: &str) -> Result<bool, io::Error> {
    if command_available("ostree") {
        return Ok(true);
    }

    let message = format!("skipping {test_name}: ostree CLI is not available in PATH");
    if std::env::var("EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE").as_deref() == Ok("1") {
        return Err(io::Error::other(message));
    }
    eprintln!("{message}");
    Ok(false)
}

pub(crate) fn require_overlay_lifecycle(test_name: &str) -> Result<bool, io::Error> {
    if std::env::var("EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE").as_deref() != Ok("1") {
        let message = format!(
            "skipping {test_name}: set EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 to run mount lifecycle checks"
        );
        if std::env::var("EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE").as_deref() == Ok("1") {
            return Err(io::Error::other(message));
        }
        eprintln!("{message}");
        return Ok(false);
    }

    for command in ["ostree", "unshare", "mount", "umount", "findmnt"] {
        require_command(test_name, command)?;
    }
    Ok(true)
}

fn require_command(test_name: &str, command: &str) -> Result<(), io::Error> {
    if command_available(command) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{test_name} requires `{command}` in PATH"
        )))
    }
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}
