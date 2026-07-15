use std::{io, path::Path, process::Command};

pub(crate) struct LinuxUserMountNamespace;

impl LinuxUserMountNamespace {
    pub(crate) fn ensure_available() -> io::Result<()> {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "true"])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                "e2e fixture requires unshare --user --map-root-user --mount on a host that permits user and mount namespaces",
            ))
        }
    }

    pub(crate) fn command(program: &Path) -> Command {
        let mut command = Command::new("unshare");
        command
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--fork",
                "--propagation",
                "private",
                "--",
            ])
            .arg(program);
        command
    }
}
