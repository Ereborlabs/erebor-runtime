use std::{path::Path, process::Command};

use snafu::{ensure, ResultExt};

use crate::{
    error::{OstreeInitFailedSnafu, StartOstreeSnafu},
    Result,
};

pub(super) fn initialize_ostree_repo(repo: &Path) -> Result<()> {
    let output = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .arg("init")
        .arg("--mode=bare-user-only")
        .output()
        .context(StartOstreeSnafu {
            repo: repo.to_path_buf(),
        })?;

    ensure!(
        output.status.success(),
        OstreeInitFailedSnafu {
            repo: repo.to_path_buf(),
            code: output.status.code(),
            stderr: command_stderr(&output.stderr),
        }
    );
    Ok(())
}

fn command_stderr(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    if stderr.is_empty() {
        String::from("<empty stderr>")
    } else {
        stderr
    }
}
