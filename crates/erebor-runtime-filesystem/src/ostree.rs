use std::{path::Path, process::Command};

use snafu::ResultExt;

use crate::{error::StartOstreeSnafu, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OstreeCommandOutput {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl OstreeCommandOutput {
    #[cfg(test)]
    pub(crate) fn new(success: bool, code: Option<i32>, stderr: impl Into<String>) -> Self {
        Self::with_stdout(success, code, "", stderr)
    }

    pub(crate) fn with_stdout(
        success: bool,
        code: Option<i32>,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self {
            success,
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    pub(crate) const fn success(&self) -> bool {
        self.success
    }

    pub(crate) const fn code(&self) -> Option<i32> {
        self.code
    }

    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub(crate) trait OstreeCommandRunner {
    fn run(&self, repo: &Path, args: &[String]) -> Result<OstreeCommandOutput>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemOstreeCommandRunner;

impl OstreeCommandRunner for SystemOstreeCommandRunner {
    fn run(&self, repo: &Path, args: &[String]) -> Result<OstreeCommandOutput> {
        let output = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(args)
            .output()
            .context(StartOstreeSnafu {
                repo: repo.to_path_buf(),
            })?;
        Ok(OstreeCommandOutput::with_stdout(
            output.status.success(),
            output.status.code(),
            command_stdout(&output.stdout),
            command_stderr(&output.stderr),
        ))
    }
}

fn command_stdout(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout).to_string()
}

fn command_stderr(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    if stderr.is_empty() {
        String::from("<empty stderr>")
    } else {
        stderr
    }
}
