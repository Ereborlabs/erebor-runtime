use std::{path::Path, process::Command};

use snafu::ResultExt;

use crate::{error::StartOstreeSnafu, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OstreeCommandOutput {
    success: bool,
    code: Option<i32>,
    stderr: String,
}

impl OstreeCommandOutput {
    pub(crate) fn new(success: bool, code: Option<i32>, stderr: impl Into<String>) -> Self {
        Self {
            success,
            code,
            stderr: stderr.into(),
        }
    }

    pub(crate) const fn success(&self) -> bool {
        self.success
    }

    pub(crate) const fn code(&self) -> Option<i32> {
        self.code
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
        Ok(OstreeCommandOutput::new(
            output.status.success(),
            output.status.code(),
            command_stderr(&output.stderr),
        ))
    }
}

fn command_stderr(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    if stderr.is_empty() {
        String::from("<empty stderr>")
    } else {
        stderr
    }
}
