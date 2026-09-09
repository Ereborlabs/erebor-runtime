use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::time::Duration;

use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::Result;

const FIXTURE_DIRECTORY: &str = "crates/mithril-e2e/fixtures/process";

pub(crate) fn process_program(repo_root: &Path, name: &str) -> Result<PathBuf> {
    let path = repo_root.join(FIXTURE_DIRECTORY).join(name);
    ensure!(
        path.is_file(),
        InvalidInputSnafu {
            path: &path,
            reason: "the process fixture program is missing",
        }
    );
    Ok(path)
}

pub(crate) struct ProcessFixture {
    child: Child,
    stopped: bool,
}

impl ProcessFixture {
    pub(crate) fn new(child: Child) -> Self {
        Self {
            child,
            stopped: false,
        }
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn try_wait(&mut self, path: &Path) -> Result<Option<ExitStatus>> {
        self.child
            .try_wait()
            .context(IoSnafu { path })
            .inspect(|status| self.stopped |= status.is_some())
    }

    pub(crate) fn wait(&mut self, path: &Path) -> Result<ExitStatus> {
        self.child
            .wait()
            .context(IoSnafu { path })
            .inspect(|_status| self.stopped = true)
    }

    pub(crate) fn wait_for_exit(
        &mut self,
        path: &Path,
        operation: &str,
        limit: Duration,
    ) -> Result<ExitStatus> {
        wait_for(
            path,
            operation,
            limit,
            || self.try_wait(path),
            || "the process is still running".to_owned(),
        )
    }

    pub(crate) fn stop(&mut self, path: &Path) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if self.try_wait(path)?.is_none() {
            self.child.kill().context(IoSnafu { path })?;
            self.wait(path)?;
        }
        Ok(())
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        let _result = self.stop(Path::new("child process"));
    }
}

pub(crate) fn wait_for_process<T>(
    process: &mut ProcessFixture,
    path: &Path,
    operation: &str,
    limit: Duration,
    mut inspect: impl FnMut() -> Result<Option<T>>,
    mut exit_diagnostic: impl FnMut() -> Result<String>,
    timeout_diagnostic: impl FnOnce() -> String,
) -> Result<T> {
    wait_for(
        path,
        operation,
        limit,
        || {
            if let Some(value) = inspect()? {
                return Ok(Some(value));
            }
            if let Some(status) = process.try_wait(path)? {
                return InvalidInputSnafu {
                    path,
                    reason: format!(
                        "the process exited with {status} before {operation}; {}",
                        exit_diagnostic()?
                    ),
                }
                .fail();
            }
            Ok(None)
        },
        timeout_diagnostic,
    )
}
