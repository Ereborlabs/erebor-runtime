use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor_abi::Id128V1;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, TimeoutSnafu};
use crate::Result;

const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) struct ProbeDirectory {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeDirectory {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        ensure!(
            !path.exists(),
            InvalidInputSnafu {
                path,
                reason: "the test directory must not already exist",
            }
        );
        fs::create_dir_all(path).context(IoSnafu { path })?;
        Ok(Self::new(path))
    }

    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

pub(crate) fn wait_for<T>(
    path: &Path,
    operation: &str,
    limit: Duration,
    mut inspect: impl FnMut() -> Result<Option<T>>,
    diagnostic: impl FnOnce() -> String,
) -> Result<T> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(value) = inspect()? {
            return Ok(value);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return TimeoutSnafu {
                path,
                operation,
                limit,
                diagnostic: diagnostic(),
            }
            .fail();
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(test)]
pub(crate) async fn wait_for_async<T>(
    path: &Path,
    operation: &str,
    limit: Duration,
    mut inspect: impl FnMut() -> Result<Option<T>>,
    diagnostic: impl FnOnce() -> String,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if let Some(value) = inspect()? {
            return Ok(value);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return TimeoutSnafu {
                path,
                operation,
                limit,
                diagnostic: diagnostic(),
            }
            .fail();
        }
        tokio::time::sleep(POLL_INTERVAL.min(remaining)).await;
    }
}

impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) struct ProbeFile {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeFile {
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeFile {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::remove_file(&self.path);
        }
    }
}

pub(crate) struct ProbeCgroup {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeCgroup {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        ensure!(
            !path.exists(),
            InvalidInputSnafu {
                path,
                reason: "the dedicated test cgroup must not already exist",
            }
        );
        fs::create_dir(path).context(IoSnafu { path })?;
        let path = fs::canonicalize(path).context(IoSnafu { path })?;
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeCgroup {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::write(self.path.join("cgroup.kill"), b"1");
            let _result = fs::remove_dir(&self.path);
        }
    }
}

pub(crate) fn boot_identity() -> Result<(String, Id128V1)> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let text = fs::read_to_string(path).context(IoSnafu { path })?;
    let uuid = uuid::Uuid::parse_str(text.trim()).map_err(|error| {
        InvalidInputSnafu {
            path,
            reason: format!("kernel boot ID is invalid: {error}"),
        }
        .build()
    })?;
    let value = uuid.as_u128();
    Ok((
        uuid.simple().to_string(),
        Id128V1::new((value >> 64) as u64, value as u64),
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use erebor_runtime_error::{ErrorExt as _, StatusCode};
    use snafu::ResultExt as _;

    use super::{wait_for, wait_for_async, ProbeDirectory};
    use crate::error::{InvalidInputSnafu, IoSnafu};

    #[test]
    fn readiness_reports_diagnostics_and_directory_cleanup_is_idempotent() -> crate::Result<()> {
        let temporary_path = Path::new("temporary readiness directory");
        let parent = tempfile::tempdir().context(IoSnafu {
            path: temporary_path,
        })?;
        let path = parent.path().join("owned");
        let directory = ProbeDirectory::create(&path)?;
        assert!(path.is_dir());
        directory.cleanup()?;
        ProbeDirectory::new(&path).cleanup()?;

        let result = wait_for(
            &path,
            "fixture readiness",
            Duration::ZERO,
            || Ok::<_, crate::Error>(None::<()>),
            || "last state was STARTING".to_owned(),
        );
        let error = result.err().ok_or_else(|| {
            InvalidInputSnafu {
                path: &path,
                reason: "readiness did not time out",
            }
            .build()
        })?;
        assert_eq!(error.status_code(), StatusCode::DeadlineExceeded);
        assert!(error.to_string().contains("last state was STARTING"));
        Ok(())
    }

    #[tokio::test]
    async fn async_readiness_yields_until_the_fixture_is_ready() -> crate::Result<()> {
        let path = Path::new("async readiness fixture");
        let mut inspections = 0;
        wait_for_async(
            path,
            "fixture readiness",
            Duration::from_secs(1),
            || {
                inspections += 1;
                Ok((inspections == 2).then_some(()))
            },
            || "fixture stayed busy".to_owned(),
        )
        .await?;
        assert_eq!(inspections, 2);
        Ok(())
    }
}
