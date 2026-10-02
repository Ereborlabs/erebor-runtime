use std::fs;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor_abi::Id128V1;
#[cfg(test)]
use snafu::OptionExt as _;
use snafu::{ensure, ResultExt as _};

use crate::error::{CommandSnafu, InvalidInputSnafu, IoSnafu, TimeoutSnafu};
use crate::Result;

#[cfg(test)]
pub(crate) mod mount_cache;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(test)]
const STABLE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(crate) struct FixtureBindMounts {
    targets: Vec<PathBuf>,
    namespace: Option<(fs::File, fs::File)>,
}

impl FixtureBindMounts {
    #[cfg(test)]
    pub(crate) fn in_actor(pid: u32) -> Result<Self> {
        let namespace = PathBuf::from(format!("/proc/{pid}/ns/mnt"));
        let root = PathBuf::from(format!("/proc/{pid}/root"));
        Ok(Self {
            targets: Vec::new(),
            namespace: Some((
                fs::File::open(&namespace).context(IoSnafu { path: &namespace })?,
                fs::File::open(&root).context(IoSnafu { path: &root })?,
            )),
        })
    }

    pub(crate) fn bind(&mut self, source: &Path, target: &Path) -> Result<()> {
        if self.namespace.is_some() {
            self.run(&["mount", "--bind", "."], target, Some(source))?;
        } else {
            fs::create_dir_all(target).context(IoSnafu { path: target })?;
            rustix::mount::mount_bind(source, target)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: target })?;
        }
        self.targets.push(target.to_owned());
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        while let Some(target) = self.targets.last() {
            if self.namespace.is_some() {
                self.run(&["umount", "--"], target, None)?;
            } else {
                rustix::mount::unmount(target, rustix::mount::UnmountFlags::empty())
                    .map_err(std::io::Error::from)
                    .context(IoSnafu { path: target })?;
            }
            self.targets.pop();
        }
        Ok(())
    }

    fn run(&self, args: &[&str], target: &Path, source: Option<&Path>) -> Result<()> {
        let (namespace, root) = self.namespace.as_ref().ok_or_else(|| {
            InvalidInputSnafu {
                path: target,
                reason: "the actor mount namespace is not held",
            }
            .build()
        })?;
        let owner = std::process::id();
        let mut command = Command::new("nsenter");
        command
            .arg(format!(
                "--mount=/proc/{owner}/fd/{}",
                namespace.as_raw_fd()
            ))
            .arg(format!("--root=/proc/{owner}/fd/{}", root.as_raw_fd()));
        if let Some(source) = source {
            // Open the source directory before entry into the actor root.
            command.arg(format!("--wd={}", source.display()));
        }
        let output = command
            .args(["--"])
            .args(args)
            .arg(target)
            .output()
            .context(IoSnafu { path: target })?;
        ensure!(
            output.status.success(),
            CommandSnafu {
                program: "nsenter",
                reason: format!(
                    "{args:?} {}: {}; stderr: {}",
                    target.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            }
        );
        Ok(())
    }
}

impl Drop for FixtureBindMounts {
    fn drop(&mut self) {
        while let Some(target) = self.targets.pop() {
            if self.namespace.is_some() {
                let _result = self.run(&["umount", "-l", "--"], &target, None);
            } else {
                let _result = rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH);
            }
        }
    }
}

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

    pub(crate) fn path(&self) -> &Path {
        &self.path
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
pub(crate) fn wait_stable(
    path: &Path,
    operation: &str,
    limit: Duration,
    samples: usize,
    mut inspect: impl FnMut() -> Result<bool>,
    diagnostic: impl FnOnce() -> String,
) -> Result<()> {
    let deadline = Instant::now() + limit;
    let mut stable = 0;
    loop {
        if inspect()? {
            stable += 1;
            if stable >= samples {
                return Ok(());
            }
        } else {
            stable = 0;
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
        thread::sleep(STABLE_INTERVAL.min(remaining));
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

    pub(crate) fn keep(mut self) {
        self.cleaned = true;
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
    previous: Option<PathBuf>,
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
            previous: None,
            cleaned: false,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn enter(&mut self) -> Result<()> {
        ensure!(
            self.previous.is_none(),
            InvalidInputSnafu {
                path: &self.path,
                reason: "the test process already entered this cgroup",
            }
        );
        let source = Path::new("/proc/self/cgroup");
        let text = fs::read_to_string(source).context(IoSnafu { path: source })?;
        let mut paths = text.lines().filter_map(|line| line.strip_prefix("0::"));
        let relative = paths.next().context(InvalidInputSnafu {
            path: source,
            reason: "the test process has no unified cgroup",
        })?;
        ensure!(
            paths.next().is_none() && relative.starts_with('/'),
            InvalidInputSnafu {
                path: source,
                reason: "the test process has an ambiguous unified cgroup",
            }
        );
        self.previous = Some(Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')));
        let target = self.path.join("cgroup.procs");
        fs::write(&target, std::process::id().to_string()).context(IoSnafu { path: target })
    }

    #[cfg(test)]
    pub(crate) fn move_in(&self, pid: u32) -> Result<()> {
        let target = self.path.join("cgroup.procs");
        fs::write(&target, pid.to_string()).context(IoSnafu { path: target })
    }

    #[cfg(test)]
    pub(crate) fn move_out(&self, pid: u32) -> Result<()> {
        let previous = self.previous.as_ref().context(InvalidInputSnafu {
            path: &self.path,
            reason: "the test process has no previous cgroup",
        })?;
        let target = previous.join("cgroup.procs");
        fs::write(&target, pid.to_string()).context(IoSnafu { path: target })
    }

    fn leave(&mut self) -> Result<()> {
        let Some(previous) = self.previous.take() else {
            return Ok(());
        };
        let target = previous.join("cgroup.procs");
        fs::write(&target, std::process::id().to_string()).context(IoSnafu { path: target })
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        self.leave()?;
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
            let _result = self.leave();
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

    use super::{wait_for, wait_for_async, FixtureBindMounts, ProbeDirectory};
    use crate::error::{InvalidInputSnafu, IoSnafu};

    #[test]
    #[ignore = "requires Linux mount privileges"]
    fn mounts_keep_failed_cleanup() -> crate::Result<()> {
        let parent = tempfile::tempdir().context(IoSnafu {
            path: Path::new("bind mount fixture"),
        })?;
        let source = parent.path().join("source");
        let target = parent.path().join("target");
        std::fs::create_dir_all(&source).context(IoSnafu { path: &source })?;
        std::fs::create_dir_all(&target).context(IoSnafu { path: &target })?;
        let file = source.join("file");
        std::fs::write(&file, b"mounted").context(IoSnafu { path: &file })?;
        for actor in [false, true] {
            let mut mounts = if actor {
                FixtureBindMounts::in_actor(std::process::id())?
            } else {
                FixtureBindMounts::default()
            };
            mounts.bind(&source, &target)?;
            let held = std::fs::File::open(&target).context(IoSnafu { path: &target })?;
            assert!(target.join("file").exists());
            assert!(mounts.cleanup().is_err());
            assert_eq!(mounts.targets.as_slice(), std::slice::from_ref(&target));
            drop(held);
            mounts.cleanup()?;
            mounts.cleanup()?;
            assert!(!target.join("file").exists());
            mounts.bind(&source, &target)?;
            drop(mounts);
            assert!(!target.join("file").exists());
        }
        Ok(())
    }

    #[test]
    fn readiness_reports_cleanup() -> crate::Result<()> {
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
    async fn async_wait_yields() -> crate::Result<()> {
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
