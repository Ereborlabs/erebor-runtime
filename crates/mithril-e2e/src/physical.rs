use std::fs;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use erebor_interceptor_abi::Id128V1;
#[cfg(test)]
use snafu::OptionExt as _;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, TimeoutSnafu};
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
            use rustix::mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags};

            let tree = open_tree(
                rustix::fs::CWD,
                source,
                OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: source })?;
            let destination = self.target(target)?;
            self.in_namespace(target, move || {
                move_mount(
                    tree,
                    "",
                    destination,
                    "",
                    MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
                        | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
                )
            })?;
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
            self.unmount(target, rustix::mount::UnmountFlags::empty())?;
            self.targets.pop();
        }
        Ok(())
    }

    fn target(&self, target: &Path) -> Result<OwnedFd> {
        let (_, root) = self.namespace.as_ref().ok_or_else(|| {
            InvalidInputSnafu {
                path: target,
                reason: "the actor mount namespace is not held",
            }
            .build()
        })?;
        let path = target.strip_prefix("/").map_err(|error| {
            InvalidInputSnafu {
                path: target,
                reason: error.to_string(),
            }
            .build()
        })?;
        rustix::fs::openat(
            root,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: target })
    }

    fn unmount(&self, target: &Path, flags: rustix::mount::UnmountFlags) -> Result<()> {
        if let Some((_, root)) = self.namespace.as_ref() {
            let root = root.try_clone().context(IoSnafu { path: target })?;
            let path = target
                .strip_prefix("/")
                .map_err(|error| {
                    InvalidInputSnafu {
                        path: target,
                        reason: error.to_string(),
                    }
                    .build()
                })?
                .to_owned();
            self.in_namespace(target, move || {
                rustix::process::fchdir(root)?;
                rustix::mount::unmount(path, flags)
            })
        } else {
            rustix::mount::unmount(target, flags)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: target })
        }
    }

    #[allow(unsafe_code)]
    fn in_namespace(
        &self,
        target: &Path,
        action: impl FnOnce() -> rustix::io::Result<()> + Send + 'static,
    ) -> Result<()> {
        let namespace = self
            .namespace
            .as_ref()
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: target,
                    reason: "the mount namespace is not held",
                }
                .build()
            })?
            .0
            .try_clone()
            .context(IoSnafu { path: target })?;
        thread::Builder::new()
            .name("fixture-mount".into())
            .spawn(move || {
                use rustix::thread::{
                    move_into_link_name_space, unshare_unsafe, LinkNameSpaceType, UnshareFlags,
                };

                // SAFETY: Only this helper's filesystem context changes. FDs stay shared.
                unsafe { unshare_unsafe(UnshareFlags::FS) }?;
                move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Mount))?;
                action()
            })
            .context(IoSnafu { path: target })?
            .join()
            .map_err(|_| {
                InvalidInputSnafu {
                    path: target,
                    reason: "the mount helper panicked",
                }
                .build()
            })?
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: target })
    }
}

impl Drop for FixtureBindMounts {
    fn drop(&mut self) {
        while let Some(target) = self.targets.pop() {
            let _result = self.unmount(&target, rustix::mount::UnmountFlags::DETACH);
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
