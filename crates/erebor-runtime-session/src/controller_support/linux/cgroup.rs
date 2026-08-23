use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    thread,
    time::Duration,
};

use rustix::fs::{fstat, open, openat, Mode, OFlags};

use crate::{HeldWorkloadBoundary, SessionControllerError};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const WORKLOAD_CGROUP: &str = "erebor-workload";

pub(super) struct OwnedWorkloadCgroup {
    controller_directory: File,
    controller_path: PathBuf,
    controller_id: u64,
    directory: File,
    path: PathBuf,
    id: u64,
}

struct CgroupCreationGuard {
    path: PathBuf,
    committed: bool,
}

impl OwnedWorkloadCgroup {
    pub(super) fn create() -> Result<Self, SessionControllerError> {
        let current =
            current_cgroup_path(&fs::read_to_string("/proc/self/cgroup").map_err(|source| {
                SessionControllerError::Io {
                    action: "reading the Linux controller cgroup",
                    path: PathBuf::from("/proc/self/cgroup"),
                    source,
                    location: snafu::Location::default(),
                }
            })?)?;
        let controller_path = Path::new(CGROUP_ROOT).join(current);
        let controller_directory = open(
            &controller_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action: "opening the Linux controller cgroup",
            path: controller_path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let controller_id = fstat(&controller_directory)
            .map_err(std::io::Error::from)
            .map_err(|source| SessionControllerError::Io {
                action: "reading the Linux controller cgroup identity",
                path: controller_path.clone(),
                source,
                location: snafu::Location::default(),
            })?
            .st_ino;
        let path = controller_path.join(WORKLOAD_CGROUP);
        fs::create_dir(&path).map_err(|source| SessionControllerError::Io {
            action: "creating the held workload cgroup",
            path: path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let mut creation = CgroupCreationGuard {
            path: path.clone(),
            committed: false,
        };
        let directory = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action: "opening the held workload cgroup",
            path: path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let id = fstat(&directory)
            .map_err(std::io::Error::from)
            .map_err(|source| SessionControllerError::Io {
                action: "reading the held workload cgroup identity",
                path: path.clone(),
                source,
                location: snafu::Location::default(),
            })?
            .st_ino;
        validate_distinct_ids(controller_id, id)?;
        let owner = Self {
            controller_directory,
            controller_path,
            controller_id,
            directory,
            path,
            id,
        };
        owner.verify_empty()?;
        creation.committed = true;
        Ok(owner)
    }

    pub(super) fn boundary(&self) -> HeldWorkloadBoundary {
        HeldWorkloadBoundary::LinuxCgroup {
            path: self.path.clone(),
            id: self.id,
            controller_id: self.controller_id,
        }
    }

    pub(super) fn directory(&self) -> &File {
        &self.directory
    }

    pub(super) fn verify_empty(&self) -> Result<(), SessionControllerError> {
        self.verify_identity()?;
        if !self.is_empty()? {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from("held workload cgroup is not empty before release"),
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    pub(super) fn terminate_remaining(&self) -> Result<(), SessionControllerError> {
        self.verify_identity()?;
        let mut kill = match openat(
            &self.directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(kill) => File::from(kill),
            Err(error) if error == rustix::io::Errno::NOENT && self.is_empty()? => {
                return Ok(());
            }
            Err(source) => {
                return Err(self.io(
                    "opening the held workload cgroup kill control",
                    std::io::Error::from(source),
                ));
            }
        };
        kill.write_all(b"1")
            .map_err(|source| self.io("terminating remaining held workload processes", source))?;
        for _attempt in 0..100 {
            if self.is_empty()? {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(SessionControllerError::InvalidHandoff {
            reason: String::from("held workload cgroup remained populated after termination"),
            location: snafu::Location::default(),
        })
    }

    fn verify_identity(&self) -> Result<(), SessionControllerError> {
        let controller_descriptor_status = fstat(&self.controller_directory)
            .map_err(std::io::Error::from)
            .map_err(|source| {
                self.io("verifying the Linux controller cgroup descriptor", source)
            })?;
        let controller_path_status = fs::symlink_metadata(&self.controller_path)
            .map_err(|source| self.io("verifying the Linux controller cgroup path", source))?;
        if !controller_path_status.is_dir()
            || controller_path_status.file_type().is_symlink()
            || controller_descriptor_status.st_ino != self.controller_id
            || controller_path_status.ino() != self.controller_id
            || controller_path_status.dev() != controller_descriptor_status.st_dev
        {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from("Linux controller cgroup identity changed before release"),
                location: snafu::Location::default(),
            });
        }
        let descriptor_status = fstat(&self.directory)
            .map_err(std::io::Error::from)
            .map_err(|source| self.io("verifying the held workload cgroup descriptor", source))?;
        let path_status = fs::symlink_metadata(&self.path)
            .map_err(|source| self.io("verifying the held workload cgroup path", source))?;
        if !path_status.is_dir()
            || path_status.file_type().is_symlink()
            || descriptor_status.st_ino != self.id
            || path_status.ino() != self.id
            || path_status.dev() != descriptor_status.st_dev
        {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from("held workload cgroup identity changed before release"),
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }

    fn is_empty(&self) -> Result<bool, SessionControllerError> {
        let mut processes = String::new();
        File::from(
            openat(
                &self.directory,
                "cgroup.procs",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|source| self.io("opening the held workload cgroup membership", source))?,
        )
        .read_to_string(&mut processes)
        .map_err(|source| self.io("reading the held workload cgroup membership", source))?;
        Ok(processes.trim().is_empty())
    }

    fn io(&self, action: &'static str, source: std::io::Error) -> SessionControllerError {
        SessionControllerError::Io {
            action,
            path: self.path.clone(),
            source,
            location: snafu::Location::default(),
        }
    }
}

impl Drop for CgroupCreationGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _result = fs::remove_dir(&self.path);
        }
    }
}

fn validate_distinct_ids(
    controller_id: u64,
    workload_id: u64,
) -> Result<(), SessionControllerError> {
    if controller_id == 0 || workload_id == 0 || controller_id == workload_id {
        return Err(SessionControllerError::InvalidHandoff {
            reason: String::from(
                "controller and workload cgroups require distinct nonzero identities",
            ),
            location: snafu::Location::default(),
        });
    }
    Ok(())
}

impl Drop for OwnedWorkloadCgroup {
    fn drop(&mut self) {
        let _result = self.terminate_remaining();
        let _result = fs::remove_dir(&self.path);
    }
}

fn current_cgroup_path(source: &str) -> Result<PathBuf, SessionControllerError> {
    let raw = source
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| SessionControllerError::InvalidHandoff {
            reason: String::from("Linux controller is not in a unified cgroup v2 hierarchy"),
            location: snafu::Location::default(),
        })?;
    let path = Path::new(raw);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SessionControllerError::InvalidHandoff {
            reason: String::from("Linux controller cgroup path is not normalized"),
            location: snafu::Location::default(),
        });
    }
    path.strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(|_error| SessionControllerError::InvalidHandoff {
            reason: String::from("Linux controller cgroup path is invalid"),
            location: snafu::Location::default(),
        })
}

#[cfg(test)]
mod tests {
    use super::{current_cgroup_path, validate_distinct_ids};
    use std::path::Path;

    #[test]
    fn unified_cgroup_path_is_normalized_for_the_cgroup_mount(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            current_cgroup_path("0::/erebor.slice/session.scope\n")?,
            Path::new("erebor.slice/session.scope")
        );
        Ok(())
    }

    #[test]
    fn cgroup_path_rejects_legacy_and_traversal_memberships() {
        assert!(current_cgroup_path("2:cpu:/legacy\n").is_err());
        assert!(current_cgroup_path("0::/scope/../other\n").is_err());
    }

    #[test]
    fn controller_and_workload_cgroup_ids_are_nonzero_and_distinct() {
        assert!(validate_distinct_ids(41, 42).is_ok());
        assert!(validate_distinct_ids(0, 42).is_err());
        assert!(validate_distinct_ids(41, 0).is_err());
        assert!(validate_distinct_ids(42, 42).is_err());
    }
}
