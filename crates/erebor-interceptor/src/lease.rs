use std::fs::{self, File};
use std::path::{Path, PathBuf};

use rustix::fs::{flock, FlockOperation};
use snafu::ResultExt as _;

use crate::error::{IoSnafu, LeaseOwnedSnafu};
use crate::Result;

const HOST_LEASE_PATH: &str = "/run/erebor-interceptor/owner.lock";

pub(crate) struct PinRootLease {
    file: File,
}

impl PinRootLease {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(IoSnafu {
                action: "create lease directory",
                path: parent,
            })?;
        }
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .context(IoSnafu {
                action: "open pin-root lease",
                path,
            })?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)
            .map_err(|_| {
                LeaseOwnedSnafu {
                    path: PathBuf::from(path),
                }
                .build()
            })?;
        Ok(Self { file })
    }
}

impl Drop for PinRootLease {
    fn drop(&mut self) {
        let _result = flock(&self.file, FlockOperation::Unlock);
    }
}

pub(crate) struct KernelHostLease {
    _host: PinRootLease,
    _pin_root: PinRootLease,
}

impl KernelHostLease {
    pub(crate) fn acquire(instance_lease_path: &Path) -> Result<Self> {
        Self::acquire_at(Path::new(HOST_LEASE_PATH), instance_lease_path)
    }

    fn acquire_at(host_path: &Path, instance_lease_path: &Path) -> Result<Self> {
        let host = PinRootLease::acquire(host_path)?;
        let pin_root = PinRootLease::acquire(instance_lease_path)?;
        Ok(Self {
            _host: host,
            _pin_root: pin_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use snafu::ResultExt as _;

    use super::{KernelHostLease, PinRootLease};
    use crate::error::IoSnafu;

    #[test]
    fn pin_root_lease_rejects_a_concurrent_owner() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            action: "create temporary lease directory",
            path: "temporary lease directory",
        })?;
        for mode in ["runtime-only", "mithril-only", "co-resident"] {
            let path = directory.path().join(format!("{mode}.lock"));
            std::fs::write(&path, b"stale").context(IoSnafu {
                action: "write stale lease file",
                path: &path,
            })?;
            let first = PinRootLease::acquire(&path)?;
            assert!(PinRootLease::acquire(&path).is_err());
            drop(first);
            assert!(PinRootLease::acquire(&path).is_ok());
        }
        Ok(())
    }

    #[test]
    fn host_lease_rejects_a_distinct_pin_root_owner() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            action: "create temporary lease directory",
            path: "temporary lease directory",
        })?;
        let host_path = directory.path().join("host.lock");
        let first = KernelHostLease::acquire_at(&host_path, &directory.path().join("one.lock"))?;
        assert!(
            KernelHostLease::acquire_at(&host_path, &directory.path().join("two.lock")).is_err()
        );
        drop(first);
        assert!(
            KernelHostLease::acquire_at(&host_path, &directory.path().join("two.lock")).is_ok()
        );
        Ok(())
    }
}
