use std::fs::{self, File};
use std::path::{Path, PathBuf};

use rustix::fs::{flock, FlockOperation};
use snafu::ResultExt as _;

use crate::error::{IoSnafu, LeaseOwnedSnafu};
use crate::Result;

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

#[cfg(test)]
mod tests {
    use snafu::ResultExt as _;

    use super::PinRootLease;
    use crate::error::IoSnafu;

    #[test]
    fn runtime_mithril_and_co_resident_modes_use_the_same_exclusive_lease() -> crate::Result<()> {
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
}
