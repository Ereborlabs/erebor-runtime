use std::{fs::File, path::Path};

use rustix::fs::{flock, FlockOperation};

use snafu::ResultExt;

use crate::{error::PromotionIoSnafu, Result};

pub(super) struct PromotionLock {
    file: File,
}

impl PromotionLock {
    pub(super) fn acquire(work_path: &Path) -> Result<Self> {
        let path = work_path.join("promotion.lock");
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .context(PromotionIoSnafu {
                action: "open promotion lock",
                path: path.as_path(),
            })?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)
            .context(PromotionIoSnafu {
                action: "lock promotion file",
                path: path.as_path(),
            })?;
        Ok(Self { file })
    }
}

impl Drop for PromotionLock {
    fn drop(&mut self) {
        let _result = flock(&self.file, FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::PromotionLock;

    #[test]
    fn existing_unlocked_file_does_not_block_promotion_lock() -> crate::Result<()> {
        let root =
            std::env::temp_dir().join(format!("erebor-promotion-lock-{}", std::process::id()));
        let _result = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|source| crate::FilesystemError::PromotionIo {
            action: "create lock test root",
            path: root.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        std::fs::write(root.join("promotion.lock"), b"stale").map_err(|source| {
            crate::FilesystemError::PromotionIo {
                action: "write stale promotion lock",
                path: root.join("promotion.lock"),
                source,
                location: snafu::Location::default(),
            }
        })?;

        let _lock = PromotionLock::acquire(&root)?;

        let _result = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn active_lock_blocks_second_promotion_lock() -> crate::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "erebor-promotion-lock-active-{}",
            std::process::id()
        ));
        let _result = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|source| crate::FilesystemError::PromotionIo {
            action: "create lock test root",
            path: root.clone(),
            source,
            location: snafu::Location::default(),
        })?;

        let _lock = PromotionLock::acquire(&root)?;
        let result = PromotionLock::acquire(&root);

        assert!(matches!(
            result,
            Err(crate::FilesystemError::PromotionIo { .. })
        ));
        let _result = std::fs::remove_dir_all(&root);
        Ok(())
    }
}
