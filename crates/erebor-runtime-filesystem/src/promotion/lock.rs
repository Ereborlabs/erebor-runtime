use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{error::PromotionIoSnafu, Result};

pub(super) struct PromotionLock {
    path: PathBuf,
}

impl PromotionLock {
    pub(super) fn acquire(work_path: &Path) -> Result<Self> {
        let path = work_path.join("promotion.lock");
        fs::create_dir(&path).context(PromotionIoSnafu {
            action: "create promotion lock",
            path: path.as_path(),
        })?;
        Ok(Self { path })
    }
}

impl Drop for PromotionLock {
    fn drop(&mut self) {
        let _result = fs::remove_dir(&self.path);
    }
}
