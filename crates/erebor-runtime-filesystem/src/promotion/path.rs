use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{PromotionIoSnafu, UnsupportedLayerSnafu},
    Result,
};

pub(super) struct PromotionPath<'a> {
    volume_id: &'a str,
    value: &'a str,
}

impl<'a> PromotionPath<'a> {
    pub(super) const fn new(volume_id: &'a str, value: &'a str) -> Self {
        Self { volume_id, value }
    }

    pub(super) fn relative(&self) -> Result<PathBuf> {
        let path = Path::new(self.value);
        if path.as_os_str().is_empty() {
            return self.invalid_path();
        }
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => return self.invalid_path(),
            }
        }
        Ok(relative)
    }

    fn invalid_path<T>(&self) -> Result<T> {
        UnsupportedLayerSnafu {
            volume_id: self.volume_id.to_owned(),
            reason: format!(
                "promotion path `{}` is not a safe relative path",
                self.value
            ),
        }
        .fail()
    }
}

pub(super) struct PromotionTargetPath<'a> {
    path: &'a Path,
}

impl<'a> PromotionTargetPath<'a> {
    pub(super) const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub(super) fn create_parent(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context(PromotionIoSnafu {
                action: "create promotion parent directory",
                path: parent,
            })?;
        }
        Ok(())
    }

    pub(super) fn remove(&self) -> Result<()> {
        let metadata = match fs::symlink_metadata(self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(source).context(PromotionIoSnafu {
                    action: "inspect promotion target before removal",
                    path: self.path,
                });
            }
        };
        if metadata.is_dir() {
            fs::remove_dir_all(self.path).context(PromotionIoSnafu {
                action: "remove promotion directory",
                path: self.path,
            })
        } else {
            fs::remove_file(self.path).context(PromotionIoSnafu {
                action: "remove promotion file",
                path: self.path,
            })
        }
    }
}
