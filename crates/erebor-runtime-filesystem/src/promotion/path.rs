use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{PromotionIoSnafu, UnsupportedLayerSnafu},
    Result,
};

pub(super) fn safe_relative(volume_id: &str, value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() {
        return invalid_path(volume_id, value);
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return invalid_path(volume_id, value),
        }
    }
    Ok(relative)
}

pub(super) fn create_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(PromotionIoSnafu {
            action: "create promotion parent directory",
            path: parent,
        })?;
    }
    Ok(())
}

pub(super) fn remove_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(source).context(PromotionIoSnafu {
                action: "inspect promotion target before removal",
                path,
            });
        }
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path).context(PromotionIoSnafu {
            action: "remove promotion directory",
            path,
        })
    } else {
        fs::remove_file(path).context(PromotionIoSnafu {
            action: "remove promotion file",
            path,
        })
    }
}

fn invalid_path(volume_id: &str, value: &str) -> Result<PathBuf> {
    UnsupportedLayerSnafu {
        volume_id: volume_id.to_owned(),
        reason: format!("promotion path `{value}` is not a safe relative path"),
    }
    .fail()
}
