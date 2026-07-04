use std::path::Path;

use snafu::ensure;

use crate::{
    error::{InvalidVolumeIdSnafu, InvalidVolumePathSnafu},
    Result,
};

pub(super) fn validate_volume_id(id: &str) -> Result<()> {
    ensure!(
        !id.trim().is_empty(),
        InvalidVolumeIdSnafu {
            id: id.to_owned(),
            reason: String::from("id cannot be empty")
        }
    );
    ensure!(
        id.chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-')),
        InvalidVolumeIdSnafu {
            id: id.to_owned(),
            reason: String::from("id must be a safe single path component")
        }
    );
    Ok(())
}

pub(super) fn validate_volume_path(
    volume_id: &str,
    field: &'static str,
    path: &Path,
) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty(),
        InvalidVolumePathSnafu {
            volume_id: volume_id.to_owned(),
            field,
            path: path.to_path_buf(),
            reason: String::from("path cannot be empty")
        }
    );
    ensure!(
        path.is_absolute(),
        InvalidVolumePathSnafu {
            volume_id: volume_id.to_owned(),
            field,
            path: path.to_path_buf(),
            reason: String::from("path must be absolute")
        }
    );
    Ok(())
}
