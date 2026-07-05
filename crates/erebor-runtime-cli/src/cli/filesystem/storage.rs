use std::{fs, path::Path};

use erebor_runtime_core::{RuntimeConfig, SessionRegistry};
use erebor_runtime_filesystem::{FilesystemSessionStorage, FilesystemVolumeStorageRequest};
use snafu::{OptionExt, ResultExt};

use crate::error::{
    CliError, FilesystemSnafu, InvalidConfigSnafu, InvalidFilesystemCommandSnafu, ReadConfigSnafu,
    SessionRegistrySnafu,
};

use super::super::resolve_config_paths;

pub(super) fn open_storage(
    registry_path: &Path,
    session_id: &str,
) -> Result<FilesystemSessionStorage, CliError> {
    let registry = SessionRegistry::new(registry_path);
    let record = registry
        .load_session(session_id)
        .context(SessionRegistrySnafu)?;
    let config_artifact = record
        .config_artifact_path()
        .context(InvalidFilesystemCommandSnafu {
            reason: String::from("session has no copied config artifact"),
        })?;
    let source = fs::read_to_string(config_artifact).context(ReadConfigSnafu {
        path: config_artifact.to_path_buf(),
    })?;
    let mut config = RuntimeConfig::from_json_str(&source).context(InvalidConfigSnafu)?;
    let path_base = record
        .source_config_path
        .as_deref()
        .unwrap_or(config_artifact);
    resolve_config_paths(path_base, &mut config);
    let requests = config
        .surfaces
        .filesystem
        .volumes
        .iter()
        .map(|volume| {
            FilesystemVolumeStorageRequest::new(
                volume.id.clone(),
                volume.host_path.clone(),
                volume.session_path.clone(),
                volume.mode,
            )
            .context(FilesystemSnafu)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if requests.is_empty() {
        return InvalidFilesystemCommandSnafu {
            reason: String::from("session config has no filesystem volumes"),
        }
        .fail();
    }
    FilesystemSessionStorage::open_existing(record.session_dir, requests).context(FilesystemSnafu)
}
