use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt;

use crate::error::{
    ContextArtifactSymlinkSnafu, InspectContextArtifactSnafu, InvalidContextArtifactPathSnafu,
    InvalidSessionDirectoryNameSnafu, SessionDirectorySymlinkSnafu,
};
use crate::SessionRegistryError;

pub(super) struct SessionRegistryPath;

impl SessionRegistryPath {
    pub(super) fn safe_dir_name(session_id: &str) -> String {
        session_id
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    pub(super) fn session_dir_name(session_id: &str) -> Result<String, SessionRegistryError> {
        let name = Self::safe_dir_name(session_id);
        if name.is_empty() || matches!(name.as_str(), "." | "..") {
            return InvalidSessionDirectoryNameSnafu {
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        Ok(name)
    }

    pub(super) fn validate_session_directory(
        session_id: &str,
        session_dir: &Path,
    ) -> Result<(), SessionRegistryError> {
        let metadata = fs::symlink_metadata(session_dir).context(InspectContextArtifactSnafu {
            session_id,
            path: session_dir.to_path_buf(),
        })?;
        if metadata.file_type().is_symlink() {
            return SessionDirectorySymlinkSnafu {
                path: session_dir.to_path_buf(),
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn context_path(
        session_id: &str,
        session_dir: &Path,
        relative_path: &Path,
    ) -> Result<PathBuf, SessionRegistryError> {
        if relative_path.is_absolute() {
            return InvalidContextArtifactPathSnafu {
                session_id: session_id.to_owned(),
                path: Box::new(relative_path.to_path_buf()),
                reason: "must be relative to the session directory",
            }
            .fail();
        }
        if relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return InvalidContextArtifactPathSnafu {
                session_id: session_id.to_owned(),
                path: Box::new(relative_path.to_path_buf()),
                reason: "must not contain root, current-directory, or parent-directory components",
            }
            .fail();
        }
        if relative_path != Path::new("context") {
            return InvalidContextArtifactPathSnafu {
                session_id: session_id.to_owned(),
                path: Box::new(relative_path.to_path_buf()),
                reason: "must be the authorized `context` artifact path",
            }
            .fail();
        }
        Self::validate_session_directory(session_id, session_dir)?;
        let context_path = session_dir.join(relative_path);
        match fs::symlink_metadata(&context_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => ContextArtifactSymlinkSnafu {
                session_id: session_id.to_owned(),
                path: context_path,
            }
            .fail(),
            Ok(_) => Ok(context_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(context_path),
            Err(source) => Err(source).context(InspectContextArtifactSnafu {
                session_id: session_id.to_owned(),
                path: context_path,
            }),
        }
    }

    pub(super) fn absolute_root(root: PathBuf) -> PathBuf {
        if root.is_absolute() {
            return root;
        }
        match std::env::current_dir() {
            Ok(current_dir) => current_dir.join(root),
            Err(_error) => root,
        }
    }
}
