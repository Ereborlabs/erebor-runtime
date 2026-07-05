use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::error::{CopyArtifactSnafu, CreateDirSnafu};
use crate::{SessionRegistryError, SessionRunPlan};

use super::{SESSION_CONFIG_FILE, SESSION_POLICIES_DIR};

pub(super) struct SessionArtifactCopier<'a> {
    session_dir: &'a Path,
}

impl<'a> SessionArtifactCopier<'a> {
    pub(super) const fn new(session_dir: &'a Path) -> Self {
        Self { session_dir }
    }

    pub(super) fn copy_config(
        &self,
        plan: &SessionRunPlan,
    ) -> Result<Option<PathBuf>, SessionRegistryError> {
        let Some(source) = plan.config_path() else {
            return Ok(None);
        };
        let destination = self.session_dir.join(SESSION_CONFIG_FILE);
        fs::copy(source, &destination).context(CopyArtifactSnafu {
            from: source.to_path_buf(),
            to: destination.clone(),
        })?;
        Ok(Some(destination))
    }

    pub(super) fn copy_policies(
        &self,
        policies: &[PathBuf],
    ) -> Result<Vec<PathBuf>, SessionRegistryError> {
        let policy_dir = self.session_dir.join(SESSION_POLICIES_DIR);
        fs::create_dir_all(&policy_dir).context(CreateDirSnafu {
            path: policy_dir.clone(),
        })?;

        policies
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let file_name = source
                    .file_name()
                    .filter(|name| !name.is_empty())
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| String::from("policy.json"));
                let destination = policy_dir.join(format!("{index:03}-{file_name}"));
                fs::copy(source, &destination).context(CopyArtifactSnafu {
                    from: source.to_path_buf(),
                    to: destination.clone(),
                })?;
                Ok(destination)
            })
            .collect()
    }
}
