use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_core::RuntimeConfig;
use snafu::ResultExt;

use crate::error::{CliError, InvalidConfigSnafu, ReadConfigSnafu};

pub(crate) struct RuntimeConfigLoader;

impl RuntimeConfigLoader {
    pub(crate) fn read(path: &Path) -> Result<RuntimeConfig, CliError> {
        tracing::debug!(path = %path.display(), "reading runtime config");
        let source = fs::read_to_string(path).context(ReadConfigSnafu {
            path: path.to_path_buf(),
        })?;
        let mut config: RuntimeConfig =
            RuntimeConfig::from_json_str(&source).context(InvalidConfigSnafu)?;
        ConfigPathResolver::from_config_path(path).resolve(&mut config);

        Ok(config)
    }
}

pub(crate) struct ConfigPathResolver {
    base_dir: Option<PathBuf>,
}

impl ConfigPathResolver {
    pub(crate) fn from_config_path(config_path: &Path) -> Self {
        Self {
            base_dir: Self::config_base_dir(config_path),
        }
    }

    pub(crate) fn resolve(&self, config: &mut RuntimeConfig) {
        for policy in &mut config.policies {
            self.resolve_path(policy);
        }
        self.resolve_optional_path(&mut config.session.workspace);
        self.resolve_optional_path(&mut config.surfaces.browser_cdp.browser.executable);
        self.resolve_optional_path(&mut config.surfaces.browser_cdp.browser.user_data_dir);
        for policy in &mut config.surfaces.browser_cdp.policies {
            self.resolve_path(policy);
        }
        for policy in &mut config.surfaces.terminal.policies {
            self.resolve_path(policy);
        }
        for policy in &mut config.surfaces.filesystem.policies {
            self.resolve_path(policy);
        }
        for volume in &mut config.surfaces.filesystem.volumes {
            self.resolve_path(&mut volume.host_path);
            self.resolve_path(&mut volume.session_path);
        }
    }

    fn config_base_dir(config_path: &Path) -> Option<PathBuf> {
        config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map(|current_dir| current_dir.join(path))
                        .unwrap_or_else(|_| path.to_path_buf())
                }
            })
    }

    fn resolve_optional_path(&self, path: &mut Option<PathBuf>) {
        if let Some(path) = path {
            self.resolve_path(path);
        }
    }

    fn resolve_path(&self, path: &mut PathBuf) {
        if path.is_absolute() {
            return;
        }
        let Some(base_dir) = self.base_dir.as_deref() else {
            return;
        };

        *path = base_dir.join(&path);
    }
}

#[cfg(test)]
mod tests;
