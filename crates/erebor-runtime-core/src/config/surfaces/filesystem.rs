use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub use erebor_runtime_filesystem::{
    FilesystemBackendKind, FilesystemPreimageBackendKind, FilesystemSessionWorkAutocommitBoundary,
    FilesystemVolumeMode,
};
use serde::Deserialize;
use snafu::ensure;

use super::SurfacePolicyResolver;
use crate::error::InvalidFilesystemSurfaceConfigSnafu;
use crate::RuntimeConfigError;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSurfaceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub backend: FilesystemBackendLayerConfig,
    #[serde(default)]
    pub volumes: Vec<FilesystemVolumeLayerConfig>,
    #[serde(default)]
    pub revert: FilesystemRevertLayerConfig,
}

impl FilesystemSurfaceLayerConfig {
    pub(crate) fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            self.backend.kind.is_supported(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: String::from("unsupported filesystem backend kind")
            }
        );
        self.revert.validate()?;

        let mut ids = HashSet::new();
        for volume in &self.volumes {
            volume.validate()?;
            ensure!(
                ids.insert(volume.id.clone()),
                InvalidFilesystemSurfaceConfigSnafu {
                    reason: format!("filesystem volume `{}` is duplicated", volume.id)
                }
            );
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBackendLayerConfig {
    #[serde(default)]
    pub kind: FilesystemBackendKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemVolumeLayerConfig {
    pub id: String,
    pub host_path: PathBuf,
    pub session_path: PathBuf,
    #[serde(default)]
    pub mode: FilesystemVolumeMode,
}

impl FilesystemVolumeLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            self.has_valid_id(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!("filesystem volume id `{}` is invalid", self.id)
            }
        );
        ensure!(
            self.has_host_path(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!("filesystem volume `{}` host_path cannot be empty", self.id)
            }
        );
        ensure!(
            self.has_session_path(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!(
                    "filesystem volume `{}` session_path cannot be empty",
                    self.id
                )
            }
        );

        Ok(())
    }

    fn has_valid_id(&self) -> bool {
        !self.id.trim().is_empty()
            && self.id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    }

    fn has_host_path(&self) -> bool {
        !self.host_path.as_os_str().is_empty()
    }

    fn has_session_path(&self) -> bool {
        !self.session_path.as_os_str().is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRevertLayerConfig {
    pub promote_on_session_finish: bool,
    pub retain_layers: bool,
    pub preimage_size_limit_bytes: u64,
    pub preimage_backend: FilesystemPreimageBackendKind,
    #[serde(default)]
    pub autocommit: FilesystemSessionWorkAutocommitLayerConfig,
}

impl Default for FilesystemRevertLayerConfig {
    fn default() -> Self {
        Self {
            promote_on_session_finish: true,
            retain_layers: true,
            preimage_size_limit_bytes: 104_857_600,
            preimage_backend: FilesystemPreimageBackendKind::OstreeBytes,
            autocommit: FilesystemSessionWorkAutocommitLayerConfig::default(),
        }
    }
}

impl FilesystemRevertLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            self.preimage_backend.is_supported(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: String::from("unsupported filesystem preimage backend kind")
            }
        );
        self.autocommit.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSessionWorkAutocommitLayerConfig {
    pub enabled: bool,
    pub rules: Vec<FilesystemSessionWorkAutocommitRuleLayerConfig>,
}

impl FilesystemSessionWorkAutocommitLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if !self.enabled {
            return Ok(());
        }
        ensure!(
            !self.rules.is_empty(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: String::from("filesystem autocommit requires at least one rule")
            }
        );
        let mut ids = HashSet::new();
        for rule in &self.rules {
            rule.validate()?;
            ensure!(
                ids.insert(rule.id.clone()),
                InvalidFilesystemSurfaceConfigSnafu {
                    reason: format!("filesystem autocommit rule `{}` is duplicated", rule.id)
                }
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSessionWorkAutocommitRuleLayerConfig {
    pub id: String,
    #[serde(default)]
    pub boundary: FilesystemSessionWorkAutocommitBoundary,
}

impl FilesystemSessionWorkAutocommitRuleLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            !self.id.trim().is_empty()
                && self
                    .id
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || matches!(character, '_' | '-')),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!("filesystem autocommit rule id `{}` is invalid", self.id)
            }
        );
        ensure!(
            self.boundary.is_supported(),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: String::from("unsupported filesystem autocommit boundary")
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSurfaceConfig {
    policies: Vec<PathBuf>,
    backend: FilesystemBackendConfig,
    volumes: Vec<FilesystemVolumeConfig>,
    revert: FilesystemRevertConfig,
}

impl FilesystemSurfaceConfig {
    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn backend(&self) -> &FilesystemBackendConfig {
        &self.backend
    }

    #[must_use]
    pub fn volumes(&self) -> &[FilesystemVolumeConfig] {
        &self.volumes
    }

    #[must_use]
    pub const fn revert(&self) -> &FilesystemRevertConfig {
        &self.revert
    }

    pub(crate) fn from_layer(
        config: &FilesystemSurfaceLayerConfig,
        default_policies: Vec<PathBuf>,
    ) -> Self {
        Self {
            policies: SurfacePolicyResolver::resolve(&config.policies, default_policies),
            backend: config.backend.into(),
            volumes: config.volumes.iter().map(Into::into).collect(),
            revert: config.revert.clone().into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemBackendConfig {
    kind: FilesystemBackendKind,
}

impl FilesystemBackendConfig {
    #[must_use]
    pub const fn kind(&self) -> FilesystemBackendKind {
        self.kind
    }
}

impl From<FilesystemBackendLayerConfig> for FilesystemBackendConfig {
    fn from(config: FilesystemBackendLayerConfig) -> Self {
        Self { kind: config.kind }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemVolumeConfig {
    id: String,
    host_path: PathBuf,
    session_path: PathBuf,
    mode: FilesystemVolumeMode,
}

impl FilesystemVolumeConfig {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    #[must_use]
    pub fn session_path(&self) -> &Path {
        &self.session_path
    }

    #[must_use]
    pub const fn mode(&self) -> FilesystemVolumeMode {
        self.mode
    }
}

impl From<&FilesystemVolumeLayerConfig> for FilesystemVolumeConfig {
    fn from(config: &FilesystemVolumeLayerConfig) -> Self {
        Self {
            id: config.id.clone(),
            host_path: config.host_path.clone(),
            session_path: config.session_path.clone(),
            mode: config.mode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemRevertConfig {
    promote_on_session_finish: bool,
    retain_layers: bool,
    preimage_size_limit_bytes: u64,
    preimage_backend: FilesystemPreimageBackendKind,
    autocommit: FilesystemSessionWorkAutocommitConfig,
}

impl FilesystemRevertConfig {
    #[must_use]
    pub const fn promote_on_session_finish(&self) -> bool {
        self.promote_on_session_finish
    }

    #[must_use]
    pub const fn retain_layers(&self) -> bool {
        self.retain_layers
    }

    #[must_use]
    pub const fn preimage_size_limit_bytes(&self) -> u64 {
        self.preimage_size_limit_bytes
    }

    #[must_use]
    pub const fn preimage_backend(&self) -> FilesystemPreimageBackendKind {
        self.preimage_backend
    }

    #[must_use]
    pub const fn autocommit(&self) -> &FilesystemSessionWorkAutocommitConfig {
        &self.autocommit
    }
}

impl From<FilesystemRevertLayerConfig> for FilesystemRevertConfig {
    fn from(config: FilesystemRevertLayerConfig) -> Self {
        Self {
            promote_on_session_finish: config.promote_on_session_finish,
            retain_layers: config.retain_layers,
            preimage_size_limit_bytes: config.preimage_size_limit_bytes,
            preimage_backend: config.preimage_backend,
            autocommit: config.autocommit.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesystemSessionWorkAutocommitConfig {
    enabled: bool,
    rules: Vec<FilesystemSessionWorkAutocommitRuleConfig>,
}

impl FilesystemSessionWorkAutocommitConfig {
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn rules(&self) -> &[FilesystemSessionWorkAutocommitRuleConfig] {
        &self.rules
    }

    #[must_use]
    pub fn session_finish_rule(&self) -> Option<&FilesystemSessionWorkAutocommitRuleConfig> {
        self.enabled.then_some(())?;
        self.rules
            .iter()
            .find(|rule| rule.boundary() == FilesystemSessionWorkAutocommitBoundary::SessionFinish)
    }
}

impl From<FilesystemSessionWorkAutocommitLayerConfig> for FilesystemSessionWorkAutocommitConfig {
    fn from(config: FilesystemSessionWorkAutocommitLayerConfig) -> Self {
        Self {
            enabled: config.enabled,
            rules: config.rules.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSessionWorkAutocommitRuleConfig {
    id: String,
    boundary: FilesystemSessionWorkAutocommitBoundary,
}

impl FilesystemSessionWorkAutocommitRuleConfig {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn boundary(&self) -> FilesystemSessionWorkAutocommitBoundary {
        self.boundary
    }
}

impl From<FilesystemSessionWorkAutocommitRuleLayerConfig>
    for FilesystemSessionWorkAutocommitRuleConfig
{
    fn from(config: FilesystemSessionWorkAutocommitRuleLayerConfig) -> Self {
        Self {
            id: config.id,
            boundary: config.boundary,
        }
    }
}

#[cfg(test)]
mod tests;
