use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub use erebor_runtime_filesystem::{FilesystemBackendKind, FilesystemVolumeMode};
use serde::Deserialize;
use snafu::ensure;

use super::surface_policies;
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
            valid_volume_id(&self.id),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!("filesystem volume id `{}` is invalid", self.id)
            }
        );
        ensure!(
            path_present(&self.host_path),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!("filesystem volume `{}` host_path cannot be empty", self.id)
            }
        );
        ensure!(
            path_present(&self.session_path),
            InvalidFilesystemSurfaceConfigSnafu {
                reason: format!(
                    "filesystem volume `{}` session_path cannot be empty",
                    self.id
                )
            }
        );

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRevertLayerConfig {
    #[serde(default = "default_promote_on_session_finish")]
    pub promote_on_session_finish: bool,
    #[serde(default = "default_retain_layers")]
    pub retain_layers: bool,
    #[serde(default = "default_preimage_size_limit_bytes")]
    pub preimage_size_limit_bytes: u64,
}

impl Default for FilesystemRevertLayerConfig {
    fn default() -> Self {
        Self {
            promote_on_session_finish: default_promote_on_session_finish(),
            retain_layers: default_retain_layers(),
            preimage_size_limit_bytes: default_preimage_size_limit_bytes(),
        }
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
            policies: surface_policies(&config.policies, default_policies),
            backend: config.backend.into(),
            volumes: config.volumes.iter().map(Into::into).collect(),
            revert: config.revert.into(),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemRevertConfig {
    promote_on_session_finish: bool,
    retain_layers: bool,
    preimage_size_limit_bytes: u64,
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
}

impl From<FilesystemRevertLayerConfig> for FilesystemRevertConfig {
    fn from(config: FilesystemRevertLayerConfig) -> Self {
        Self {
            promote_on_session_finish: config.promote_on_session_finish,
            retain_layers: config.retain_layers,
            preimage_size_limit_bytes: config.preimage_size_limit_bytes,
        }
    }
}

fn valid_volume_id(id: &str) -> bool {
    !id.trim().is_empty()
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn path_present(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}

const fn default_promote_on_session_finish() -> bool {
    true
}

const fn default_retain_layers() -> bool {
    true
}

const fn default_preimage_size_limit_bytes() -> u64 {
    104_857_600
}

#[cfg(test)]
mod tests;
