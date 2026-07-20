use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snafu::ensure;

mod docker;
mod linux_host;

pub use docker::{DockerSessionCommandOptions, DockerSessionCommandPlan, DockerSessionMount};
pub use linux_host::{LinuxHostSessionCommandOptions, LinuxHostSessionCommandPlan};

use crate::error::{EmptyDockerSessionImageSnafu, EmptyDockerSessionNetworkSnafu};
use crate::RuntimeConfigError;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct SessionRunnerLayerConfig {
    pub kind: SessionRunnerKind,
    pub docker: DockerSessionRunnerLayerConfig,
    pub linux_host: LinuxHostSessionRunnerLayerConfig,
}

impl SessionRunnerLayerConfig {
    pub(in crate::config) fn validate(&self) -> Result<(), RuntimeConfigError> {
        match self.kind {
            SessionRunnerKind::Docker => self.docker.validate(),
            SessionRunnerKind::LinuxHost => self.linux_host.validate(),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionRunnerKind {
    #[default]
    Docker,
    #[serde(alias = "linux-host")]
    LinuxHost,
}

impl SessionRunnerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::LinuxHost => "linux-host",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct LinuxHostSessionRunnerLayerConfig {}

impl LinuxHostSessionRunnerLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct DockerSessionRunnerLayerConfig {
    pub image: String,
    pub network: String,
    pub workdir: PathBuf,
}

impl Default for DockerSessionRunnerLayerConfig {
    fn default() -> Self {
        Self {
            image: String::from("alpine:3.20"),
            network: String::from("bridge"),
            workdir: PathBuf::from("/workspace"),
        }
    }
}

impl DockerSessionRunnerLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(!self.image.trim().is_empty(), EmptyDockerSessionImageSnafu);

        ensure!(
            !self.network.trim().is_empty(),
            EmptyDockerSessionNetworkSnafu
        );

        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunnerConfig {
    kind: SessionRunnerKind,
    docker: DockerSessionRunnerConfig,
    linux_host: LinuxHostSessionRunnerConfig,
}

impl SessionRunnerConfig {
    #[must_use]
    pub const fn kind(&self) -> SessionRunnerKind {
        self.kind
    }

    #[must_use]
    pub const fn docker(&self) -> &DockerSessionRunnerConfig {
        &self.docker
    }

    #[must_use]
    pub const fn linux_host(&self) -> &LinuxHostSessionRunnerConfig {
        &self.linux_host
    }
}

impl From<SessionRunnerLayerConfig> for SessionRunnerConfig {
    fn from(config: SessionRunnerLayerConfig) -> Self {
        Self {
            kind: config.kind,
            docker: config.docker.into(),
            linux_host: config.linux_host.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionRunnerConfig {}

impl From<LinuxHostSessionRunnerLayerConfig> for LinuxHostSessionRunnerConfig {
    fn from(_config: LinuxHostSessionRunnerLayerConfig) -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionRunnerConfig {
    image: String,
    network: String,
    workdir: PathBuf,
}

impl DockerSessionRunnerConfig {
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    #[must_use]
    pub fn needs_host_reachable_endpoints(&self) -> bool {
        !self.network.eq_ignore_ascii_case("host") && !self.network.eq_ignore_ascii_case("none")
    }
}

impl From<DockerSessionRunnerLayerConfig> for DockerSessionRunnerConfig {
    fn from(config: DockerSessionRunnerLayerConfig) -> Self {
        Self {
            image: config.image,
            network: config.network,
            workdir: config.workdir,
        }
    }
}
