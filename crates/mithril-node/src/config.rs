use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptorConfig {
    pub object_path: PathBuf,
    pub object_sha256: String,
    pub runtime_btf_path: PathBuf,
    pub lease_path: PathBuf,
    pub pin_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeControlConfig {
    pub endpoint: String,
    pub server_name: String,
    pub ca_path: PathBuf,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    #[serde(default = "default_reconnect_minimum_ms")]
    pub reconnect_minimum_ms: u64,
    #[serde(default = "default_reconnect_maximum_ms")]
    pub reconnect_maximum_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservationConfig {
    pub socket_path: PathBuf,
    pub allowed_uid: u32,
    pub cgroup_scope: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    pub state_directory: PathBuf,
    pub interceptor: InterceptorConfig,
    pub control: NodeControlConfig,
    #[serde(default)]
    pub runtime_observation: Option<RuntimeObservationConfig>,
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        let config: Self = serde_json::from_slice(&bytes).context(JsonSnafu { path })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.node_id.is_empty() && !self.node_id.chars().any(char::is_whitespace),
            InvalidConfigurationSnafu {
                reason: "node_id must be nonempty and contain no whitespace",
            }
        );
        ensure!(
            is_sha256_hex(&self.interceptor.object_sha256),
            InvalidConfigurationSnafu {
                reason: "interceptor object digest must be SHA-256 hex",
            }
        );
        ensure!(
            self.control.endpoint.starts_with("https://") && !self.control.server_name.is_empty(),
            InvalidConfigurationSnafu {
                reason: "Control endpoint must use HTTPS and have an explicit server name",
            }
        );
        ensure!(
            self.control.reconnect_minimum_ms > 0
                && self.control.reconnect_maximum_ms >= self.control.reconnect_minimum_ms,
            InvalidConfigurationSnafu {
                reason: "Control reconnect bounds are invalid",
            }
        );
        if let Some(runtime) = &self.runtime_observation {
            ensure!(
                runtime.cgroup_scope.starts_with('/')
                    && !runtime.cgroup_scope.split('/').any(|part| part == ".."),
                InvalidConfigurationSnafu {
                    reason: "Runtime observation cgroup_scope must be an absolute clean path",
                }
            );
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl NodeControlConfig {
    #[must_use]
    pub const fn reconnect_minimum(&self) -> Duration {
        Duration::from_millis(self.reconnect_minimum_ms)
    }

    #[must_use]
    pub const fn reconnect_maximum(&self) -> Duration {
        Duration::from_millis(self.reconnect_maximum_ms)
    }
}

const fn default_reconnect_minimum_ms() -> u64 {
    100
}

const fn default_reconnect_maximum_ms() -> u64 {
    5_000
}
