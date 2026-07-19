use std::{io::Read, path::Path};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{error::InvalidConfigSnafu, paths::DaemonSecurity, DaemonPaths, Result};

const DEFAULT_MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_LOG_RECORDS: u32 = 256;
const DEFAULT_MAX_IDEMPOTENCY_RECORDS: u32 = 256;
const MIN_LOG_BYTES: u64 = 4096;
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LOG_RECORDS: u32 = 4096;
const MAX_IDEMPOTENCY_RECORDS: u32 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub socket_group_gid: u32,
    #[serde(default = "default_max_log_bytes")]
    pub max_log_bytes: u64,
    #[serde(default = "default_max_log_records")]
    pub max_log_records: u32,
    #[serde(default = "default_max_idempotency_records")]
    pub max_idempotency_records: u32,
}

impl DaemonConfig {
    pub(crate) fn load(paths: &DaemonPaths, security: DaemonSecurity) -> Result<Self> {
        let path = paths.config_path();
        let mut source = String::new();
        paths
            .open_config(security)?
            .read_to_string(&mut source)
            .map_err(|source| crate::DaemonError::Io {
                action: "reading daemon configuration",
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        let config: Self = serde_json::from_str(&source).context(InvalidConfigSnafu { path })?;
        config.validate(path)?;
        Ok(config)
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.max_log_bytes < MIN_LOG_BYTES
            || self.max_log_bytes > MAX_LOG_BYTES
            || self.max_log_records == 0
            || self.max_log_records > MAX_LOG_RECORDS
            || self.max_idempotency_records == 0
            || self.max_idempotency_records > MAX_IDEMPOTENCY_RECORDS
        {
            return Err(crate::DaemonError::InvalidConfig {
                path: path.to_path_buf(),
                source: serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "daemon limits must be positive and within the configured maximums",
                )),
                location: snafu::Location::default(),
            });
        }
        Ok(())
    }
}

const fn default_max_log_bytes() -> u64 {
    DEFAULT_MAX_LOG_BYTES
}

const fn default_max_log_records() -> u32 {
    DEFAULT_MAX_LOG_RECORDS
}

const fn default_max_idempotency_records() -> u32 {
    DEFAULT_MAX_IDEMPOTENCY_RECORDS
}
