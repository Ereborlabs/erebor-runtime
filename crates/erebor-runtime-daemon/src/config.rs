use std::{collections::BTreeSet, io::Read, path::Path};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{error::InvalidConfigSnafu, paths::DaemonSecurity, DaemonPaths, Result};

const DEFAULT_MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_LOG_RECORDS: u32 = 256;
const DEFAULT_MAX_IDEMPOTENCY_RECORDS: u32 = 256;
const DEFAULT_MAX_SESSION_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SESSION_OUTPUT_ROTATION_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_DAEMON_LOSS_GRACE_SECONDS: u64 = 300;
const DEFAULT_SESSION_RETRY_HORIZON_SECONDS: u64 = 24 * 60 * 60;
const MIN_LOG_BYTES: u64 = 4096;
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LOG_RECORDS: u32 = 4096;
const MAX_IDEMPOTENCY_RECORDS: u32 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhaseTwoValidatedFixture {
    package_digest: Option<String>,
    installation_digest: Option<String>,
    adapter_digest: Option<String>,
    policy_input_digests: Vec<String>,
    policy_set_digest: String,
}

impl PhaseTwoValidatedFixture {
    fn validate(&self) -> bool {
        let agent_identity_is_complete = [
            self.package_digest.as_ref(),
            self.installation_digest.as_ref(),
            self.adapter_digest.as_ref(),
        ]
        .into_iter()
        .all(|identity| identity.is_some());
        let agent_identity_is_absent = self.package_digest.is_none()
            && self.installation_digest.is_none()
            && self.adapter_digest.is_none();
        (agent_identity_is_complete || agent_identity_is_absent)
            && self
                .package_digest
                .iter()
                .chain(self.installation_digest.iter())
                .chain(self.adapter_digest.iter())
                .chain(self.policy_input_digests.iter())
                .chain(std::iter::once(&self.policy_set_digest))
                .all(|digest| valid_sha256(digest))
            && !self.policy_input_digests.is_empty()
            && self
                .policy_input_digests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.policy_input_digests.len()
    }

    pub(crate) fn policy_input_digests(&self) -> &[String] {
        &self.policy_input_digests
    }

    fn matches(
        &self,
        package_digest: Option<&str>,
        installation_digest: Option<&str>,
        adapter_digest: Option<&str>,
        policy_set_digest: &str,
    ) -> bool {
        self.package_digest.as_deref() == package_digest
            && self.installation_digest.as_deref() == installation_digest
            && self.adapter_digest.as_deref() == adapter_digest
            && self.policy_set_digest == policy_set_digest
    }
}

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
    #[serde(default = "default_max_session_output_bytes")]
    pub max_session_output_bytes: u64,
    #[serde(default = "default_session_output_rotation_bytes")]
    pub session_output_rotation_bytes: u64,
    #[serde(default = "default_max_daemon_loss_grace_seconds")]
    pub max_daemon_loss_grace_seconds: u64,
    #[serde(default = "default_session_retry_horizon_seconds")]
    pub session_retry_horizon_seconds: u64,
    #[serde(default)]
    pub(crate) phase_two_validated_fixtures: Vec<PhaseTwoValidatedFixture>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_group_gid: 0,
            max_log_bytes: DEFAULT_MAX_LOG_BYTES,
            max_log_records: DEFAULT_MAX_LOG_RECORDS,
            max_idempotency_records: DEFAULT_MAX_IDEMPOTENCY_RECORDS,
            max_session_output_bytes: DEFAULT_MAX_SESSION_OUTPUT_BYTES,
            session_output_rotation_bytes: DEFAULT_SESSION_OUTPUT_ROTATION_BYTES,
            max_daemon_loss_grace_seconds: DEFAULT_MAX_DAEMON_LOSS_GRACE_SECONDS,
            session_retry_horizon_seconds: DEFAULT_SESSION_RETRY_HORIZON_SECONDS,
            phase_two_validated_fixtures: Vec::new(),
        }
    }
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
            || self.max_session_output_bytes < 4096
            || self.session_output_rotation_bytes == 0
            || self.session_output_rotation_bytes > self.max_session_output_bytes / 4
            || self.max_daemon_loss_grace_seconds == 0
            || self.max_daemon_loss_grace_seconds > 24 * 60 * 60
            || self.session_retry_horizon_seconds == 0
            || !valid_phase_two_fixtures(&self.phase_two_validated_fixtures)
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

    pub(crate) fn phase_two_fixture(
        &self,
        package_digest: Option<&str>,
        installation_digest: Option<&str>,
        adapter_digest: Option<&str>,
        policy_set_digest: &str,
    ) -> Option<&PhaseTwoValidatedFixture> {
        self.phase_two_validated_fixtures.iter().find(|fixture| {
            fixture.matches(
                package_digest,
                installation_digest,
                adapter_digest,
                policy_set_digest,
            )
        })
    }
}

fn valid_phase_two_fixtures(fixtures: &[PhaseTwoValidatedFixture]) -> bool {
    fixtures.iter().all(PhaseTwoValidatedFixture::validate)
        && fixtures.iter().collect::<BTreeSet<_>>().len() == fixtures.len()
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

const fn default_max_session_output_bytes() -> u64 {
    DEFAULT_MAX_SESSION_OUTPUT_BYTES
}

const fn default_session_output_rotation_bytes() -> u64 {
    DEFAULT_SESSION_OUTPUT_ROTATION_BYTES
}

const fn default_max_daemon_loss_grace_seconds() -> u64 {
    DEFAULT_MAX_DAEMON_LOSS_GRACE_SECONDS
}

const fn default_session_retry_horizon_seconds() -> u64 {
    DEFAULT_SESSION_RETRY_HORIZON_SECONDS
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{DaemonConfig, PhaseTwoValidatedFixture};

    #[test]
    fn phase_two_fixtures_require_complete_unique_validated_identity_sets() {
        let digest =
            String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let fixture = PhaseTwoValidatedFixture {
            package_digest: Some(digest.clone()),
            installation_digest: Some(digest.clone()),
            adapter_digest: Some(digest.clone()),
            policy_input_digests: vec![digest.clone()],
            policy_set_digest: digest.clone(),
        };
        let mut config = DaemonConfig {
            phase_two_validated_fixtures: vec![fixture.clone()],
            ..DaemonConfig::default()
        };
        assert!(config.validate(Path::new("<test-config>")).is_ok());
        assert!(config
            .phase_two_fixture(Some(&digest), Some(&digest), Some(&digest), &digest)
            .is_some());
        assert!(config
            .phase_two_fixture(None, Some(&digest), Some(&digest), &digest)
            .is_none());

        config.phase_two_validated_fixtures = vec![fixture.clone(), fixture];
        assert!(config.validate(Path::new("<test-config>")).is_err());
        config.phase_two_validated_fixtures = vec![PhaseTwoValidatedFixture {
            package_digest: Some(digest.clone()),
            installation_digest: None,
            adapter_digest: Some(digest.clone()),
            policy_input_digests: vec![digest.clone()],
            policy_set_digest: digest,
        }];
        assert!(config.validate(Path::new("<test-config>")).is_err());
    }
}
