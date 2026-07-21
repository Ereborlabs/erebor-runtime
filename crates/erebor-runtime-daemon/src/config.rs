use std::{collections::BTreeSet, io::Read, path::Path};

use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, InstallationRecord, PolicyPackageRevision,
    PolicySetRevision,
};
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
const DEFAULT_MAX_POLICY_UPLOAD_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_SESSIONS_PER_UID: u32 = 16;
const MIN_LOG_BYTES: u64 = 4096;
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LOG_RECORDS: u32 = 4096;
const MAX_IDEMPOTENCY_RECORDS: u32 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootCuratedAdmission {
    package: AgentPackageManifest,
    installation: InstallationRecord,
    policy_set: PolicySetRevision,
    policies: Vec<PolicyPackageRevision>,
}

impl RootCuratedAdmission {
    #[cfg(test)]
    pub(crate) fn new(
        package: AgentPackageManifest,
        installation: InstallationRecord,
        policy_set: PolicySetRevision,
        policies: Vec<PolicyPackageRevision>,
    ) -> Self {
        Self {
            package,
            installation,
            policy_set,
            policies,
        }
    }

    fn validate(&self) -> bool {
        self.package.validate().is_ok()
            && self.installation.validate().is_ok()
            && self.policy_set.validate().is_ok()
            && self
                .package
                .canonical_digest()
                .is_ok_and(|digest| self.installation.package_digest() == &digest)
            && self.policy_set.policy_input_digests().iter().all(|digest| {
                self.policies.iter().any(|policy| {
                    policy
                        .canonical_digest()
                        .is_ok_and(|candidate| candidate == **digest)
                })
            })
    }

    pub(crate) fn package(&self) -> &AgentPackageManifest {
        &self.package
    }

    pub(crate) fn installation(&self) -> &InstallationRecord {
        &self.installation
    }

    pub(crate) fn policy_set(&self) -> &PolicySetRevision {
        &self.policy_set
    }

    pub(crate) fn policies(&self) -> &[PolicyPackageRevision] {
        &self.policies
    }

    fn identity_key(&self) -> Option<(String, String, String)> {
        Some((
            self.package.canonical_digest().ok()?.as_str().to_owned(),
            self.installation
                .canonical_digest()
                .ok()?
                .as_str()
                .to_owned(),
            self.policy_set.canonical_digest().ok()?.as_str().to_owned(),
        ))
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
    #[serde(default = "default_max_policy_upload_bytes")]
    pub max_policy_upload_bytes: u64,
    #[serde(default = "default_max_concurrent_sessions_per_uid")]
    pub max_concurrent_sessions_per_uid: u32,
    #[serde(default)]
    pub(crate) root_curated_admissions: Vec<RootCuratedAdmission>,
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
            max_policy_upload_bytes: DEFAULT_MAX_POLICY_UPLOAD_BYTES,
            max_concurrent_sessions_per_uid: DEFAULT_MAX_CONCURRENT_SESSIONS_PER_UID,
            root_curated_admissions: Vec::new(),
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
            || self.max_policy_upload_bytes < 1024
            || self.max_policy_upload_bytes > 8 * 1024 * 1024
            || self.max_concurrent_sessions_per_uid == 0
            || self.max_concurrent_sessions_per_uid > 1024
            || !valid_root_curated_admissions(&self.root_curated_admissions)
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

    pub(crate) fn root_curated_admissions(&self) -> &[RootCuratedAdmission] {
        &self.root_curated_admissions
    }

    pub(crate) const fn max_policy_upload_bytes(&self) -> u64 {
        self.max_policy_upload_bytes
    }

    pub(crate) const fn max_concurrent_sessions_per_uid(&self) -> u32 {
        self.max_concurrent_sessions_per_uid
    }
}

fn valid_root_curated_admissions(admissions: &[RootCuratedAdmission]) -> bool {
    let keys = admissions
        .iter()
        .map(RootCuratedAdmission::identity_key)
        .collect::<Option<BTreeSet<_>>>();
    admissions.iter().all(RootCuratedAdmission::validate)
        && keys.is_some_and(|keys| keys.len() == admissions.len())
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

const fn default_max_policy_upload_bytes() -> u64 {
    DEFAULT_MAX_POLICY_UPLOAD_BYTES
}

const fn default_max_concurrent_sessions_per_uid() -> u32 {
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_UID
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use erebor_runtime_packages::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
        PolicyPackageRevision, PolicySetRevision,
    };

    use super::{DaemonConfig, RootCuratedAdmission};

    #[test]
    fn root_curated_admissions_require_matching_unique_canonical_identities(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config_digest =
            ContentDigest::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            config_digest,
            Vec::new(),
        )?;
        let installation = InstallationRecord::new(1000, package.canonical_digest()?, 1);
        let policy = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            )]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        let policy_set = PolicySetRevision::new(policy.canonical_digest()?, Vec::new(), None)?;
        let admission = RootCuratedAdmission::new(package, installation, policy_set, vec![policy]);
        let mut config = DaemonConfig {
            root_curated_admissions: vec![admission.clone()],
            ..DaemonConfig::default()
        };
        assert!(config.validate(Path::new("<test-config>")).is_ok());
        assert_eq!(config.root_curated_admissions().len(), 1);

        config.root_curated_admissions = vec![admission.clone(), admission];
        assert!(config.validate(Path::new("<test-config>")).is_err());
        Ok(())
    }
}
