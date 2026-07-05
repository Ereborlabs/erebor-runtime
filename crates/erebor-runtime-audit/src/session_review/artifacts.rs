use std::{fs, path::Path};

use erebor_runtime_core::RuntimeConfig;
use snafu::ResultExt;

use crate::{
    error::{ReviewInvalidRuntimeConfigSnafu, ReviewReadFileSnafu},
    evidence_trace::EvidenceHasher,
    SessionReviewError,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionReviewArtifacts {
    runner: Option<String>,
    policy_sha256: Option<String>,
    config_sha256: Option<String>,
}

impl SessionReviewArtifacts {
    #[must_use]
    pub fn new(runner: Option<String>) -> Self {
        Self {
            runner,
            policy_sha256: None,
            config_sha256: None,
        }
    }

    pub fn from_paths(
        runner: Option<String>,
        policy: &Path,
        config: &Path,
    ) -> Result<Self, SessionReviewError> {
        Ok(Self {
            runner,
            policy_sha256: Some(SessionReviewArtifactHasher::file_sha256(policy)?),
            config_sha256: Some(SessionReviewArtifactHasher::file_sha256(config)?),
        })
    }

    #[must_use]
    pub fn runner(&self) -> Option<&str> {
        self.runner.as_deref()
    }

    #[must_use]
    pub fn policy_sha256(&self) -> Option<&str> {
        self.policy_sha256.as_deref()
    }

    #[must_use]
    pub fn config_sha256(&self) -> Option<&str> {
        self.config_sha256.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SessionReviewArtifactLoader;

impl SessionReviewArtifactLoader {
    pub(crate) fn from_config_paths(
        policy: &Path,
        config: &Path,
    ) -> Result<SessionReviewArtifacts, SessionReviewError> {
        let config_source = fs::read_to_string(config).context(ReviewReadFileSnafu {
            path: config.to_path_buf(),
        })?;
        let runtime_config = RuntimeConfig::from_json_str(&config_source).context(
            ReviewInvalidRuntimeConfigSnafu {
                path: config.to_path_buf(),
            },
        )?;
        let runner = runtime_config
            .session
            .enabled
            .then(|| runtime_config.session.runner.kind.as_str().to_owned());
        SessionReviewArtifacts::from_paths(runner, policy, config)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SessionReviewArtifactHasher;

impl SessionReviewArtifactHasher {
    fn file_sha256(path: &Path) -> Result<String, SessionReviewError> {
        let bytes = fs::read(path).context(ReviewReadFileSnafu {
            path: path.to_path_buf(),
        })?;
        Ok(EvidenceHasher::sha256_hex(&bytes))
    }
}
