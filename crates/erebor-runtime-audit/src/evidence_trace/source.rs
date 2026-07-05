use std::path::{Path, PathBuf};

use erebor_runtime_core::{SessionRegistry, DEFAULT_SESSION_REGISTRY_PATH};
use snafu::{OptionExt, ResultExt};

use crate::{
    error::{
        EvidenceMissingConfigArtifactSnafu, EvidenceMissingPolicyArtifactSnafu,
        EvidenceSessionRegistrySnafu,
    },
    EvidenceTraceError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceSource {
    registry: PathBuf,
}

impl Default for EvidenceTraceSource {
    fn default() -> Self {
        Self {
            registry: PathBuf::from(DEFAULT_SESSION_REGISTRY_PATH),
        }
    }
}

impl EvidenceTraceSource {
    #[must_use]
    pub fn new(registry: impl Into<PathBuf>) -> Self {
        Self {
            registry: registry.into(),
        }
    }

    pub fn paths(
        &self,
        session_id: &str,
        prompt: Option<PathBuf>,
        purpose: impl Into<String>,
    ) -> Result<EvidenceTracePaths, EvidenceTraceError> {
        let session = SessionRegistry::new(self.registry.clone())
            .load_session(session_id)
            .context(EvidenceSessionRegistrySnafu)?;
        let policy = session
            .primary_policy_artifact_path()
            .map(Path::to_path_buf)
            .context(EvidenceMissingPolicyArtifactSnafu {
                session_id: session_id.to_owned(),
            })?;
        let config = session
            .config_artifact_path()
            .map(Path::to_path_buf)
            .context(EvidenceMissingConfigArtifactSnafu {
                session_id: session_id.to_owned(),
            })?;

        Ok(EvidenceTracePaths {
            audit: session.audit_path().to_path_buf(),
            policy,
            config,
            prompt,
            session_id: Some(session_id.to_owned()),
            purpose: purpose.into(),
        })
    }

    pub fn audit_path(&self, session_id: &str) -> Result<PathBuf, EvidenceTraceError> {
        let session = SessionRegistry::new(self.registry.clone())
            .load_session(session_id)
            .context(EvidenceSessionRegistrySnafu)?;
        Ok(session.audit_path().to_path_buf())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTracePaths {
    pub audit: PathBuf,
    pub policy: PathBuf,
    pub config: PathBuf,
    pub prompt: Option<PathBuf>,
    pub session_id: Option<String>,
    pub purpose: String,
}
