use std::path::{Path, PathBuf};

use erebor_runtime_core::{SessionRegistry, DEFAULT_SESSION_REGISTRY_PATH};
use snafu::{OptionExt, ResultExt};

use crate::{
    error::{
        ReviewMissingConfigArtifactSnafu, ReviewMissingPolicyArtifactSnafu,
        ReviewSessionRegistrySnafu,
    },
    SessionReviewError,
};

use super::{
    render::{SessionReviewOutput, SessionReviewOutputFormat, SessionReviewRenderer},
    summary::RegistrySessionSummaryBuilder,
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionReviewSource {
    paths: SessionReviewSourcePaths,
}

impl SessionReviewSource {
    #[must_use]
    pub fn new(registry: impl Into<PathBuf>) -> Self {
        Self {
            paths: SessionReviewSourcePaths {
                registry: registry.into(),
            },
        }
    }

    pub fn render_list(
        &self,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let registry = SessionRegistry::new(self.paths.registry.clone());
        let records = registry
            .list_sessions()
            .context(ReviewSessionRegistrySnafu)?;
        let summaries = RegistrySessionSummaryBuilder::new(&records).build();
        match format {
            SessionReviewOutputFormat::Text => Ok(SessionReviewOutput::summary_table(&summaries)),
            SessionReviewOutputFormat::Json => SessionReviewOutput::json(&summaries),
        }
    }

    pub fn render_show(
        &self,
        session_id: &str,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let (audit, policy, config) = self.registry_paths(session_id)?;
        SessionReviewRenderer::render_show_from_paths(&audit, &policy, &config, session_id, format)
    }

    pub fn render_describe(
        &self,
        session_id: &str,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let (audit, policy, config) = self.registry_paths(session_id)?;
        SessionReviewRenderer::render_describe_from_paths(
            &audit, &policy, &config, session_id, format,
        )
    }

    fn registry_paths(
        &self,
        session_id: &str,
    ) -> Result<(PathBuf, PathBuf, PathBuf), SessionReviewError> {
        let registry = SessionRegistry::new(self.paths.registry.clone());
        let record = registry
            .load_session(session_id)
            .context(ReviewSessionRegistrySnafu)?;
        let policy = record
            .primary_policy_artifact_path()
            .map(Path::to_path_buf)
            .context(ReviewMissingPolicyArtifactSnafu {
                session_id: session_id.to_owned(),
            })?;
        let config = record
            .config_artifact_path()
            .map(Path::to_path_buf)
            .context(ReviewMissingConfigArtifactSnafu {
                session_id: session_id.to_owned(),
            })?;
        Ok((record.audit_path().to_path_buf(), policy, config))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionReviewSourcePaths {
    registry: PathBuf,
}

impl Default for SessionReviewSourcePaths {
    fn default() -> Self {
        Self {
            registry: PathBuf::from(DEFAULT_SESSION_REGISTRY_PATH),
        }
    }
}
