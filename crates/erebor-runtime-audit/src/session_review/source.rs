use std::path::{Path, PathBuf};

use erebor_runtime_context::ContextRepository;
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
        let (audit, policy, config, context) = self.registry_paths(session_id)?;
        let records =
            crate::read_audit_records(&audit).context(crate::error::ReviewAuditLogSnafu)?;
        let artifacts =
            super::artifacts::SessionReviewArtifactLoader::from_config_paths(&policy, &config)?;
        SessionReviewRenderer::new(&records, &artifacts).render_show_with_context(
            session_id,
            format,
            context.as_ref(),
        )
    }

    pub fn render_describe(
        &self,
        session_id: &str,
        format: SessionReviewOutputFormat,
    ) -> Result<String, SessionReviewError> {
        let (audit, policy, config, context) = self.registry_paths(session_id)?;
        let records =
            crate::read_audit_records(&audit).context(crate::error::ReviewAuditLogSnafu)?;
        let artifacts =
            super::artifacts::SessionReviewArtifactLoader::from_config_paths(&policy, &config)?;
        SessionReviewRenderer::new(&records, &artifacts).render_describe_with_context(
            session_id,
            format,
            context.as_ref(),
        )
    }

    fn registry_paths(
        &self,
        session_id: &str,
    ) -> Result<(PathBuf, PathBuf, PathBuf, Option<ContextRepository>), SessionReviewError> {
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
        let context = registry
            .open_context_repository(session_id)
            .context(ReviewSessionRegistrySnafu)?;
        Ok((record.audit_path().to_path_buf(), policy, config, context))
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
