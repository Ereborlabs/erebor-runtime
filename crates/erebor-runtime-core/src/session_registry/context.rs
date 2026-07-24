use std::{
    error::Error,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_context::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextRepository,
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::error::{
    ContextRepositorySnafu, InspectContextArtifactSnafu, InvalidContextArtifactMetadataSnafu,
    MissingContextArtifactSnafu,
};
use crate::SessionRegistryError;

const CONTEXT_DIRECTORY: &str = "context";
const BARE_REPOSITORY_KIND: &str = "bare";
const SHA256_OBJECT_FORMAT: &str = "sha256";
const COMMITTER_NAME: &str = "Erebor Runtime";
const COMMITTER_EMAIL: &str = "runtime@erebor.dev";

/// Optional session-record metadata for the session-local Git context artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionContextArtifact {
    path: PathBuf,
    repository_kind: String,
    object_format: String,
}

impl SessionContextArtifact {
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(CONTEXT_DIRECTORY),
            repository_kind: BARE_REPOSITORY_KIND.to_owned(),
            object_format: SHA256_OBJECT_FORMAT.to_owned(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn repository_kind(&self) -> &str {
        &self.repository_kind
    }

    #[must_use]
    pub fn object_format(&self) -> &str {
        &self.object_format
    }

    pub(super) fn validate(&self, session_id: &str) -> Result<(), SessionRegistryError> {
        if self.repository_kind != BARE_REPOSITORY_KIND {
            return InvalidContextArtifactMetadataSnafu {
                session_id: session_id.to_owned(),
                field: "repository kind",
                expected: BARE_REPOSITORY_KIND,
                actual: self.repository_kind.clone().into_boxed_str(),
            }
            .fail();
        }
        if self.object_format != SHA256_OBJECT_FORMAT {
            return InvalidContextArtifactMetadataSnafu {
                session_id: session_id.to_owned(),
                field: "object format",
                expected: SHA256_OBJECT_FORMAT,
                actual: self.object_format.clone().into_boxed_str(),
            }
            .fail();
        }
        Ok(())
    }
}

impl Default for SessionContextArtifact {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) struct SessionContextRepository;

impl SessionContextRepository {
    pub(super) fn initialize(
        session_id: &str,
        path: &Path,
    ) -> Result<ContextRepository, SessionRegistryError> {
        ContextRepository::init(path, SessionContextCommitMetadataSource)
            .map_err(Box::new)
            .context(ContextRepositorySnafu {
                session_id: session_id.to_owned(),
                path: path.to_path_buf(),
            })
    }

    pub(super) fn open(
        session_id: &str,
        path: &Path,
    ) -> Result<ContextRepository, SessionRegistryError> {
        if !path.try_exists().context(InspectContextArtifactSnafu {
            session_id: session_id.to_owned(),
            path: path.to_path_buf(),
        })? {
            return MissingContextArtifactSnafu {
                session_id: session_id.to_owned(),
                path: path.to_path_buf(),
            }
            .fail();
        }
        ContextRepository::open(path, SessionContextCommitMetadataSource)
            .map_err(Box::new)
            .context(ContextRepositorySnafu {
                session_id: session_id.to_owned(),
                path: path.to_path_buf(),
            })
    }
}

struct SessionContextCommitMetadataSource;

impl CommitMetadataSource for SessionContextCommitMetadataSource {
    fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| Box::new(source) as Box<dyn Error + Send + Sync>)?;
        let seconds = i64::try_from(duration.as_secs())
            .map_err(|source| Box::new(source) as Box<dyn Error + Send + Sync>)?;
        let time = CommitTime::new(seconds, 0)
            .map_err(|source| Box::new(source) as Box<dyn Error + Send + Sync>)?;
        let signature = CommitSignature::new(COMMITTER_NAME, COMMITTER_EMAIL, time)
            .map_err(|source| Box::new(source) as Box<dyn Error + Send + Sync>)?;
        Ok(CommitMetadata::new(signature.clone(), signature))
    }
}
