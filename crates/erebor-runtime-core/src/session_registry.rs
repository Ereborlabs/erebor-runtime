use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_context::ContextPin;
use erebor_runtime_events::{ActorKind, SessionId};
use erebor_runtime_telemetry::info;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

mod artifacts;
mod clock;
mod context;
mod paths;
mod record_io;
#[cfg(test)]
mod tests;

use artifacts::SessionArtifactCopier;
use clock::SessionRegistryClock;
use context::SessionContextRepository;
use paths::SessionRegistryPath;
use record_io::SessionRecordIo;

use crate::error::{
    ContextParentCycleSnafu, CreateDirSnafu, InspectContextArtifactSnafu,
    InvalidContextParentSnafu, SessionDirectoryCollisionSnafu, SessionDirectoryMismatchSnafu,
    SessionDirectoryOccupiedSnafu, SessionIdMismatchSnafu, UnknownSessionSnafu,
};
use crate::{RuntimeConfig, SessionRegistryError, SessionRunOutcome, SessionRunPlan};

pub const DEFAULT_SESSION_REGISTRY_PATH: &str = ".erebor/sessions";
pub(super) const SESSION_RECORD_FILE: &str = "session.json";
const SESSION_AUDIT_FILE: &str = "audit.jsonl";
const CURRENT_SESSION_REGISTRY_SCHEMA_VERSION: u32 = 2;
pub(super) const SESSION_CONFIG_FILE: &str = "config.json";
pub(super) const SESSION_POLICIES_DIR: &str = "policies";

pub use context::SessionContextArtifact;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRegistry {
    root: PathBuf,
}

impl SessionRegistry {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: SessionRegistryPath::absolute_root(root.into()),
        }
    }

    #[must_use]
    pub fn default_path() -> PathBuf {
        PathBuf::from(DEFAULT_SESSION_REGISTRY_PATH)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn start_session(
        &self,
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
    ) -> Result<StartedSessionRegistryRecord, SessionRegistryError> {
        self.start_session_with_parent(config, plan, None)
    }

    /// Start a separately governed child without allocating a second context
    /// repository. Its checked parent pin is enough to reopen the root
    /// session's existing artifact after recovery.
    pub fn start_child_session(
        &self,
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
        parent_context: ContextPin,
    ) -> Result<StartedSessionRegistryRecord, SessionRegistryError> {
        self.start_session_with_parent(config, plan, Some(parent_context))
    }

    fn start_session_with_parent(
        &self,
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
        parent_context: Option<ContextPin>,
    ) -> Result<StartedSessionRegistryRecord, SessionRegistryError> {
        let session_dir = self.prepare_session_dir(plan.session_id())?;

        let artifacts = SessionArtifactCopier::new(&session_dir);
        let config_artifact_path = artifacts.copy_config(plan)?;
        let policy_artifact_paths = artifacts.copy_policies(plan.policies())?;
        let audit_path = session_dir.join(SESSION_AUDIT_FILE);
        if let Some(parent) = audit_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).context(CreateDirSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        let owned_context_repository = if let Some(parent_context) = parent_context.as_ref() {
            let parent_scope = parent_context.scope().map_err(|error| {
                InvalidContextParentSnafu {
                    session_id: plan.session_id().as_str().to_owned(),
                    reason: error.to_string(),
                }
                .build()
            })?;
            if parent_scope.session_id() == plan.session_id().as_str() {
                return InvalidContextParentSnafu {
                    session_id: plan.session_id().as_str().to_owned(),
                    reason: String::from("a child context must name a different parent session"),
                }
                .fail();
            }
            None
        } else {
            let context_artifact = SessionContextArtifact::new();
            let context_path =
                self.context_path(plan.session_id().as_str(), &session_dir, &context_artifact)?;
            Some(SessionContextRepository::initialize(
                plan.session_id().as_str(),
                &context_path,
            )?)
        };
        let context_artifact = parent_context.is_none().then(SessionContextArtifact::new);

        let record = SessionRegistryRecord {
            schema_version: CURRENT_SESSION_REGISTRY_SCHEMA_VERSION,
            session_id: plan.session_id().as_str().to_owned(),
            status: SessionRegistryStatus::Running,
            actor_id: plan.actor().id.clone(),
            actor_kind: plan.actor().kind.clone(),
            runner: plan.runner().kind().as_str().to_owned(),
            surfaces: config
                .enabled_surfaces()
                .into_iter()
                .map(|surface| surface.as_str().to_owned())
                .collect(),
            workspace: plan.workspace().map(Path::to_path_buf),
            command: plan.command().to_vec(),
            diagnostic: plan.diagnostic().map(str::to_owned),
            registry_path: self.root.clone(),
            session_dir: session_dir.clone(),
            audit_path: audit_path.clone(),
            config_artifact_path,
            source_config_path: plan.config_path().map(Path::to_path_buf),
            policy_artifact_paths,
            source_policy_paths: plan.policies().to_vec(),
            context_artifact,
            parent_context,
            started_at_unix_ms: SessionRegistryClock::unix_time_ms(),
            ended_at_unix_ms: None,
            exit_code: None,
            failure: None,
        };
        self.record_io().write_record(&record)?;
        info!(
            session_id = %record.session_id,
            registry = %self.root.display(),
            audit = %record.audit_path.display(),
            "created session registry record"
        );

        let context_repository = match owned_context_repository {
            Some(repository) => repository,
            None => self
                .open_context_repository(plan.session_id().as_str())?
                .ok_or_else(|| {
                    InvalidContextParentSnafu {
                        session_id: plan.session_id().as_str().to_owned(),
                        reason: String::from(
                            "child session could not resolve its parent context repository",
                        ),
                    }
                    .build()
                })?,
        };
        Ok(StartedSessionRegistryRecord {
            record,
            audit_path,
            context_repository,
        })
    }

    pub fn finish_session(
        &self,
        session_id: &SessionId,
        update: SessionRegistryFinish,
    ) -> Result<SessionRegistryRecord, SessionRegistryError> {
        let mut record = self.load_session(session_id.as_str())?;
        record.status = update.status;
        record.ended_at_unix_ms = Some(SessionRegistryClock::unix_time_ms());
        record.exit_code = update.exit_code;
        record.failure = update.failure;
        self.record_io().write_record(&record)?;
        info!(
            session_id = %record.session_id,
            status = record.status.as_str(),
            exit_code = ?record.exit_code,
            "updated session registry record"
        );
        Ok(record)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRegistryRecord>, SessionRegistryError> {
        self.record_io().list_sessions()
    }

    pub fn load_session(
        &self,
        session_id: &str,
    ) -> Result<SessionRegistryRecord, SessionRegistryError> {
        let session_dir = self.session_dir_for_id(session_id)?;
        match fs::symlink_metadata(&session_dir) {
            Ok(_) => SessionRegistryPath::validate_session_directory(session_id, &session_dir)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return UnknownSessionSnafu {
                    root: self.root.clone(),
                    session_id: session_id.to_owned(),
                }
                .fail();
            }
            Err(source) => {
                return Err(source).context(InspectContextArtifactSnafu {
                    session_id: session_id.to_owned(),
                    path: session_dir,
                });
            }
        }
        let path = session_dir.join(SESSION_RECORD_FILE);
        if !path.try_exists().context(InspectContextArtifactSnafu {
            session_id: session_id.to_owned(),
            path: path.clone(),
        })? {
            return UnknownSessionSnafu {
                root: self.root.clone(),
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        let record = self.record_io().read_record(&path)?;
        self.validate_loaded_record(session_id, &session_dir, &path, &record)?;
        Ok(record)
    }

    pub fn open_context_repository(
        &self,
        session_id: &str,
    ) -> Result<Option<erebor_runtime_context::ContextRepository>, SessionRegistryError> {
        self.open_context_repository_inner(session_id, &mut HashSet::new())
    }

    fn open_context_repository_inner(
        &self,
        session_id: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Option<erebor_runtime_context::ContextRepository>, SessionRegistryError> {
        if !visited.insert(session_id.to_owned()) {
            return ContextParentCycleSnafu {
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        let record = self.load_session(session_id)?;
        if let Some(context_artifact) = record.context_artifact.as_ref() {
            let context_path =
                self.context_path(session_id, &record.session_dir, context_artifact)?;
            return SessionContextRepository::open(session_id, &context_path).map(Some);
        }
        let Some(parent_context) = record.parent_context.as_ref() else {
            return Ok(None);
        };
        let parent_scope = parent_context.scope().map_err(|error| {
            InvalidContextParentSnafu {
                session_id: session_id.to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        if parent_scope.session_id() == session_id {
            return InvalidContextParentSnafu {
                session_id: session_id.to_owned(),
                reason: String::from("a child context must name a different parent session"),
            }
            .fail();
        }
        let repository = self
            .open_context_repository_inner(parent_scope.session_id(), visited)?
            .ok_or_else(|| {
                InvalidContextParentSnafu {
                    session_id: session_id.to_owned(),
                    reason: format!(
                        "parent session `{}` has no context artifact",
                        parent_scope.session_id()
                    ),
                }
                .build()
            })?;
        repository.validate_pin(parent_context).map_err(|error| {
            InvalidContextParentSnafu {
                session_id: session_id.to_owned(),
                reason: error.to_string(),
            }
            .build()
        })?;
        Ok(Some(repository))
    }

    fn prepare_session_dir(&self, session_id: &SessionId) -> Result<PathBuf, SessionRegistryError> {
        let session_dir = self.session_dir(session_id)?;
        match fs::symlink_metadata(&session_dir) {
            Ok(_) => {
                SessionRegistryPath::validate_session_directory(session_id.as_str(), &session_dir)?;
                let record_path = session_dir.join(SESSION_RECORD_FILE);
                if record_path
                    .try_exists()
                    .context(InspectContextArtifactSnafu {
                        session_id: session_id.as_str().to_owned(),
                        path: record_path.clone(),
                    })?
                {
                    let record = self.record_io().read_record(&record_path)?;
                    if record.session_id != session_id.as_str() {
                        return SessionDirectoryCollisionSnafu {
                            requested_session_id: session_id.as_str().to_owned(),
                            stored_session_id: record.session_id,
                            session_dir: Box::new(session_dir),
                        }
                        .fail();
                    }
                }
                SessionDirectoryOccupiedSnafu {
                    session_id: session_id.as_str().to_owned(),
                    session_dir,
                }
                .fail()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&session_dir).context(CreateDirSnafu {
                    path: session_dir.clone(),
                })?;
                SessionRegistryPath::validate_session_directory(session_id.as_str(), &session_dir)?;
                Ok(session_dir)
            }
            Err(source) => Err(source).context(InspectContextArtifactSnafu {
                session_id: session_id.as_str().to_owned(),
                path: session_dir,
            }),
        }
    }

    fn validate_loaded_record(
        &self,
        requested_session_id: &str,
        expected_session_dir: &Path,
        record_path: &Path,
        record: &SessionRegistryRecord,
    ) -> Result<(), SessionRegistryError> {
        if record.session_id != requested_session_id {
            return SessionIdMismatchSnafu {
                requested_session_id: requested_session_id.to_owned(),
                recorded_session_id: record.session_id.clone(),
                record_path: Box::new(record_path.to_path_buf()),
            }
            .fail();
        }
        if record.session_dir != expected_session_dir {
            return SessionDirectoryMismatchSnafu {
                record_path: Box::new(record_path.to_path_buf()),
                expected_session_dir: expected_session_dir.to_path_buf(),
                actual_session_dir: Box::new(record.session_dir.clone()),
            }
            .fail();
        }
        if let Some(context_artifact) = record.context_artifact.as_ref() {
            self.context_path(requested_session_id, expected_session_dir, context_artifact)?;
        }
        if let Some(parent_context) = record.parent_context.as_ref() {
            let parent_scope = parent_context.scope().map_err(|error| {
                InvalidContextParentSnafu {
                    session_id: requested_session_id.to_owned(),
                    reason: error.to_string(),
                }
                .build()
            })?;
            if parent_scope.session_id() == requested_session_id {
                return InvalidContextParentSnafu {
                    session_id: requested_session_id.to_owned(),
                    reason: String::from("a child context must name a different parent session"),
                }
                .fail();
            }
            if record.context_artifact.is_some() {
                return InvalidContextParentSnafu {
                    session_id: requested_session_id.to_owned(),
                    reason: String::from(
                        "a child context must resolve its parent artifact instead of owning one",
                    ),
                }
                .fail();
            }
        }
        Ok(())
    }

    fn context_path(
        &self,
        session_id: &str,
        session_dir: &Path,
        context_artifact: &SessionContextArtifact,
    ) -> Result<PathBuf, SessionRegistryError> {
        context_artifact.validate(session_id)?;
        SessionRegistryPath::context_path(session_id, session_dir, context_artifact.path())
    }

    fn session_dir(&self, session_id: &SessionId) -> Result<PathBuf, SessionRegistryError> {
        self.session_dir_for_id(session_id.as_str())
    }

    fn session_dir_for_id(&self, session_id: &str) -> Result<PathBuf, SessionRegistryError> {
        Ok(self
            .root
            .join(SessionRegistryPath::session_dir_name(session_id)?))
    }

    fn record_io(&self) -> SessionRecordIo<'_> {
        SessionRecordIo::new(&self.root)
    }
}

pub struct StartedSessionRegistryRecord {
    record: SessionRegistryRecord,
    audit_path: PathBuf,
    context_repository: erebor_runtime_context::ContextRepository,
}

impl StartedSessionRegistryRecord {
    #[must_use]
    pub const fn record(&self) -> &SessionRegistryRecord {
        &self.record
    }

    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    #[must_use]
    pub fn context_repository(&self) -> &erebor_runtime_context::ContextRepository {
        &self.context_repository
    }

    #[must_use]
    pub fn into_context_repository(self) -> erebor_runtime_context::ContextRepository {
        self.context_repository
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRegistryFinish {
    status: SessionRegistryStatus,
    exit_code: Option<i32>,
    failure: Option<String>,
}

impl SessionRegistryFinish {
    #[must_use]
    pub fn succeeded(outcome: &SessionRunOutcome) -> Self {
        Self {
            status: SessionRegistryStatus::Succeeded,
            exit_code: outcome.exit_code(),
            failure: None,
        }
    }

    #[must_use]
    pub fn failed(exit_code: Option<i32>, failure: impl Into<String>) -> Self {
        Self {
            status: SessionRegistryStatus::Failed,
            exit_code,
            failure: Some(failure.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRegistryStatus {
    Running,
    Succeeded,
    Failed,
}

impl SessionRegistryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionRegistryRecord {
    pub schema_version: u32,
    pub session_id: String,
    pub status: SessionRegistryStatus,
    pub actor_id: String,
    pub actor_kind: ActorKind,
    pub runner: String,
    pub surfaces: Vec<String>,
    pub workspace: Option<PathBuf>,
    pub command: Vec<String>,
    pub diagnostic: Option<String>,
    pub registry_path: PathBuf,
    pub session_dir: PathBuf,
    pub audit_path: PathBuf,
    pub config_artifact_path: Option<PathBuf>,
    pub source_config_path: Option<PathBuf>,
    pub policy_artifact_paths: Vec<PathBuf>,
    pub source_policy_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_artifact: Option<SessionContextArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_context: Option<ContextPin>,
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub failure: Option<String>,
}

impl SessionRegistryRecord {
    #[must_use]
    pub fn primary_policy_artifact_path(&self) -> Option<&Path> {
        self.policy_artifact_paths.first().map(PathBuf::as_path)
    }

    #[must_use]
    pub fn config_artifact_path(&self) -> Option<&Path> {
        self.config_artifact_path.as_deref()
    }

    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }
}
