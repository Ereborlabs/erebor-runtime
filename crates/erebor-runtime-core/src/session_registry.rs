use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_events::{ActorKind, SessionId};
use erebor_runtime_telemetry::info;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

mod artifacts;
mod clock;
mod paths;
mod record_io;
#[cfg(test)]
mod tests;

use artifacts::SessionArtifactCopier;
use clock::SessionRegistryClock;
use paths::SessionRegistryPath;
use record_io::SessionRecordIo;

use crate::error::{CreateDirSnafu, UnknownSessionSnafu};
use crate::{RuntimeConfig, SessionRegistryError, SessionRunOutcome, SessionRunPlan};

pub const DEFAULT_SESSION_REGISTRY_PATH: &str = ".erebor/sessions";
pub(super) const SESSION_RECORD_FILE: &str = "session.json";
const SESSION_AUDIT_FILE: &str = "audit.jsonl";
pub(super) const SESSION_CONFIG_FILE: &str = "config.json";
pub(super) const SESSION_POLICIES_DIR: &str = "policies";

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
        let session_dir = self.session_dir(plan.session_id());
        fs::create_dir_all(&session_dir).context(CreateDirSnafu {
            path: session_dir.clone(),
        })?;

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

        let record = SessionRegistryRecord {
            schema_version: 1,
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

        Ok(StartedSessionRegistryRecord { record, audit_path })
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
        let path = self
            .session_dir_for_id(session_id)
            .join(SESSION_RECORD_FILE);
        if !path.exists() {
            return UnknownSessionSnafu {
                root: self.root.clone(),
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        self.record_io().read_record(&path)
    }

    fn session_dir(&self, session_id: &SessionId) -> PathBuf {
        self.session_dir_for_id(session_id.as_str())
    }

    fn session_dir_for_id(&self, session_id: &str) -> PathBuf {
        self.root
            .join(SessionRegistryPath::safe_dir_name(session_id))
    }

    fn record_io(&self) -> SessionRecordIo<'_> {
        SessionRecordIo::new(&self.root)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartedSessionRegistryRecord {
    record: SessionRegistryRecord,
    audit_path: PathBuf,
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
