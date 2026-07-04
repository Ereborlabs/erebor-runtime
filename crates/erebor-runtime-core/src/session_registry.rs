use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_events::{ActorKind, SessionId};
use erebor_runtime_telemetry::info;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt};

use crate::error::{
    CopyArtifactSnafu, CreateDirSnafu, DecodeRecordSnafu, EncodeRecordSnafu, ReadRecordSnafu,
    UnknownSessionSnafu, WriteRecordSnafu,
};
use crate::{RuntimeConfig, SessionRegistryError, SessionRunOutcome, SessionRunPlan};

pub const DEFAULT_SESSION_REGISTRY_PATH: &str = ".erebor/sessions";
const SESSION_RECORD_FILE: &str = "session.json";
const SESSION_AUDIT_FILE: &str = "audit.jsonl";
const SESSION_CONFIG_FILE: &str = "config.json";
const SESSION_POLICIES_DIR: &str = "policies";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRegistry {
    root: PathBuf,
}

impl SessionRegistry {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: absolute_registry_root(root.into()),
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

        let config_artifact_path = copy_optional_config_artifact(&session_dir, plan)?;
        let policy_artifact_paths = copy_policy_artifacts(&session_dir, plan.policies())?;
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
            started_at_unix_ms: unix_time_ms(),
            ended_at_unix_ms: None,
            exit_code: None,
            failure: None,
        };
        self.write_record(&record)?;
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
        record.ended_at_unix_ms = Some(unix_time_ms());
        record.exit_code = update.exit_code;
        record.failure = update.failure;
        self.write_record(&record)?;
        info!(
            session_id = %record.session_id,
            status = record.status.as_str(),
            exit_code = ?record.exit_code,
            "updated session registry record"
        );
        Ok(record)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRegistryRecord>, SessionRegistryError> {
        let mut records = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(source) => {
                return Err(SessionRegistryError::ReadRecord {
                    path: self.root.clone(),
                    source,
                    location: Location::default(),
                });
            }
        };

        for entry in entries {
            let entry = entry.context(ReadRecordSnafu {
                path: self.root.clone(),
            })?;
            let path = entry.path().join(SESSION_RECORD_FILE);
            if path.exists() {
                records.push(self.read_record(&path)?);
            }
        }

        records.sort_by(|left, right| {
            right
                .started_at_unix_ms
                .cmp(&left.started_at_unix_ms)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        Ok(records)
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
        self.read_record(&path)
    }

    fn session_dir(&self, session_id: &SessionId) -> PathBuf {
        self.session_dir_for_id(session_id.as_str())
    }

    fn session_dir_for_id(&self, session_id: &str) -> PathBuf {
        self.root.join(safe_session_dir_name(session_id))
    }

    fn write_record(&self, record: &SessionRegistryRecord) -> Result<(), SessionRegistryError> {
        fs::create_dir_all(&record.session_dir).context(CreateDirSnafu {
            path: record.session_dir.clone(),
        })?;
        let path = record.session_dir.join(SESSION_RECORD_FILE);
        let source = serde_json::to_string_pretty(record)
            .context(EncodeRecordSnafu { path: path.clone() })?;
        fs::write(&path, format!("{source}\n")).context(WriteRecordSnafu { path })
    }

    fn read_record(&self, path: &Path) -> Result<SessionRegistryRecord, SessionRegistryError> {
        let source = fs::read_to_string(path).context(ReadRecordSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_str(&source).context(DecodeRecordSnafu {
            path: path.to_path_buf(),
        })
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

fn copy_optional_config_artifact(
    session_dir: &Path,
    plan: &SessionRunPlan,
) -> Result<Option<PathBuf>, SessionRegistryError> {
    let Some(source) = plan.config_path() else {
        return Ok(None);
    };
    let destination = session_dir.join(SESSION_CONFIG_FILE);
    fs::copy(source, &destination).context(CopyArtifactSnafu {
        from: source.to_path_buf(),
        to: destination.clone(),
    })?;
    Ok(Some(destination))
}

fn copy_policy_artifacts(
    session_dir: &Path,
    policies: &[PathBuf],
) -> Result<Vec<PathBuf>, SessionRegistryError> {
    let policy_dir = session_dir.join(SESSION_POLICIES_DIR);
    fs::create_dir_all(&policy_dir).context(CreateDirSnafu {
        path: policy_dir.clone(),
    })?;

    policies
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let file_name = source
                .file_name()
                .filter(|name| !name.is_empty())
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| String::from("policy.json"));
            let destination = policy_dir.join(format!("{index:03}-{file_name}"));
            fs::copy(source, &destination).context(CopyArtifactSnafu {
                from: source.to_path_buf(),
                to: destination.clone(),
            })?;
            Ok(destination)
        })
        .collect()
}

fn safe_session_dir_name(session_id: &str) -> String {
    session_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unix_time_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn absolute_registry_root(root: PathBuf) -> PathBuf {
    if root.is_absolute() {
        return root;
    }
    match std::env::current_dir() {
        Ok(current_dir) => current_dir.join(root),
        Err(_error) => root,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        RuntimeConfig, SessionRegistry, SessionRegistryFinish, SessionRegistryStatus,
        SessionRunOutcome, SessionRunPlan, SessionRunnerKind,
    };
    use erebor_runtime_events::SessionId;

    #[test]
    fn registry_creates_session_record_and_artifacts() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("registry")?;
        let policy = root.join("policy.json");
        let config_path = root.join("runtime.json");
        fs::write(&policy, r#"{"rules":[]}"#)?;
        fs::write(
            &config_path,
            format!(
                r#"{{
                    "policies": ["{}"],
                    "session": {{
                        "enabled": true,
                        "workspace": "{}",
                        "runner": {{ "kind": "linux_host" }}
                    }},
                    "surfaces": {{
                        "terminal": {{ "enabled": true }}
                    }}
                }}"#,
                policy.display(),
                root.display()
            ),
        )?;
        let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-registry-test"),
            vec![String::from("true")],
        )?
        .with_config_path(config_path.clone());
        let registry = SessionRegistry::new(plan.registry_path().to_path_buf());

        let started = registry.start_session(&config, &plan)?;

        assert_eq!(started.record().status, SessionRegistryStatus::Running);
        assert!(started.record().session_dir.join("session.json").exists());
        assert!(started
            .record()
            .config_artifact_path()
            .is_some_and(Path::exists));
        assert_eq!(started.record().policy_artifact_paths.len(), 1);
        assert_eq!(started.audit_path(), started.record().audit_path());

        let finished = registry.finish_session(
            plan.session_id(),
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
                SessionRunnerKind::LinuxHost,
                Some(0),
            )),
        )?;

        assert_eq!(finished.status, SessionRegistryStatus::Succeeded);
        assert_eq!(finished.exit_code, Some(0));
        assert!(finished.ended_at_unix_ms.is_some());
        assert_eq!(registry.list_sessions()?.len(), 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn temp_dir(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-session-registry-{name}-{nanos}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
