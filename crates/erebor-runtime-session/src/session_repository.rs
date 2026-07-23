use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{RunnerBinding, SessionLifecycleState, SessionSpec};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::session_repository::{
        AlreadyExistsSnafu, DecodeSnafu, GenerationConflictSnafu, IoSnafu, NotFoundSnafu,
        RetentionHeldSnafu, SpecSnafu, UnsafePathSnafu,
    },
    SessionRepositoryError,
};

const SESSION_RECORD_SCHEMA_VERSION: u32 = 2;
const SESSION_RECORD_FILE: &str = "session.json";
const SESSION_ALIAS_FILE: &str = "aliases.json";

/// A daemon-owned local alias for one exact session id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionAlias {
    alias: String,
    session_id: String,
}

impl SessionAlias {
    fn new(alias: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            session_id: session_id.into(),
        }
    }

    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableSessionRecord {
    schema_version: u32,
    spec: SessionSpec,
    state: SessionLifecycleState,
    generation: u64,
    runner_binding: Option<RunnerBinding>,
    failure: Option<String>,
    retention_hold: bool,
    #[serde(default = "default_content_retained")]
    content_retained: bool,
    updated_at_unix_ms: u64,
}

impl DurableSessionRecord {
    #[must_use]
    pub const fn state(&self) -> SessionLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec(&self) -> &SessionSpec {
        &self.spec
    }

    #[must_use]
    pub fn runner_binding(&self) -> Option<&RunnerBinding> {
        self.runner_binding.as_ref()
    }

    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    #[must_use]
    pub const fn retention_hold(&self) -> bool {
        self.retention_hold
    }

    #[must_use]
    pub const fn retains_content(&self) -> bool {
        self.content_retained
    }

    #[must_use]
    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPruneResult {
    pub pruned: usize,
    pub pruned_session_ids: Vec<String>,
    pub retained_session_ids: Vec<String>,
}

pub struct SessionRepository {
    root: PathBuf,
    mutation_lock: Mutex<()>,
}

impl SessionRepository {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            mutation_lock: Mutex::new(()),
        }
    }

    pub fn create(
        &self,
        spec: SessionSpec,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        spec.validate().context(SpecSnafu)?;
        let directory = self.session_directory(spec.owner().uid(), spec.session_id().as_str());
        if directory.exists() {
            return AlreadyExistsSnafu {
                session_id: spec.session_id().as_str().to_owned(),
            }
            .fail();
        }
        self.create_directory(&directory)?;
        let record = DurableSessionRecord {
            schema_version: SESSION_RECORD_SCHEMA_VERSION,
            spec,
            state: SessionLifecycleState::Created,
            generation: 1,
            runner_binding: None,
            failure: None,
            retention_hold: false,
            content_retained: true,
            updated_at_unix_ms: unix_time_ms(),
        };
        self.write(&directory, &record)?;
        Ok(record)
    }

    pub fn load(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        validate_session_id(session_id, &self.root)?;
        let directory = self.session_directory(uid, session_id);
        self.read(&directory, session_id)
    }

    pub fn transition(
        &self,
        uid: u32,
        session_id: &str,
        expected_generation: u64,
        next: SessionLifecycleState,
        runner_binding: Option<RunnerBinding>,
        failure: Option<String>,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        validate_session_id(session_id, &self.root)?;
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        let directory = self.session_directory(uid, session_id);
        let mut record = self.read(&directory, session_id)?;
        if record.generation != expected_generation {
            return GenerationConflictSnafu {
                session_id: session_id.to_owned(),
                expected: expected_generation,
                actual: record.generation,
            }
            .fail();
        }
        record.state.transition(next).context(SpecSnafu)?;
        if runner_binding.is_some() && next != SessionLifecycleState::Running && !next.is_terminal()
        {
            return UnsafePathSnafu {
                path: directory,
                reason: String::from("runner binding may be recorded only with running state"),
            }
            .fail();
        }
        if next == SessionLifecycleState::Running
            && runner_binding.is_none()
            && record.runner_binding.is_none()
        {
            return UnsafePathSnafu {
                path: directory,
                reason: String::from("running state requires an observed runner binding"),
            }
            .fail();
        }
        if let Some(binding) = runner_binding {
            record.runner_binding = Some(binding);
        }
        record.state = next;
        record.generation = record.generation.saturating_add(1);
        record.failure = failure;
        record.updated_at_unix_ms = unix_time_ms();
        self.write(&directory, &record)?;
        Ok(record)
    }

    pub fn list(&self, uid: u32) -> Result<Vec<DurableSessionRecord>, SessionRepositoryError> {
        let sessions = self
            .root
            .join("users")
            .join(uid.to_string())
            .join("sessions");
        let entries = match fs::read_dir(&sessions) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "listing user sessions",
                    path: &sessions,
                });
            }
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.context(IoSnafu {
                action: "reading user session entry",
                path: &sessions,
            })?;
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting user session entry",
                path: entry.path(),
            })?;
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            let session_id = entry.file_name().to_string_lossy().into_owned();
            records.push(self.read(&entry.path(), &session_id)?);
        }
        records.sort_by(|left, right| {
            left.spec
                .session_id()
                .as_str()
                .cmp(right.spec.session_id().as_str())
        });
        Ok(records)
    }

    pub fn user_ids(&self) -> Result<Vec<u32>, SessionRepositoryError> {
        let users = self.root.join("users");
        let entries = match fs::read_dir(&users) {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "listing session owners",
                    path: &users,
                });
            }
        };
        let mut user_ids = Vec::new();
        for entry in entries {
            let entry = entry.context(IoSnafu {
                action: "reading session owner entry",
                path: &users,
            })?;
            let file_type = entry.file_type().context(IoSnafu {
                action: "inspecting session owner entry",
                path: entry.path(),
            })?;
            if file_type.is_dir() && !file_type.is_symlink() {
                if let Some(uid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|value| value.parse::<u32>().ok())
                {
                    user_ids.push(uid);
                }
            }
        }
        user_ids.sort_unstable();
        Ok(user_ids)
    }

    pub fn set_alias(
        &self,
        uid: u32,
        alias: &str,
        session_id: &str,
    ) -> Result<SessionAlias, SessionRepositoryError> {
        validate_session_alias(alias, &self.root)?;
        validate_session_id(session_id, &self.root)?;
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        self.read(&self.session_directory(uid, session_id), session_id)?;
        let mut aliases = self.read_aliases(uid)?;
        aliases.insert(alias.to_owned(), session_id.to_owned());
        self.write_aliases(uid, &aliases)?;
        Ok(SessionAlias::new(alias, session_id))
    }

    pub fn remove_alias(
        &self,
        uid: u32,
        alias: &str,
    ) -> Result<SessionAlias, SessionRepositoryError> {
        validate_session_alias(alias, &self.root)?;
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        let mut aliases = self.read_aliases(uid)?;
        let session_id = aliases.remove(alias).ok_or_else(|| {
            NotFoundSnafu {
                session_id: format!("alias-{alias}"),
            }
            .build()
        })?;
        self.write_aliases(uid, &aliases)?;
        Ok(SessionAlias::new(alias, session_id))
    }

    pub fn aliases(&self, uid: u32) -> Result<Vec<SessionAlias>, SessionRepositoryError> {
        Ok(self
            .read_aliases(uid)?
            .into_iter()
            .map(|(alias, session_id)| SessionAlias::new(alias, session_id))
            .collect())
    }

    pub fn resolve_alias(
        &self,
        uid: u32,
        alias: &str,
    ) -> Result<Option<String>, SessionRepositoryError> {
        if validate_session_alias(alias, &self.root).is_err() {
            return Ok(None);
        }
        Ok(self.read_aliases(uid)?.remove(alias))
    }

    pub fn remove(
        &self,
        uid: u32,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        validate_session_id(session_id, &self.root)?;
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        let directory = self.session_directory(uid, session_id);
        let mut record = self.read(&directory, session_id)?;
        if record.generation != expected_generation {
            return GenerationConflictSnafu {
                session_id: session_id.to_owned(),
                expected: expected_generation,
                actual: record.generation,
            }
            .fail();
        }
        if record.retention_hold {
            return RetentionHeldSnafu {
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        record
            .state
            .transition(SessionLifecycleState::Removed)
            .context(SpecSnafu)?;
        record.state = SessionLifecycleState::Removed;
        record.generation = record.generation.saturating_add(1);
        record.updated_at_unix_ms = unix_time_ms();
        self.write(&directory, &record)?;
        self.write_tombstone(&directory, &record)?;
        Ok(record)
    }

    pub fn set_retention_hold(
        &self,
        uid: u32,
        session_id: &str,
        retention_hold: bool,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        validate_session_id(session_id, &self.root)?;
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        let directory = self.session_directory(uid, session_id);
        let mut record = self.read(&directory, session_id)?;
        if record.retention_hold == retention_hold {
            return Ok(record);
        }
        record.retention_hold = retention_hold;
        record.generation = record.generation.saturating_add(1);
        record.updated_at_unix_ms = unix_time_ms();
        self.write(&directory, &record)?;
        Ok(record)
    }

    pub fn prune(
        &self,
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: usize,
    ) -> Result<SessionPruneResult, SessionRepositoryError> {
        let _guard = self.mutation_lock.lock().map_err(|_error| {
            UnsafePathSnafu {
                path: self.root.clone(),
                reason: String::from("mutation lock is poisoned"),
            }
            .build()
        })?;
        let mut records = self.list(uid)?;
        records.sort_by_key(DurableSessionRecord::updated_at_unix_ms);
        let mut pruned = 0;
        let mut pruned_session_ids = Vec::new();
        let mut retained_session_ids = Vec::new();
        for mut record in records {
            if !record.content_retained {
                continue;
            }
            if record.state != SessionLifecycleState::Removed
                || record.retention_hold
                || record.updated_at_unix_ms > terminal_before_unix_ms
                || pruned >= maximum_sessions
            {
                if record.state == SessionLifecycleState::Removed {
                    retained_session_ids.push(record.spec.session_id().as_str().to_owned());
                }
                continue;
            }
            let output = self
                .session_directory(uid, record.spec.session_id().as_str())
                .join("output");
            match fs::remove_dir_all(&output) {
                Ok(()) => {
                    pruned += 1;
                    pruned_session_ids.push(record.spec.session_id().as_str().to_owned());
                }
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    pruned += 1;
                    pruned_session_ids.push(record.spec.session_id().as_str().to_owned());
                }
                Err(source) => {
                    return Err(source).context(IoSnafu {
                        action: "pruning removed session output",
                        path: output,
                    });
                }
            }
            record.content_retained = false;
            record.generation = record.generation.saturating_add(1);
            record.updated_at_unix_ms = unix_time_ms();
            let directory = self.session_directory(uid, record.spec.session_id().as_str());
            self.write(&directory, &record)?;
        }
        Ok(SessionPruneResult {
            pruned,
            pruned_session_ids,
            retained_session_ids,
        })
    }

    fn session_directory(&self, uid: u32, session_id: &str) -> PathBuf {
        self.root
            .join("users")
            .join(uid.to_string())
            .join("sessions")
            .join(session_id)
    }

    fn aliases_path(&self, uid: u32) -> PathBuf {
        self.root
            .join("users")
            .join(uid.to_string())
            .join(SESSION_ALIAS_FILE)
    }

    fn read_aliases(&self, uid: u32) -> Result<BTreeMap<String, String>, SessionRepositoryError> {
        let path = self.aliases_path(uid);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "reading session aliases",
                    path: &path,
                })
            }
        };
        let aliases = serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
            .context(DecodeSnafu { path: &path })?;
        for (alias, session_id) in &aliases {
            validate_session_alias(alias, &self.root)?;
            validate_session_id(session_id, &self.root)?;
        }
        Ok(aliases)
    }

    fn write_aliases(
        &self,
        uid: u32,
        aliases: &BTreeMap<String, String>,
    ) -> Result<(), SessionRepositoryError> {
        let path = self.aliases_path(uid);
        let parent = path.parent().ok_or_else(|| {
            UnsafePathSnafu {
                path: path.clone(),
                reason: String::from("session alias file has no parent directory"),
            }
            .build()
        })?;
        fs::create_dir_all(parent).context(IoSnafu {
            action: "creating session alias directory",
            path: parent,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).context(IoSnafu {
            action: "protecting session alias directory",
            path: parent,
        })?;
        let temporary = parent.join("aliases.json.tmp");
        self.remove_stale_temporary(&temporary)?;
        let encoded = serde_json::to_vec(aliases).context(DecodeSnafu { path: &path })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(IoSnafu {
                action: "creating temporary session aliases",
                path: &temporary,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "writing session aliases",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing session aliases",
            path: &temporary,
        })?;
        fs::rename(&temporary, &path).context(IoSnafu {
            action: "publishing session aliases",
            path: &path,
        })?;
        File::open(parent)
            .context(IoSnafu {
                action: "opening session alias directory",
                path: parent,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing session alias directory",
                path: parent,
            })
    }

    fn create_directory(&self, directory: &Path) -> Result<(), SessionRepositoryError> {
        fs::create_dir_all(directory).context(IoSnafu {
            action: "creating session directory",
            path: directory,
        })?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).context(IoSnafu {
            action: "protecting session directory",
            path: directory,
        })?;
        Ok(())
    }

    fn read(
        &self,
        directory: &Path,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionRepositoryError> {
        let path = directory.join(SESSION_RECORD_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return NotFoundSnafu {
                    session_id: session_id.to_owned(),
                }
                .fail();
            }
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "reading session record",
                    path: &path,
                })
            }
        };
        let record: DurableSessionRecord =
            serde_json::from_slice(&bytes).context(DecodeSnafu { path: &path })?;
        if record.schema_version != SESSION_RECORD_SCHEMA_VERSION
            || record.spec.session_id().as_str() != session_id
        {
            return UnsafePathSnafu {
                path,
                reason: String::from(
                    "record schema or session identity does not match its directory",
                ),
            }
            .fail();
        }
        record.spec.validate().context(SpecSnafu)?;
        if let Some(binding) = record.runner_binding.as_ref() {
            binding.validate().context(SpecSnafu)?;
            if binding.runner() != record.spec.runner_capability().runner()
                || binding.implementation_id()
                    != record.spec.runner_capability().implementation_id()
            {
                return UnsafePathSnafu {
                    path,
                    reason: String::from(
                        "runner binding does not match the immutable capability snapshot",
                    ),
                }
                .fail();
            }
        }
        Ok(record)
    }

    fn write(
        &self,
        directory: &Path,
        record: &DurableSessionRecord,
    ) -> Result<(), SessionRepositoryError> {
        let path = directory.join(SESSION_RECORD_FILE);
        let temporary = directory.join("session.json.tmp");
        self.remove_stale_temporary(&temporary)?;
        let encoded = serde_json::to_vec(record).context(DecodeSnafu { path: &path })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .context(IoSnafu {
                action: "creating temporary session record",
                path: &temporary,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "writing session record",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing session record",
            path: &temporary,
        })?;
        fs::rename(&temporary, &path).context(IoSnafu {
            action: "publishing session record",
            path: &path,
        })?;
        File::open(directory)
            .context(IoSnafu {
                action: "opening session directory",
                path: directory,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing session directory",
                path: directory,
            })
    }

    fn write_tombstone(
        &self,
        directory: &Path,
        record: &DurableSessionRecord,
    ) -> Result<(), SessionRepositoryError> {
        let path = directory.join("tombstone.json");
        let encoded = serde_json::to_vec(record).context(DecodeSnafu { path: &path })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .context(IoSnafu {
                action: "creating session tombstone",
                path: &path,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "writing session tombstone",
            path: &path,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing session tombstone",
            path: &path,
        })?;
        File::open(directory)
            .context(IoSnafu {
                action: "opening session directory",
                path: directory,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing session directory",
                path: directory,
            })
    }

    fn remove_stale_temporary(&self, temporary: &Path) -> Result<(), SessionRepositoryError> {
        let metadata = match fs::symlink_metadata(temporary) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "inspecting temporary session record",
                    path: temporary,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return UnsafePathSnafu {
                path: temporary.to_path_buf(),
                reason: String::from("stale temporary record is not a regular file"),
            }
            .fail();
        }
        fs::remove_file(temporary).context(IoSnafu {
            action: "removing stale temporary session record",
            path: temporary,
        })
    }
}

const fn default_content_retained() -> bool {
    true
}

fn validate_session_id(session_id: &str, root: &Path) -> Result<(), SessionRepositoryError> {
    if !session_id.is_empty()
        && session_id.len() <= 128
        && session_id != "."
        && session_id != ".."
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        UnsafePathSnafu {
            path: root.join(session_id),
            reason: String::from("session id is not a safe path component"),
        }
        .fail()
    }
}

fn validate_session_alias(alias: &str, root: &Path) -> Result<(), SessionRepositoryError> {
    if !alias.is_empty()
        && alias.len() <= 128
        && alias != "."
        && alias != ".."
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        UnsafePathSnafu {
            path: root.join(alias),
            reason: String::from("session alias is not a safe path component"),
        }
        .fail()
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::PathBuf,
    };

    use erebor_runtime_core::{
        ActiveSessionSignalKind, DaemonFailureMode, ImmutableIdentity, OutputPlan, RunnerBinding,
        RunnerCapabilityDocument, RunnerId, RunnerRecovery, SafePathBinding, SafePathKind,
        SessionAdmission, SessionLifecycleState, SessionOwner, SessionSpec, WorkloadPrivilegePlan,
    };
    use erebor_runtime_events::SessionId;
    use tempfile::TempDir;

    use super::SessionRepository;

    fn digest() -> String {
        String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }

    fn spec() -> Result<SessionSpec, Box<dyn std::error::Error>> {
        let capabilities = RunnerCapabilityDocument::new(
            RunnerId::new("linux-host")?,
            "linux-host-v1",
            "1",
            "linux",
            "x86_64",
            true,
            true,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
            ]),
            false,
            true,
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue]),
            BTreeMap::new(),
        )?;
        Ok(SessionSpec::new(SessionAdmission {
            session_id: SessionId::new("session-9f7b7f6e"),
            owner: SessionOwner::new(1000, 1000),
            workload_privileges: WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 512, 0)?,
            command: vec![String::from("/usr/bin/agent")],
            package: None,
            package_configuration: None,
            installation: None,
            adapter: None,
            policy_inputs: vec![ImmutableIdentity::new("root-policy", digest())?],
            policy_set: ImmutableIdentity::new("policy-set", digest())?,
            runner_capability: capabilities,
            workspace: SafePathBinding::new(
                PathBuf::from("/workspace"),
                1,
                2,
                1,
                1000,
                1000,
                SafePathKind::Directory,
            )?,
            executable: Some(
                SafePathBinding::new(
                    PathBuf::from("/usr/bin/agent"),
                    1,
                    3,
                    1,
                    0,
                    0,
                    SafePathKind::Executable,
                )?
                .with_content_sha256(digest())?,
            ),
            script_interpreters: Vec::new(),
            container_image: None,
            environment: Vec::new(),
            secret_references: Vec::new(),
            filesystem_projections: Vec::new(),
            endpoint_projections: Vec::new(),
            output: OutputPlan::new(
                PathBuf::from("/var/lib/erebor/users/1000/sessions/session-9f7b7f6e/output"),
                1024,
                512,
                64,
                erebor_runtime_core::OutputStreamRequirements::required(),
            )?,
            evidence_requirements: Vec::new(),
            tty: false,
            terminal_size: None,
            detached: true,
            daemon_failure_mode: DaemonFailureMode::Terminate,
            loss_grace_seconds: 10,
            root_configuration_generation: 1,
            created_at_unix_ms: 1,
        })?)
    }

    #[test]
    fn repository_persists_create_start_and_runner_binding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        assert_eq!(created.state(), SessionLifecycleState::Created);

        let starting = repository.transition(
            1000,
            "session-9f7b7f6e",
            created.generation(),
            SessionLifecycleState::Starting,
            None,
            None,
        )?;
        let running = repository.transition(
            1000,
            "session-9f7b7f6e",
            starting.generation(),
            SessionLifecycleState::Running,
            Some(RunnerBinding::new(
                RunnerId::new("linux-host")?,
                "linux-host-v1",
                RunnerRecovery::new(1, r#"{"pidfd":17}"#)?,
                1,
            )?),
            None,
        )?;
        assert_eq!(running.state(), SessionLifecycleState::Running);
        assert_eq!(
            running
                .runner_binding()
                .map(|binding| binding.recovery().payload()),
            Some(r#"{"pidfd":17}"#)
        );
        assert_eq!(
            repository.load(1000, "session-9f7b7f6e")?.generation(),
            running.generation()
        );
        Ok(())
    }

    #[test]
    fn aliases_are_durable_scoped_and_resolve_to_exact_session_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        repository.create(spec()?)?;

        let alias = repository.set_alias(1000, "demo", "session-9f7b7f6e")?;
        assert_eq!(alias.alias(), "demo");
        assert_eq!(alias.session_id(), "session-9f7b7f6e");
        assert_eq!(
            repository.resolve_alias(1000, "demo")?,
            Some(String::from("session-9f7b7f6e"))
        );
        assert!(repository.resolve_alias(1001, "demo")?.is_none());
        assert_eq!(
            repository.aliases(1000)?.as_slice(),
            std::slice::from_ref(&alias)
        );

        assert!(repository
            .set_alias(1000, "../unsafe", "session-9f7b7f6e")
            .is_err());
        assert!(repository
            .set_alias(1000, "missing", "session-missing")
            .is_err());

        let removed = repository.remove_alias(1000, "demo")?;
        assert_eq!(removed, alias);
        assert!(repository.resolve_alias(1000, "demo")?.is_none());
        Ok(())
    }

    #[test]
    fn repository_rejects_stale_generation_and_live_removal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        assert!(repository
            .transition(
                1000,
                "session-9f7b7f6e",
                created.generation().saturating_add(1),
                SessionLifecycleState::Starting,
                None,
                None
            )
            .is_err());
        assert!(repository
            .transition(
                1000,
                "session-9f7b7f6e",
                created.generation(),
                SessionLifecycleState::Running,
                None,
                None
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn repository_rejects_a_runner_binding_that_no_longer_matches_the_spec(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        let starting = repository.transition(
            1000,
            "session-9f7b7f6e",
            created.generation(),
            SessionLifecycleState::Starting,
            None,
            None,
        )?;
        repository.transition(
            1000,
            "session-9f7b7f6e",
            starting.generation(),
            SessionLifecycleState::Running,
            Some(RunnerBinding::new(
                RunnerId::new("linux-host")?,
                "linux-host-v1",
                RunnerRecovery::new(1, r#"{"pidfd":17}"#)?,
                1,
            )?),
            None,
        )?;
        let path = temporary
            .path()
            .join("users/1000/sessions/session-9f7b7f6e/session.json");
        let mut encoded: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        encoded["runner_binding"]["implementation_id"] = serde_json::json!("different-runner");
        fs::write(&path, serde_json::to_vec(&encoded)?)?;

        assert!(repository.load(1000, "session-9f7b7f6e").is_err());
        Ok(())
    }

    #[test]
    fn failed_record_write_preserves_the_last_durable_generation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        let directory = temporary
            .path()
            .join("users/1000/sessions/session-9f7b7f6e");
        let blocked_temporary = directory.join("session.json.tmp");
        fs::create_dir(&blocked_temporary)?;
        let transition = repository.transition(
            1000,
            "session-9f7b7f6e",
            created.generation(),
            SessionLifecycleState::Starting,
            None,
            None,
        );
        fs::remove_dir(&blocked_temporary)?;

        assert!(transition.is_err());
        let recovered = repository.load(1000, "session-9f7b7f6e")?;
        assert_eq!(recovered.state(), SessionLifecycleState::Created);
        assert_eq!(recovered.generation(), created.generation());
        Ok(())
    }

    #[test]
    fn retention_hold_is_durable_and_blocks_removal_until_released(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        let held = repository.set_retention_hold(1000, "session-9f7b7f6e", true)?;

        assert!(held.retention_hold());
        assert_eq!(held.generation(), created.generation().saturating_add(1));
        assert!(repository
            .remove(1000, "session-9f7b7f6e", held.generation())
            .is_err());
        assert!(repository.load(1000, "session-9f7b7f6e")?.retention_hold());

        let released = repository.set_retention_hold(1000, "session-9f7b7f6e", false)?;
        assert!(!released.retention_hold());
        assert_eq!(
            repository
                .remove(1000, "session-9f7b7f6e", released.generation())?
                .state(),
            SessionLifecycleState::Removed
        );
        Ok(())
    }

    #[test]
    fn prune_reports_each_session_whose_retained_output_is_removed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let repository = SessionRepository::new(temporary.path());
        let created = repository.create(spec()?)?;
        repository.remove(1000, "session-9f7b7f6e", created.generation())?;
        let output = temporary
            .path()
            .join("users/1000/sessions/session-9f7b7f6e/output");
        fs::create_dir_all(&output)?;
        fs::write(output.join("stdout.log"), b"retained evidence")?;

        let pruned = repository.prune(1000, u64::MAX, 1)?;

        assert_eq!(pruned.pruned, 1);
        assert_eq!(pruned.pruned_session_ids, ["session-9f7b7f6e"]);
        assert!(pruned.retained_session_ids.is_empty());
        assert!(!output.exists());
        assert!(!repository.load(1000, "session-9f7b7f6e")?.retains_content());
        Ok(())
    }
}
