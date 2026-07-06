use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt};

use crate::{
    error::{EncodeSessionWorkSnafu, InvalidTransactionNameSnafu, SessionWorkIoSnafu},
    FilesystemSessionStorage, Result,
};

use super::catalog::{FilesystemSessionWorkCatalog, SessionWorkCatalogResolver};
use crate::ostree::{OstreeRepository, SystemOstreeRepository};

const SESSION_WORK_DIR: &str = "session-work";
const SESSION_WORK_STATE_FILE: &str = "erebor-session-work-catalog.json";
const SESSION_WORK_JOURNAL_FILE: &str = "erebor-session-work-catalog.jsonl";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SessionWorkState {
    #[serde(default = "SessionWorkState::current_version")]
    version: u32,
    #[serde(default)]
    names: Vec<SessionWorkName>,
    #[serde(default)]
    current_transaction_id: Option<String>,
}

impl Default for SessionWorkState {
    fn default() -> Self {
        Self {
            version: Self::current_version(),
            names: Vec::new(),
            current_transaction_id: None,
        }
    }
}

impl SessionWorkState {
    pub(super) fn read(storage: &FilesystemSessionStorage) -> Result<Self> {
        SessionWorkStateStore::new(storage).read()
    }

    pub(super) fn write(&self, storage: &FilesystemSessionStorage) -> Result<()> {
        SessionWorkStateStore::new(storage).write(self)
    }

    pub(super) fn name_for(&self, key: &SessionWorkTargetKey) -> Option<&str> {
        self.names
            .iter()
            .find(|entry| entry.key == *key)
            .map(|entry| entry.name.as_str())
    }

    pub(super) fn set_name(&mut self, key: SessionWorkTargetKey, name: String) {
        if let Some(entry) = self.names.iter_mut().find(|entry| entry.key == key) {
            entry.name = name;
        } else {
            self.names.push(SessionWorkName { key, name });
        }
    }

    pub(super) fn mark_current(&mut self, transaction_id: &str) {
        self.current_transaction_id = Some(transaction_id.to_owned());
    }

    pub(super) fn current_transaction_id(&self) -> Option<&str> {
        self.current_transaction_id.as_deref()
    }

    pub(super) fn append_commit_event(
        &self,
        storage: &FilesystemSessionStorage,
        event: SessionWorkCommitJournal,
    ) -> Result<()> {
        SessionWorkJournal::new(storage).append_event(&SessionWorkJournalEvent::Commit(event))
    }

    pub(super) fn append_rename_event(
        &self,
        storage: &FilesystemSessionStorage,
        selector: &str,
        name: &str,
    ) -> Result<()> {
        SessionWorkJournal::new(storage).append_event(&SessionWorkJournalEvent::Rename {
            selector: selector.to_owned(),
            name: name.to_owned(),
        })
    }

    pub(super) fn append_rollback_event(
        &self,
        storage: &FilesystemSessionStorage,
        event: SessionWorkRollbackJournal,
    ) -> Result<()> {
        SessionWorkJournal::new(storage).append_event(&SessionWorkJournalEvent::Rollback(event))
    }

    const fn current_version() -> u32 {
        1
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum SessionWorkTargetKey {
    Transaction {
        transaction_id: String,
    },
    Subtransaction {
        transaction_id: String,
        volume_id: String,
    },
}

impl SessionWorkTargetKey {
    pub(super) fn transaction(transaction_id: &str) -> Self {
        Self::Transaction {
            transaction_id: transaction_id.to_owned(),
        }
    }

    pub(super) fn subtransaction(transaction_id: &str, volume_id: &str) -> Self {
        Self::Subtransaction {
            transaction_id: transaction_id.to_owned(),
            volume_id: volume_id.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SessionWorkName {
    #[serde(flatten)]
    key: SessionWorkTargetKey,
    name: String,
}

struct SessionWorkStateStore<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> SessionWorkStateStore<'a> {
    const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    fn read(&self) -> Result<SessionWorkState> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(SessionWorkState::default());
        }
        let source = fs::read_to_string(&path).context(SessionWorkIoSnafu {
            action: "read session-work catalog",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeSessionWorkSnafu { path })
    }

    fn write(&self, state: &SessionWorkState) -> Result<()> {
        let path = self.state_path();
        self.create_parent()?;
        let source = serde_json::to_vec_pretty(state)
            .context(EncodeSessionWorkSnafu { path: path.clone() })?;
        fs::write(&path, source).context(SessionWorkIoSnafu {
            action: "write session-work catalog",
            path: path.as_path(),
        })
    }

    fn create_parent(&self) -> Result<()> {
        let path = self.dir();
        fs::create_dir_all(&path).context(SessionWorkIoSnafu {
            action: "create session-work catalog directory",
            path: path.as_path(),
        })
    }

    fn state_path(&self) -> PathBuf {
        self.dir().join(SESSION_WORK_STATE_FILE)
    }

    fn dir(&self) -> PathBuf {
        self.storage.root().join(SESSION_WORK_DIR)
    }
}

pub struct FilesystemSessionWorkRename {
    handle: String,
    name: String,
}

impl FilesystemSessionWorkRename {
    pub fn rename(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
        name: &str,
    ) -> Result<Self> {
        Self::rename_using_repository(storage, session_id, selector, name, &SystemOstreeRepository)
    }

    pub(crate) fn rename_using_repository(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
        name: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let catalog =
            FilesystemSessionWorkCatalog::load_using_repository(storage, session_id, repository)?;
        let resolver = SessionWorkCatalogResolver::new(&catalog);
        let target = resolver.resolve(selector)?;
        let key = target.catalog_key();
        let name = SessionWorkTargetName::new(name)?;
        resolver.ensure_unique_name(&key, &name)?;
        let name = name.into_string();
        let mut state = SessionWorkState::read(storage)?;
        state.set_name(key, name.clone());
        state.write(storage)?;
        state.append_rename_event(storage, selector, &name)?;
        Ok(Self::new(selector, name))
    }

    pub(super) fn new(handle: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            name: name.into(),
        }
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub(super) struct SessionWorkTargetName {
    value: String,
}

impl SessionWorkTargetName {
    pub(super) fn new(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(
            !value.is_empty() && !value.contains('\n'),
            InvalidTransactionNameSnafu {
                name: value.to_owned(),
                reason: String::from("name must be non-empty and single-line"),
            }
        );
        Ok(Self {
            value: value.to_owned(),
        })
    }

    pub(super) fn as_str(&self) -> &str {
        &self.value
    }

    pub(super) fn into_string(self) -> String {
        self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SessionWorkCommitJournal {
    pub(super) session_id: String,
    pub(super) transaction_id: String,
    pub(super) parent_transaction_id: Option<String>,
    pub(super) source: String,
    pub(super) autocommit_rule_id: Option<String>,
    pub(super) action_request_id: Option<String>,
    pub(super) manifest_ref: String,
    pub(super) checkpoint_ref: String,
    pub(super) volume_refs: Vec<SessionWorkJournalRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SessionWorkRollbackJournal {
    pub(super) selector: String,
    pub(super) transaction_id: String,
    pub(super) selected_volumes: Vec<String>,
    pub(super) restored_volumes: Vec<String>,
    pub(super) outcome: String,
    pub(super) error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct SessionWorkJournalRef {
    pub(super) volume_id: String,
    pub(super) layer_ref: String,
}

struct SessionWorkJournal<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> SessionWorkJournal<'a> {
    const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    fn append_event(&self, event: &SessionWorkJournalEvent) -> Result<()> {
        let path = self.path();
        self.create_parent()?;
        let mut source =
            serde_json::to_string(event).context(EncodeSessionWorkSnafu { path: path.clone() })?;
        source.push('\n');
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        std::io::Write::write_all(
            &mut options.open(&path).context(SessionWorkIoSnafu {
                action: "open session-work journal",
                path: path.as_path(),
            })?,
            source.as_bytes(),
        )
        .context(SessionWorkIoSnafu {
            action: "write session-work journal",
            path: path.as_path(),
        })
    }

    fn create_parent(&self) -> Result<()> {
        let path = self.path();
        let parent = path.parent().map(PathBuf::from).unwrap_or_default();
        fs::create_dir_all(&parent).context(SessionWorkIoSnafu {
            action: "create session-work journal directory",
            path: parent.as_path(),
        })
    }

    fn path(&self) -> PathBuf {
        self.storage
            .root()
            .join(SESSION_WORK_DIR)
            .join(SESSION_WORK_JOURNAL_FILE)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum SessionWorkJournalEvent {
    Commit(SessionWorkCommitJournal),
    Rename { selector: String, name: String },
    Rollback(SessionWorkRollbackJournal),
}

pub(super) struct SessionWorkClock;

impl SessionWorkClock {
    pub(super) fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }
}
