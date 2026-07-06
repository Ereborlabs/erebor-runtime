use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    checkpoint::FilesystemCheckpointCommit,
    error::{EncodeSessionWorkSnafu, SessionWorkIoSnafu},
    ostree::{OstreeRepository, OstreeTreeCommit, SystemOstreeRepository},
    FilesystemSessionStorage, Result,
};

use super::{
    id::{SessionWorkRefParser, SessionWorkSessionId, SessionWorkTransactionId},
    manifest::{
        FilesystemSessionWorkManifest, FilesystemSessionWorkManifestRequest,
        FilesystemSessionWorkVolume, SESSION_WORK_MANIFEST_FILE,
    },
    state::{
        SessionWorkClock, SessionWorkCommitJournal, SessionWorkJournalRef, SessionWorkState,
        SessionWorkTargetKey, SessionWorkTargetName,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemSessionWorkCommitSource {
    User,
    Autocommit,
}

impl FilesystemSessionWorkCommitSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Autocommit => "autocommit",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSessionWorkCommitRequest {
    session_id: String,
    source: FilesystemSessionWorkCommitSource,
    autocommit_rule_id: Option<String>,
    action_request_id: Option<String>,
    name: Option<String>,
}

impl FilesystemSessionWorkCommitRequest {
    pub fn user(session_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        SessionWorkSessionId::new(&session_id)?;
        Ok(Self {
            session_id,
            source: FilesystemSessionWorkCommitSource::User,
            autocommit_rule_id: None,
            action_request_id: None,
            name: None,
        })
    }

    pub fn autocommit(session_id: impl Into<String>, rule_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        let rule_id = rule_id.into();
        SessionWorkSessionId::new(&session_id)?;
        SessionWorkTargetName::new(&rule_id)?;
        Ok(Self {
            session_id,
            source: FilesystemSessionWorkCommitSource::Autocommit,
            autocommit_rule_id: Some(rule_id),
            action_request_id: None,
            name: None,
        })
    }

    pub fn set_action_request_id(&mut self, action_request_id: impl Into<String>) -> Result<()> {
        let action_request_id = action_request_id.into();
        SessionWorkTargetName::new(&action_request_id)?;
        self.action_request_id = Some(action_request_id);
        Ok(())
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<()> {
        let name = name.into();
        SessionWorkTargetName::new(&name)?;
        self.name = Some(name);
        Ok(())
    }

    pub(super) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(super) const fn source(&self) -> FilesystemSessionWorkCommitSource {
        self.source
    }

    pub(super) fn autocommit_rule_id(&self) -> Option<&str> {
        self.autocommit_rule_id.as_deref()
    }

    pub(super) fn action_request_id(&self) -> Option<&str> {
        self.action_request_id.as_deref()
    }

    pub(super) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkCommit {
    handle: String,
    session_id: String,
    transaction_id: String,
    parent_transaction_id: Option<String>,
    source: FilesystemSessionWorkCommitSource,
    autocommit_rule_id: Option<String>,
    action_request_id: Option<String>,
    manifest_ref: String,
    checkpoint_ref: String,
    volumes: Vec<FilesystemSessionWorkVolume>,
}

impl FilesystemSessionWorkCommit {
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    #[must_use]
    pub fn manifest_ref(&self) -> &str {
        &self.manifest_ref
    }

    #[must_use]
    pub fn checkpoint_ref(&self) -> &str {
        &self.checkpoint_ref
    }

    #[must_use]
    pub fn volumes(&self) -> &[FilesystemSessionWorkVolume] {
        &self.volumes
    }
}

pub struct FilesystemSessionWorkCommitter;

impl FilesystemSessionWorkCommitter {
    pub fn commit(
        storage: &FilesystemSessionStorage,
        request: FilesystemSessionWorkCommitRequest,
    ) -> Result<FilesystemSessionWorkCommit> {
        Self::commit_using_repository(storage, request, &SystemOstreeRepository)
    }

    pub(crate) fn commit_using_repository(
        storage: &FilesystemSessionStorage,
        request: FilesystemSessionWorkCommitRequest,
        repository: &impl OstreeRepository,
    ) -> Result<FilesystemSessionWorkCommit> {
        SessionWorkCommitWorkflow::new(storage, request, repository)?.commit()
    }
}

struct SessionWorkCommitWorkflow<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    request: FilesystemSessionWorkCommitRequest,
    repository: &'a R,
    allocation: SessionWorkAllocation,
}

impl<'a, R> SessionWorkCommitWorkflow<'a, R>
where
    R: OstreeRepository,
{
    fn new(
        storage: &'a FilesystemSessionStorage,
        request: FilesystemSessionWorkCommitRequest,
        repository: &'a R,
    ) -> Result<Self> {
        let allocation =
            SessionWorkAllocator::new(storage, request.session_id(), repository)?.allocate()?;
        Ok(Self {
            storage,
            request,
            repository,
            allocation,
        })
    }

    fn commit(&self) -> Result<FilesystemSessionWorkCommit> {
        let manifests = self.storage.normalize_layers()?;
        let checkpoint = FilesystemCheckpointCommit::commit_normalized_using_repository(
            self.storage,
            &self.allocation.transaction_id,
            &manifests,
            self.repository,
        )?;
        let manifest = self.session_work_manifest(&checkpoint);
        let manifest_path = self.write_manifest(&manifest)?;
        OstreeTreeCommit::new(
            self.storage.repo_path(),
            &self.allocation.manifest_ref,
            &manifest_path,
            "commit session-work manifest",
            &format!(
                "Erebor filesystem session-work {} manifest",
                self.allocation.transaction_id
            ),
        )
        .commit(self.repository)?;
        self.update_state(&manifest)?;

        Ok(FilesystemSessionWorkCommit {
            handle: format!("work@{{{}}}", self.allocation.handle_index),
            session_id: manifest.session_id,
            transaction_id: manifest.transaction_id,
            parent_transaction_id: manifest.parent_transaction_id,
            source: manifest.source,
            autocommit_rule_id: manifest.autocommit_rule_id,
            action_request_id: manifest.action_request_id,
            manifest_ref: self.allocation.manifest_ref.clone(),
            checkpoint_ref: manifest.checkpoint_ref,
            volumes: manifest.volumes,
        })
    }

    fn session_work_manifest(
        &self,
        checkpoint: &FilesystemCheckpointCommit,
    ) -> FilesystemSessionWorkManifest {
        let volumes = checkpoint
            .volumes()
            .iter()
            .map(|volume| FilesystemSessionWorkVolume {
                volume_id: volume.volume_id.clone(),
                layer_ref: volume.layer_ref.clone(),
            })
            .collect();
        FilesystemSessionWorkManifest::new(FilesystemSessionWorkManifestRequest {
            session_id: self.request.session_id().to_owned(),
            transaction_id: self.allocation.transaction_id.clone(),
            parent_transaction_id: self.allocation.parent_transaction_id.clone(),
            source: self.request.source(),
            autocommit_rule_id: self.request.autocommit_rule_id().map(ToOwned::to_owned),
            action_request_id: self.request.action_request_id().map(ToOwned::to_owned),
            checkpoint_ref: checkpoint.checkpoint_ref().to_owned(),
            committed_at_unix_ms: SessionWorkClock::unix_time_ms(),
            volumes,
        })
    }

    fn write_manifest(&self, manifest: &FilesystemSessionWorkManifest) -> Result<PathBuf> {
        let stage = self
            .storage
            .work_path()
            .join("session-work")
            .join(&self.allocation.transaction_id)
            .join("manifest");
        if stage.exists() {
            fs::remove_dir_all(&stage).context(SessionWorkIoSnafu {
                action: "remove session-work manifest stage",
                path: stage.as_path(),
            })?;
        }
        fs::create_dir_all(&stage).context(SessionWorkIoSnafu {
            action: "create session-work manifest stage",
            path: stage.as_path(),
        })?;
        let path = stage.join(SESSION_WORK_MANIFEST_FILE);
        let source = serde_json::to_vec_pretty(manifest)
            .context(EncodeSessionWorkSnafu { path: path.clone() })?;
        fs::write(&path, source).context(SessionWorkIoSnafu {
            action: "write session-work manifest",
            path: path.as_path(),
        })?;
        Ok(stage)
    }

    fn update_state(&self, manifest: &FilesystemSessionWorkManifest) -> Result<()> {
        let mut state = SessionWorkState::read(self.storage)?;
        if let Some(name) = self.request.name() {
            state.set_name(
                SessionWorkTargetKey::transaction(&manifest.transaction_id),
                name.to_owned(),
            );
        }
        state.mark_current(&manifest.transaction_id);
        state.write(self.storage)?;
        state.append_commit_event(
            self.storage,
            SessionWorkCommitJournal {
                session_id: manifest.session_id.clone(),
                transaction_id: manifest.transaction_id.clone(),
                parent_transaction_id: manifest.parent_transaction_id.clone(),
                source: manifest.source.as_str().to_owned(),
                autocommit_rule_id: manifest.autocommit_rule_id.clone(),
                action_request_id: manifest.action_request_id.clone(),
                manifest_ref: self.allocation.manifest_ref.clone(),
                checkpoint_ref: manifest.checkpoint_ref.clone(),
                volume_refs: manifest
                    .volumes
                    .iter()
                    .map(|volume| SessionWorkJournalRef {
                        volume_id: volume.volume_id.clone(),
                        layer_ref: volume.layer_ref.clone(),
                    })
                    .collect(),
            },
        )
    }
}

struct SessionWorkAllocator<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    session_id: SessionWorkSessionId<'a>,
    repository: &'a R,
}

impl<'a, R> SessionWorkAllocator<'a, R>
where
    R: OstreeRepository,
{
    fn new(
        storage: &'a FilesystemSessionStorage,
        session_id: &'a str,
        repository: &'a R,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            session_id: SessionWorkSessionId::new(session_id)?,
            repository,
        })
    }

    fn allocate(&self) -> Result<SessionWorkAllocation> {
        let mut existing = self.existing_transactions()?;
        existing.sort_by_key(|transaction| transaction.sequence);
        let next_sequence = existing
            .last()
            .map_or(1, |transaction| transaction.sequence + 1);
        let transaction_id = self.session_id.transaction_id(next_sequence);
        let transaction = SessionWorkTransactionId::new(&transaction_id)?;
        let manifest_ref = transaction.manifest_ref(self.session_id);
        Ok(SessionWorkAllocation {
            handle_index: 0,
            transaction_id,
            parent_transaction_id: existing
                .last()
                .map(|transaction| transaction.transaction_id.clone()),
            manifest_ref,
        })
    }

    fn existing_transactions(&self) -> Result<Vec<ExistingSessionWorkTransaction>> {
        let parser = SessionWorkRefParser::new(self.session_id);
        let mut transactions = Vec::new();
        for ref_name in self.repository.list_refs(self.storage.repo_path())? {
            let Some(transaction_id) = parser.transaction_id_from_manifest_ref(&ref_name) else {
                continue;
            };
            let id = SessionWorkTransactionId::new(&transaction_id)?;
            if let Some(sequence) = id.sequence(self.session_id) {
                transactions.push(ExistingSessionWorkTransaction {
                    transaction_id,
                    sequence,
                });
            }
        }
        Ok(transactions)
    }
}

struct SessionWorkAllocation {
    handle_index: usize,
    transaction_id: String,
    parent_transaction_id: Option<String>,
    manifest_ref: String,
}

struct ExistingSessionWorkTransaction {
    transaction_id: String,
    sequence: u64,
}
