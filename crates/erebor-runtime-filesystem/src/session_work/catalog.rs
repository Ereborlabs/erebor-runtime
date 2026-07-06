use std::{collections::BTreeSet, fs, path::Path};

use serde::Serialize;
use snafu::{ensure, ResultExt};

use crate::{
    error::{EncodeSessionWorkSnafu, InvalidTransactionNameSnafu, SessionWorkIoSnafu},
    manifest::LAYER_MANIFEST_FILE,
    ostree::{OstreeRepository, OstreeTreeCheckout, SystemOstreeRepository},
    FilesystemLayerManifest, FilesystemLayerOperation, FilesystemSessionStorage, Result,
};

use super::{
    id::{SessionWorkRefParser, SessionWorkSessionId, SessionWorkTransactionId},
    manifest::{FilesystemSessionWorkManifest, SESSION_WORK_MANIFEST_FILE},
    state::{SessionWorkState, SessionWorkTargetKey, SessionWorkTargetName},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkCatalog {
    transactions: Vec<FilesystemSessionWorkTransaction>,
}

impl FilesystemSessionWorkCatalog {
    pub fn load(storage: &FilesystemSessionStorage, session_id: &str) -> Result<Self> {
        Self::load_using_repository(storage, session_id, &SystemOstreeRepository)
    }

    pub(crate) fn load_using_repository(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        SessionWorkCatalogLoader::new(storage, session_id, repository)?.load()
    }

    pub fn transactions(&self) -> &[FilesystemSessionWorkTransaction] {
        &self.transactions
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkTransaction {
    handle: String,
    session_id: String,
    transaction_id: String,
    parent_transaction_id: Option<String>,
    name: Option<String>,
    state: FilesystemSessionWorkTransactionState,
    source: String,
    autocommit_rule_id: Option<String>,
    action_request_id: Option<String>,
    manifest_ref: String,
    checkpoint_ref: String,
    change_count: usize,
    subtransactions: Vec<FilesystemSessionWorkSubtransaction>,
}

impl FilesystemSessionWorkTransaction {
    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub const fn state(&self) -> FilesystemSessionWorkTransactionState {
        self.state
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub const fn change_count(&self) -> usize {
        self.change_count
    }

    pub fn subtransactions(&self) -> &[FilesystemSessionWorkSubtransaction] {
        &self.subtransactions
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkSubtransaction {
    handle: String,
    transaction_id: String,
    volume_id: String,
    layer_ref: String,
    name: Option<String>,
    changes: Vec<FilesystemSessionWorkChange>,
}

impl FilesystemSessionWorkSubtransaction {
    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }

    pub fn layer_ref(&self) -> &str {
        &self.layer_ref
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn changes(&self) -> &[FilesystemSessionWorkChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkChange {
    operation: String,
    path: String,
}

impl FilesystemSessionWorkChange {
    fn new(operation: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            path: path.into(),
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemSessionWorkTransactionState {
    Current,
    Available,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilesystemSessionWorkTarget {
    Transaction(FilesystemSessionWorkTransaction),
    Subtransaction(FilesystemSessionWorkSubtransaction),
}

impl FilesystemSessionWorkTarget {
    pub fn show(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
    ) -> Result<Self> {
        Self::show_using_repository(storage, session_id, selector, &SystemOstreeRepository)
    }

    pub(crate) fn show_using_repository(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let catalog =
            FilesystemSessionWorkCatalog::load_using_repository(storage, session_id, repository)?;
        SessionWorkCatalogResolver::new(&catalog).resolve(selector)
    }

    pub(super) fn catalog_key(&self) -> SessionWorkTargetKey {
        match self {
            Self::Transaction(transaction) => {
                SessionWorkTargetKey::transaction(transaction.transaction_id())
            }
            Self::Subtransaction(subtransaction) => SessionWorkTargetKey::subtransaction(
                subtransaction.transaction_id(),
                subtransaction.volume_id(),
            ),
        }
    }

    pub(super) fn transaction_id(&self) -> &str {
        match self {
            Self::Transaction(transaction) => transaction.transaction_id(),
            Self::Subtransaction(subtransaction) => subtransaction.transaction_id(),
        }
    }

    pub(super) fn selected_volumes(&self) -> Vec<String> {
        match self {
            Self::Transaction(transaction) => transaction
                .subtransactions()
                .iter()
                .map(|subtransaction| subtransaction.volume_id().to_owned())
                .collect(),
            Self::Subtransaction(subtransaction) => vec![subtransaction.volume_id().to_owned()],
        }
    }

    pub(super) fn selected_layers(&self) -> Vec<SessionWorkSelectedLayer> {
        match self {
            Self::Transaction(transaction) => transaction
                .subtransactions()
                .iter()
                .map(SessionWorkSelectedLayer::from)
                .collect(),
            Self::Subtransaction(subtransaction) => {
                vec![SessionWorkSelectedLayer::from(subtransaction)]
            }
        }
    }
}

pub(super) struct SessionWorkSelectedLayer {
    pub(super) volume_id: String,
    pub(super) layer_ref: String,
}

impl From<&FilesystemSessionWorkSubtransaction> for SessionWorkSelectedLayer {
    fn from(subtransaction: &FilesystemSessionWorkSubtransaction) -> Self {
        Self {
            volume_id: subtransaction.volume_id().to_owned(),
            layer_ref: subtransaction.layer_ref().to_owned(),
        }
    }
}

pub(super) struct SessionWorkCatalogResolver<'a> {
    catalog: &'a FilesystemSessionWorkCatalog,
}

impl<'a> SessionWorkCatalogResolver<'a> {
    pub(super) const fn new(catalog: &'a FilesystemSessionWorkCatalog) -> Self {
        Self { catalog }
    }

    pub(super) fn resolve(&self, selector: &str) -> Result<FilesystemSessionWorkTarget> {
        if let Some(target) = self.resolve_handle(selector) {
            return Ok(target);
        }
        self.resolve_name(selector)
    }

    pub(super) fn ensure_unique_name(
        &self,
        target: &SessionWorkTargetKey,
        name: &SessionWorkTargetName,
    ) -> Result<()> {
        let mut owners = BTreeSet::new();
        for transaction in self.catalog.transactions() {
            if transaction.name() == Some(name.as_str()) {
                owners.insert(SessionWorkTargetKey::transaction(
                    transaction.transaction_id(),
                ));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.name() == Some(name.as_str()) {
                    owners.insert(SessionWorkTargetKey::subtransaction(
                        transaction.transaction_id(),
                        subtransaction.volume_id(),
                    ));
                }
            }
        }
        ensure!(
            owners.is_empty() || owners == BTreeSet::from([target.clone()]),
            InvalidTransactionNameSnafu {
                name: name.as_str().to_owned(),
                reason: String::from("name is already used by another session-work target"),
            }
        );
        Ok(())
    }

    fn resolve_handle(&self, selector: &str) -> Option<FilesystemSessionWorkTarget> {
        for transaction in self.catalog.transactions() {
            if transaction.handle() == selector {
                return Some(FilesystemSessionWorkTarget::Transaction(
                    transaction.clone(),
                ));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.handle() == selector {
                    return Some(FilesystemSessionWorkTarget::Subtransaction(
                        subtransaction.clone(),
                    ));
                }
            }
        }
        None
    }

    fn resolve_name(&self, selector: &str) -> Result<FilesystemSessionWorkTarget> {
        let mut matches = Vec::new();
        for transaction in self.catalog.transactions() {
            if transaction.name() == Some(selector) {
                matches.push(FilesystemSessionWorkTarget::Transaction(
                    transaction.clone(),
                ));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.name() == Some(selector) {
                    matches.push(FilesystemSessionWorkTarget::Subtransaction(
                        subtransaction.clone(),
                    ));
                }
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => crate::error::InvalidTransactionHandleSnafu {
                handle: selector.to_owned(),
                reason: String::from("no session-work target matches this handle or name"),
            }
            .fail(),
            _ => crate::error::InvalidTransactionHandleSnafu {
                handle: selector.to_owned(),
                reason: String::from("session-work target name is ambiguous"),
            }
            .fail(),
        }
    }
}

struct SessionWorkCatalogLoader<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    session_id: SessionWorkSessionId<'a>,
    repository: &'a R,
    state: SessionWorkState,
}

impl<'a, R> SessionWorkCatalogLoader<'a, R>
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
            state: SessionWorkState::read(storage)?,
        })
    }

    fn load(&self) -> Result<FilesystemSessionWorkCatalog> {
        let mut ids = self.transaction_ids()?;
        ids.sort_by_key(|id| {
            SessionWorkTransactionId::new(id)
                .ok()
                .and_then(|id| id.sequence(self.session_id))
        });
        ids.reverse();
        let transactions = ids
            .iter()
            .enumerate()
            .map(|(index, transaction_id)| self.load_transaction(index, transaction_id))
            .collect::<Result<Vec<_>>>()?;
        Ok(FilesystemSessionWorkCatalog { transactions })
    }

    fn transaction_ids(&self) -> Result<Vec<String>> {
        let parser = SessionWorkRefParser::new(self.session_id);
        let mut ids = self
            .repository
            .list_refs(self.storage.repo_path())?
            .into_iter()
            .filter_map(|ref_name| parser.transaction_id_from_manifest_ref(&ref_name))
            .collect::<Vec<_>>();
        ids.dedup();
        Ok(ids)
    }

    fn load_transaction(
        &self,
        index: usize,
        transaction_id: &str,
    ) -> Result<FilesystemSessionWorkTransaction> {
        let transaction = SessionWorkTransactionId::new(transaction_id)?;
        let root = self.checkout_root(transaction_id);
        OstreeTreeCheckout::new(
            self.storage.repo_path(),
            &transaction.manifest_ref(self.session_id),
            &root.join("manifest"),
            "checkout session-work manifest",
        )
        .checkout(self.repository)?;
        let manifest = Self::read_manifest(&root.join("manifest"))?;
        let mut subtransactions = Vec::new();
        for (sub_index, volume) in manifest.volumes.iter().enumerate() {
            let layer_root = root.join("layers").join(&volume.volume_id).join("layer");
            OstreeTreeCheckout::new(
                self.storage.repo_path(),
                &volume.layer_ref,
                &layer_root,
                "checkout session-work layer",
            )
            .checkout(self.repository)?;
            let layer = Self::read_layer_manifest(&layer_root)?;
            subtransactions.push(FilesystemSessionWorkSubtransaction {
                handle: format!("work@{{{index}}}.sub@{{{sub_index}}}"),
                transaction_id: transaction_id.to_owned(),
                volume_id: volume.volume_id.clone(),
                layer_ref: volume.layer_ref.clone(),
                name: self
                    .state
                    .name_for(&SessionWorkTargetKey::subtransaction(
                        transaction_id,
                        &volume.volume_id,
                    ))
                    .map(ToOwned::to_owned),
                changes: layer
                    .operations
                    .iter()
                    .map(Self::change_from_operation)
                    .collect(),
            });
        }
        let change_count = subtransactions
            .iter()
            .map(|subtransaction| subtransaction.changes().len())
            .sum();
        Ok(FilesystemSessionWorkTransaction {
            handle: format!("work@{{{index}}}"),
            session_id: manifest.session_id,
            transaction_id: manifest.transaction_id,
            parent_transaction_id: manifest.parent_transaction_id,
            name: self
                .state
                .name_for(&SessionWorkTargetKey::transaction(transaction_id))
                .map(ToOwned::to_owned),
            state: self.transaction_state(transaction_id),
            source: manifest.source.as_str().to_owned(),
            autocommit_rule_id: manifest.autocommit_rule_id,
            action_request_id: manifest.action_request_id,
            manifest_ref: transaction.manifest_ref(self.session_id),
            checkpoint_ref: manifest.checkpoint_ref,
            change_count,
            subtransactions,
        })
    }

    fn transaction_state(&self, transaction_id: &str) -> FilesystemSessionWorkTransactionState {
        if self.state.current_transaction_id() == Some(transaction_id) {
            FilesystemSessionWorkTransactionState::Current
        } else {
            FilesystemSessionWorkTransactionState::Available
        }
    }

    fn read_manifest(root: &Path) -> Result<FilesystemSessionWorkManifest> {
        let path = root.join(SESSION_WORK_MANIFEST_FILE);
        let source = fs::read_to_string(&path).context(SessionWorkIoSnafu {
            action: "read session-work manifest",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeSessionWorkSnafu { path })
    }

    fn read_layer_manifest(root: &Path) -> Result<FilesystemLayerManifest> {
        let path = root.join(LAYER_MANIFEST_FILE);
        let source = fs::read_to_string(&path).context(SessionWorkIoSnafu {
            action: "read session-work layer manifest",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeSessionWorkSnafu { path })
    }

    fn change_from_operation(operation: &FilesystemLayerOperation) -> FilesystemSessionWorkChange {
        match operation {
            FilesystemLayerOperation::Create { path, .. } => {
                FilesystemSessionWorkChange::new("create", path)
            }
            FilesystemLayerOperation::Replace { path, .. } => {
                FilesystemSessionWorkChange::new("replace", path)
            }
            FilesystemLayerOperation::Delete { path } => {
                FilesystemSessionWorkChange::new("delete", path)
            }
            FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                FilesystemSessionWorkChange::new("opaque_replace", path)
            }
        }
    }

    fn checkout_root(&self, transaction_id: &str) -> std::path::PathBuf {
        self.storage
            .work_path()
            .join("session-work")
            .join("catalog")
            .join("checkouts")
            .join(transaction_id)
    }
}
