//! Native Data storage used during the production storage replacement.
//! Production admission still uses `AnalysisStore` until all owners move.

use std::{
    ops::Bound::Included,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, RwLock,
    },
};

use fjall::{Branch, BranchSnapshot, BranchWriteTransaction, Commit, SingleWriterTxDatabase};
use snafu::ResultExt as _;
use uuid::Uuid;

use super::{
    raw::{RawIndex, RawJournal},
    read::locks::{Mutex as RawMutex, RwLock as Maintenance},
};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

const HEAD: &[u8] = b"\0data/head";
const IDENTITY: &[u8] = b"\0data/identity";
const FORMAT: &[u8] = b"\0data/format";
const SCHEMA: &[u8] = b"\0data/schema";
const RECOVERY: &[u8] = b"\0data/recovery";

mod context;
mod extraction;
pub(in crate::analysis) mod inputs;
mod managed;
mod notification;
mod packages;
mod records;
mod revisions;
mod source;

pub use managed::{
    GraphPublication, ManagedCommit, ManagedGraph, ManagedGraphJournal, ManagedGraphTransaction,
    ManagedLease, ManagedReturn, PreparedManagedCommit,
};

pub struct NativeStore {
    database: SingleWriterTxDatabase,
    branch: Branch,
    writer: Mutex<()>,
    published: Arc<RwLock<Arc<DataView>>>,
    root: PathBuf,
    raw: RawMutex<RawJournal>,
    maintenance: Maintenance<()>,
    ready: Arc<AtomicBool>,
    managed_owner: AtomicBool,
    revision: tokio::sync::watch::Sender<u64>,
    inputs: Arc<inputs::Coordinator>,
    _lease: super::connection::AnalysisLease,
}

pub struct DataView {
    revision: u64,
    store_uuid: Uuid,
    snapshot: BranchSnapshot,
    metadata_revision: u64,
    schema_version: u32,
    recovery_epoch: u64,
    raw: RawIndex,
    graphs: rpds::RedBlackTreeMapSync<([u8; 16], u64), ()>,
    contexts: context::ContextNames,
}

pub struct DataWrite<'a> {
    store: &'a NativeStore,
    revision: u64,
    transaction: BranchWriteTransaction<'a>,
    raw: RawIndex,
    graphs: rpds::RedBlackTreeMapSync<([u8; 16], u64), ()>,
    contexts: context::ContextNames,
    metadata_revision: u64,
    dirty: bool,
    verified: super::context::VerifiedPackages,
    _writer: MutexGuard<'a, ()>,
}

impl DataView {
    pub fn meta(&self) -> crate::AnalysisStoreMetaV1 {
        crate::AnalysisStoreMetaV1 {
            store_uuid: self.store_uuid,
            schema_version: self.schema_version,
            recovery_epoch: self.recovery_epoch,
            commit_revision: self.revision,
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn store_uuid(&self) -> Uuid {
        self.store_uuid
    }

    pub fn snapshot(&self) -> &BranchSnapshot {
        &self.snapshot
    }
}

impl NativeStore {
    pub fn open(root: &Path) -> Result<Self> {
        let lease = super::connection::AnalysisLease::acquire(root)?;
        if root.join("analysis.duckdb").exists() {
            return NativeStateSnafu {
                field: "store format",
            }
            .fail();
        }
        let database = SingleWriterTxDatabase::builder(root.join("fjall"))
            .versioned()
            .open()
            .context(NativeStorageSnafu { operation: "open" })?;
        let branch = match database.branch("data").context(NativeStorageSnafu {
            operation: "resolve live branch",
        })? {
            Some(branch) => branch,
            None => database.create_branch("data").context(NativeStorageSnafu {
                operation: "create live branch",
            })?,
        };
        let snapshot = branch.snapshot().context(NativeStorageSnafu {
            operation: "capture recovered state",
        })?;
        if snapshot
            .get(FORMAT)
            .context(NativeStorageSnafu {
                operation: "read format",
            })?
            .is_none()
        {
            if snapshot
                .iter()
                .next()
                .transpose()
                .context(NativeStorageSnafu {
                    operation: "check initial branch",
                })?
                .is_some()
            {
                return NativeStateSnafu {
                    field: "unrecognized branch",
                }
                .fail();
            }
            if !database
                .history()
                .context(NativeStorageSnafu {
                    operation: "read history policies",
                })?
                .iter()
                .any(|policy| {
                    policy.branch == branch.id()
                        && policy.first <= snapshot.revision()
                        && policy.last.to_bytes() == u64::MAX.to_be_bytes()
                })
            {
                branch
                    .retain_history(snapshot.revision()..)
                    .context(NativeStorageSnafu {
                        operation: "retain initial history",
                    })?;
            }
            let mut tx = branch.write_tx().context(NativeStorageSnafu {
                operation: "initialize",
            })?;
            tx.insert(FORMAT, 4u64.to_be_bytes());
            tx.insert(
                SCHEMA,
                (super::ANALYSIS_SCHEMA_VERSION as u64).to_be_bytes(),
            );
            tx.insert(RECOVERY, 1u64.to_be_bytes());
            tx.insert(IDENTITY, Uuid::new_v4().as_bytes().as_slice());
            tx.insert(HEAD, 0u64.to_be_bytes());
            tx.commit_stamped([Self::cut(0)])
                .context(NativeStorageSnafu {
                    operation: "commit initial state",
                })?;
        }
        let snapshot = branch.snapshot().context(NativeStorageSnafu {
            operation: "capture initial state",
        })?;
        let revision = Self::number(&Self::required(&snapshot, HEAD)?)?;
        let cut = Self::required(&snapshot, &Self::cut(revision))?;
        let mut view = Self::cut_view(&branch, revision, &cut)?;
        if Self::required(&snapshot, IDENTITY)? != view.store_uuid.as_bytes() {
            return NativeStateSnafu {
                field: "recovered store identity",
            }
            .fail();
        }
        let first = Self::required(&snapshot, &Self::cut(0))?;
        let first = fjall::Revision::from_bytes(first.as_slice().try_into().map_err(|_| {
            NativeStateSnafu {
                field: "initial cut width",
            }
            .build()
        })?);
        if !database
            .history()
            .context(NativeStorageSnafu {
                operation: "check recovered history",
            })?
            .iter()
            .any(|policy| {
                policy.branch == branch.id()
                    && policy.first <= first
                    && policy.last.to_bytes() == u64::MAX.to_be_bytes()
            })
        {
            return NativeStateSnafu {
                field: "required history protection",
            }
            .fail();
        }
        let raw = Self::recover_raw(root, &view.snapshot)?;
        view.revision = view.revision.max(raw.index.revision);
        view.raw = raw.index.clone();
        view.validate_catalogue()?;
        view.validate_contexts()?;
        view.validate_managed()?;
        view.validate_attempts()?;
        let revision = tokio::sync::watch::channel(view.revision).0;
        let published = Arc::new(RwLock::new(Arc::new(view)));
        let ready = Arc::new(AtomicBool::new(true));
        let inputs = Arc::new(inputs::Coordinator::new(
            database.clone(),
            branch.clone(),
            Arc::clone(&published),
            Arc::clone(&ready),
        )?);
        let store = Self {
            database,
            branch,
            writer: Mutex::new(()),
            published,
            root: root.to_path_buf(),
            raw: RawMutex::new(raw),
            maintenance: Maintenance::new(()),
            ready,
            managed_owner: AtomicBool::new(false),
            revision,
            inputs,
            _lease: lease,
        };
        store.validate_result_recovery()?;
        store.validate_graph_recovery()?;
        store.recover_managed_startup()?;
        Ok(store)
    }

    fn decode_view(snapshot: BranchSnapshot) -> Result<DataView> {
        if Self::number(&Self::required(&snapshot, FORMAT)?)? != 4 {
            return NativeStateSnafu {
                field: "format version",
            }
            .fail();
        }
        let schema = Self::number(&Self::required(&snapshot, SCHEMA)?)?;
        let recovery_epoch = Self::number(&Self::required(&snapshot, RECOVERY)?)?;
        if schema != super::ANALYSIS_SCHEMA_VERSION as u64 || recovery_epoch == 0 {
            return NativeStateSnafu {
                field: "logical Data metadata",
            }
            .fail();
        }
        let revision = Self::number(&Self::required(&snapshot, HEAD)?)?;
        let identity = Self::required(&snapshot, IDENTITY)?;
        let identity: [u8; 16] = identity.as_slice().try_into().map_err(|_| {
            NativeStateSnafu {
                field: "store identity",
            }
            .build()
        })?;
        let store_uuid = Uuid::from_bytes(identity);
        if store_uuid.is_nil() {
            return NativeStateSnafu {
                field: "store identity",
            }
            .fail();
        }
        let cut = Self::required(&snapshot, &Self::cut(revision))?;
        if cut != snapshot.revision().to_bytes() {
            return NativeStateSnafu {
                field: "published cut",
            }
            .fail();
        }
        Ok(DataView {
            revision,
            store_uuid,
            snapshot,
            metadata_revision: revision,
            schema_version: schema as u32,
            recovery_epoch,
            raw: RawIndex::default(),
            graphs: Default::default(),
            contexts: Default::default(),
        })
    }

    fn cut_view(branch: &Branch, revision: u64, bytes: &[u8]) -> Result<DataView> {
        let cut = fjall::Revision::from_bytes(bytes.try_into().map_err(|_| {
            NativeStateSnafu {
                field: "historical cut width",
            }
            .build()
        })?);
        let snapshot = branch.read_at(cut).context(NativeStorageSnafu {
            operation: "capture exact Data cut",
        })?;
        let view = Self::decode_view(snapshot)?;
        if view.revision != revision {
            return NativeStateSnafu {
                field: "cut index revision",
            }
            .fail();
        }
        Ok(view)
    }

    fn required(snapshot: &BranchSnapshot, key: &[u8]) -> Result<Vec<u8>> {
        snapshot
            .get(key)
            .context(NativeStorageSnafu {
                operation: "read Data metadata",
            })?
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "metadata record",
                }
                .build()
            })
    }

    fn number(bytes: &[u8]) -> Result<u64> {
        bytes.try_into().map(u64::from_be_bytes).map_err(|_| {
            NativeStateSnafu {
                field: "metadata integer",
            }
            .build()
        })
    }

    fn cut(revision: u64) -> Vec<u8> {
        [b"\0data/cut/".as_slice(), &revision.to_be_bytes()].concat()
    }

    fn check(&self) -> Result<()> {
        if !self.ready.load(Ordering::Acquire) {
            return NativeStateSnafu {
                field: "uncertain commit; reopen required",
            }
            .fail();
        }
        Ok(())
    }

    pub fn view(&self) -> Result<Arc<DataView>> {
        self.check()?;
        let view = self.published.read().map_err(|_| {
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })?;
        self.check()?;
        Ok(Arc::clone(&view))
    }

    pub fn read_at(&self, revision: u64) -> Result<DataView> {
        let current = self.view()?;
        Self::cut_at(&self.branch, &current, revision)
    }

    fn cut_at(branch: &Branch, current: &DataView, revision: u64) -> Result<DataView> {
        if revision > current.revision {
            return NativeStateSnafu {
                field: "requested revision",
            }
            .fail();
        }
        let (key, cut) = current
            .snapshot
            .range::<Vec<u8>, _>((Included(Self::cut(0)), Included(Self::cut(revision))))
            .next_back()
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "historical cut",
                }
                .build()
            })?
            .context(NativeStorageSnafu {
                operation: "read historical cut",
            })?;
        let selected = Self::number(&key[b"\0data/cut/".len()..])?;
        let mut view = Self::cut_view(branch, selected, &cut)?;
        if view.store_uuid != current.store_uuid {
            return NativeStateSnafu {
                field: "historical store identity",
            }
            .fail();
        }
        view.revision = revision;
        view.raw = current.raw.clone();
        view.graphs = current.graphs.clone();
        view.contexts = current.contexts.clone();
        Ok(view)
    }

    pub fn write(&self) -> Result<DataWrite<'_>> {
        self.check()?;
        let writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        let view = self.view()?;
        let revision = view.revision.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "revision exhausted",
            }
            .build()
        })?;
        let transaction = self.branch.write_tx().context(NativeStorageSnafu {
            operation: "begin Data write",
        })?;
        let stored = transaction
            .get(HEAD)
            .context(NativeStorageSnafu {
                operation: "check Data head",
            })?
            .ok_or_else(|| NativeStateSnafu { field: "Data head" }.build())?;
        if Self::number(&stored)? != view.metadata_revision {
            return NativeStateSnafu {
                field: "unpublished Data write",
            }
            .fail();
        }
        Ok(DataWrite {
            store: self,
            revision,
            transaction,
            raw: view.raw.clone(),
            graphs: view.graphs.clone(),
            contexts: view.contexts.clone(),
            metadata_revision: view.metadata_revision,
            dirty: false,
            verified: super::context::VerifiedPackages::default(),
            _writer: writer,
        })
    }

    pub fn database(&self) -> &SingleWriterTxDatabase {
        &self.database
    }

    pub fn branch(&self) -> &Branch {
        &self.branch
    }
}

impl<'a> DataWrite<'a> {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn native(&mut self) -> &mut BranchWriteTransaction<'a> {
        self.dirty = true;
        &mut self.transaction
    }

    pub fn rollback(self) {
        self.transaction.rollback();
    }

    pub fn commit(self, stamps: impl IntoIterator<Item = Vec<u8>>) -> Result<Option<Commit>> {
        self.commit_published(stamps, || {})
    }

    fn commit_published(
        mut self,
        stamps: impl IntoIterator<Item = Vec<u8>>,
        published: impl FnOnce(),
    ) -> Result<Option<Commit>> {
        let stamps = stamps.into_iter().collect::<Vec<_>>();
        if !self.dirty && stamps.is_empty() {
            return Ok(None);
        }
        self.checkpoint_inputs()?;
        self.stage_raw()?;
        self.transaction.insert(HEAD, self.revision.to_be_bytes());
        let stamps = stamps.into_iter().chain([NativeStore::cut(self.revision)]);
        let committed = self.transaction.commit_stamped(stamps);
        let receipt = match committed {
            Ok(Some(receipt)) => receipt,
            Ok(None) => {
                return NativeStateSnafu {
                    field: "empty Data commit",
                }
                .fail()
            }
            Err(source) => {
                self.store.ready.store(false, Ordering::Release);
                return Err(source).context(NativeStorageSnafu {
                    operation: "commit Data write",
                });
            }
        };
        let visible = (|| {
            let snapshot =
                self.store
                    .branch
                    .read_at(receipt.revision)
                    .context(NativeStorageSnafu {
                        operation: "capture committed cut",
                    })?;
            let mut view = NativeStore::decode_view(snapshot)?;
            if view.revision != self.revision {
                return NativeStateSnafu {
                    field: "committed Data revision",
                }
                .fail();
            }
            view.raw = self.raw;
            view.graphs = self.graphs;
            view.contexts = self.contexts;
            self.store
                .raw
                .lock()
                .map_err(|_| {
                    NativeStateSnafu {
                        field: "raw owner lock",
                    }
                    .build()
                })?
                .index = view.raw.clone();
            *self.store.published.write().map_err(|_| {
                NativeStateSnafu {
                    field: "publication lock",
                }
                .build()
            })? = Arc::new(view);
            Ok(())
        })();
        if let Err(error) = visible {
            self.store.ready.store(false, Ordering::Release);
            return Err(error);
        }
        published();
        self.store.revision.send_replace(self.revision);
        Ok(Some(receipt))
    }
}
