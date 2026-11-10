//! Data owns original raw segments and versioned native transactions.

use std :: { ops :: Bound :: Included , path :: { Path , PathBuf } , sync :: { atomic :: { AtomicBool , AtomicUsize , Ordering } , Arc , Mutex , MutexGuard , RwLock } } ;

use fjall::{Branch, BranchSnapshot, BranchWriteTransaction, Commit, SingleWriterTxDatabase};
use snafu::ResultExt as _;
use uuid::Uuid;

use super :: { raw :: { RawIndex , RawJournal } , read :: locks :: { Mutex as RawMutex , RwLock as Maintenance } } ;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

const HEAD: &[u8] = b"\0data/head";
const IDENTITY: &[u8] = b"\0data/identity";
const FORMAT: &[u8] = b"\0data/format";
const SCHEMA: &[u8] = b"\0data/schema";
const RECOVERY: &[u8] = b"\0data/recovery";

mod admission;
mod capacity;
mod backup;
mod context;
mod extraction;
mod health;
#[cfg(any(test, feature = "test-fixtures"))]
mod fixtures;
#[cfg(any(test, feature = "test-fixtures"))]
pub use fixtures::StorageFault;
pub(in crate::analysis) mod inputs;
mod managed;
use managed::PublicationRead;
pub(in crate::analysis) use managed::FindingRead;
mod notification;
pub use notification::NotificationCapture;
mod packages;
mod progress;
mod records;
mod retention;
pub use retention::EvidenceRetentionOwner;
mod revisions;
mod source;
mod trace;
mod witnesses;
mod recovery;

pub use inputs::ActivationSubscription;
pub use managed :: { GraphPublication , ManagedCommit , ManagedGraph , ManagedGraphJournal , ManagedGraphTransaction , ManagedLease , ManagedReturn , PreparedManagedCommit } ;

pub struct NativeStore {
    database: SingleWriterTxDatabase,
    branch: Branch,
    writer: Mutex<()>,
    published: Arc<RwLock<Arc<DataView>>>,
    root: PathBuf,
    raw: RawMutex<RawJournal>,
    maintenance: Maintenance<()>,
    ready: Arc<AtomicBool>,
    retention_healthy: AtomicBool,
    managed_owner: AtomicBool,
    notification_owner: AtomicBool,
    discovery_owners: AtomicUsize,
    storage: crate::StorageLimitsV1,
    retention: crate::RetentionLimitsV1,
    read_slots: Option<Arc<tokio::sync::Semaphore>>,
    capacity: tokio::sync::watch::Sender<()>,
    revision: tokio::sync::watch::Sender<u64>,
    controls: tokio::sync::watch::Sender<()>,
    inputs: Arc<inputs::Coordinator>,
    #[cfg(any(test, feature = "test-fixtures"))]
    commit_hook: Mutex<Option<super::CommitHook>>,
    _lease: super::read::AnalysisLease,
}

#[derive(Clone)]
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
    trace_budget: Option<(u64, usize)>,
    processors: std::collections::BTreeMap<u64, (crate::EvidenceIntakeIdentityV1, Option<u64>)>,
    expiry: Vec<(u64, Vec<u8>, u64, u64)>,
    deletions: Vec<u64>,
    quotas: std::collections::BTreeSet<[u8; 16]>,
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
    pub fn table_schemas(
    ) -> &'static std::collections::BTreeMap<String, Arc<araphor_analysis_sdk::Schema>> {
        super::extraction::tables::Capture::schemas()
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(root, Default::default(), Default::default())
    }

    pub fn open_with_limits(
        root: impl AsRef<Path>,
        retention: crate::RetentionLimitsV1,
        storage: crate::StorageLimitsV1,
    ) -> Result<Self> {
        let root = root.as_ref();
        if !storage.valid()
            || storage
                .native_memory_bytes
                .is_some_and(|bytes| bytes < 1024 * 1024)
        {
            return crate::Error::reject_path(root, "the storage capacity limits are invalid");
        }
        let lease = super::read::AnalysisLease::acquire(root)?;
        Self::open_leased(root, retention, storage, lease, false)
    }

    fn open_leased(
        root: &Path,
        retention: crate::RetentionLimitsV1,
        storage: crate::StorageLimitsV1,
        lease: super::read::AnalysisLease,
        restoring: bool,
    ) -> Result<Self> {

        let pending = root.join("restore.pending");
        if !restoring { match std::fs::symlink_metadata(&pending) {
            Ok(_) => {
                return crate::Error::reject_path(
                    root,
                    "the analysis restore is incomplete; restore into a new directory",
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(source) => return Err(source).context(crate::IoSnafu { path: pending }),
        }
        }
        let legacy = root.join("analysis.duckdb");
        match std::fs::symlink_metadata(&legacy) {
            Ok(_) => {
                return NativeStateSnafu {
                    field: "store format",
                }
                .fail()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(source) => return Err(source).context(crate::IoSnafu { path: legacy }),
        }
        let mut builder = SingleWriterTxDatabase::builder(root.join("fjall")).versioned();
        if let Some(bytes) = storage.native_memory_bytes {
            let buffer = (bytes / 2).max(1024 * 1024);
            #[allow(deprecated)]
            {
                builder = builder
                    .cache_size(bytes - buffer)
                    .max_write_buffer_size(Some(buffer));
            }
        }
        let database = builder
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
            for entry in std::fs::read_dir(root).context(crate::IoSnafu { path: root })? {
                let name = entry.context(crate::IoSnafu { path: root })?.file_name();
                if name != "analysis.lock" && name != "fjall" {
                    return crate::Error::reject_path(
                        root,
                        "the analysis metadata is missing from a nonempty data directory",
                    );
                }
            }
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
            tx.insert(FORMAT, 10u64.to_be_bytes());
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
        let mut counts = capacity::RevisionCounts::default();
        let mut raw = Self::recover_raw(root, &view.snapshot, &mut counts, None)?;
        Self::restore_backlog(&mut raw, &view.snapshot, retention)?;
        view.revision = view.revision.max(raw.index.revision);
        view.raw = raw.index.clone();
        view.validate_recovery_ranges()?;
        view.validate_catalogue()?;
        view.validate_contexts(&mut counts)?;
        view.validate_managed()?;
        view.validate_attempts(&branch)?;
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
            retention_healthy: AtomicBool::new(true),
            managed_owner: AtomicBool::new(false),
            notification_owner: AtomicBool::new(false),
            discovery_owners: AtomicUsize::new(0),
            storage,
            retention,
            read_slots: storage
                .reader_admissions
                .map(|limit| Arc::new(tokio::sync::Semaphore::new(limit))),
            capacity: tokio::sync::watch::channel(()).0,
            revision,
            controls: tokio::sync::watch::channel(()).0,
            inputs,
            #[cfg(any(test, feature = "test-fixtures"))]
            commit_hook: Mutex::new(None),
            _lease: lease,
        };
        store.validate_progress_recovery(&mut counts)?;
        store.validate_result_recovery(&mut counts)?;
        store.validate_graph_recovery()?;
        store.validate_source_recovery()?;
        store.validate_trace_recovery()?;
        store.validate_counts(counts)?;
        if !restoring {
            store.recover_managed_startup()?;
        }
        Ok(store)
    }

    fn decode_view(snapshot: BranchSnapshot) -> Result<DataView> {
        if Self::number(&Self::required(&snapshot, FORMAT)?)? != 10 {
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
        if self.database.inner().is_poisoned() { self.poison(); }
        if !self.ready.load(Ordering::Acquire) {
            return NativeStateSnafu {
                field: "uncertain commit; reopen required",
            }
            .fail();
        }
        Ok(())
    }

    fn poison(&self) {
        if self.ready.swap(false, Ordering::AcqRel) {
            self.controls.send_replace(());
        }
    }

    pub fn subscribe_control(&self) -> tokio::sync::watch::Receiver<()> {
        self.controls.subscribe()
    }

    /// This hint can merge publications. Read committed state after each change.
    pub fn subscribe_revision(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn meta(&self) -> Result<crate::AnalysisStoreMetaV1> {
        self.view().map(|view| view.meta())
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
        let write = self.write_access()?;
        self.require_capacity(false)?;
        Ok(write)
    }

    fn maintenance_write(&self) -> Result<DataWrite<'_>> {
        let write = self.write_access()?;
        self.require_capacity(true)?;
        Ok(write)
    }

    fn write_access(&self) -> Result<DataWrite<'_>> {
        self.check()?;
        let writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        self.write_locked(writer)
    }

    fn write_locked<'a>(&'a self, writer: MutexGuard<'a, ()>) -> Result<DataWrite<'a>> {
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
            trace_budget: None,
            processors: Default::default(),
            expiry: Vec::new(),
            deletions: Vec::new(),
            quotas: Default::default(),
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
        self,
        stamps: impl IntoIterator<Item = Vec<u8>>,
        published: impl FnOnce(),
    ) -> Result<Option<Commit>> {
        self.commit_locked(stamps, published)
            .map(|(commit, _)| commit)
    }

    fn commit_locked(
        mut self,
        stamps: impl IntoIterator<Item = Vec<u8>>,
        published: impl FnOnce(),
    ) -> Result<(Option<Commit>, MutexGuard<'a, ()>)> {
        let stamps = stamps.into_iter().collect::<Vec<_>>();
        if !self.dirty && stamps.is_empty() {
            return Ok((None, self._writer));
        }
        self.check_revisions()?;
        {
            let raw = self.store.raw.lock().map_err(|_| NativeStateSnafu { field: "raw owner lock" }.build())?;
            self.deletions.extend(raw.budget.deletions.iter().copied());
        }
        for id in &self.deletions {
            self.transaction.remove(retention::ExpiredSegment::key(retention::ExpiredSegment::DELETING, *id));
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
                self.store.poison();
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
            let mut raw = self.store.raw.lock().map_err(|_| {
                NativeStateSnafu {
                    field: "raw owner lock",
                }
                .build()
            })?;
            raw.index = view.raw.clone();
            for (owner, (identity, floor)) in self.processors {
                raw.budget.set_required(owner, identity.key(), identity.tenant_id, floor);
            }
            for id in self.deletions { raw.budget.deletions.remove(&id); }
            for (id, key, first, last) in self.expiry {
                if let Some(segment) = raw.segments.get(&id) {
                    segment.live.store(false, Ordering::Release);
                }
                raw.budget.expired.insert((key, first), last);
            }
            if let Some((bytes, slots)) = self.trace_budget {
                raw.budget.trace_reserve = bytes;
                raw.budget.trace_slots = slots;
            }
            drop(raw);
            *self.store.published.write().map_err(|_| {
                NativeStateSnafu {
                    field: "publication lock",
                }
                .build()
            })? = Arc::new(view);
            Ok(())
        })();
        if let Err(error) = visible {
            self.store.poison();
            return Err(error);
        }
        published();
        self.store.revision.send_replace(self.revision);
        Ok((Some(receipt), self._writer))
    }
}
