use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{atomic::Ordering, TryLockError};

use super::read::locks::{MutexGuard, ReadGuard};

use duckdb::{AccessMode, Config, Connection};
use snafu::ResultExt as _;
use tokio::sync::OwnedSemaphorePermit;

use super::{AnalysisReadControl, AnalysisStore, StorageLimitsV1};
use crate::{AnalysisBusySnafu, AnalysisDatabaseSnafu, AnalysisStateSnafu, IoSnafu, Result};

pub(super) struct AnalysisLease {
    file: std::fs::File,
    process_id: u32,
}

impl AnalysisLease {
    pub(super) fn acquire(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return AnalysisStore::reject_path(root, "the analysis path is not absolute");
        }
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: root }),
        }
        let metadata = fs::symlink_metadata(root).context(IoSnafu { path: root })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStore::reject_path(root, "the analysis directory is not private");
        }
        let filesystem = rustix::fs::statfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        if !matches!(filesystem.f_type, 0xef53 | 0x0102_1994) {
            return AnalysisStore::reject_path(root, "the analysis filesystem is not qualified");
        }
        let path = root.join("analysis.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        let metadata = file.metadata().context(IoSnafu { path: &path })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStore::reject_path(&path, "the analysis lease file is not private");
        }
        file.try_lock().map_err(|error| {
            AnalysisStateSnafu {
                path: root,
                reason: format!("the analysis writer is already owned: {error}"),
            }
            .build()
        })?;
        Ok(Self::from(file))
    }
}

impl From<std::fs::File> for AnalysisLease {
    fn from(file: std::fs::File) -> Self {
        Self {
            file,
            process_id: std::process::id(),
        }
    }
}

impl Drop for AnalysisLease {
    fn drop(&mut self) {
        // A child descriptor must not retain or release the parent's lease.
        if self.process_id == std::process::id() {
            let _result = self.file.unlock();
        }
    }
}

pub(super) struct AnalysisConnection<'a> {
    pub(super) connection: MutexGuard<'a, Option<Connection>>,
    pub(super) monitor: Option<&'a super::read::ReadMonitor>,
    root: &'a Path,
    dirty: Option<&'a std::sync::atomic::AtomicBool>,
    _snapshot: Option<ReadGuard<'a, ()>>,
    _permit: Option<ReadPermit>,
}

pub(crate) struct ReadPermit {
    permit: Option<OwnedSemaphorePermit>,
    capacity: tokio::sync::watch::Sender<()>,
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.capacity.send_replace(());
    }
}

impl AnalysisConnection<'_> {
    pub(super) fn get(&self) -> Result<&Connection> {
        self.connection.as_ref().ok_or_else(|| {
            AnalysisStateSnafu {
                path: self.root,
                reason: "the analysis connections are closed",
            }
            .build()
        })
    }

    pub(super) fn get_mut(&mut self) -> Result<&mut Connection> {
        if let Some(dirty) = self.dirty {
            dirty.store(true, Ordering::Release);
        }
        self.connection.as_mut().ok_or_else(|| {
            AnalysisStateSnafu {
                path: self.root,
                reason: "the analysis connections are closed",
            }
            .build()
        })
    }
}

impl AnalysisStore {
    pub fn recover(&self) -> Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| self.state_error("the analysis writer lock is poisoned"))?;
        let _maintenance = self
            .maintenance
            .write()
            .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?;
        self.write_ready.store(false, Ordering::Release);
        let mut readers = [
            self.readers[0]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
            self.readers[1]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
        ];
        for reader in &mut readers {
            drop(reader.take());
        }
        drop(writer.take());
        let path = self.root.join("analysis.duckdb");
        let file = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        if !file.is_file() || file.permissions().mode() & 0o077 != 0 {
            return self.reject("the analysis database file is not private");
        }
        let mut connection = Self::open_native(&path, self.storage, AccessMode::Automatic)?;
        let meta = Self::read_meta_from(&connection, &path)?;
        if meta.schema_version != super::ANALYSIS_SCHEMA_VERSION as u32
            || meta.store_uuid != self.store_uuid
        {
            return self.reject("the recovered database differs from the active store");
        }
        Self::validate_tables(&connection)?;
        Self::validate_state(&connection, &self.root)?;
        let raw = Self::recover_segments(&mut connection, &self.root, self.retention)?;
        let meta = Self::read_meta_from(&connection, &path)?;
        if meta.commit_revision < *self.revision.borrow() {
            return self.reject("the recovered store lost an accepted revision");
        }
        *self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))? = raw;
        self.raw_dirty.store(false, Ordering::Release);
        self.raw_pending.store(false, Ordering::Release);
        let first = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "recover first trusted reader",
        })?;
        let second = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "recover second trusted reader",
        })?;
        *readers[0] = Some(first);
        *readers[1] = Some(second);
        *writer = Some(connection);
        let recovered = *self.revision.borrow() != meta.commit_revision;
        self.write_ready.store(true, Ordering::Release);
        self.revision.send_replace(meta.commit_revision);
        if recovered {
            self.activations.send_replace(meta.commit_revision);
        }
        Ok(())
    }

    pub(super) fn commit_metadata(
        &self,
        transaction: duckdb::Transaction<'_>,
        operation: &'static str,
    ) -> Result<()> {
        self.write_ready.store(false, Ordering::Release);
        transaction
            .commit()
            .context(AnalysisDatabaseSnafu { operation })?;
        self.write_ready.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn open_native(
        path: &Path,
        storage: StorageLimitsV1,
        access_mode: AccessMode,
    ) -> Result<Connection> {
        let readonly = access_mode == AccessMode::ReadOnly;
        let config = Config::default()
            .enable_autoload_extension(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable extension loading",
            })?
            .access_mode(access_mode)
            .and_then(|config| config.threads(2))
            .and_then(|config| config.with("wal_autocheckpoint", "16MiB"))
            .and_then(|config| {
                config.with(
                    "max_temp_directory_size",
                    storage
                        .native_temp_bytes
                        .map_or_else(|| "-1".to_owned(), |bytes| format!("{bytes}B")),
                )
            })
            .and_then(|config| config.with("allocator_bulk_deallocation_flush_threshold", "0B"))
            .context(AnalysisDatabaseSnafu {
                operation: "configure native data resources",
            })?;
        let config = if readonly {
            config.with("temp_directory", "")
        } else {
            Ok(config)
        }
        .context(AnalysisDatabaseSnafu {
            operation: "configure native temporary directory",
        })?;
        let config = config
            .enable_external_access(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable external access",
            })?;
        let config = if let Some(bytes) = storage.native_memory_bytes {
            config.max_memory(&format!("{bytes}B"))
        } else {
            Ok(config)
        }
        .context(AnalysisDatabaseSnafu {
            operation: "configure native memory limit",
        })?;
        let connection = Connection::open_with_flags(path, config)
            .context(AnalysisDatabaseSnafu { operation: "open" })?;
        if storage.native_memory_bytes.is_none() {
            // DuckDB replaces unlimited memory with its default during database startup.
            connection
                .execute_batch("SET memory_limit = '-1'")
                .context(AnalysisDatabaseSnafu {
                    operation: "disable native memory limit",
                })?;
        }
        Ok(connection)
    }

    pub(super) fn writer(&self) -> Result<AnalysisConnection<'_>> {
        let connection = self.writer_access()?;
        self.require_capacity(false)?;
        Ok(connection)
    }

    pub(super) fn maintenance_writer(&self) -> Result<AnalysisConnection<'_>> {
        let connection = self.writer_access()?;
        self.require_capacity(true)?;
        Ok(connection)
    }

    pub(super) fn writer_access(&self) -> Result<AnalysisConnection<'_>> {
        self.writer_wait(None, true)
    }

    pub(super) fn raw_access(&self) -> Result<AnalysisConnection<'_>> {
        self.writer_wait(None, false)
    }

    pub(super) fn raw_coordinator(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisConnection<'_>> {
        self.writer_wait(Some(control), false)
    }

    pub(super) fn read_coordinator(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisConnection<'_>> {
        self.writer_wait(Some(control), true)
    }

    pub(super) fn project_raw(
        &self,
        writer: &mut Connection,
        raw: &mut super::raw::RawJournal,
        control: Option<&AnalysisReadControl>,
    ) -> Result<()> {
        if self.raw_pending.load(Ordering::Acquire) {
            self.write_ready.store(false, Ordering::Release);
            let result = raw.project(writer, control);
            if matches!(
                &result,
                Err(crate::Error::AnalysisReadDeadline { .. }
                    | crate::Error::AnalysisReadCancelled { .. })
            ) {
                self.write_ready.store(true, Ordering::Release);
            }
            result?;
            self.raw_pending.store(false, Ordering::Release);
            self.write_ready.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn writer_wait(
        &self,
        control: Option<&AnalysisReadControl>,
        project: bool,
    ) -> Result<AnalysisConnection<'_>> {
        let mut connection = match control {
            Some(control) => self.writer.until(control)?,
            None => self
                .writer
                .lock()
                .map_err(|_| self.state_error("the analysis writer lock is poisoned"))?,
        };
        if !self.write_ready.load(Ordering::Acquire) {
            return self.reject("the data writer requires catalog recovery before retry");
        }
        let mut raw = match control {
            Some(control) => self.raw.until(control)?,
            None => self
                .raw
                .lock()
                .map_err(|_| self.state_error("the raw owner lock is poisoned"))?,
        };
        let writer = connection
            .as_mut()
            .ok_or_else(|| self.state_error("the analysis connections are closed"))?;
        if project {
            self.project_raw(writer, &mut raw, control)?;
        }
        if !project && self.raw_dirty.load(Ordering::Acquire) {
            raw.refresh_budget(writer, self.retention)?;
            self.raw_dirty.store(false, Ordering::Release);
        }
        drop(raw);
        Ok(AnalysisConnection {
            connection,
            monitor: None,
            root: &self.root,
            dirty: Some(&self.raw_dirty),
            _snapshot: None,
            _permit: None,
        })
    }

    #[cfg(test)]
    pub(super) fn reader(&self) -> Result<AnalysisConnection<'_>> {
        self.reader_wait(None, self.reserve_reader()?)
    }

    pub(super) fn reader_until(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisConnection<'_>> {
        self.reader_wait(Some(control), self.reserve_reader()?)
    }

    pub(crate) fn reserve_reader(&self) -> Result<ReadPermit> {
        if self.storage.reader_admissions == Some(0) {
            return crate::StorageCapacitySnafu {
                resource: "reader admissions",
            }
            .fail();
        }
        let permit = self
            .read_slots
            .as_ref()
            .map(|slots| {
                slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| AnalysisBusySnafu { resource: "reader" }.build())
            })
            .transpose()?;
        Ok(ReadPermit {
            permit,
            capacity: self.capacity.clone(),
        })
    }

    pub async fn wait_capacity(&self) -> Result<()> {
        let mut capacity = self.subscribe_capacity();
        loop {
            capacity.borrow_and_update();
            match self.reserve_reader() {
                Ok(permit) => {
                    drop(permit);
                    return Ok(());
                }
                Err(crate::Error::AnalysisBusy {
                    resource: "reader", ..
                }) => {}
                Err(error) => return Err(error),
            }
            capacity
                .changed()
                .await
                .map_err(|_| self.state_error("the reader capacity channel is closed"))?;
        }
    }

    pub(super) fn reader_wait(
        &self,
        control: Option<&AnalysisReadControl>,
        permit: ReadPermit,
    ) -> Result<AnalysisConnection<'_>> {
        if self.raw_pending.load(Ordering::Acquire) {
            drop(self.writer_wait(control, true)?);
        }
        let snapshot = match control {
            Some(control) => self.maintenance.read_until(control)?,
            None => self
                .maintenance
                .read()
                .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?,
        };
        let first = self.read_next.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        for index in 0..self.readers.len() {
            match self.readers[(first + index) % self.readers.len()].try_lock() {
                Ok(connection) => {
                    return Ok(AnalysisConnection {
                        connection,
                        monitor: Some(&self.read_monitors[(first + index) % self.readers.len()]),
                        root: &self.root,
                        dirty: None,
                        _snapshot: Some(snapshot),
                        _permit: Some(permit),
                    });
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => {
                    return Err(self.state_error("the analysis reader lock is poisoned"));
                }
            }
        }
        // ponytail: a queued read keeps its selected reader. Use a shared queue if measurements show imbalance.
        let connection = match control {
            Some(control) => self.readers[first].until(control)?,
            None => self.readers[first]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
        };
        Ok(AnalysisConnection {
            connection,
            monitor: Some(&self.read_monitors[first]),
            root: &self.root,
            dirty: None,
            _snapshot: Some(snapshot),
            _permit: Some(permit),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::*;
    use crate::{
        EvidenceIntakeIdentityV1, EvidenceRetentionOwner, RetentionLimitsV1,
        ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn identity() -> EvidenceIntakeIdentityV1 {
        crate::analysis::tests::identity()
    }

    fn batch(cursor: u64) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: cursor * 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        }
    }

    #[test]
    fn reader_release_wakes_capacity() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("store"),
            Default::default(),
            crate::StorageLimitsV1 {
                reader_admissions: Some(16),
                ..Default::default()
            },
        )?;
        let identity = identity();
        store.accept_validated_batch(identity.clone(), batch(1))?;
        store.meta()?;
        let mut capacity = store.subscribe_capacity();
        let mut permits = (0..16)
            .map(|_| store.reserve_trace_read())
            .collect::<crate::Result<Vec<_>>>()?;
        assert!(matches!(
            store.reserve_trace_read(),
            Err(crate::Error::AnalysisBusy { .. })
        ));
        assert!(!capacity.has_changed()?);
        drop(permits.pop());
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits(),
            1
        );
        assert!(capacity.has_changed()?);
        capacity.borrow_and_update();
        let reader =
            store.reader_until(&AnalysisReadControl::with_timeout(Duration::from_secs(30))?)?;
        assert!(!capacity.has_changed()?);
        drop(reader);
        assert!(capacity.has_changed()?);
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits(),
            1
        );
        drop(permits);
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits(),
            16
        );
        capacity.borrow_and_update();
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        assert!(capacity.has_changed()?);
        Ok(())
    }

    #[tokio::test]
    async fn capacity_checks_reader_gate() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("store"),
            Default::default(),
            crate::StorageLimitsV1 {
                reader_admissions: Some(16),
                ..Default::default()
            },
        )?;
        let mut permits = (0..16)
            .map(|_| store.reserve_trace_read())
            .collect::<crate::Result<Vec<_>>>()?;
        let wait = store.wait_capacity();
        tokio::pin!(wait);
        assert!(futures_util::poll!(&mut wait).is_pending());
        store.capacity.send_replace(());
        assert!(futures_util::poll!(&mut wait).is_pending());
        drop(permits.pop());
        tokio::time::timeout(Duration::from_secs(1), wait).await??;
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits(),
            1
        );
        drop(permits);
        store.wait_capacity().await?;
        Ok(())
    }

    #[test]
    fn reader_default_admits_queue() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        assert!(store.read_slots.is_none());
        assert_eq!(store.readers.len(), 2);
        let held = store
            .maintenance
            .write()
            .map_err(|_| "maintenance poisoned")?;
        let (entered, observed) = mpsc::channel();
        let controls = (0..17)
            .map(|_| {
                let control = AnalysisReadControl::default();
                *control
                    .wait_signal
                    .lock()
                    .map_err(|_| "wait signal poisoned")? = Some(entered.clone());
                Ok(std::sync::Arc::new(control))
            })
            .collect::<std::result::Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        thread::scope(|scope| -> TestResult {
            let mut workers: Vec<_> = controls
                .iter()
                .map(|control| {
                    let control = std::sync::Arc::clone(control);
                    let store = &store;
                    scope.spawn(move || -> Result<i64> {
                        let reader = store.reader_until(&control)?;
                        reader
                            .get()?
                            .query_row("SELECT 1", [], |row| row.get(0))
                            .context(AnalysisDatabaseSnafu {
                                operation: "test unbounded reader admission",
                            })
                    })
                })
                .collect();
            for _ in 0..17 {
                observed.recv_timeout(Duration::from_secs(5))?;
            }
            controls[0].cancel()?;
            assert!(matches!(
                workers.remove(0).join().map_err(|_| "reader panicked")?,
                Err(crate::Error::AnalysisReadCancelled { .. })
            ));
            drop(held);
            for worker in workers {
                assert_eq!(worker.join().map_err(|_| "reader panicked")??, 1);
            }
            Ok(())
        })?;
        store.meta()?;
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn reader_zero_rejects_reads() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(
            &root,
            Default::default(),
            StorageLimitsV1 {
                reader_admissions: Some(0),
                ..Default::default()
            },
        )?;
        assert!(matches!(
            store.reserve_reader(),
            Err(crate::Error::StorageCapacity {
                resource: "reader admissions",
                ..
            })
        ));
        assert!(matches!(
            store.meta(),
            Err(crate::Error::StorageCapacity {
                resource: "reader admissions",
                ..
            })
        ));
        assert!(matches!(
            store.wait_capacity().await,
            Err(crate::Error::StorageCapacity {
                resource: "reader admissions",
                ..
            })
        ));
        store.accept_validated_batch(identity(), batch(1))?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert!(store.read_slots.is_none());
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_lease_release() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let duplicate = store._lease.file.try_clone()?;
        let mut inherited = AnalysisLease::from(store._lease.file.try_clone()?);
        inherited.process_id = std::process::id().wrapping_add(1);
        drop(inherited);
        assert!(AnalysisStore::open(&root).is_err());
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        drop(duplicate);
        assert!(AnalysisStore::open(&root).is_err());
        drop(reopened);
        drop(AnalysisStore::open(root)?);
        Ok(())
    }

    #[test]
    fn analysis_store_uncertain_commit() -> TestResult {
        for applied in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open(&root)?;
            let notice = store.subscribe_revision();
            let mut writer = store.writer()?;
            let transaction = writer.get_mut()?.transaction()?;
            transaction.execute("UPDATE store_meta SET next_segment_id = 2", [])?;
            AnalysisStore::record_revision(&transaction, 1, &["events"])?;
            transaction.execute_batch(if applied { "COMMIT" } else { "ROLLBACK" })?;
            assert!(store
                .commit_metadata(transaction, "test uncertain commit")
                .is_err());
            drop(writer);
            assert!(store.writer().is_err());
            assert!(store.maintenance_writer().is_err());
            assert!(store.accept_validated_batch(identity(), batch(1)).is_err());
            assert!(!store.storage_health()?.write_ready);
            assert!(!notice.has_changed()?);
            store.recover()?;
            assert!(store.storage_health()?.write_ready);
            assert!(notice.has_changed()?);
            assert_eq!(*notice.borrow(), u64::from(applied));
            let next: u64 = store.reader()?.get()?.query_row(
                "SELECT next_segment_id FROM store_meta",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(next, if applied { 2 } else { 1 });
            store.accept_validated_batch(identity(), batch(1))?;
            assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn analysis_recovery_rejects_corruption() -> TestResult {
        use std::os::unix::fs::FileExt as _;
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let notice = store.subscribe_revision();
        let path = super::super::segments::SegmentRange::path(&root, 1);
        let file = OpenOptions::new().write(true).open(&path)?;
        file.write_all_at(b"wrong", file.metadata()?.len() - 5)?;
        file.sync_all()?;
        let bytes = fs::read(&path)?;
        for _ in 0..2 {
            assert!(store.recover().is_err());
            assert!(!store.storage_health()?.write_ready);
            assert!(store.writer().is_err());
            assert!(store.read_page(&identity(), 1).is_err());
            assert!(AnalysisStore::open(&root).is_err());
            assert_eq!(fs::read(&path)?, bytes);
            assert!(!notice.has_changed()?);
        }
        Ok(())
    }

    #[test]
    fn analysis_store_admission_bounds() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            StorageLimitsV1 {
                reader_admissions: Some(16),
                ..Default::default()
            },
        )?;
        let held = store.writer()?;
        thread::scope(|scope| -> TestResult {
            let store = &store;
            let (started, entering) = mpsc::channel();
            let (finished, completed) = mpsc::channel();
            let queued: Vec<_> = (0..12)
                .map(|_| {
                    let started = started.clone();
                    let finished = finished.clone();
                    scope.spawn(move || {
                        let _result = started.send(());
                        let result = store.writer().map(|_| ());
                        let _result = finished.send(());
                        result
                    })
                })
                .collect();
            for _ in 0..12 {
                entering.recv_timeout(Duration::from_secs(5))?;
            }
            assert!(matches!(
                completed.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            assert_eq!(store.meta()?.commit_revision, 0);
            drop(held);
            for worker in queued {
                worker.join().map_err(|_| "writer panicked")??;
            }
            Ok(())
        })?;
        let first = store.reader()?;
        let second = store.reader()?;
        thread::scope(|scope| -> TestResult {
            let queued: Vec<_> = (0..14)
                .map(|_| scope.spawn(|| store.reader().map(|_| ())))
                .collect();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits()
                != 0
            {
                if std::time::Instant::now() >= deadline {
                    drop((first, second));
                    return Err("readers did not enter admission".into());
                }
                thread::yield_now();
            }
            assert!(matches!(
                store.meta(),
                Err(crate::Error::AnalysisBusy {
                    resource: "reader",
                    ..
                })
            ));
            store.accept_validated_batch(identity(), batch(1))?;
            drop((first, second));
            for worker in queued {
                worker.join().map_err(|_| "reader panicked")??;
            }
            Ok(())
        })?;
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("configured reader admissions")?
                .available_permits(),
            16
        );
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_snapshot_maintenance() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(50),
            raw_max_bytes: Some(100),
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        store.accept_validated_batch(identity(), batch(1))?;
        let (sender, receiver) = mpsc::channel();
        thread::scope(|scope| -> TestResult {
            let mut reader = store.reader()?;
            let snapshot = reader.get_mut()?.transaction()?;
            assert_eq!(
                snapshot.query_row("SELECT COUNT(*) FROM segments", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            store.accept_validated_batch(identity(), batch(2))?;
            let owner = EvidenceRetentionOwner::new(&store);
            let worker = scope.spawn(move || {
                sender
                    .send(owner.retain(&identity(), 300))
                    .map_err(|_| "retention result lost")
            });
            let pending = receiver.recv_timeout(Duration::from_millis(50));
            assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
            assert_eq!(
                snapshot.query_row("SELECT COUNT(*) FROM segments", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            assert_eq!(
                snapshot.query_row("SELECT contiguous_cursor FROM source_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?,
                1
            );
            assert_eq!(
                snapshot.query_row("SELECT commit_revision FROM store_meta", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            let ranges = store.raw_ranges(&snapshot, &identity(), 1, 1, 1)?;
            assert_eq!(ranges[0].read(&store.root)?.len(), 1);
            drop(snapshot);
            drop(reader);
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(5))??
                    .removed_records,
                2
            );
            worker.join().map_err(|_| "retention panicked")??;
            Ok(())
        })?;
        store.checkpoint()?;
        assert_eq!(store.meta()?.commit_revision, 3);
        drop(store);
        let reopened = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        assert!(matches!(
            reopened.read_page(&identity(), 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        Ok(())
    }
}
