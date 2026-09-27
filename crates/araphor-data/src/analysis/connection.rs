use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{atomic::Ordering, MutexGuard, RwLockReadGuard, TryLockError};

use duckdb::{Config, Connection};
use snafu::ResultExt as _;
use tokio::sync::SemaphorePermit;

use super::{AnalysisReadControl, AnalysisStore};
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
    root: &'a Path,
    _snapshot: Option<RwLockReadGuard<'a, ()>>,
    _permit: SemaphorePermit<'a>,
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
        let _permit = self
            .write_slots
            .try_acquire()
            .map_err(|_| AnalysisBusySnafu { resource: "writer" }.build())?;
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
        let mut connection = Self::open_native(&path)?;
        let meta = Self::read_meta_from(&connection, &path)?;
        if meta.schema_version != super::ANALYSIS_SCHEMA_VERSION as u32
            || meta.store_uuid != self.store_uuid
            || meta.commit_revision < *self.revision.borrow()
        {
            return self.reject("the recovered database differs from the active store");
        }
        Self::validate_tables(&connection)?;
        Self::validate_state(&connection, &self.root)?;
        Self::recover_segments(&mut connection, &self.root)?;
        let first = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "recover first trusted reader",
        })?;
        let second = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "recover second trusted reader",
        })?;
        *readers[0] = Some(first);
        *readers[1] = Some(second);
        *writer = Some(connection);
        self.revision.send_if_modified(|revision| {
            let changed = *revision != meta.commit_revision;
            *revision = meta.commit_revision;
            changed
        });
        self.write_ready.store(true, Ordering::Release);
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

    pub(super) fn open_native(path: &Path) -> Result<Connection> {
        let config = Config::default()
            .enable_autoload_extension(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable extension loading",
            })?
            .enable_external_access(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable external access",
            })?
            .max_memory("64MiB")
            .and_then(|config| config.threads(2))
            .and_then(|config| config.with("wal_autocheckpoint", "16MiB"))
            .and_then(|config| config.with("max_temp_directory_size", "128MiB"))
            .and_then(|config| config.with("allocator_bulk_deallocation_flush_threshold", "0B"))
            .context(AnalysisDatabaseSnafu {
                operation: "bound native data resources",
            })?;
        Connection::open_with_flags(path, config)
            .context(AnalysisDatabaseSnafu { operation: "open" })
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
        self.writer_wait(None)
    }

    pub(super) fn read_coordinator(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisConnection<'_>> {
        self.writer_wait(Some(control))
    }

    fn writer_wait(&self, control: Option<&AnalysisReadControl>) -> Result<AnalysisConnection<'_>> {
        let permit = self
            .write_slots
            .try_acquire()
            .map_err(|_| AnalysisBusySnafu { resource: "writer" }.build())?;
        let connection = match control {
            Some(control) => control.lock(|| self.writer.try_lock())?,
            None => self
                .writer
                .lock()
                .map_err(|_| self.state_error("the analysis writer lock is poisoned"))?,
        };
        if !self.write_ready.load(Ordering::Acquire) {
            return self.reject("the data writer requires catalog recovery before retry");
        }
        Ok(AnalysisConnection {
            connection,
            root: &self.root,
            _snapshot: None,
            _permit: permit,
        })
    }

    #[cfg(test)]
    pub(super) fn reader(&self) -> Result<AnalysisConnection<'_>> {
        self.reader_wait(None)
    }

    pub(super) fn reader_until(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisConnection<'_>> {
        self.reader_wait(Some(control))
    }

    fn reader_wait(&self, control: Option<&AnalysisReadControl>) -> Result<AnalysisConnection<'_>> {
        let permit = self
            .read_slots
            .try_acquire()
            .map_err(|_| AnalysisBusySnafu { resource: "reader" }.build())?;
        let snapshot = match control {
            Some(control) => control.lock(|| self.maintenance.try_read())?,
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
                        root: &self.root,
                        _snapshot: Some(snapshot),
                        _permit: permit,
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
            Some(control) => control.lock(|| self.readers[first].try_lock())?,
            None => self.readers[first]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
        };
        Ok(AnalysisConnection {
            connection,
            root: &self.root,
            _snapshot: Some(snapshot),
            _permit: permit,
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
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
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
            assert_eq!(notice.has_changed()?, applied);
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
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let held = store.writer()?;
        thread::scope(|scope| -> TestResult {
            let queued: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| store.writer().map(|_| ())))
                .collect();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while store.write_slots.available_permits() != 0 {
                if std::time::Instant::now() >= deadline {
                    drop(held);
                    return Err("writers did not enter admission".into());
                }
                thread::yield_now();
            }
            assert!(matches!(
                store.accept_validated_batch(identity(), batch(1)),
                Err(crate::Error::AnalysisBusy {
                    resource: "writer",
                    ..
                })
            ));
            assert_eq!(store.meta()?.commit_revision, 0);
            drop(held);
            for worker in queued {
                worker.join().map_err(|_| "writer panicked")??;
            }
            Ok(())
        })?;
        assert_eq!(store.write_slots.available_permits(), 9);
        let first = store.reader()?;
        let second = store.reader()?;
        thread::scope(|scope| -> TestResult {
            let queued: Vec<_> = (0..14)
                .map(|_| scope.spawn(|| store.reader().map(|_| ())))
                .collect();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while store.read_slots.available_permits() != 0 {
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
        assert_eq!(store.read_slots.available_permits(), 16);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_snapshot_maintenance() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        store.accept_validated_batch(identity(), batch(1))?;
        let (sender, receiver) = mpsc::channel();
        thread::scope(|scope| -> TestResult {
            let mut reader = store.reader()?;
            let snapshot = reader.get_mut()?.transaction()?;
            assert_eq!(
                snapshot.query_row("SELECT COUNT(*) FROM batch_ranges", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            store.accept_validated_batch(identity(), batch(2))?;
            let owner = EvidenceRetentionOwner::new(
                &store,
                RetentionLimitsV1 {
                    raw_max_age_ns: 50,
                    raw_max_bytes: 100,
                },
            )?;
            let worker = scope.spawn(move || {
                sender
                    .send(owner.retain(&identity(), 300))
                    .map_err(|_| "retention result lost")
            });
            let pending = receiver.recv_timeout(Duration::from_millis(50));
            assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
            assert_eq!(
                snapshot.query_row("SELECT COUNT(*) FROM batch_ranges", [], |row| row
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
                snapshot.query_row("SELECT first_cursor FROM batch_ranges", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            let ranges = AnalysisStore::raw_ranges(&snapshot, &identity(), 1, 1, 1)?;
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
        let reopened = AnalysisStore::open(directory.path().join("analysis"))?;
        assert!(matches!(
            reopened.read_page(&identity(), 2),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        Ok(())
    }
}
