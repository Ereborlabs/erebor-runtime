use std::path::Path;
use std::sync::{atomic::Ordering, MutexGuard, RwLockReadGuard, TryLockError};

use duckdb::{Config, Connection};
use snafu::ResultExt as _;
use tokio::sync::SemaphorePermit;

use super::AnalysisStore;
use crate::{AnalysisBusySnafu, AnalysisDatabaseSnafu, AnalysisStateSnafu, Result};

pub(super) struct AnalysisLease {
    file: std::fs::File,
    process_id: u32,
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
            .max_memory("128MiB")
            .and_then(|config| config.threads(2))
            .and_then(|config| config.with("wal_autocheckpoint", "64MiB"))
            .and_then(|config| config.with("max_temp_directory_size", "128MiB"))
            // Indexed raw tables need compaction too. Resource limits still apply.
            .and_then(|config| config.with("vacuum_rebuild_indexes", u64::MAX.to_string()))
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

    fn writer_access(&self) -> Result<AnalysisConnection<'_>> {
        let permit = self
            .write_slots
            .try_acquire()
            .map_err(|_| AnalysisBusySnafu { resource: "writer" }.build())?;
        let connection = self
            .writer
            .lock()
            .map_err(|_| self.state_error("the analysis writer lock is poisoned"))?;
        Ok(AnalysisConnection {
            connection,
            root: &self.root,
            _snapshot: None,
            _permit: permit,
        })
    }

    pub(super) fn reader(&self) -> Result<AnalysisConnection<'_>> {
        let permit = self
            .read_slots
            .try_acquire()
            .map_err(|_| AnalysisBusySnafu { resource: "reader" }.build())?;
        let snapshot = self
            .maintenance
            .read()
            .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?;
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
        let connection = self.readers[first]
            .lock()
            .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?;
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
                snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
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
            assert_eq!(owner.retain(&identity(), 200)?.removed_records, 1);
            assert_eq!(
                snapshot.query_row("SELECT COUNT(*) FROM events", [], |row| row
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
                snapshot.query_row("SELECT durable_cursor FROM events", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            assert_eq!(store.read_page(&identity(), 2)?.records[0].cursor, 2);
            let worker = scope.spawn(|| {
                sender
                    .send(store.checkpoint())
                    .map_err(|_| "checkpoint result lost")
            });
            let pending = receiver.recv_timeout(Duration::from_millis(50));
            drop(snapshot);
            drop(reader);
            assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
            receiver.recv_timeout(Duration::from_secs(5))??;
            worker.join().map_err(|_| "checkpoint panicked")??;
            Ok(())
        })?;
        assert_eq!(store.meta()?.commit_revision, 3);
        drop(store);
        let reopened = AnalysisStore::open(directory.path().join("analysis"))?;
        assert_eq!(reopened.read_page(&identity(), 2)?.records[0].cursor, 2);
        Ok(())
    }
}
