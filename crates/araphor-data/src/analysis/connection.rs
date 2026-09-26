use std::ops::{Deref, DerefMut};
use std::sync::{atomic::Ordering, MutexGuard, RwLockReadGuard, TryLockError};

use duckdb::Connection;
use tokio::sync::SemaphorePermit;

use super::AnalysisStore;
use crate::{AnalysisBusySnafu, Result};

pub(super) struct AnalysisConnection<'a> {
    connection: MutexGuard<'a, Connection>,
    _snapshot: Option<RwLockReadGuard<'a, ()>>,
    _permit: SemaphorePermit<'a>,
}

impl Deref for AnalysisConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl DerefMut for AnalysisConnection<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

impl AnalysisStore {
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
            let snapshot = reader.transaction()?;
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
