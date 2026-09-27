use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, TryLockError, TryLockResult,
};
use std::time::{Duration, Instant};

use duckdb::{params, OptionalExt as _};
use snafu::ResultExt as _;

use super::{
    source_key, valid_source_identity, AnalysisReadPageV1, AnalysisStore, MAX_ANALYSIS_PAGE_BYTES,
    MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result, RetainedRangeExpiredSnafu};

/// One snapshot deadline and cancellation flag. The deadline is one second.
pub struct AnalysisReadControl {
    deadline: Instant,
    cancelled: AtomicBool,
    interrupt: Mutex<Option<Arc<duckdb::InterruptHandle>>>,
}

impl Default for AnalysisReadControl {
    fn default() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: AtomicBool::new(false),
            interrupt: Mutex::new(None),
        }
    }
}

impl AnalysisReadControl {
    pub fn cancel(&self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        if let Some(interrupt) = self
            .interrupt
            .lock()
            .map_err(|_| Self::lock_error())?
            .as_ref()
        {
            interrupt.interrupt();
        }
        Ok(())
    }

    pub(super) fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return crate::AnalysisReadCancelledSnafu.fail();
        }
        if Instant::now() >= self.deadline {
            return crate::AnalysisReadDeadlineSnafu.fail();
        }
        Ok(())
    }

    pub(super) fn lock<T>(&self, mut acquire: impl FnMut() -> TryLockResult<T>) -> Result<T> {
        loop {
            self.check()?;
            match acquire() {
                Ok(guard) => {
                    self.check()?;
                    return Ok(guard);
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
                Err(TryLockError::Poisoned(_)) => return Err(Self::lock_error()),
            }
        }
    }

    fn lock_error() -> crate::Error {
        crate::AnalysisStateSnafu {
            path: std::path::Path::new("<analysis-read>"),
            reason: "the read lock is poisoned",
        }
        .build()
    }

    fn run<T>(
        &self,
        interrupt: Arc<duckdb::InterruptHandle>,
        read: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.check()?;
        let mut slot = self.interrupt.lock().map_err(|_| Self::lock_error())?;
        if slot.is_some() {
            return crate::AnalysisBusySnafu {
                resource: "read control",
            }
            .fail();
        }
        *slot = Some(interrupt.clone());
        drop(slot);
        let _guard = ReadInterrupt(self);
        self.check()?;
        let result = std::thread::scope(|scope| {
            let (stop, stopped) = std::sync::mpsc::channel::<()>();
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            std::thread::Builder::new()
                .name("analysis-read-deadline".into())
                .spawn_scoped(scope, move || {
                    let mut wait = remaining;
                    while matches!(
                        stopped.recv_timeout(wait),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ) {
                        interrupt.interrupt();
                        wait = Duration::from_millis(1);
                    }
                })
                .map_err(|error| {
                    crate::AnalysisStateSnafu {
                        path: std::path::Path::new("<analysis-read>"),
                        reason: format!("the read deadline worker could not start: {error}"),
                    }
                    .build()
                })?;
            let result = read();
            drop(stop);
            result
        });
        self.check()?;
        result
    }
}

struct ReadInterrupt<'a>(&'a AnalysisReadControl);

impl Drop for ReadInterrupt<'_> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.0.interrupt.lock() {
            *slot = None;
        }
    }
}

impl AnalysisStore {
    pub fn source_page(
        &self,
        tenant_id: [u8; 16],
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        if tenant_id == [0; 16]
            || after.is_some_and(|source| {
                source.tenant_id != tenant_id || !valid_source_identity(source)
            })
        {
            return self.reject("the source page tenant or cursor is invalid");
        }
        let after = after.map(source_key);
        let control = AnalysisReadControl::default();
        let reader_guard = self.reader_until(&control)?;
        let reader = reader_guard.get()?;
        control.run(reader.interrupt_handle(), || {
            let mut statement = reader
                .prepare(
                    "SELECT stream_key, identity_json FROM source_receipts
                 WHERE tenant_id = ? AND (CAST(? AS BLOB) IS NULL OR stream_key > ?)
                 ORDER BY stream_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare source page",
                })?;
            let rows = statement
                .query_map(
                    params![
                        tenant_id.as_slice(),
                        after.as_ref().map(|key| key.as_slice()),
                        after.as_ref().map(|key| key.as_slice()),
                        MAX_ANALYSIS_PAGE_RECORDS as u32,
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read source page",
                })?;
            let mut sources = Vec::new();
            for row in rows {
                control.check()?;
                let (key, json) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode source page",
                })?;
                let identity: EvidenceIntakeIdentityV1 =
                    serde_json::from_str(&json).context(crate::JsonSnafu { path: &self.root })?;
                if identity.tenant_id != tenant_id
                    || !valid_source_identity(&identity)
                    || source_key(&identity).as_slice() != key
                {
                    return self
                        .reject("the source page identity does not match its key or tenant");
                }
                sources.push(identity);
            }
            Ok(sources)
        })
    }

    pub fn read_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<AnalysisReadPageV1> {
        self.read_page_cancel(identity, first_cursor, &AnalysisReadControl::default())
    }

    pub fn read_page_cancel(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisReadPageV1> {
        control.check()?;
        let coordinator = self.read_coordinator(control)?;
        let mut reader_guard = self.reader_until(control)?;
        let reader = reader_guard.get_mut()?;
        control.run(reader.interrupt_handle(), || {
            let key = source_key(identity);
            let writer = reader.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin evidence snapshot",
            })?;
            let receipt = Self::read_receipt_from(&writer, &self.root, identity, &key)?
                .ok_or_else(|| self.state_error("the evidence source is absent"))?;
            if first_cursor == 0 || first_cursor > receipt.contiguous_cursor.saturating_add(1) {
                return self.reject("the evidence read cursor is outside the accepted range");
            }
            if first_cursor <= receipt.retained_floor {
                return RetainedRangeExpiredSnafu {
                    first_cursor,
                    last_cursor: receipt.retained_floor,
                }
                .fail();
            }
            self.check_expired(&writer, &key, identity, first_cursor)?;
            let expiry: Option<u64> = writer
                .query_row(
                    "SELECT MIN(first_cursor) FROM expired_ranges
             WHERE stream_key = ? AND tenant_id = ? AND first_cursor > ? AND first_cursor <= ?",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        first_cursor,
                        receipt.contiguous_cursor
                    ],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "bound read before expired input",
                })?;
            let page_end = expiry.map_or(receipt.contiguous_cursor, |cursor| cursor - 1);
            let read_revision =
                Self::read_meta_from(&writer, &self.root.join("analysis.duckdb"))?.commit_revision;
            let ranges = Self::raw_ranges(
                &writer,
                identity,
                first_cursor,
                page_end.min(first_cursor.saturating_add(MAX_ANALYSIS_PAGE_RECORDS as u64)),
                MAX_ANALYSIS_PAGE_RECORDS + 1,
            )?;
            // The reader guard prevents deletion until extraction ends.
            drop(coordinator);
            let mut records = Vec::new();
            let mut encoded_bytes = 0;
            let mut bounded = false;
            'ranges: for range in ranges {
                control.check()?;
                for record in range.read(&self.root)? {
                    control.check()?;
                    if record.cursor < first_cursor || record.cursor > page_end {
                        continue;
                    }
                    let expected = first_cursor
                        .checked_add(records.len() as u64)
                        .ok_or_else(|| self.state_error("the evidence read cursor is exhausted"))?;
                    if record.cursor != expected {
                        return self.expired_or_missing(&writer, &key, identity, expected);
                    }
                    if records.len() == MAX_ANALYSIS_PAGE_RECORDS {
                        bounded = true;
                        break 'ranges;
                    }
                    if encoded_bytes + record.framed_record.len() > MAX_ANALYSIS_PAGE_BYTES {
                        if records.is_empty() {
                            return self.reject("one evidence frame exceeds the read page bound");
                        }
                        bounded = true;
                        break 'ranges;
                    }
                    encoded_bytes += record.framed_record.len();
                    records.push(record);
                }
            }
            let next_cursor = first_cursor.checked_add(records.len() as u64);
            if let Some(next) = next_cursor.filter(|next| *next <= page_end && !bounded) {
                return self.expired_or_missing(&writer, &key, identity, next);
            }
            Ok(AnalysisReadPageV1 {
                first_cursor,
                records,
                encoded_bytes,
                next_cursor: next_cursor.filter(|next| *next <= receipt.contiguous_cursor),
                read_revision,
            })
        })
    }

    fn check_expired(
        &self,
        writer: &duckdb::Connection,
        key: &[u8; 32],
        identity: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> Result<()> {
        let last: Option<u64> = writer
            .query_row(
                "SELECT last_cursor FROM expired_ranges
                 WHERE stream_key = ? AND tenant_id = ?
                 AND first_cursor <= ? AND last_cursor >= ? LIMIT 1",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    cursor,
                    cursor
                ],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "classify missing evidence",
            })?;
        if let Some(last_cursor) = last {
            return RetainedRangeExpiredSnafu {
                first_cursor: cursor,
                last_cursor,
            }
            .fail();
        }
        Ok(())
    }

    fn expired_or_missing<T>(
        &self,
        writer: &duckdb::Connection,
        key: &[u8; 32],
        identity: &EvidenceIntakeIdentityV1,
        cursor: u64,
    ) -> Result<T> {
        self.check_expired(writer, key, identity, cursor)?;
        self.reject("the accepted evidence range has a missing record")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn analysis_read_lock_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "n".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        store.accept_validated_batch(
            identity.clone(),
            super::super::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        for held in 0..3 {
            let writer = (held == 0).then(|| store.writer()).transpose()?;
            let maintenance = (held == 1)
                .then(|| store.maintenance.write())
                .transpose()
                .map_err(|_| "maintenance poisoned")?;
            let readers = if held == 2 {
                Some([store.reader()?, store.reader()?])
            } else {
                None
            };
            let control = AnalysisReadControl {
                deadline: Instant::now() + Duration::from_millis(50),
                ..Default::default()
            };
            assert!(matches!(
                store.read_page_cancel(&identity, 1, &control),
                Err(crate::Error::AnalysisReadDeadline { .. })
            ));
            drop((writer, maintenance, readers));
            assert_eq!(store.write_slots.available_permits(), 9);
            assert_eq!(store.read_slots.available_permits(), 16);
            assert!(store.maintenance.try_write().is_ok());
            assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        }
        let control = AnalysisReadControl::default();
        assert_eq!(
            store
                .read_page_cancel(&identity, 1, &control)?
                .records
                .len(),
            1
        );
        assert!(control
            .interrupt
            .lock()
            .map_err(|_| "interrupt poisoned")?
            .is_none());
        control.cancel()?;
        assert!(matches!(
            store.read_page_cancel(&identity, 1, &control),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        let control = AnalysisReadControl::default();
        let writer = store.writer()?;
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| store.read_page_cancel(&identity, 1, &control));
            let deadline = Instant::now() + Duration::from_secs(2);
            while store.write_slots.available_permits() != 7 {
                if Instant::now() >= deadline {
                    return Err("read did not enter admission".into());
                }
                std::thread::yield_now();
            }
            control.cancel()?;
            assert!(matches!(
                waiting.join().map_err(|_| "read worker panicked")?,
                Err(crate::Error::AnalysisReadCancelled { .. })
            ));
            Ok(())
        })?;
        drop(writer);
        assert_eq!(store.write_slots.available_permits(), 9);
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_read_native_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let before = store.meta()?;
        let control = AnalysisReadControl {
            deadline: Instant::now() + Duration::from_millis(50),
            ..Default::default()
        };
        let mut reader = store.reader_until(&control)?;
        let connection = reader.get_mut()?;
        let started = Instant::now();
        let result = control.run(connection.interrupt_handle(), || {
            let snapshot = connection.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin deadline test",
            })?;
            snapshot
                .query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                    row.get::<_, i64>(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "test native deadline",
                })
        });
        assert!(
            matches!(result, Err(crate::Error::AnalysisReadDeadline { .. })),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(control
            .interrupt
            .lock()
            .map_err(|_| "interrupt poisoned")?
            .is_none());
        assert_eq!(
            connection.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?,
            1
        );
        drop(reader);
        assert!(store.maintenance.try_write().is_ok());
        assert_eq!(store.meta()?, before);
        store.checkpoint()?;
        Ok(())
    }

    #[test]
    fn analysis_store_source_pages() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        assert!(store.source_page(identity.tenant_id, None)?.is_empty());
        let mut expected = Vec::new();
        for index in 0..MAX_ANALYSIS_PAGE_RECORDS + 2 {
            let source = EvidenceIntakeIdentityV1 {
                source_epoch: index as u64 + 1,
                ..identity.clone()
            };
            store.accept_validated_coverage(crate::ValidatedCoverageV1 {
                identity: source.clone(),
                cpu_id: 0,
                revision: 1,
                encoded_report: vec![1],
            })?;
            expected.push(source);
        }
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [4; 16],
            ..identity.clone()
        };
        store.accept_validated_coverage(crate::ValidatedCoverageV1 {
            identity: foreign.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: vec![2],
        })?;
        expected.sort_by_key(source_key);
        let before = store.meta()?;
        let changed = store.subscribe_revision();
        let first = store.source_page(identity.tenant_id, None)?;
        assert_eq!(first, expected[..MAX_ANALYSIS_PAGE_RECORDS]);
        let second = store.source_page(identity.tenant_id, first.last())?;
        assert_eq!(second, expected[MAX_ANALYSIS_PAGE_RECORDS..]);
        assert!(store
            .source_page(identity.tenant_id, second.last())?
            .is_empty());
        assert_eq!(
            store.source_page(foreign.tenant_id, None)?,
            vec![foreign.clone()]
        );
        assert!(store
            .source_page(identity.tenant_id, Some(&foreign))
            .is_err());
        assert!(store.source_page([0; 16], None).is_err());
        assert_eq!(store.meta()?, before);
        assert!(!changed.has_changed()?);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.source_page(identity.tenant_id, None)?, first);
        assert_eq!(store.source_page(identity.tenant_id, first.last())?, second);
        Ok(())
    }
}
