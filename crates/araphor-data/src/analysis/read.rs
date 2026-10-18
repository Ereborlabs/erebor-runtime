use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, TryLockError, TryLockResult,
};
use std::time::{Duration, Instant};

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::{AnalysisReadPageV1, AnalysisStore, MAX_ANALYSIS_PAGE_RECORDS};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result};

#[cfg(any(test, feature = "test-fixtures"))]
type ReadStep = Box<dyn FnOnce() -> Result<()> + Send>;

/// One deadline for a read stage and shared cancellation. The default is one second.
pub struct AnalysisReadControl {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    cancelled_event: Arc<tokio::sync::Notify>,
    interrupt: Arc<Mutex<Option<Arc<duckdb::InterruptHandle>>>>,
    monitor: Arc<ReadMonitor>,
    #[cfg(any(test, feature = "test-fixtures"))]
    read_step: Arc<Mutex<Option<ReadStep>>>,
    #[cfg(test)]
    pub(super) wait_signal: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl Default for AnalysisReadControl {
    fn default() -> Self {
        Self::monitored(Arc::new(ReadMonitor::default()))
    }
}

impl AnalysisReadControl {
    pub(super) fn monitored(monitor: Arc<ReadMonitor>) -> Self {
        Self::at(Instant::now() + Duration::from_secs(1), monitor)
    }

    fn at(deadline: Instant, monitor: Arc<ReadMonitor>) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
            cancelled_event: Arc::new(tokio::sync::Notify::new()),
            interrupt: Arc::new(Mutex::new(None)),
            monitor,
            #[cfg(any(test, feature = "test-fixtures"))]
            read_step: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            wait_signal: Mutex::new(None),
        }
    }

    fn timeout_deadline(timeout: Duration) -> Result<Instant> {
        Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: std::path::Path::new("<analysis-read>"),
                    reason: "the read timeout is zero or exceeds the clock range",
                }
                .build()
            })
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        Ok(Self::at(
            Self::timeout_deadline(timeout)?,
            Arc::new(ReadMonitor::default()),
        ))
    }

    fn child(&self, deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::clone(&self.cancelled),
            cancelled_event: Arc::clone(&self.cancelled_event),
            interrupt: Arc::clone(&self.interrupt),
            monitor: Arc::clone(&self.monitor),
            #[cfg(any(test, feature = "test-fixtures"))]
            read_step: Arc::clone(&self.read_step),
            #[cfg(test)]
            wait_signal: Mutex::new(None),
        }
    }

    pub fn stage(&self, timeout: Duration) -> Result<Self> {
        Ok(self.child(Self::timeout_deadline(timeout)?))
    }

    pub fn within(&self, timeout: impl Into<Option<Duration>>) -> Result<Self> {
        self.check()?;
        let deadline = match timeout.into() {
            Some(timeout) => Self::timeout_deadline(timeout)?.min(self.deadline),
            None => self.deadline,
        };
        Ok(self.child(deadline))
    }

    pub fn cancel(&self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        self.cancelled_event.notify_waiters();
        let state = self.interrupt.lock().map_err(|_| Self::lock_error())?;
        if let Some(interrupt) = state.as_ref() {
            interrupt.interrupt();
        }
        Ok(())
    }

    pub async fn cancelled(&self) {
        let cancelled = self.cancelled_event.notified();
        tokio::pin!(cancelled);
        let _registered = cancelled.as_mut().enable();
        if !self.cancelled.load(Ordering::Acquire) {
            cancelled.await;
        }
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn on_read_step(&self, hook: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
        *self.read_step.lock().map_err(|_| Self::lock_error())? = Some(Box::new(hook));
        Ok(())
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn test_read_step(&self) -> Result<()> {
        let hook = self
            .read_step
            .lock()
            .map_err(|_| Self::lock_error())?
            .take();
        if let Some(hook) = hook {
            hook()?;
        }
        Ok(())
    }

    #[track_caller]
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return crate::AnalysisReadCancelledSnafu.fail();
        }
        if Instant::now() >= self.deadline {
            return crate::AnalysisReadDeadlineSnafu.fail();
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<Duration> {
        self.check()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }

    pub(super) fn lock<T>(&self, mut acquire: impl FnMut() -> TryLockResult<T>) -> Result<T> {
        loop {
            self.check()?;
            match acquire() {
                Ok(guard) => {
                    self.check()?;
                    return Ok(guard);
                }
                Err(TryLockError::WouldBlock) => {
                    #[cfg(test)]
                    if let Some(signal) = self
                        .wait_signal
                        .lock()
                        .map_err(|_| Self::lock_error())?
                        .take()
                    {
                        let _sent = signal.send(());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
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

    #[track_caller]
    pub(super) fn run<T>(
        &self,
        reader: &mut super::connection::AnalysisConnection<'_>,
        read: impl FnOnce(&duckdb::Connection) -> Result<T>,
    ) -> Result<T> {
        self.check()?;
        let monitor = reader.monitor.unwrap_or(&self.monitor);
        let connection = reader.get_mut()?;
        let mut snapshot = None;
        let mut attempted = false;
        let result = self.native_run(monitor, connection.interrupt_handle(), || {
            attempted = true;
            let transaction = connection.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin read snapshot",
            })?;
            read(snapshot.insert(transaction))
        });
        // Both interrupt sources stop before rollback. Replace a failed native reader.
        let opened = snapshot.is_some();
        let cleanup = snapshot
            .map(duckdb::Transaction::rollback)
            .transpose()
            .context(AnalysisDatabaseSnafu {
                operation: "close read snapshot",
            });
        if cleanup.is_err() || (attempted && !opened && result.is_err()) {
            let replacement = reader.get()?.try_clone().context(AnalysisDatabaseSnafu {
                operation: "replace failed read connection",
            });
            drop(reader.connection.take());
            *reader.connection = Some(replacement?);
        }
        cleanup?;
        self.check()?;
        result
    }

    pub(crate) fn query_run<T>(
        &self,
        connection: &duckdb::Connection,
        query: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let result = self.native_run(&self.monitor, connection.interrupt_handle(), query);
        self.check()?;
        result
    }

    pub async fn query_async<T, E: From<crate::Error>>(
        &self,
        query: impl std::future::Future<Output = std::result::Result<T, E>>,
    ) -> std::result::Result<T, E> {
        let cancelled = self.cancelled_event.notified();
        tokio::pin!(cancelled);
        let _registered = cancelled.as_mut().enable();
        self.check()?;
        let result = tokio::select! {
            biased;
            _ = &mut cancelled => Err(crate::AnalysisReadCancelledSnafu.build().into()),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline)) => {
                Err(crate::AnalysisReadDeadlineSnafu.build().into())
            }
            result = query => result,
        };
        self.check()?;
        result
    }

    fn native_run<T>(
        &self,
        monitor: &ReadMonitor,
        interrupt: Arc<duckdb::InterruptHandle>,
        read: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.check()?;
        let mut slot = self.lock(|| self.interrupt.try_lock())?;
        if slot.is_some() {
            return crate::AnalysisBusySnafu {
                resource: "read control",
            }
            .fail();
        }
        *slot = Some(interrupt.clone());
        drop(slot);
        let guard = ReadInterrupt(self);
        let deadline = monitor.enter(self, interrupt)?;
        self.check()?;
        let result = read();
        drop(deadline);
        drop(guard);
        result
    }
}

#[derive(Default)]
pub(super) struct ReadMonitor {
    state: Arc<(Mutex<ReadDeadline>, Condvar)>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Default)]
struct ReadDeadline {
    active: Option<(Instant, Arc<duckdb::InterruptHandle>)>,
    stopped: bool,
}

impl ReadMonitor {
    fn enter(
        &self,
        control: &AnalysisReadControl,
        interrupt: Arc<duckdb::InterruptHandle>,
    ) -> Result<ReadStage<'_>> {
        let mut worker = control.lock(|| self.worker.try_lock())?;
        let mut state = control.lock(|| self.state.0.try_lock())?;
        if state.active.is_some() {
            return crate::AnalysisBusySnafu {
                resource: "read control",
            }
            .fail();
        }
        if worker
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            return crate::AnalysisStateSnafu {
                path: "<analysis-read>",
                reason: "the read deadline worker stopped",
            }
            .fail();
        }
        if worker.is_none() {
            let shared = self.state.clone();
            *worker = Some(
                std::thread::Builder::new()
                    .name("analysis-read-deadline".into())
                    .spawn(move || Self::run(&shared))
                    .map_err(|error| {
                        crate::AnalysisStateSnafu {
                            path: "<analysis-read>",
                            reason: format!("the read deadline worker could not start: {error}"),
                        }
                        .build()
                    })?,
            );
        }
        state.active = Some((control.deadline, interrupt));
        self.state.1.notify_one();
        Ok(ReadStage(self))
    }

    fn run(shared: &(Mutex<ReadDeadline>, Condvar)) {
        let Ok(mut state) = shared.0.lock() else {
            return;
        };
        while !state.stopped {
            let next = if let Some((deadline, interrupt)) = &state.active {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let wait = if remaining.is_zero() {
                    interrupt.interrupt();
                    Duration::from_millis(1)
                } else {
                    remaining
                };
                shared
                    .1
                    .wait_timeout(state, wait)
                    .ok()
                    .map(|(state, _)| state)
            } else {
                shared.1.wait(state).ok()
            };
            let Some(next) = next else {
                return;
            };
            state = next;
        }
    }
}

impl Drop for ReadMonitor {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.0.lock() {
            state.stopped = true;
        }
        self.state.1.notify_one();
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _joined = worker.join();
            }
        }
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

struct ReadStage<'a>(&'a ReadMonitor);

impl Drop for ReadStage<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.0.lock() {
            state.active = None;
            self.0.state.1.notify_one();
        }
    }
}

impl AnalysisStore {
    pub fn tenant_page(&self, after: Option<[u8; 16]>) -> Result<Vec<[u8; 16]>> {
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare(
                    "SELECT DISTINCT tenant_id FROM source_receipts
                 WHERE CAST(? AS BLOB) IS NULL OR tenant_id > ?
                 ORDER BY tenant_id LIMIT 256",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare source tenants",
                })?;
            let rows = statement
                .query_map(
                    params![
                        after.as_ref().map(|key| key.as_slice()),
                        after.as_ref().map(|key| key.as_slice())
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read source tenants",
                })?;
            rows.map(|row| {
                let tenant = row.context(AnalysisDatabaseSnafu {
                    operation: "decode source tenant",
                })?;
                tenant
                    .try_into()
                    .map_err(|_| self.state_error("the source tenant identity is invalid"))
            })
            .collect()
        })
    }

    #[track_caller]
    pub(super) fn read_snapshot<T>(
        &self,
        read: impl FnOnce(&duckdb::Connection) -> Result<T>,
    ) -> Result<T> {
        let control = AnalysisReadControl::default();
        let mut reader = self.reader_until(&control)?;
        control.run(&mut reader, read)
    }

    pub fn source_page(
        &self,
        tenant_id: [u8; 16],
        after: Option<&EvidenceIntakeIdentityV1>,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        if tenant_id == [0; 16]
            || after.is_some_and(|source| source.tenant_id != tenant_id || !source.valid())
        {
            return self.reject("the source page tenant or cursor is invalid");
        }
        let control = AnalysisReadControl::default();
        let mut reader_guard = self.reader_until(&control)?;
        control.run(&mut reader_guard, |reader| {
            self.source_page_from(reader, tenant_id, after, &control)
        })
    }

    pub(super) fn source_page_from(
        &self,
        reader: &Connection,
        tenant_id: [u8; 16],
        after: Option<&EvidenceIntakeIdentityV1>,
        control: &AnalysisReadControl,
    ) -> Result<Vec<EvidenceIntakeIdentityV1>> {
        control.check()?;
        let after = after.map(EvidenceIntakeIdentityV1::key);
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
                    after.as_deref(),
                    after.as_deref(),
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
                || !identity.valid()
                || identity.key().as_slice() != key
            {
                return self.reject("the source page identity does not match its key or tenant");
            }
            sources.push(identity);
        }
        control.check()?;
        Ok(sources)
    }

    pub fn read_page(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        first_cursor: u64,
    ) -> Result<AnalysisReadPageV1> {
        self.read_page_cancel(identity, first_cursor, &AnalysisReadControl::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn optional_deadline_inherits() -> TestResult {
        let parent = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
        let inherited = parent.within(None)?;
        assert_eq!(inherited.deadline, parent.deadline);
        assert_eq!(
            parent.within(Some(Duration::from_secs(120)))?.deadline,
            parent.deadline
        );
        assert!(parent.within(Some(Duration::from_secs(1)))?.deadline < parent.deadline);
        assert!(parent.within(Some(Duration::ZERO)).is_err());
        assert!(parent.within(Some(Duration::MAX)).is_err());
        let mut expired = inherited;
        expired.deadline = Instant::now();
        assert!(matches!(
            expired.within(None),
            Err(crate::Error::AnalysisReadDeadline { .. })
        ));
        parent.check()?;
        Ok(())
    }

    #[tokio::test]
    async fn optional_deadline_cancels() -> TestResult {
        let parent = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
        let inherited = parent.within(None)?;
        assert_eq!(
            inherited
                .query_async(async { Ok::<_, crate::Error>(7) })
                .await?,
            7
        );
        let waiting = inherited.query_async(std::future::pending::<Result<()>>());
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        parent.cancel()?;
        assert!(matches!(
            waiting.await,
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert!(matches!(
            inherited.within(None),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn optional_deadline_expires() -> TestResult {
        let parent = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
        let evaluation = parent.within(Some(Duration::from_millis(10)))?;
        assert!(matches!(
            evaluation
                .query_async(std::future::pending::<Result<()>>())
                .await,
            Err(crate::Error::AnalysisReadDeadline { .. })
        ));
        parent.check()?;
        parent.within(None)?.check()?;
        Ok(())
    }

    #[test]
    fn read_monitor_store_reuse() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let expected = store.meta()?;
        let workers = || -> std::result::Result<Vec<_>, &str> {
            store
                .read_monitors
                .iter()
                .map(|monitor| {
                    Ok(monitor
                        .worker
                        .lock()
                        .map_err(|_| "monitor poisoned")?
                        .as_ref()
                        .map(|worker| worker.thread().id()))
                })
                .collect()
        };
        assert_eq!(store.meta()?, expected);
        let before = workers()?;
        assert!(before.iter().all(Option::is_some));
        assert_eq!(store.meta()?, expected);
        assert_eq!(workers()?, before);
        assert!(store.trace_intent([1; 16], [1; 16])?.is_none());
        let writer = store
            .write_monitor
            .worker
            .lock()
            .map_err(|_| "monitor poisoned")?
            .as_ref()
            .ok_or("monitor absent")?
            .thread()
            .id();
        assert!(store.trace_intent([1; 16], [1; 16])?.is_none());
        assert_eq!(
            store
                .write_monitor
                .worker
                .lock()
                .map_err(|_| "monitor poisoned")?
                .as_ref()
                .ok_or("monitor absent")?
                .thread()
                .id(),
            writer
        );
        Ok(())
    }

    #[test]
    fn read_monitor_stage_cleanup() -> TestResult {
        let connection = Connection::open_in_memory()?;
        let operation = AnalysisReadControl::with_timeout(Duration::from_secs(5))?;
        let stage = operation.within(Duration::from_millis(50))?;
        let result = stage.query_run(&connection, || {
            connection
                .query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                    row.get::<_, i64>(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "test shorter stage deadline",
                })
        });
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadDeadline { .. })
        ));
        let worker = operation
            .monitor
            .worker
            .lock()
            .map_err(|_| "monitor poisoned")?
            .as_ref()
            .ok_or("monitor absent")?
            .thread()
            .id();
        let result = operation.query_run(&connection, || {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "test next stage",
                })
        })?;
        assert_eq!(result, 1);
        assert_eq!(
            operation
                .monitor
                .worker
                .lock()
                .map_err(|_| "monitor poisoned")?
                .as_ref()
                .ok_or("monitor absent")?
                .thread()
                .id(),
            worker
        );
        operation.check()?;
        Ok(())
    }

    #[test]
    fn query_scope_reader_recovery() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let expected = store.meta()?;
        let control = AnalysisReadControl::with_timeout(Duration::from_millis(50))?;
        let (entered, entering) = std::sync::mpsc::channel();
        *control.wait_signal.lock().map_err(|_| "signal poisoned")? = Some(entered);
        let held = control.interrupt.lock().map_err(|_| "interrupt poisoned")?;
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| -> Result<()> {
                let mut reader = store.reader()?;
                let result = control.run(&mut reader, |_| Ok(()));
                assert!(reader.connection.is_some());
                result
            });
            entering.recv_timeout(Duration::from_secs(2))?;
            assert!(matches!(
                waiting.join().map_err(|_| "reader panicked")?,
                Err(crate::Error::AnalysisReadDeadline { .. })
            ));
            Ok(())
        })?;
        drop(held);
        assert_eq!(store.meta()?, expected);

        for failure in ["begin", "rollback"] {
            let mut reader = store.reader()?;
            if failure == "begin" {
                reader.get()?.execute_batch("BEGIN TRANSACTION")?;
            }
            let result = AnalysisReadControl::default().run(&mut reader, |snapshot| {
                snapshot
                    .execute_batch("ROLLBACK")
                    .context(AnalysisDatabaseSnafu {
                        operation: "force read rollback failure",
                    })
            });
            assert!(result.is_err(), "{failure}");
            AnalysisReadControl::default().run(&mut reader, |snapshot| {
                assert_eq!(
                    AnalysisStore::read_meta_from(snapshot, directory.path())?,
                    expected
                );
                Ok(())
            })?;
        }
        assert_eq!(store.meta()?, expected);
        assert!(store.storage_health()?.write_ready);
        Ok(())
    }

    #[test]
    fn query_input_native_cancel() -> TestResult {
        use std::sync::mpsc;

        assert!(AnalysisReadControl::with_timeout(Duration::ZERO).is_err());
        assert!(AnalysisReadControl::with_timeout(Duration::MAX).is_err());
        assert!(AnalysisReadControl::with_timeout(Duration::from_nanos(1)).is_ok());
        let config = duckdb::Config::default()
            .enable_external_access(false)?
            .enable_autoload_extension(false)?
            .threads(1)?;
        let connection = duckdb::Connection::open_in_memory_with_flags(config)?;
        let mut control = AnalysisReadControl::with_timeout(Duration::from_secs(2))?;
        control.deadline = Instant::now();
        assert!(matches!(
            control.check(),
            Err(crate::Error::AnalysisReadDeadline { .. })
        ));
        assert!(control.within(Duration::from_secs(2)).is_err());
        let outer = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
        let bounded = outer.within(Duration::from_secs(1))?;
        assert!(bounded.deadline < outer.deadline);
        assert_eq!(
            outer.within(Duration::from_secs(120))?.deadline,
            outer.deadline
        );
        let evaluation = control.stage(Duration::from_secs(2))?;
        evaluation.check()?;
        let (start, started) = mpsc::channel();
        let (stop, stopped) = mpsc::channel::<()>();
        std::thread::scope(|scope| -> TestResult {
            let control = &control;
            let cancel = scope.spawn(move || -> TestResult {
                started.recv_timeout(Duration::from_secs(2))?;
                while matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    control.cancel()?;
                    std::thread::yield_now();
                }
                Ok(())
            });
            let mut native_failed = false;
            let result = evaluation.query_run(&connection, || {
                let sibling = control.stage(Duration::from_secs(2))?;
                let nested = sibling.query_run(&connection, || Ok(()));
                assert!(matches!(nested, Err(crate::Error::AnalysisBusy { .. })));
                let _sent = start.send(());
                let result =
                    connection.query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                        row.get::<_, i128>(0)
                    });
                native_failed = result.is_err();
                result.context(AnalysisDatabaseSnafu {
                    operation: "test direct native cancellation",
                })
            });
            drop(stop);
            cancel.join().map_err(|_| "cancel worker panicked")??;
            assert!(native_failed);
            assert!(
                matches!(result, Err(crate::Error::AnalysisReadCancelled { .. })),
                "{result:?}"
            );
            Ok(())
        })?;
        assert!(matches!(
            evaluation.check(),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert!(control
            .interrupt
            .lock()
            .map_err(|_| "interrupt poisoned")?
            .is_none());
        let fresh = AnalysisReadControl::with_timeout(Duration::from_secs(1))?;
        let value = fresh.query_run(&connection, || {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "test native cancellation cleanup",
                })
        })?;
        assert_eq!(value, 1);
        Ok(())
    }

    #[test]
    fn analysis_metadata_read_deadlines() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
        };
        let processor = super::super::ProcessorScopeV1 {
            identity: identity.clone(),
            processor_id: "p".into(),
            method_version: 1,
        };
        let context = super::super::AnalysisContextKeyV1 {
            tenant_id: identity.tenant_id,
            owner_id: "o".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 0,
        };
        let reads: [&dyn Fn() -> Result<()>; 8] = [
            &|| store.meta().map(|_| ()),
            &|| store.source_status(&identity).map(|_| ()),
            &|| store.context_version(&context).map(|_| ()),
            &|| store.read_result(identity.tenant_id, "r").map(|_| ()),
            &|| store.recovery_gaps(&identity, 0).map(|_| ()),
            &|| store.processor_health(&processor).map(|_| ()),
            &|| store.processor_retirement(&processor).map(|_| ()),
            &|| store.graph_snapshot(&identity).map(|_| ()),
        ];
        let before = store.meta()?;
        for read in reads {
            let maintenance = store
                .maintenance
                .write()
                .map_err(|_| "maintenance poisoned")?;
            let started = Instant::now();
            assert!(matches!(
                read(),
                Err(crate::Error::AnalysisReadDeadline { .. })
            ));
            assert!(started.elapsed() < Duration::from_secs(3));
            drop(maintenance);
            assert_eq!(store.read_slots.available_permits(), 16);
            read()?;
        }
        assert_eq!(store.meta()?, before);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_read_lock_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
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
            let control = AnalysisReadControl::with_timeout(Duration::from_millis(50))?;
            if held == 2 {
                assert_eq!(
                    store
                        .read_page_cancel(&identity, 1, &control)?
                        .records
                        .len(),
                    1
                );
            } else {
                assert!(matches!(
                    store.read_page_cancel(&identity, 1, &control),
                    Err(crate::Error::AnalysisReadDeadline { .. })
                ));
            }
            drop((writer, maintenance, readers));
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
            control.cancel()?;
            assert!(matches!(
                waiting.join().map_err(|_| "read worker panicked")?,
                Err(crate::Error::AnalysisReadCancelled { .. })
            ));
            Ok(())
        })?;
        drop(writer);
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_read_native_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let before = store.meta()?;
        let mut reader = store.reader()?;
        for _ in 0..16 {
            let control = AnalysisReadControl::with_timeout(Duration::from_millis(50))?;
            let started = Instant::now();
            let call_line = line!() + 1;
            let result = control.run(&mut reader, |snapshot| {
                snapshot
                    .query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .context(AnalysisDatabaseSnafu {
                        operation: "test native deadline",
                    })
            });
            assert!(
                matches!(
                    &result,
                    Err(crate::Error::AnalysisReadDeadline { location })
                        if location.file == file!() && location.line == call_line
                ),
                "{result:?}"
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(control
                .interrupt
                .lock()
                .map_err(|_| "interrupt poisoned")?
                .is_none());
            let snapshot = reader.get_mut()?.transaction()?;
            assert_eq!(
                snapshot.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?,
                1
            );
            snapshot.rollback()?;
        }
        drop(reader);
        let call_line = line!() + 1;
        let result = store.read_snapshot(|snapshot| {
            snapshot
                .query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                    row.get::<_, i64>(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "test snapshot deadline",
                })
        });
        assert!(
            matches!(
                &result,
                Err(crate::Error::AnalysisReadDeadline { location })
                    if location.file == file!() && location.line == call_line
            ),
            "{result:?}"
        );
        assert_eq!(store.read_slots.available_permits(), 16);
        assert!(store.maintenance.try_write().is_ok());
        assert_eq!(store.meta()?, before);
        store.checkpoint()?;
        Ok(())
    }

    #[test]
    fn analysis_read_cancel_cleanup() -> TestResult {
        use std::sync::mpsc;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let before = store.meta()?;
        let mut reader = store.reader()?;
        for _ in 0..16 {
            let control = AnalysisReadControl::default();
            let (start, started) = mpsc::channel();
            let (stop, stopped) = mpsc::channel::<()>();
            let result = std::thread::scope(|scope| -> TestResult {
                let control = &control;
                let cancel = scope.spawn(move || -> TestResult {
                    started.recv_timeout(Duration::from_secs(2))?;
                    while matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                        control.cancel()?;
                        std::thread::yield_now();
                    }
                    Ok(())
                });
                let result = control.run(&mut reader, |snapshot| {
                    let _sent = start.send(());
                    while !control.cancelled.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    snapshot
                        .query_row("SELECT sum(range) FROM range(100000000000)", [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .context(AnalysisDatabaseSnafu {
                            operation: "test repeated cancellation",
                        })
                });
                drop(stop);
                cancel.join().map_err(|_| "cancel worker panicked")??;
                assert!(
                    matches!(result, Err(crate::Error::AnalysisReadCancelled { .. })),
                    "{result:?}"
                );
                Ok(())
            });
            result?;
            let snapshot = reader.get_mut()?.transaction()?;
            assert_eq!(
                snapshot.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?,
                1
            );
            snapshot.rollback()?;
        }
        let control = AnalysisReadControl::default();
        assert!(control
            .run(&mut reader, |snapshot| {
                snapshot
                    .execute_batch("ROLLBACK")
                    .context(AnalysisDatabaseSnafu {
                        operation: "test failed snapshot cleanup",
                    })
            })
            .is_err());
        assert!(reader.connection.is_some());
        drop(reader);
        assert_eq!(store.read_slots.available_permits(), 16);
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
        let identity = crate::analysis::tests::identity();
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
        expected.sort_by_key(EvidenceIntakeIdentityV1::key);
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
