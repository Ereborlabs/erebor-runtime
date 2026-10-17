use std::collections::BTreeSet;
use std::hash::Hash;
use std::mem::size_of;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStoreMetaV1, StorePositionV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::ScalarValue;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;
use futures_core::Stream;
use futures_util::{StreamExt as _, TryStreamExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::execution::{Engine, Permit, Read, Retention};
use crate::sources::ArrowSnapshot;
use crate::stream::Output;
use crate::{InvalidSnafu, Result, SqlSnafu};

mod clock;
mod cursor;
mod delivery;
mod window;

#[cfg(test)]
mod tests;

pub use clock::{Clock, SystemClock};
pub use cursor::Cursor;
use cursor::Fingerprint;
pub use delivery::{Action, Consumer, Delivery};
use window::Window;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum Operation {
    Append,
    Replace,
}

#[derive(Debug)]
pub struct Update {
    pub snapshot: Arc<ArrowSnapshot>,
    pub batches: Option<Vec<RecordBatch>>,
    pub cursor: Cursor,
    pub operation: Operation,
    pub exhausted: bool,
    pub clock_changed: bool,
    pub positions: Vec<StorePositionV1>,
    pub evaluated_utc_ns: u64,
    pub limited: bool,
    _memory: MemoryReservation,
}

pub struct Subscription {
    engine: Arc<Engine>,
    schema: SchemaRef,
    moving: Option<u64>,
    control: Arc<AnalysisReadControl>,
    resume: Option<Cursor>,
    operation: Operation,
    stream: Pin<Box<dyn Stream<Item = std::result::Result<Update, StreamError>> + Send>>,
}

type StreamError = (crate::Error, Option<Arc<ArrowSnapshot>>);

impl Subscription {
    /// `sources` contains all original durable Data sources. Exclude registered local tables.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Arc<Engine>,
        plan: Arc<LogicalPlan>,
        sources: BTreeSet<String>,
        selection: AnalysisSelectionV1,
        control: Arc<AnalysisReadControl>,
        binding: &[u8],
        resume: Option<Cursor>,
        clock: Arc<dyn Clock>,
        follow: bool,
    ) -> Result<Self> {
        control.check()?;
        if !selection.valid() || (!follow && resume.is_some()) {
            return InvalidSnafu {
                field: "cursor request",
            }
            .fail();
        }
        if selection.graph_traversal().is_some()
            && (follow
                || resume.is_some()
                || !sources
                    .iter()
                    .any(|name| matches!(name.as_str(), "graph_subjects" | "relationships"))
                || sources.iter().any(|name| {
                    !matches!(
                        name.as_str(),
                        "graph_subjects" | "relationships" | "catalog"
                    )
                }))
        {
            return Err(crate::Error::Sql {
                source: datafusion::error::DataFusionError::NotImplemented(
                    "graph traversal query capability".into(),
                ),
            });
        }
        let clocks = Window::clocks(&plan)?;
        let source_clock = sources.contains("notifications");
        let window = if follow {
            Window::from_plan(&plan)?
        } else {
            None
        };
        let operation = if clocks == 0
            && !source_clock
            && crate::planner::subscription::Subscribe::appendable(&plan).context(SqlSnafu)?
        {
            Operation::Append
        } else {
            Operation::Replace
        };
        let binding = Fingerprint::binding(&plan, &sources, &selection, operation, binding)?;
        if let Some(cursor) = &resume {
            cursor.check_binding(&binding, operation)?;
        }
        let schema = Arc::clone(plan.schema().inner());
        let changes = engine.store().subscribe_revision();
        let clock_changes = clock.changes();
        let permit = engine.reserve_stream(selection.tenant_id)?;
        let state = State {
            engine: Arc::clone(&engine),
            plan,
            sources,
            selection,
            control: Arc::clone(&control),
            clock,
            changes,
            clock_changes,
            follow,
            operation,
            window,
            source_clock,
            binding,
            cursor: resume.clone(),
            snapshot: None,
            content: None,
            expiry: None,
            evaluated: 0,
            exhausted: true,
            dirty: false,
            clock_dirty: false,
            changes_open: true,
            clock_open: true,
            ended: false,
            health: None,
            last_run: None,
            execution: None,
            compiled: false,
            _permit: permit,
        };
        let stream = futures_util::stream::unfold(Some(state), |state| async move {
            let mut state = state?;
            match state.next().await {
                Ok(Some(update)) => Some((Ok(update), Some(state))),
                Ok(None) => None,
                Err(mut error) => {
                    let receipt = if state.snapshot.is_none()
                        && state.cursor.is_some()
                        && crate::Failure::from(&error) == crate::Failure::CursorExpired
                    {
                        let capture = async {
                            let now = state.clock.now_ns()?;
                            let control = AnalysisReadControl::with_timeout(
                                state.engine.limits().extract_timeout,
                            )?;
                            state
                                .engine
                                .metadata(state.selection.clone(), &state.sources, &control, now)
                                .await
                        }
                        .await;
                        match capture {
                            Ok(receipt) => Some(receipt),
                            Err(capture) => {
                                error = capture;
                                None
                            }
                        }
                    } else {
                        None
                    };
                    Some((Err((error, receipt)), None))
                }
            }
        })
        .boxed();
        Ok(Self {
            engine,
            schema,
            moving: (follow && (window.is_some() || source_clock)).then_some(500_000_000),
            control,
            resume,
            operation,
            stream,
        })
    }

    pub fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    pub fn moving_resolution_ns(&self) -> Option<u64> {
        self.moving
    }

    pub fn cancel(&mut self) -> Result<()> {
        self.stream = Box::pin(futures_util::stream::empty());
        self.control.cancel()?;
        Ok(())
    }
}

impl Stream for Subscription {
    type Item = Result<Update>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream
            .as_mut()
            .poll_next(context)
            .map(|item| item.map(|result| result.map_err(|(error, _)| error)))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _cancelled = self.control.cancel();
    }
}

struct State {
    engine: Arc<Engine>,
    plan: Arc<LogicalPlan>,
    sources: BTreeSet<String>,
    selection: AnalysisSelectionV1,
    control: Arc<AnalysisReadControl>,
    clock: Arc<dyn Clock>,
    changes: watch::Receiver<u64>,
    clock_changes: watch::Receiver<u64>,
    follow: bool,
    operation: Operation,
    window: Option<Window>,
    source_clock: bool,
    binding: [u8; 32],
    cursor: Option<Cursor>,
    snapshot: Option<Arc<ArrowSnapshot>>,
    content: Option<[u8; 32]>,
    expiry: Option<u64>,
    evaluated: u64,
    exhausted: bool,
    dirty: bool,
    clock_dirty: bool,
    changes_open: bool,
    clock_open: bool,
    ended: bool,
    health: Option<Instant>,
    last_run: Option<Instant>,
    execution: Option<crate::stream::OutputStream>,
    compiled: bool,
    _permit: Permit,
}

enum Wake {
    Store,
    Clock,
    Health,
}

impl State {
    async fn next(&mut self) -> Result<Option<Update>> {
        if self.ended {
            return Ok(None);
        }
        if self.snapshot.is_none() {
            return self.evaluate(false).await.map(Some);
        }
        if !self.follow {
            self.ended = true;
            return Ok(None);
        }
        if self.operation == Operation::Append && !self.exhausted {
            return self.evaluate(false).await.map(Some);
        }
        loop {
            self.control.check()?;
            if self.clock_dirty {
                self.clock_dirty = false;
                if self.window.is_some() || self.source_clock {
                    return self.evaluate(true).await.map(Some);
                }
                return self.health_update(true).await.map(Some);
            }
            if self.dirty {
                self.dirty = false;
                if self.changed().await? {
                    return self.evaluate(false).await.map(Some);
                }
                return self.health_update(false).await.map(Some);
            }
            match self.wait().await? {
                Wake::Store => self.dirty = true,
                Wake::Clock => {
                    if self.window.is_some() || self.source_clock {
                        return self.evaluate(true).await.map(Some);
                    }
                    return self.health_update(true).await.map(Some);
                }
                Wake::Health => return self.health_update(false).await.map(Some),
            }
        }
    }

    async fn wait(&mut self) -> Result<Wake> {
        let now = self.clock.now_ns()?;
        if self.expiry.is_some_and(|expiry| expiry <= now) {
            return Ok(Wake::Clock);
        }
        let expiry = self
            .expiry
            .map(|expiry| Duration::from_nanos(expiry.saturating_sub(now)));
        let health = self
            .health
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(15));
        let control = Arc::clone(&self.control);
        control.query_async(async {
            loop {
                tokio::select! {
                    changed = self.changes.changed(), if self.changes_open => {
                        if changed.is_err() { self.changes_open = false; continue; }
                        self.changes.borrow_and_update();
                        return Ok(Wake::Store);
                    }
                    changed = self.clock_changes.changed(), if self.clock_open => {
                        if changed.is_err() { self.clock_open = false; continue; }
                        self.clock_changes.borrow_and_update();
                        return Ok(Wake::Clock);
                    }
                    _ = tokio::time::sleep(expiry.unwrap_or(Duration::from_secs(86_400))), if expiry.is_some() => {
                        return Ok(Wake::Clock);
                    }
                    _ = tokio::time::sleep_until(health) => return Ok(Wake::Health),
                }
            }
        }).await
    }

    async fn changed(&mut self) -> Result<bool> {
        self.changes.borrow_and_update();
        let snapshot = self.snapshot.as_ref().ok_or_else(Self::state_error)?;
        let selection = snapshot.selection.clone();
        let (meta, revision) = self.dependencies(selection).await?;
        let cursor = self.cursor.as_ref().ok_or_else(Self::state_error)?;
        cursor.check_store(&meta)?;
        self.dirty = self.changes.has_changed().unwrap_or(false)
            || *self.changes.borrow() > meta.commit_revision;
        Ok(revision > cursor.read_revision())
    }

    async fn dependencies(
        &mut self,
        selection: AnalysisSelectionV1,
    ) -> Result<(AnalysisStoreMetaV1, u64)> {
        let stage = Arc::new(self.control.within(self.engine.limits().extract_timeout)?);
        let worker = Arc::clone(&stage);
        let store = Arc::clone(self.engine.store());
        stage
            .query_async(async move {
                tokio::task::spawn_blocking(move || store.dependency_revision(&selection, &worker))
                    .await
                    .map_err(|source| crate::Error::Sql {
                        source: datafusion::common::DataFusionError::External(Box::new(source)),
                    })?
                    .map_err(crate::Error::from)
            })
            .await
    }

    async fn evaluate(&mut self, clock_changed: bool) -> Result<Update> {
        if self.follow && self.operation == Operation::Replace && self.execution.is_none() {
            if let Some(last) = self.last_run {
                let due = last + Duration::from_millis(500);
                self.control
                    .query_async(async {
                        tokio::time::sleep_until(due).await;
                        Ok::<_, crate::Error>(())
                    })
                    .await?;
            }
        }
        let permit = Arc::new(
            self.control
                .query_async(self.engine.acquire_evaluation(self.selection.tenant_id))
                .await?,
        );
        self.changes.borrow_and_update();
        self.clock_changes.borrow_and_update();
        let now = self.clock.now_ns()?;
        let selection = self.window.map_or_else(
            || self.selection.clone(),
            |window| window.selection(&self.selection, now),
        );
        if self.snapshot.is_none() {
            if let Some(cursor) = self.cursor.clone() {
                let (meta, _) = self.dependencies(selection.clone()).await?;
                cursor.check_store(&meta)?;
            }
        }
        if self.operation == Operation::Append {
            self.execution = self
                .engine
                .session(selection, &self.control, now)?
                .subscribe(
                    &self.plan,
                    &self.sources,
                    Read::Page(self.cursor.as_ref().map(Cursor::position)),
                    permit,
                )
                .await?;
            let result = self.advance(now).await;
            self.execution = None;
            return result;
        }
        if !self.compiled {
            self.compiled = true;
            if self.follow
                && self.operation == Operation::Replace
                && Window::clocks(&self.plan)? == 0
                && !self.source_clock
            {
                self.execution = self
                    .engine
                    .session(self.selection.clone(), &self.control, now)?
                    .subscribe(
                        &self.plan,
                        &self.sources,
                        Read::Snapshot,
                        Arc::clone(&permit),
                    )
                    .await?;
            }
        }
        if self.execution.is_some() {
            drop(permit);
            return self.advance(now).await;
        }
        let session = self.engine.session(selection, &self.control, now)?;
        let (snapshot, mut stream, permit, control, mut reservation) = session
            .start(
                &self.plan,
                &self.sources,
                Read::Snapshot,
                Retention::Output,
                permit,
            )
            .await?;
        if let Some(cursor) = &self.cursor {
            cursor.check_store(&snapshot.page.extraction.meta)?;
        }
        let mut batches = Vec::new();
        let (mut rows, mut bytes) = (0usize, 0usize);
        while let Some(batch) = control
            .query_async(async { stream.try_next().await.context(SqlSnafu) })
            .await?
        {
            if batch.num_rows() == 0 {
                continue;
            }
            rows = rows.saturating_add(batch.num_rows());
            bytes = bytes.saturating_add(batch.get_array_memory_size());
            if rows > self.engine.limits().output_rows || bytes > self.engine.limits().output_bytes
            {
                return Err(Self::output_error());
            }
            self.engine
                .memory()
                .retain_output(&batch, &mut reservation)
                .context(SqlSnafu)?;
            batches.push(batch);
        }
        drop(stream);
        drop(permit);
        control
            .query_async(self.engine.check_read(&snapshot))
            .await?;
        let hash = self.content_hash(&batches, &mut reservation)?;
        let unchanged = self.content == Some(hash);
        self.content = Some(hash);
        let batches = (!unchanged).then_some(batches);
        let retained = batches.as_ref().map_or(0, |batches| {
            batches
                .capacity()
                .saturating_mul(size_of::<RecordBatch>())
                .saturating_add(
                    batches
                        .iter()
                        .map(|batch| {
                            batch.num_columns() * size_of::<datafusion::arrow::array::ArrayRef>()
                        })
                        .sum::<usize>(),
                )
        });
        reservation
            .try_resize(retained)
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })?;
        self.finish(
            Output {
                snapshot,
                batches,
                positions: Vec::new(),
                position: StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                },
                limited: false,
                _memory: reservation,
                _permit: None,
                _control: control,
            },
            now,
            clock_changed,
        )
    }

    async fn advance(&mut self, now: u64) -> Result<Update> {
        let output = self
            .execution
            .as_mut()
            .ok_or_else(Self::state_error)?
            .try_next()
            .await?
            .ok_or_else(Self::state_error)?;
        self.finish(output, now, false)
    }

    fn finish(&mut self, output: Output, now: u64, clock_changed: bool) -> Result<Update> {
        let Output {
            snapshot,
            batches,
            positions,
            position,
            limited,
            _memory,
            ..
        } = output;
        if let Some(cursor) = &self.cursor {
            cursor.check_store(&snapshot.page.extraction.meta)?;
        }
        let cursor = Cursor::new(
            &snapshot.page.extraction.meta,
            self.operation,
            self.binding,
            position,
            now,
        );
        self.cursor = Some(cursor.clone());
        self.dirty = self.changes.has_changed().unwrap_or(false)
            || *self.changes.borrow() > snapshot.page.extraction.meta.commit_revision;
        self.clock_dirty = self.clock_changes.has_changed().unwrap_or(false);
        self.expiry = self
            .window
            .and_then(|window| window.expiry(snapshot.received_min))
            .into_iter()
            .chain(snapshot.next_change)
            .min();
        self.snapshot = Some(Arc::clone(&snapshot));
        self.evaluated = now;
        self.exhausted =
            self.operation == Operation::Replace || (snapshot.page.exhausted && !limited);
        self.last_run = Some(Instant::now());
        self.health = Some(Instant::now() + Duration::from_secs(15));
        Ok(Update {
            snapshot,
            batches,
            cursor,
            operation: self.operation,
            exhausted: self.exhausted,
            clock_changed,
            positions,
            evaluated_utc_ns: now,
            limited: limited || !self.exhausted,
            _memory,
        })
    }

    fn content_hash(
        &self,
        batches: &[RecordBatch],
        reservation: &mut MemoryReservation,
    ) -> Result<[u8; 32]> {
        let metadata = batches
            .len()
            .saturating_mul(size_of::<RecordBatch>())
            .saturating_add(
                batches
                    .iter()
                    .map(|batch| {
                        batch.num_columns() * size_of::<datafusion::arrow::array::ArrayRef>()
                    })
                    .sum::<usize>(),
            );
        let mut hash = Fingerprint::new();
        self.plan.schema().hash(&mut hash);
        batches
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>()
            .hash(&mut hash);
        for batch in batches {
            for row in 0..batch.num_rows() {
                self.control.check()?;
                reservation
                    .try_resize(
                        metadata
                            .saturating_add(Output::row_bytes(batch, row)?)
                            .saturating_add(size_of::<ScalarValue>()),
                    )
                    .map_err(|source| crate::Error::Capacity {
                        resource: "shared output",
                        source,
                    })?;
                for column in batch.columns() {
                    ScalarValue::try_from_array(column, row)
                        .context(SqlSnafu)?
                        .hash(&mut hash);
                }
            }
        }
        Ok(hash.finish_digest())
    }

    async fn health_update(&mut self, clock_changed: bool) -> Result<Update> {
        let clock_changed = clock_changed || self.clock_changes.has_changed().unwrap_or(false);
        if (self.window.is_some() || self.source_clock) && clock_changed {
            return self.evaluate(true).await;
        }
        self.clock_changes.borrow_and_update();
        let now = self.clock.now_ns()?;
        let selection = self.window.map_or_else(
            || self.selection.clone(),
            |window| window.selection(&self.selection, now),
        );
        let snapshot = self
            .engine
            .metadata(selection, &self.sources, &self.control, now)
            .await?;
        self.control
            .query_async(self.engine.check_read(&snapshot))
            .await?;
        self.dirty |= self.changes.has_changed().unwrap_or(false)
            || *self.changes.borrow() > snapshot.page.extraction.meta.commit_revision;
        self.snapshot = Some(Arc::clone(&snapshot));
        self.health = Some(Instant::now() + Duration::from_secs(15));
        Ok(Update {
            snapshot,
            batches: None,
            cursor: self.cursor.as_ref().ok_or_else(Self::state_error)?.clone(),
            operation: self.operation,
            exhausted: self.exhausted,
            clock_changed,
            positions: Vec::new(),
            evaluated_utc_ns: self.evaluated,
            limited: !self.exhausted,
            _memory: self.engine.memory().reserve_output(0).context(SqlSnafu)?,
        })
    }

    fn output_error() -> crate::Error {
        crate::Error::Sql {
            source: datafusion::common::DataFusionError::ResourcesExhausted("query output".into()),
        }
    }

    fn state_error() -> crate::Error {
        crate::Error::Sql {
            source: datafusion::common::DataFusionError::Internal(
                "subscription state is incomplete".into(),
            ),
        }
    }
}
