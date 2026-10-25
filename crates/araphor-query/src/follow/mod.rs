use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{AnalysisReadControl, AnalysisTableRequests, StorePositionV1};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;
use futures_core::Stream;
use futures_util::{StreamExt as _, TryStreamExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::execution::{Engine, Permit, Session};
use crate::sources::ArrowSnapshot;
use crate::stream::physical::{Fingerprint, SubscribeExec};
use crate::stream::{Event, Output, OutputStream, Run, StreamError};
use crate::{InvalidSnafu, Result, SqlSnafu};

mod clock;
mod cursor;
mod delivery;
mod managed;
mod window;

#[cfg(test)]
mod tests;

pub use crate::stream::progress::{Progress, Wake};
pub use crate::stream::recovery::SourceRecovery;
pub use clock::{Clock, SystemClock};
pub use cursor::Cursor;
pub use delivery::{Action, Consumer, Delivery};
pub use managed::ManagedPublication;
pub(crate) use window::Window;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub enum Operation {
    Append,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum WindowSource {
    Query,
    Input { call: u64, slot: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowRange {
    pub source: WindowSource,
    pub start_utc_ns: i64,
    pub end_utc_ns: i64,
    pub(crate) active: bool,
}

impl WindowRange {
    pub(crate) fn same_interval(&self, other: &Self) -> bool {
        (self.source, self.start_utc_ns, self.end_utc_ns)
            == (other.source, other.start_utc_ns, other.end_utc_ns)
    }
}

#[derive(Debug)]
pub struct Update {
    pub snapshot: Arc<ArrowSnapshot>,
    pub batches: Option<Vec<RecordBatch>>,
    pub calls: std::collections::BTreeMap<u64, Arc<crate::definition::CallResult>>,
    pub cursor: Cursor,
    pub operation: Operation,
    pub exhausted: bool,
    pub clock_changed: bool,
    pub completed_windows: Vec<WindowRange>,
    pub positions: Vec<StorePositionV1>,
    pub evaluated_utc_ns: u64,
    pub limited: bool,
    _memory: MemoryReservation,
}

pub struct Subscription {
    session: Arc<Session>,
    workers: araphor_package_runtime::TaskTracker,
    schema: SchemaRef,
    moving: Option<u64>,
    resume: Option<Cursor>,
    operation: Operation,
    stream: Pin<Box<dyn Stream<Item = std::result::Result<Update, StreamError>> + Send>>,
}

impl Subscription {
    /// `sources` contains all original durable Data sources. Exclude registered local tables.
    pub fn new(
        session: Session,
        plan: Arc<LogicalPlan>,
        sources: AnalysisTableRequests,
        binding: &[u8],
        resume: Option<Cursor>,
        clock: Arc<dyn Clock>,
        follow: bool,
    ) -> Result<Self> {
        Self::open(
            session, plan, sources, binding, resume, clock, follow, None, None, false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        mut session: Session,
        plan: Arc<LogicalPlan>,
        sources: AnalysisTableRequests,
        binding: &[u8],
        resume: Option<Cursor>,
        clock: Arc<dyn Clock>,
        follow: bool,
        managed: Option<(
            crate::definition::PreparedDefinition,
            Arc<dyn ManagedPublication>,
        )>,
        resume_expiry: Option<u64>,
        resume_pending: bool,
    ) -> Result<Self> {
        let workers = araphor_package_runtime::TaskTracker::new();
        session.workers = Some(workers.clone());
        let session = Arc::new(session);
        let engine = session.engine();
        let selection = session.selection();
        let control = session.control();
        control.check()?;
        crate::definition::PackageCall::check_admission(&plan).context(SqlSnafu)?;
        if !selection.valid() || (!follow && resume.is_some()) {
            return InvalidSnafu {
                field: "cursor request",
            }
            .fail();
        }
        let requests = managed
            .as_ref()
            .map_or(&sources, |(definition, _)| definition.sources());
        if selection.graph_traversal().is_some()
            && (follow
                || resume.is_some()
                || !requests
                    .keys()
                    .any(|name| matches!(name.as_str(), "graph_subjects" | "relationships"))
                || requests.keys().any(|name| {
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
        let window = if follow || managed.is_some() {
            Window::from_plan(&plan)?
        } else {
            None
        };
        let operation = if clocks == 0
            && crate::planner::subscription::Subscribe::appendable(&plan).context(SqlSnafu)?
        {
            Operation::Append
        } else {
            Operation::Replace
        };
        let binding = Fingerprint::binding(&plan, requests, selection, operation, binding)?;
        if let Some(cursor) = &resume {
            cursor.check_binding(&binding, operation)?;
            cursor.check_windows(&plan, window.as_ref())?;
        }
        let schema = Arc::clone(plan.schema().inner());
        let permit = if follow || managed.is_none() {
            Some(engine.reserve_stream(selection.tenant_id)?)
        } else {
            None
        };
        let run = Arc::new(Run {
            session: Arc::clone(&session),
            plan,
            sources,
            clock,
            follow,
            operation,
            window,
            resume: resume.clone(),
            binding,
            resume_expiry,
            resume_pending,
            managed,
        });
        let execution = Arc::clone(&run);
        let stream = futures_util::stream::once(async move {
            SubscribeExec::open(execution)
                .await
                .map_err(|error| (error, None))
        })
        .try_flatten();
        let state = State {
            run,
            cursor: resume.clone(),
            started: false,
            stream: Box::pin(stream),
            _permit: permit,
        };
        let stream = futures_util::stream::unfold(Some(state), |state| async move {
            let mut state = state?;
            match state.next().await {
                Ok(Some(update)) => Some((Ok(update), Some(state))),
                Ok(None) => None,
                Err((mut error, receipt)) => {
                    let receipt = if receipt.is_none()
                        && !state.started
                        && state.cursor.is_some()
                        && crate::Failure::from(&error) == crate::Failure::CursorExpired
                    {
                        let capture = async {
                            let now = state.run.clock.now_ns()?;
                            let control = AnalysisReadControl::default()
                                .within(state.run.session.engine().limits().extract_timeout)?;
                            let mut session = state.run.session.engine().session_on(
                                state.run.session.selection().clone(),
                                &control,
                                now,
                                Arc::clone(state.run.session.memory()),
                            )?;
                            session.workers = state.run.session.workers.clone();
                            session.metadata(state.run.sources()).await
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
                        receipt
                    };
                    Some((Err((error, receipt)), None))
                }
            }
        })
        .boxed();
        Ok(Self {
            session,
            workers,
            schema,
            moving: (follow && clocks != 0).then_some(1_000),
            resume,
            operation,
            stream,
        })
    }

    pub fn until_change(self, mut changes: tokio::sync::watch::Receiver<u64>) -> Self {
        self.until(async move {
            let _changed = changes.changed().await;
        })
    }

    pub fn until_checked(
        self,
        mut changes: tokio::sync::watch::Receiver<u64>,
        check: impl Fn(&AnalysisReadControl) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        let control = Arc::clone(self.session.control());
        let workers = self.workers.clone();
        let check = Arc::new(check);
        self.until(async move {
            loop {
                if changes.changed().await.is_err() {
                    return;
                }
                let Ok(control) = control.operation().map(Arc::new) else {
                    return;
                };
                let lease = workers.token();
                if workers.is_closed() {
                    return;
                }
                let stage = Arc::clone(&control);
                let check = Arc::clone(&check);
                if Engine::blocking(control, lease, move || {
                    stage.check()?;
                    check(&stage)
                })
                .await
                .is_err()
                {
                    return;
                }
            }
        })
    }

    pub fn until(self, changed: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        self.until_error(async move {
            changed.await;
            crate::Error::AuthorityChanged {
                location: snafu::location!(),
            }
        })
    }

    pub fn until_error(
        self,
        changed: impl std::future::Future<Output = crate::Error> + Send + 'static,
    ) -> Self {
        let mut subscription = self;
        let control = Arc::clone(subscription.session.control());
        let changed = Box::pin(async move {
            let error = changed.await;
            let _cancelled = control.cancel();
            error
        });
        let inner = std::mem::replace(
            &mut subscription.stream,
            Box::pin(futures_util::stream::empty()),
        );
        let stream = inner.take_until(changed);
        let workers = subscription.workers.clone();
        subscription.stream = futures_util::stream::unfold(Some(stream), move |stream| {
            let workers = workers.clone();
            async move {
                let mut stream = stream?;
                match stream.next().await {
                    Some(update) => Some((update, Some(stream))),
                    None => {
                        let reason = stream.take_result();
                        drop(stream);
                        workers.close();
                        workers.wait().await;
                        reason.map(|reason| (Err((reason, None)), None))
                    }
                }
            }
        })
        .boxed();
        subscription
    }

    pub fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&AnalysisReadControl) -> Result<T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T>> + Send + 'static {
        let control = Arc::clone(self.session.control());
        let workers = self.workers.clone();
        async move {
            let lease = workers.token();
            if workers.is_closed() {
                return InvalidSnafu {
                    field: "closed subscription worker",
                }
                .fail();
            }
            control.check()?;
            let stage = Arc::clone(&control);
            Engine::blocking(control, lease, move || {
                stage.check()?;
                operation(&stage)
            })
            .await
        }
    }

    pub fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    pub fn moving_resolution_ns(&self) -> Option<u64> {
        self.moving
    }

    pub async fn cancel_and_join(mut self) -> Result<()> {
        let result = self.cancel();
        self.workers.close();
        self.workers.wait().await;
        result
    }

    pub fn cancel(&mut self) -> Result<()> {
        self.stream = Box::pin(futures_util::stream::empty());
        self.session.control().cancel()?;
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
        let _cancelled = self.session.control().cancel();
    }
}

struct State {
    run: Arc<Run>,
    cursor: Option<Cursor>,
    started: bool,
    stream: OutputStream,
    _permit: Option<Permit>,
}

impl State {
    async fn next(&mut self) -> std::result::Result<Option<Update>, StreamError> {
        let Some(Event {
            output,
            calls,
            completed,
            revision,
            evaluated,
            clock_changed,
            completed_windows,
            exhausted,
        }) = self.stream.try_next().await?
        else {
            return Ok(None);
        };
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
            cursor
                .check_store(&snapshot.page.extraction.meta)
                .map_err(|error| (error, Some(Arc::clone(&snapshot))))?;
        }
        let mut cursor = if completed {
            Cursor::new(
                &snapshot.page.extraction.meta,
                self.run.operation,
                self.run.binding,
                position,
                evaluated,
            )
        } else {
            self.cursor.clone().ok_or_else(|| {
                (
                    crate::Error::Sql {
                        source: datafusion::common::DataFusionError::Internal(
                            "subscription cursor is absent".into(),
                        ),
                    },
                    Some(Arc::clone(&snapshot)),
                )
            })?
        };
        if completed {
            cursor.set_windows(&snapshot.windows, &completed_windows);
            if self.run.operation == Operation::Replace {
                cursor.set_revision(revision);
            }
        }
        self.started = true;
        self.cursor = Some(cursor.clone());
        Ok(Some(Update {
            snapshot,
            batches,
            calls,
            cursor,
            operation: self.run.operation,
            exhausted,
            clock_changed,
            completed_windows,
            positions,
            evaluated_utc_ns: evaluated,
            limited: limited || !exhausted,
            _memory,
        }))
    }
}
