use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, StorePositionV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;
use futures_core::Stream;
use futures_util::{StreamExt as _, TryStreamExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::execution::{Engine, Permit};
use crate::sources::ArrowSnapshot;
use crate::stream::physical::{Fingerprint, SubscribeExec};
use crate::stream::{Event, Output, OutputStream, Run};
use crate::{InvalidSnafu, Result, SqlSnafu};

mod clock;
mod cursor;
mod delivery;
mod window;

#[cfg(test)]
mod tests;

pub use crate::stream::progress::{Progress, Wake};
pub use clock::{Clock, SystemClock};
pub use cursor::Cursor;
pub use delivery::{Action, Consumer, Delivery};
pub(crate) use window::Window;

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
        sources: AnalysisTableRequests,
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
                    .keys()
                    .any(|name| matches!(name.as_str(), "graph_subjects" | "relationships"))
                || sources.keys().any(|name| {
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
        let source_clock = sources.contains_key("notifications");
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
        let permit = engine.reserve_stream(selection.tenant_id)?;
        let run = Arc::new(Run {
            engine: Arc::clone(&engine),
            plan,
            sources,
            selection,
            control: Arc::clone(&control),
            clock,
            follow,
            operation,
            window,
            resume: resume.clone(),
        });
        let execution = Arc::clone(&run);
        let stream =
            futures_util::stream::once(async move { SubscribeExec::open(execution).await })
                .try_flatten();
        let state = State {
            run,
            binding,
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
                Err(mut error) => {
                    let receipt = if !state.started
                        && state.cursor.is_some()
                        && crate::Failure::from(&error) == crate::Failure::CursorExpired
                    {
                        let capture = async {
                            let now = state.run.clock.now_ns()?;
                            let control = AnalysisReadControl::with_timeout(
                                state.run.engine.limits().extract_timeout,
                            )?;
                            state
                                .run
                                .engine
                                .metadata(
                                    state.run.selection.clone(),
                                    &state.run.sources,
                                    &control,
                                    now,
                                )
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
    run: Arc<Run>,
    binding: [u8; 32],
    cursor: Option<Cursor>,
    started: bool,
    stream: OutputStream,
    _permit: Permit,
}

impl State {
    async fn next(&mut self) -> Result<Option<Update>> {
        let Some(Event {
            output,
            completed,
            evaluated,
            clock_changed,
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
            cursor.check_store(&snapshot.page.extraction.meta)?;
        }
        let cursor = if completed {
            Cursor::new(
                &snapshot.page.extraction.meta,
                self.run.operation,
                self.binding,
                position,
                evaluated,
            )
        } else {
            self.cursor.clone().ok_or_else(|| crate::Error::Sql {
                source: datafusion::common::DataFusionError::Internal(
                    "subscription cursor is absent".into(),
                ),
            })?
        };
        self.started = true;
        self.cursor = Some(cursor.clone());
        Ok(Some(Update {
            snapshot,
            batches,
            cursor,
            operation: self.run.operation,
            exhausted,
            clock_changed,
            positions,
            evaluated_utc_ns: evaluated,
            limited: limited || !exhausted,
            _memory,
        }))
    }
}
