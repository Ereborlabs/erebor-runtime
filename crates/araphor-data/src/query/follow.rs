use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};

use super::budget::QueryLease;
use super::frame::{
    QueryCheckpoint, QueryCoverageRows, QueryErrorCode, QueryFrame, QueryTerminalReason,
};
use super::{QueryOperation, QueryOwner, QueryPlan, QueryTemplate};
use crate::{AnalysisReadControl, AnalysisStoreMetaV1, Result};

/// A host clock. A clock-change signal is optional; expiry timers also sample it.
pub trait QueryClock: Send + Sync + 'static {
    fn now_ns(&self) -> Result<u64>;

    fn changes(&self) -> Option<watch::Receiver<()>> {
        None
    }
}

pub struct SystemQueryClock;

impl QueryClock for SystemQueryClock {
    fn now_ns(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| {
                crate::QueryInvalidSnafu {
                    field: "query clock",
                }
                .build()
            })
    }
}

pub struct QueryStream {
    receiver: mpsc::Receiver<QueryFrame>,
    control: Arc<AnalysisReadControl>,
    stop: watch::Sender<bool>,
    #[cfg(test)]
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl QueryStream {
    pub async fn next(&mut self) -> Option<QueryFrame> {
        self.receiver.recv().await
    }

    pub fn cancel(&self) -> Result<()> {
        self.stop.send_replace(true);
        self.control.cancel()
    }
}

impl Drop for QueryStream {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        let _cancelled = self.control.cancel();
    }
}

struct QueryFollow {
    owner: Arc<QueryOwner>,
    plan: QueryPlan,
    clock: Arc<dyn QueryClock>,
    changes: watch::Receiver<u64>,
    clock_changes: Option<watch::Receiver<()>>,
    stop: watch::Receiver<bool>,
    sender: mpsc::Sender<QueryFrame>,
    control: Arc<AnalysisReadControl>,
    checkpoint: Option<QueryCheckpoint>,
    meta: AnalysisStoreMetaV1,
    coverage: Option<Arc<QueryCoverageRows>>,
    _lease: QueryLease,
}

impl QueryOwner {
    pub fn follow(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
    ) -> Result<QueryStream> {
        self.follow_clock(plan, checkpoint, Arc::new(SystemQueryClock))
    }

    pub fn follow_clock(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        clock: Arc<dyn QueryClock>,
    ) -> Result<QueryStream> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query follow runtime",
            }
            .build()
        })?;
        let lease = self.budget.stream(plan.selection.tenant_id)?;
        // Register before the task can capture its first storage snapshot.
        let changes = self.store.subscribe_revision();
        let clock_changes = clock.changes();
        let (sender, receiver) = mpsc::channel(1);
        let (stop, stopped) = watch::channel(false);
        let control = Arc::new(AnalysisReadControl::default());
        let follow = QueryFollow {
            owner: self.clone(),
            plan,
            clock,
            changes,
            clock_changes,
            stop: stopped,
            sender,
            control: control.clone(),
            checkpoint,
            meta: self.identity.clone(),
            coverage: None,
            _lease: lease,
        };
        let _task = runtime.spawn(follow.run());
        Ok(QueryStream {
            receiver,
            control,
            stop,
            #[cfg(test)]
            task: _task,
        })
    }
}

impl QueryFollow {
    async fn run(mut self) {
        let result = match self.run_loop().await {
            Err(crate::Error::AnalysisReadCancelled { .. }) => Ok(QueryTerminalReason::Cancelled),
            result => result,
        };
        let stalled = matches!(
            &result,
            Ok(QueryTerminalReason::OutputTimeout | QueryTerminalReason::Closed)
        );
        let permit = if stalled {
            self.sender.try_reserve().ok()
        } else {
            tokio::time::timeout(self.owner.limits.output_timeout, self.sender.reserve())
                .await
                .ok()
                .and_then(std::result::Result::ok)
        };
        let Some(permit) = permit else {
            return;
        };
        let Ok(lease) = self.owner.budget.output(std::mem::size_of::<QueryFrame>()) else {
            return;
        };
        let meta = &self.meta;
        let frame = match result {
            Ok(reason) => QueryFrame::terminal(
                &self.plan,
                meta,
                reason,
                self.checkpoint.clone(),
                std::mem::take(&mut self.coverage),
            ),
            Err(ref error) => QueryFrame::error(
                &self.plan,
                meta,
                QueryErrorCode::from(error),
                self.checkpoint.clone(),
                std::mem::take(&mut self.coverage),
            ),
        };
        if let Ok(frame) = frame.and_then(|frame| {
            self.owner.check_output(frame.total_bytes()?)?;
            frame.attach_lease(lease)
        }) {
            permit.send(frame);
        }
    }

    async fn run_loop(&mut self) -> Result<QueryTerminalReason> {
        let owner = self.owner.clone();
        let meta = tokio::task::spawn_blocking(move || owner.store.meta())
            .await
            .map_err(|_| {
                crate::QueryInvalidSnafu {
                    field: "query follow task",
                }
                .build()
            })??;
        self.meta = meta.clone();
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate(&self.plan, &meta, None)?;
        }
        let mut after = self.checkpoint.as_ref().and_then(QueryCheckpoint::position);
        let mut dirty = true;
        let mut seen = None;
        let mut initial = true;
        let mut last_eval = None;
        let mut next_expiry = None;
        let mut next_health = tokio::time::Instant::now() + self.owner.limits.heartbeat;
        let mut clock_sample = None;
        let mut clock_signal = false;
        loop {
            if *self.stop.borrow() {
                return Ok(QueryTerminalReason::Cancelled);
            }
            if self.sender.is_closed() {
                return Ok(QueryTerminalReason::Closed);
            }
            let _revision = *self.changes.borrow_and_update();
            let now_ns = self.clock.now_ns()?;
            let now = tokio::time::Instant::now();
            let clock_changed = clock_signal
                || clock_sample.is_some_and(|(time, instant): (u64, tokio::time::Instant)| {
                    let elapsed =
                        u64::try_from(now.duration_since(instant).as_nanos()).unwrap_or(u64::MAX);
                    now_ns.abs_diff(time.saturating_add(elapsed)) > 1_000_000_000
                });
            clock_sample = Some((now_ns, now));
            clock_signal = false;
            let moving = matches!(self.plan.template(), QueryTemplate::MovingCount { .. });
            if moving && (clock_changed || next_expiry.is_some_and(|expiry| now_ns >= expiry)) {
                dirty = true;
            }
            let owner = self.owner.clone();
            let selection = self.plan.dependencies(now_ns);
            let control = self.control.stage(self.owner.limits.extract_timeout)?;
            let (meta, revision) = tokio::task::spawn_blocking(move || {
                owner.store.dependency_revision(&selection, &control)
            })
            .await
            .map_err(|_| {
                crate::QueryInvalidSnafu {
                    field: "query dependency task",
                }
                .build()
            })??;
            self.meta = meta;
            dirty |= seen != Some(revision);
            let ready = self.plan.operation() == QueryOperation::Append
                || last_eval.is_none_or(|last| now >= last + self.owner.limits.replace_interval);
            let mut evaluated = false;
            if dirty && ready {
                let owner = self.owner.clone();
                let plan = self.plan.clone();
                let control = self.control.stage(self.owner.limits.extract_timeout)?;
                let paged = plan.operation() == QueryOperation::Append;
                let result = tokio::task::spawn_blocking(move || {
                    owner.evaluate(&plan, now_ns, after, paged, &control)
                })
                .await
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "query evaluation task",
                    }
                    .build()
                })??;
                let checkpoint = QueryCheckpoint::from_result(&self.plan, &result)?;
                self.meta = result.meta.clone();
                self.coverage = Some(result.sources.clone());
                next_expiry = result.next_expiry_ns;
                dirty = paged && !result.exhausted;
                if initial {
                    if !self
                        .send(
                            QueryFrame::metadata_bytes(&result, &self.owner.limits)?,
                            || {
                                QueryFrame::metadata(
                                    &self.plan,
                                    &result,
                                    &self.owner.limits,
                                    revision,
                                )
                            },
                        )
                        .await?
                    {
                        return Ok(self.stop_reason());
                    }
                    initial = false;
                }
                if !self
                    .send(
                        std::mem::size_of::<QueryFrame>()
                            - std::mem::size_of::<super::QueryResult>(),
                        || {
                            let mut frame = QueryFrame::data(&self.plan, result)?;
                            frame.clock_changed = clock_changed;
                            Ok(frame)
                        },
                    )
                    .await?
                {
                    return Ok(self.stop_reason());
                }
                if !self
                    .send(std::mem::size_of::<QueryFrame>(), || {
                        QueryFrame::checkpoint(checkpoint.clone(), self.coverage.clone())
                    })
                    .await?
                {
                    return Ok(self.stop_reason());
                }
                after = checkpoint.position();
                self.checkpoint = Some(checkpoint);
                seen = Some(revision);
                last_eval = Some(tokio::time::Instant::now());
                evaluated = true;
            }
            if !initial && (tokio::time::Instant::now() >= next_health || clock_changed) {
                let owner = self.owner.clone();
                let plan = self.plan.clone();
                let control = self.control.stage(self.owner.limits.extract_timeout)?;
                let (meta, coverage, health) =
                    tokio::task::spawn_blocking(move || owner.coverage(&plan, now_ns, &control))
                        .await
                        .map_err(|_| {
                            crate::QueryInvalidSnafu {
                                field: "query health task",
                            }
                            .build()
                        })??;
                self.meta = meta.clone();
                self.coverage = Some(coverage);
                if !self
                    .send(std::mem::size_of::<QueryFrame>(), || {
                        QueryFrame::health(
                            &self.plan,
                            &meta,
                            revision,
                            self.coverage.clone(),
                            health,
                            clock_changed,
                        )
                    })
                    .await?
                {
                    return Ok(self.stop_reason());
                }
                next_health = tokio::time::Instant::now() + self.owner.limits.heartbeat;
            }
            if evaluated {
                continue;
            }
            let mut wake = next_health;
            if dirty {
                if let Some(last) = last_eval {
                    wake = wake.min(last + self.owner.limits.replace_interval);
                }
            }
            if moving && !dirty {
                if let Some(expiry) = next_expiry {
                    wake = wake.min(now + Duration::from_nanos(expiry.saturating_sub(now_ns)));
                }
            }
            tokio::select! {
                _ = self.stop.changed() => {},
                _ = self.sender.closed() => return Ok(QueryTerminalReason::Closed),
                changed = self.changes.changed() => {
                    if changed.is_err() { return Ok(QueryTerminalReason::Closed); }
                },
                changed = async {
                    match self.clock_changes.as_mut() {
                        Some(changes) => changes.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_ok() { clock_signal = true; } else { self.clock_changes = None; }
                },
                _ = tokio::time::sleep_until(wake) => {},
            }
        }
    }

    fn stop_reason(&self) -> QueryTerminalReason {
        if *self.stop.borrow() {
            QueryTerminalReason::Cancelled
        } else if self.sender.is_closed() {
            QueryTerminalReason::Closed
        } else {
            QueryTerminalReason::OutputTimeout
        }
    }

    async fn send(&self, bytes: usize, frame: impl FnOnce() -> Result<QueryFrame>) -> Result<bool> {
        if *self.stop.borrow() {
            return Ok(false);
        }
        let mut stop = self.stop.clone();
        tokio::select! {
            _ = stop.changed() => Ok(false),
            result = tokio::time::timeout(self.owner.limits.output_timeout, self.sender.reserve()) => {
                match result {
                    Ok(Ok(permit)) => {
                        let lease = self.owner.budget.output(bytes)?;
                        let frame = frame()?;
                        self.owner.check_output(frame.total_bytes()?)?;
                        permit.send(frame.attach_lease(lease)?);
                        Ok(true)
                    },
                    _ => Ok(false),
                }
            },
        }
    }
}
