use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_core::{stream::FusedStream, Stream};
use tokio::sync::{mpsc, watch};

use super::authorization::QuerySession;
use super::budget::QueryLease;
use super::frame::{
    QueryCheckpoint, QueryCoverageRows, QueryFrame, QueryReadScope, QueryTerminalReason,
};
use super::{QueryAuthorization, QueryOperation, QueryOwner, QueryPlan, QueryRead, QueryTemplate};
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
    session: Option<QuerySession>,
    done: bool,
    pending: Option<Pin<Box<dyn Future<Output = Result<QueryFrame>> + Send>>>,
    lease: Option<Arc<QueryLease>>,
    #[cfg(test)]
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl QueryStream {
    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.receiver.len()
    }

    pub fn cancel(&self) -> Result<()> {
        self.stop.send_replace(true);
        self.control.cancel()
    }

    fn close(&mut self) {
        self.done = true;
        self.receiver.close();
        self.pending = None;
        self.lease = None;
        while let Ok(frame) = self.receiver.try_recv() {
            drop(frame);
        }
        let _cancelled = self.cancel();
    }
}

impl Stream for QueryStream {
    type Item = Result<QueryFrame>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(session) = &self.session {
            if let Err(error) = session.check() {
                self.close();
                return Poll::Ready(Some(Err(error)));
            }
        }
        let frame = if let Some(pending) = self.pending.as_mut() {
            match pending.as_mut().poll(context) {
                Poll::Ready(result) => {
                    self.pending = None;
                    Poll::Ready(Some(result))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            match self.receiver.poll_recv(context) {
                Poll::Ready(Some(frame)) if frame.reads.is_some() => {
                    let lease = self.lease.clone();
                    let session = self.session.clone();
                    self.pending = Some(Box::pin(async move {
                        {
                            let check = frame.check_stream(lease);
                            tokio::pin!(check);
                            let mut changes =
                                session.as_ref().map(|session| session.authority.changes());
                            loop {
                                tokio::select! {
                                    result = &mut check => { result?; break; },
                                    changed = async {
                                        match changes.as_mut() {
                                            Some(changes) => changes.changed().await,
                                            None => std::future::pending().await,
                                        }
                                    } => {
                                        if changed.is_err() { return crate::QueryDeniedSnafu.fail(); }
                                        if let Some(session) = &session { session.check()?; }
                                    },
                                }
                            }
                        }
                        if let Some(session) = &session {
                            session.check()?;
                        }
                        Ok(frame)
                    }));
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        };
        if let Some(session) = &self.session {
            if let Err(error) = session.check() {
                self.close();
                return Poll::Ready(Some(Err(error)));
            }
        }
        match frame {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                self.close();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.done = true;
                self.lease = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl FusedStream for QueryStream {
    fn is_terminated(&self) -> bool {
        self.done
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
    reads: Option<Arc<QueryReadScope>>,
    session: Option<QuerySession>,
    auth_changes: Option<watch::Receiver<u64>>,
    follows: bool,
    _lease: Arc<QueryLease>,
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
        if plan.grant.is_some() {
            return crate::QueryDeniedSnafu.fail();
        }
        self.follow_inner(plan, checkpoint, clock, None)
    }

    pub fn follow_client(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        authority: Arc<dyn QueryAuthorization>,
    ) -> Result<QueryStream> {
        self.follow_client_clock(plan, checkpoint, authority, Arc::new(SystemQueryClock))
    }

    pub fn follow_client_clock(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        authority: Arc<dyn QueryAuthorization>,
        clock: Arc<dyn QueryClock>,
    ) -> Result<QueryStream> {
        if !matches!(&plan.template, QueryTemplate::Client(sql) if sql.follow()) {
            return crate::QueryDeniedSnafu.fail();
        }
        self.stream_client_clock(plan, checkpoint, authority, clock)
    }

    pub fn stream_client(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        authority: Arc<dyn QueryAuthorization>,
    ) -> Result<QueryStream> {
        self.stream_client_clock(plan, checkpoint, authority, Arc::new(SystemQueryClock))
    }

    pub fn stream_client_clock(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        authority: Arc<dyn QueryAuthorization>,
        clock: Arc<dyn QueryClock>,
    ) -> Result<QueryStream> {
        let QueryTemplate::Client(sql) = &plan.template else {
            return crate::QueryDeniedSnafu.fail();
        };
        if !sql.follow() && checkpoint.is_some() {
            return crate::QueryInvalidSnafu {
                field: "checkpoint requires follow",
            }
            .fail();
        }
        let grant = plan
            .grant
            .clone()
            .ok_or_else(|| crate::QueryDeniedSnafu.build())?;
        authority.check(&grant)?;
        self.limits.client_capacity()?;
        self.follow_inner(
            plan,
            checkpoint,
            clock,
            Some(QuerySession { authority, grant }),
        )
    }

    fn follow_inner(
        self: &Arc<Self>,
        plan: QueryPlan,
        checkpoint: Option<QueryCheckpoint>,
        clock: Arc<dyn QueryClock>,
        session: Option<QuerySession>,
    ) -> Result<QueryStream> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            crate::QueryInvalidSnafu {
                field: "query follow runtime",
            }
            .build()
        })?;
        let lease = Arc::new(self.budget.stream(plan.selection.tenant_id)?);
        // Register before the task can capture its first storage snapshot.
        let changes = self.store.subscribe_revision();
        let clock_changes = clock.changes();
        let (sender, receiver) = mpsc::channel(1);
        let (stop, stopped) = watch::channel(false);
        let control = Arc::new(AnalysisReadControl::default());
        let auth_changes = session.as_ref().map(|session| session.authority.changes());
        let follows = match &plan.template {
            QueryTemplate::Client(sql) => sql.follow(),
            _ => true,
        };
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
            reads: None,
            session: session.clone(),
            auth_changes,
            follows,
            _lease: lease.clone(),
        };
        let _task = runtime.spawn(follow.run());
        Ok(QueryStream {
            receiver,
            control,
            stop,
            session,
            done: false,
            pending: None,
            lease: Some(lease),
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
        if matches!(result, Err(crate::Error::QueryDenied { .. })) {
            self.coverage = None;
            self.reads = None;
            self.checkpoint = None;
        }
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
        if self.check_auth().is_err() {
            return;
        }
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
                error,
                self.checkpoint.clone(),
                std::mem::take(&mut self.coverage),
            ),
        };
        if let Ok(frame) = frame.and_then(|mut frame| {
            frame.reads = self.reads.clone();
            self.owner.check_output(frame.total_bytes()?)?;
            frame.attach_lease(lease)
        }) {
            if self.check_auth().is_err() {
                return;
            }
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
            self.check_auth()?;
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
            let moving = self.plan.moving_seconds().is_some();
            if moving && (clock_changed || next_expiry.is_some_and(|expiry| now_ns >= expiry)) {
                dirty = true;
            }
            let owner = self.owner.clone();
            let selection = self.plan.dependencies(now_ns)?;
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
                let paged = self.follows && plan.operation() == QueryOperation::Append;
                let lease = self.reserve(&control).await?;
                let read = if paged {
                    QueryRead::Append(after)
                } else {
                    QueryRead::Snapshot
                };
                let result = owner
                    .evaluate_reserved(
                        plan,
                        now_ns,
                        read,
                        Arc::new(control),
                        lease,
                        self.session.clone(),
                    )
                    .await?;
                let checkpoint = QueryCheckpoint::from_result(&self.plan, &result)?;
                let exhausted = result.exhausted;
                self.meta = result.meta.clone();
                self.coverage = Some(result.sources.clone());
                self.reads = result.reads.clone();
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
                        QueryFrame::checkpoint(checkpoint.clone(), self.coverage.clone(), exhausted)
                    })
                    .await?
                {
                    return Ok(self.stop_reason());
                }
                after = checkpoint.position();
                self.checkpoint = Some(checkpoint);
                seen = Some(revision);
                last_eval = Some(tokio::time::Instant::now());
                if !self.follows {
                    return Ok(QueryTerminalReason::Completed);
                }
                evaluated = true;
            }
            if !initial && (tokio::time::Instant::now() >= next_health || clock_changed) {
                let owner = self.owner.clone();
                let plan = self.plan.clone();
                let control = self.control.stage(self.owner.limits.extract_timeout)?;
                let lease = self.reserve(&control).await?;
                let session = self.session.clone();
                let (meta, coverage, health) = tokio::task::spawn_blocking(move || {
                    control.check()?;
                    if let Some(session) = &session {
                        session.check()?;
                    }
                    owner.coverage(&plan, now_ns, &control, lease)
                })
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
            if let Some(expiry) = self
                .session
                .as_ref()
                .and_then(|session| session.authority.expires_ns())
            {
                wake = wake.min(now + Duration::from_nanos(expiry.saturating_sub(now_ns)));
            }
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
                    match self.auth_changes.as_mut() {
                        Some(changes) => changes.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_err() { return crate::QueryDeniedSnafu.fail(); }
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

    async fn reserve(&mut self, control: &AnalysisReadControl) -> Result<QueryLease> {
        let owner = self.owner.clone();
        let plan = self.plan.clone();
        let wait = owner.reserve_wait(&plan);
        let deadline = tokio::time::sleep(control.remaining()?);
        tokio::pin!(wait, deadline);
        loop {
            self.check_auth()?;
            control.check()?;
            if *self.stop.borrow() || self.sender.is_closed() {
                return crate::AnalysisReadCancelledSnafu.fail();
            }
            tokio::select! {
                result = &mut wait => {
                    let lease = result?;
                    self.check_auth()?;
                    control.check()?;
                    if *self.stop.borrow() || self.sender.is_closed() {
                        return crate::AnalysisReadCancelledSnafu.fail();
                    }
                    return Ok(lease);
                },
                _ = &mut deadline => return crate::AnalysisReadDeadlineSnafu.fail(),
                _ = self.stop.changed() => return crate::AnalysisReadCancelledSnafu.fail(),
                _ = self.sender.closed() => return crate::AnalysisReadCancelledSnafu.fail(),
                changed = async {
                    match self.auth_changes.as_mut() {
                        Some(changes) => changes.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_err() { return crate::QueryDeniedSnafu.fail(); }
                },
            }
        }
    }

    async fn send(&self, bytes: usize, frame: impl FnOnce() -> Result<QueryFrame>) -> Result<bool> {
        self.check_auth()?;
        if *self.stop.borrow() {
            return Ok(false);
        }
        let mut stop = self.stop.clone();
        tokio::select! {
            _ = stop.changed() => Ok(false),
            result = tokio::time::timeout(self.owner.limits.output_timeout, self.sender.reserve()) => {
                match result {
                    Ok(Ok(permit)) => {
                        self.check_auth()?;
                        let lease = self.owner.budget.output(bytes)?;
                        let mut frame = frame()?;
                        frame.reads = self.reads.clone();
                        self.owner.check_output(frame.total_bytes()?)?;
                        permit.send(frame.attach_lease(lease)?);
                        Ok(true)
                    },
                    _ => Ok(false),
                }
            },
        }
    }

    fn check_auth(&self) -> Result<()> {
        if let Some(session) = &self.session {
            session.check()?;
        }
        Ok(())
    }
}
