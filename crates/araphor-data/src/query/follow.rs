use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_core::{stream::FusedStream, Stream};
use tokio::sync::watch;

use super::authorization::QuerySession;
use super::budget::QueryLease;
use super::frame::{
    QueryCheckpoint, QueryCoverageRows, QueryFrame, QueryPayload, QueryReadScope,
    QueryTerminalReason,
};
use super::{
    QueryAuthorization, QueryOperation, QueryOwner, QueryPlan, QueryRead, QueryResult,
    QueryTemplate,
};
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

type QueryNext = Pin<Box<dyn Future<Output = (QueryState, Result<Option<QueryFrame>>)> + Send>>;

pub struct QueryStream {
    state: Option<QueryState>,
    next: Option<QueryNext>,
    control: Arc<AnalysisReadControl>,
    stop: watch::Sender<bool>,
    session: Option<QuerySession>,
    done: bool,
    checking: Option<Pin<Box<dyn Future<Output = Result<QueryFrame>> + Send>>>,
    lease: Option<Arc<QueryLease>>,
}

impl QueryStream {
    pub fn cancel(&self) -> Result<()> {
        self.stop.send_replace(true);
        self.control.cancel()
    }

    fn close(&mut self) {
        self.done = true;
        self.next = None;
        self.checking = None;
        self.state = None;
        self.lease = None;
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
        if tokio::runtime::Handle::try_current().is_err() {
            self.close();
            return Poll::Ready(Some(
                crate::QueryInvalidSnafu {
                    field: "query follow runtime",
                }
                .fail(),
            ));
        }
        let frame = if let Some(pending) = self.checking.as_mut() {
            match pending.as_mut().poll(context) {
                Poll::Ready(result) => {
                    self.checking = None;
                    Poll::Ready(Some(result))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            if self.next.is_none() {
                let Some(state) = self.state.take() else {
                    self.close();
                    return Poll::Ready(None);
                };
                self.next = Some(Box::pin(Self::advance(state)));
            }
            let Some(next) = self.next.as_mut() else {
                self.close();
                return Poll::Ready(Some(
                    crate::QueryInvalidSnafu {
                        field: "query next frame",
                    }
                    .fail(),
                ));
            };
            let result = match next.as_mut().poll(context) {
                Poll::Ready((state, result)) => {
                    self.next = None;
                    self.state = Some(state);
                    result
                }
                Poll::Pending => return Poll::Pending,
            };
            match result {
                Ok(Some(frame)) if frame.reads.is_some() => {
                    let lease = self.lease.clone();
                    let session = self.session.clone();
                    let mut stop = self.stop.subscribe();
                    let cancelled = matches!(
                        frame.payload,
                        QueryPayload::Terminal {
                            reason: QueryTerminalReason::Cancelled,
                            ..
                        }
                    );
                    self.checking = Some(Box::pin(async move {
                        {
                            let check = frame.check_stream(lease);
                            tokio::pin!(check);
                            let mut changes =
                                session.as_ref().map(|session| session.authority.changes());
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = stop.changed(), if !cancelled => {
                                        return crate::AnalysisReadCancelledSnafu.fail();
                                    },
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
                Ok(Some(frame)) => Poll::Ready(Some(Ok(frame))),
                Ok(None) => Poll::Ready(None),
                Err(error) => Poll::Ready(Some(Err(error))),
            }
        };
        if let Some(session) = &self.session {
            if let Err(error) = session.check() {
                self.close();
                return Poll::Ready(Some(Err(error)));
            }
        }
        match frame {
            Poll::Ready(Some(Ok(frame))) => {
                if let QueryPayload::Checkpoint { checkpoint, .. } = &frame.payload {
                    if let Some(state) = self.state.as_mut() {
                        state.after = checkpoint.position();
                        state.checkpoint = Some(checkpoint.clone());
                        state.seen = Some(state.revision);
                        state.last_eval = Some(tokio::time::Instant::now());
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.close();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.close();
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

#[derive(Clone, Copy)]
enum QueryYield {
    Idle,
    Metadata,
    Data,
    Checkpoint,
}

struct QueryState {
    owner: Arc<QueryOwner>,
    plan: QueryPlan,
    clock: Arc<dyn QueryClock>,
    changes: watch::Receiver<u64>,
    clock_changes: Option<watch::Receiver<()>>,
    stop: watch::Receiver<bool>,
    control: Arc<AnalysisReadControl>,
    checkpoint: Option<QueryCheckpoint>,
    meta: AnalysisStoreMetaV1,
    coverage: Option<Arc<QueryCoverageRows>>,
    reads: Option<Arc<QueryReadScope>>,
    session: Option<QuerySession>,
    auth_changes: Option<watch::Receiver<u64>>,
    follows: bool,
    started: bool,
    finished: bool,
    after: Option<crate::StorePositionV1>,
    dirty: bool,
    seen: Option<u64>,
    initial: bool,
    last_eval: Option<tokio::time::Instant>,
    next_expiry: Option<u64>,
    next_health: tokio::time::Instant,
    clock_sample: Option<(u64, tokio::time::Instant)>,
    clock_signal: bool,
    clock_changed: bool,
    revision: u64,
    result: Option<QueryResult>,
    candidate: Option<QueryCheckpoint>,
    exhausted: bool,
    yielding: QueryYield,
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
        let lease = Arc::new(self.budget.stream(plan.selection.tenant_id)?);
        // Register before the first poll can capture storage state.
        let changes = self.store.subscribe_revision();
        let clock_changes = clock.changes();
        let (stop, stopped) = watch::channel(false);
        let control = Arc::new(AnalysisReadControl::default());
        let auth_changes = session.as_ref().map(|session| session.authority.changes());
        let follows = match &plan.template {
            QueryTemplate::Client(sql) => sql.follow(),
            _ => true,
        };
        let after = checkpoint.as_ref().and_then(QueryCheckpoint::position);
        let state = QueryState {
            owner: self.clone(),
            plan,
            clock,
            changes,
            clock_changes,
            stop: stopped,
            control: control.clone(),
            checkpoint,
            meta: self.identity.clone(),
            coverage: None,
            reads: None,
            session: session.clone(),
            auth_changes,
            follows,
            after,
            started: false,
            finished: false,
            dirty: true,
            seen: None,
            initial: true,
            last_eval: None,
            next_expiry: None,
            next_health: tokio::time::Instant::now() + self.limits.heartbeat,
            clock_sample: None,
            clock_signal: false,
            clock_changed: false,
            revision: 0,
            result: None,
            candidate: None,
            exhausted: false,
            yielding: QueryYield::Idle,
        };
        Ok(QueryStream {
            state: Some(state),
            next: None,
            control,
            stop,
            session,
            done: false,
            checking: None,
            lease: Some(lease),
        })
    }
}

impl QueryStream {
    async fn advance(mut state: QueryState) -> (QueryState, Result<Option<QueryFrame>>) {
        if state.finished {
            return (state, Ok(None));
        }
        let mut stop = state.stop.clone();
        let mut changes = state.auth_changes.clone();
        let session = state.session.clone();
        let result = {
            let next = Self::next_frame(&mut state);
            tokio::pin!(next);
            loop {
                if *stop.borrow() {
                    break crate::AnalysisReadCancelledSnafu.fail();
                }
                if let Some(session) = &session {
                    if let Err(error) = session.check() {
                        break Err(error);
                    }
                }
                tokio::select! {
                    result = &mut next => break result,
                    _ = stop.changed() => {},
                    changed = async {
                        match changes.as_mut() {
                            Some(changes) => changes.changed().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if changed.is_err() { break crate::QueryDeniedSnafu.fail(); }
                    },
                }
            }
        };
        let result = match result {
            Err(crate::Error::AnalysisReadCancelled { .. }) => {
                Self::finish(&mut state, Ok(QueryTerminalReason::Cancelled))
            }
            Err(error @ crate::Error::QueryDenied { .. }) => Err(error),
            Err(error) => Self::finish(&mut state, Err(error)),
            result => result,
        };
        (state, result)
    }

    async fn next_frame(state: &mut QueryState) -> Result<Option<QueryFrame>> {
        if state.finished {
            return Ok(None);
        }
        if !state.started {
            let owner = state.owner.clone();
            let meta = tokio::task::spawn_blocking(move || owner.store.meta())
                .await
                .map_err(|_| {
                    crate::QueryInvalidSnafu {
                        field: "query follow task",
                    }
                    .build()
                })??;
            if let Some(checkpoint) = &state.checkpoint {
                checkpoint.validate(&state.plan, &meta, None)?;
            }
            state.meta = meta;
            state.started = true;
            state.next_health = tokio::time::Instant::now() + state.owner.limits.heartbeat;
        }
        loop {
            Self::check_auth(state)?;
            match state.yielding {
                QueryYield::Metadata => {
                    let result = state.result.as_ref().ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "staged query result",
                        }
                        .build()
                    })?;
                    let bytes = QueryFrame::metadata_bytes(result, &state.owner.limits)?;
                    state.yielding = QueryYield::Data;
                    state.initial = false;
                    return Self::emit(state, bytes, || {
                        QueryFrame::metadata(
                            &state.plan,
                            result,
                            &state.owner.limits,
                            state.revision,
                        )
                    });
                }
                QueryYield::Data => {
                    let result = state.result.take().ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "staged query result",
                        }
                        .build()
                    })?;
                    state.yielding = QueryYield::Checkpoint;
                    return Self::emit(
                        state,
                        std::mem::size_of::<QueryFrame>() - std::mem::size_of::<QueryResult>(),
                        || {
                            let mut frame = QueryFrame::data(&state.plan, result)?;
                            frame.clock_changed = state.clock_changed;
                            Ok(frame)
                        },
                    );
                }
                QueryYield::Checkpoint => {
                    let checkpoint = state.candidate.take().ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "staged query checkpoint",
                        }
                        .build()
                    })?;
                    state.yielding = QueryYield::Idle;
                    return Self::emit(state, std::mem::size_of::<QueryFrame>(), || {
                        QueryFrame::checkpoint(checkpoint, state.coverage.clone(), state.exhausted)
                    });
                }
                QueryYield::Idle => {}
            }
            if !state.initial && !state.follows {
                return Self::finish(state, Ok(QueryTerminalReason::Completed));
            }
            let _revision = *state.changes.borrow_and_update();
            let now_ns = state.clock.now_ns()?;
            let now = tokio::time::Instant::now();
            let clock_changed = state.clock_signal
                || state.clock_sample.is_some_and(|(time, instant)| {
                    let elapsed =
                        u64::try_from(now.duration_since(instant).as_nanos()).unwrap_or(u64::MAX);
                    now_ns.abs_diff(time.saturating_add(elapsed)) > 1_000_000_000
                });
            state.clock_sample = Some((now_ns, now));
            state.clock_signal = false;
            let moving = state.plan.moving_seconds().is_some();
            if moving && (clock_changed || state.next_expiry.is_some_and(|expiry| now_ns >= expiry))
            {
                state.dirty = true;
            }
            let owner = state.owner.clone();
            let selection = state.plan.dependencies(now_ns)?;
            let control = state.control.stage(state.owner.limits.extract_timeout)?;
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
            state.meta = meta;
            state.dirty |= state.seen != Some(revision);
            let ready = state.plan.operation() == QueryOperation::Append
                || state
                    .last_eval
                    .is_none_or(|last| now >= last + state.owner.limits.replace_interval);
            if state.dirty && ready {
                let owner = state.owner.clone();
                let plan = state.plan.clone();
                let control = state.control.stage(state.owner.limits.extract_timeout)?;
                let paged = state.follows && plan.operation() == QueryOperation::Append;
                let lease = Self::reserve(state, &control).await?;
                let read = if paged {
                    QueryRead::Append(state.after)
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
                        state.session.clone(),
                    )
                    .await?;
                state.candidate = Some(QueryCheckpoint::from_result(&state.plan, &result)?);
                state.exhausted = result.exhausted;
                state.meta = result.meta.clone();
                state.coverage = Some(result.sources.clone());
                state.reads = result.reads.clone();
                state.next_expiry = result.next_expiry_ns;
                state.dirty = paged && !result.exhausted;
                state.revision = revision;
                state.clock_changed = clock_changed;
                state.result = Some(result);
                state.yielding = if state.initial {
                    QueryYield::Metadata
                } else {
                    QueryYield::Data
                };
                continue;
            }
            if !state.initial && (tokio::time::Instant::now() >= state.next_health || clock_changed)
            {
                let owner = state.owner.clone();
                let plan = state.plan.clone();
                let control = state.control.stage(state.owner.limits.extract_timeout)?;
                let lease = Self::reserve(state, &control).await?;
                let session = state.session.clone();
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
                state.meta = meta.clone();
                state.coverage = Some(coverage);
                state.next_health = tokio::time::Instant::now() + state.owner.limits.heartbeat;
                return Self::emit(state, std::mem::size_of::<QueryFrame>(), || {
                    QueryFrame::health(
                        &state.plan,
                        &meta,
                        revision,
                        state.coverage.clone(),
                        health,
                        clock_changed,
                    )
                });
            }
            let mut wake = state.next_health;
            if let Some(expiry) = state
                .session
                .as_ref()
                .and_then(|session| session.authority.expires_ns())
            {
                wake = wake.min(now + Duration::from_nanos(expiry.saturating_sub(now_ns)));
            }
            if state.dirty {
                if let Some(last) = state.last_eval {
                    wake = wake.min(last + state.owner.limits.replace_interval);
                }
            }
            if moving && !state.dirty {
                if let Some(expiry) = state.next_expiry {
                    wake = wake.min(now + Duration::from_nanos(expiry.saturating_sub(now_ns)));
                }
            }
            tokio::select! {
                changed = state.changes.changed() => {
                    if changed.is_err() { return Self::finish(state, Ok(QueryTerminalReason::Closed)); }
                },
                changed = async {
                    match state.auth_changes.as_mut() {
                        Some(changes) => changes.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_err() { return crate::QueryDeniedSnafu.fail(); }
                },
                changed = async {
                    match state.clock_changes.as_mut() {
                        Some(changes) => changes.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_ok() { state.clock_signal = true; } else { state.clock_changes = None; }
                },
                _ = tokio::time::sleep_until(wake) => {},
            }
        }
    }

    fn emit(
        state: &QueryState,
        bytes: usize,
        create: impl FnOnce() -> Result<QueryFrame>,
    ) -> Result<Option<QueryFrame>> {
        Self::check_auth(state)?;
        let lease = state.owner.budget.output(bytes)?;
        let mut frame = create()?;
        frame.reads = state.reads.clone();
        state.owner.check_output(frame.total_bytes()?)?;
        Ok(Some(frame.attach_lease(lease)?))
    }

    fn finish(
        state: &mut QueryState,
        result: Result<QueryTerminalReason>,
    ) -> Result<Option<QueryFrame>> {
        state.finished = true;
        state.result = None;
        state.candidate = None;
        Self::check_auth(state)?;
        let coverage = state.coverage.take();
        Self::emit(state, std::mem::size_of::<QueryFrame>(), || match result {
            Ok(reason) => QueryFrame::terminal(
                &state.plan,
                &state.meta,
                reason,
                state.checkpoint.clone(),
                coverage,
            ),
            Err(ref error) => QueryFrame::error(
                &state.plan,
                &state.meta,
                error,
                state.checkpoint.clone(),
                coverage,
            ),
        })
    }

    async fn reserve(state: &QueryState, control: &AnalysisReadControl) -> Result<QueryLease> {
        let wait = state.owner.reserve_wait(&state.plan);
        let deadline = tokio::time::sleep(control.remaining()?);
        tokio::pin!(wait, deadline);
        tokio::select! {
            result = &mut wait => {
                let lease = result?;
                Self::check_auth(state)?;
                control.check()?;
                Ok(lease)
            },
            _ = &mut deadline => crate::AnalysisReadDeadlineSnafu.fail(),
        }
    }

    fn check_auth(state: &QueryState) -> Result<()> {
        if let Some(session) = &state.session {
            session.check()?;
        }
        Ok(())
    }
}
