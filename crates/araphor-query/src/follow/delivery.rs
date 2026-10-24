use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use araphor_data::StorageHealthV1;
use datafusion::error::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use futures_core::Stream;
use tokio::sync::watch;
use tokio::time::{Instant, Sleep};

use super::{Cursor, Operation, Subscription, Update};
use crate::execution::Session;
use crate::sources::ArrowSnapshot;
use crate::{Error, Failure, Result};

pub enum Action<'a> {
    Metadata,
    Row(usize),
    Checkpoint,
    Health(StorageHealthV1),
    Error {
        failure: Failure,
        cause: Option<&'a Error>,
        last: Option<&'a Cursor>,
    },
    Complete {
        last: Option<&'a Cursor>,
    },
}

pub trait Consumer: Send + Unpin + 'static {
    type Item: Send;
    type Error: Send;

    fn authorize(&self) -> std::result::Result<(), Self::Error>;
    fn changes(&self) -> watch::Receiver<u64>;
    fn expires(&self) -> Instant;
    fn expired(&self) -> Self::Error;
    fn code(&self, failure: Failure) -> Self::Error;
    fn rows(&self, update: &Update) -> usize;
    fn encode(
        &mut self,
        action: Action<'_>,
        receipt: &Update,
        memory: &mut MemoryReservation,
    ) -> std::result::Result<Self::Item, Self::Error>;
    fn initial_error(
        &mut self,
        failure: Failure,
        cause: &Error,
        snapshot: &ArrowSnapshot,
        operation: Operation,
        memory: &mut MemoryReservation,
    ) -> std::result::Result<Self::Item, Self::Error>;
    fn complete_after_checkpoint(&self, update: &Update) -> bool;
    fn deadline_completes(&self) -> bool;
}

#[derive(Clone, Copy)]
enum Phase {
    Metadata,
    Row,
    Checkpoint,
    Health,
    Error,
    Complete,
}

type ReadCheck = Pin<Box<dyn Future<Output = Result<Option<StorageHealthV1>>> + Send>>;
type AuthChange = Pin<Box<dyn Future<Output = Option<watch::Receiver<u64>>> + Send>>;

pub struct Delivery<C: Consumer> {
    inner: Option<Subscription>,
    session: Arc<Session>,
    consumer: Option<C>,
    update: Option<Update>,
    last: Option<Update>,
    error_receipt: Option<(Arc<ArrowSnapshot>, Operation)>,
    cursor: Option<Cursor>,
    phase: Option<Phase>,
    row: usize,
    metadata: bool,
    pending_rows: bool,
    checking: Option<ReadCheck>,
    changes: Option<AuthChange>,
    expiry: Pin<Box<Sleep>>,
    deadline: Option<Pin<Box<Sleep>>>,
    ended: bool,
    idle: Option<Instant>,
    timeout: Option<Duration>,
    conversion: MemoryReservation,
    initial: Option<MemoryReservation>,
    failure: Option<(Failure, Option<Error>)>,
    pending: Option<C::Error>,
    done: bool,
}

impl<C: Consumer> Unpin for Delivery<C> {}

impl<C: Consumer> Delivery<C> {
    pub fn new(
        inner: Subscription,
        consumer: C,
        deadline: Option<Instant>,
        output_timeout: Option<Duration>,
        initial: Option<MemoryReservation>,
    ) -> Result<Self> {
        if output_timeout.is_some_and(|timeout| {
            timeout.is_zero() || Instant::now().checked_add(timeout).is_none()
        }) {
            return crate::InvalidSnafu {
                field: "output timeout",
            }
            .fail();
        }
        let conversion = inner
            .session
            .memory()
            .reserve_output(0)
            .map_err(|source| Error::Sql { source })?;
        let changes = Some(Self::changes(consumer.changes()));
        let expiry = Box::pin(tokio::time::sleep_until(consumer.expires()));
        Ok(Self {
            session: Arc::clone(&inner.session),
            cursor: inner.resume.clone(),
            inner: Some(inner),
            consumer: Some(consumer),
            update: None,
            last: None,
            error_receipt: None,
            phase: None,
            row: 0,
            metadata: false,
            pending_rows: false,
            checking: None,
            changes,
            expiry,
            deadline: deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
            ended: false,
            idle: None,
            timeout: output_timeout,
            conversion,
            initial,
            failure: None,
            pending: None,
            done: false,
        })
    }

    pub fn set_deadline(&mut self, deadline: Instant) {
        match self.deadline.as_mut() {
            Some(current) if deadline < current.deadline() => current.as_mut().reset(deadline),
            None => self.deadline = Some(Box::pin(tokio::time::sleep_until(deadline))),
            _ => {}
        }
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn holds_output(&self) -> bool {
        self.update
            .as_ref()
            .is_some_and(|update| update.batches.is_some())
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn frame_bytes(&self) -> usize {
        self.conversion.size()
    }

    fn changes(mut changes: watch::Receiver<u64>) -> AuthChange {
        Box::pin(async move {
            changes.changed().await.ok()?;
            changes.borrow_and_update();
            Some(changes)
        })
    }

    fn stop(&mut self) {
        self.inner = None;
        self.update = None;
        self.last = None;
        self.error_receipt = None;
        self.checking = None;
        self.initial = None;
        self.failure = None;
        let _cancelled = self.session.control().cancel();
    }

    fn finish(&mut self, error: C::Error) -> Poll<Option<std::result::Result<C::Item, C::Error>>> {
        self.done = true;
        self.consumer = None;
        self.stop();
        self.conversion.free();
        Poll::Ready(Some(Err(error)))
    }

    fn discard_rows(update: &mut Update) {
        update.batches = None;
        update.calls.clear();
        update.positions = Vec::new();
        update._memory.free();
    }

    fn internal(
        &mut self,
        consumer: &C,
        reason: &'static str,
    ) -> Poll<Option<std::result::Result<C::Item, C::Error>>> {
        let error = Error::Sql {
            source: DataFusionError::Internal(reason.into()),
        };
        self.finish(consumer.code(Failure::from(&error)))
    }

    fn check(&mut self, health: bool) -> bool {
        let engine = Arc::clone(self.session.engine());
        let snapshot = self
            .update
            .as_ref()
            .or(self.last.as_ref())
            .map(|receipt| &receipt.snapshot)
            .or_else(|| self.error_receipt.as_ref().map(|(snapshot, _)| snapshot));
        let Some(snapshot) = snapshot else {
            return false;
        };
        let snapshot = Arc::clone(snapshot);
        self.checking = Some(Box::pin(async move {
            let health = if health {
                let store = Arc::clone(engine.store());
                Some(
                    tokio::task::spawn_blocking(move || store.storage_health())
                        .await
                        .map_err(|source| Error::Sql {
                            source: DataFusionError::External(Box::new(source)),
                        })??,
                )
            } else {
                None
            };
            engine.check_read(&snapshot).await?;
            Ok(health)
        }));
        true
    }
}

impl<C: Consumer> Delivery<C> {
    fn poll_delivery(
        &mut self,
        consumer: &mut C,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<C::Item, C::Error>>> {
        let this = self;
        if let Err(error) = consumer.authorize() {
            return this.finish(error);
        }
        if let Some(changes) = this.changes.as_mut() {
            if let Poll::Ready(changes) = changes.as_mut().poll(context) {
                this.changes = changes.map(Self::changes);
                if let Err(error) = consumer.authorize() {
                    return this.finish(error);
                }
            }
        }
        if this.expiry.as_mut().poll(context).is_ready() {
            let error = consumer.expired();
            return this.finish(error);
        }
        if let Some(error) = this.pending.take() {
            return this.finish(error);
        }
        if this
            .idle
            .take()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            let error = consumer.code(Failure::OutputTimeout);
            return this.finish(error);
        }
        if !this.ended
            && this
                .deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
        {
            this.ended = true;
            this.inner = None;
            this.checking = None;
            if consumer.deadline_completes() && (this.update.is_some() || this.last.is_some()) {
                if let Some(update) = this.update.as_mut() {
                    if update.batches.is_some() {
                        update.exhausted = false;
                    }
                    Self::discard_rows(update);
                }
                this.phase = Some(Phase::Complete);
            } else if this.last.is_some() {
                this.update = None;
                if this.pending_rows {
                    this.failure = Some((Failure::DeadlineExceeded, None));
                    this.phase = Some(Phase::Error);
                } else {
                    this.phase = Some(Phase::Complete);
                }
            } else {
                let error = consumer.code(Failure::DeadlineExceeded);
                return this.finish(error);
            }
        }
        if this.phase.is_none() {
            let Some(inner) = this.inner.as_mut() else {
                return this.internal(consumer, "an active delivery has no subscription");
            };
            match inner.stream.as_mut().poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(update))) => {
                    this.row = 0;
                    this.phase = Some(if !this.metadata {
                        Phase::Metadata
                    } else if update.batches.is_some() {
                        Phase::Row
                    } else {
                        Phase::Health
                    });
                    this.update = Some(update);
                }
                Poll::Ready(Some(Err((error, receipt)))) => {
                    let code = Failure::from(&error);
                    if code == Failure::Denied {
                        let error = consumer.code(code);
                        return this.finish(error);
                    }
                    if this.last.is_none() {
                        if let (Some(snapshot), Some(cursor)) =
                            (receipt.as_ref(), this.cursor.as_ref())
                        {
                            let memory = match this.session.memory().reserve_output(0) {
                                Ok(memory) => memory,
                                Err(error) => {
                                    return this.finish(consumer.code(Failure::native(&error)))
                                }
                            };
                            this.last = Some(Update {
                                snapshot: Arc::clone(snapshot),
                                batches: None,
                                calls: Default::default(),
                                cursor: cursor.clone(),
                                operation: inner.operation,
                                exhausted: false,
                                clock_changed: false,
                                completed_windows: Vec::new(),
                                positions: Vec::new(),
                                evaluated_utc_ns: 0,
                                limited: false,
                                _memory: memory,
                            });
                        } else if let Some(snapshot) = receipt {
                            this.error_receipt = Some((snapshot, inner.operation));
                        } else {
                            let error = consumer.code(code);
                            return this.finish(error);
                        }
                    }
                    this.inner = None;
                    this.failure = Some((code, Some(error)));
                    this.phase = Some(Phase::Error);
                }
                Poll::Ready(None) => {
                    this.inner = None;
                    if this.last.is_none() {
                        this.done = true;
                        this.consumer = None;
                        this.stop();
                        return Poll::Ready(None);
                    }
                    this.phase = Some(Phase::Complete);
                }
            }
        }
        if matches!(this.phase, Some(Phase::Row))
            && this
                .update
                .as_ref()
                .is_some_and(|update| this.row >= consumer.rows(update))
        {
            this.phase = Some(Phase::Checkpoint);
        }
        let Some(phase) = this.phase else {
            return this.internal(consumer, "the delivery phase is absent");
        };
        if this.checking.is_none() && !this.check(matches!(phase, Phase::Health)) {
            return this.internal(consumer, "the disclosure receipt is absent");
        }
        let Some(checking) = this.checking.as_mut() else {
            return this.internal(consumer, "the read check is absent");
        };
        let health = match checking.as_mut().poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                let error = consumer.code(Failure::from(&error));
                return this.finish(error);
            }
            Poll::Ready(Ok(health)) => {
                this.checking = None;
                health
            }
        };
        if let Err(error) = consumer.authorize() {
            return this.finish(error);
        }
        if let Some(initial) = this.initial.take() {
            this.conversion = initial;
        }
        let action = match phase {
            Phase::Metadata => Action::Metadata,
            Phase::Row => Action::Row(this.row),
            Phase::Checkpoint => Action::Checkpoint,
            Phase::Health => {
                let Some(health) = health else {
                    return this.internal(consumer, "the health check result is absent");
                };
                Action::Health(health)
            }
            Phase::Error => {
                let Some((code, cause)) = this.failure.as_ref() else {
                    return this.internal(consumer, "the delivery failure is absent");
                };
                Action::Error {
                    failure: *code,
                    cause: cause.as_ref(),
                    last: this.cursor.as_ref(),
                }
            }
            Phase::Complete => Action::Complete {
                last: this.cursor.as_ref(),
            },
        };
        let item = if let Some(receipt) = this.update.as_ref().or(this.last.as_ref()) {
            consumer.encode(action, receipt, &mut this.conversion)
        } else if let (
            Action::Error {
                failure,
                cause: Some(cause),
                ..
            },
            Some((snapshot, operation)),
        ) = (action, this.error_receipt.as_ref())
        {
            consumer.initial_error(failure, cause, snapshot, *operation, &mut this.conversion)
        } else {
            return this.internal(consumer, "the disclosure receipt is absent");
        };
        let item = match item {
            Ok(item) => item,
            Err(error) => return this.finish(error),
        };
        if let Err(error) = consumer.authorize() {
            return this.finish(error);
        }
        match phase {
            Phase::Metadata => {
                let Some(update) = this.update.as_ref() else {
                    return this.internal(consumer, "the initial update is absent");
                };
                this.metadata = true;
                this.initial = None;
                this.phase = Some(if update.batches.is_some() {
                    Phase::Row
                } else {
                    Phase::Checkpoint
                });
            }
            Phase::Row => {
                this.pending_rows = true;
                this.row += 1;
                this.phase = Some(Phase::Row);
            }
            Phase::Checkpoint => {
                let Some(mut update) = this.update.take() else {
                    return this.internal(consumer, "the completed update is absent");
                };
                let complete = consumer.complete_after_checkpoint(&update);
                this.cursor = Some(update.cursor.clone());
                Self::discard_rows(&mut update);
                this.last = Some(update);
                this.pending_rows = false;
                this.phase = complete.then_some(Phase::Complete);
                if complete {
                    this.inner = None;
                }
            }
            Phase::Health => this.phase = Some(Phase::Checkpoint),
            Phase::Error => {
                let Some((code, _)) = this.failure.take() else {
                    return this.internal(consumer, "the delivery failure is absent");
                };
                this.pending = Some(consumer.code(code));
                this.stop();
                this.phase = None;
            }
            Phase::Complete => {
                this.done = true;
                this.consumer = None;
                this.stop();
            }
        }
        this.idle = match this.timeout {
            Some(timeout) => match Instant::now().checked_add(timeout) {
                Some(deadline) => Some(deadline),
                None => {
                    let error = crate::InvalidSnafu {
                        field: "output timeout",
                    }
                    .build();
                    return this.finish(consumer.code(Failure::from(&error)));
                }
            },
            None => None,
        };
        Poll::Ready(Some(Ok(item)))
    }
}

impl<C: Consumer> Stream for Delivery<C> {
    type Item = std::result::Result<C::Item, C::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.conversion.free();
        if this.done {
            return Poll::Ready(None);
        }
        let Some(mut consumer) = this.consumer.take() else {
            this.done = true;
            this.stop();
            return Poll::Ready(None);
        };
        let result = this.poll_delivery(&mut consumer, context);
        if !this.done {
            this.consumer = Some(consumer);
        }
        result
    }
}

impl<C: Consumer> Drop for Delivery<C> {
    fn drop(&mut self) {
        let _cancelled = self.session.control().cancel();
    }
}

#[cfg(test)]
mod tests;
