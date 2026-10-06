use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use araphor_data::{
    QueryCheckpoint, QueryErrorCode, QueryFrame, QueryGrant, QueryPayload, QueryPlan, QuerySql,
    QueryStream,
};
use futures_util::Stream;
use tokio::time::Sleep;
use tonic::Status;

use super::wire::{Parameters, WireFrame};
use super::{proto, ClientAccess, ClientGrpcOwner};

pub(super) struct QueryTransport {
    inner: QueryStream,
    access: Arc<ClientAccess>,
    held: Option<QueryFrame>,
    guard: Option<Arc<QueryFrame>>,
    checking: Option<Pin<Box<dyn Future<Output = araphor_data::Result<()>> + Send>>>,
    deadline: Option<Pin<Box<Sleep>>>,
    last: proto::QueryFrame,
    bookmark: Vec<u8>,
    pending_rows: bool,
    pending: Option<Status>,
    done: bool,
}

impl ClientGrpcOwner {
    pub(super) fn query_request(
        &self,
        request: proto::QueryRequest,
        access: Arc<ClientAccess>,
    ) -> Result<QueryTransport, Status> {
        if request.duration_ns.is_some_and(|duration| duration == 0) {
            return Err(Status::invalid_argument("The follow duration is empty."));
        }
        if !request.follow && request.duration_ns.is_some() {
            return Err(Status::invalid_argument("Duration requires follow."));
        }
        let parameters = Parameters::try_from(request.parameters)?.0;
        let sql = QuerySql::admit(&request.sql, parameters, request.follow)
            .map_err(QueryTransport::failure)?;
        let selection = self.select(request.selection, access.tenant_id())?;
        let plan = QueryPlan::client(
            QueryGrant {
                principal: access.principal().to_owned(),
                revision: access.revision(),
                selection,
            },
            sql,
        )
        .map_err(QueryTransport::failure)?;
        let checkpoint = QueryTransport::checkpoint(&request.bookmark)?;
        let inner = self
            .data()?
            .query
            .stream_client(plan, checkpoint, access.clone())
            .map_err(QueryTransport::failure)?;
        Ok(QueryTransport::new(inner, access, request.duration_ns))
    }
}

impl QueryTransport {
    pub(super) fn new(
        inner: QueryStream,
        access: Arc<ClientAccess>,
        duration: Option<u64>,
    ) -> Self {
        Self {
            inner,
            access,
            held: None,
            guard: None,
            checking: None,
            deadline: duration
                .map(|duration| Box::pin(tokio::time::sleep(Duration::from_nanos(duration)))),
            last: proto::QueryFrame::default(),
            bookmark: Vec::new(),
            pending_rows: false,
            pending: None,
            done: false,
        }
    }

    #[cfg(test)]
    pub(super) async fn expire(&mut self) {
        let deadline = self.deadline.as_mut().expect("the duration exists");
        deadline.as_mut().reset(tokio::time::Instant::now());
        deadline.as_mut().await;
    }

    pub(super) fn checkpoint(bytes: &[u8]) -> Result<Option<QueryCheckpoint>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        QueryCheckpoint::try_from(bytes)
            .map(Some)
            .map_err(Self::failure)
    }

    pub(super) fn failure(error: araphor_data::Error) -> Status {
        Self::code(QueryErrorCode::from(&error))
    }

    pub(super) fn code(code: QueryErrorCode) -> Status {
        let status = match code {
            QueryErrorCode::InvalidQuery | QueryErrorCode::InvalidCheckpoint => {
                tonic::Code::InvalidArgument
            }
            QueryErrorCode::CursorExpired => tonic::Code::OutOfRange,
            QueryErrorCode::Denied => tonic::Code::PermissionDenied,
            QueryErrorCode::Unsupported => tonic::Code::Unimplemented,
            QueryErrorCode::InputTooLarge
            | QueryErrorCode::ResultTooLarge
            | QueryErrorCode::Busy => tonic::Code::ResourceExhausted,
            QueryErrorCode::Cancelled => tonic::Code::Cancelled,
            QueryErrorCode::DeadlineExceeded | QueryErrorCode::OutputTimeout => {
                tonic::Code::DeadlineExceeded
            }
            QueryErrorCode::StorageUnavailable => tonic::Code::Unavailable,
            QueryErrorCode::EvaluationFailed => tonic::Code::Internal,
        };
        Status::new(status, code.reason())
    }
}

impl Stream for QueryTransport {
    type Item = Result<proto::QueryFrame, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        self.held.take();
        if let Err(error) = self.access.check() {
            self.done = true;
            let _cancelled = self.inner.cancel();
            return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
        }
        if let Some(status) = self.pending.take() {
            self.done = true;
            return Poll::Ready(Some(Err(status)));
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| Future::poll(deadline.as_mut(), context).is_ready())
        {
            if self.bookmark.is_empty() {
                let _cancelled = self.inner.cancel();
                self.done = true;
                return Poll::Ready(Some(Err(Status::deadline_exceeded(
                    "Follow ended before its first complete checkpoint.",
                ))));
            }
            if self.checking.is_none() {
                let frame = self.guard.clone().expect("the checkpoint frame exists");
                self.checking = Some(Box::pin(async move { frame.check_read().await }));
            }
            match self
                .checking
                .as_mut()
                .expect("the read check exists")
                .as_mut()
                .poll(context)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.done = true;
                    self.checking = None;
                    self.guard = None;
                    let _cancelled = self.inner.cancel();
                    return Poll::Ready(Some(Err(Self::failure(error))));
                }
                Poll::Ready(Ok(())) => self.checking = None,
            }
            if let Err(error) = self.access.check() {
                self.done = true;
                self.guard = None;
                let _cancelled = self.inner.cancel();
                return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
            }
            self.guard = None;
            let _cancelled = self.inner.cancel();
            self.last.payload = Some(if self.pending_rows {
                let code = QueryErrorCode::DeadlineExceeded;
                self.pending = Some(Self::code(code));
                proto::query_frame::Payload::Error(proto::QueryError {
                    code: format!("{code:?}"),
                    reason: code.reason().into(),
                    last_checkpoint: self.bookmark.clone(),
                    position: None,
                    floor: None,
                })
            } else {
                self.done = true;
                proto::query_frame::Payload::Terminal(proto::QueryTerminal {
                    reason: "Completed".into(),
                    last_checkpoint: self.bookmark.clone(),
                })
            });
            return Poll::Ready(Some(Ok(std::mem::take(&mut self.last))));
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let QueryPayload::Error { code, .. } = &frame.payload {
                    self.pending = Some(Self::code(*code));
                }
                let wire = match WireFrame::try_from(frame) {
                    Ok(wire) => wire,
                    Err(error) => {
                        self.done = true;
                        return Poll::Ready(Some(Err(error)));
                    }
                };
                if let Err(error) = self.access.check() {
                    self.done = true;
                    let _cancelled = self.inner.cancel();
                    return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
                }
                if let Some(proto::query_frame::Payload::Checkpoint(bookmark)) =
                    &wire.message.payload
                {
                    self.bookmark = bookmark.clone();
                    self.pending_rows = false;
                    self.last = proto::QueryFrame {
                        schema_version: wire.message.schema_version,
                        operation: wire.message.operation,
                        store_uuid: wire.message.store_uuid.clone(),
                        recovery_epoch: wire.message.recovery_epoch,
                        read_revision: wire.message.read_revision,
                        clock_changed: wire.message.clock_changed,
                        coverage: wire.message.coverage.clone(),
                        payload: None,
                    };
                    self.guard = Some(Arc::new(wire.owner));
                } else {
                    if matches!(
                        &wire.message.payload,
                        Some(proto::query_frame::Payload::Rows(_))
                    ) {
                        self.pending_rows = true;
                    }
                    self.held = Some(wire.owner);
                }
                Poll::Ready(Some(Ok(wire.message)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(Self::failure(error))))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
