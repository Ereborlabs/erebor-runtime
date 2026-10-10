use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use araphor_data::{
    GraphTraversalV1, QueryCheckpoint, QueryErrorCode, QueryFrame, QueryGrant, QueryPayload,
    QueryPlan, QuerySql, QueryStream,
};
use futures_util::Stream;
use tokio::time::Sleep;
use tonic::Status;

use super::wire::{Parameters, WireFrame};
use super::{proto, ClientAccess, ClientGrpcOwner};

type GuardCheck = Pin<Box<dyn Future<Output = araphor_data::Result<Box<QueryFrame>>> + Send>>;

enum QueryGuard {
    Stored(Box<QueryFrame>),
    Checking(GuardCheck),
}

pub(super) struct QueryTransport {
    inner: QueryStream,
    access: Arc<ClientAccess>,
    held: Option<QueryFrame>,
    guard: Option<QueryGuard>,
    deadline: Option<Pin<Box<Sleep>>>,
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
        let grant = QueryGrant {
            principal: access.principal().to_owned(),
            revision: access.revision(),
            selection,
        };
        let plan = if let Some(traversal) = request.graph_traversal {
            if !request.bookmark.is_empty() {
                return Err(Status::unimplemented(
                    "Graph traversal does not support bookmarks.",
                ));
            }
            let traversal = GraphTraversalV1::try_from(traversal.definition_json.as_slice())
                .map_err(QueryTransport::failure)?;
            QueryPlan::client_graph(grant, sql, traversal)
        } else {
            QueryPlan::client(grant, sql)
        }
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
            deadline: duration
                .map(|duration| Box::pin(tokio::time::sleep(Duration::from_nanos(duration)))),
            pending_rows: false,
            pending: None,
            done: false,
        }
    }

    #[cfg(test)]
    pub(super) async fn expire(&mut self) {
        if let Some(deadline) = self.deadline.as_mut() {
            deadline.as_mut().reset(tokio::time::Instant::now());
            deadline.as_mut().await;
        }
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
            let mut checking: GuardCheck = match self.guard.take() {
                Some(QueryGuard::Stored(frame)) => Box::pin(async move {
                    frame.check_read().await?;
                    Ok(frame)
                }),
                Some(QueryGuard::Checking(checking)) => checking,
                None => {
                    let _cancelled = self.inner.cancel();
                    self.done = true;
                    return Poll::Ready(Some(Err(Status::deadline_exceeded(
                        "Follow ended before its first complete checkpoint.",
                    ))));
                }
            };
            let frame = match checking.as_mut().poll(context) {
                Poll::Pending => {
                    self.guard = Some(QueryGuard::Checking(checking));
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    self.done = true;
                    let _cancelled = self.inner.cancel();
                    return Poll::Ready(Some(Err(Self::failure(error))));
                }
                Poll::Ready(Ok(frame)) => frame,
            };
            if let Err(error) = self.access.check() {
                self.done = true;
                let _cancelled = self.inner.cancel();
                return Poll::Ready(Some(Err(ClientGrpcOwner::auth_failure(error))));
            }
            let _cancelled = self.inner.cancel();
            let QueryPayload::Checkpoint { checkpoint, .. } = &frame.payload else {
                self.done = true;
                return Poll::Ready(Some(Err(Status::internal(
                    "The query checkpoint frame is absent.",
                ))));
            };
            let bookmark = match WireFrame::bookmark(Some(checkpoint)) {
                Ok(bookmark) => bookmark,
                Err(error) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
            };
            let mut output = WireFrame::header(&frame);
            output.payload = Some(if self.pending_rows {
                let code = QueryErrorCode::DeadlineExceeded;
                self.pending = Some(Self::code(code));
                proto::query_frame::Payload::Error(proto::QueryError {
                    code: format!("{code:?}"),
                    reason: code.reason().into(),
                    last_checkpoint: bookmark,
                    position: None,
                    floor: None,
                })
            } else {
                self.done = true;
                proto::query_frame::Payload::Terminal(proto::QueryTerminal {
                    reason: "Completed".into(),
                    last_checkpoint: bookmark,
                })
            });
            return Poll::Ready(Some(Ok(output)));
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
                if matches!(
                    &wire.message.payload,
                    Some(proto::query_frame::Payload::Checkpoint(_))
                ) {
                    self.pending_rows = false;
                    self.guard = Some(QueryGuard::Stored(Box::new(wire.owner)));
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
