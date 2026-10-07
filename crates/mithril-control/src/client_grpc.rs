#![allow(clippy::result_large_err)]

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_data::{AnalysisStore, QueryLimits, QueryOwner};
use erebor_runtime_error::StatusCode;
use erebor_runtime_ipc::araphor as proto;
use futures_util::{Stream, StreamExt as _};
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::{ClientAccess, ClientAuth, ControlPlane};

mod query;
mod selection;
mod trace;
mod wire;

#[cfg(test)]
mod tests;

pub type ClientStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientGrpcConfig {
    pub query: QueryLimits,
}

#[derive(Clone)]
pub struct ClientGrpcOwner {
    control: ControlPlane,
    auth: Arc<ClientAuth>,
    data: Option<ClientData>,
}

#[derive(Clone)]
struct ClientData {
    store: Arc<AnalysisStore>,
    query: Arc<QueryOwner>,
    output_timeout: Duration,
}

impl ClientGrpcOwner {
    pub fn new(
        control: ControlPlane,
        auth: Arc<ClientAuth>,
        config: ClientGrpcConfig,
    ) -> crate::Result<Self> {
        let output_timeout = config.query.output_timeout;
        let data = control
            .analysis_store()
            .map(|store| {
                QueryOwner::new(store.clone(), config.query).map(|query| ClientData {
                    store,
                    query: Arc::new(query),
                    output_timeout,
                })
            })
            .transpose()?;
        Ok(Self {
            control,
            auth,
            data,
        })
    }

    fn data(&self) -> Result<&ClientData, Status> {
        self.data
            .as_ref()
            .ok_or_else(|| Status::unavailable("Retained data storage is unavailable."))
    }

    fn output_stream<T, S>(&self, inner: S) -> Result<ClientStream<T>, Status>
    where
        T: Send + 'static,
        S: Stream<Item = Result<T, Status>> + Send + 'static,
    {
        let timeout = self.data()?.output_timeout;
        let stream = futures_util::stream::unfold(
            (Some(Box::pin(inner)), None),
            move |(inner, deadline)| async move {
                let mut inner = inner?;
                // Check the output deadline only when the client requests another frame.
                if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                    drop(inner);
                    return Some((
                        Err(query::QueryTransport::code(
                            araphor_data::QueryErrorCode::OutputTimeout,
                        )),
                        (None, None),
                    ));
                }
                let item = inner.next().await?;
                let state = if item.is_ok() {
                    (Some(inner), Some(tokio::time::Instant::now() + timeout))
                } else {
                    (None, None)
                };
                Some((item, state))
            },
        );
        Ok(Box::pin(stream.fuse()))
    }

    async fn authenticate<T>(
        &self,
        request: &Request<T>,
        mutation: bool,
    ) -> Result<Arc<ClientAccess>, Status> {
        let access = self
            .auth
            .authenticate(request.metadata(), mutation)
            .await
            .map(Arc::new)
            .map_err(Self::auth_failure)?;
        self.data()?;
        Ok(access)
    }

    fn auth_failure(error: crate::Error) -> Status {
        if matches!(error, crate::Error::ClientUnauthenticated { .. }) {
            Status::unauthenticated("Client authentication expired or failed.")
        } else {
            Self::failure(error)
        }
    }

    fn failure(error: impl erebor_runtime_error::ErrorExt) -> Status {
        let code = match error.status_code() {
            StatusCode::InvalidArguments | StatusCode::InvalidSyntax => {
                tonic::Code::InvalidArgument
            }
            StatusCode::PermissionDenied | StatusCode::PolicyDenied => {
                tonic::Code::PermissionDenied
            }
            StatusCode::NotFound => tonic::Code::NotFound,
            StatusCode::AlreadyExists => tonic::Code::AlreadyExists,
            StatusCode::Cancelled => tonic::Code::Cancelled,
            StatusCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
            StatusCode::Unsupported => tonic::Code::Unimplemented,
            StatusCode::Unavailable | StatusCode::External => tonic::Code::Unavailable,
            StatusCode::IllegalState => tonic::Code::FailedPrecondition,
            _ => tonic::Code::Internal,
        };
        // Do not disclose native errors, credentials, or stored input.
        Status::new(code, "The client operation failed.")
    }

    fn now() -> Result<u64, Status> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| Status::internal("The server clock is unavailable."))
    }

    fn identity(bytes: &[u8]) -> Result<[u8; 16], Status> {
        let id: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Status::invalid_argument("The identifier must have 16 bytes."))?;
        if id == [0; 16] {
            return Err(Status::invalid_argument("The identifier is empty."));
        }
        Ok(id)
    }
}

#[tonic::async_trait]
impl proto::araphor_client_service_server::AraphorClientService for ClientGrpcOwner {
    type QueryStream = ClientStream<proto::QueryFrame>;
    type WatchTraceStream = ClientStream<proto::TraceFrame>;

    async fn query(
        &self,
        request: Request<proto::QueryRequest>,
    ) -> Result<Response<Self::QueryStream>, Status> {
        let access = self.authenticate(&request, false).await?;
        self.query_request(request.into_inner(), access)
            .and_then(|stream| self.output_stream(stream))
            .map(Response::new)
    }

    async fn submit_trace(
        &self,
        request: Request<proto::SubmitTraceRequest>,
    ) -> Result<Response<proto::TraceReceipt>, Status> {
        let access = self.authenticate(&request, true).await?;
        self.submit(request.into_inner(), access)
            .await
            .map(Response::new)
    }

    async fn get_trace(
        &self,
        request: Request<proto::GetTraceRequest>,
    ) -> Result<Response<proto::TraceDetail>, Status> {
        let access = self.authenticate(&request, false).await?;
        let trace = Self::identity(&request.into_inner().trace_id)?;
        self.detail(trace, &access).await.map(Response::new)
    }

    async fn watch_trace(
        &self,
        request: Request<proto::WatchTraceRequest>,
    ) -> Result<Response<Self::WatchTraceStream>, Status> {
        let access = self.authenticate(&request, false).await?;
        self.watch(request.into_inner(), access)
            .await
            .and_then(|stream| self.output_stream(stream))
            .map(Response::new)
    }

    async fn cancel_trace(
        &self,
        request: Request<proto::CancelTraceRequest>,
    ) -> Result<Response<proto::CancelTraceReceipt>, Status> {
        let access = self.authenticate(&request, true).await?;
        let trace = Self::identity(&request.into_inner().trace_id)?;
        let store = self.data()?.store.clone();
        let current = access.clone();
        let state = tokio::task::spawn_blocking(move || {
            let grant = current.trace_access().map_err(Self::auth_failure)?;
            let now = Self::now()?;
            crate::TraceOwner::new(store)
                .cancel(grant.tenant_id, trace, &grant, now, false)
                .map_err(Self::failure)
        })
        .await
        .map_err(|_| Status::internal("The trace cancellation task failed."))??;
        access.check().map_err(Self::auth_failure)?;
        Ok(Response::new(proto::CancelTraceReceipt {
            trace_id: trace.to_vec(),
            cancel_requested: state.cancel_requested,
        }))
    }
}
