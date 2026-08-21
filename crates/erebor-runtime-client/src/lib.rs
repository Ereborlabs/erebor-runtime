//! Typed gRPC clients for Erebor local services.

mod agent;
mod approvals;
mod error;
mod filesystem;
mod mithril;
mod policy;
mod runner;
mod session;
mod surface;

use std::{path::PathBuf, time::Duration};

use erebor_runtime_ipc::{
    transport::{connect_unix, IDEMPOTENCY_KEY_METADATA, MAX_GRPC_MESSAGE_BYTES},
    v1::{
        daemon_lifecycle_service_client::DaemonLifecycleServiceClient, DaemonCommandResult,
        DaemonLogRecord, DaemonLogsRequest, DaemonReloadRequest, DaemonStatusRequest,
        DaemonStatusResponse, DaemonStopRequest,
    },
};
use tonic::{metadata::MetadataValue, transport::Channel, Request, Status};

pub use approvals::{ApprovalPage, ApprovalRecord};
pub use erebor_runtime_ipc::v1::{
    PolicyPackageListResponse, PolicyPackageRecord, PolicySetListResponse, PolicySetRecord,
    PolicyTestResponse, SurfaceListResponse, SurfaceRecord,
};
pub use error::{DaemonClientError, Result};
pub use mithril::MithrilObservationClient;
pub use runner::RunnerCapability;
pub use session::{SessionEventPage, SessionEvidencePage, SessionLogPage};

use error::{ProtocolSnafu, RpcSnafu, TimedOutSnafu};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const SESSION_MUTATION_TIMEOUT: Duration = Duration::from_secs(35);

#[derive(Clone, Debug)]
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    #[must_use]
    pub fn local() -> Self {
        Self {
            socket_path: PathBuf::from("/run/erebor/daemon.sock"),
        }
    }

    #[must_use]
    pub fn at(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn status(&self) -> Result<DaemonStatusResponse> {
        let mut client = self.lifecycle_client().await?;
        rpc(client.status(Request::new(DaemonStatusRequest {})).await)
    }

    pub async fn logs(
        &self,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<Vec<DaemonLogRecord>> {
        let mut client = self.lifecycle_client().await?;
        let mut stream = client
            .logs(Request::new(DaemonLogsRequest {
                after_sequence,
                maximum_records,
            }))
            .await
            .map_err(rpc_error)?
            .into_inner();
        let mut records = Vec::new();
        while let Some(record) = stream.message().await.map_err(rpc_error)? {
            records.push(record);
        }
        Ok(records)
    }

    pub async fn reload(&self, idempotency_key: &str) -> Result<String> {
        let mut client = self.lifecycle_client().await?;
        let response: DaemonCommandResult = rpc(client
            .reload(self.mutation_request(DaemonReloadRequest {}, idempotency_key)?)
            .await)?;
        Ok(response.message)
    }

    pub async fn stop(&self, idempotency_key: &str) -> Result<String> {
        let mut client = self.lifecycle_client().await?;
        let response: DaemonCommandResult = rpc(client
            .stop(self.mutation_request(DaemonStopRequest {}, idempotency_key)?)
            .await)?;
        Ok(response.message)
    }

    pub(crate) async fn connect(&self) -> Result<Channel> {
        tokio::time::timeout(REQUEST_TIMEOUT, connect_unix(&self.socket_path))
            .await
            .map_err(|_elapsed| {
                TimedOutSnafu {
                    operation: "connecting to erebord",
                }
                .build()
            })?
            .map_err(|source| DaemonClientError::Connect {
                path: self.socket_path.clone(),
                source,
                location: snafu::Location::default(),
            })
    }

    pub(crate) fn mutation_request<T>(
        &self,
        message: T,
        idempotency_key: &str,
    ) -> Result<Request<T>> {
        let value = MetadataValue::try_from(idempotency_key).map_err(|_error| {
            ProtocolSnafu {
                reason: String::from("the idempotency key is not valid gRPC metadata"),
            }
            .build()
        })?;
        let mut request = Request::new(message);
        request.set_timeout(SESSION_MUTATION_TIMEOUT);
        request
            .metadata_mut()
            .insert(IDEMPOTENCY_KEY_METADATA, value);
        Ok(request)
    }

    async fn lifecycle_client(&self) -> Result<DaemonLifecycleServiceClient<Channel>> {
        Ok(DaemonLifecycleServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}

pub(crate) fn rpc<T>(result: std::result::Result<tonic::Response<T>, Status>) -> Result<T> {
    result.map(tonic::Response::into_inner).map_err(rpc_error)
}

pub(crate) fn rpc_error(status: Status) -> DaemonClientError {
    RpcSnafu {
        code: status.code(),
        message: status.message().to_owned(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::DaemonClient;

    #[test]
    fn explicit_local_socket_replaces_only_the_default_path() {
        let client = DaemonClient::at(PathBuf::from("/tmp/erebor-lab/daemon.sock"));
        assert_eq!(
            client.socket_path,
            PathBuf::from("/tmp/erebor-lab/daemon.sock")
        );
        assert_eq!(
            DaemonClient::local().socket_path,
            PathBuf::from("/run/erebor/daemon.sock")
        );
    }
}
