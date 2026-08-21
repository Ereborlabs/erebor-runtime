use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        filesystem_service_client::FilesystemServiceClient, FilesystemMutationRequest,
        FilesystemOperationResponse, FilesystemQueryRequest,
    },
};
use tonic::Request;

use crate::{rpc, DaemonClient, Result};

impl DaemonClient {
    pub async fn filesystem_query(
        &self,
        request: FilesystemQueryRequest,
    ) -> Result<FilesystemOperationResponse> {
        let mut client = self.filesystem_client().await?;
        rpc(client.query(Request::new(request)).await)
    }

    pub async fn filesystem_mutation(
        &self,
        request: FilesystemMutationRequest,
        idempotency_key: &str,
    ) -> Result<FilesystemOperationResponse> {
        let mut client = self.filesystem_client().await?;
        rpc(client
            .mutate(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    async fn filesystem_client(
        &self,
    ) -> Result<FilesystemServiceClient<tonic::transport::Channel>> {
        Ok(FilesystemServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}
