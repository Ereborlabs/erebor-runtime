use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        surface_service_client::SurfaceServiceClient, SurfaceCreateRequest, SurfaceInspectRequest,
        SurfaceListRequest, SurfaceListResponse, SurfaceRecord,
    },
};
use tonic::Request;

use crate::{rpc, DaemonClient, Result};

impl DaemonClient {
    pub async fn surface_create(
        &self,
        name: impl Into<String>,
        surface_type: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SurfaceRecord> {
        let mut client = self.surface_client().await?;
        rpc(client
            .create(self.mutation_request(
                SurfaceCreateRequest {
                    name: name.into(),
                    surface_type: surface_type.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn surface_list(&self) -> Result<SurfaceListResponse> {
        let mut client = self.surface_client().await?;
        rpc(client.list(Request::new(SurfaceListRequest {})).await)
    }

    pub async fn surface_inspect(&self, name: impl Into<String>) -> Result<SurfaceRecord> {
        let mut client = self.surface_client().await?;
        rpc(client
            .inspect(Request::new(SurfaceInspectRequest { name: name.into() }))
            .await)
    }

    async fn surface_client(&self) -> Result<SurfaceServiceClient<tonic::transport::Channel>> {
        Ok(SurfaceServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}
