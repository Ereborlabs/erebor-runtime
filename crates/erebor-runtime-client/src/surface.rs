use erebor_runtime_ipc::v1::{
    Header, SurfaceCreateRequest, SurfaceInspectRequest, SurfaceListRequest, SurfaceListResponse,
    SurfaceRecord, EREBOR_IDEMPOTENCY_KEY_HEADER, KIND_SURFACE_CREATE_REQUEST,
    KIND_SURFACE_INSPECT_REQUEST, KIND_SURFACE_LIST_REQUEST, KIND_SURFACE_LIST_RESPONSE,
    KIND_SURFACE_RECORD,
};

use crate::{DaemonClient, Result};

impl DaemonClient {
    pub async fn surface_create(
        &self,
        name: impl Into<String>,
        surface_type: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SurfaceRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SURFACE_CREATE_REQUEST,
                &SurfaceCreateRequest {
                    name: name.into(),
                    surface_type: surface_type.into(),
                },
                KIND_SURFACE_RECORD,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_owned(),
                    value: idempotency_key.to_owned(),
                }],
            )
            .await
    }

    pub async fn surface_list(&self) -> Result<SurfaceListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SURFACE_LIST_REQUEST,
                &SurfaceListRequest {},
                KIND_SURFACE_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn surface_inspect(&self, name: impl Into<String>) -> Result<SurfaceRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SURFACE_INSPECT_REQUEST,
                &SurfaceInspectRequest { name: name.into() },
                KIND_SURFACE_RECORD,
                Vec::new(),
            )
            .await
    }
}
