use erebor_runtime_ipc::v1::{
    FilesystemMutationRequest, FilesystemOperationResponse, FilesystemQueryRequest,
    KIND_FILESYSTEM_MUTATION_REQUEST, KIND_FILESYSTEM_OPERATION_RESPONSE,
    KIND_FILESYSTEM_QUERY_REQUEST,
};

use crate::{DaemonClient, Result};

impl DaemonClient {
    pub async fn filesystem_query(
        &self,
        request: FilesystemQueryRequest,
    ) -> Result<FilesystemOperationResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_FILESYSTEM_QUERY_REQUEST,
                &request,
                KIND_FILESYSTEM_OPERATION_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn filesystem_mutation(
        &self,
        request: FilesystemMutationRequest,
        idempotency_key: &str,
    ) -> Result<FilesystemOperationResponse> {
        self.session_mutation(
            KIND_FILESYSTEM_MUTATION_REQUEST,
            &request,
            KIND_FILESYSTEM_OPERATION_RESPONSE,
            idempotency_key,
        )
        .await
    }
}
