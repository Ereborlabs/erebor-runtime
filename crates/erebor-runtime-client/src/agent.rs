use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        agent_service_client::AgentServiceClient, AgentInstallRequest, AgentInstallResponse,
        CodexRunRequest, SessionCreateResponse,
    },
};

use crate::{rpc, DaemonClient, Result};

impl DaemonClient {
    /// Enroll one caller-provided Codex executable against a root-curated release.
    pub async fn agent_load_codex(
        &self,
        package_name: impl Into<String>,
        source_path: impl Into<String>,
        name: impl Into<String>,
        adapter: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<AgentInstallResponse> {
        let mut client = AgentServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES);
        rpc(client
            .install(self.mutation_request(
                AgentInstallRequest {
                    package_name: package_name.into(),
                    source_path: source_path.into(),
                    name: name.into(),
                    adapter: adapter.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn codex_run(
        &self,
        request: CodexRunRequest,
        idempotency_key: &str,
    ) -> Result<SessionCreateResponse> {
        let mut client = AgentServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES);
        rpc(client
            .run_codex(self.mutation_request(request, idempotency_key)?)
            .await)
    }
}
