use erebor_runtime_ipc::v1::{
    AgentInstallRequest, AgentInstallResponse, CodexRunRequest, SessionCreateResponse,
    KIND_AGENT_INSTALL_REQUEST, KIND_AGENT_INSTALL_RESPONSE, KIND_CODEX_RUN_REQUEST,
    KIND_SESSION_CREATE_RESPONSE,
};

use crate::{DaemonClient, Result};

impl DaemonClient {
    /// Enroll one caller-provided Codex executable against a root-curated
    /// release. The daemon, not this client, resolves and verifies the path.
    pub async fn agent_install_codex(
        &self,
        package_reference: impl Into<String>,
        source_path: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<AgentInstallResponse> {
        self.session_mutation(
            KIND_AGENT_INSTALL_REQUEST,
            &AgentInstallRequest {
                package_reference: package_reference.into(),
                source_path: source_path.into(),
            },
            KIND_AGENT_INSTALL_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn codex_run(
        &self,
        request: CodexRunRequest,
        idempotency_key: &str,
    ) -> Result<SessionCreateResponse> {
        self.session_mutation(
            KIND_CODEX_RUN_REQUEST,
            &request,
            KIND_SESSION_CREATE_RESPONSE,
            idempotency_key,
        )
        .await
    }
}
