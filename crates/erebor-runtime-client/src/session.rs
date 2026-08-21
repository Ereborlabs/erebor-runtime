use std::time::Duration;

use erebor_runtime_ipc::{
    transport::MAX_GRPC_MESSAGE_BYTES,
    v1::{
        administration_service_client::AdministrationServiceClient,
        context_service_client::ContextServiceClient, session_event_stream_item,
        session_evidence_stream_item, session_log_stream_item,
        session_service_client::SessionServiceClient, AdminSessionInspectRequest,
        AdminSessionKillRequest, AdminSessionListRequest, AdminSessionSetRetentionHoldRequest,
        AdminSessionStopRequest, CodexAppServerAttachRequest, CodexAppServerAttachResponse,
        CodexAppServerInputCloseRequest, CodexAppServerInputCloseResponse,
        CodexAppServerInputRequest, CodexAppServerInputResponse, ContextDeliveryDecisionResponse,
        ContextDeliveryInboxRequest, ContextDeliveryInboxResponse, ContextDeliveryReceiveRequest,
        ContextDeliveryRejectRequest, ContextGraphRequest, ContextGraphResponse,
        SessionAliasListRequest, SessionAliasListResponse, SessionAliasRecord,
        SessionAliasRemoveRequest, SessionAliasSetRequest, SessionAttachRequest,
        SessionAttachResponse, SessionCreateRequest, SessionCreateResponse, SessionEventRecord,
        SessionEventsEnd, SessionEventsRequest, SessionEvidenceEnd, SessionEvidenceRecord,
        SessionEvidenceRequest, SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest,
        SessionInputLeaseResponse, SessionInputRequest, SessionInputResponse,
        SessionInspectRequest, SessionKillRequest, SessionListRequest, SessionListResponse,
        SessionLogChunk, SessionLogsEnd, SessionLogsRequest, SessionPruneRequest,
        SessionPruneResponse, SessionRecord, SessionRemoveRequest, SessionStartRequest,
        SessionStopRequest, SessionTerminalResizeRequest, SessionTerminalResizeResponse,
        SessionWaitRequest,
    },
};
use tonic::Request;

use crate::{error::ProtocolSnafu, rpc, rpc_error, DaemonClient, Result};

const SESSION_WAIT_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug)]
pub struct SessionLogPage {
    pub records: Vec<SessionLogChunk>,
    pub end: SessionLogsEnd,
}

#[derive(Clone, Debug)]
pub struct SessionEventPage {
    pub records: Vec<SessionEventRecord>,
    pub end: SessionEventsEnd,
}

#[derive(Clone, Debug)]
pub struct SessionEvidencePage {
    pub records: Vec<SessionEvidenceRecord>,
    pub end: SessionEvidenceEnd,
}

impl DaemonClient {
    pub async fn context_delivery_inbox(
        &self,
        parent_session_id: impl Into<String>,
    ) -> Result<ContextDeliveryInboxResponse> {
        let mut client = self.context_client().await?;
        rpc(client
            .delivery_inbox(Request::new(ContextDeliveryInboxRequest {
                parent_session_id: parent_session_id.into(),
            }))
            .await)
    }

    pub async fn context_graph(
        &self,
        session_id: impl Into<String>,
    ) -> Result<ContextGraphResponse> {
        let mut client = self.context_client().await?;
        rpc(client
            .graph(Request::new(ContextGraphRequest {
                session_id: session_id.into(),
            }))
            .await)
    }

    pub async fn context_delivery_receive(
        &self,
        request: ContextDeliveryReceiveRequest,
        idempotency_key: &str,
    ) -> Result<ContextDeliveryDecisionResponse> {
        let mut client = self.context_client().await?;
        rpc(client
            .receive_delivery(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn context_delivery_reject(
        &self,
        request: ContextDeliveryRejectRequest,
        idempotency_key: &str,
    ) -> Result<ContextDeliveryDecisionResponse> {
        let mut client = self.context_client().await?;
        rpc(client
            .reject_delivery(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_create(
        &self,
        request: SessionCreateRequest,
        idempotency_key: &str,
    ) -> Result<SessionCreateResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .create(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_start(
        &self,
        session_id: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .start(self.mutation_request(
                SessionStartRequest {
                    session_id: session_id.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_stop(
        &self,
        session_id: impl Into<String>,
        grace_period_seconds: u64,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .stop(self.mutation_request(
                SessionStopRequest {
                    session_id: session_id.into(),
                    grace_period_seconds,
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_kill(
        &self,
        session_id: impl Into<String>,
        signal: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .kill(self.mutation_request(
                SessionKillRequest {
                    session_id: session_id.into(),
                    signal: signal.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_remove(
        &self,
        session_id: impl Into<String>,
        force: bool,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .remove(self.mutation_request(
                SessionRemoveRequest {
                    session_id: session_id.into(),
                    force,
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_inspect(&self, session_id: impl Into<String>) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .inspect(Request::new(SessionInspectRequest {
                session_id: session_id.into(),
            }))
            .await)
    }

    pub async fn session_list(&self) -> Result<SessionListResponse> {
        let mut client = self.session_client().await?;
        rpc(client.list(Request::new(SessionListRequest {})).await)
    }

    pub async fn session_alias_set(
        &self,
        alias: impl Into<String>,
        session_id: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionAliasRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .set_alias(self.mutation_request(
                SessionAliasSetRequest {
                    alias: alias.into(),
                    session_id: session_id.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_alias_remove(
        &self,
        alias: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionAliasRecord> {
        let mut client = self.session_client().await?;
        rpc(client
            .remove_alias(self.mutation_request(
                SessionAliasRemoveRequest {
                    alias: alias.into(),
                },
                idempotency_key,
            )?)
            .await)
    }

    pub async fn session_alias_list(&self) -> Result<SessionAliasListResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .list_aliases(Request::new(SessionAliasListRequest {}))
            .await)
    }

    pub async fn session_wait(
        &self,
        session_id: impl Into<String>,
        after_generation: u64,
    ) -> Result<SessionRecord> {
        let mut client = self.session_client().await?;
        let mut request = Request::new(SessionWaitRequest {
            session_id: session_id.into(),
            after_generation,
        });
        request.set_timeout(SESSION_WAIT_TIMEOUT);
        rpc(client.wait(request).await)
    }

    pub async fn session_logs(
        &self,
        session_id: impl Into<String>,
        stream_name: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionLogPage> {
        let mut client = self.session_client().await?;
        let mut stream = client
            .logs(Request::new(SessionLogsRequest {
                session_id: session_id.into(),
                stream: stream_name.into(),
                after_sequence,
                maximum_records,
            }))
            .await
            .map_err(rpc_error)?
            .into_inner();
        let mut records = Vec::new();
        let mut end = None;
        while let Some(item) = stream.message().await.map_err(rpc_error)? {
            match item.item {
                Some(session_log_stream_item::Item::Record(record)) => records.push(record),
                Some(session_log_stream_item::Item::End(value)) => end = Some(value),
                None => return missing_stream_item("session logs"),
            }
        }
        Ok(SessionLogPage {
            records,
            end: end.ok_or_else(|| missing_stream_end("session logs"))?,
        })
    }

    pub async fn session_events(
        &self,
        session_id: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionEventPage> {
        let mut client = self.session_client().await?;
        let mut stream = client
            .events(Request::new(SessionEventsRequest {
                session_id: session_id.into(),
                after_sequence,
                maximum_records,
            }))
            .await
            .map_err(rpc_error)?
            .into_inner();
        let mut records = Vec::new();
        let mut end = None;
        while let Some(item) = stream.message().await.map_err(rpc_error)? {
            match item.item {
                Some(session_event_stream_item::Item::Record(record)) => records.push(record),
                Some(session_event_stream_item::Item::End(value)) => end = Some(value),
                None => return missing_stream_item("session events"),
            }
        }
        Ok(SessionEventPage {
            records,
            end: end.ok_or_else(|| missing_stream_end("session events"))?,
        })
    }

    pub async fn session_evidence(
        &self,
        session_id: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionEvidencePage> {
        let mut client = self.session_client().await?;
        let mut stream = client
            .evidence(Request::new(SessionEvidenceRequest {
                session_id: session_id.into(),
                after_sequence,
                maximum_records,
            }))
            .await
            .map_err(rpc_error)?
            .into_inner();
        let mut records = Vec::new();
        let mut end = None;
        while let Some(item) = stream.message().await.map_err(rpc_error)? {
            match item.item {
                Some(session_evidence_stream_item::Item::Record(record)) => records.push(record),
                Some(session_evidence_stream_item::Item::End(value)) => end = Some(value),
                None => return missing_stream_item("session evidence"),
            }
        }
        Ok(SessionEvidencePage {
            records,
            end: end.ok_or_else(|| missing_stream_end("session evidence"))?,
        })
    }

    pub async fn session_attach(
        &self,
        request: SessionAttachRequest,
        idempotency_key: &str,
    ) -> Result<SessionAttachResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .attach(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_input_lease_renew(
        &self,
        request: SessionInputLeaseRenewRequest,
        idempotency_key: &str,
    ) -> Result<SessionInputLeaseResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .renew_input_lease(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_input_lease_release(
        &self,
        request: SessionInputLeaseReleaseRequest,
        idempotency_key: &str,
    ) -> Result<SessionInputLeaseResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .release_input_lease(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_input(
        &self,
        request: SessionInputRequest,
    ) -> Result<SessionInputResponse> {
        let mut client = self.session_client().await?;
        rpc(client.input(Request::new(request)).await)
    }

    pub async fn session_prune(
        &self,
        request: SessionPruneRequest,
        idempotency_key: &str,
    ) -> Result<SessionPruneResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .prune(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn session_terminal_resize(
        &self,
        request: SessionTerminalResizeRequest,
    ) -> Result<SessionTerminalResizeResponse> {
        let mut client = self.session_client().await?;
        rpc(client.resize_terminal(Request::new(request)).await)
    }

    pub async fn codex_app_server_attach(
        &self,
        request: CodexAppServerAttachRequest,
        idempotency_key: &str,
    ) -> Result<CodexAppServerAttachResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .attach_codex_app_server(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn codex_app_server_input(
        &self,
        request: CodexAppServerInputRequest,
    ) -> Result<CodexAppServerInputResponse> {
        let mut client = self.session_client().await?;
        rpc(client.input_codex_app_server(Request::new(request)).await)
    }

    pub async fn codex_app_server_input_close(
        &self,
        request: CodexAppServerInputCloseRequest,
    ) -> Result<CodexAppServerInputCloseResponse> {
        let mut client = self.session_client().await?;
        rpc(client
            .close_codex_app_server_input(Request::new(request))
            .await)
    }

    pub async fn admin_session_list(
        &self,
        target_uid: u32,
        all_users: bool,
    ) -> Result<SessionListResponse> {
        let mut client = self.administration_client().await?;
        rpc(client
            .list_sessions(Request::new(AdminSessionListRequest {
                target_uid,
                all_users,
            }))
            .await)
    }

    pub async fn admin_session_inspect(
        &self,
        target_uid: u32,
        session_id: impl Into<String>,
    ) -> Result<SessionRecord> {
        let mut client = self.administration_client().await?;
        rpc(client
            .inspect_session(Request::new(AdminSessionInspectRequest {
                target_uid,
                session_id: session_id.into(),
            }))
            .await)
    }

    pub async fn admin_session_stop(
        &self,
        request: AdminSessionStopRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.administration_client().await?;
        rpc(client
            .stop_session(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn admin_session_kill(
        &self,
        request: AdminSessionKillRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.administration_client().await?;
        rpc(client
            .kill_session(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    pub async fn admin_session_set_retention_hold(
        &self,
        request: AdminSessionSetRetentionHoldRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        let mut client = self.administration_client().await?;
        rpc(client
            .set_session_retention_hold(self.mutation_request(request, idempotency_key)?)
            .await)
    }

    async fn session_client(&self) -> Result<SessionServiceClient<tonic::transport::Channel>> {
        Ok(SessionServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }

    async fn context_client(&self) -> Result<ContextServiceClient<tonic::transport::Channel>> {
        Ok(ContextServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }

    async fn administration_client(
        &self,
    ) -> Result<AdministrationServiceClient<tonic::transport::Channel>> {
        Ok(AdministrationServiceClient::new(self.connect().await?)
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES))
    }
}

fn missing_stream_item<T>(name: &str) -> Result<T> {
    ProtocolSnafu {
        reason: format!("the {name} stream returned an empty item"),
    }
    .fail()
}

fn missing_stream_end(name: &str) -> crate::DaemonClientError {
    ProtocolSnafu {
        reason: format!("the {name} stream ended without its durable cursor"),
    }
    .build()
}
