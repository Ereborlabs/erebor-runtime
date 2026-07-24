use erebor_runtime_ipc::v1::{
    AdminSessionInspectRequest, AdminSessionKillRequest, AdminSessionListRequest,
    AdminSessionSetRetentionHoldRequest, AdminSessionStopRequest, CodexAppServerAttachRequest,
    CodexAppServerAttachResponse, CodexAppServerInputCloseRequest,
    CodexAppServerInputCloseResponse, CodexAppServerInputRequest, CodexAppServerInputResponse,
    ContextDeliveryDecisionResponse, ContextDeliveryInboxRequest, ContextDeliveryInboxResponse,
    ContextDeliveryReceiveRequest, ContextDeliveryRejectRequest, Header, SessionAliasListRequest,
    SessionAliasListResponse, SessionAliasRecord, SessionAliasRemoveRequest,
    SessionAliasSetRequest, SessionAttachRequest, SessionAttachResponse, SessionCreateRequest,
    SessionCreateResponse, SessionEventRecord, SessionEventsEnd, SessionEventsRequest,
    SessionEvidenceEnd, SessionEvidenceRecord, SessionEvidenceRequest,
    SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionInputLeaseResponse,
    SessionInputRequest, SessionInputResponse, SessionInspectRequest, SessionKillRequest,
    SessionListRequest, SessionListResponse, SessionLogChunk, SessionLogsEnd, SessionLogsRequest,
    SessionPruneRequest, SessionPruneResponse, SessionRecord, SessionRemoveRequest,
    SessionStartRequest, SessionStopRequest, SessionTerminalResizeRequest,
    SessionTerminalResizeResponse, SessionWaitRequest, EREBOR_IDEMPOTENCY_KEY_HEADER,
    KIND_ADMIN_SESSION_INSPECT_REQUEST, KIND_ADMIN_SESSION_KILL_REQUEST,
    KIND_ADMIN_SESSION_LIST_REQUEST, KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST,
    KIND_ADMIN_SESSION_STOP_REQUEST, KIND_CODEX_APP_SERVER_ATTACH_REQUEST,
    KIND_CODEX_APP_SERVER_ATTACH_RESPONSE, KIND_CODEX_APP_SERVER_INPUT_CLOSE_REQUEST,
    KIND_CODEX_APP_SERVER_INPUT_CLOSE_RESPONSE, KIND_CODEX_APP_SERVER_INPUT_REQUEST,
    KIND_CODEX_APP_SERVER_INPUT_RESPONSE, KIND_CONTEXT_DELIVERY_DECISION_RESPONSE,
    KIND_CONTEXT_DELIVERY_INBOX_REQUEST, KIND_CONTEXT_DELIVERY_INBOX_RESPONSE,
    KIND_CONTEXT_DELIVERY_RECEIVE_REQUEST, KIND_CONTEXT_DELIVERY_REJECT_REQUEST, KIND_DAEMON_ERROR,
    KIND_SESSION_ALIAS_LIST_REQUEST, KIND_SESSION_ALIAS_LIST_RESPONSE, KIND_SESSION_ALIAS_RECORD,
    KIND_SESSION_ALIAS_REMOVE_REQUEST, KIND_SESSION_ALIAS_SET_REQUEST, KIND_SESSION_ATTACH_REQUEST,
    KIND_SESSION_ATTACH_RESPONSE, KIND_SESSION_CREATE_REQUEST, KIND_SESSION_CREATE_RESPONSE,
    KIND_SESSION_EVENTS_END, KIND_SESSION_EVENTS_REQUEST, KIND_SESSION_EVENT_RECORD,
    KIND_SESSION_EVIDENCE_END, KIND_SESSION_EVIDENCE_RECORD, KIND_SESSION_EVIDENCE_REQUEST,
    KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST, KIND_SESSION_INPUT_LEASE_RENEW_REQUEST,
    KIND_SESSION_INPUT_LEASE_RESPONSE, KIND_SESSION_INPUT_REQUEST, KIND_SESSION_INPUT_RESPONSE,
    KIND_SESSION_INSPECT_REQUEST, KIND_SESSION_KILL_REQUEST, KIND_SESSION_LIST_REQUEST,
    KIND_SESSION_LIST_RESPONSE, KIND_SESSION_LOGS_END, KIND_SESSION_LOGS_REQUEST,
    KIND_SESSION_LOG_CHUNK, KIND_SESSION_PRUNE_REQUEST, KIND_SESSION_PRUNE_RESPONSE,
    KIND_SESSION_RECORD, KIND_SESSION_REMOVE_REQUEST, KIND_SESSION_START_REQUEST,
    KIND_SESSION_STOP_REQUEST, KIND_SESSION_TERMINAL_RESIZE_REQUEST,
    KIND_SESSION_TERMINAL_RESIZE_RESPONSE, KIND_SESSION_WAIT_REQUEST,
};
use snafu::ResultExt;
use std::time::Duration;

use crate::{
    error::{IpcSnafu, ProtocolSnafu},
    DaemonClient, Result, SESSION_MUTATION_TIMEOUT,
};

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
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_CONTEXT_DELIVERY_INBOX_REQUEST,
                &ContextDeliveryInboxRequest {
                    parent_session_id: parent_session_id.into(),
                },
                KIND_CONTEXT_DELIVERY_INBOX_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn context_delivery_receive(
        &self,
        request: ContextDeliveryReceiveRequest,
        idempotency_key: &str,
    ) -> Result<ContextDeliveryDecisionResponse> {
        self.session_mutation(
            KIND_CONTEXT_DELIVERY_RECEIVE_REQUEST,
            &request,
            KIND_CONTEXT_DELIVERY_DECISION_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn context_delivery_reject(
        &self,
        request: ContextDeliveryRejectRequest,
        idempotency_key: &str,
    ) -> Result<ContextDeliveryDecisionResponse> {
        self.session_mutation(
            KIND_CONTEXT_DELIVERY_REJECT_REQUEST,
            &request,
            KIND_CONTEXT_DELIVERY_DECISION_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_create(
        &self,
        request: SessionCreateRequest,
        idempotency_key: &str,
    ) -> Result<SessionCreateResponse> {
        self.session_mutation(
            KIND_SESSION_CREATE_REQUEST,
            &request,
            KIND_SESSION_CREATE_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_start(
        &self,
        session_id: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_SESSION_START_REQUEST,
            &SessionStartRequest {
                session_id: session_id.into(),
            },
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_stop(
        &self,
        session_id: impl Into<String>,
        grace_period_seconds: u64,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_SESSION_STOP_REQUEST,
            &SessionStopRequest {
                session_id: session_id.into(),
                grace_period_seconds,
            },
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_kill(
        &self,
        session_id: impl Into<String>,
        signal: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_SESSION_KILL_REQUEST,
            &SessionKillRequest {
                session_id: session_id.into(),
                signal: signal.into(),
            },
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_remove(
        &self,
        session_id: impl Into<String>,
        force: bool,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_SESSION_REMOVE_REQUEST,
            &SessionRemoveRequest {
                session_id: session_id.into(),
                force,
            },
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_inspect(&self, session_id: impl Into<String>) -> Result<SessionRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SESSION_INSPECT_REQUEST,
                &SessionInspectRequest {
                    session_id: session_id.into(),
                },
                KIND_SESSION_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn session_list(&self) -> Result<SessionListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SESSION_LIST_REQUEST,
                &SessionListRequest {},
                KIND_SESSION_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn session_alias_set(
        &self,
        alias: impl Into<String>,
        session_id: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionAliasRecord> {
        self.session_mutation(
            KIND_SESSION_ALIAS_SET_REQUEST,
            &SessionAliasSetRequest {
                alias: alias.into(),
                session_id: session_id.into(),
            },
            KIND_SESSION_ALIAS_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_alias_remove(
        &self,
        alias: impl Into<String>,
        idempotency_key: &str,
    ) -> Result<SessionAliasRecord> {
        self.session_mutation(
            KIND_SESSION_ALIAS_REMOVE_REQUEST,
            &SessionAliasRemoveRequest {
                alias: alias.into(),
            },
            KIND_SESSION_ALIAS_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn session_alias_list(&self) -> Result<SessionAliasListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SESSION_ALIAS_LIST_REQUEST,
                &SessionAliasListRequest {},
                KIND_SESSION_ALIAS_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn session_wait(
        &self,
        session_id: impl Into<String>,
        after_generation: u64,
    ) -> Result<SessionRecord> {
        let mut connection = self.connect().await?;
        let request_id = connection
            .send(
                KIND_SESSION_WAIT_REQUEST,
                &SessionWaitRequest {
                    session_id: session_id.into(),
                    after_generation,
                },
                Vec::new(),
            )
            .await?;
        let envelope = connection
            .receive_with_timeout(request_id, SESSION_WAIT_TIMEOUT)
            .await?;
        if envelope.message_kind == KIND_DAEMON_ERROR {
            return Err(connection.daemon_error(envelope)?);
        }
        envelope
            .decode_typed_payload(KIND_SESSION_RECORD)
            .context(IpcSnafu)
    }

    pub async fn session_logs(
        &self,
        session_id: impl Into<String>,
        stream: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionLogPage> {
        let mut connection = self.connect().await?;
        let request_id = connection
            .send(
                KIND_SESSION_LOGS_REQUEST,
                &SessionLogsRequest {
                    session_id: session_id.into(),
                    stream: stream.into(),
                    after_sequence,
                    maximum_records,
                },
                Vec::new(),
            )
            .await?;
        let mut records = Vec::new();
        loop {
            let envelope = connection.receive(request_id).await?;
            match envelope.message_kind.as_str() {
                KIND_SESSION_LOG_CHUNK => records.push(
                    envelope
                        .decode_typed_payload(KIND_SESSION_LOG_CHUNK)
                        .context(IpcSnafu)?,
                ),
                KIND_SESSION_LOGS_END => {
                    let end = envelope
                        .decode_typed_payload(KIND_SESSION_LOGS_END)
                        .context(IpcSnafu)?;
                    return Ok(SessionLogPage { records, end });
                }
                KIND_DAEMON_ERROR => return Err(connection.daemon_error(envelope)?),
                actual => {
                    return ProtocolSnafu {
                        reason: format!("unexpected session logs response kind `{actual}`"),
                    }
                    .fail();
                }
            }
        }
    }

    pub async fn session_events(
        &self,
        session_id: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionEventPage> {
        let mut connection = self.connect().await?;
        let request_id = connection
            .send(
                KIND_SESSION_EVENTS_REQUEST,
                &SessionEventsRequest {
                    session_id: session_id.into(),
                    after_sequence,
                    maximum_records,
                },
                Vec::new(),
            )
            .await?;
        let mut records = Vec::new();
        loop {
            let envelope = connection.receive(request_id).await?;
            match envelope.message_kind.as_str() {
                KIND_SESSION_EVENT_RECORD => records.push(
                    envelope
                        .decode_typed_payload(KIND_SESSION_EVENT_RECORD)
                        .context(IpcSnafu)?,
                ),
                KIND_SESSION_EVENTS_END => {
                    let end = envelope
                        .decode_typed_payload(KIND_SESSION_EVENTS_END)
                        .context(IpcSnafu)?;
                    return Ok(SessionEventPage { records, end });
                }
                KIND_DAEMON_ERROR => return Err(connection.daemon_error(envelope)?),
                actual => {
                    return ProtocolSnafu {
                        reason: format!("unexpected session events response kind `{actual}`"),
                    }
                    .fail();
                }
            }
        }
    }

    pub async fn session_evidence(
        &self,
        session_id: impl Into<String>,
        after_sequence: u64,
        maximum_records: u32,
    ) -> Result<SessionEvidencePage> {
        let mut connection = self.connect().await?;
        let request_id = connection
            .send(
                KIND_SESSION_EVIDENCE_REQUEST,
                &SessionEvidenceRequest {
                    session_id: session_id.into(),
                    after_sequence,
                    maximum_records,
                },
                Vec::new(),
            )
            .await?;
        let mut records = Vec::new();
        loop {
            let envelope = connection.receive(request_id).await?;
            match envelope.message_kind.as_str() {
                KIND_SESSION_EVIDENCE_RECORD => records.push(
                    envelope
                        .decode_typed_payload(KIND_SESSION_EVIDENCE_RECORD)
                        .context(IpcSnafu)?,
                ),
                KIND_SESSION_EVIDENCE_END => {
                    let end = envelope
                        .decode_typed_payload(KIND_SESSION_EVIDENCE_END)
                        .context(IpcSnafu)?;
                    return Ok(SessionEvidencePage { records, end });
                }
                KIND_DAEMON_ERROR => return Err(connection.daemon_error(envelope)?),
                actual => {
                    return ProtocolSnafu {
                        reason: format!("unexpected session evidence response kind `{actual}`"),
                    }
                    .fail();
                }
            }
        }
    }

    pub async fn session_attach(
        &self,
        request: SessionAttachRequest,
        idempotency_key: &str,
    ) -> Result<SessionAttachResponse> {
        self.session_mutation(
            KIND_SESSION_ATTACH_REQUEST,
            &request,
            KIND_SESSION_ATTACH_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_input_lease_renew(
        &self,
        request: SessionInputLeaseRenewRequest,
        idempotency_key: &str,
    ) -> Result<SessionInputLeaseResponse> {
        self.session_mutation(
            KIND_SESSION_INPUT_LEASE_RENEW_REQUEST,
            &request,
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_input_lease_release(
        &self,
        request: SessionInputLeaseReleaseRequest,
        idempotency_key: &str,
    ) -> Result<SessionInputLeaseResponse> {
        self.session_mutation(
            KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST,
            &request,
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_input(
        &self,
        request: SessionInputRequest,
    ) -> Result<SessionInputResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SESSION_INPUT_REQUEST,
                &request,
                KIND_SESSION_INPUT_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn session_prune(
        &self,
        request: SessionPruneRequest,
        idempotency_key: &str,
    ) -> Result<SessionPruneResponse> {
        self.session_mutation(
            KIND_SESSION_PRUNE_REQUEST,
            &request,
            KIND_SESSION_PRUNE_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn session_terminal_resize(
        &self,
        request: SessionTerminalResizeRequest,
    ) -> Result<SessionTerminalResizeResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_SESSION_TERMINAL_RESIZE_REQUEST,
                &request,
                KIND_SESSION_TERMINAL_RESIZE_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn codex_app_server_attach(
        &self,
        request: CodexAppServerAttachRequest,
        idempotency_key: &str,
    ) -> Result<CodexAppServerAttachResponse> {
        self.session_mutation(
            KIND_CODEX_APP_SERVER_ATTACH_REQUEST,
            &request,
            KIND_CODEX_APP_SERVER_ATTACH_RESPONSE,
            idempotency_key,
        )
        .await
    }

    pub async fn codex_app_server_input(
        &self,
        request: CodexAppServerInputRequest,
    ) -> Result<CodexAppServerInputResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_CODEX_APP_SERVER_INPUT_REQUEST,
                &request,
                KIND_CODEX_APP_SERVER_INPUT_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn codex_app_server_input_close(
        &self,
        request: CodexAppServerInputCloseRequest,
    ) -> Result<CodexAppServerInputCloseResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_CODEX_APP_SERVER_INPUT_CLOSE_REQUEST,
                &request,
                KIND_CODEX_APP_SERVER_INPUT_CLOSE_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn admin_session_list(
        &self,
        target_uid: u32,
        all_users: bool,
    ) -> Result<SessionListResponse> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_ADMIN_SESSION_LIST_REQUEST,
                &AdminSessionListRequest {
                    target_uid,
                    all_users,
                },
                KIND_SESSION_LIST_RESPONSE,
                Vec::new(),
            )
            .await
    }

    pub async fn admin_session_inspect(
        &self,
        target_uid: u32,
        session_id: impl Into<String>,
    ) -> Result<SessionRecord> {
        let mut connection = self.connect().await?;
        connection
            .unary(
                KIND_ADMIN_SESSION_INSPECT_REQUEST,
                &AdminSessionInspectRequest {
                    target_uid,
                    session_id: session_id.into(),
                },
                KIND_SESSION_RECORD,
                Vec::new(),
            )
            .await
    }

    pub async fn admin_session_stop(
        &self,
        request: AdminSessionStopRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_ADMIN_SESSION_STOP_REQUEST,
            &request,
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn admin_session_kill(
        &self,
        request: AdminSessionKillRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_ADMIN_SESSION_KILL_REQUEST,
            &request,
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub async fn admin_session_set_retention_hold(
        &self,
        request: AdminSessionSetRetentionHoldRequest,
        idempotency_key: &str,
    ) -> Result<SessionRecord> {
        self.session_mutation(
            KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST,
            &request,
            KIND_SESSION_RECORD,
            idempotency_key,
        )
        .await
    }

    pub(crate) async fn session_mutation<T: prost::Message, R: prost::Message + Default>(
        &self,
        kind: &str,
        request: &T,
        response_kind: &str,
        idempotency_key: &str,
    ) -> Result<R> {
        let mut connection = self.connect().await?;
        connection
            .unary_with_timeout(
                kind,
                request,
                response_kind,
                vec![Header {
                    key: EREBOR_IDEMPOTENCY_KEY_HEADER.to_owned(),
                    value: idempotency_key.to_owned(),
                }],
                SESSION_MUTATION_TIMEOUT,
            )
            .await
    }
}
