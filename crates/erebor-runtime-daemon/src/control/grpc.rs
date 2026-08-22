#![allow(clippy::result_large_err)]

use std::{pin::Pin, sync::Arc};

use erebor_runtime_approvals::ApprovalRepository;
use erebor_runtime_error::{ErrorExt, StatusCode};
use erebor_runtime_ipc::{
    transport::{UnixPeerIdentity, IDEMPOTENCY_KEY_METADATA},
    v1::{
        administration_service_server::{AdministrationService, AdministrationServiceServer},
        agent_service_server::{AgentService, AgentServiceServer},
        approval_service_server::{ApprovalService, ApprovalServiceServer},
        context_service_server::{ContextService, ContextServiceServer},
        daemon_lifecycle_service_server::{DaemonLifecycleService, DaemonLifecycleServiceServer},
        filesystem_service_server::{FilesystemService, FilesystemServiceServer},
        policy_service_server::{PolicyService, PolicyServiceServer},
        runner_service_server::{RunnerService, RunnerServiceServer},
        session_service_server::{SessionService, SessionServiceServer},
        surface_service_server::{SurfaceService, SurfaceServiceServer},
        AdminSessionInspectRequest, AdminSessionKillRequest, AdminSessionListRequest,
        AdminSessionSetRetentionHoldRequest, AdminSessionStopRequest, AgentInstallRequest,
        AgentInstallResponse, ApprovalApproveRequest, ApprovalDenyRequest, ApprovalInspectRequest,
        ApprovalListRequest, ApprovalListResponse, ApprovalRecord as ApprovalRecordMessage,
        CodexAppServerAttachRequest, CodexAppServerAttachResponse, CodexAppServerInputCloseRequest,
        CodexAppServerInputCloseResponse, CodexAppServerInputRequest, CodexAppServerInputResponse,
        CodexRunRequest, ContextDeliveryDecisionResponse, ContextDeliveryInboxRequest,
        ContextDeliveryInboxResponse, ContextDeliveryReceiveRequest, ContextDeliveryRecord,
        ContextDeliveryRejectRequest, ContextGraphActivity, ContextGraphRequest,
        ContextGraphResponse, ContextScopeGraphNode, DaemonCommandResult,
        DaemonLogRecord as DaemonLogRecordMessage, DaemonLogsRequest, DaemonReloadRequest,
        DaemonStatusRequest, DaemonStatusResponse, DaemonStopRequest, FilesystemMutationRequest,
        FilesystemOperationResponse, FilesystemQueryRequest, PolicyPackageApplyRequest,
        PolicyPackageInspectRequest, PolicyPackageListRequest, PolicyPackageListResponse,
        PolicyPackageRecord, PolicyPackageVerifyRequest, PolicySetCreateRequest,
        PolicySetInspectRequest, PolicySetListRequest, PolicySetListResponse, PolicySetRecord,
        PolicySetVerifyRequest, PolicyTestRequest, PolicyTestResponse, RpcErrorDetail,
        RunnerCapabilityRecord, RunnerInspectRequest, RunnerListRequest, RunnerListResponse,
        SessionAliasListRequest, SessionAliasListResponse, SessionAliasRecord,
        SessionAliasRemoveRequest, SessionAliasSetRequest, SessionAttachRequest,
        SessionAttachResponse, SessionCreateRequest, SessionCreateResponse, SessionEventRecord,
        SessionEventStreamItem, SessionEventsEnd, SessionEventsRequest, SessionEvidenceEnd,
        SessionEvidenceRecord, SessionEvidenceRequest, SessionEvidenceStreamItem,
        SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionInputLeaseResponse,
        SessionInputRequest, SessionInputResponse, SessionInspectRequest, SessionKillRequest,
        SessionListRequest, SessionListResponse, SessionLogChunk, SessionLogStreamItem,
        SessionLogsEnd, SessionLogsRequest, SessionPruneRequest, SessionPruneResponse,
        SessionRecord, SessionRemoveRequest, SessionStartRequest, SessionStopRequest,
        SessionTerminalResizeRequest, SessionTerminalResizeResponse, SessionWaitRequest,
        SurfaceCreateRequest, SurfaceInspectRequest, SurfaceListRequest, SurfaceListResponse,
        SurfaceRecord,
    },
};
use futures_util::{stream, Stream, StreamExt};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::{transport::Server, Code, Request, Response, Status};

use super::{
    evaluate_policy_test, parse_signal, runner_capability_record, DaemonControlState, PeerIdentity,
    PerUidStreamPermit,
};
use crate::{
    error::StateLockSnafu,
    idempotency::{IdempotencyAction, MutationIntent, MutationResponse, MutationResponseType},
    DaemonError, Result,
};
use erebor_runtime_session::StreamKind;

type RpcStream<T> = Pin<Box<dyn Stream<Item = std::result::Result<T, Status>> + Send + 'static>>;

#[derive(Clone)]
pub(super) struct DaemonGrpc {
    state: Arc<DaemonControlState>,
}

struct MutationContext {
    key: String,
    fingerprint: [u8; 32],
}

impl DaemonGrpc {
    pub(super) fn new(state: Arc<DaemonControlState>) -> Self {
        Self { state }
    }

    fn peer<T>(request: &Request<T>) -> std::result::Result<PeerIdentity, Status> {
        request
            .extensions()
            .get::<UnixPeerIdentity>()
            .copied()
            .map(|peer| PeerIdentity {
                uid: peer.uid,
                gid: peer.gid,
            })
            .ok_or_else(|| Status::unauthenticated("local peer credentials are unavailable"))
    }

    fn mutation_context<T: Message>(
        request: &Request<T>,
        method: &'static str,
    ) -> std::result::Result<MutationContext, Status> {
        let key = request
            .metadata()
            .get(IDEMPOTENCY_KEY_METADATA)
            .ok_or_else(|| Status::invalid_argument("the idempotency key is required"))?
            .to_str()
            .map_err(|_error| Status::invalid_argument("the idempotency key is invalid"))?;
        if key.is_empty() || key.len() > 256 {
            return Err(Status::invalid_argument(
                "the idempotency key must contain between 1 and 256 bytes",
            ));
        }
        let mut encoded = Vec::with_capacity(request.get_ref().encoded_len());
        request
            .get_ref()
            .encode(&mut encoded)
            .map_err(|_error| Status::invalid_argument("the request cannot be encoded"))?;
        let mut digest = Sha256::new();
        digest.update(b"erebor.daemon.grpc-request.v1\0");
        digest.update((method.len() as u64).to_le_bytes());
        digest.update(method.as_bytes());
        digest.update((encoded.len() as u64).to_le_bytes());
        digest.update(encoded);
        Ok(MutationContext {
            key: key.to_owned(),
            fingerprint: digest.finalize().into(),
        })
    }

    fn mutate<R: Message + Default>(
        &self,
        peer: PeerIdentity,
        operation: &'static str,
        context: MutationContext,
        intent: MutationIntent,
        response_type: MutationResponseType,
    ) -> std::result::Result<(R, bool), Status> {
        let store = self
            .state
            .idempotency
            .lock()
            .map_err(|_error| status(StateLockSnafu.build()))?;
        let action = store
            .prepare(
                peer.uid,
                operation,
                &context.key,
                context.fingerprint,
                intent,
            )
            .map_err(status)?;
        let (response, applied) = match action {
            IdempotencyAction::ReturnCompleted(response) => (response, false),
            IdempotencyAction::Execute(intent) => {
                let response = self.state.apply_mutation(&intent, false).map_err(status)?;
                store
                    .complete(
                        peer.uid,
                        operation,
                        &context.key,
                        context.fingerprint,
                        *intent,
                        response.clone(),
                    )
                    .map_err(status)?;
                (response, true)
            }
            IdempotencyAction::ResumePending(intent) => {
                let response = self.state.apply_mutation(&intent, true).map_err(status)?;
                store
                    .complete(
                        peer.uid,
                        operation,
                        &context.key,
                        context.fingerprint,
                        *intent,
                        response.clone(),
                    )
                    .map_err(status)?;
                (response, true)
            }
        };
        decode_mutation(response, response_type).map(|response| (response, applied))
    }

    fn stream<T: Send + 'static>(&self, permit: PerUidStreamPermit, items: Vec<T>) -> RpcStream<T> {
        Box::pin(stream::iter(items.into_iter().map(Ok)).map(move |item| {
            let _permit = &permit;
            item
        }))
    }
}

pub(super) async fn serve(
    listener: tokio::net::UnixListener,
    state: Arc<DaemonControlState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::result::Result<(), tonic::transport::Error> {
    let service = DaemonGrpc::new(state);
    let limit = erebor_runtime_ipc::transport::MAX_GRPC_MESSAGE_BYTES;
    Server::builder()
        .timeout(super::REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(super::CONNECTION_LIMIT)
        .add_service(
            DaemonLifecycleServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            AgentServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            SessionServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            FilesystemServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            ContextServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            AdministrationServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            ApprovalServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            PolicyServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            SurfaceServiceServer::new(service.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .add_service(
            RunnerServiceServer::new(service)
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit),
        )
        .serve_with_incoming_shutdown(
            erebor_runtime_ipc::transport::UnixIncoming::new(listener),
            async move {
                while !*shutdown.borrow() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
            },
        )
        .await
}

#[tonic::async_trait]
impl DaemonLifecycleService for DaemonGrpc {
    type LogsStream = RpcStream<DaemonLogRecordMessage>;

    async fn status(
        &self,
        request: Request<DaemonStatusRequest>,
    ) -> std::result::Result<Response<DaemonStatusResponse>, Status> {
        let _peer = Self::peer(&request)?;
        let generation = self
            .state
            .configuration
            .read()
            .map_err(|_error| status(StateLockSnafu.build()))?
            .generation;
        Ok(Response::new(DaemonStatusResponse {
            daemon_pid: i64::from(std::process::id()),
            configuration_generation: generation,
            service_state: String::from("running"),
        }))
    }

    async fn logs(
        &self,
        request: Request<DaemonLogsRequest>,
    ) -> std::result::Result<Response<Self::LogsStream>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let permit = self.state.acquire_stream_permit(peer.uid).map_err(status)?;
        let request = request.into_inner();
        let maximum = usize::try_from(request.maximum_records.max(1)).map_err(|_error| {
            Status::invalid_argument("the maximum log record count is invalid")
        })?;
        let configured = self
            .state
            .configuration
            .read()
            .map_err(|_error| status(StateLockSnafu.build()))?
            .value
            .max_log_records as usize;
        let records = self
            .state
            .telemetry
            .records_after(request.after_sequence, maximum.min(configured))
            .map_err(|source| {
                status(DaemonError::Telemetry {
                    source,
                    location: snafu::Location::default(),
                })
            })?
            .into_iter()
            .map(|record| {
                let message = record.rendered_message();
                DaemonLogRecordMessage {
                    sequence: record.sequence,
                    timestamp: record.timestamp,
                    level: record.level,
                    message,
                }
            })
            .collect();
        Ok(Response::new(self.stream(permit, records)))
    }

    async fn reload(
        &self,
        request: Request<DaemonReloadRequest>,
    ) -> std::result::Result<Response<DaemonCommandResult>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context = Self::mutation_context(&request, "DaemonLifecycleService/Reload")?;
        let configuration =
            crate::config::DaemonConfig::load(&self.state.paths, self.state.security)
                .map_err(status)?;
        let generation = self.state.next_configuration_generation().map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "reload",
            context,
            MutationIntent::Reload {
                configuration,
                generation,
            },
            MutationResponseType::DaemonCommandResult,
        )?;
        Ok(Response::new(response))
    }

    async fn stop(
        &self,
        request: Request<DaemonStopRequest>,
    ) -> std::result::Result<Response<DaemonCommandResult>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        if self
            .state
            .sessions
            .has_unresolved_sessions()
            .map_err(status)?
        {
            return Err(Status::failed_precondition(
                "graceful daemon stop refuses while sessions remain unresolved",
            ));
        }
        let context = Self::mutation_context(&request, "DaemonLifecycleService/Stop")?;
        let (response, _applied) = self.mutate(
            peer,
            "stop",
            context,
            MutationIntent::Stop,
            MutationResponseType::DaemonCommandResult,
        )?;
        let _result = self.state.shutdown.send(true);
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl AgentService for DaemonGrpc {
    async fn install(
        &self,
        request: Request<AgentInstallRequest>,
    ) -> std::result::Result<Response<AgentInstallResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "AgentService/Install")?;
        let request = request.into_inner();
        let verified = self
            .state
            .sessions
            .verify_codex_installation(
                &request.package_name,
                &request.adapter,
                std::path::Path::new(&request.source_path),
                peer.uid,
                peer.gid,
            )
            .map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "agent-install",
            context,
            MutationIntent::AgentInstall {
                uid: peer.uid,
                agent_name: request.name,
                package_digest: verified.package_digest().to_owned(),
                installed_at_unix_ms: crate::session_api::DaemonSessionApi::installation_time(),
                artifact: verified.artifact().clone(),
            },
            MutationResponseType::AgentInstallResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn run_codex(
        &self,
        request: Request<CodexRunRequest>,
    ) -> std::result::Result<Response<SessionCreateResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "AgentService/RunCodex")?;
        let (generation, configuration) = {
            let active = self
                .state
                .configuration
                .read()
                .map_err(|_error| status(StateLockSnafu.build()))?;
            (active.generation, active.value.clone())
        };
        let spec = self
            .state
            .sessions
            .admit_codex_run(
                request.into_inner(),
                peer.uid,
                peer.gid,
                generation,
                &configuration,
            )
            .map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "codex-run",
            context,
            MutationIntent::SessionCreate {
                spec: Box::new(spec),
            },
            MutationResponseType::SessionCreateResponse,
        )?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl SessionService for DaemonGrpc {
    type LogsStream = RpcStream<SessionLogStreamItem>;
    type EventsStream = RpcStream<SessionEventStreamItem>;
    type EvidenceStream = RpcStream<SessionEvidenceStreamItem>;

    async fn create(
        &self,
        request: Request<SessionCreateRequest>,
    ) -> std::result::Result<Response<SessionCreateResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Create")?;
        let request = request.into_inner();
        let intent = if crate::session_api::DaemonSessionApi::admits_static_association(&request) {
            let admission = self
                .state
                .sessions
                .admit_static_session(request, peer.uid)
                .map_err(status)?;
            MutationIntent::StaticSessionCreate {
                uid: peer.uid,
                admission,
            }
        } else {
            let (generation, configuration) = {
                let active = self
                    .state
                    .configuration
                    .read()
                    .map_err(|_error| status(StateLockSnafu.build()))?;
                (active.generation, active.value.clone())
            };
            let spec = self
                .state
                .sessions
                .admit_request(request, peer.uid, peer.gid, generation, &configuration)
                .map_err(status)?;
            MutationIntent::SessionCreate {
                spec: Box::new(spec),
            }
        };
        let (response, _applied) = self.mutate(
            peer,
            "session-create",
            context,
            intent,
            MutationResponseType::SessionCreateResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn start(
        &self,
        request: Request<SessionStartRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Start")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-start",
            context,
            MutationIntent::SessionStart {
                uid: peer.uid,
                session_id: request.session_id,
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn stop(
        &self,
        request: Request<SessionStopRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Stop")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-stop",
            context,
            MutationIntent::SessionStop {
                uid: peer.uid,
                session_id: request.session_id,
                grace_period_seconds: request.grace_period_seconds.max(1),
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn kill(
        &self,
        request: Request<SessionKillRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Kill")?;
        let request = request.into_inner();
        let signal = parse_signal(&request.signal).map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "session-kill",
            context,
            MutationIntent::SessionKill {
                uid: peer.uid,
                session_id: request.session_id,
                signal,
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn remove(
        &self,
        request: Request<SessionRemoveRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Remove")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-remove",
            context,
            MutationIntent::SessionRemove {
                uid: peer.uid,
                session_id: request.session_id,
                force: request.force,
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn inspect(
        &self,
        request: Request<SessionInspectRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let record = self
            .state
            .sessions
            .inspect(peer.uid, &request.into_inner().session_id)
            .map_err(status)?;
        Ok(Response::new(record))
    }

    async fn list(
        &self,
        request: Request<SessionListRequest>,
    ) -> std::result::Result<Response<SessionListResponse>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state.sessions.list(peer.uid).map_err(status)?,
        ))
    }

    async fn wait(
        &self,
        request: Request<SessionWaitRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let record = self
            .state
            .sessions
            .wait(peer.uid, &request.session_id)
            .map_err(status)?;
        Ok(Response::new(record))
    }

    async fn logs(
        &self,
        request: Request<SessionLogsRequest>,
    ) -> std::result::Result<Response<Self::LogsStream>, Status> {
        let peer = Self::peer(&request)?;
        let permit = self.state.acquire_stream_permit(peer.uid).map_err(status)?;
        let request = request.into_inner();
        let kind = match request.stream.as_str() {
            "stdout" => StreamKind::Stdout,
            "stderr" => StreamKind::Stderr,
            _ => {
                return Err(Status::invalid_argument(
                    "the log stream must be stdout or stderr",
                ))
            }
        };
        let session_id = self
            .state
            .sessions
            .resolve_session_reference(peer.uid, &request.session_id)
            .map_err(status)?;
        let page = self
            .state
            .sessions
            .stream(
                peer.uid,
                &session_id,
                kind,
                request.after_sequence,
                request.maximum_records.max(1) as usize,
            )
            .map_err(status)?;
        let mut items = page
            .records()
            .iter()
            .map(|record| SessionLogStreamItem {
                item: Some(
                    erebor_runtime_ipc::v1::session_log_stream_item::Item::Record(
                        SessionLogChunk {
                            session_id: session_id.clone(),
                            stream: request.stream.clone(),
                            sequence: record.sequence(),
                            timestamp_unix_ms: record.timestamp_unix_ms(),
                            data: record.data().to_vec(),
                            durable: true,
                        },
                    ),
                ),
            })
            .collect::<Vec<_>>();
        items.push(SessionLogStreamItem {
            item: Some(erebor_runtime_ipc::v1::session_log_stream_item::Item::End(
                SessionLogsEnd {
                    session_id,
                    stream: request.stream,
                    durable_cursor: page.durable_cursor(),
                    truncated_before_cursor: page.truncated_before_cursor(),
                },
            )),
        });
        Ok(Response::new(self.stream(permit, items)))
    }

    async fn events(
        &self,
        request: Request<SessionEventsRequest>,
    ) -> std::result::Result<Response<Self::EventsStream>, Status> {
        let peer = Self::peer(&request)?;
        let permit = self.state.acquire_stream_permit(peer.uid).map_err(status)?;
        let request = request.into_inner();
        let session_id = self
            .state
            .sessions
            .resolve_session_reference(peer.uid, &request.session_id)
            .map_err(status)?;
        let page = self
            .state
            .sessions
            .stream(
                peer.uid,
                &session_id,
                StreamKind::Events,
                request.after_sequence,
                request.maximum_records.max(1) as usize,
            )
            .map_err(status)?;
        let mut items = page
            .records()
            .iter()
            .map(|record| SessionEventStreamItem {
                item: Some(
                    erebor_runtime_ipc::v1::session_event_stream_item::Item::Record(
                        SessionEventRecord {
                            session_id: session_id.clone(),
                            sequence: record.sequence(),
                            timestamp_unix_ms: record.timestamp_unix_ms(),
                            event_kind: record.source().to_owned(),
                            payload: record.data().to_vec(),
                            durable: true,
                        },
                    ),
                ),
            })
            .collect::<Vec<_>>();
        items.push(SessionEventStreamItem {
            item: Some(
                erebor_runtime_ipc::v1::session_event_stream_item::Item::End(SessionEventsEnd {
                    session_id,
                    durable_cursor: page.durable_cursor(),
                    truncated_before_cursor: page.truncated_before_cursor(),
                }),
            ),
        });
        Ok(Response::new(self.stream(permit, items)))
    }

    async fn evidence(
        &self,
        request: Request<SessionEvidenceRequest>,
    ) -> std::result::Result<Response<Self::EvidenceStream>, Status> {
        let peer = Self::peer(&request)?;
        let permit = self.state.acquire_stream_permit(peer.uid).map_err(status)?;
        let request = request.into_inner();
        let session_id = self
            .state
            .sessions
            .resolve_session_reference(peer.uid, &request.session_id)
            .map_err(status)?;
        let page = self
            .state
            .sessions
            .stream(
                peer.uid,
                &session_id,
                StreamKind::Evidence,
                request.after_sequence,
                request.maximum_records.max(1) as usize,
            )
            .map_err(status)?;
        let mut items = page
            .records()
            .iter()
            .map(|record| SessionEvidenceStreamItem {
                item: Some(
                    erebor_runtime_ipc::v1::session_evidence_stream_item::Item::Record(
                        SessionEvidenceRecord {
                            session_id: session_id.clone(),
                            sequence: record.sequence(),
                            timestamp_unix_ms: record.timestamp_unix_ms(),
                            source: record.source().to_owned(),
                            payload: record.data().to_vec(),
                            durable: true,
                        },
                    ),
                ),
            })
            .collect::<Vec<_>>();
        items.push(SessionEvidenceStreamItem {
            item: Some(
                erebor_runtime_ipc::v1::session_evidence_stream_item::Item::End(
                    SessionEvidenceEnd {
                        session_id,
                        durable_cursor: page.durable_cursor(),
                        truncated_before_cursor: page.truncated_before_cursor(),
                    },
                ),
            ),
        });
        Ok(Response::new(self.stream(permit, items)))
    }

    async fn attach(
        &self,
        request: Request<SessionAttachRequest>,
    ) -> std::result::Result<Response<SessionAttachResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Attach")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-attach",
            context,
            MutationIntent::SessionAttach {
                uid: peer.uid,
                session_id: request.session_id,
                request_input_lease: request.request_input_lease,
                client_instance_id: request.client_instance_id,
            },
            MutationResponseType::SessionAttachResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn renew_input_lease(
        &self,
        request: Request<SessionInputLeaseRenewRequest>,
    ) -> std::result::Result<Response<SessionInputLeaseResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/RenewInputLease")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-input-lease-renew",
            context,
            MutationIntent::SessionInputLeaseRenew {
                uid: peer.uid,
                session_id: request.session_id,
                lease_id: request.input_lease_id,
                client_instance_id: request.client_instance_id,
            },
            MutationResponseType::SessionInputLeaseResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn release_input_lease(
        &self,
        request: Request<SessionInputLeaseReleaseRequest>,
    ) -> std::result::Result<Response<SessionInputLeaseResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/ReleaseInputLease")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-input-lease-release",
            context,
            MutationIntent::SessionInputLeaseRelease {
                uid: peer.uid,
                session_id: request.session_id,
                lease_id: request.input_lease_id,
                client_instance_id: request.client_instance_id,
            },
            MutationResponseType::SessionInputLeaseResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn input(
        &self,
        request: Request<SessionInputRequest>,
    ) -> std::result::Result<Response<SessionInputResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let maximum = self
            .state
            .configuration
            .read()
            .map_err(|_error| status(StateLockSnafu.build()))?
            .value
            .max_ipc_upload_bytes_per_uid();
        if request.data.is_empty() || request.data.len() as u64 > maximum {
            return Err(Status::resource_exhausted(format!(
                "interactive input must contain between one and {maximum} bytes"
            )));
        }
        let response = self
            .state
            .sessions
            .input(
                peer.uid,
                &request.session_id,
                &request.input_lease_id,
                &request.client_instance_id,
                &request.data,
            )
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn resize_terminal(
        &self,
        request: Request<SessionTerminalResizeRequest>,
    ) -> std::result::Result<Response<SessionTerminalResizeResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let response = self
            .state
            .sessions
            .resize_terminal(
                peer.uid,
                &request.session_id,
                &request.input_lease_id,
                &request.client_instance_id,
                request.rows,
                request.columns,
            )
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn attach_codex_app_server(
        &self,
        request: Request<CodexAppServerAttachRequest>,
    ) -> std::result::Result<Response<CodexAppServerAttachResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/AttachCodexAppServer")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "codex-app-server-attach",
            context,
            MutationIntent::CodexAppServerAttach {
                uid: peer.uid,
                session_id: request.session_id,
                client_instance_id: request.client_instance_id,
            },
            MutationResponseType::CodexAppServerAttachResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn input_codex_app_server(
        &self,
        request: Request<CodexAppServerInputRequest>,
    ) -> std::result::Result<Response<CodexAppServerInputResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let maximum = self
            .state
            .configuration
            .read()
            .map_err(|_error| status(StateLockSnafu.build()))?
            .value
            .max_ipc_upload_bytes_per_uid();
        if request.jsonl_frame.is_empty() || request.jsonl_frame.len() as u64 > maximum {
            return Err(Status::resource_exhausted(format!(
                "Codex App Server input must contain between one and {maximum} bytes"
            )));
        }
        let response = self
            .state
            .sessions
            .codex_app_server_input(
                peer.uid,
                &request.session_id,
                &request.input_lease_id,
                &request.client_instance_id,
                &request.jsonl_frame,
            )
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn close_codex_app_server_input(
        &self,
        request: Request<CodexAppServerInputCloseRequest>,
    ) -> std::result::Result<Response<CodexAppServerInputCloseResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let response = self
            .state
            .sessions
            .close_codex_app_server_input(
                peer.uid,
                &request.session_id,
                &request.input_lease_id,
                &request.client_instance_id,
            )
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn prune(
        &self,
        request: Request<SessionPruneRequest>,
    ) -> std::result::Result<Response<SessionPruneResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/Prune")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-prune",
            context,
            MutationIntent::SessionPrune {
                uid: peer.uid,
                terminal_before_unix_ms: request.terminal_before_unix_ms,
                maximum_sessions: request.maximum_sessions,
            },
            MutationResponseType::SessionPruneResponse,
        )?;
        Ok(Response::new(response))
    }

    async fn set_alias(
        &self,
        request: Request<SessionAliasSetRequest>,
    ) -> std::result::Result<Response<SessionAliasRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/SetAlias")?;
        let request = request.into_inner();
        let session_id = self
            .state
            .sessions
            .resolve_session_reference(peer.uid, &request.session_id)
            .map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "session-alias-set",
            context,
            MutationIntent::SessionAliasSet {
                uid: peer.uid,
                alias: request.alias,
                session_id,
            },
            MutationResponseType::SessionAliasRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn remove_alias(
        &self,
        request: Request<SessionAliasRemoveRequest>,
    ) -> std::result::Result<Response<SessionAliasRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SessionService/RemoveAlias")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "session-alias-remove",
            context,
            MutationIntent::SessionAliasRemove {
                uid: peer.uid,
                alias: request.alias,
            },
            MutationResponseType::SessionAliasRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn list_aliases(
        &self,
        request: Request<SessionAliasListRequest>,
    ) -> std::result::Result<Response<SessionAliasListResponse>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state.sessions.aliases(peer.uid).map_err(status)?,
        ))
    }
}

#[tonic::async_trait]
impl FilesystemService for DaemonGrpc {
    async fn query(
        &self,
        request: Request<FilesystemQueryRequest>,
    ) -> std::result::Result<Response<FilesystemOperationResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let response = self
            .state
            .sessions
            .filesystem_query(
                peer.uid,
                &request.session_id,
                request.operation,
                &request.target,
                &request.output_format,
            )
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn mutate(
        &self,
        request: Request<FilesystemMutationRequest>,
    ) -> std::result::Result<Response<FilesystemOperationResponse>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "FilesystemService/Mutate")?;
        let request = request.into_inner();
        let session_id = self
            .state
            .sessions
            .resolve_session_reference(peer.uid, &request.session_id)
            .map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "filesystem-mutation",
            context,
            MutationIntent::FilesystemMutation {
                uid: peer.uid,
                session_id,
                operation: request.operation,
                target: request.target,
                name: request.name,
                output_format: request.output_format,
            },
            MutationResponseType::FilesystemOperationResponse,
        )?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl ContextService for DaemonGrpc {
    async fn delivery_inbox(
        &self,
        request: Request<ContextDeliveryInboxRequest>,
    ) -> std::result::Result<Response<ContextDeliveryInboxResponse>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let deliveries = self
            .state
            .sessions
            .context_delivery_inbox(peer.uid, &request.parent_session_id)
            .map_err(status)?
            .into_iter()
            .map(|delivery| ContextDeliveryRecord {
                receiver_scope: delivery.receiver_scope().as_str().to_owned(),
                child_scope: delivery.source_scope().as_str().to_owned(),
                delivery_path: delivery.delivery_path().to_owned(),
                delivery_commit: delivery.delivery_commit().to_string(),
                expected_parent_head: delivery.expected_parent_head().to_string(),
            })
            .collect();
        Ok(Response::new(ContextDeliveryInboxResponse { deliveries }))
    }

    async fn graph(
        &self,
        request: Request<ContextGraphRequest>,
    ) -> std::result::Result<Response<ContextGraphResponse>, Status> {
        let peer = Self::peer(&request)?;
        let (root_scope, nodes, activities) = self
            .state
            .sessions
            .context_graph(peer.uid, &request.into_inner().session_id)
            .map_err(status)?;
        Ok(Response::new(ContextGraphResponse {
            root_scope: root_scope.as_str().to_owned(),
            nodes: nodes
                .into_iter()
                .map(|node| ContextScopeGraphNode {
                    scope: node.scope().as_str().to_owned(),
                    parent_scope: node
                        .parent_scope()
                        .map_or_else(String::new, |scope| scope.as_str().to_owned()),
                    head_commit: node.head_commit().to_string(),
                    fork_parent_commit: node
                        .fork_parent_commit()
                        .map_or_else(String::new, |commit| commit.to_string()),
                    source_identity: node.source_identity().unwrap_or_default().to_owned(),
                    execution_binding: node
                        .execution_binding()
                        .map_or_else(String::new, |binding| binding.as_str().to_owned()),
                    depth: u32::from(node.depth()),
                    source_tool_use_id: node.source_tool_use_id().unwrap_or_default().to_owned(),
                })
                .collect(),
            activities: activities
                .into_iter()
                .map(|activity| ContextGraphActivity {
                    scope: activity.scope().as_str().to_owned(),
                    summary: activity.summary().to_owned(),
                    tool_use_id: activity.tool_use_id().unwrap_or_default().to_owned(),
                })
                .collect(),
        }))
    }

    async fn receive_delivery(
        &self,
        request: Request<ContextDeliveryReceiveRequest>,
    ) -> std::result::Result<Response<ContextDeliveryDecisionResponse>, Status> {
        let peer = Self::peer(&request)?;
        let _context = Self::mutation_context(&request, "ContextService/ReceiveDelivery")?;
        let request = request.into_inner();
        let decision = self
            .state
            .sessions
            .receive_context_delivery(
                peer.uid,
                &request.parent_session_id,
                &request.delivery_path,
                &request.delivery_commit,
                &request.expected_parent_head,
            )
            .map_err(status)?;
        Ok(Response::new(ContextDeliveryDecisionResponse {
            parent_head: decision.parent_head().to_string(),
            receipt_path: decision.receipt_path().to_owned(),
            rejected: decision.rejected(),
        }))
    }

    async fn reject_delivery(
        &self,
        request: Request<ContextDeliveryRejectRequest>,
    ) -> std::result::Result<Response<ContextDeliveryDecisionResponse>, Status> {
        let peer = Self::peer(&request)?;
        let _context = Self::mutation_context(&request, "ContextService/RejectDelivery")?;
        let request = request.into_inner();
        let decision = self
            .state
            .sessions
            .reject_context_delivery(
                peer.uid,
                &request.parent_session_id,
                &request.delivery_path,
                &request.delivery_commit,
                &request.expected_parent_head,
                &request.reason,
            )
            .map_err(status)?;
        Ok(Response::new(ContextDeliveryDecisionResponse {
            parent_head: decision.parent_head().to_string(),
            receipt_path: decision.receipt_path().to_owned(),
            rejected: decision.rejected(),
        }))
    }
}

#[tonic::async_trait]
impl AdministrationService for DaemonGrpc {
    async fn list_sessions(
        &self,
        request: Request<AdminSessionListRequest>,
    ) -> std::result::Result<Response<SessionListResponse>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let request = request.into_inner();
        let response = if request.all_users {
            self.state.sessions.list_all()
        } else {
            self.state.sessions.list(request.target_uid)
        }
        .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn inspect_session(
        &self,
        request: Request<AdminSessionInspectRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let request = request.into_inner();
        Ok(Response::new(
            self.state
                .sessions
                .inspect(request.target_uid, &request.session_id)
                .map_err(status)?,
        ))
    }

    async fn stop_session(
        &self,
        request: Request<AdminSessionStopRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context = Self::mutation_context(&request, "AdministrationService/StopSession")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "admin-session-stop",
            context,
            MutationIntent::SessionStop {
                uid: request.target_uid,
                session_id: request.session_id,
                grace_period_seconds: request.grace_period_seconds.max(1),
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn kill_session(
        &self,
        request: Request<AdminSessionKillRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context = Self::mutation_context(&request, "AdministrationService/KillSession")?;
        let request = request.into_inner();
        let signal = parse_signal(&request.signal).map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "admin-session-kill",
            context,
            MutationIntent::SessionKill {
                uid: request.target_uid,
                session_id: request.session_id,
                signal,
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn set_session_retention_hold(
        &self,
        request: Request<AdminSessionSetRetentionHoldRequest>,
    ) -> std::result::Result<Response<SessionRecord>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context =
            Self::mutation_context(&request, "AdministrationService/SetSessionRetentionHold")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "admin-session-set-retention-hold",
            context,
            MutationIntent::SessionSetRetentionHold {
                uid: request.target_uid,
                session_id: request.session_id,
                retention_hold: request.retention_hold,
            },
            MutationResponseType::SessionRecord,
        )?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl ApprovalService for DaemonGrpc {
    async fn list(
        &self,
        request: Request<ApprovalListRequest>,
    ) -> std::result::Result<Response<ApprovalListResponse>, Status> {
        let peer = Self::peer(&request)?;
        let approvals = self
            .state
            .approvals
            .list_pending(peer.uid)
            .map_err(|source| {
                status(DaemonError::Approval {
                    source,
                    location: snafu::Location::default(),
                })
            })?
            .iter()
            .map(DaemonControlState::approval_record)
            .collect();
        Ok(Response::new(ApprovalListResponse { approvals }))
    }

    async fn inspect(
        &self,
        request: Request<ApprovalInspectRequest>,
    ) -> std::result::Result<Response<ApprovalRecordMessage>, Status> {
        let peer = Self::peer(&request)?;
        let request = request.into_inner();
        let owner_uid = self
            .state
            .approval_owner(peer, request.owner_uid)
            .map_err(status)?;
        let record = self
            .state
            .approvals
            .inspect(owner_uid, &request.approval_id)
            .map_err(|source| {
                status(DaemonError::Approval {
                    source,
                    location: snafu::Location::default(),
                })
            })?;
        Ok(Response::new(DaemonControlState::approval_record(&record)))
    }

    async fn approve(
        &self,
        request: Request<ApprovalApproveRequest>,
    ) -> std::result::Result<Response<ApprovalRecordMessage>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context = Self::mutation_context(&request, "ApprovalService/Approve")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "approval-approve",
            context,
            MutationIntent::ApprovalApprove {
                owner_uid: request.owner_uid,
                approval_id: request.approval_id,
            },
            MutationResponseType::ApprovalRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn deny(
        &self,
        request: Request<ApprovalDenyRequest>,
    ) -> std::result::Result<Response<ApprovalRecordMessage>, Status> {
        let peer = Self::peer(&request)?;
        self.state.require_root(peer).map_err(status)?;
        let context = Self::mutation_context(&request, "ApprovalService/Deny")?;
        let request = request.into_inner();
        if request.reason.trim().is_empty() {
            return Err(Status::invalid_argument(
                "the approval denial reason must not be empty",
            ));
        }
        let (response, _applied) = self.mutate(
            peer,
            "approval-deny",
            context,
            MutationIntent::ApprovalDeny {
                owner_uid: request.owner_uid,
                approval_id: request.approval_id,
                reason: request.reason,
            },
            MutationResponseType::ApprovalRecord,
        )?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl PolicyService for DaemonGrpc {
    async fn test(
        &self,
        request: Request<PolicyTestRequest>,
    ) -> std::result::Result<Response<PolicyTestResponse>, Status> {
        let _peer = Self::peer(&request)?;
        let maximum = self
            .state
            .configuration
            .read()
            .map_err(|_error| status(StateLockSnafu.build()))?
            .value
            .max_ipc_upload_bytes_per_uid();
        Ok(Response::new(
            evaluate_policy_test(request.into_inner(), maximum).map_err(status)?,
        ))
    }

    async fn apply_package(
        &self,
        request: Request<PolicyPackageApplyRequest>,
    ) -> std::result::Result<Response<PolicyPackageRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "PolicyService/ApplyPackage")?;
        let request = request.into_inner();
        if request.path.trim().is_empty() || request.name.trim().is_empty() {
            return Err(Status::invalid_argument(
                "the policy package path and name are required",
            ));
        }
        let (maximum, maximum_stored_bytes) = {
            let configuration = self
                .state
                .configuration
                .read()
                .map_err(|_error| status(StateLockSnafu.build()))?;
            (
                configuration.value.max_policy_upload_bytes(),
                configuration.value.max_stored_policy_bytes_per_uid(),
            )
        };
        let policy = self
            .state
            .sessions
            .read_policy_package(
                peer.uid,
                peer.gid,
                std::path::Path::new(&request.path),
                &request.name,
                maximum,
            )
            .map_err(status)?;
        let (response, _applied) = self.mutate(
            peer,
            "policy-package-apply",
            context,
            MutationIntent::PolicyPackageApply {
                uid: peer.uid,
                policy,
                maximum_stored_bytes,
            },
            MutationResponseType::PolicyPackageRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn list_packages(
        &self,
        request: Request<PolicyPackageListRequest>,
    ) -> std::result::Result<Response<PolicyPackageListResponse>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(PolicyPackageListResponse {
            packages: self
                .state
                .sessions
                .list_policy_packages(peer.uid)
                .map_err(status)?,
        }))
    }

    async fn inspect_package(
        &self,
        request: Request<PolicyPackageInspectRequest>,
    ) -> std::result::Result<Response<PolicyPackageRecord>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .inspect_policy_package(peer.uid, &request.into_inner().name)
                .map_err(status)?,
        ))
    }

    async fn verify_package(
        &self,
        request: Request<PolicyPackageVerifyRequest>,
    ) -> std::result::Result<Response<PolicyPackageRecord>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .inspect_policy_package(peer.uid, &request.into_inner().name)
                .map_err(status)?,
        ))
    }

    async fn create_set(
        &self,
        request: Request<PolicySetCreateRequest>,
    ) -> std::result::Result<Response<PolicySetRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "PolicyService/CreateSet")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "policy-set-create",
            context,
            MutationIntent::PolicySetCreate {
                uid: peer.uid,
                name: request.name,
                package_names: request.package_names,
            },
            MutationResponseType::PolicySetRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn list_sets(
        &self,
        request: Request<PolicySetListRequest>,
    ) -> std::result::Result<Response<PolicySetListResponse>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(PolicySetListResponse {
            policy_sets: self
                .state
                .sessions
                .list_policy_sets(peer.uid)
                .map_err(status)?,
        }))
    }

    async fn inspect_set(
        &self,
        request: Request<PolicySetInspectRequest>,
    ) -> std::result::Result<Response<PolicySetRecord>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .inspect_policy_set(peer.uid, &request.into_inner().name)
                .map_err(status)?,
        ))
    }

    async fn verify_set(
        &self,
        request: Request<PolicySetVerifyRequest>,
    ) -> std::result::Result<Response<PolicySetRecord>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .inspect_policy_set(peer.uid, &request.into_inner().name)
                .map_err(status)?,
        ))
    }
}

#[tonic::async_trait]
impl SurfaceService for DaemonGrpc {
    async fn create(
        &self,
        request: Request<SurfaceCreateRequest>,
    ) -> std::result::Result<Response<SurfaceRecord>, Status> {
        let peer = Self::peer(&request)?;
        let context = Self::mutation_context(&request, "SurfaceService/Create")?;
        let request = request.into_inner();
        let (response, _applied) = self.mutate(
            peer,
            "surface-create",
            context,
            MutationIntent::SurfaceCreate {
                uid: peer.uid,
                name: request.name,
                surface_type: request.surface_type,
            },
            MutationResponseType::SurfaceRecord,
        )?;
        Ok(Response::new(response))
    }

    async fn list(
        &self,
        request: Request<SurfaceListRequest>,
    ) -> std::result::Result<Response<SurfaceListResponse>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .list_surfaces(peer.uid)
                .map_err(status)?,
        ))
    }

    async fn inspect(
        &self,
        request: Request<SurfaceInspectRequest>,
    ) -> std::result::Result<Response<SurfaceRecord>, Status> {
        let peer = Self::peer(&request)?;
        Ok(Response::new(
            self.state
                .sessions
                .inspect_surface(peer.uid, &request.into_inner().name)
                .map_err(status)?,
        ))
    }
}

#[tonic::async_trait]
impl RunnerService for DaemonGrpc {
    async fn list(
        &self,
        request: Request<RunnerListRequest>,
    ) -> std::result::Result<Response<RunnerListResponse>, Status> {
        let _peer = Self::peer(&request)?;
        let runners = self
            .state
            .sessions
            .runner_reports()
            .map_err(status)?
            .iter()
            .map(runner_capability_record)
            .collect::<Result<Vec<_>>>()
            .map_err(status)?;
        Ok(Response::new(RunnerListResponse { runners }))
    }

    async fn inspect(
        &self,
        request: Request<RunnerInspectRequest>,
    ) -> std::result::Result<Response<RunnerCapabilityRecord>, Status> {
        let _peer = Self::peer(&request)?;
        let report = self
            .state
            .sessions
            .runner_report(&request.into_inner().runner_id)
            .map_err(status)?;
        Ok(Response::new(
            runner_capability_record(&report).map_err(status)?,
        ))
    }
}

fn decode_mutation<T: Message + Default>(
    response: MutationResponse,
    expected_type: MutationResponseType,
) -> std::result::Result<T, Status> {
    if response.response_type() != expected_type {
        return Err(Status::internal(
            "the durable mutation response type is invalid",
        ));
    }
    T::decode(response.into_encoded_message().as_slice())
        .map_err(|_error| Status::internal("the durable mutation response is invalid"))
}

fn status(error: DaemonError) -> Status {
    let message = error.output_msg();
    let (code, reason_code, retryable) = match error.status_code() {
        StatusCode::Success => (Code::Ok, "SUCCESS", false),
        StatusCode::Unsupported => (Code::Unimplemented, "UNSUPPORTED", false),
        StatusCode::InvalidArguments | StatusCode::InvalidSyntax => {
            (Code::InvalidArgument, "INVALID_ARGUMENT", false)
        }
        StatusCode::NotFound => (Code::NotFound, "NOT_FOUND", false),
        StatusCode::AlreadyExists => (Code::AlreadyExists, "ALREADY_EXISTS", false),
        StatusCode::PolicyDenied | StatusCode::PermissionDenied => {
            (Code::PermissionDenied, "PERMISSION_DENIED", false)
        }
        StatusCode::Cancelled => (Code::Cancelled, "CANCELLED", true),
        StatusCode::DeadlineExceeded => (Code::DeadlineExceeded, "DEADLINE_EXCEEDED", true),
        StatusCode::IllegalState => (Code::FailedPrecondition, "FAILED_PRECONDITION", false),
        StatusCode::Unavailable | StatusCode::External => (Code::Unavailable, "UNAVAILABLE", true),
        StatusCode::Unknown | StatusCode::Unexpected | StatusCode::Internal => {
            (Code::Internal, "INTERNAL", false)
        }
    };
    Status::with_details(
        code,
        message,
        RpcErrorDetail {
            reason_code: reason_code.to_owned(),
            retryable,
        }
        .encode_to_vec()
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use tonic::Code;

    use super::{status, RpcErrorDetail};

    #[test]
    fn daemon_errors_have_stable_codes_and_safe_structured_details(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status = status(
            crate::error::InvalidRequestSnafu {
                reason: String::from("request is invalid"),
            }
            .build(),
        );
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(
            status.message(),
            "daemon request is invalid: request is invalid"
        );
        assert_eq!(
            RpcErrorDetail::decode(status.details())?,
            RpcErrorDetail {
                reason_code: String::from("INVALID_ARGUMENT"),
                retryable: false,
            }
        );
        Ok(())
    }
}
