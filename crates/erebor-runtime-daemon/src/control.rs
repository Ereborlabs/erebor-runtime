use std::{
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener as StdUnixListener,
    },
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_approvals::{ApprovalRecord, ApprovalRepository};
use erebor_runtime_error::ErrorExt;
use erebor_runtime_ipc::{
    v1::{
        AdminSessionInspectRequest, AdminSessionKillRequest, AdminSessionListRequest,
        AdminSessionSetRetentionHoldRequest, AdminSessionStopRequest, ApprovalApproveRequest,
        ApprovalDenyRequest, ApprovalInspectRequest, ApprovalListRequest, ApprovalListResponse,
        ApprovalRecord as ApprovalRecordMessage, DaemonCommandResult,
        DaemonError as DaemonErrorMessage, DaemonHello, DaemonHelloAck,
        DaemonLogRecord as DaemonLogRecordMessage, DaemonLogsEnd, DaemonLogsRequest,
        DaemonReloadRequest, DaemonStatusRequest, DaemonStatusResponse, DaemonStopRequest,
        Envelope, EnvelopeServiceFamily, SessionAttachRequest, SessionCreateRequest,
        SessionEventRecord, SessionEventsEnd, SessionEventsRequest,
        SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionInspectRequest,
        SessionKillRequest, SessionListRequest, SessionLogChunk, SessionLogsEnd,
        SessionLogsRequest, SessionPruneRequest, SessionRemoveRequest, SessionStartRequest,
        SessionStopRequest, SessionWaitRequest, KIND_ADMIN_SESSION_INSPECT_REQUEST,
        KIND_ADMIN_SESSION_KILL_REQUEST, KIND_ADMIN_SESSION_LIST_REQUEST,
        KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST, KIND_ADMIN_SESSION_STOP_REQUEST,
        KIND_APPROVAL_APPROVE_REQUEST, KIND_APPROVAL_DENY_REQUEST, KIND_APPROVAL_INSPECT_REQUEST,
        KIND_APPROVAL_LIST_REQUEST, KIND_APPROVAL_LIST_RESPONSE, KIND_APPROVAL_RECORD,
        KIND_DAEMON_COMMAND_RESULT, KIND_DAEMON_ERROR, KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK,
        KIND_DAEMON_LOGS_END, KIND_DAEMON_LOGS_REQUEST, KIND_DAEMON_LOG_RECORD,
        KIND_DAEMON_RELOAD_REQUEST, KIND_DAEMON_STATUS_REQUEST, KIND_DAEMON_STATUS_RESPONSE,
        KIND_DAEMON_STOP_REQUEST, KIND_SESSION_ATTACH_REQUEST, KIND_SESSION_CREATE_REQUEST,
        KIND_SESSION_EVENTS_END, KIND_SESSION_EVENTS_REQUEST, KIND_SESSION_EVENT_RECORD,
        KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST, KIND_SESSION_INPUT_LEASE_RENEW_REQUEST,
        KIND_SESSION_INSPECT_REQUEST, KIND_SESSION_KILL_REQUEST, KIND_SESSION_LIST_REQUEST,
        KIND_SESSION_LIST_RESPONSE, KIND_SESSION_LOGS_END, KIND_SESSION_LOGS_REQUEST,
        KIND_SESSION_LOG_CHUNK, KIND_SESSION_PRUNE_REQUEST, KIND_SESSION_RECORD,
        KIND_SESSION_REMOVE_REQUEST, KIND_SESSION_START_REQUEST, KIND_SESSION_STOP_REQUEST,
        KIND_SESSION_WAIT_REQUEST, PROTOCOL_VERSION,
    },
    AsyncFrameCodec,
};
use prost::Message;
use rustix::{
    fs::chown,
    process::{geteuid, Gid, Uid},
};
use snafu::ResultExt;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    approvals::DaemonApprovalRepository,
    config::DaemonConfig,
    error::{InvalidRequestSnafu, IoSnafu, IpcSnafu, StateLockSnafu, UnauthorizedSnafu},
    idempotency::{DaemonIdempotencyStore, IdempotencyAction, MutationIntent},
    log::DaemonLogStore,
    paths::{DaemonLock, DaemonSecurity},
    session_api::DaemonSessionApi,
    DaemonError, DaemonPaths, Result,
};
use erebor_runtime_core::ActiveSessionSignal;
use erebor_runtime_session::StreamKind;

const CONNECTION_LIMIT: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonControlService {
    listener: UnixListener,
    state: Arc<DaemonControlState>,
    socket: DaemonSocket,
    _lock: DaemonLock,
    shutdown: watch::Receiver<bool>,
}

struct DaemonControlState {
    paths: DaemonPaths,
    security: DaemonSecurity,
    configuration: RwLock<DaemonConfiguration>,
    idempotency: Mutex<DaemonIdempotencyStore>,
    logs: DaemonLogStore,
    sessions: DaemonSessionApi,
    approvals: DaemonApprovalRepository,
    shutdown: watch::Sender<bool>,
    connections: Arc<Semaphore>,
}

struct DaemonConfiguration {
    value: DaemonConfig,
    generation: u64,
}

struct MutationOutcome {
    response: crate::idempotency::MutationResponse,
    applied: bool,
}

#[derive(Clone, Copy)]
struct PeerIdentity {
    pid: Option<i32>,
    uid: u32,
    gid: u32,
}

struct DaemonSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
    cleanup_attempted: bool,
}

impl DaemonControlService {
    /// Starts one root-owned daemon using explicitly supplied local paths.
    pub async fn start_with_paths(paths: DaemonPaths) -> Result<Self> {
        Self::require_root_process()?;
        Self::start(paths, 0).await
    }

    fn require_root_process() -> Result<()> {
        if geteuid().as_raw() == 0 {
            Ok(())
        } else {
            InvalidRequestSnafu {
                reason: String::from("erebord must run as root"),
            }
            .fail()
        }
    }

    pub(crate) async fn start(paths: DaemonPaths, owner_uid: u32) -> Result<Self> {
        let bootstrap_security = DaemonSecurity {
            owner_uid,
            socket_gid: 0,
        };
        paths.prepare(bootstrap_security)?;
        let config = DaemonConfig::load(&paths, bootstrap_security)?;
        let security = DaemonSecurity {
            owner_uid,
            socket_gid: config.socket_group_gid,
        };
        paths.set_runtime_group(security)?;
        let lock = paths.acquire_lock(security)?;
        paths.remove_stale_socket(&lock, security).await?;

        let socket_path = paths.socket_path();
        let listener = Self::bind_listener(&socket_path, security)?;
        let socket = DaemonSocket::from_bound_path(socket_path)?;
        let logs = DaemonLogStore::open(paths.log_path(), config.max_log_bytes)?;
        let sessions = DaemonSessionApi::installed(&paths, &config)?;
        let approvals = DaemonApprovalRepository::installed(&paths)?;
        let reconciled = sessions.reconcile()?;
        logs.record("INFO", "erebord daemon control service started")?;
        if !reconciled.is_empty() {
            logs.record(
                "INFO",
                format!("reconciled {} durable sessions", reconciled.len()),
            )?;
        }
        let (shutdown_sender, shutdown) = watch::channel(false);
        let state = Arc::new(DaemonControlState {
            idempotency: Mutex::new(DaemonIdempotencyStore::new(
                paths.idempotency_path(),
                paths.session_state_path(),
                config.max_idempotency_records as usize,
                Duration::from_secs(config.session_retry_horizon_seconds),
            )),
            paths,
            security,
            configuration: RwLock::new(DaemonConfiguration {
                value: config,
                generation: 1,
            }),
            logs,
            sessions,
            approvals,
            shutdown: shutdown_sender,
            connections: Arc::new(Semaphore::new(CONNECTION_LIMIT)),
        });
        Ok(Self {
            listener,
            state,
            socket,
            _lock: lock,
            shutdown,
        })
    }

    pub async fn serve(mut self) -> Result<()> {
        let result = loop {
            tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        break Ok(());
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _address) = match accepted {
                        Ok(accepted) => accepted,
                        Err(source) => break Err(DaemonError::Io {
                            action: "accepting daemon client",
                            path: self.socket.path.clone(),
                            source,
                            location: snafu::Location::default(),
                        }),
                    };
                    let Some(permit) = self.state.connections.clone().try_acquire_owned().ok() else {
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        state.serve_connection(stream, permit).await;
                    });
                }
            }
        };
        if result.is_err() {
            let _result = self
                .state
                .logs
                .record("ERROR", "daemon control service terminated unexpectedly");
        }
        result
    }

    fn bind_listener(path: &PathBuf, security: DaemonSecurity) -> Result<UnixListener> {
        let listener = StdUnixListener::bind(path).context(IoSnafu {
            action: "binding daemon socket",
            path,
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).context(
            IoSnafu {
                action: "setting daemon socket permissions",
                path,
            },
        )?;
        chown(
            path,
            Some(Uid::from_raw(security.owner_uid)),
            Some(Gid::from_raw(security.socket_gid)),
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "setting daemon socket ownership",
            path,
        })?;
        listener.set_nonblocking(true).context(IoSnafu {
            action: "configuring daemon socket",
            path,
        })?;
        UnixListener::from_std(listener).context(IoSnafu {
            action: "starting daemon socket listener",
            path,
        })
    }
}

impl DaemonControlState {
    async fn serve_connection(
        self: Arc<Self>,
        mut stream: UnixStream,
        _permit: OwnedSemaphorePermit,
    ) {
        let peer = match self.peer_identity(&stream) {
            Ok(peer) => peer,
            Err(_error) => {
                let _result = self
                    .logs
                    .record("ERROR", "daemon peer credential lookup failed");
                return;
            }
        };
        if self
            .logs
            .record(
                "INFO",
                format!(
                    "accepted daemon client pid={:?} uid={} gid={}",
                    peer.pid, peer.uid, peer.gid
                ),
            )
            .is_err()
        {
            return;
        }
        let hello = match self.read_envelope(&mut stream).await {
            Ok(envelope) => envelope,
            Err(_error) => return,
        };
        if let Err(_error) = self.handle_hello(&mut stream, peer, hello).await {
            let _result = self.logs.record("WARN", "daemon client handshake rejected");
            return;
        }
        loop {
            let envelope = match self.read_envelope(&mut stream).await {
                Ok(envelope) => envelope,
                Err(_error) => return,
            };
            if let Err(_error) = self.dispatch(&mut stream, peer, envelope).await {
                let _result = self.logs.record("WARN", "daemon client request failed");
                return;
            }
        }
    }

    fn peer_identity(&self, stream: &UnixStream) -> Result<PeerIdentity> {
        let credentials = stream.peer_cred().map_err(|source| DaemonError::Io {
            action: "observing daemon peer credentials",
            path: self.paths.socket_path(),
            source,
            location: snafu::Location::default(),
        })?;
        Ok(PeerIdentity {
            pid: credentials.pid(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        })
    }

    async fn handle_hello(
        &self,
        stream: &mut UnixStream,
        _peer: PeerIdentity,
        envelope: Envelope,
    ) -> Result<()> {
        envelope
            .validate_headers(EnvelopeServiceFamily::DaemonControl { mutating: false })
            .context(IpcSnafu)?;
        envelope.require_supported_protocol().context(IpcSnafu)?;
        if envelope.message_kind != KIND_DAEMON_HELLO {
            return InvalidRequestSnafu {
                reason: String::from("daemon control connection requires DaemonHello"),
            }
            .fail();
        }
        let hello: DaemonHello = envelope
            .decode_typed_payload(KIND_DAEMON_HELLO)
            .context(IpcSnafu)?;
        if hello.protocol_version != PROTOCOL_VERSION {
            return InvalidRequestSnafu {
                reason: String::from("unsupported daemon client protocol version"),
            }
            .fail();
        }
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_DAEMON_HELLO_ACK,
            &DaemonHelloAck {
                protocol_version: PROTOCOL_VERSION,
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                capabilities: vec![
                    String::from("daemon-status"),
                    String::from("daemon-logs"),
                    String::from("daemon-reload"),
                    String::from("daemon-stop"),
                    String::from("session-control-v1"),
                    String::from("approvals-v1"),
                    String::from("runtime-guard-service-v1"),
                ],
            },
        )
        .await
    }

    async fn dispatch(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: Envelope,
    ) -> Result<()> {
        if let Err(error) = envelope.require_supported_protocol().context(IpcSnafu) {
            return self.write_error(stream, &envelope, error).await;
        }
        let mutating = is_mutating_message(&envelope.message_kind);
        if let Err(error) = envelope
            .validate_headers(EnvelopeServiceFamily::DaemonControl { mutating })
            .context(IpcSnafu)
        {
            return self.write_error(stream, &envelope, error).await;
        }
        let result = match envelope.message_kind.as_str() {
            KIND_DAEMON_STATUS_REQUEST => self.status(stream, &envelope).await,
            KIND_DAEMON_LOGS_REQUEST => self.logs(stream, peer, &envelope).await,
            KIND_DAEMON_RELOAD_REQUEST => self.reload(stream, peer, &envelope).await,
            KIND_DAEMON_STOP_REQUEST => self.stop(stream, peer, &envelope).await,
            KIND_SESSION_CREATE_REQUEST => self.session_create(stream, peer, &envelope).await,
            KIND_SESSION_START_REQUEST => self.session_start(stream, peer, &envelope).await,
            KIND_SESSION_STOP_REQUEST => self.session_stop(stream, peer, &envelope).await,
            KIND_SESSION_KILL_REQUEST => self.session_kill(stream, peer, &envelope).await,
            KIND_SESSION_REMOVE_REQUEST => self.session_remove(stream, peer, &envelope).await,
            KIND_SESSION_ATTACH_REQUEST => self.session_attach(stream, peer, &envelope).await,
            KIND_SESSION_INPUT_LEASE_RENEW_REQUEST => {
                self.session_lease_renew(stream, peer, &envelope).await
            }
            KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST => {
                self.session_lease_release(stream, peer, &envelope).await
            }
            KIND_SESSION_PRUNE_REQUEST => self.session_prune(stream, peer, &envelope).await,
            KIND_SESSION_INSPECT_REQUEST => self.session_inspect(stream, peer, &envelope).await,
            KIND_SESSION_LIST_REQUEST => self.session_list(stream, peer, &envelope).await,
            KIND_SESSION_WAIT_REQUEST => self.session_wait(stream, peer, &envelope).await,
            KIND_SESSION_LOGS_REQUEST => self.session_logs(stream, peer, &envelope).await,
            KIND_SESSION_EVENTS_REQUEST => self.session_events(stream, peer, &envelope).await,
            KIND_ADMIN_SESSION_LIST_REQUEST => {
                self.admin_session_list(stream, peer, &envelope).await
            }
            KIND_ADMIN_SESSION_INSPECT_REQUEST => {
                self.admin_session_inspect(stream, peer, &envelope).await
            }
            KIND_ADMIN_SESSION_STOP_REQUEST => {
                self.admin_session_stop(stream, peer, &envelope).await
            }
            KIND_ADMIN_SESSION_KILL_REQUEST => {
                self.admin_session_kill(stream, peer, &envelope).await
            }
            KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST => {
                self.admin_session_set_retention_hold(stream, peer, &envelope)
                    .await
            }
            KIND_APPROVAL_LIST_REQUEST => self.approval_list(stream, peer, &envelope).await,
            KIND_APPROVAL_INSPECT_REQUEST => self.approval_inspect(stream, peer, &envelope).await,
            KIND_APPROVAL_APPROVE_REQUEST => self.approval_approve(stream, peer, &envelope).await,
            KIND_APPROVAL_DENY_REQUEST => self.approval_deny(stream, peer, &envelope).await,
            _ => Err(InvalidRequestSnafu {
                reason: format!(
                    "message kind `{}` is not accepted on daemon control",
                    envelope.message_kind
                ),
            }
            .build()),
        };
        if let Err(error) = result {
            self.write_error(stream, &envelope, error).await?;
        }
        Ok(())
    }

    async fn status(&self, stream: &mut UnixStream, envelope: &Envelope) -> Result<()> {
        envelope
            .decode_typed_payload::<DaemonStatusRequest>(KIND_DAEMON_STATUS_REQUEST)
            .context(IpcSnafu)?;
        let generation = self
            .configuration
            .read()
            .map_err(|_error| StateLockSnafu.build())?
            .generation;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_DAEMON_STATUS_RESPONSE,
            &DaemonStatusResponse {
                daemon_pid: i64::from(std::process::id()),
                configuration_generation: generation,
                service_state: String::from("running"),
            },
        )
        .await
    }

    async fn logs(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: DaemonLogsRequest = envelope
            .decode_typed_payload(KIND_DAEMON_LOGS_REQUEST)
            .context(IpcSnafu)?;
        let maximum = usize::try_from(request.maximum_records.max(1)).map_err(|_error| {
            InvalidRequestSnafu {
                reason: String::from("maximum log records is invalid"),
            }
            .build()
        })?;
        let configured = self
            .configuration
            .read()
            .map_err(|_error| StateLockSnafu.build())?
            .value
            .max_log_records as usize;
        let records = self
            .logs
            .records_after(request.after_sequence, maximum.min(configured))?;
        let record_count = records.len();
        let mut last_sequence = request.after_sequence;
        for (index, record) in records.into_iter().enumerate() {
            last_sequence = record.sequence;
            self.write_message(
                stream,
                envelope.message_id.saturating_add(index as u64 + 1),
                envelope.message_id,
                KIND_DAEMON_LOG_RECORD,
                &DaemonLogRecordMessage {
                    sequence: record.sequence,
                    timestamp: record.timestamp,
                    level: record.level,
                    message: record.message,
                },
            )
            .await?;
        }
        self.write_message(
            stream,
            envelope
                .message_id
                .saturating_add(record_count as u64)
                .saturating_add(1),
            envelope.message_id,
            KIND_DAEMON_LOGS_END,
            &DaemonLogsEnd { last_sequence },
        )
        .await
    }

    async fn session_create(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionCreateRequest = envelope
            .decode_typed_payload(KIND_SESSION_CREATE_REQUEST)
            .context(IpcSnafu)?;
        let (configuration_generation, configuration) = {
            let active = self
                .configuration
                .read()
                .map_err(|_error| StateLockSnafu.build())?;
            (active.generation, active.value.clone())
        };
        let spec = self.sessions.admit_request(
            request,
            peer.uid,
            peer.gid,
            configuration_generation,
            &configuration,
        )?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-create",
            envelope,
            MutationIntent::SessionCreate {
                spec: Box::new(spec),
            },
        )
        .await
    }

    async fn session_start(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionStartRequest = envelope
            .decode_typed_payload(KIND_SESSION_START_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-start",
            envelope,
            MutationIntent::SessionStart {
                uid: peer.uid,
                session_id: request.session_id,
            },
        )
        .await
    }

    async fn session_stop(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionStopRequest = envelope
            .decode_typed_payload(KIND_SESSION_STOP_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-stop",
            envelope,
            MutationIntent::SessionStop {
                uid: peer.uid,
                session_id: request.session_id,
                grace_period_seconds: request.grace_period_seconds.max(1),
            },
        )
        .await
    }

    async fn session_kill(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionKillRequest = envelope
            .decode_typed_payload(KIND_SESSION_KILL_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-kill",
            envelope,
            MutationIntent::SessionKill {
                uid: peer.uid,
                session_id: request.session_id,
                signal: parse_signal(&request.signal)?,
            },
        )
        .await
    }

    async fn session_remove(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionRemoveRequest = envelope
            .decode_typed_payload(KIND_SESSION_REMOVE_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-remove",
            envelope,
            MutationIntent::SessionRemove {
                uid: peer.uid,
                session_id: request.session_id,
                force: request.force,
            },
        )
        .await
    }

    async fn session_attach(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionAttachRequest = envelope
            .decode_typed_payload(KIND_SESSION_ATTACH_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-attach",
            envelope,
            MutationIntent::SessionAttach {
                uid: peer.uid,
                session_id: request.session_id,
                request_input_lease: request.request_input_lease,
                client_instance_id: request.client_instance_id,
            },
        )
        .await
    }

    async fn session_lease_renew(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionInputLeaseRenewRequest = envelope
            .decode_typed_payload(KIND_SESSION_INPUT_LEASE_RENEW_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-input-lease-renew",
            envelope,
            MutationIntent::SessionInputLeaseRenew {
                uid: peer.uid,
                session_id: request.session_id,
                lease_id: request.input_lease_id,
                client_instance_id: request.client_instance_id,
            },
        )
        .await
    }

    async fn session_lease_release(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionInputLeaseReleaseRequest = envelope
            .decode_typed_payload(KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-input-lease-release",
            envelope,
            MutationIntent::SessionInputLeaseRelease {
                uid: peer.uid,
                session_id: request.session_id,
                lease_id: request.input_lease_id,
                client_instance_id: request.client_instance_id,
            },
        )
        .await
    }

    async fn session_prune(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionPruneRequest = envelope
            .decode_typed_payload(KIND_SESSION_PRUNE_REQUEST)
            .context(IpcSnafu)?;
        self.apply_session_mutation(
            stream,
            peer,
            "session-prune",
            envelope,
            MutationIntent::SessionPrune {
                uid: peer.uid,
                terminal_before_unix_ms: request.terminal_before_unix_ms,
                maximum_sessions: request.maximum_sessions,
            },
        )
        .await
    }

    async fn session_inspect(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionInspectRequest = envelope
            .decode_typed_payload(KIND_SESSION_INSPECT_REQUEST)
            .context(IpcSnafu)?;
        let record = self.sessions.inspect(peer.uid, &request.session_id)?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_SESSION_RECORD,
            &record,
        )
        .await
    }

    async fn session_list(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        envelope
            .decode_typed_payload::<SessionListRequest>(KIND_SESSION_LIST_REQUEST)
            .context(IpcSnafu)?;
        let response = self.sessions.list(peer.uid)?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_SESSION_LIST_RESPONSE,
            &response,
        )
        .await
    }

    async fn session_wait(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionWaitRequest = envelope
            .decode_typed_payload(KIND_SESSION_WAIT_REQUEST)
            .context(IpcSnafu)?;
        let record = self.sessions.wait(peer.uid, &request.session_id)?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_SESSION_RECORD,
            &record,
        )
        .await
    }

    async fn session_logs(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionLogsRequest = envelope
            .decode_typed_payload(KIND_SESSION_LOGS_REQUEST)
            .context(IpcSnafu)?;
        let kind = match request.stream.as_str() {
            "stdout" => StreamKind::Stdout,
            "stderr" => StreamKind::Stderr,
            _ => {
                return InvalidRequestSnafu {
                    reason: String::from("session log stream must be stdout or stderr"),
                }
                .fail();
            }
        };
        let page = self.sessions.stream(
            peer.uid,
            &request.session_id,
            kind,
            request.after_sequence,
            request.maximum_records.max(1) as usize,
        )?;
        for (index, record) in page.records().iter().enumerate() {
            self.write_message(
                stream,
                envelope.message_id.saturating_add(index as u64 + 1),
                envelope.message_id,
                KIND_SESSION_LOG_CHUNK,
                &SessionLogChunk {
                    session_id: request.session_id.clone(),
                    stream: request.stream.clone(),
                    sequence: record.sequence(),
                    timestamp_unix_ms: record.timestamp_unix_ms(),
                    data: record.data().to_vec(),
                    durable: true,
                },
            )
            .await?;
        }
        self.write_message(
            stream,
            envelope
                .message_id
                .saturating_add(page.records().len() as u64 + 1),
            envelope.message_id,
            KIND_SESSION_LOGS_END,
            &SessionLogsEnd {
                session_id: request.session_id,
                stream: request.stream,
                durable_cursor: page.durable_cursor(),
                truncated_before_cursor: page.truncated_before_cursor(),
            },
        )
        .await
    }

    async fn session_events(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: SessionEventsRequest = envelope
            .decode_typed_payload(KIND_SESSION_EVENTS_REQUEST)
            .context(IpcSnafu)?;
        let page = self.sessions.stream(
            peer.uid,
            &request.session_id,
            StreamKind::Events,
            request.after_sequence,
            request.maximum_records.max(1) as usize,
        )?;
        for (index, record) in page.records().iter().enumerate() {
            self.write_message(
                stream,
                envelope.message_id.saturating_add(index as u64 + 1),
                envelope.message_id,
                KIND_SESSION_EVENT_RECORD,
                &SessionEventRecord {
                    session_id: request.session_id.clone(),
                    sequence: record.sequence(),
                    timestamp_unix_ms: record.timestamp_unix_ms(),
                    event_kind: record.source().to_owned(),
                    payload: record.data().to_vec(),
                    durable: true,
                },
            )
            .await?;
        }
        self.write_message(
            stream,
            envelope
                .message_id
                .saturating_add(page.records().len() as u64 + 1),
            envelope.message_id,
            KIND_SESSION_EVENTS_END,
            &SessionEventsEnd {
                session_id: request.session_id,
                durable_cursor: page.durable_cursor(),
                truncated_before_cursor: page.truncated_before_cursor(),
            },
        )
        .await
    }

    async fn approval_list(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        envelope
            .decode_typed_payload::<ApprovalListRequest>(KIND_APPROVAL_LIST_REQUEST)
            .context(IpcSnafu)?;
        let records =
            self.approvals
                .list_pending(peer.uid)
                .map_err(|source| DaemonError::Approval {
                    source,
                    location: snafu::Location::default(),
                })?;
        let approvals = records
            .iter()
            .map(Self::approval_record)
            .collect::<Vec<_>>();
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_APPROVAL_LIST_RESPONSE,
            &ApprovalListResponse { approvals },
        )
        .await
    }

    async fn approval_inspect(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        let request: ApprovalInspectRequest = envelope
            .decode_typed_payload(KIND_APPROVAL_INSPECT_REQUEST)
            .context(IpcSnafu)?;
        let owner_uid = self.approval_owner(peer, request.owner_uid)?;
        let record = self
            .approvals
            .inspect(owner_uid, &request.approval_id)
            .map_err(|source| DaemonError::Approval {
                source,
                location: snafu::Location::default(),
            })?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_APPROVAL_RECORD,
            &Self::approval_record(&record),
        )
        .await
    }

    async fn approval_approve(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: ApprovalApproveRequest = envelope
            .decode_typed_payload(KIND_APPROVAL_APPROVE_REQUEST)
            .context(IpcSnafu)?;
        self.apply_approval_mutation(
            stream,
            peer,
            "approval-approve",
            envelope,
            MutationIntent::ApprovalApprove {
                owner_uid: request.owner_uid,
                approval_id: request.approval_id,
            },
        )
        .await
    }

    async fn approval_deny(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: ApprovalDenyRequest = envelope
            .decode_typed_payload(KIND_APPROVAL_DENY_REQUEST)
            .context(IpcSnafu)?;
        if request.reason.trim().is_empty() {
            return InvalidRequestSnafu {
                reason: String::from("approval denial reason must not be empty"),
            }
            .fail();
        }
        self.apply_approval_mutation(
            stream,
            peer,
            "approval-deny",
            envelope,
            MutationIntent::ApprovalDeny {
                owner_uid: request.owner_uid,
                approval_id: request.approval_id,
                reason: request.reason,
            },
        )
        .await
    }

    fn approval_owner(&self, peer: PeerIdentity, requested_owner_uid: u32) -> Result<u32> {
        let owner_uid = if requested_owner_uid == 0 {
            peer.uid
        } else {
            requested_owner_uid
        };
        if owner_uid == peer.uid || peer.uid == 0 {
            Ok(owner_uid)
        } else {
            UnauthorizedSnafu { uid: peer.uid }.fail()
        }
    }

    fn approval_record(record: &ApprovalRecord) -> ApprovalRecordMessage {
        ApprovalRecordMessage {
            approval_id: record.id().to_owned(),
            state: match record.state() {
                erebor_runtime_approvals::ApprovalState::Pending => String::from("pending"),
                erebor_runtime_approvals::ApprovalState::Approved => String::from("approved"),
                erebor_runtime_approvals::ApprovalState::Denied => String::from("denied"),
                erebor_runtime_approvals::ApprovalState::Expired => String::from("expired"),
                erebor_runtime_approvals::ApprovalState::Cancelled => String::from("cancelled"),
                erebor_runtime_approvals::ApprovalState::Consumed => String::from("consumed"),
            },
            owner_uid: record.binding().owner_uid(),
            session_id: record.binding().session_id().to_owned(),
            session_generation: record.binding().session_generation(),
            effect_digest: record.binding().effect_digest().to_owned(),
            process_identity: record.binding().process_identity().to_owned(),
            policy_set_digest: record.binding().policy_set_digest().to_owned(),
            policy_rule_id: record.binding().policy_rule_id().to_owned(),
            expires_at_unix_ms: record.expires_at_unix_ms(),
        }
    }

    fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_millis() as u64)
    }

    async fn admin_session_list(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: AdminSessionListRequest = envelope
            .decode_typed_payload(KIND_ADMIN_SESSION_LIST_REQUEST)
            .context(IpcSnafu)?;
        let response = if request.all_users {
            self.sessions.list_all()?
        } else {
            self.sessions.list(request.target_uid)?
        };
        self.logs.record(
            "INFO",
            format!(
                "root administration listed sessions target_uid={} all_users={}",
                request.target_uid, request.all_users
            ),
        )?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_SESSION_LIST_RESPONSE,
            &response,
        )
        .await
    }

    async fn admin_session_inspect(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: AdminSessionInspectRequest = envelope
            .decode_typed_payload(KIND_ADMIN_SESSION_INSPECT_REQUEST)
            .context(IpcSnafu)?;
        let record = self
            .sessions
            .inspect(request.target_uid, &request.session_id)?;
        self.logs.record(
            "INFO",
            format!(
                "root administration inspected session target_uid={} session_id={}",
                request.target_uid, request.session_id
            ),
        )?;
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_SESSION_RECORD,
            &record,
        )
        .await
    }

    async fn admin_session_stop(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: AdminSessionStopRequest = envelope
            .decode_typed_payload(KIND_ADMIN_SESSION_STOP_REQUEST)
            .context(IpcSnafu)?;
        self.apply_admin_session_mutation(
            stream,
            peer,
            "admin-session-stop",
            envelope,
            MutationIntent::SessionStop {
                uid: request.target_uid,
                session_id: request.session_id.clone(),
                grace_period_seconds: request.grace_period_seconds.max(1),
            },
        )
        .await
    }

    async fn admin_session_kill(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: AdminSessionKillRequest = envelope
            .decode_typed_payload(KIND_ADMIN_SESSION_KILL_REQUEST)
            .context(IpcSnafu)?;
        self.apply_admin_session_mutation(
            stream,
            peer,
            "admin-session-kill",
            envelope,
            MutationIntent::SessionKill {
                uid: request.target_uid,
                session_id: request.session_id.clone(),
                signal: parse_signal(&request.signal)?,
            },
        )
        .await
    }

    async fn admin_session_set_retention_hold(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        let request: AdminSessionSetRetentionHoldRequest = envelope
            .decode_typed_payload(KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST)
            .context(IpcSnafu)?;
        self.apply_admin_session_mutation(
            stream,
            peer,
            "admin-session-set-retention-hold",
            envelope,
            MutationIntent::SessionSetRetentionHold {
                uid: request.target_uid,
                session_id: request.session_id,
                retention_hold: request.retention_hold,
            },
        )
        .await
    }

    async fn apply_admin_session_mutation(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        operation: &str,
        envelope: &Envelope,
        intent: MutationIntent,
    ) -> Result<()> {
        let (target_uid, session_id) = intent
            .session_scope()
            .map(|(uid, session_id)| (uid, session_id.to_owned()))
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: String::from("administrative session mutation has no session target"),
                }
                .build()
            })?;
        let outcome = self.mutate(peer, operation, envelope, intent)?;
        if outcome.applied {
            self.logs.record(
                "INFO",
                format!(
                    "root administration applied {operation} target_uid={target_uid} session_id={session_id}"
                ),
            )?;
        }
        self.write_mutation_response(stream, envelope, outcome.response)
            .await
    }

    async fn apply_session_mutation(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        operation: &str,
        envelope: &Envelope,
        intent: MutationIntent,
    ) -> Result<()> {
        let outcome = self.mutate(peer, operation, envelope, intent)?;
        self.write_mutation_response(stream, envelope, outcome.response)
            .await
    }

    async fn apply_approval_mutation(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        operation: &str,
        envelope: &Envelope,
        intent: MutationIntent,
    ) -> Result<()> {
        let outcome = self.mutate(peer, operation, envelope, intent.clone())?;
        if outcome.applied {
            let (action, owner_uid, approval_id) = match intent {
                MutationIntent::ApprovalApprove {
                    owner_uid,
                    approval_id,
                } => ("approved", owner_uid, approval_id),
                MutationIntent::ApprovalDeny {
                    owner_uid,
                    approval_id,
                    ..
                } => ("denied", owner_uid, approval_id),
                _ => {
                    return InvalidRequestSnafu {
                        reason: String::from("approval mutation used a non-approval intent"),
                    }
                    .fail()
                }
            };
            self.logs.record(
                "INFO",
                format!("root approver {action} approval_id={approval_id} owner_uid={owner_uid}"),
            )?;
        }
        self.write_mutation_response(stream, envelope, outcome.response)
            .await
    }

    async fn reload(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        envelope
            .decode_typed_payload::<DaemonReloadRequest>(KIND_DAEMON_RELOAD_REQUEST)
            .context(IpcSnafu)?;
        let configuration = DaemonConfig::load(&self.paths, self.security)?;
        let outcome = self.mutate(
            peer,
            "reload",
            envelope,
            MutationIntent::Reload {
                configuration,
                generation: self.next_configuration_generation()?,
            },
        )?;
        if outcome.applied {
            self.logs.record("INFO", "daemon configuration reloaded")?;
        }
        self.write_mutation_response(stream, envelope, outcome.response)
            .await
    }

    async fn stop(
        &self,
        stream: &mut UnixStream,
        peer: PeerIdentity,
        envelope: &Envelope,
    ) -> Result<()> {
        self.require_root(peer)?;
        envelope
            .decode_typed_payload::<DaemonStopRequest>(KIND_DAEMON_STOP_REQUEST)
            .context(IpcSnafu)?;
        if self.sessions.has_unresolved_sessions()? {
            return InvalidRequestSnafu {
                reason: String::from(
                    "graceful daemon stop refuses while sessions remain unresolved",
                ),
            }
            .fail();
        }
        let outcome = self.mutate(peer, "stop", envelope, MutationIntent::Stop)?;
        if outcome.applied {
            self.logs.record("INFO", "daemon stop accepted")?;
        }
        self.write_mutation_response(stream, envelope, outcome.response)
            .await?;
        let _result = self.shutdown.send(true);
        Ok(())
    }

    fn mutate(
        &self,
        peer: PeerIdentity,
        operation: &str,
        envelope: &Envelope,
        intent: MutationIntent,
    ) -> Result<MutationOutcome> {
        let key = envelope
            .header(erebor_runtime_ipc::v1::EREBOR_IDEMPOTENCY_KEY_HEADER)
            .ok_or_else(|| {
                InvalidRequestSnafu {
                    reason: String::from("mutating daemon request requires erebor-idempotency-key"),
                }
                .build()
            })?;
        let fingerprint = envelope.daemon_request_fingerprint();
        let store = self
            .idempotency
            .lock()
            .map_err(|_error| StateLockSnafu.build())?;
        match store.prepare(peer.uid, operation, key, fingerprint, intent)? {
            IdempotencyAction::ReturnCompleted(response) => Ok(MutationOutcome {
                response,
                applied: false,
            }),
            IdempotencyAction::Execute(intent) => {
                let response = self.apply_mutation(&intent, false)?;
                store.complete(
                    peer.uid,
                    operation,
                    key,
                    fingerprint,
                    *intent,
                    response.clone(),
                )?;
                Ok(MutationOutcome {
                    response,
                    applied: true,
                })
            }
            IdempotencyAction::ResumePending(intent) => {
                let response = self.apply_mutation(&intent, true)?;
                store.complete(
                    peer.uid,
                    operation,
                    key,
                    fingerprint,
                    *intent,
                    response.clone(),
                )?;
                Ok(MutationOutcome {
                    response,
                    applied: true,
                })
            }
        }
    }

    fn apply_mutation(
        &self,
        intent: &MutationIntent,
        resume_pending: bool,
    ) -> Result<crate::idempotency::MutationResponse> {
        match intent {
            MutationIntent::Reload {
                configuration,
                generation,
            } => {
                let message = self.publish_configuration(configuration.clone(), *generation)?;
                encode_mutation_response(
                    KIND_DAEMON_COMMAND_RESULT,
                    &DaemonCommandResult { message },
                )
            }
            MutationIntent::Stop => encode_mutation_response(
                KIND_DAEMON_COMMAND_RESULT,
                &DaemonCommandResult {
                    message: String::from("daemon stop accepted"),
                },
            ),
            MutationIntent::SessionStart { uid, session_id } => {
                let active = self
                    .configuration
                    .read()
                    .map_err(|_error| StateLockSnafu.build())?;
                let constraints = self.sessions.validate_start(
                    *uid,
                    session_id,
                    active.generation,
                    &active.value,
                )?;
                drop(active);
                self.sessions
                    .start(*uid, session_id, &constraints, resume_pending)
            }
            MutationIntent::ApprovalApprove {
                owner_uid,
                approval_id,
            } => {
                let mut record = self.approval_record_for_transition(*owner_uid, approval_id)?;
                if record.state() == erebor_runtime_approvals::ApprovalState::Pending {
                    record.approve(Self::unix_time_ms()).map_err(|source| {
                        DaemonError::Approval {
                            source,
                            location: snafu::Location::default(),
                        }
                    })?;
                    record =
                        self.approvals
                            .replace(record)
                            .map_err(|source| DaemonError::Approval {
                                source,
                                location: snafu::Location::default(),
                            })?;
                }
                if record.state() != erebor_runtime_approvals::ApprovalState::Approved {
                    return InvalidRequestSnafu {
                        reason: String::from("approval is no longer pending or approved"),
                    }
                    .fail();
                }
                encode_mutation_response(KIND_APPROVAL_RECORD, &Self::approval_record(&record))
            }
            MutationIntent::ApprovalDeny {
                owner_uid,
                approval_id,
                reason,
            } => {
                let mut record = self.approval_record_for_transition(*owner_uid, approval_id)?;
                if record.state() == erebor_runtime_approvals::ApprovalState::Pending {
                    record
                        .deny(Self::unix_time_ms(), reason)
                        .map_err(|source| DaemonError::Approval {
                            source,
                            location: snafu::Location::default(),
                        })?;
                    record =
                        self.approvals
                            .replace(record)
                            .map_err(|source| DaemonError::Approval {
                                source,
                                location: snafu::Location::default(),
                            })?;
                }
                if record.state() != erebor_runtime_approvals::ApprovalState::Denied {
                    return InvalidRequestSnafu {
                        reason: String::from("approval is no longer pending or denied"),
                    }
                    .fail();
                }
                encode_mutation_response(KIND_APPROVAL_RECORD, &Self::approval_record(&record))
            }
            session => self.sessions.apply(session),
        }
    }

    fn approval_record_for_transition(
        &self,
        owner_uid: u32,
        approval_id: &str,
    ) -> Result<ApprovalRecord> {
        self.approvals
            .inspect(owner_uid, approval_id)
            .map_err(|source| DaemonError::Approval {
                source,
                location: snafu::Location::default(),
            })
    }

    fn next_configuration_generation(&self) -> Result<u64> {
        Ok(self
            .configuration
            .read()
            .map_err(|_error| StateLockSnafu.build())?
            .generation
            .saturating_add(1))
    }

    fn publish_configuration(
        &self,
        configuration: DaemonConfig,
        generation: u64,
    ) -> Result<String> {
        self.sessions.seed_root_curated(&configuration)?;
        let mut active = self
            .configuration
            .write()
            .map_err(|_error| StateLockSnafu.build())?;
        if active.value != configuration {
            active.value = configuration;
            active.generation = active.generation.saturating_add(1).max(generation);
        } else {
            active.generation = active.generation.max(generation);
        }
        Ok(format!(
            "configuration reloaded at generation {}",
            active.generation
        ))
    }

    fn require_root(&self, peer: PeerIdentity) -> Result<()> {
        if peer.uid == 0 {
            Ok(())
        } else {
            UnauthorizedSnafu { uid: peer.uid }.fail()
        }
    }

    async fn read_envelope(&self, stream: &mut UnixStream) -> Result<Envelope> {
        let frame = timeout(REQUEST_TIMEOUT, AsyncFrameCodec::read_frame(stream))
            .await
            .map_err(|_elapsed| {
                InvalidRequestSnafu {
                    reason: String::from("daemon request timed out"),
                }
                .build()
            })?
            .context(IpcSnafu)?;
        frame.decode_payload().context(IpcSnafu)
    }

    async fn write_message<T: prost::Message>(
        &self,
        stream: &mut UnixStream,
        message_id: u64,
        correlation_id: u64,
        kind: &str,
        message: &T,
    ) -> Result<()> {
        let envelope =
            Envelope::wrap_message(message_id, correlation_id, kind, message).context(IpcSnafu)?;
        let frame = envelope.into_frame().context(IpcSnafu)?;
        timeout(
            REQUEST_TIMEOUT,
            AsyncFrameCodec::write_frame(stream, &frame),
        )
        .await
        .map_err(|_elapsed| {
            InvalidRequestSnafu {
                reason: String::from("daemon response timed out"),
            }
            .build()
        })?
        .context(IpcSnafu)
    }

    async fn write_mutation_response(
        &self,
        stream: &mut UnixStream,
        envelope: &Envelope,
        response: crate::idempotency::MutationResponse,
    ) -> Result<()> {
        let response_envelope = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: envelope.message_id.saturating_add(1),
            correlation_id: envelope.message_id,
            message_kind: response.message_kind,
            payload: response.payload,
            headers: Vec::new(),
        };
        let frame = response_envelope.into_frame().context(IpcSnafu)?;
        timeout(
            REQUEST_TIMEOUT,
            AsyncFrameCodec::write_frame(stream, &frame),
        )
        .await
        .map_err(|_elapsed| {
            InvalidRequestSnafu {
                reason: String::from("daemon response timed out"),
            }
            .build()
        })?
        .context(IpcSnafu)
    }

    async fn write_error(
        &self,
        stream: &mut UnixStream,
        envelope: &Envelope,
        error: DaemonError,
    ) -> Result<()> {
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_DAEMON_ERROR,
            &DaemonErrorMessage {
                status_code: error.status_code().as_u32(),
                message: error.output_msg(),
            },
        )
        .await
    }
}

impl Drop for DaemonSocket {
    fn drop(&mut self) {
        self.unlink_if_owned();
    }
}

fn is_mutating_message(kind: &str) -> bool {
    matches!(
        kind,
        KIND_DAEMON_RELOAD_REQUEST
            | KIND_DAEMON_STOP_REQUEST
            | KIND_SESSION_CREATE_REQUEST
            | KIND_SESSION_START_REQUEST
            | KIND_SESSION_STOP_REQUEST
            | KIND_SESSION_KILL_REQUEST
            | KIND_SESSION_REMOVE_REQUEST
            | KIND_SESSION_ATTACH_REQUEST
            | KIND_SESSION_INPUT_LEASE_RENEW_REQUEST
            | KIND_SESSION_INPUT_LEASE_RELEASE_REQUEST
            | KIND_SESSION_PRUNE_REQUEST
            | KIND_ADMIN_SESSION_STOP_REQUEST
            | KIND_ADMIN_SESSION_KILL_REQUEST
            | KIND_ADMIN_SESSION_SET_RETENTION_HOLD_REQUEST
            | KIND_APPROVAL_APPROVE_REQUEST
            | KIND_APPROVAL_DENY_REQUEST
    )
}

fn parse_signal(value: &str) -> Result<ActiveSessionSignal> {
    match value {
        "terminate" | "TERM" | "SIGTERM" => Ok(ActiveSessionSignal::Terminate),
        "kill" | "KILL" | "SIGKILL" => Ok(ActiveSessionSignal::Kill),
        "interrupt" | "INT" | "SIGINT" => Ok(ActiveSessionSignal::Interrupt),
        _ => InvalidRequestSnafu {
            reason: format!("unsupported session signal `{value}`"),
        }
        .fail(),
    }
}

fn encode_mutation_response(
    kind: &str,
    message: &impl Message,
) -> Result<crate::idempotency::MutationResponse> {
    let envelope = Envelope::wrap_message(1, 0, kind, message).context(IpcSnafu)?;
    Ok(crate::idempotency::MutationResponse {
        message_kind: envelope.message_kind,
        payload: envelope.payload,
    })
}

impl DaemonSocket {
    fn from_bound_path(path: PathBuf) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(&path).context(IoSnafu {
            action: "inspecting bound daemon socket",
            path: &path,
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return crate::error::UnsafePathSnafu {
                path,
                reason: String::from("bound daemon socket path is not a socket"),
            }
            .fail();
        }
        Ok(Self {
            cleanup_attempted: false,
            device: metadata.dev(),
            inode: metadata.ino(),
            path,
        })
    }

    fn unlink_if_owned(&mut self) {
        if self.cleanup_attempted {
            return;
        }
        self.cleanup_attempted = true;
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if !metadata.file_type().is_symlink()
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _result = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for DaemonControlService {
    fn drop(&mut self) {
        self.socket.unlink_if_owned();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
        sync::{Arc, Mutex, RwLock},
        time::Duration,
    };

    use erebor_runtime_error::StatusCode;
    use erebor_runtime_ipc::{
        v1::{
            DaemonError as DaemonErrorMessage, DaemonHello, DaemonLogsRequest, DaemonStatusRequest,
            Envelope, GuardHello, KIND_DAEMON_ERROR, KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK,
            KIND_DAEMON_LOGS_REQUEST, KIND_DAEMON_STATUS_REQUEST, KIND_DAEMON_STATUS_RESPONSE,
            PROTOCOL_VERSION,
        },
        AsyncFrameCodec, IpcProtocolError,
    };
    use rustix::process::geteuid;
    use tempfile::TempDir;
    use tokio::{net::UnixStream, sync::Semaphore};

    use super::{
        DaemonApprovalRepository, DaemonConfiguration, DaemonControlState, DaemonLogStore,
        DaemonSecurity, DaemonSocket,
    };
    use crate::{
        config::DaemonConfig, idempotency::DaemonIdempotencyStore, session_api::DaemonSessionApi,
        DaemonPaths,
    };

    #[tokio::test]
    #[ignore = "requires host Unix-domain socket I/O"]
    async fn control_service_observes_real_peer_credentials_and_denies_non_root_logs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let state = Arc::clone(&test_state.state);
        let (mut client, server) = stream_pair()?;
        let permit = state.connections.clone().acquire_owned().await?;
        let worker = tokio::spawn(Arc::clone(&state).serve_connection(server, permit));

        write(
            &mut client,
            1,
            KIND_DAEMON_HELLO,
            &DaemonHello {
                protocol_version: PROTOCOL_VERSION,
                client_name: String::from("test-client"),
                capabilities: Vec::new(),
            },
        )
        .await?;
        let hello = read(&mut client).await?;
        assert_eq!(hello.correlation_id, 1);
        assert_eq!(hello.message_kind, KIND_DAEMON_HELLO_ACK);
        assert!(state.logs.records_after(0, 10)?.iter().any(|record| record
            .message
            .contains(&format!("uid={}", geteuid().as_raw()))));

        write(
            &mut client,
            2,
            KIND_DAEMON_STATUS_REQUEST,
            &DaemonStatusRequest {},
        )
        .await?;
        let status = read(&mut client).await?;
        assert_eq!(status.correlation_id, 2);
        assert_eq!(status.message_kind, KIND_DAEMON_STATUS_RESPONSE);

        if geteuid().as_raw() != 0 {
            write(
                &mut client,
                3,
                KIND_DAEMON_LOGS_REQUEST,
                &DaemonLogsRequest {
                    after_sequence: 0,
                    maximum_records: 1,
                },
            )
            .await?;
            let denied = read(&mut client).await?;
            assert_eq!(denied.message_kind, KIND_DAEMON_ERROR);
            let error: DaemonErrorMessage = denied.decode_typed_payload(KIND_DAEMON_ERROR)?;
            assert_eq!(error.status_code, StatusCode::PermissionDenied.as_u32());
        }
        drop(client);
        worker.await?;
        Ok(())
    }

    #[test]
    fn root_only_operations_reject_non_root_observed_uids() -> Result<(), Box<dyn std::error::Error>>
    {
        let test_state = state()?;
        assert!(test_state
            .state
            .require_root(super::PeerIdentity {
                pid: Some(1),
                uid: 1000,
                gid: 1000,
            })
            .is_err());
        assert!(test_state
            .state
            .require_root(super::PeerIdentity {
                pid: Some(1),
                uid: 0,
                gid: 0,
            })
            .is_ok());
        Ok(())
    }

    #[test]
    fn reload_publishes_configuration_and_generation_as_one_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let mut replacement = test_state
            .state
            .configuration
            .read()
            .map_err(|_error| "configuration lock poisoned")?
            .value
            .clone();
        replacement.max_log_records = 3;

        assert_eq!(
            test_state
                .state
                .publish_configuration(replacement.clone(), 2)?,
            "configuration reloaded at generation 2"
        );
        assert_eq!(
            test_state
                .state
                .publish_configuration(replacement.clone(), 2)?,
            "configuration reloaded at generation 2"
        );
        let active = test_state
            .state
            .configuration
            .read()
            .map_err(|_error| "configuration lock poisoned")?;
        assert_eq!(active.value, replacement);
        assert_eq!(active.generation, 2);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires host Unix-domain socket I/O"]
    async fn control_service_closes_guard_family_connection_before_dispatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let state = Arc::clone(&test_state.state);
        let (mut client, server) = stream_pair()?;
        let permit = state.connections.clone().acquire_owned().await?;
        let worker = tokio::spawn(Arc::clone(&state).serve_connection(server, permit));
        write(
            &mut client,
            1,
            "erebor.runtime.ipc.v1.GuardHello",
            &GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session"),
                actor_id: String::from("guard"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux"),
                capabilities: Vec::new(),
            },
        )
        .await?;
        assert!(matches!(
            AsyncFrameCodec::read_frame(&mut client).await,
            Err(IpcProtocolError::EndOfStream { .. })
        ));
        worker.await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires host Unix-domain socket I/O"]
    async fn control_service_rejects_an_unsupported_request_envelope_protocol(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let state = Arc::clone(&test_state.state);
        let (mut client, server) = stream_pair()?;
        let permit = state.connections.clone().acquire_owned().await?;
        let worker = tokio::spawn(Arc::clone(&state).serve_connection(server, permit));
        write(
            &mut client,
            1,
            KIND_DAEMON_HELLO,
            &DaemonHello {
                protocol_version: PROTOCOL_VERSION,
                client_name: String::from("test-client"),
                capabilities: Vec::new(),
            },
        )
        .await?;
        let _hello = read(&mut client).await?;
        let mut request =
            Envelope::wrap_message(2, 0, KIND_DAEMON_STATUS_REQUEST, &DaemonStatusRequest {})?;
        request.protocol_version = PROTOCOL_VERSION.saturating_add(1);
        AsyncFrameCodec::write_frame(&mut client, &request.into_frame()?).await?;
        let response = read(&mut client).await?;
        assert_eq!(response.message_kind, KIND_DAEMON_ERROR);
        let error: DaemonErrorMessage = response.decode_typed_payload(KIND_DAEMON_ERROR)?;
        assert_eq!(error.status_code, StatusCode::Unsupported.as_u32());
        drop(client);
        worker.await?;
        Ok(())
    }

    #[test]
    #[ignore = "requires host Unix-domain socket I/O"]
    fn daemon_socket_cleanup_preserves_a_replacement_socket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("daemon.sock");
        let listener = StdUnixListener::bind(&path)?;
        let socket = DaemonSocket::from_bound_path(path.clone())?;
        fs::remove_file(&path)?;
        let replacement = StdUnixListener::bind(&path)?;

        drop(socket);
        assert!(path.exists());
        drop(replacement);
        drop(listener);
        Ok(())
    }

    fn state() -> Result<TestState, Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let paths = DaemonPaths::for_testing(root.path());
        let parent = match paths.config_path().parent() {
            Some(parent) => parent,
            None => return Err("test daemon config path has no parent".into()),
        };
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
        let security = DaemonSecurity::current_process();
        fs::write(
            paths.config_path(),
            format!(
                "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":4,\"max_idempotency_records\":4}}",
                security.socket_gid
            ),
        )?;
        fs::set_permissions(paths.config_path(), fs::Permissions::from_mode(0o600))?;
        paths.prepare(security)?;
        let configuration = DaemonConfig::load(&paths, security)?;
        let logs = DaemonLogStore::open(paths.log_path(), configuration.max_log_bytes)?;
        let sessions = DaemonSessionApi::installed(&paths, &configuration)?;
        let approvals = DaemonApprovalRepository::installed(&paths)?;
        let (shutdown, _receiver) = tokio::sync::watch::channel(false);
        Ok(TestState {
            state: Arc::new(DaemonControlState {
                idempotency: Mutex::new(DaemonIdempotencyStore::new(
                    paths.idempotency_path(),
                    paths.session_state_path(),
                    configuration.max_idempotency_records as usize,
                    Duration::from_secs(configuration.session_retry_horizon_seconds),
                )),
                paths,
                security,
                configuration: RwLock::new(DaemonConfiguration {
                    value: configuration,
                    generation: 1,
                }),
                logs,
                sessions,
                approvals,
                shutdown,
                connections: Arc::new(Semaphore::new(1)),
            }),
            _root: root,
        })
    }

    struct TestState {
        state: Arc<DaemonControlState>,
        _root: TempDir,
    }

    fn stream_pair() -> Result<(UnixStream, UnixStream), Box<dyn std::error::Error>> {
        let (first, second) = std::os::unix::net::UnixStream::pair()?;
        first.set_nonblocking(true)?;
        second.set_nonblocking(true)?;
        Ok((UnixStream::from_std(first)?, UnixStream::from_std(second)?))
    }

    async fn write<T: prost::Message>(
        stream: &mut UnixStream,
        message_id: u64,
        kind: &str,
        message: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let envelope = Envelope::wrap_message(message_id, 0, kind, message)?;
        AsyncFrameCodec::write_frame(stream, &envelope.into_frame()?).await?;
        Ok(())
    }

    async fn read(stream: &mut UnixStream) -> Result<Envelope, Box<dyn std::error::Error>> {
        Ok(AsyncFrameCodec::read_frame(stream)
            .await?
            .decode_payload()?)
    }
}
