use std::{
    os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use erebor_runtime_error::ErrorExt;
use erebor_runtime_ipc::{
    v1::{
        DaemonCommandResult, DaemonError as DaemonErrorMessage, DaemonHello, DaemonHelloAck,
        DaemonLogRecord as DaemonLogRecordMessage, DaemonLogsEnd, DaemonLogsRequest,
        DaemonReloadRequest, DaemonStatusRequest, DaemonStatusResponse, DaemonStopRequest,
        Envelope, EnvelopeServiceFamily, KIND_DAEMON_COMMAND_RESULT, KIND_DAEMON_ERROR,
        KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK, KIND_DAEMON_LOGS_END, KIND_DAEMON_LOGS_REQUEST,
        KIND_DAEMON_LOG_RECORD, KIND_DAEMON_RELOAD_REQUEST, KIND_DAEMON_STATUS_REQUEST,
        KIND_DAEMON_STATUS_RESPONSE, KIND_DAEMON_STOP_REQUEST, PROTOCOL_VERSION,
    },
    AsyncFrameCodec,
};
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
    config::DaemonConfig,
    error::{InvalidRequestSnafu, IoSnafu, IpcSnafu, StateLockSnafu, UnauthorizedSnafu},
    idempotency::{DaemonIdempotencyStore, IdempotencyAction},
    log::DaemonLogStore,
    paths::{DaemonLock, DaemonSecurity},
    DaemonError, DaemonPaths, Result,
};

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
    configuration: RwLock<DaemonConfig>,
    generation: Mutex<u64>,
    idempotency: Mutex<DaemonIdempotencyStore>,
    logs: DaemonLogStore,
    shutdown: watch::Sender<bool>,
    connections: Arc<Semaphore>,
}

#[derive(Clone, Copy)]
struct PeerIdentity {
    pid: Option<i32>,
    uid: u32,
    gid: u32,
}

struct DaemonSocket {
    path: PathBuf,
}

impl DaemonControlService {
    pub async fn start_system() -> Result<Self> {
        if geteuid().as_raw() != 0 {
            return InvalidRequestSnafu {
                reason: String::from("erebord must run as root"),
            }
            .fail();
        }
        Self::start(DaemonPaths::system(), 0).await
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
        paths.remove_stale_socket()?;

        let socket_path = paths.socket_path();
        let listener = Self::bind_listener(&socket_path, security)?;
        let socket = DaemonSocket { path: socket_path };
        let logs = DaemonLogStore::open(paths.log_path(), config.max_log_bytes)?;
        logs.record("INFO", "erebord daemon control service started")?;
        let (shutdown_sender, shutdown) = watch::channel(false);
        let state = Arc::new(DaemonControlState {
            idempotency: Mutex::new(DaemonIdempotencyStore::new(paths.idempotency_path())),
            paths,
            security,
            configuration: RwLock::new(config),
            generation: Mutex::new(1),
            logs,
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
        loop {
            tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        return Ok(());
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _address) = accepted.map_err(|source| DaemonError::Io {
                        action: "accepting daemon client",
                        path: self.socket.path.clone(),
                        source,
                        location: snafu::Location::default(),
                    })?;
                    let Some(permit) = self.state.connections.clone().try_acquire_owned().ok() else {
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        state.serve_connection(stream, permit).await;
                    });
                }
            }
        }
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
            Err(error) => {
                let _result = self.logs.record(
                    "ERROR",
                    format!("daemon peer credential lookup failed: {error}"),
                );
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
        if let Err(error) = self.handle_hello(&mut stream, peer, hello).await {
            let _result = self
                .logs
                .record("WARN", format!("daemon client handshake rejected: {error}"));
            return;
        }
        loop {
            let envelope = match self.read_envelope(&mut stream).await {
                Ok(envelope) => envelope,
                Err(_error) => return,
            };
            if let Err(error) = self.dispatch(&mut stream, peer, envelope).await {
                let _result = self
                    .logs
                    .record("WARN", format!("daemon client request failed: {error}"));
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
        if envelope.protocol_version != PROTOCOL_VERSION
            || envelope.message_kind != KIND_DAEMON_HELLO
        {
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
        let mutating = matches!(
            envelope.message_kind.as_str(),
            KIND_DAEMON_RELOAD_REQUEST | KIND_DAEMON_STOP_REQUEST
        );
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
        let generation = *self
            .generation
            .lock()
            .map_err(|_error| StateLockSnafu.build())?;
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
        let message = self.mutate(peer, "reload", envelope, || {
            let config = DaemonConfig::load(&self.paths, self.security)?;
            *self
                .configuration
                .write()
                .map_err(|_error| StateLockSnafu.build())? = config;
            let mut generation = self
                .generation
                .lock()
                .map_err(|_error| StateLockSnafu.build())?;
            *generation = generation.saturating_add(1);
            Ok(format!("configuration reloaded at generation {generation}"))
        })?;
        self.logs.record("INFO", "daemon configuration reloaded")?;
        self.write_result(stream, envelope, message).await
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
        let message = self.mutate(peer, "stop", envelope, || {
            Ok(String::from("daemon stop accepted"))
        })?;
        self.logs.record("INFO", "daemon stop accepted")?;
        self.write_result(stream, envelope, message).await?;
        let _result = self.shutdown.send(true);
        Ok(())
    }

    fn mutate(
        &self,
        peer: PeerIdentity,
        operation: &str,
        envelope: &Envelope,
        action: impl FnOnce() -> Result<String>,
    ) -> Result<String> {
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
        match store.prepare(peer.uid, operation, key, fingerprint)? {
            IdempotencyAction::ReturnCompleted(message) => Ok(message),
            IdempotencyAction::Execute => {
                let message = action()?;
                store.complete(peer.uid, operation, key, fingerprint, message.clone())?;
                Ok(message)
            }
        }
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

    async fn write_result(
        &self,
        stream: &mut UnixStream,
        envelope: &Envelope,
        message: String,
    ) -> Result<()> {
        self.write_message(
            stream,
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_DAEMON_COMMAND_RESULT,
            &DaemonCommandResult { message },
        )
        .await
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
        let _result = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex, RwLock},
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

    use super::{DaemonControlState, DaemonLogStore, DaemonSecurity};
    use crate::{config::DaemonConfig, idempotency::DaemonIdempotencyStore, DaemonPaths};

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
                "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":4}}",
                security.socket_gid
            ),
        )?;
        fs::set_permissions(paths.config_path(), fs::Permissions::from_mode(0o600))?;
        paths.prepare(security)?;
        let configuration = DaemonConfig::load(&paths, security)?;
        let logs = DaemonLogStore::open(paths.log_path(), configuration.max_log_bytes)?;
        let (shutdown, _receiver) = tokio::sync::watch::channel(false);
        Ok(TestState {
            state: Arc::new(DaemonControlState {
                idempotency: Mutex::new(DaemonIdempotencyStore::new(paths.idempotency_path())),
                paths,
                security,
                configuration: RwLock::new(configuration),
                generation: Mutex::new(1),
                logs,
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
