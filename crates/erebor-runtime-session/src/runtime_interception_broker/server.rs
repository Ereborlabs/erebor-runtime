use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use erebor_runtime_ipc::{
    v1::{
        Envelope, GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
        KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, KIND_INTERCEPTION_DECISION,
        KIND_INTERCEPTION_REQUEST, PROTOCOL_VERSION,
    },
    IpcProtocolError,
};
use thiserror::Error;

use super::{
    constants::{DEFAULT_TIMEOUT_MS, RUNTIME_INTERCEPTION_SOCKET_NAME},
    decision::{deny_decision, surface_decision},
    endpoint::RuntimeInterceptionEndpoint,
    handlers::{SessionInterceptionRouter, SessionRegistration},
    platform::{
        Platform, RuntimeInterceptionBrokerPlatform, RuntimeInterceptionBrokerServerPlatform,
    },
    wire::{hex_encode, interception_token, read_frame_from_stream, write_frame_to_stream},
};

static RUNTIME_INTERCEPTION_BROKER_SERVER: Mutex<Option<Arc<RuntimeInterceptionBrokerServer>>> =
    Mutex::new(None);

pub struct RuntimeInterceptionBroker;

impl RuntimeInterceptionBroker {
    pub fn register_session(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        router: SessionInterceptionRouter,
    ) -> Result<SessionInterceptionRegistration, RuntimeInterceptionBrokerError> {
        shared_runtime_interception_broker_server()?.register_session(
            session_id.into(),
            actor_id.into(),
            router,
        )
    }
}

pub struct SessionInterceptionRegistration {
    endpoint: RuntimeInterceptionEndpoint,
    server: Arc<RuntimeInterceptionBrokerServer>,
    session_id: String,
}

impl SessionInterceptionRegistration {
    #[must_use]
    pub fn endpoint(&self) -> &RuntimeInterceptionEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub(crate) fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.endpoint = self.endpoint.with_timeout_ms(timeout_ms);
        self
    }

    #[must_use]
    pub fn docker_endpoint(
        &self,
        container_directory: impl AsRef<Path>,
    ) -> RuntimeInterceptionEndpoint {
        self.endpoint.with_path(
            container_directory
                .as_ref()
                .join(RUNTIME_INTERCEPTION_SOCKET_NAME),
        )
    }
}

impl Drop for SessionInterceptionRegistration {
    fn drop(&mut self) {
        self.server
            .unregister_session(&self.session_id, self.endpoint.token());
    }
}

#[derive(Debug, Error)]
pub enum RuntimeInterceptionBrokerError {
    #[error("runtime interception broker transport `{transport}` is unsupported on this platform")]
    UnsupportedTransport { transport: String },
    #[error("runtime interception broker state lock failed")]
    StateLock,
    #[error("session `{session_id}` is already registered with the runtime interception broker")]
    SessionAlreadyRegistered { session_id: String },
    #[error("runtime interception broker server platform is not started")]
    ServerNotStarted,
    #[error("runtime interception broker rejected guard hello: {reason}")]
    RejectedHello { reason: String },
    #[error("runtime interception broker I/O failed: {source}")]
    Io { source: io::Error },
    #[error("runtime interception broker IPC protocol failed: {source}")]
    Protocol { source: IpcProtocolError },
}

impl RuntimeInterceptionBrokerError {
    pub(super) fn io(source: io::Error) -> Self {
        Self::Io { source }
    }

    pub(super) fn protocol(source: IpcProtocolError) -> Self {
        Self::Protocol { source }
    }
}

pub(super) struct RuntimeInterceptionBrokerServer {
    platform: Mutex<Option<Box<dyn RuntimeInterceptionBrokerServerPlatform>>>,
    sessions: Mutex<HashMap<String, SessionRegistration>>,
}

impl RuntimeInterceptionBrokerServer {
    fn start() -> Result<Arc<Self>, RuntimeInterceptionBrokerError> {
        let server = Arc::new(Self {
            platform: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
        });
        let platform =
            <Platform as RuntimeInterceptionBrokerPlatform>::start_server(Arc::clone(&server))?;
        *server
            .platform
            .lock()
            .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)? = Some(platform);
        Ok(server)
    }

    fn register_session(
        self: &Arc<Self>,
        session_id: String,
        actor_id: String,
        router: SessionInterceptionRouter,
    ) -> Result<SessionInterceptionRegistration, RuntimeInterceptionBrokerError> {
        let endpoint_path = self.endpoint_path()?;
        let token = read_interception_token()?;
        let registration = SessionRegistration {
            token: token.clone(),
            broker_id: format!("{session_id}:{actor_id}"),
            router,
        };
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)?;
            if sessions.contains_key(&session_id) {
                return Err(RuntimeInterceptionBrokerError::SessionAlreadyRegistered {
                    session_id,
                });
            }
            sessions.insert(session_id.clone(), registration);
        }

        Ok(SessionInterceptionRegistration {
            endpoint: RuntimeInterceptionEndpoint::unix(endpoint_path, token, DEFAULT_TIMEOUT_MS),
            server: Arc::clone(self),
            session_id,
        })
    }

    fn unregister_session(&self, session_id: &str, token: &str) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        if sessions
            .get(session_id)
            .is_some_and(|registration| registration.token == token)
        {
            sessions.remove(session_id);
        }
    }

    fn endpoint_path(&self) -> Result<PathBuf, RuntimeInterceptionBrokerError> {
        let platform = self
            .platform
            .lock()
            .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)?;
        let Some(platform) = platform.as_ref() else {
            return Err(RuntimeInterceptionBrokerError::ServerNotStarted);
        };
        Ok(platform.endpoint_path().to_path_buf())
    }

    pub(super) fn handle_stream(&self, stream: &mut (impl Read + Write)) {
        let mut bound = None::<BoundConnection>;
        while let Ok(request_frame) = read_frame_from_stream(stream) {
            let envelope = match request_frame.decode_payload::<Envelope>() {
                Ok(envelope) => envelope,
                Err(_error) => break,
            };
            let response = match self.handle_runtime_interception_envelope(envelope, &mut bound) {
                Ok(response) => response,
                Err(_error) => break,
            };
            let response_frame = match response.into_frame() {
                Ok(frame) => frame,
                Err(_error) => break,
            };
            if write_frame_to_stream(stream, &response_frame).is_err() {
                break;
            }
        }
    }
}

impl Drop for RuntimeInterceptionBrokerServer {
    fn drop(&mut self) {
        if let Ok(mut platform) = self.platform.lock() {
            if let Some(platform) = platform.take() {
                platform.shutdown();
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundConnection {
    session_id: String,
}

fn shared_runtime_interception_broker_server(
) -> Result<Arc<RuntimeInterceptionBrokerServer>, RuntimeInterceptionBrokerError> {
    let mut server = RUNTIME_INTERCEPTION_BROKER_SERVER
        .lock()
        .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)?;
    if let Some(server) = server.as_ref() {
        return Ok(Arc::clone(server));
    }

    let started = RuntimeInterceptionBrokerServer::start()?;
    *server = Some(Arc::clone(&started));
    Ok(started)
}

fn read_interception_token() -> Result<String, RuntimeInterceptionBrokerError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(RuntimeInterceptionBrokerError::io)?;

    Ok(hex_encode(&random))
}

impl RuntimeInterceptionBrokerServer {
    fn handle_runtime_interception_envelope(
        &self,
        envelope: Envelope,
        bound: &mut Option<BoundConnection>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        if bound.is_none() {
            return self.handle_hello_envelope(envelope, bound);
        }

        match envelope.message_kind.as_str() {
            KIND_INTERCEPTION_REQUEST => self.handle_interception_request_envelope(envelope, bound),
            _ => deny_unexpected_bound_message(envelope),
        }
    }

    fn handle_hello_envelope(
        &self,
        envelope: Envelope,
        bound: &mut Option<BoundConnection>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let mut broker_id = String::from("unregistered");
        let mut accepted = false;
        let mut accepted_session_id = None;

        let reason = if envelope.message_kind != KIND_GUARD_HELLO {
            format!("unexpected message kind `{}`", envelope.message_kind)
        } else {
            let hello: GuardHello = envelope
                .decode_typed_payload(KIND_GUARD_HELLO)
                .map_err(RuntimeInterceptionBrokerError::protocol)?;
            let sessions = self
                .sessions
                .lock()
                .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)?;
            match sessions.get(&hello.session_id) {
                Some(registration)
                    if interception_token(&envelope) == Some(registration.token.as_str()) =>
                {
                    broker_id = registration.broker_id.clone();
                    accepted = true;
                    accepted_session_id = Some(hello.session_id);
                    String::from("accepted")
                }
                Some(_) => String::from("invalid interception token"),
                None => String::from("unknown session"),
            }
        };
        let ack = GuardHelloAck {
            protocol_version: PROTOCOL_VERSION,
            broker_id,
            accepted,
            reason,
        };
        if accepted {
            if let Some(session_id) = accepted_session_id {
                *bound = Some(BoundConnection { session_id });
            }
        }

        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_GUARD_HELLO_ACK,
            &ack,
        )
        .map_err(RuntimeInterceptionBrokerError::protocol)
    }

    fn handle_interception_request_envelope(
        &self,
        envelope: Envelope,
        bound: &Option<BoundConnection>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let request: InterceptionRequest = envelope
            .decode_typed_payload(KIND_INTERCEPTION_REQUEST)
            .map_err(RuntimeInterceptionBrokerError::protocol)?;
        let decision = self.interception_decision_for_request(bound, &request)?;

        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            request.request_id,
            KIND_INTERCEPTION_DECISION,
            &decision,
        )
        .map_err(RuntimeInterceptionBrokerError::protocol)
    }

    fn interception_decision_for_request(
        &self,
        bound: &Option<BoundConnection>,
        request: &InterceptionRequest,
    ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
        let Some(bound) = bound else {
            return Ok(deny_decision(
                request.request_id,
                "erebor-runtime-interception-broker-unbound",
                "interception request arrived before GuardHello",
            ));
        };
        {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_error| RuntimeInterceptionBrokerError::StateLock)?;
            let Some(registration) = sessions.get(&bound.session_id) else {
                return Ok(deny_decision(
                    request.request_id,
                    "erebor-runtime-interception-broker-unknown-session",
                    "session is no longer registered with the runtime interception broker",
                ));
            };
            Ok(registration
                .router
                .route_interception(request)
                .map(|decision| surface_decision(request.request_id, decision))
                .unwrap_or_else(|| {
                    deny_decision(
                        request.request_id,
                        "erebor-runtime-interception-broker-unrouted-process-exec",
                        "no surface is registered for process_exec interception",
                    )
                }))
        }
    }
}

fn deny_unexpected_bound_message(
    envelope: Envelope,
) -> Result<Envelope, RuntimeInterceptionBrokerError> {
    let decision = deny_decision(
        envelope.message_id,
        "erebor-runtime-interception-broker-unexpected-message",
        format!(
            "unexpected message kind `{}` on bound guard connection",
            envelope.message_kind
        ),
    );
    Envelope::wrap_message(
        envelope.message_id.saturating_add(1),
        envelope.message_id,
        KIND_INTERCEPTION_DECISION,
        &decision,
    )
    .map_err(RuntimeInterceptionBrokerError::protocol)
}
