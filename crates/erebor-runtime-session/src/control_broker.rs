use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

use erebor_runtime_ipc::{
    v1::{
        AllowDecision, DecisionKind, DenyDecision, Envelope, GuardHello, GuardHelloAck, Header,
        InterceptionDecision, InterceptionRequest, MediateDecision, KIND_GUARD_HELLO,
        KIND_GUARD_HELLO_ACK, KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST,
        PROTOCOL_VERSION,
    },
    EreborIpcFrame, IpcProtocolError, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN,
};
use thiserror::Error;

const CONTROL_SOCKET_NAME: &str = "session-control.sock";
const CONTROL_PROTOCOL: &str = "erebor_ipc_v1";
const CONTROL_TOKEN_HEADER: &str = "control_token";
const DEFAULT_TIMEOUT_MS: u64 = 25;

static CONTROL_BROKER_SERVER: Mutex<Option<Arc<ControlBrokerServer>>> = Mutex::new(None);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionControlBrokerEndpoint {
    transport: String,
    path: PathBuf,
    token: String,
    timeout_ms: u64,
}

impl SessionControlBrokerEndpoint {
    #[must_use]
    pub fn unix(path: impl Into<PathBuf>, token: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            transport: String::from("unix"),
            path: path.into(),
            token: token.into(),
            timeout_ms,
        }
    }

    #[must_use]
    pub fn with_path(&self, path: impl Into<PathBuf>) -> Self {
        Self {
            transport: self.transport.clone(),
            path: path.into(),
            token: self.token.clone(),
            timeout_ms: self.timeout_ms,
        }
    }

    #[must_use]
    pub fn environment(&self) -> Vec<(String, String)> {
        vec![
            (
                String::from("EREBOR_SESSION_CONTROL_PROTOCOL"),
                String::from(CONTROL_PROTOCOL),
            ),
            (
                String::from("EREBOR_SESSION_CONTROL_TRANSPORT"),
                self.transport.clone(),
            ),
            (
                String::from("EREBOR_SESSION_CONTROL_PATH"),
                self.path.display().to_string(),
            ),
            (
                String::from("EREBOR_SESSION_CONTROL_TOKEN"),
                self.token.clone(),
            ),
            (
                String::from("EREBOR_SESSION_CONTROL_TIMEOUT_MS"),
                self.timeout_ms.to_string(),
            ),
        ]
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Clone, Debug)]
struct SessionRegistration {
    token: String,
    broker_id: String,
    handlers: HashMap<String, SessionInterceptionHandler>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionHandler {
    id: String,
    decision: SessionInterceptionDecision,
    reason: String,
    allowed_ports: Vec<u16>,
    mediate: Option<SessionInterceptionMediation>,
}

impl SessionInterceptionHandler {
    #[must_use]
    pub fn allow(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Allow,
            reason: reason.into(),
            allowed_ports: Vec::new(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn deny(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Deny,
            reason: reason.into(),
            allowed_ports: Vec::new(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn require_approval(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::RequireApproval,
            reason: reason.into(),
            allowed_ports: Vec::new(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn mediate(
        id: impl Into<String>,
        reason: impl Into<String>,
        mediation: SessionInterceptionMediation,
    ) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Mediate,
            reason: reason.into(),
            allowed_ports: Vec::new(),
            mediate: Some(mediation),
        }
    }

    #[must_use]
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = ports;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionInterceptionDecision {
    Allow,
    Deny,
    RequireApproval,
    Mediate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionMediation {
    kind: String,
    replacement_surface: String,
    endpoint: String,
    lease_id: String,
    print_line: String,
    keepalive: bool,
}

impl SessionInterceptionMediation {
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        replacement_surface: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            endpoint: endpoint.into(),
            lease_id: String::new(),
            print_line: String::new(),
            keepalive: false,
        }
    }

    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = lease_id.into();
        self
    }

    #[must_use]
    pub fn with_print_line(mut self, print_line: impl Into<String>) -> Self {
        self.print_line = print_line.into();
        self
    }

    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }
}

pub struct SessionControlBroker;

impl SessionControlBroker {
    pub fn register_session(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        handlers: Vec<SessionInterceptionHandler>,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        shared_control_broker_server()?.register_session(
            session_id.into(),
            actor_id.into(),
            handlers,
        )
    }
}

pub struct SessionControlRegistration {
    endpoint: SessionControlBrokerEndpoint,
    server: Arc<ControlBrokerServer>,
    session_id: String,
}

impl SessionControlRegistration {
    #[must_use]
    pub fn endpoint(&self) -> &SessionControlBrokerEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn docker_endpoint(
        &self,
        container_directory: impl AsRef<Path>,
    ) -> SessionControlBrokerEndpoint {
        self.endpoint
            .with_path(container_directory.as_ref().join(CONTROL_SOCKET_NAME))
    }
}

impl Drop for SessionControlRegistration {
    fn drop(&mut self) {
        self.server
            .unregister_session(&self.session_id, self.endpoint.token());
    }
}

pub struct GuardBrokerClient;

impl GuardBrokerClient {
    pub fn send_hello(
        endpoint: &SessionControlBrokerEndpoint,
        hello: GuardHello,
    ) -> Result<GuardHelloAck, SessionControlBrokerError> {
        platform::send_hello(endpoint, hello)
    }

    pub fn request_interception_decision(
        endpoint: &SessionControlBrokerEndpoint,
        hello: GuardHello,
        request: InterceptionRequest,
    ) -> Result<InterceptionDecision, SessionControlBrokerError> {
        platform::request_interception_decision(endpoint, hello, request)
    }

    fn connect_raw(
        endpoint: &SessionControlBrokerEndpoint,
    ) -> Result<(), SessionControlBrokerError> {
        platform::connect_raw(endpoint)
    }
}

#[derive(Debug, Error)]
pub enum SessionControlBrokerError {
    #[error("session control broker transport `{transport}` is unsupported on this platform")]
    UnsupportedTransport { transport: String },
    #[error("session control broker state lock failed")]
    StateLock,
    #[error("session `{session_id}` is already registered with the control broker")]
    SessionAlreadyRegistered { session_id: String },
    #[error("session control broker rejected guard hello: {reason}")]
    RejectedHello { reason: String },
    #[error("session control broker I/O failed: {source}")]
    Io { source: io::Error },
    #[error("session control broker IPC protocol failed: {source}")]
    Protocol { source: IpcProtocolError },
}

impl SessionControlBrokerError {
    fn io(source: io::Error) -> Self {
        Self::Io { source }
    }

    fn protocol(source: IpcProtocolError) -> Self {
        Self::Protocol { source }
    }
}

struct ControlBrokerServer {
    endpoint_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    sessions: Arc<Mutex<HashMap<String, SessionRegistration>>>,
}

impl ControlBrokerServer {
    fn register_session(
        self: &Arc<Self>,
        session_id: String,
        actor_id: String,
        handlers: Vec<SessionInterceptionHandler>,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        let token = read_control_token()?;
        let registration = SessionRegistration {
            token: token.clone(),
            broker_id: format!("{session_id}:{actor_id}"),
            handlers: handlers
                .into_iter()
                .map(|handler| (handler.id.clone(), handler))
                .collect(),
        };
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_error| SessionControlBrokerError::StateLock)?;
            if sessions.contains_key(&session_id) {
                return Err(SessionControlBrokerError::SessionAlreadyRegistered { session_id });
            }
            sessions.insert(session_id.clone(), registration);
        }

        Ok(SessionControlRegistration {
            endpoint: SessionControlBrokerEndpoint::unix(
                &self.endpoint_path,
                token,
                DEFAULT_TIMEOUT_MS,
            ),
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundConnection {
    session_id: String,
}

impl Drop for ControlBrokerServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _result = GuardBrokerClient::connect_raw(&SessionControlBrokerEndpoint::unix(
            &self.endpoint_path,
            "",
            DEFAULT_TIMEOUT_MS,
        ));
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                let _result = worker.join();
            }
        }
        let _result = fs::remove_file(&self.endpoint_path);
    }
}

fn shared_control_broker_server() -> Result<Arc<ControlBrokerServer>, SessionControlBrokerError> {
    let mut server = CONTROL_BROKER_SERVER
        .lock()
        .map_err(|_error| SessionControlBrokerError::StateLock)?;
    if let Some(server) = server.as_ref() {
        return Ok(Arc::clone(server));
    }

    let started = platform::start_server()?;
    *server = Some(Arc::clone(&started));
    Ok(started)
}

fn read_control_token() -> Result<String, SessionControlBrokerError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(SessionControlBrokerError::io)?;

    Ok(hex_encode(&random))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn control_token(envelope: &Envelope) -> Option<&str> {
    envelope
        .headers
        .iter()
        .find(|header| header.key == CONTROL_TOKEN_HEADER)
        .map(|header| header.value.as_str())
}

fn envelope_with_token(mut envelope: Envelope, token: impl Into<String>) -> Envelope {
    envelope.headers.push(Header {
        key: String::from(CONTROL_TOKEN_HEADER),
        value: token.into(),
    });
    envelope
}

fn read_frame_from_stream(
    stream: &mut impl Read,
) -> Result<EreborIpcFrame, SessionControlBrokerError> {
    let mut header = [0_u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(SessionControlBrokerError::io)?;

    if header[0..4] != MAGIC {
        return Err(SessionControlBrokerError::protocol(
            IpcProtocolError::InvalidMagic,
        ));
    }

    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != FRAME_VERSION {
        return Err(SessionControlBrokerError::protocol(
            IpcProtocolError::UnsupportedFrameVersion { version },
        ));
    }

    let payload_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(SessionControlBrokerError::protocol(
            IpcProtocolError::PayloadTooLarge {
                actual: payload_len,
                maximum: MAX_PAYLOAD_LEN,
            },
        ));
    }

    let mut frame = Vec::with_capacity(HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_LEN + payload_len, 0);
    stream
        .read_exact(&mut frame[HEADER_LEN..])
        .map_err(SessionControlBrokerError::io)?;

    EreborIpcFrame::decode(&frame).map_err(SessionControlBrokerError::protocol)
}

fn write_frame_to_stream(
    stream: &mut impl Write,
    frame: &EreborIpcFrame,
) -> Result<(), SessionControlBrokerError> {
    stream
        .write_all(
            &frame
                .encode()
                .map_err(SessionControlBrokerError::protocol)?,
        )
        .map_err(SessionControlBrokerError::io)
}

fn handle_control_envelope(
    envelope: Envelope,
    sessions: &Mutex<HashMap<String, SessionRegistration>>,
    bound: &mut Option<BoundConnection>,
) -> Result<Envelope, SessionControlBrokerError> {
    if bound.is_none() {
        return handle_hello_envelope(envelope, sessions, bound);
    }

    match envelope.message_kind.as_str() {
        KIND_INTERCEPTION_REQUEST => {
            handle_interception_request_envelope(envelope, sessions, bound)
        }
        _ => deny_unexpected_bound_message(envelope),
    }
}

fn handle_hello_envelope(
    envelope: Envelope,
    sessions: &Mutex<HashMap<String, SessionRegistration>>,
    bound: &mut Option<BoundConnection>,
) -> Result<Envelope, SessionControlBrokerError> {
    let mut broker_id = String::from("unregistered");
    let mut accepted = false;
    let mut accepted_session_id = None;

    let reason = if envelope.message_kind != KIND_GUARD_HELLO {
        format!("unexpected message kind `{}`", envelope.message_kind)
    } else {
        let hello: GuardHello = envelope
            .decode_typed_payload(KIND_GUARD_HELLO)
            .map_err(SessionControlBrokerError::protocol)?;
        let sessions = sessions
            .lock()
            .map_err(|_error| SessionControlBrokerError::StateLock)?;
        match sessions.get(&hello.session_id) {
            Some(registration) if control_token(&envelope) == Some(registration.token.as_str()) => {
                broker_id = registration.broker_id.clone();
                accepted = true;
                accepted_session_id = Some(hello.session_id);
                String::from("accepted")
            }
            Some(_) => String::from("invalid control token"),
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
    .map_err(SessionControlBrokerError::protocol)
}

fn handle_interception_request_envelope(
    envelope: Envelope,
    sessions: &Mutex<HashMap<String, SessionRegistration>>,
    bound: &Option<BoundConnection>,
) -> Result<Envelope, SessionControlBrokerError> {
    let request: InterceptionRequest = envelope
        .decode_typed_payload(KIND_INTERCEPTION_REQUEST)
        .map_err(SessionControlBrokerError::protocol)?;
    let decision = interception_decision_for_request(sessions, bound, &request)?;

    Envelope::wrap_message(
        envelope.message_id.saturating_add(1),
        request.request_id,
        KIND_INTERCEPTION_DECISION,
        &decision,
    )
    .map_err(SessionControlBrokerError::protocol)
}

fn interception_decision_for_request(
    sessions: &Mutex<HashMap<String, SessionRegistration>>,
    bound: &Option<BoundConnection>,
    request: &InterceptionRequest,
) -> Result<InterceptionDecision, SessionControlBrokerError> {
    let Some(bound) = bound else {
        return Ok(deny_decision(
            request.request_id,
            "erebor-control-broker-unbound",
            "interception request arrived before GuardHello",
        ));
    };
    let sessions = sessions
        .lock()
        .map_err(|_error| SessionControlBrokerError::StateLock)?;
    let Some(registration) = sessions.get(&bound.session_id) else {
        return Ok(deny_decision(
            request.request_id,
            "erebor-control-broker-unknown-session",
            "session is no longer registered with the control broker",
        ));
    };
    let Some(handler) = registration.handlers.get(&request.matched_handler_id) else {
        return Ok(deny_decision(
            request.request_id,
            "erebor-control-broker-unknown-handler",
            "interception handler is not registered for this session",
        ));
    };

    Ok(handler.decision_for_request(request))
}

fn deny_unexpected_bound_message(
    envelope: Envelope,
) -> Result<Envelope, SessionControlBrokerError> {
    let decision = deny_decision(
        envelope.message_id,
        "erebor-control-broker-unexpected-message",
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
    .map_err(SessionControlBrokerError::protocol)
}

impl SessionInterceptionHandler {
    fn decision_for_request(&self, request: &InterceptionRequest) -> InterceptionDecision {
        if self.decision == SessionInterceptionDecision::Mediate {
            if let Some(reason) = self.port_validation_failure(request) {
                return deny_decision(request.request_id, &self.id, reason);
            }
        }

        match self.decision {
            SessionInterceptionDecision::Allow => InterceptionDecision {
                request_id: request.request_id,
                decision: DecisionKind::Allow as i32,
                rule_id: self.id.clone(),
                reason: self.reason.clone(),
                timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                allow: Some(AllowDecision {
                    exec_target: String::new(),
                }),
                deny: None,
                mediate: None,
            },
            SessionInterceptionDecision::Deny => {
                deny_decision(request.request_id, &self.id, self.reason.clone())
            }
            SessionInterceptionDecision::RequireApproval => InterceptionDecision {
                request_id: request.request_id,
                decision: DecisionKind::RequireApproval as i32,
                rule_id: self.id.clone(),
                reason: self.reason.clone(),
                timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                allow: None,
                deny: None,
                mediate: None,
            },
            SessionInterceptionDecision::Mediate => {
                let Some(mediation) = self.mediate.as_ref() else {
                    return deny_decision(
                        request.request_id,
                        &self.id,
                        "mediate handler has no replacement details",
                    );
                };
                InterceptionDecision {
                    request_id: request.request_id,
                    decision: DecisionKind::Mediate as i32,
                    rule_id: self.id.clone(),
                    reason: self.reason.clone(),
                    timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                    allow: None,
                    deny: None,
                    mediate: Some(MediateDecision {
                        kind: mediation.kind.clone(),
                        replacement_surface: mediation.replacement_surface.clone(),
                        endpoint: mediation.endpoint.clone(),
                        lease_id: mediation.lease_id.clone(),
                        print_line: mediation.print_line.clone(),
                        keepalive: mediation.keepalive,
                    }),
                }
            }
        }
    }

    fn port_validation_failure(&self, request: &InterceptionRequest) -> Option<String> {
        if self.allowed_ports.is_empty() {
            return None;
        }
        let requested_port = remote_debugging_port(&request.argv)?;
        if self.allowed_ports.contains(&requested_port) {
            None
        } else {
            Some(format!(
                "requested remote debugging port {requested_port} is not allowed"
            ))
        }
    }
}

fn deny_decision(
    request_id: u64,
    rule_id: impl Into<String>,
    reason: impl Into<String>,
) -> InterceptionDecision {
    InterceptionDecision {
        request_id,
        decision: DecisionKind::Deny as i32,
        rule_id: rule_id.into(),
        reason: reason.into(),
        timeout_ms: DEFAULT_TIMEOUT_MS as u32,
        allow: None,
        deny: Some(DenyDecision { exit_code: 126 }),
        mediate: None,
    }
}

fn remote_debugging_port(args: &[String]) -> Option<u16> {
    let mut iter = args.iter().peekable();
    while let Some(argument) = iter.next() {
        if let Some(port) = argument.strip_prefix("--remote-debugging-port=") {
            return port.parse().ok();
        }
        if argument == "--remote-debugging-port" {
            return iter.peek().and_then(|port| port.parse().ok());
        }
    }
    None
}

#[cfg(unix)]
mod platform {
    use std::{
        fs,
        os::unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread,
        time::Duration,
    };

    use erebor_runtime_ipc::v1::{
        Envelope, GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
        KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, KIND_INTERCEPTION_DECISION,
        KIND_INTERCEPTION_REQUEST,
    };

    use super::{
        envelope_with_token, handle_control_envelope, read_frame_from_stream,
        write_frame_to_stream, BoundConnection, ControlBrokerServer, SessionControlBrokerEndpoint,
        SessionControlBrokerError, SessionRegistration, CONTROL_SOCKET_NAME, DEFAULT_TIMEOUT_MS,
    };
    use std::collections::HashMap;

    pub(super) fn start_server() -> Result<Arc<ControlBrokerServer>, SessionControlBrokerError> {
        let directory =
            std::env::temp_dir().join(format!("erebor-session-control-{}", std::process::id()));
        fs::create_dir_all(&directory).map_err(SessionControlBrokerError::io)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(SessionControlBrokerError::io)?;
        let socket_path = directory.join(CONTROL_SOCKET_NAME);
        let _result = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).map_err(SessionControlBrokerError::io)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .map_err(SessionControlBrokerError::io)?;
        listener
            .set_nonblocking(true)
            .map_err(SessionControlBrokerError::io)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let sessions: Arc<Mutex<HashMap<String, SessionRegistration>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let worker_sessions = Arc::clone(&sessions);
        let worker = thread::spawn(move || {
            let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
            while !worker_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let sessions = Arc::clone(&worker_sessions);
                        thread::spawn(move || {
                            handle_connection(stream, sessions, timeout);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_error) => {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });

        Ok(Arc::new(ControlBrokerServer {
            endpoint_path: socket_path,
            shutdown,
            worker: Mutex::new(Some(worker)),
            sessions,
        }))
    }

    fn handle_connection(
        mut stream: UnixStream,
        sessions: Arc<Mutex<HashMap<String, SessionRegistration>>>,
        timeout: Duration,
    ) {
        let _result = stream.set_write_timeout(Some(timeout));
        let mut bound = None::<BoundConnection>;
        while let Ok(request_frame) = read_frame_from_stream(&mut stream) {
            let envelope = match request_frame.decode_payload::<Envelope>() {
                Ok(envelope) => envelope,
                Err(_error) => break,
            };
            let response = match handle_control_envelope(envelope, &sessions, &mut bound) {
                Ok(response) => response,
                Err(_error) => break,
            };
            let response_frame = match response.into_frame() {
                Ok(frame) => frame,
                Err(_error) => break,
            };
            if write_frame_to_stream(&mut stream, &response_frame).is_err() {
                break;
            }
        }
    }

    pub(super) fn send_hello(
        endpoint: &SessionControlBrokerEndpoint,
        hello: GuardHello,
    ) -> Result<GuardHelloAck, SessionControlBrokerError> {
        let mut stream =
            UnixStream::connect(endpoint.path()).map_err(SessionControlBrokerError::io)?;
        stream
            .set_read_timeout(Some(endpoint.timeout()))
            .map_err(SessionControlBrokerError::io)?;
        stream
            .set_write_timeout(Some(endpoint.timeout()))
            .map_err(SessionControlBrokerError::io)?;
        let envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &hello)
            .map_err(SessionControlBrokerError::protocol)?;
        let request = envelope_with_token(envelope, endpoint.token());
        let request_frame = request
            .into_frame()
            .map_err(SessionControlBrokerError::protocol)?;
        write_frame_to_stream(&mut stream, &request_frame)?;

        let response_frame = read_frame_from_stream(&mut stream)?;
        let response_envelope: Envelope = response_frame
            .decode_payload()
            .map_err(SessionControlBrokerError::protocol)?;
        response_envelope
            .decode_typed_payload(KIND_GUARD_HELLO_ACK)
            .map_err(SessionControlBrokerError::protocol)
    }

    pub(super) fn request_interception_decision(
        endpoint: &SessionControlBrokerEndpoint,
        hello: GuardHello,
        request: InterceptionRequest,
    ) -> Result<InterceptionDecision, SessionControlBrokerError> {
        let mut stream =
            UnixStream::connect(endpoint.path()).map_err(SessionControlBrokerError::io)?;
        stream
            .set_read_timeout(Some(endpoint.timeout()))
            .map_err(SessionControlBrokerError::io)?;
        stream
            .set_write_timeout(Some(endpoint.timeout()))
            .map_err(SessionControlBrokerError::io)?;

        let hello_envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &hello)
            .map_err(SessionControlBrokerError::protocol)?;
        let hello_request = envelope_with_token(hello_envelope, endpoint.token());
        write_frame_to_stream(
            &mut stream,
            &hello_request
                .into_frame()
                .map_err(SessionControlBrokerError::protocol)?,
        )?;
        let hello_response_frame = read_frame_from_stream(&mut stream)?;
        let hello_response: Envelope = hello_response_frame
            .decode_payload()
            .map_err(SessionControlBrokerError::protocol)?;
        let ack: GuardHelloAck = hello_response
            .decode_typed_payload(KIND_GUARD_HELLO_ACK)
            .map_err(SessionControlBrokerError::protocol)?;
        if !ack.accepted {
            return Err(SessionControlBrokerError::RejectedHello { reason: ack.reason });
        }

        let request_envelope = Envelope::wrap_message(2, 1, KIND_INTERCEPTION_REQUEST, &request)
            .map_err(SessionControlBrokerError::protocol)?;
        write_frame_to_stream(
            &mut stream,
            &request_envelope
                .into_frame()
                .map_err(SessionControlBrokerError::protocol)?,
        )?;
        let response_frame = read_frame_from_stream(&mut stream)?;
        let response_envelope: Envelope = response_frame
            .decode_payload()
            .map_err(SessionControlBrokerError::protocol)?;
        response_envelope
            .decode_typed_payload(KIND_INTERCEPTION_DECISION)
            .map_err(SessionControlBrokerError::protocol)
    }

    pub(super) fn connect_raw(
        endpoint: &SessionControlBrokerEndpoint,
    ) -> Result<(), SessionControlBrokerError> {
        let _stream =
            UnixStream::connect(endpoint.path()).map_err(SessionControlBrokerError::io)?;
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use std::sync::Arc;

    use erebor_runtime_ipc::v1::{
        GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
    };

    use super::{ControlBrokerServer, SessionControlBrokerEndpoint, SessionControlBrokerError};

    pub(super) fn start_server() -> Result<Arc<ControlBrokerServer>, SessionControlBrokerError> {
        Err(SessionControlBrokerError::UnsupportedTransport {
            transport: String::from("windows-named-pipe"),
        })
    }

    pub(super) fn send_hello(
        _endpoint: &SessionControlBrokerEndpoint,
        _hello: GuardHello,
    ) -> Result<GuardHelloAck, SessionControlBrokerError> {
        Err(SessionControlBrokerError::UnsupportedTransport {
            transport: String::from("windows-named-pipe"),
        })
    }

    pub(super) fn request_interception_decision(
        _endpoint: &SessionControlBrokerEndpoint,
        _hello: GuardHello,
        _request: InterceptionRequest,
    ) -> Result<InterceptionDecision, SessionControlBrokerError> {
        Err(SessionControlBrokerError::UnsupportedTransport {
            transport: String::from("windows-named-pipe"),
        })
    }

    pub(super) fn connect_raw(
        _endpoint: &SessionControlBrokerEndpoint,
    ) -> Result<(), SessionControlBrokerError> {
        Err(SessionControlBrokerError::UnsupportedTransport {
            transport: String::from("windows-named-pipe"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use erebor_runtime_ipc::v1::{
        DecisionKind, GuardHello, InterceptionRequest, InterceptionSource, PROTOCOL_VERSION,
    };

    use super::{
        GuardBrokerClient, SessionControlBroker, SessionControlBrokerEndpoint,
        SessionControlBrokerError, SessionInterceptionHandler, SessionInterceptionMediation,
    };

    #[test]
    fn broker_accepts_guard_hello_with_control_token() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("accepts-hello");
        let broker = SessionControlBroker::register_session(&session_id, "openclaw", Vec::new())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(broker.endpoint().directory())?
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(broker.endpoint().path())?.permissions().mode() & 0o777,
                0o600
            );
        }

        let ack = GuardBrokerClient::send_hello(broker.endpoint(), hello(&session_id))?;

        assert!(ack.accepted);
        assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
        assert!(ack.broker_id.contains(&session_id));

        Ok(())
    }

    #[test]
    fn broker_rejects_guard_hello_with_bad_control_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let session_id = session_id("rejects-token");
        let broker = SessionControlBroker::register_session(&session_id, "openclaw", Vec::new())?;
        let bad_endpoint = broker.endpoint().with_path(broker.endpoint().path());
        let bad_endpoint =
            SessionControlBrokerEndpoint::unix(bad_endpoint.path(), "wrong-token", 25);

        let ack = GuardBrokerClient::send_hello(&bad_endpoint, hello(&session_id))?;

        assert!(!ack.accepted);
        assert_eq!(ack.reason, "invalid control token");

        Ok(())
    }

    #[test]
    fn broker_accepts_multiple_sessions_on_one_server() -> Result<(), Box<dyn std::error::Error>> {
        let first_session = session_id("first");
        let second_session = session_id("second");
        let first = SessionControlBroker::register_session(&first_session, "openclaw", Vec::new())?;
        let second = SessionControlBroker::register_session(&second_session, "codex", Vec::new())?;

        assert_eq!(first.endpoint().path(), second.endpoint().path());
        assert_ne!(first.endpoint().token(), second.endpoint().token());

        let first_ack = GuardBrokerClient::send_hello(first.endpoint(), hello(&first_session))?;
        let second_ack = GuardBrokerClient::send_hello(second.endpoint(), hello(&second_session))?;
        let crossed_endpoint = SessionControlBrokerEndpoint::unix(
            first.endpoint().path(),
            second.endpoint().token(),
            25,
        );
        let crossed_ack = GuardBrokerClient::send_hello(&crossed_endpoint, hello(&first_session))?;

        assert!(first_ack.accepted);
        assert!(second_ack.accepted);
        assert!(!crossed_ack.accepted);
        assert_eq!(crossed_ack.reason, "invalid control token");
        Ok(())
    }

    #[test]
    fn broker_unregisters_session_when_registration_drops() -> Result<(), Box<dyn std::error::Error>>
    {
        let session_id = session_id("drop-unregisters");
        let broker = SessionControlBroker::register_session(&session_id, "openclaw", Vec::new())?;
        let endpoint = broker.endpoint().clone();
        drop(broker);

        let ack = GuardBrokerClient::send_hello(&endpoint, hello(&session_id))?;

        assert!(!ack.accepted);
        assert_eq!(ack.reason, "unknown session");
        Ok(())
    }

    #[test]
    fn broker_rejects_duplicate_session_registration() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("duplicate");
        let _broker = SessionControlBroker::register_session(&session_id, "openclaw", Vec::new())?;
        let error = match SessionControlBroker::register_session(&session_id, "codex", Vec::new()) {
            Ok(_registration) => return Err("duplicate session id should be rejected".into()),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SessionControlBrokerError::SessionAlreadyRegistered { .. }
        ));
        Ok(())
    }

    #[test]
    fn broker_returns_interception_decisions_after_guard_hello(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("decisions");
        let broker = SessionControlBroker::register_session(
            &session_id,
            "openclaw",
            vec![
                SessionInterceptionHandler::allow("allow-tool", "safe tool"),
                SessionInterceptionHandler::deny("deny-tool", "dangerous tool"),
                SessionInterceptionHandler::require_approval("approve-tool", "needs approval"),
                SessionInterceptionHandler::mediate(
                    "mediate-tool",
                    "route to replacement surface",
                    SessionInterceptionMediation::new("future_api", "api", "local://replacement")
                        .with_print_line("replacement ready")
                        .with_keepalive(false),
                ),
            ],
        )?;

        let allow = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("allow-tool"),
        )?;
        let deny = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("deny-tool"),
        )?;
        let approval = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("approve-tool"),
        )?;
        let mediate = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("mediate-tool"),
        )?;

        assert_eq!(allow.decision, DecisionKind::Allow as i32);
        assert_eq!(deny.decision, DecisionKind::Deny as i32);
        assert_eq!(approval.decision, DecisionKind::RequireApproval as i32);
        assert_eq!(mediate.decision, DecisionKind::Mediate as i32);
        assert_eq!(
            mediate
                .mediate
                .as_ref()
                .map(|decision| decision.replacement_surface.as_str()),
            Some("api")
        );
        Ok(())
    }

    #[test]
    fn broker_fails_closed_for_unknown_interception_handler(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("unknown-handler");
        let broker = SessionControlBroker::register_session(&session_id, "openclaw", Vec::new())?;

        let decision = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("missing-handler"),
        )?;

        assert_eq!(decision.decision, DecisionKind::Deny as i32);
        assert_eq!(decision.rule_id, "erebor-control-broker-unknown-handler");
        Ok(())
    }

    #[test]
    fn client_fails_closed_when_broker_is_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let directory = test_dir("unavailable")?;
        let endpoint =
            SessionControlBrokerEndpoint::unix(directory.join("missing.sock"), "token", 25);

        let error = GuardBrokerClient::send_hello(&endpoint, hello("missing-session"));

        assert!(error.is_err());

        fs::remove_dir_all(directory)?;
        Ok(())
    }

    fn hello(session_id: &str) -> GuardHello {
        GuardHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.to_owned(),
            actor_id: String::from("openclaw"),
            guard_pid: 42,
            runner_kind: String::from("linux_host"),
            platform: String::from("linux-x86_64"),
            capabilities: vec![String::from("interception_request")],
        }
    }

    fn request(handler_id: &str) -> InterceptionRequest {
        InterceptionRequest {
            request_id: 7,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Shim as i32,
            pid: 100,
            ppid: 99,
            executable: String::from("tool"),
            argv: vec![String::from("tool")],
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: handler_id.to_owned(),
            timestamp: String::from("unix:1"),
        }
    }

    fn session_id(name: &str) -> String {
        format!("session-test-{name}-{}", std::process::id())
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let directory = std::env::temp_dir().join(format!(
            "erebor-control-broker-{name}-{}",
            std::process::id()
        ));
        let _result = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }
}
