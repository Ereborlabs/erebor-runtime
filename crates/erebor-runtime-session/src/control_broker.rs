use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    BrowserCdpSurfaceConfig, ProcessMediationPrivateEndpointConfig,
    ProcessMediationPrivatePortStrategy, RunningSessionSurface, SessionSurfaceService,
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
use erebor_runtime_policy::PolicySet;
use thiserror::Error;
use tokio::runtime::Runtime;

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
    pub fn with_timeout_ms(&self, timeout_ms: u64) -> Self {
        Self {
            transport: self.transport.clone(),
            path: self.path.clone(),
            token: self.token.clone(),
            timeout_ms,
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
    mediators: SessionMediationRegistry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionHandler {
    id: String,
    decision: SessionInterceptionDecision,
    reason: String,
    mediate: Option<SessionMediationIntent>,
}

impl SessionInterceptionHandler {
    #[must_use]
    pub fn allow(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Allow,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn deny(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Deny,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn require_approval(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::RequireApproval,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn mediate(
        id: impl Into<String>,
        reason: impl Into<String>,
        intent: SessionMediationIntent,
    ) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Mediate,
            reason: reason.into(),
            mediate: Some(intent),
        }
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
pub struct SessionMediationIntent {
    kind: String,
    replacement_surface: String,
    lease_id: String,
    allowed_ports: Vec<u16>,
    private_endpoint: ProcessMediationPrivateEndpointConfig,
    emit_compatibility_line: bool,
    keepalive: bool,
}

impl SessionMediationIntent {
    #[must_use]
    pub fn new(kind: impl Into<String>, replacement_surface: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            lease_id: String::new(),
            allowed_ports: Vec::new(),
            private_endpoint: ProcessMediationPrivateEndpointConfig::default(),
            emit_compatibility_line: false,
            keepalive: false,
        }
    }

    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = lease_id.into();
        self
    }

    #[must_use]
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = ports;
        self
    }

    #[must_use]
    pub const fn with_private_endpoint(
        mut self,
        private_endpoint: ProcessMediationPrivateEndpointConfig,
    ) -> Self {
        self.private_endpoint = private_endpoint;
        self
    }

    #[must_use]
    pub const fn with_compatibility_line(mut self, enabled: bool) -> Self {
        self.emit_compatibility_line = enabled;
        self
    }

    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn replacement_surface(&self) -> &str {
        &self.replacement_surface
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub fn allowed_ports(&self) -> &[u16] {
        &self.allowed_ports
    }

    #[must_use]
    pub const fn private_endpoint(&self) -> &ProcessMediationPrivateEndpointConfig {
        &self.private_endpoint
    }

    #[must_use]
    pub const fn emit_compatibility_line(&self) -> bool {
        self.emit_compatibility_line
    }

    #[must_use]
    pub const fn keepalive(&self) -> bool {
        self.keepalive
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceMediationOutcome {
    kind: String,
    replacement_surface: String,
    endpoint: String,
    lease_id: String,
    print_line: String,
    keepalive: bool,
}

impl SurfaceMediationOutcome {
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

pub trait SurfaceMediationHandler: Send + Sync {
    fn surface(&self) -> &str;

    fn mediate(
        &self,
        request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String>;
}

#[derive(Clone, Default)]
pub struct SessionMediationRegistry {
    handlers: HashMap<String, Arc<dyn SurfaceMediationHandler>>,
}

impl SessionMediationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_handler(mut self, handler: impl SurfaceMediationHandler + 'static) -> Self {
        self.register_handler(handler);
        self
    }

    pub fn register_handler(&mut self, handler: impl SurfaceMediationHandler + 'static) {
        self.handlers
            .insert(handler.surface().to_owned(), Arc::new(handler));
    }

    fn mediate(
        &self,
        request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String> {
        let Some(handler) = self.handlers.get(intent.replacement_surface()) else {
            return Err(format!(
                "no mediation handler is registered for replacement surface `{}`",
                intent.replacement_surface()
            ));
        };
        handler.mediate(request, intent)
    }
}

impl fmt::Debug for SessionMediationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMediationRegistry")
            .field("surfaces", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Clone)]
pub struct BrowserCdpMediationHandler {
    mode: BrowserCdpMediationMode,
}

#[derive(Clone)]
enum BrowserCdpMediationMode {
    FixedEndpoint { endpoint: String },
    LazySurface(Arc<LazyBrowserCdpMediation>),
}

struct LazyBrowserCdpMediation {
    config_template: BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    runtime: Runtime,
    running: Mutex<HashMap<u16, RunningSessionSurface>>,
}

impl BrowserCdpMediationHandler {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            mode: BrowserCdpMediationMode::FixedEndpoint {
                endpoint: endpoint.into(),
            },
        }
    }

    pub fn lazy(
        config_template: BrowserCdpSurfaceConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
        audit_jsonl: Option<PathBuf>,
    ) -> Result<Self, io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        Ok(Self {
            mode: BrowserCdpMediationMode::LazySurface(Arc::new(LazyBrowserCdpMediation {
                config_template,
                policy_set,
                context,
                audit_jsonl,
                runtime,
                running: Mutex::new(HashMap::new()),
            })),
        })
    }
}

impl fmt::Debug for BrowserCdpMediationHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            BrowserCdpMediationMode::FixedEndpoint { endpoint } => formatter
                .debug_struct("BrowserCdpMediationHandler")
                .field("mode", &"fixed_endpoint")
                .field("endpoint", endpoint)
                .finish(),
            BrowserCdpMediationMode::LazySurface(_) => formatter
                .debug_struct("BrowserCdpMediationHandler")
                .field("mode", &"lazy_surface")
                .finish(),
        }
    }
}

impl SurfaceMediationHandler for BrowserCdpMediationHandler {
    fn surface(&self) -> &str {
        "browser_cdp"
    }

    fn mediate(
        &self,
        request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String> {
        let endpoint = match &self.mode {
            BrowserCdpMediationMode::FixedEndpoint { endpoint } => {
                let allowed_ports = effective_browser_cdp_allowed_ports(intent, endpoint)?;
                if let Some(requested_port) = remote_debugging_port(&request.argv) {
                    if !allowed_ports.contains(&requested_port) {
                        return Err(format!(
                            "requested remote debugging port {requested_port} is not allowed"
                        ));
                    }
                }
                endpoint.clone()
            }
            BrowserCdpMediationMode::LazySurface(lazy) => {
                let requested_port = remote_debugging_port(&request.argv).ok_or_else(|| {
                    String::from("managed browser CDP mediation requires --remote-debugging-port")
                })?;
                validate_requested_port(intent, requested_port)?;
                lazy.endpoint_for_requested_port(requested_port, intent)?
            }
        };

        Ok(
            SurfaceMediationOutcome::new(intent.kind(), self.surface(), &endpoint)
                .with_lease_id(intent.lease_id())
                .with_print_line(if intent.emit_compatibility_line() {
                    format!("DevTools listening on {}", devtools_browser_url(&endpoint))
                } else {
                    String::new()
                })
                .with_keepalive(intent.keepalive()),
        )
    }
}

impl LazyBrowserCdpMediation {
    fn endpoint_for_requested_port(
        &self,
        requested_port: u16,
        intent: &SessionMediationIntent,
    ) -> Result<String, String> {
        let mut running = self
            .running
            .lock()
            .map_err(|_| String::from("browser CDP mediation state is poisoned"))?;
        if let Some(surface) = running.get(&requested_port) {
            return Ok(surface.endpoint().to_owned());
        }

        let listen = SocketAddr::new(self.config_template.listen().ip(), requested_port);
        let private_remote_debugging_port =
            private_remote_debugging_port_for_request(intent, requested_port)?;
        let mut surface = BrowserCdpSurface::new(
            self.config_template
                .clone()
                .with_listen(listen)
                .with_browser_remote_debugging_port(private_remote_debugging_port),
            self.policy_set.clone(),
            self.context.clone(),
        );
        if let Some(audit_jsonl) = self.audit_jsonl.as_ref() {
            surface = surface.with_audit_jsonl(audit_jsonl.clone());
        }
        let (failures, _failure_rx) = mpsc::channel();
        let running_surface = Box::new(surface)
            .start(&self.runtime, failures)
            .map_err(|error| error.to_string())?;
        let endpoint = running_surface.endpoint().to_owned();
        running.insert(requested_port, running_surface);
        Ok(endpoint)
    }
}

pub struct SessionControlBroker;

impl SessionControlBroker {
    pub fn register_session(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        handlers: Vec<SessionInterceptionHandler>,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        Self::register_session_with_mediators(
            session_id,
            actor_id,
            handlers,
            SessionMediationRegistry::new(),
        )
    }

    pub fn register_session_with_mediators(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        handlers: Vec<SessionInterceptionHandler>,
        mediators: SessionMediationRegistry,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        shared_control_broker_server()?.register_session(
            session_id.into(),
            actor_id.into(),
            handlers,
            mediators,
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
    pub(crate) fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.endpoint = self.endpoint.with_timeout_ms(timeout_ms);
        self
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
        mediators: SessionMediationRegistry,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        let token = read_control_token()?;
        let registration = SessionRegistration {
            token: token.clone(),
            broker_id: format!("{session_id}:{actor_id}"),
            handlers: handlers
                .into_iter()
                .map(|handler| (handler.id.clone(), handler))
                .collect(),
            mediators,
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
    let (handler, mediators) = {
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
        (handler.clone(), registration.mediators.clone())
    };

    Ok(handler.decision_for_request(request, &mediators))
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
    fn decision_for_request(
        &self,
        request: &InterceptionRequest,
        mediators: &SessionMediationRegistry,
    ) -> InterceptionDecision {
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
                let Some(intent) = self.mediate.as_ref() else {
                    return deny_decision(
                        request.request_id,
                        &self.id,
                        "mediate handler has no replacement intent",
                    );
                };
                let outcome = match mediators.mediate(request, intent) {
                    Ok(outcome) => outcome,
                    Err(reason) => return deny_decision(request.request_id, &self.id, reason),
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
                        kind: outcome.kind,
                        replacement_surface: outcome.replacement_surface,
                        endpoint: outcome.endpoint,
                        lease_id: outcome.lease_id,
                        print_line: outcome.print_line,
                        keepalive: outcome.keepalive,
                    }),
                }
            }
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

fn effective_browser_cdp_allowed_ports(
    intent: &SessionMediationIntent,
    endpoint: &str,
) -> Result<Vec<u16>, String> {
    if !intent.allowed_ports().is_empty() {
        return Ok(intent.allowed_ports().to_vec());
    }
    Ok(vec![endpoint_port(endpoint).ok_or_else(|| {
        String::from("browser_cdp mediation endpoint does not include a parseable port")
    })?])
}

fn validate_requested_port(
    intent: &SessionMediationIntent,
    requested_port: u16,
) -> Result<(), String> {
    if !intent.allowed_ports().is_empty() && !intent.allowed_ports().contains(&requested_port) {
        return Err(format!(
            "requested remote debugging port {requested_port} is not allowed"
        ));
    }
    Ok(())
}

fn private_remote_debugging_port_for_request(
    intent: &SessionMediationIntent,
    requested_port: u16,
) -> Result<Option<u16>, String> {
    match intent.private_endpoint().port_strategy() {
        ProcessMediationPrivatePortStrategy::Ephemeral => Ok(None),
        ProcessMediationPrivatePortStrategy::RequestedPlusOffset => {
            let offset = intent.private_endpoint().port_offset();
            requested_port.checked_add(offset).map(Some).ok_or_else(|| {
                format!(
                    "requested remote debugging port {requested_port} plus private endpoint offset {offset} exceeds u16"
                )
            })
        }
    }
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let endpoint = endpoint
        .strip_prefix("ws://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let host = endpoint.split('/').next().unwrap_or(endpoint);
    host.rsplit_once(':')?.1.parse().ok()
}

fn devtools_browser_url(endpoint: &str) -> String {
    format!(
        "{}/devtools/browser/erebor-managed-browser",
        endpoint.trim_end_matches('/')
    )
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
    use std::{fs, net::TcpListener, path::PathBuf};

    use erebor_runtime_cdp::CdpSessionContext;
    use erebor_runtime_core::{
        ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
        RuntimeConfig,
    };
    use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
    use erebor_runtime_ipc::v1::{
        DecisionKind, GuardHello, InterceptionRequest, InterceptionSource, PROTOCOL_VERSION,
    };
    use erebor_runtime_policy::PolicySet;

    use super::{
        private_remote_debugging_port_for_request, BrowserCdpMediationHandler, GuardBrokerClient,
        SessionControlBroker, SessionControlBrokerEndpoint, SessionControlBrokerError,
        SessionInterceptionHandler, SessionMediationIntent, SessionMediationRegistry,
        SurfaceMediationHandler, SurfaceMediationOutcome,
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
        let broker = SessionControlBroker::register_session_with_mediators(
            &session_id,
            "openclaw",
            vec![
                SessionInterceptionHandler::allow("allow-tool", "safe tool"),
                SessionInterceptionHandler::deny("deny-tool", "dangerous tool"),
                SessionInterceptionHandler::require_approval("approve-tool", "needs approval"),
                SessionInterceptionHandler::mediate(
                    "mediate-tool",
                    "route to replacement surface",
                    SessionMediationIntent::new("future_api", "api")
                        .with_lease_id("api-lease")
                        .with_keepalive(false),
                ),
            ],
            SessionMediationRegistry::new().with_handler(TestMediationHandler {
                surface: String::from("api"),
                endpoint: String::from("local://replacement"),
            }),
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
    fn broker_fails_closed_when_mediation_surface_is_not_registered(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("missing-mediator");
        let broker = SessionControlBroker::register_session(
            &session_id,
            "openclaw",
            vec![SessionInterceptionHandler::mediate(
                "mediate-tool",
                "route to replacement surface",
                SessionMediationIntent::new("future_api", "api"),
            )],
        )?;

        let decision = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request("mediate-tool"),
        )?;

        assert_eq!(decision.decision, DecisionKind::Deny as i32);
        assert!(decision
            .reason
            .contains("no mediation handler is registered for replacement surface `api`"));
        Ok(())
    }

    #[test]
    fn browser_cdp_mediation_handler_owns_endpoint_and_port_validation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("browser-cdp-mediator");
        let broker = SessionControlBroker::register_session_with_mediators(
            &session_id,
            "openclaw",
            vec![SessionInterceptionHandler::mediate(
                "managed-browser-cdp",
                "route browser launch to governed CDP",
                SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
                    .with_allowed_ports(vec![9222])
                    .with_lease_id("browser-lease")
                    .with_compatibility_line(true)
                    .with_keepalive(true),
            )],
            SessionMediationRegistry::new()
                .with_handler(BrowserCdpMediationHandler::new("ws://127.0.0.1:9222/")),
        )?;

        let decision = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request_with_argv(
                "managed-browser-cdp",
                &[
                    String::from("google-chrome"),
                    String::from("--remote-debugging-port=9222"),
                ],
            ),
        )?;

        let mediation = decision
            .mediate
            .as_ref()
            .ok_or_else(|| std::io::Error::other("expected browser_cdp mediation decision"))?;
        assert_eq!(decision.decision, DecisionKind::Mediate as i32);
        assert_eq!(mediation.replacement_surface, "browser_cdp");
        assert_eq!(mediation.endpoint, "ws://127.0.0.1:9222/");
        assert_eq!(mediation.lease_id, "browser-lease");
        assert!(mediation
            .print_line
            .contains("ws://127.0.0.1:9222/devtools/browser/erebor-managed-browser"));
        assert!(mediation.keepalive);

        let denied = GuardBrokerClient::request_interception_decision(
            broker.endpoint(),
            hello(&session_id),
            request_with_argv(
                "managed-browser-cdp",
                &[
                    String::from("google-chrome"),
                    String::from("--remote-debugging-port=9333"),
                ],
            ),
        )?;

        assert_eq!(denied.decision, DecisionKind::Deny as i32);
        assert!(denied
            .reason
            .contains("requested remote debugging port 9333 is not allowed"));
        Ok(())
    }

    #[test]
    fn browser_cdp_lazy_mediation_starts_surface_on_requested_port(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let requested_port = free_tcp_port()?;
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0",
                  "browser_url": "ws://127.0.0.1:9/devtools/browser/fake"
                }
              }
            }
            "#,
        )?;
        let browser_cdp = config
            .surface_start_plan()?
            .browser_cdp()
            .ok_or_else(|| std::io::Error::other("missing browser CDP config"))?
            .clone();
        let handler = BrowserCdpMediationHandler::lazy(
            browser_cdp,
            PolicySet::default(),
            CdpSessionContext {
                session_id: SessionId::new("session-lazy-browser"),
                actor: ActorIdentity {
                    id: String::from("openclaw"),
                    kind: ActorKind::Agent,
                },
                timestamp: String::from("unix:1"),
            },
            None,
        )?;

        let outcome = handler.mediate(
            &request_with_argv(
                "managed-browser-cdp",
                &[
                    String::from("google-chrome"),
                    format!("--remote-debugging-port={requested_port}"),
                ],
            ),
            &SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
                .with_lease_id("browser-lease")
                .with_compatibility_line(true)
                .with_keepalive(true),
        )?;

        assert_eq!(
            outcome.endpoint,
            format!("ws://127.0.0.1:{requested_port}/")
        );
        assert!(outcome.print_line.contains(&format!(
            "ws://127.0.0.1:{requested_port}/devtools/browser/"
        )));
        Ok(())
    }

    #[test]
    fn private_browser_port_can_follow_requested_port_plus_offset() -> Result<(), String> {
        let intent = SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
            .with_private_endpoint(
                ProcessMediationPrivateEndpointLayerConfig {
                    port_strategy: ProcessMediationPrivatePortStrategy::RequestedPlusOffset,
                    port_offset: 1,
                }
                .into(),
            );

        assert_eq!(
            private_remote_debugging_port_for_request(&intent, 1000)?,
            Some(1001)
        );
        let overflow = private_remote_debugging_port_for_request(&intent, u16::MAX);
        let Err(error) = overflow else {
            return Err(String::from("overflow should fail closed"));
        };
        assert!(error.contains("exceeds u16"));

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
        request_with_argv(handler_id, &[String::from("tool")])
    }

    fn request_with_argv(handler_id: &str, argv: &[String]) -> InterceptionRequest {
        InterceptionRequest {
            request_id: 7,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Shim as i32,
            pid: 100,
            ppid: 99,
            executable: argv
                .first()
                .cloned()
                .unwrap_or_else(|| String::from("tool")),
            argv: argv.to_vec(),
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: handler_id.to_owned(),
            timestamp: String::from("unix:1"),
        }
    }

    struct TestMediationHandler {
        surface: String,
        endpoint: String,
    }

    impl SurfaceMediationHandler for TestMediationHandler {
        fn surface(&self) -> &str {
            &self.surface
        }

        fn mediate(
            &self,
            _request: &InterceptionRequest,
            intent: &SessionMediationIntent,
        ) -> Result<SurfaceMediationOutcome, String> {
            Ok(SurfaceMediationOutcome::new(
                intent.kind(),
                intent.replacement_surface(),
                &self.endpoint,
            )
            .with_lease_id(intent.lease_id())
            .with_keepalive(intent.keepalive()))
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

    fn free_tcp_port() -> Result<u16, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        Ok(listener.local_addr()?.port())
    }
}
