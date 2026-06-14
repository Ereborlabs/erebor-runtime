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
        Envelope, GuardHello, GuardHelloAck, Header, KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK,
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
}

pub struct SessionControlBroker;

impl SessionControlBroker {
    pub fn register_session(
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        shared_control_broker_server()?.register_session(session_id.into(), actor_id.into())
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
    ) -> Result<SessionControlRegistration, SessionControlBrokerError> {
        let token = read_control_token()?;
        let registration = SessionRegistration {
            token: token.clone(),
            broker_id: format!("{session_id}:{actor_id}"),
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

fn handle_hello_envelope(
    envelope: Envelope,
    sessions: &Mutex<HashMap<String, SessionRegistration>>,
) -> Result<Envelope, SessionControlBrokerError> {
    let mut broker_id = String::from("unregistered");
    let mut accepted = false;

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

    Envelope::wrap_message(
        envelope.message_id.saturating_add(1),
        envelope.message_id,
        KIND_GUARD_HELLO_ACK,
        &ack,
    )
    .map_err(SessionControlBrokerError::protocol)
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
        Envelope, GuardHello, GuardHelloAck, KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK,
    };

    use super::{
        envelope_with_token, handle_hello_envelope, read_frame_from_stream, write_frame_to_stream,
        ControlBrokerServer, SessionControlBrokerEndpoint, SessionControlBrokerError,
        SessionRegistration, CONTROL_SOCKET_NAME, DEFAULT_TIMEOUT_MS,
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
                    Ok((mut stream, _addr)) => {
                        let _result = stream.set_read_timeout(Some(timeout));
                        let _result = stream.set_write_timeout(Some(timeout));
                        let Ok(request_frame) = read_frame_from_stream(&mut stream) else {
                            continue;
                        };
                        let Ok(envelope) = request_frame.decode_payload::<Envelope>() else {
                            continue;
                        };
                        let Ok(response) = handle_hello_envelope(envelope, &worker_sessions) else {
                            continue;
                        };
                        let Ok(response_frame) = response.into_frame() else {
                            continue;
                        };
                        let _result = write_frame_to_stream(&mut stream, &response_frame);
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

    use erebor_runtime_ipc::v1::{GuardHello, GuardHelloAck};

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

    use erebor_runtime_ipc::v1::{GuardHello, PROTOCOL_VERSION};

    use super::{
        GuardBrokerClient, SessionControlBroker, SessionControlBrokerEndpoint,
        SessionControlBrokerError,
    };

    #[test]
    fn broker_accepts_guard_hello_with_control_token() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = session_id("accepts-hello");
        let broker = SessionControlBroker::register_session(&session_id, "openclaw")?;

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
        let broker = SessionControlBroker::register_session(&session_id, "openclaw")?;
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
        let first = SessionControlBroker::register_session(&first_session, "openclaw")?;
        let second = SessionControlBroker::register_session(&second_session, "codex")?;

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
        let broker = SessionControlBroker::register_session(&session_id, "openclaw")?;
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
        let _broker = SessionControlBroker::register_session(&session_id, "openclaw")?;
        let error = match SessionControlBroker::register_session(&session_id, "codex") {
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
