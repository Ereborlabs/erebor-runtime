use std::{path::Path, sync::Arc};

use erebor_runtime_ipc::v1::{
    GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
};

use super::{endpoint::RuntimeInterceptionEndpoint, server::RuntimeInterceptionBrokerServer};
use crate::error::RuntimeInterceptionBrokerError;

pub(super) trait RuntimeInterceptionBrokerPlatform {
    fn start_server(
        server: Arc<RuntimeInterceptionBrokerServer>,
    ) -> Result<Box<dyn RuntimeInterceptionBrokerServerPlatform>, RuntimeInterceptionBrokerError>;

    fn send_hello(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
    ) -> Result<GuardHelloAck, RuntimeInterceptionBrokerError>;

    fn request_interception_decision(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
        request: InterceptionRequest,
    ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError>;
}

pub(super) trait RuntimeInterceptionBrokerServerPlatform: Send + Sync {
    fn authorize_session_guard(&self) -> Result<(), RuntimeInterceptionBrokerError>;
    fn endpoint_path(&self) -> &Path;
    fn shutdown(self: Box<Self>);
}

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        os::unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use erebor_runtime_ipc::v1::{
        Envelope, GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
        KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, KIND_INTERCEPTION_DECISION,
        KIND_INTERCEPTION_REQUEST,
    };
    use rustix::{
        fs::chown,
        process::{geteuid, Gid, Uid},
    };
    use snafu::ResultExt;

    use super::{RuntimeInterceptionBrokerPlatform, RuntimeInterceptionBrokerServerPlatform};
    use crate::error::{
        BrokerIoSnafu, BrokerProtocolSnafu, BrokerRejectedHelloSnafu,
        BrokerSessionAccessConflictSnafu, BrokerStateLockSnafu,
    };
    use crate::runtime_interception_broker::{
        constants::{DEFAULT_TIMEOUT_MS, RUNTIME_INTERCEPTION_SOCKET_NAME},
        endpoint::RuntimeInterceptionEndpoint,
        server::RuntimeInterceptionBrokerServer,
        wire::{envelope_with_token, read_frame_from_stream, write_frame_to_stream},
    };
    use crate::RuntimeInterceptionBrokerError;

    pub(in crate::runtime_interception_broker) struct Platform;

    struct UnixRuntimeInterceptionBrokerServer {
        directory: PathBuf,
        endpoint_path: PathBuf,
        session_group: Mutex<Option<u32>>,
        shutdown: Arc<AtomicBool>,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl RuntimeInterceptionBrokerPlatform for Platform {
        fn start_server(
            server: Arc<RuntimeInterceptionBrokerServer>,
        ) -> Result<Box<dyn RuntimeInterceptionBrokerServerPlatform>, RuntimeInterceptionBrokerError>
        {
            let directory = std::env::temp_dir()
                .join("erebor-runtime")
                .join("interception")
                .join(std::process::id().to_string());
            fs::create_dir_all(&directory).context(BrokerIoSnafu)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .context(BrokerIoSnafu)?;
            let socket_path = directory.join(RUNTIME_INTERCEPTION_SOCKET_NAME);
            let _result = fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).context(BrokerIoSnafu)?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                .context(BrokerIoSnafu)?;
            listener.set_nonblocking(true).context(BrokerIoSnafu)?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let worker_shutdown = Arc::clone(&shutdown);
            let worker = thread::spawn(move || {
                let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
                while !worker_shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _addr)) => {
                            let server = Arc::clone(&server);
                            thread::spawn(move || {
                                let _result = stream.set_write_timeout(Some(timeout));
                                server.handle_stream(&mut stream);
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

            Ok(Box::new(UnixRuntimeInterceptionBrokerServer {
                directory,
                endpoint_path: socket_path,
                session_group: Mutex::new(None),
                shutdown,
                worker: Mutex::new(Some(worker)),
            }))
        }

        fn send_hello(
            endpoint: &RuntimeInterceptionEndpoint,
            hello: GuardHello,
        ) -> Result<GuardHelloAck, RuntimeInterceptionBrokerError> {
            let mut stream = UnixStream::connect(endpoint.path()).context(BrokerIoSnafu)?;
            stream
                .set_read_timeout(Some(endpoint.timeout()))
                .context(BrokerIoSnafu)?;
            stream
                .set_write_timeout(Some(endpoint.timeout()))
                .context(BrokerIoSnafu)?;
            let envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &hello)
                .context(BrokerProtocolSnafu)?;
            let request = envelope_with_token(envelope, endpoint.token());
            let request_frame = request.into_frame().context(BrokerProtocolSnafu)?;
            write_frame_to_stream(&mut stream, &request_frame)?;

            let response_frame = read_frame_from_stream(&mut stream)?;
            let response_envelope: Envelope = response_frame
                .decode_payload()
                .context(BrokerProtocolSnafu)?;
            response_envelope
                .decode_typed_payload(KIND_GUARD_HELLO_ACK)
                .context(BrokerProtocolSnafu)
        }

        fn request_interception_decision(
            endpoint: &RuntimeInterceptionEndpoint,
            hello: GuardHello,
            request: InterceptionRequest,
        ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
            let mut stream = UnixStream::connect(endpoint.path()).context(BrokerIoSnafu)?;
            stream
                .set_read_timeout(Some(endpoint.timeout()))
                .context(BrokerIoSnafu)?;
            stream
                .set_write_timeout(Some(endpoint.timeout()))
                .context(BrokerIoSnafu)?;

            let hello_envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &hello)
                .context(BrokerProtocolSnafu)?;
            let hello_request = envelope_with_token(hello_envelope, endpoint.token());
            write_frame_to_stream(
                &mut stream,
                &hello_request.into_frame().context(BrokerProtocolSnafu)?,
            )?;
            let hello_response_frame = read_frame_from_stream(&mut stream)?;
            let hello_response: Envelope = hello_response_frame
                .decode_payload()
                .context(BrokerProtocolSnafu)?;
            let ack: GuardHelloAck = hello_response
                .decode_typed_payload(KIND_GUARD_HELLO_ACK)
                .context(BrokerProtocolSnafu)?;
            if !ack.accepted {
                return BrokerRejectedHelloSnafu { reason: ack.reason }.fail();
            }

            let request_envelope =
                Envelope::wrap_message(2, 1, KIND_INTERCEPTION_REQUEST, &request)
                    .context(BrokerProtocolSnafu)?;
            write_frame_to_stream(
                &mut stream,
                &request_envelope.into_frame().context(BrokerProtocolSnafu)?,
            )?;
            let response_frame = read_frame_from_stream(&mut stream)?;
            let response_envelope: Envelope = response_frame
                .decode_payload()
                .context(BrokerProtocolSnafu)?;
            response_envelope
                .decode_typed_payload(KIND_INTERCEPTION_DECISION)
                .context(BrokerProtocolSnafu)
        }
    }

    impl RuntimeInterceptionBrokerServerPlatform for UnixRuntimeInterceptionBrokerServer {
        fn authorize_session_guard(&self) -> Result<(), RuntimeInterceptionBrokerError> {
            let Some(requested_group) = session_guard_group_from_environment() else {
                return Ok(());
            };

            let mut session_group = self
                .session_group
                .lock()
                .map_err(|_error| BrokerStateLockSnafu.build())?;
            if let Some(expected_group) = *session_group {
                if expected_group == requested_group {
                    return Ok(());
                }
                return BrokerSessionAccessConflictSnafu {
                    expected_group,
                    requested_group,
                }
                .fail();
            }

            let group = Gid::from_raw(requested_group);
            chown(&self.directory, Some(Uid::ROOT), Some(group))
                .map_err(std::io::Error::from)
                .context(BrokerIoSnafu)?;
            chown(&self.endpoint_path, Some(Uid::ROOT), Some(group))
                .map_err(std::io::Error::from)
                .context(BrokerIoSnafu)?;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o710))
                .context(BrokerIoSnafu)?;
            fs::set_permissions(&self.endpoint_path, fs::Permissions::from_mode(0o620))
                .context(BrokerIoSnafu)?;
            *session_group = Some(requested_group);
            Ok(())
        }

        fn endpoint_path(&self) -> &Path {
            &self.endpoint_path
        }

        fn shutdown(self: Box<Self>) {
            self.shutdown.store(true, Ordering::SeqCst);
            let _result = UnixStream::connect(&self.endpoint_path);
            if let Ok(mut worker) = self.worker.lock() {
                if let Some(worker) = worker.take() {
                    let _result = worker.join();
                }
            }
            let _result = fs::remove_file(&self.endpoint_path);
        }
    }

    fn session_guard_group_from_environment() -> Option<u32> {
        session_guard_group(
            geteuid().is_root(),
            std::env::var("EREBOR_SESSION_UID")
                .ok()
                .or_else(|| std::env::var("SUDO_UID").ok()),
            std::env::var("EREBOR_SESSION_GID")
                .ok()
                .or_else(|| std::env::var("SUDO_GID").ok()),
        )
    }

    fn session_guard_group(
        runs_as_root: bool,
        session_uid: Option<String>,
        session_gid: Option<String>,
    ) -> Option<u32> {
        if !runs_as_root {
            return None;
        }
        let session_uid = session_uid?.parse::<u32>().ok()?;
        let session_gid = session_gid?.parse::<u32>().ok()?;
        (session_uid != 0).then_some(session_gid)
    }

    #[cfg(test)]
    mod tests {
        use super::session_guard_group;

        #[test]
        fn root_broker_grants_only_the_dropped_session_group() {
            assert_eq!(
                session_guard_group(true, Some(String::from("1000")), Some(String::from("1001"))),
                Some(1001)
            );
            assert_eq!(
                session_guard_group(
                    false,
                    Some(String::from("1000")),
                    Some(String::from("1001"))
                ),
                None
            );
            assert_eq!(
                session_guard_group(true, Some(String::from("0")), Some(String::from("0"))),
                None
            );
            assert_eq!(
                session_guard_group(
                    true,
                    Some(String::from("invalid")),
                    Some(String::from("1001"))
                ),
                None
            );
        }
    }
}

#[cfg(unix)]
pub(super) use unix::Platform;

#[cfg(windows)]
mod windows {
    use std::sync::Arc;

    use erebor_runtime_ipc::v1::{
        GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
    };

    use super::{RuntimeInterceptionBrokerPlatform, RuntimeInterceptionBrokerServerPlatform};
    use crate::error::{BrokerUnsupportedTransportSnafu, RuntimeInterceptionBrokerError};
    use crate::runtime_interception_broker::{
        endpoint::RuntimeInterceptionEndpoint, server::RuntimeInterceptionBrokerServer,
    };

    pub(in crate::runtime_interception_broker) struct Platform;

    impl RuntimeInterceptionBrokerPlatform for Platform {
        fn start_server(
            _server: Arc<RuntimeInterceptionBrokerServer>,
        ) -> Result<Box<dyn RuntimeInterceptionBrokerServerPlatform>, RuntimeInterceptionBrokerError>
        {
            unsupported()
        }

        fn send_hello(
            _endpoint: &RuntimeInterceptionEndpoint,
            _hello: GuardHello,
        ) -> Result<GuardHelloAck, RuntimeInterceptionBrokerError> {
            unsupported()
        }

        fn request_interception_decision(
            _endpoint: &RuntimeInterceptionEndpoint,
            _hello: GuardHello,
            _request: InterceptionRequest,
        ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
            unsupported()
        }
    }

    fn unsupported<T>() -> Result<T, RuntimeInterceptionBrokerError> {
        BrokerUnsupportedTransportSnafu {
            transport: String::from("windows-named-pipe"),
        }
        .fail()
    }
}

#[cfg(windows)]
pub(super) use windows::Platform;
