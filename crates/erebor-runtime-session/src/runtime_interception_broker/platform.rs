use std::{path::Path, sync::Arc};

use erebor_runtime_ipc::v1::{
    GuardHello, GuardHelloAck, InterceptionDecision, InterceptionRequest,
};

use super::{
    endpoint::RuntimeInterceptionEndpoint,
    server::{RuntimeGuardServerConfig, RuntimeInterceptionBrokerServer},
};
use crate::error::RuntimeInterceptionBrokerError;

pub(super) trait RuntimeInterceptionBrokerPlatform {
    fn start_server(
        server: Arc<RuntimeInterceptionBrokerServer>,
        config: RuntimeGuardServerConfig,
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
        collections::HashMap,
        fs,
        os::unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use super::{RuntimeInterceptionBrokerPlatform, RuntimeInterceptionBrokerServerPlatform};
    use crate::error::{
        BrokerIoSnafu, BrokerProtocolSnafu, BrokerRejectedHelloSnafu,
        BrokerSessionAccessConflictSnafu, BrokerStateLockSnafu,
    };
    use crate::runtime_interception_broker::{
        constants::RUNTIME_INTERCEPTION_SOCKET_NAME,
        endpoint::RuntimeInterceptionEndpoint,
        server::{
            GuardPeerIdentity, RuntimeGuardServerConfig, RuntimeGuardSocketAccess,
            RuntimeInterceptionBrokerServer,
        },
        wire::{envelope_with_token, read_frame_from_stream, write_frame_to_stream},
    };
    use crate::RuntimeInterceptionBrokerError;
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

    pub(in crate::runtime_interception_broker) struct Platform;

    struct UnixRuntimeInterceptionBrokerServer {
        directory: PathBuf,
        endpoint_path: PathBuf,
        session_group: Mutex<Option<u32>>,
        socket_access: RuntimeGuardSocketAccess,
        shutdown: Arc<AtomicBool>,
        acceptor: Mutex<Option<JoinHandle<()>>>,
        workers: Mutex<Vec<JoinHandle<()>>>,
        owns_directory: bool,
    }

    #[derive(Clone)]
    struct GuardConnectionCapacity {
        state: Arc<Mutex<GuardConnectionCapacityState>>,
        global_limit: usize,
        per_uid_limit: usize,
    }

    struct GuardConnectionPermit {
        state: Arc<Mutex<GuardConnectionCapacityState>>,
        uid: Option<u32>,
    }

    struct GuardConnection {
        stream: UnixStream,
        peer: Option<GuardPeerIdentity>,
        _permit: GuardConnectionPermit,
    }

    #[derive(Default)]
    struct GuardConnectionCapacityState {
        active: usize,
        active_by_uid: HashMap<u32, usize>,
    }

    impl GuardConnectionCapacity {
        fn new(global_limit: usize, per_uid_limit: usize) -> Self {
            Self {
                state: Arc::new(Mutex::new(GuardConnectionCapacityState::default())),
                global_limit,
                per_uid_limit,
            }
        }

        fn try_acquire(&self, peer: Option<GuardPeerIdentity>) -> Option<GuardConnectionPermit> {
            let uid = peer.map(|identity| identity.uid);
            let mut state = self.state.lock().ok()?;
            if state.active >= self.global_limit
                || uid.is_some_and(|uid| {
                    state.active_by_uid.get(&uid).copied().unwrap_or(0) >= self.per_uid_limit
                })
            {
                return None;
            }
            state.active += 1;
            if let Some(uid) = uid {
                *state.active_by_uid.entry(uid).or_default() += 1;
            }
            drop(state);
            Some(GuardConnectionPermit {
                state: Arc::clone(&self.state),
                uid,
            })
        }
    }

    impl Drop for GuardConnectionPermit {
        fn drop(&mut self) {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.active = state.active.saturating_sub(1);
            if let Some(uid) = self.uid {
                if let Some(active) = state.active_by_uid.get_mut(&uid) {
                    *active = active.saturating_sub(1);
                    if *active == 0 {
                        state.active_by_uid.remove(&uid);
                    }
                }
            }
        }
    }

    impl RuntimeInterceptionBrokerPlatform for Platform {
        fn start_server(
            server: Arc<RuntimeInterceptionBrokerServer>,
            config: RuntimeGuardServerConfig,
        ) -> Result<Box<dyn RuntimeInterceptionBrokerServerPlatform>, RuntimeInterceptionBrokerError>
        {
            let owns_directory = config.directory.is_none();
            let directory = config.directory.unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("erebor-runtime")
                    .join("interception")
                    .join(std::process::id().to_string())
            });
            fs::create_dir_all(&directory).context(BrokerIoSnafu)?;
            fs::set_permissions(
                &directory,
                fs::Permissions::from_mode(config.directory_mode),
            )
            .context(BrokerIoSnafu)?;
            chown(
                &directory,
                Some(Uid::from_raw(config.owner_uid)),
                Some(Gid::from_raw(config.owner_gid)),
            )
            .map_err(std::io::Error::from)
            .context(BrokerIoSnafu)?;
            let socket_path = directory.join(RUNTIME_INTERCEPTION_SOCKET_NAME);
            let _result = fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).context(BrokerIoSnafu)?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(config.socket_mode))
                .context(BrokerIoSnafu)?;
            chown(
                &socket_path,
                Some(Uid::from_raw(config.owner_uid)),
                Some(Gid::from_raw(config.owner_gid)),
            )
            .map_err(std::io::Error::from)
            .context(BrokerIoSnafu)?;
            listener.set_nonblocking(true).context(BrokerIoSnafu)?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let deadline = config.limits.connection_deadline;
            let capacity = GuardConnectionCapacity::new(
                config.limits.connection_limit,
                config.limits.per_uid_connection_limit,
            );
            let (sender, receiver) = mpsc::sync_channel(config.limits.connection_limit);
            let receiver = Arc::new(Mutex::new(receiver));
            let mut workers = Vec::with_capacity(config.limits.worker_count);
            for _ in 0..config.limits.worker_count {
                let worker_shutdown = Arc::clone(&shutdown);
                let worker_receiver = Arc::clone(&receiver);
                let weak_server = Arc::downgrade(&server);
                workers.push(thread::spawn(move || loop {
                    let connection = match worker_receiver.lock() {
                        Ok(receiver) => receiver.recv_timeout(Duration::from_millis(1)),
                        Err(_error) => return,
                    };
                    match connection {
                        Ok(GuardConnection {
                            mut stream,
                            peer,
                            _permit,
                        }) => {
                            let _result = stream.set_read_timeout(Some(deadline));
                            let _result = stream.set_write_timeout(Some(deadline));
                            let Some(server) = weak_server.upgrade() else {
                                return;
                            };
                            server.handle_stream(&mut stream, peer);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout)
                            if worker_shutdown.load(Ordering::SeqCst) =>
                        {
                            return;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }));
            }
            let acceptor_shutdown = Arc::clone(&shutdown);
            let acceptor = thread::spawn(move || {
                while !acceptor_shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _address)) => {
                            let peer = rustix::net::sockopt::socket_peercred(&stream).ok().map(
                                |credentials| GuardPeerIdentity {
                                    pid: Some(credentials.pid.as_raw_nonzero().get() as u32),
                                    uid: credentials.uid.as_raw(),
                                },
                            );
                            let Some(permit) = capacity.try_acquire(peer) else {
                                continue;
                            };
                            let _result = sender.try_send(GuardConnection {
                                stream,
                                peer,
                                _permit: permit,
                            });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_error) => thread::sleep(Duration::from_millis(1)),
                    }
                }
            });

            Ok(Box::new(UnixRuntimeInterceptionBrokerServer {
                directory,
                endpoint_path: socket_path,
                session_group: Mutex::new(None),
                socket_access: config.socket_access,
                shutdown,
                acceptor: Mutex::new(Some(acceptor)),
                workers: Mutex::new(workers),
                owns_directory,
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
            if self.socket_access == RuntimeGuardSocketAccess::ProjectedShared {
                return Ok(());
            }
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
            if let Ok(mut acceptor) = self.acceptor.lock() {
                if let Some(acceptor) = acceptor.take() {
                    let _result = acceptor.join();
                }
            }
            if let Ok(mut workers) = self.workers.lock() {
                for worker in workers.drain(..) {
                    let _result = worker.join();
                }
            }
            let _result = fs::remove_file(&self.endpoint_path);
            if self.owns_directory {
                let _result = fs::remove_dir(&self.directory);
            }
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
        use super::{session_guard_group, GuardConnectionCapacity, GuardPeerIdentity};

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

        #[test]
        fn shared_guard_capacity_enforces_global_and_per_uid_limits() -> Result<(), &'static str> {
            let capacity = GuardConnectionCapacity::new(3, 1);
            let first = capacity
                .try_acquire(Some(peer(1001)))
                .ok_or("first UID should have capacity")?;
            assert!(capacity.try_acquire(Some(peer(1001))).is_none());
            let _second = capacity
                .try_acquire(Some(peer(1002)))
                .ok_or("second UID should have independent capacity")?;
            let _third = capacity
                .try_acquire(Some(peer(1003)))
                .ok_or("third UID should reach the global limit")?;
            assert!(capacity.try_acquire(Some(peer(1004))).is_none());

            drop(first);
            assert!(capacity.try_acquire(Some(peer(1001))).is_some());
            Ok(())
        }

        const fn peer(uid: u32) -> GuardPeerIdentity {
            GuardPeerIdentity { pid: Some(1), uid }
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
        endpoint::RuntimeInterceptionEndpoint,
        server::{RuntimeGuardServerConfig, RuntimeInterceptionBrokerServer},
    };

    pub(in crate::runtime_interception_broker) struct Platform;

    impl RuntimeInterceptionBrokerPlatform for Platform {
        fn start_server(
            _server: Arc<RuntimeInterceptionBrokerServer>,
            _config: RuntimeGuardServerConfig,
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
