use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rustix::process::{getegid, geteuid};
use snafu::ResultExt;

use crate::error::{
    BrokerIoSnafu, BrokerSessionAlreadyRegisteredSnafu, BrokerStateLockSnafu,
    RuntimeInterceptionBrokerError,
};

use super::{
    endpoint::RuntimeInterceptionEndpoint,
    handlers::SessionInterceptionRouter,
    server::{
        RuntimeGuardServerConfig, RuntimeGuardServerLimits, RuntimeGuardSocketAccess,
        RuntimeInterceptionBrokerServer, SessionInterceptionRegistration,
    },
};

pub struct RuntimeGuardService {
    server: Arc<RuntimeInterceptionBrokerServer>,
    sessions: Mutex<HashMap<(u32, String), SessionInterceptionRegistration>>,
}

impl RuntimeGuardService {
    pub fn new(runtime_root: impl Into<PathBuf>) -> Result<Self, RuntimeInterceptionBrokerError> {
        Self::new_with_limits(runtime_root, RuntimeGuardServerLimits::default())
    }

    fn new_with_limits(
        runtime_root: impl Into<PathBuf>,
        limits: RuntimeGuardServerLimits,
    ) -> Result<Self, RuntimeInterceptionBrokerError> {
        let server = RuntimeInterceptionBrokerServer::start(RuntimeGuardServerConfig {
            directory: Some(runtime_root.into()),
            owner_uid: geteuid().as_raw(),
            owner_gid: getegid().as_raw(),
            directory_mode: 0o700,
            socket_mode: 0o666,
            limits,
            socket_access: RuntimeGuardSocketAccess::ProjectedShared,
        })?;
        Ok(Self {
            server,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn start_session(
        &self,
        uid: u32,
        session_id: &str,
        actor_id: &str,
        router: SessionInterceptionRouter,
    ) -> Result<RuntimeInterceptionEndpoint, RuntimeInterceptionBrokerError> {
        self.start_session_with_token(uid, session_id, actor_id, router, None)
    }

    pub fn start_session_with_token(
        &self,
        uid: u32,
        session_id: &str,
        actor_id: &str,
        router: SessionInterceptionRouter,
        token: Option<String>,
    ) -> Result<RuntimeInterceptionEndpoint, RuntimeInterceptionBrokerError> {
        validate_session_id(session_id)?;
        if token.as_ref().is_some_and(|value| {
            value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "runtime guard token is malformed",
            ))
            .context(BrokerIoSnafu);
        }
        let key = (uid, session_id.to_owned());
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())?;
        if sessions.contains_key(&key) {
            return BrokerSessionAlreadyRegisteredSnafu {
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        let registration = self.server.register_session(
            session_id.to_owned(),
            actor_id.to_owned(),
            router,
            Some(uid),
            true,
            token,
        )?;
        let endpoint = registration.endpoint().clone();
        sessions.insert(key, registration);
        Ok(endpoint)
    }

    pub fn stop_session(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<(), RuntimeInterceptionBrokerError> {
        validate_session_id(session_id)?;
        let registration = self
            .sessions
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())?
            .remove(&(uid, session_id.to_owned()));
        drop(registration);
        Ok(())
    }

    #[cfg(test)]
    fn registered_session_count(&self) -> usize {
        self.server.registered_session_count()
    }

    #[cfg(test)]
    fn worker_count(&self) -> usize {
        self.server.worker_count()
    }
}

impl Drop for RuntimeGuardService {
    fn drop(&mut self) {
        self.server.shutdown();
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.clear();
        }
    }
}

fn validate_session_id(session_id: &str) -> Result<(), RuntimeInterceptionBrokerError> {
    if !session_id.is_empty()
        && session_id.len() <= 128
        && session_id != "."
        && session_id != ".."
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session id is not a safe path component",
        ))
        .context(BrokerIoSnafu)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        sync::{mpsc, Arc, Barrier},
        thread,
        time::{Duration, Instant},
    };

    use erebor_runtime_core::{
        ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SurfaceInterceptionDecision,
    };
    use erebor_runtime_ipc::v1::{
        DaemonStatusRequest, Envelope, GuardHello, GuardHelloAck, InterceptionOperation,
        InterceptionRequest, InterceptionSource, ProcessExecOperation, KIND_DAEMON_STATUS_REQUEST,
        KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, PROTOCOL_VERSION,
    };
    use rustix::process::geteuid;
    use tempfile::TempDir;

    use crate::{
        runtime_interception_broker::{
            server::RuntimeGuardServerLimits,
            wire::{envelope_with_token, read_frame_from_stream, write_frame_to_stream},
        },
        InterceptionBrokerClient, RuntimeGuardService, SessionInterceptionRouter,
    };

    #[test]
    fn shared_service_routes_many_sessions_with_one_listener_and_fixed_workers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new_with_limits(
            temporary.path(),
            RuntimeGuardServerLimits {
                connection_limit: 128,
                per_uid_connection_limit: 128,
                per_session_connection_limit: 4,
                worker_count: 2,
                connection_deadline: Duration::from_millis(100),
            },
        )?;
        let uid = geteuid().as_raw();
        let mut endpoints = Vec::new();
        for index in 0..100 {
            endpoints.push(service.start_session(
                uid,
                &format!("session-guard-{index}"),
                "agent",
                SessionInterceptionRouter::new(),
            )?);
        }
        let endpoint = &endpoints[0];
        let ack = InterceptionBrokerClient::send_hello(
            endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-guard-0"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;

        assert!(ack.accepted);
        assert!(endpoints
            .iter()
            .all(|candidate| candidate.path() == endpoint.path()));
        assert_eq!(service.registered_session_count(), 100);
        assert_eq!(service.worker_count(), 2);
        assert_eq!(
            endpoint.path(),
            temporary.path().join("runtime-interception.sock")
        );
        assert_eq!(
            fs::metadata(endpoint.path())?.permissions().mode() & 0o777,
            0o666
        );
        assert_eq!(
            fs::metadata(temporary.path())?.permissions().mode() & 0o777,
            0o700
        );
        let crossed_endpoint =
            crate::RuntimeInterceptionEndpoint::unix(endpoint.path(), endpoints[99].token(), 100);
        let crossed = InterceptionBrokerClient::send_hello(
            &crossed_endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-guard-0"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;
        assert!(!crossed.accepted);
        assert_eq!(crossed.reason, "invalid interception token");

        service.stop_session(uid, "session-guard-0")?;
        assert!(fs::exists(endpoint.path())?);
        assert_eq!(service.registered_session_count(), 99);
        let stopped = InterceptionBrokerClient::send_hello(
            endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-guard-0"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;
        assert!(!stopped.accepted);
        assert_eq!(stopped.reason, "unknown session");

        let last = InterceptionBrokerClient::send_hello(
            &endpoints[99],
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-guard-99"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;
        assert!(last.accepted);
        Ok(())
    }

    #[test]
    fn runtime_guard_socket_rejects_daemon_control_messages_before_dispatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new(temporary.path())?;
        let uid = geteuid().as_raw();
        let endpoint = service.start_session(
            uid,
            "session-cross-service",
            "agent",
            SessionInterceptionRouter::new(),
        )?;
        let mut stream = UnixStream::connect(endpoint.path())?;
        let request =
            Envelope::wrap_message(1, 0, KIND_DAEMON_STATUS_REQUEST, &DaemonStatusRequest {})?;
        let request = envelope_with_token(request, endpoint.token());
        write_frame_to_stream(&mut stream, &request.into_frame()?)?;

        let rejection: Envelope = read_frame_from_stream(&mut stream)?.decode_payload()?;
        assert_eq!(rejection.message_kind, KIND_GUARD_HELLO_ACK);
        let rejection: GuardHelloAck = rejection.decode_typed_payload(KIND_GUARD_HELLO_ACK)?;
        assert!(!rejection.accepted);
        assert!(rejection.reason.contains(KIND_DAEMON_STATUS_REQUEST));
        service.stop_session(uid, "session-cross-service")?;
        Ok(())
    }

    #[test]
    fn runtime_guard_limits_idle_connections_and_drains_on_stop(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new_with_limits(
            temporary.path(),
            RuntimeGuardServerLimits {
                connection_limit: 1,
                per_uid_connection_limit: 1,
                per_session_connection_limit: 1,
                worker_count: 1,
                connection_deadline: Duration::from_millis(100),
            },
        )?;
        let uid = geteuid().as_raw();
        let endpoint = service.start_session(
            uid,
            "session-connection-limit",
            "agent",
            SessionInterceptionRouter::new(),
        )?;
        let _idle = UnixStream::connect(endpoint.path())?;
        thread::sleep(Duration::from_millis(10));

        assert!(InterceptionBrokerClient::send_hello(
            &endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-connection-limit"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )
        .is_err());

        thread::sleep(Duration::from_millis(120));
        let ack = InterceptionBrokerClient::send_hello(
            &endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-connection-limit"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;
        assert!(ack.accepted);

        let _idle = UnixStream::connect(endpoint.path())?;
        thread::sleep(Duration::from_millis(10));
        let socket_path = endpoint.path().to_path_buf();
        let stopped_at = Instant::now();
        drop(service);
        assert!(stopped_at.elapsed() < Duration::from_secs(1));
        assert!(!socket_path.exists());
        Ok(())
    }

    #[test]
    fn shared_service_enforces_each_session_connection_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new_with_limits(
            temporary.path(),
            RuntimeGuardServerLimits {
                connection_limit: 8,
                per_uid_connection_limit: 8,
                per_session_connection_limit: 1,
                worker_count: 2,
                connection_deadline: Duration::from_millis(250),
            },
        )?;
        let uid = geteuid().as_raw();
        let endpoint = service.start_session(
            uid,
            "session-logical-limit",
            "agent",
            SessionInterceptionRouter::new(),
        )?;
        let hello = GuardHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: String::from("session-logical-limit"),
            actor_id: String::from("agent"),
            guard_pid: i64::from(std::process::id()),
            runner_kind: String::from("linux-host"),
            platform: String::from("linux-x86_64"),
            capabilities: Vec::new(),
        };
        let (first, first_ack) = authenticated_connection(&endpoint, &hello)?;
        assert!(first_ack.accepted);

        let second_ack = InterceptionBrokerClient::send_hello(&endpoint, hello.clone())?;
        assert!(!second_ack.accepted);
        assert_eq!(second_ack.reason, "session connection limit reached");

        drop(first);
        thread::sleep(Duration::from_millis(10));
        let third_ack = InterceptionBrokerClient::send_hello(&endpoint, hello)?;
        assert!(third_ack.accepted);
        Ok(())
    }

    #[test]
    fn slow_session_dispatch_does_not_lock_other_session_registration(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new_with_limits(
            temporary.path(),
            RuntimeGuardServerLimits {
                connection_limit: 8,
                per_uid_connection_limit: 8,
                per_session_connection_limit: 2,
                worker_count: 2,
                connection_deadline: Duration::from_millis(500),
            },
        )?;
        let uid = geteuid().as_raw();
        let (entered_tx, entered_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let first_endpoint = service.start_session(
            uid,
            "session-slow-dispatch",
            "agent",
            SessionInterceptionRouter::new().with_process_exec_handler(
                BlockingProcessExecHandler {
                    entered: entered_tx,
                    release: Arc::clone(&release),
                },
            ),
        )?;
        let second_endpoint = service.start_session(
            uid,
            "session-independent-dispatch",
            "agent",
            SessionInterceptionRouter::new(),
        )?;
        let first = thread::spawn(move || {
            InterceptionBrokerClient::request_interception_decision(
                &first_endpoint,
                hello("session-slow-dispatch"),
                process_request(),
            )
        });
        entered_rx.recv_timeout(Duration::from_millis(250))?;

        let (second_tx, second_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            let result = InterceptionBrokerClient::send_hello(
                &second_endpoint,
                hello("session-independent-dispatch"),
            );
            let _result = second_tx.send(result);
        });
        let second_before_release = second_rx.recv_timeout(Duration::from_millis(100));
        release.wait();
        first
            .join()
            .map_err(|_| std::io::Error::other("slow dispatch thread panicked"))??;
        second
            .join()
            .map_err(|_| std::io::Error::other("independent dispatch thread panicked"))?;

        let ack = second_before_release.map_err(|_| {
            std::io::Error::other("another session was blocked by the slow session dispatcher")
        })??;
        assert!(ack.accepted);
        Ok(())
    }

    struct BlockingProcessExecHandler {
        entered: mpsc::Sender<()>,
        release: Arc<Barrier>,
    }

    impl ProcessExecSurfaceHandler for BlockingProcessExecHandler {
        fn surface(&self) -> &str {
            "terminal"
        }

        fn decide_process_exec(
            &self,
            _request: &ProcessExecInterceptionRequest<'_>,
        ) -> SurfaceInterceptionDecision {
            let _result = self.entered.send(());
            self.release.wait();
            SurfaceInterceptionDecision::allow("slow-handler", "slow handler released")
        }
    }

    fn hello(session_id: &str) -> GuardHello {
        GuardHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.to_owned(),
            actor_id: String::from("agent"),
            guard_pid: i64::from(std::process::id()),
            runner_kind: String::from("linux-host"),
            platform: String::from("linux-x86_64"),
            capabilities: Vec::new(),
        }
    }

    fn process_request() -> InterceptionRequest {
        InterceptionRequest {
            request_id: 1,
            actor_id: String::from("agent"),
            source: InterceptionSource::Shim as i32,
            pid: 100,
            ppid: 99,
            executable: String::from("slow-tool"),
            argv: vec![String::from("slow-tool")],
            cwd: String::from("/workspace"),
            selected_env: Vec::new(),
            requested_endpoint: None,
            matched_handler_id: String::from("slow-handler"),
            timestamp: String::from("unix:1"),
            operation: InterceptionOperation::ProcessExec as i32,
            process_exec: Some(ProcessExecOperation {
                executable: String::from("slow-tool"),
                argv: vec![String::from("slow-tool")],
                requested_endpoint: None,
                matched_handler_id: String::from("slow-handler"),
            }),
            file: None,
            socket: None,
        }
    }

    fn authenticated_connection(
        endpoint: &crate::RuntimeInterceptionEndpoint,
        hello: &GuardHello,
    ) -> Result<(UnixStream, GuardHelloAck), Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(endpoint.path())?;
        let request = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, hello)?;
        let request = envelope_with_token(request, endpoint.token());
        write_frame_to_stream(&mut stream, &request.into_frame()?)?;
        let response: Envelope = read_frame_from_stream(&mut stream)?.decode_payload()?;
        let ack = response.decode_typed_payload(KIND_GUARD_HELLO_ACK)?;
        Ok((stream, ack))
    }
}
