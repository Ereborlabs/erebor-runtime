use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use snafu::ResultExt;

use crate::error::{
    BrokerIoSnafu, BrokerServerNotStartedSnafu, BrokerSessionAlreadyRegisteredSnafu,
    BrokerStateLockSnafu, RuntimeInterceptionBrokerError,
};

use super::{
    constants::{DEFAULT_TIMEOUT_MS, RUNTIME_INTERCEPTION_SOCKET_NAME},
    endpoint::RuntimeInterceptionEndpoint,
    handlers::{SessionInterceptionRouter, SessionRegistration},
    platform::{
        Platform, RuntimeInterceptionBrokerPlatform, RuntimeInterceptionBrokerServerPlatform,
    },
    wire::hex_encode,
};

static RUNTIME_INTERCEPTION_BROKER_SERVER: Mutex<Option<Arc<RuntimeInterceptionBrokerServer>>> =
    Mutex::new(None);

#[derive(Clone, Debug)]
pub(super) struct RuntimeGuardServerConfig {
    pub(super) directory: Option<PathBuf>,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
    pub(super) directory_mode: u32,
    pub(super) socket_mode: u32,
    pub(super) limits: RuntimeGuardServerLimits,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RuntimeGuardServerLimits {
    pub(super) connection_limit: usize,
    pub(super) worker_count: usize,
    pub(super) connection_deadline: Duration,
}

impl Default for RuntimeGuardServerLimits {
    fn default() -> Self {
        Self {
            connection_limit: 16,
            worker_count: 4,
            connection_deadline: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl RuntimeGuardServerConfig {
    fn foreground() -> Self {
        Self {
            directory: None,
            owner_uid: rustix::process::geteuid().as_raw(),
            owner_gid: rustix::process::getegid().as_raw(),
            directory_mode: 0o700,
            socket_mode: 0o600,
            limits: RuntimeGuardServerLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct GuardPeerIdentity {
    pub(super) pid: Option<u32>,
    pub(super) uid: u32,
}

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
            None,
            false,
            None,
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

    pub(super) fn shutdown_server(self) {
        self.server.shutdown();
    }
}

impl Drop for SessionInterceptionRegistration {
    fn drop(&mut self) {
        self.server
            .unregister_session(&self.session_id, self.endpoint.token());
    }
}

pub(super) struct RuntimeInterceptionBrokerServer {
    platform: Mutex<Option<Box<dyn RuntimeInterceptionBrokerServerPlatform>>>,
    pub(super) sessions: Mutex<HashMap<String, SessionRegistration>>,
}

impl RuntimeInterceptionBrokerServer {
    pub(super) fn start(
        config: RuntimeGuardServerConfig,
    ) -> Result<Arc<Self>, RuntimeInterceptionBrokerError> {
        let server = Arc::new(Self {
            platform: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
        });
        let platform = <Platform as RuntimeInterceptionBrokerPlatform>::start_server(
            Arc::clone(&server),
            config,
        )?;
        *server
            .platform
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())? = Some(platform);
        Ok(server)
    }

    pub(super) fn register_session(
        self: &Arc<Self>,
        session_id: String,
        actor_id: String,
        router: SessionInterceptionRouter,
        expected_peer_uid: Option<u32>,
        require_peer_pid_match: bool,
        token: Option<String>,
    ) -> Result<SessionInterceptionRegistration, RuntimeInterceptionBrokerError> {
        self.authorize_session_guard()?;
        let endpoint_path = self.endpoint_path()?;
        let token = token.map_or_else(read_interception_token, Ok)?;
        let registration = SessionRegistration {
            token: token.clone(),
            broker_id: format!("{session_id}:{actor_id}"),
            expected_peer_uid,
            require_peer_pid_match,
            router,
        };
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_error| BrokerStateLockSnafu.build())?;
            if sessions.contains_key(&session_id) {
                return BrokerSessionAlreadyRegisteredSnafu { session_id }.fail();
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
            .map_err(|_error| BrokerStateLockSnafu.build())?;
        let Some(platform) = platform.as_ref() else {
            return BrokerServerNotStartedSnafu.fail();
        };
        Ok(platform.endpoint_path().to_path_buf())
    }

    fn authorize_session_guard(&self) -> Result<(), RuntimeInterceptionBrokerError> {
        let platform = self
            .platform
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())?;
        let Some(platform) = platform.as_ref() else {
            return BrokerServerNotStartedSnafu.fail();
        };
        platform.authorize_session_guard()
    }

    fn shutdown(&self) {
        if let Ok(mut platform) = self.platform.lock() {
            if let Some(platform) = platform.take() {
                platform.shutdown();
            }
        }
    }
}

impl Drop for RuntimeInterceptionBrokerServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn shared_runtime_interception_broker_server(
) -> Result<Arc<RuntimeInterceptionBrokerServer>, RuntimeInterceptionBrokerError> {
    let mut server = RUNTIME_INTERCEPTION_BROKER_SERVER
        .lock()
        .map_err(|_error| BrokerStateLockSnafu.build())?;
    if let Some(server) = server.as_ref() {
        return Ok(Arc::clone(server));
    }

    let started = RuntimeInterceptionBrokerServer::start(RuntimeGuardServerConfig::foreground())?;
    *server = Some(Arc::clone(&started));
    Ok(started)
}

fn read_interception_token() -> Result<String, RuntimeInterceptionBrokerError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .context(BrokerIoSnafu)?;

    Ok(hex_encode(&random))
}
