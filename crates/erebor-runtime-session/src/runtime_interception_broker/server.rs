use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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

pub(super) struct RuntimeInterceptionBrokerServer {
    platform: Mutex<Option<Box<dyn RuntimeInterceptionBrokerServerPlatform>>>,
    pub(super) sessions: Mutex<HashMap<String, SessionRegistration>>,
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
            .map_err(|_error| BrokerStateLockSnafu.build())? = Some(platform);
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

fn shared_runtime_interception_broker_server(
) -> Result<Arc<RuntimeInterceptionBrokerServer>, RuntimeInterceptionBrokerError> {
    let mut server = RUNTIME_INTERCEPTION_BROKER_SERVER
        .lock()
        .map_err(|_error| BrokerStateLockSnafu.build())?;
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
        .context(BrokerIoSnafu)?;

    Ok(hex_encode(&random))
}
