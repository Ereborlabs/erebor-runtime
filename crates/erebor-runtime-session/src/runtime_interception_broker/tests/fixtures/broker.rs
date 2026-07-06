use std::{fs, net::TcpListener, path::PathBuf};

use erebor_runtime_ipc::v1::{
    GuardHello, InterceptionDecision, InterceptionRequest, PROTOCOL_VERSION,
};

use super::super::super::{
    InterceptionBrokerClient, RuntimeInterceptionBroker, RuntimeInterceptionBrokerError,
    SessionInterceptionRegistration, SessionInterceptionRouter,
};

pub(crate) struct BrokerFixture {
    session_id: String,
}

impl BrokerFixture {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            session_id: format!("session-test-{name}-{}", std::process::id()),
        }
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn hello(&self) -> GuardHello {
        GuardHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            actor_id: String::from("openclaw"),
            guard_pid: 42,
            runner_kind: String::from("linux_host"),
            platform: String::from("linux-x86_64"),
            capabilities: vec![String::from("interception_request")],
        }
    }

    pub(crate) fn register(
        &self,
        router: SessionInterceptionRouter,
    ) -> Result<SessionInterceptionRegistration, RuntimeInterceptionBrokerError> {
        RuntimeInterceptionBroker::register_session(&self.session_id, "openclaw", router)
    }

    pub(crate) fn request_decision(
        &self,
        broker: &SessionInterceptionRegistration,
        request: InterceptionRequest,
    ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
        InterceptionBrokerClient::request_interception_decision(
            broker.endpoint(),
            self.hello(),
            request,
        )
    }
}

pub(crate) struct TempDirectoryFixture {
    path: PathBuf,
}

impl TempDirectoryFixture {
    pub(crate) fn new(name: &str) -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-interception-broker-{name}-{}",
            std::process::id()
        ));
        let _result = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDirectoryFixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct TcpPortFixture;

impl TcpPortFixture {
    pub(crate) fn free_local() -> Result<u16, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        Ok(listener.local_addr()?.port())
    }
}
