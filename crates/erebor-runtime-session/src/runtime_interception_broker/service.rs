use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};

use rustix::{
    fs::chown,
    process::{getegid, geteuid, Gid, Uid},
};
use snafu::ResultExt;

use crate::error::{
    BrokerIoSnafu, BrokerSessionAlreadyRegisteredSnafu, BrokerStateLockSnafu,
    RuntimeInterceptionBrokerError,
};

use super::{
    endpoint::RuntimeInterceptionEndpoint,
    handlers::SessionInterceptionRouter,
    server::{
        RuntimeGuardServerConfig, RuntimeInterceptionBrokerServer, SessionInterceptionRegistration,
    },
};

pub struct RuntimeGuardService {
    runtime_root: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
    sessions: Mutex<HashMap<(u32, String), SessionInterceptionRegistration>>,
}

impl RuntimeGuardService {
    pub fn new(runtime_root: impl Into<PathBuf>) -> Result<Self, RuntimeInterceptionBrokerError> {
        let runtime_root = runtime_root.into();
        fs::create_dir_all(&runtime_root).context(BrokerIoSnafu)?;
        fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o711))
            .context(BrokerIoSnafu)?;
        Ok(Self {
            runtime_root,
            owner_uid: geteuid().as_raw(),
            owner_gid: getegid().as_raw(),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn start_session(
        &self,
        uid: u32,
        gid: u32,
        session_id: &str,
        actor_id: &str,
        router: SessionInterceptionRouter,
    ) -> Result<RuntimeInterceptionEndpoint, RuntimeInterceptionBrokerError> {
        self.start_session_with_token(uid, gid, session_id, actor_id, router, None)
    }

    pub fn start_session_with_token(
        &self,
        uid: u32,
        gid: u32,
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
        let user_directory = self.runtime_root.join(uid.to_string());
        fs::create_dir_all(&user_directory).context(BrokerIoSnafu)?;
        fs::set_permissions(&user_directory, fs::Permissions::from_mode(0o711))
            .context(BrokerIoSnafu)?;
        chown(
            &user_directory,
            Some(Uid::from_raw(self.owner_uid)),
            Some(Gid::from_raw(self.owner_gid)),
        )
        .map_err(std::io::Error::from)
        .context(BrokerIoSnafu)?;
        let session_directory = user_directory.join(session_id);
        fs::create_dir_all(&session_directory).context(BrokerIoSnafu)?;
        let server = match RuntimeInterceptionBrokerServer::start(RuntimeGuardServerConfig {
            directory: Some(session_directory.clone()),
            owner_uid: self.owner_uid,
            owner_gid: gid,
            directory_mode: 0o710,
            socket_mode: 0o620,
        }) {
            Ok(server) => server,
            Err(error) => {
                let _result = fs::remove_dir(&session_directory);
                return Err(error);
            }
        };
        let registration = match server.register_session(
            session_id.to_owned(),
            actor_id.to_owned(),
            router,
            Some(uid),
            true,
            token,
        ) {
            Ok(registration) => registration,
            Err(error) => {
                drop(server);
                let _result = fs::remove_dir(&session_directory);
                return Err(error);
            }
        };
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
        if let Some(registration) = registration {
            registration.shutdown_server();
        }
        let directory = self.runtime_root.join(uid.to_string()).join(session_id);
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) if source.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(source) => return Err(source).context(BrokerIoSnafu),
        }
        Ok(())
    }

    #[must_use]
    pub fn session_directory(&self, uid: u32, session_id: &str) -> PathBuf {
        self.runtime_root.join(uid.to_string()).join(session_id)
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
    use std::{fs, os::unix::net::UnixStream};

    use erebor_runtime_ipc::v1::{
        DaemonStatusRequest, Envelope, GuardHello, GuardHelloAck, KIND_DAEMON_STATUS_REQUEST,
        KIND_GUARD_HELLO_ACK, PROTOCOL_VERSION,
    };
    use rustix::process::{getegid, geteuid};
    use tempfile::TempDir;

    use crate::{
        runtime_interception_broker::wire::{
            envelope_with_token, read_frame_from_stream, write_frame_to_stream,
        },
        InterceptionBrokerClient, RuntimeGuardService, SessionInterceptionRouter,
    };

    #[test]
    fn per_session_service_uses_exact_listener_and_observed_peer_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new(temporary.path())?;
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let endpoint = service.start_session(
            uid,
            gid,
            "session-guard",
            "agent",
            SessionInterceptionRouter::new(),
        )?;
        let ack = InterceptionBrokerClient::send_hello(
            &endpoint,
            GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: String::from("session-guard"),
                actor_id: String::from("agent"),
                guard_pid: i64::from(std::process::id()),
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;

        assert!(ack.accepted);
        assert!(endpoint
            .path()
            .ends_with("session-guard/runtime-interception.sock"));
        service.stop_session(uid, "session-guard")?;
        assert!(!fs::exists(endpoint.path())?);
        Ok(())
    }

    #[test]
    fn runtime_guard_socket_rejects_daemon_control_messages_before_dispatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let service = RuntimeGuardService::new(temporary.path())?;
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let endpoint = service.start_session(
            uid,
            gid,
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
}
