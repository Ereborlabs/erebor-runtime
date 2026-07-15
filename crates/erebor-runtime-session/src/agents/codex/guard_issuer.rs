use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Mutex,
    thread::{self, JoinHandle},
};

use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

use super::{broker::LinuxHookPeerInspector, CodexManagedSession, CodexSessionError};

const REQUEST_MAGIC: [u8; 4] = *b"ERGX";
const RESPONSE_MAGIC: [u8; 4] = *b"ERGA";
const VERSION: u8 = 1;
const MAX_HISTORY_ENTRIES: usize = 16;
const MAX_PATH_BYTES: usize = 4096;

/// Codex-owned ticket issuer that consumes generic guarded-exec observations
/// from a private inherited descriptor. The generic ptrace guard never learns
/// Codex profile, hook, or ticket details.
pub(crate) struct CodexGuardTicketIssuer {
    guard_stream: UnixStream,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl CodexGuardTicketIssuer {
    pub(crate) fn start(managed_session: CodexManagedSession) -> Result<Self, CodexSessionError> {
        let (server_stream, guard_stream) =
            UnixStream::pair().map_err(|source| CodexSessionError::HookBrokerIo {
                source,
                location: snafu::Location::default(),
            })?;
        let mut flags = fcntl_getfd(&guard_stream)
            .map_err(std::io::Error::from)
            .map_err(|source| CodexSessionError::HookBrokerIo {
                source,
                location: snafu::Location::default(),
            })?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&guard_stream, flags)
            .map_err(std::io::Error::from)
            .map_err(|source| CodexSessionError::HookBrokerIo {
                source,
                location: snafu::Location::default(),
            })?;

        let worker = thread::spawn(move || {
            CodexGuardTicketIssuerServer::new(managed_session).serve(server_stream);
        });
        Ok(Self {
            guard_stream,
            worker: Mutex::new(Some(worker)),
        })
    }

    #[must_use]
    pub(crate) fn inherited_guard_fd(&self) -> i32 {
        self.guard_stream.as_raw_fd()
    }
}

impl Drop for CodexGuardTicketIssuer {
    fn drop(&mut self) {
        let _result = self.guard_stream.shutdown(Shutdown::Both);
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                let _result = worker.join();
            }
        }
    }
}

struct CodexGuardTicketIssuerServer {
    managed_session: CodexManagedSession,
}

impl CodexGuardTicketIssuerServer {
    const fn new(managed_session: CodexManagedSession) -> Self {
        Self { managed_session }
    }

    fn serve(&self, mut stream: UnixStream) {
        while let Ok(observation) = GuardedExecObservation::read(&mut stream) {
            let status = self.issue_if_managed_hook(observation);
            if GuardedExecObservation::write_status(&mut stream, status).is_err() {
                break;
            }
        }
    }

    fn issue_if_managed_hook(&self, observation: GuardedExecObservation) -> u8 {
        let expected_history = self
            .managed_session
            .profile()
            .hook_exec_history
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        if observation.exec_history != expected_history {
            return 0;
        }
        let peer = match LinuxHookPeerInspector::inspect_pid(observation.pid, "") {
            Ok(peer) => peer,
            Err(_error) => return 2,
        };
        let profile = self.managed_session.profile();
        if peer.executable != profile.managed_hook_path.display().to_string()
            || peer.argv != [profile.managed_hook_path.display().to_string()]
        {
            return 2;
        }
        self.managed_session
            .issue_guarded_hook_ticket(peer)
            .map_or(2, |_ticket| 1)
    }
}

struct GuardedExecObservation {
    pid: i32,
    exec_history: Vec<String>,
}

impl GuardedExecObservation {
    fn read(stream: &mut UnixStream) -> Result<Self, std::io::Error> {
        let mut header = [0_u8; 10];
        stream.read_exact(&mut header)?;
        if header[..4] != REQUEST_MAGIC || header[4] != VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid guarded exec observation header",
            ));
        }
        let pid = i32::from_le_bytes([header[5], header[6], header[7], header[8]]);
        let count = usize::from(header[9]);
        if pid <= 0 || count == 0 || count > MAX_HISTORY_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid guarded exec observation shape",
            ));
        }
        let mut exec_history = Vec::with_capacity(count);
        for _index in 0..count {
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length)?;
            let length = usize::from(u16::from_le_bytes(length));
            if length == 0 || length > MAX_PATH_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid guarded exec history path size",
                ));
            }
            let mut path = vec![0_u8; length];
            stream.read_exact(&mut path)?;
            let path = String::from_utf8(path).map_err(|_error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "guarded exec history path is not UTF-8",
                )
            })?;
            exec_history.push(path);
        }
        Ok(Self { pid, exec_history })
    }

    fn write_status(stream: &mut UnixStream, status: u8) -> Result<(), std::io::Error> {
        stream.write_all(&[
            RESPONSE_MAGIC[0],
            RESPONSE_MAGIC[1],
            RESPONSE_MAGIC[2],
            RESPONSE_MAGIC[3],
            VERSION,
            status,
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixStream},
        process::Command,
        time::Duration,
    };

    use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

    use super::GuardedExecObservation;

    #[test]
    fn guarded_exec_observation_rejects_malformed_history() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut writer, mut reader) = match UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = writer.write_all(b"ERGX\x01\x00\x00\x00\x00\x00") {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(());
            }
            return Err(error.into());
        }
        assert!(GuardedExecObservation::read(&mut reader).is_err());
        Ok(())
    }

    #[test]
    fn generic_process_guard_reports_each_exec_over_its_private_descriptor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        match generic_process_guard_observation() {
            Ok(()) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn generic_process_guard_observation() -> Result<(), Box<dyn std::error::Error>> {
        let (mut server, guard) = UnixStream::pair()?;
        let mut flags = fcntl_getfd(&guard)?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&guard, flags)?;
        server.set_read_timeout(Some(Duration::from_secs(2)))?;
        let guard_path = env!("EREBOR_BUILD_LINUX_PROCESS_GUARD");
        let mut child = Command::new(guard_path)
            .arg("/bin/true")
            .env(
                "EREBOR_GUARD_EXEC_OBSERVER_FD",
                guard.as_raw_fd().to_string(),
            )
            .spawn()?;
        let observation = match GuardedExecObservation::read(&mut server) {
            Ok(observation) => observation,
            Err(error) => {
                let _result = child.kill();
                return Err(error.into());
            }
        };
        assert!(observation.pid > 0);
        assert!(!observation.exec_history.is_empty());
        GuardedExecObservation::write_status(&mut server, 0)?;
        assert!(child.wait()?.success());
        Ok(())
    }
}
