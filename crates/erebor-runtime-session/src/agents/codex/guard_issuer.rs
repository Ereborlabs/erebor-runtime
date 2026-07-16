use std::{
    collections::HashSet,
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

#[path = "../../os/linux/process_guard/observer_protocol.rs"]
mod observer_protocol;

use observer_protocol::{GuardObserverEvent, GuardObserverStatus};

use super::{
    broker::LinuxHookPeerInspector, CodexInvocationLeaseOwner, CodexManagedSession,
    CodexSessionError,
};

/// Codex-owned ticket issuer that consumes generic guarded-exec observations
/// from a private inherited descriptor. The generic ptrace guard never learns
/// Codex profile, hook, or ticket details.
pub(crate) struct CodexGuardTicketIssuer {
    guard_stream: UnixStream,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl CodexGuardTicketIssuer {
    pub(crate) fn start(
        managed_session: CodexManagedSession,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Result<Self, CodexSessionError> {
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
            CodexGuardTicketIssuerServer::new(managed_session, lease_owner).serve(server_stream);
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
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    tracked_hook_pids: HashSet<i32>,
}

impl CodexGuardTicketIssuerServer {
    fn new(
        managed_session: CodexManagedSession,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        Self {
            managed_session,
            lease_owner,
            tracked_hook_pids: HashSet::new(),
        }
    }

    fn serve(&mut self, mut stream: UnixStream) {
        while let Ok(observation) = GuardObserverEvent::read(&mut stream) {
            let status = self.handle_observation(observation);
            if status.write(&mut stream).is_err() {
                break;
            }
        }
    }

    fn handle_observation(&mut self, observation: GuardObserverEvent) -> GuardObserverStatus {
        match observation {
            GuardObserverEvent::Exec { pid, exec_history } => {
                let status = self.issue_if_managed_hook(pid, &exec_history);
                if status == GuardObserverStatus::Track {
                    self.tracked_hook_pids.insert(pid);
                }
                status
            }
            GuardObserverEvent::Fork {
                parent_pid,
                child_pid,
            } => self
                .lease_owner
                .record_guarded_process_fork(i64::from(parent_pid), i64::from(child_pid))
                .map_or_else(
                    |error| {
                        self.log_observer_error("fork", parent_pid, &error);
                        GuardObserverStatus::Reject
                    },
                    |_| GuardObserverStatus::Ignore,
                ),
            GuardObserverEvent::Exit { pid, succeeded } => {
                if let Err(error) = self.lease_owner.record_guarded_process_exit(i64::from(pid)) {
                    self.log_observer_error("exit", pid, &error);
                    return GuardObserverStatus::Reject;
                }
                if !self.tracked_hook_pids.remove(&pid) {
                    return GuardObserverStatus::Ignore;
                }
                self.lease_owner
                    .record_guarded_hook_exit(i64::from(pid), succeeded)
                    .map_or_else(
                        |error| {
                            self.log_observer_error("hook exit", pid, &error);
                            GuardObserverStatus::Reject
                        },
                        |released| {
                            if released {
                                GuardObserverStatus::Track
                            } else {
                                GuardObserverStatus::Reject
                            }
                        },
                    )
            }
        }
    }

    fn issue_if_managed_hook(&self, pid: i32, exec_history: &[String]) -> GuardObserverStatus {
        let expected_history = self
            .managed_session
            .profile()
            .hook_exec_history
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        if exec_history != expected_history {
            return GuardObserverStatus::Ignore;
        }
        let peer = match LinuxHookPeerInspector::inspect_pid(pid, "") {
            Ok(peer) => peer,
            Err(error) => {
                erebor_runtime_telemetry::log!(
                        erebor_runtime_telemetry::tracing::Level::WARN,
                        error = ?error,
                    pid,
                    "managed Codex hook peer inspection failed"
                );
                return GuardObserverStatus::Reject;
            }
        };
        let profile = self.managed_session.profile();
        if peer.executable != profile.managed_hook_path.display().to_string()
            || peer.argv != [profile.managed_hook_path.display().to_string()]
        {
            erebor_runtime_telemetry::log!(
                erebor_runtime_telemetry::tracing::Level::WARN,
                pid,
                executable = %peer.executable,
                argv = %peer.argv.join(" "),
                "managed Codex hook identity did not match its projected profile"
            );
            return GuardObserverStatus::Reject;
        }
        match self.managed_session.issue_guarded_hook_ticket(peer) {
            Ok(_ticket) => GuardObserverStatus::Track,
            Err(error) => {
                erebor_runtime_telemetry::log!(
                    erebor_runtime_telemetry::tracing::Level::WARN,
                    error = ?error,
                pid,
                    "managed Codex hook ticket issuance failed"
                );
                GuardObserverStatus::Reject
            }
        }
    }
    fn log_observer_error(&self, event: &str, pid: i32, error: &CodexSessionError) {
        erebor_runtime_telemetry::log!(
            erebor_runtime_telemetry::tracing::Level::WARN,
            error = ?error,
            event,
            pid,
            "managed Codex guard lifecycle observation failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixStream},
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

    use super::observer_protocol::{GuardObserverEvent, GuardObserverStatus};

    #[test]
    fn guarded_lifecycle_observation_rejects_malformed_header(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut reader) = match UnixStream::pair() {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = writer.write_all(b"ERGX\x02\x01\x00\x00\x00\x00\x00") {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(());
            }
            return Err(error.into());
        }
        assert!(GuardObserverEvent::read(&mut reader).is_err());
        Ok(())
    }

    #[test]
    fn generic_process_guard_reports_exec_and_exit_over_its_private_descriptor(
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
        let observation = match GuardObserverEvent::read(&mut server) {
            Ok(observation) => observation,
            Err(error) => {
                let _result = child.kill();
                return Err(error.into());
            }
        };
        let GuardObserverEvent::Exec { pid, exec_history } = observation else {
            return Err("expected guarded exec observation".into());
        };
        assert!(pid > 0);
        assert!(!exec_history.is_empty());
        GuardObserverStatus::Ignore.write(&mut server)?;
        let exit = GuardObserverEvent::read(&mut server)?;
        assert_eq!(
            exit,
            GuardObserverEvent::Exit {
                pid,
                succeeded: true
            }
        );
        GuardObserverStatus::Ignore.write(&mut server)?;
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn generic_process_guard_parks_a_physical_exec_until_the_tracked_hook_exits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let marker = root.path().join("effect-after-hook-exit");
        let hook_tracked = root.path().join("hook-tracked");
        let (server, guard) = UnixStream::pair()?;
        let mut flags = fcntl_getfd(&guard)?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&guard, flags)?;
        let guard_path = env!("EREBOR_BUILD_LINUX_PROCESS_GUARD");
        let script = format!(
            "/usr/bin/sleep 0.4 & while [ ! -e {} ]; do :; done; /usr/bin/touch {}",
            hook_tracked.display(),
            marker.display()
        );
        let mut child = Command::new(guard_path)
            .args(["/bin/sh", "-c", &script])
            .env(
                "EREBOR_GUARD_EXEC_OBSERVER_FD",
                guard.as_raw_fd().to_string(),
            )
            .spawn()?;
        let marker_for_observer = marker.clone();
        let hook_tracked_for_observer = hook_tracked.clone();
        let observed_marker_absent = thread::spawn(move || {
            let mut server = server;
            server.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut tracked_hook_pid = None;
            let mut marker_absent_at_hook_exit = false;
            while let Ok(event) = GuardObserverEvent::read(&mut server) {
                let status = match event {
                    GuardObserverEvent::Exec { pid, exec_history }
                        if exec_history
                            .last()
                            .is_some_and(|path| path.ends_with("/sleep")) =>
                    {
                        tracked_hook_pid = Some(pid);
                        fs::write(&hook_tracked_for_observer, "tracked")?;
                        GuardObserverStatus::Track
                    }
                    GuardObserverEvent::Exit { pid, succeeded }
                        if Some(pid) == tracked_hook_pid && succeeded =>
                    {
                        marker_absent_at_hook_exit = !marker_for_observer.exists();
                        GuardObserverStatus::Track
                    }
                    _ => GuardObserverStatus::Ignore,
                };
                if status.write(&mut server).is_err() {
                    break;
                }
            }
            Ok::<_, std::io::Error>((tracked_hook_pid.is_some(), marker_absent_at_hook_exit))
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _result = child.kill();
                return Err("process guard did not release the held physical exec".into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (saw_tracked_hook, marker_absent_at_hook_exit) = observed_marker_absent
            .join()
            .map_err(|_error| "process guard observer thread panicked")??;
        assert!(status.success());
        assert!(saw_tracked_hook);
        assert!(marker_absent_at_hook_exit);
        assert!(fs::metadata(marker).is_ok());
        Ok(())
    }
}
