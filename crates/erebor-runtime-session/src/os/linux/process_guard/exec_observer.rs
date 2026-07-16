use std::{
    env,
    os::{fd::FromRawFd, unix::net::UnixStream},
    time::Duration,
};

use super::{
    observer_protocol::{GuardObserverEvent, GuardObserverStatus},
    sys::{LinuxSys, Pid},
};

const ENV_FD: &str = "EREBOR_GUARD_EXEC_OBSERVER_FD";

/// Optional generic process-exec observer, carried over an inherited file
/// descriptor. It contains no agent-specific profile or ticket semantics.
pub(super) struct GuardExecObserver {
    stream: UnixStream,
}

impl GuardExecObserver {
    pub(super) fn from_environment() -> Result<Option<Self>, String> {
        let Some(value) = env::var(ENV_FD).ok().filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let fd = value
            .parse()
            .map_err(|_error| format!("{ENV_FD} must be a file descriptor number"))?;
        LinuxSys::set_close_on_exec(fd)?;
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|error| format!("failed to set exec observer read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|error| format!("failed to set exec observer write timeout: {error}"))?;
        Ok(Some(Self { stream }))
    }

    pub(super) fn observe_exec(
        &mut self,
        pid: Pid,
        history: Vec<String>,
    ) -> Result<GuardObserverStatus, String> {
        self.observe(GuardObserverEvent::Exec {
            pid,
            exec_history: history,
        })
    }

    pub(super) fn observe_fork(
        &mut self,
        parent_pid: Pid,
        child_pid: Pid,
    ) -> Result<GuardObserverStatus, String> {
        self.observe(GuardObserverEvent::Fork {
            parent_pid,
            child_pid,
        })
    }

    pub(super) fn observe_exit(
        &mut self,
        pid: Pid,
        succeeded: bool,
    ) -> Result<GuardObserverStatus, String> {
        self.observe(GuardObserverEvent::Exit { pid, succeeded })
    }

    fn observe(&mut self, event: GuardObserverEvent) -> Result<GuardObserverStatus, String> {
        event
            .write(&mut self.stream)
            .map_err(|error| format!("failed to send guarded process observation: {error}"))?;
        GuardObserverStatus::read(&mut self.stream).map_err(|error| {
            format!("failed to read guarded process observation response: {error}")
        })
    }
}
