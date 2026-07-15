use std::{
    env,
    io::{Read, Write},
    os::{fd::FromRawFd, unix::net::UnixStream},
    time::Duration,
};

use super::sys::{LinuxSys, Pid};

const ENV_FD: &str = "EREBOR_GUARD_EXEC_OBSERVER_FD";
const REQUEST_MAGIC: [u8; 4] = *b"ERGX";
const RESPONSE_MAGIC: [u8; 4] = *b"ERGA";
const VERSION: u8 = 1;
const MAX_HISTORY_ENTRIES: usize = 16;
const MAX_PATH_BYTES: usize = 4096;

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

    pub(super) fn observe(&mut self, pid: Pid, history: &[String]) -> Result<(), String> {
        if history.is_empty() || history.len() > MAX_HISTORY_ENTRIES {
            return Err(String::from(
                "exec observer history has an invalid entry count",
            ));
        }
        let mut request = Vec::new();
        request.extend_from_slice(&REQUEST_MAGIC);
        request.push(VERSION);
        request.extend_from_slice(&pid.to_le_bytes());
        request.push(history.len() as u8);
        for path in history {
            let bytes = path.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
                return Err(String::from(
                    "exec observer history path has an invalid size",
                ));
            }
            request.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            request.extend_from_slice(bytes);
        }
        self.stream
            .write_all(&request)
            .map_err(|error| format!("failed to send guarded exec observation: {error}"))?;

        let mut response = [0_u8; 6];
        self.stream.read_exact(&mut response).map_err(|error| {
            format!("failed to read guarded exec observation response: {error}")
        })?;
        if response[..4] != RESPONSE_MAGIC || response[4] != VERSION {
            return Err(String::from(
                "guarded exec observer returned an invalid response",
            ));
        }
        match response[5] {
            0 | 1 => Ok(()),
            _ => Err(String::from(
                "guarded exec observer rejected the observation",
            )),
        }
    }
}
