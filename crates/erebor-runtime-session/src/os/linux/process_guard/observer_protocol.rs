use std::io::{Read, Write};

const REQUEST_MAGIC: [u8; 4] = *b"ERGX";
const RESPONSE_MAGIC: [u8; 4] = *b"ERGA";
const VERSION: u8 = 2;
const HEADER_LEN: usize = 11;
const MAX_HISTORY_ENTRIES: usize = 16;
const MAX_PATH_BYTES: usize = 4096;

const EXEC_EVENT: u8 = 1;
const FORK_EVENT: u8 = 2;
const EXIT_EVENT: u8 = 3;

/// A generic process-lifecycle observation emitted by the Linux ptrace guard.
/// The observer decides which process identities matter; the guard never
/// carries agent, profile, ticket, or policy semantics.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum GuardObserverEvent {
    Exec { pid: i32, exec_history: Vec<String> },
    Fork { parent_pid: i32, child_pid: i32 },
    Exit { pid: i32, succeeded: bool },
}

/// The observer's disposition for one lifecycle observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardObserverStatus {
    Ignore,
    Track,
    Reject,
}

#[allow(dead_code)]
impl GuardObserverEvent {
    pub(crate) fn read(stream: &mut impl Read) -> Result<Self, std::io::Error> {
        let mut header = [0_u8; HEADER_LEN];
        stream.read_exact(&mut header)?;
        if header[..4] != REQUEST_MAGIC || header[4] != VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid guarded process observation header",
            ));
        }
        let pid = i32::from_le_bytes([header[6], header[7], header[8], header[9]]);
        if pid <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded process observation pid is invalid",
            ));
        }
        match header[5] {
            EXEC_EVENT => Self::read_exec(stream, pid, header[10]),
            FORK_EVENT => Self::read_fork(stream, pid, header[10]),
            EXIT_EVENT => Self::read_exit(pid, header[10]),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded process observation event kind is invalid",
            )),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn write(&self, stream: &mut impl Write) -> Result<(), std::io::Error> {
        match self {
            Self::Exec { pid, exec_history } => {
                if *pid <= 0 || exec_history.is_empty() || exec_history.len() > MAX_HISTORY_ENTRIES
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "guarded exec observation shape is invalid",
                    ));
                }
                stream.write_all(&Self::header(EXEC_EVENT, *pid, exec_history.len() as u8))?;
                for path in exec_history {
                    let bytes = path.as_bytes();
                    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "guarded exec history path size is invalid",
                        ));
                    }
                    stream.write_all(&(bytes.len() as u16).to_le_bytes())?;
                    stream.write_all(bytes)?;
                }
                Ok(())
            }
            Self::Fork {
                parent_pid,
                child_pid,
            } => {
                if *parent_pid <= 0 || *child_pid <= 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "guarded fork observation pid is invalid",
                    ));
                }
                stream.write_all(&Self::header(FORK_EVENT, *parent_pid, 0))?;
                stream.write_all(&child_pid.to_le_bytes())
            }
            Self::Exit { pid, succeeded } => {
                if *pid <= 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "guarded exit observation pid is invalid",
                    ));
                }
                stream.write_all(&Self::header(EXIT_EVENT, *pid, u8::from(*succeeded)))
            }
        }
    }

    #[allow(dead_code)]
    fn header(kind: u8, pid: i32, detail: u8) -> [u8; HEADER_LEN] {
        let mut header = [0_u8; HEADER_LEN];
        header[..4].copy_from_slice(&REQUEST_MAGIC);
        header[4] = VERSION;
        header[5] = kind;
        header[6..10].copy_from_slice(&pid.to_le_bytes());
        header[10] = detail;
        header
    }

    fn read_exec(stream: &mut impl Read, pid: i32, count: u8) -> Result<Self, std::io::Error> {
        let count = usize::from(count);
        if count == 0 || count > MAX_HISTORY_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded exec observation history count is invalid",
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
                    "guarded exec history path size is invalid",
                ));
            }
            let mut path = vec![0_u8; length];
            stream.read_exact(&mut path)?;
            exec_history.push(String::from_utf8(path).map_err(|_error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "guarded exec history path is not UTF-8",
                )
            })?);
        }
        Ok(Self::Exec { pid, exec_history })
    }

    fn read_fork(
        stream: &mut impl Read,
        parent_pid: i32,
        detail: u8,
    ) -> Result<Self, std::io::Error> {
        if detail != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded fork observation header detail is invalid",
            ));
        }
        let mut child_pid = [0_u8; 4];
        stream.read_exact(&mut child_pid)?;
        let child_pid = i32::from_le_bytes(child_pid);
        if child_pid <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded fork observation child pid is invalid",
            ));
        }
        Ok(Self::Fork {
            parent_pid,
            child_pid,
        })
    }

    fn read_exit(pid: i32, succeeded: u8) -> Result<Self, std::io::Error> {
        match succeeded {
            0 => Ok(Self::Exit {
                pid,
                succeeded: false,
            }),
            1 => Ok(Self::Exit {
                pid,
                succeeded: true,
            }),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded exit observation status is invalid",
            )),
        }
    }
}

#[allow(dead_code)]
impl GuardObserverStatus {
    #[allow(dead_code)]
    pub(crate) fn read(stream: &mut impl Read) -> Result<Self, std::io::Error> {
        let mut response = [0_u8; 6];
        stream.read_exact(&mut response)?;
        if response[..4] != RESPONSE_MAGIC || response[4] != VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded process observer returned an invalid response",
            ));
        }
        match response[5] {
            0 => Ok(Self::Ignore),
            1 => Ok(Self::Track),
            2 => Ok(Self::Reject),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "guarded process observer returned an invalid status",
            )),
        }
    }

    pub(crate) fn write(self, stream: &mut impl Write) -> Result<(), std::io::Error> {
        let status = match self {
            Self::Ignore => 0,
            Self::Track => 1,
            Self::Reject => 2,
        };
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
    use std::io::Cursor;

    use super::{GuardObserverEvent, GuardObserverStatus};

    #[test]
    fn lifecycle_events_round_trip_without_agent_specific_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for event in [
            GuardObserverEvent::Exec {
                pid: 41,
                exec_history: vec![String::from("/bin/zsh"), String::from("/hook")],
            },
            GuardObserverEvent::Fork {
                parent_pid: 41,
                child_pid: 42,
            },
            GuardObserverEvent::Exit {
                pid: 42,
                succeeded: true,
            },
        ] {
            let mut encoded = Vec::new();
            event.write(&mut encoded)?;
            assert_eq!(GuardObserverEvent::read(&mut Cursor::new(encoded))?, event);
        }
        let mut encoded = Vec::new();
        GuardObserverStatus::Track.write(&mut encoded)?;
        assert_eq!(
            GuardObserverStatus::read(&mut Cursor::new(encoded))?,
            GuardObserverStatus::Track
        );
        Ok(())
    }
}
