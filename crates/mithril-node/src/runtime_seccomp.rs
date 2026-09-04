#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::ioctl::{opcode, Getter, Setter};
use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde::Deserialize;
use snafu::{ensure, OptionExt as _, ResultExt as _};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::error::{IdentityStateSnafu, IoSnafu, JsonSnafu};
use crate::{Result, RuntimeAdmissionConfig};

const MAXIMUM_PROCESS_STATE_BYTES: usize = 64 * 1_024;
const MAXIMUM_EXECUTABLE_PATH_BYTES: usize = 4_096;
const SECCOMP_IOCTL_NOTIF_RECV: rustix::ioctl::Opcode =
    opcode::read_write::<libc::seccomp_notif>(b'!', 0);
const SECCOMP_IOCTL_NOTIF_SEND: rustix::ioctl::Opcode =
    opcode::read_write::<libc::seccomp_notif_resp>(b'!', 1);
const SECCOMP_IOCTL_NOTIF_ID_VALID: rustix::ioctl::Opcode = opcode::write::<u64>(b'!', 2);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OciContainerProcessStateV1 {
    #[serde(rename = "ociVersion")]
    version: String,
    fds: Vec<String>,
    pid: i32,
    metadata: String,
    state: OciStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct OciStateV1 {
    #[serde(rename = "ociVersion")]
    version: String,
    id: String,
    status: String,
    pid: i32,
    bundle: String,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeExecNotificationV1 {
    pub id: u64,
    pub pid: u32,
    pub syscall: i32,
    pub executable_path: PathBuf,
    pub initial_exec: bool,
}

pub(crate) struct RuntimeSeccompEnvelope {
    pub process: OciContainerProcessStateV1,
    pub notification: RuntimeExecNotificationV1,
    pub pidfd: OwnedFd,
    deadline: Instant,
    response: oneshot::Sender<RuntimeSeccompDispatch>,
}

struct RuntimeSeccompDispatch {
    allowed: bool,
    delivered: oneshot::Sender<()>,
}

pub(crate) struct RuntimeSeccompServer {
    listener: UnixListener,
    _socket_owner: crate::unix_socket::UnixSocketPathOwner,
    socket_path: PathBuf,
    timeout: Duration,
    notifications: mpsc::Sender<RuntimeSeccompEnvelope>,
}

pub(crate) struct RuntimeSeccompReceiver {
    notifications: mpsc::Receiver<RuntimeSeccompEnvelope>,
}

impl OciContainerProcessStateV1 {
    pub(crate) fn container_id(&self) -> &str {
        &self.state.id
    }

    pub(crate) fn annotations(&self) -> &BTreeMap<String, String> {
        &self.state.annotations
    }

    pub(crate) fn state_pid(&self) -> i32 {
        self.state.pid
    }

    pub(crate) fn process_pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn status(&self) -> &str {
        &self.state.status
    }

    pub(crate) fn bundle(&self) -> &Path {
        Path::new(&self.state.bundle)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version.starts_with("1.")
                && self.state.version.starts_with("1.")
                && self.fds == ["seccompFd"]
                && self.metadata == crate::runtime_admission::SECCOMP_LISTENER_METADATA
                && (32..=128).contains(&self.state.id.len())
                && self
                    .state
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
                && self.pid > 0
                && self.state.pid >= 0
                && matches!(self.state.status.as_str(), "creating" | "running")
                && Path::new(&self.state.bundle).is_absolute()
                && self.state.bundle.len() <= 4_096
                && self.state.annotations.len() <= 64,
            IdentityStateSnafu {
                reason: "runc seccomp process state is not canonical and bounded",
            }
        );
        Ok(())
    }
}

impl RuntimeSeccompEnvelope {
    pub(crate) fn ensure_active(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline && !self.response.is_closed(),
            IdentityStateSnafu {
                reason: "runtime exec notification is no longer waiting",
            }
        );
        Ok(())
    }

    pub(crate) async fn respond(self, allowed: bool) -> Result<()> {
        self.ensure_active()?;
        let (delivered, delivery) = oneshot::channel();
        self.response
            .send(RuntimeSeccompDispatch { allowed, delivered })
            .map_err(|_dispatch| {
                IdentityStateSnafu {
                    reason: "runtime exec notification closed before its response".to_owned(),
                }
                .build()
            })?;
        tokio::time::timeout_at(self.deadline, delivery)
            .await
            .map_err(|_elapsed| {
                IdentityStateSnafu {
                    reason: "runtime exec notification response exceeded its deadline".to_owned(),
                }
                .build()
            })?
            .map_err(|_closed| {
                IdentityStateSnafu {
                    reason: "runtime exec notification response did not reach the kernel"
                        .to_owned(),
                }
                .build()
            })?;
        Ok(())
    }
}

impl RuntimeSeccompServer {
    pub(crate) fn bind(config: &RuntimeAdmissionConfig) -> Result<(Self, RuntimeSeccompReceiver)> {
        let socket_path = crate::runtime_admission::seccomp_listener_path(&config.socket_path);
        let (listener, socket_owner) =
            crate::unix_socket::UnixSocketPathOwner::bind(&socket_path, 0)?;
        let (notifications, receiver) = mpsc::channel(128);
        Ok((
            Self {
                listener,
                _socket_owner: socket_owner,
                socket_path,
                timeout: Duration::from_millis(config.timeout_ms),
                notifications,
            },
            RuntimeSeccompReceiver {
                notifications: receiver,
            },
        ))
    }

    pub(crate) async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _address) = accepted.context(IoSnafu {
                        path: &self.socket_path,
                    })?;
                    let path = self.socket_path.clone();
                    let timeout = self.timeout;
                    let notifications = self.notifications.clone();
                    tokio::spawn(async move {
                        if let Err(error) = Self::handle_connection(
                            stream,
                            &path,
                            timeout,
                            notifications,
                        ).await {
                            erebor_telemetry::warn!(
                                error;
                                "runtime seccomp notification exchange failed",
                                retry = %"runtime"
                            );
                        }
                    });
                }
                changed = shutdown.changed() => {
                    let _result = changed;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_connection(
        stream: UnixStream,
        socket_path: &Path,
        timeout: Duration,
        notifications: mpsc::Sender<RuntimeSeccompEnvelope>,
    ) -> Result<()> {
        ensure!(
            stream
                .peer_cred()
                .context(IoSnafu { path: socket_path })?
                .uid()
                == 0,
            IdentityStateSnafu {
                reason: "runtime seccomp peer is not root",
            }
        );
        let (process, listener) = receive_process_state(&stream, socket_path).await?;
        process.validate()?;
        let listener = AsyncFd::new(listener).context(IoSnafu { path: socket_path })?;
        let mut sequence = 0_u64;
        loop {
            let notification = receive_notification(&listener).await?;
            let initial_exec = sequence == 0 && process.status() == "creating";
            sequence = sequence.checked_add(1).context(IdentityStateSnafu {
                reason: "runtime exec notification sequence overflowed",
            })?;
            validate_notification(&process, &notification, initial_exec)?;
            let executable_path = read_executable_path(&notification)?;
            let pid = Pid::from_raw(notification.pid as i32).context(IdentityStateSnafu {
                reason: "runtime exec notification has an invalid PID",
            })?;
            let pidfd = pidfd_open(pid, PidfdFlags::empty())
                .map_err(std::io::Error::from)
                .context(IoSnafu {
                    path: PathBuf::from(format!("/proc/{}", notification.pid)),
                })?;
            let deadline = Instant::now() + timeout;
            let (response, dispatched) = oneshot::channel();
            notifications
                .send(RuntimeSeccompEnvelope {
                    process: process.clone(),
                    notification: RuntimeExecNotificationV1 {
                        id: notification.id,
                        pid: notification.pid,
                        syscall: notification.data.nr,
                        executable_path,
                        initial_exec,
                    },
                    pidfd,
                    deadline,
                    response,
                })
                .await
                .map_err(|_closed| {
                    IdentityStateSnafu {
                        reason: "runtime seccomp notification receiver stopped".to_owned(),
                    }
                    .build()
                })?;
            let dispatched = tokio::time::timeout_at(deadline, dispatched)
                .await
                .ok()
                .and_then(std::result::Result::ok)
                .unwrap_or(RuntimeSeccompDispatch {
                    allowed: false,
                    delivered: oneshot::channel().0,
                });
            respond_to_notification(&listener, notification.id, dispatched.allowed).await?;
            let _result = dispatched.delivered.send(());
        }
    }
}

impl RuntimeSeccompReceiver {
    pub(crate) async fn receive(&mut self) -> Option<RuntimeSeccompEnvelope> {
        self.notifications.recv().await
    }
}

async fn receive_process_state(
    stream: &UnixStream,
    socket_path: &Path,
) -> Result<(OciContainerProcessStateV1, OwnedFd)> {
    loop {
        stream
            .readable()
            .await
            .context(IoSnafu { path: socket_path })?;
        match stream.try_io(Interest::READABLE, || {
            let mut bytes = vec![0_u8; MAXIMUM_PROCESS_STATE_BYTES + 1];
            let mut slices = [IoSliceMut::new(&mut bytes)];
            let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut control_space);
            let received = recvmsg(
                stream,
                &mut slices,
                &mut control,
                RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
            )?;
            if received.flags.contains(ReturnFlags::CTRUNC) {
                return Err(rustix::io::Errno::MSGSIZE.into());
            }
            bytes.truncate(received.bytes);
            let mut fds = control.drain().flat_map(|message| match message {
                RecvAncillaryMessage::ScmRights(fds) => fds.collect::<Vec<_>>(),
                _ => Vec::new(),
            });
            let listener = fds
                .next()
                .ok_or_else(|| std::io::Error::from(rustix::io::Errno::BADMSG))?;
            if fds.next().is_some() {
                return Err(rustix::io::Errno::BADMSG.into());
            }
            Ok((bytes, listener))
        }) {
            Ok((bytes, listener)) => {
                ensure!(
                    !bytes.is_empty() && bytes.len() <= MAXIMUM_PROCESS_STATE_BYTES,
                    IdentityStateSnafu {
                        reason: "runc seccomp process state exceeds its byte limit",
                    }
                );
                let process = serde_json::from_slice(&bytes).context(JsonSnafu {
                    path: "runc-seccomp-process-state",
                })?;
                return Ok((process, listener));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error).context(IoSnafu { path: socket_path }),
        }
    }
}

async fn receive_notification(listener: &AsyncFd<OwnedFd>) -> Result<libc::seccomp_notif> {
    loop {
        let mut ready = listener.readable().await.context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        })?;
        match ready.try_io(|listener| {
            let request = unsafe {
                rustix::ioctl::ioctl(
                    listener.get_ref(),
                    Getter::<SECCOMP_IOCTL_NOTIF_RECV, libc::seccomp_notif>::new(),
                )
            }?;
            Ok(request)
        }) {
            Ok(Ok(notification)) => return Ok(notification),
            Ok(Err(error)) => {
                return Err(error).context(IoSnafu {
                    path: Path::new("seccomp notification fd"),
                });
            }
            Err(_would_block) => continue,
        }
    }
}

async fn respond_to_notification(
    listener: &AsyncFd<OwnedFd>,
    id: u64,
    allowed: bool,
) -> Result<()> {
    let valid = unsafe {
        rustix::ioctl::ioctl(
            listener,
            Setter::<SECCOMP_IOCTL_NOTIF_ID_VALID, u64>::new(id),
        )
    };
    if let Err(error) = valid {
        return Err(std::io::Error::from(error)).context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        });
    }
    let response = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: if allowed { 0 } else { -libc::EPERM },
        flags: if allowed {
            libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32
        } else {
            0
        },
    };
    unsafe {
        rustix::ioctl::ioctl(
            listener,
            Setter::<SECCOMP_IOCTL_NOTIF_SEND, libc::seccomp_notif_resp>::new(response),
        )
    }
    .map_err(std::io::Error::from)
    .context(IoSnafu {
        path: Path::new("seccomp notification fd"),
    })
}

fn validate_notification(
    process: &OciContainerProcessStateV1,
    notification: &libc::seccomp_notif,
    initial_exec: bool,
) -> Result<()> {
    ensure!(
        notification.id > 0
            && notification.pid > 0
            && notification.flags == 0
            && matches!(
                notification.data.nr as libc::c_long,
                libc::SYS_execve | libc::SYS_execveat
            )
            && (!initial_exec || notification.pid == process.process_pid() as u32),
        IdentityStateSnafu {
            reason: "seccomp notification is not one exact exec request",
        }
    );
    Ok(())
}

fn read_executable_path(notification: &libc::seccomp_notif) -> Result<PathBuf> {
    let address = if notification.data.nr as libc::c_long == libc::SYS_execve {
        notification.data.args[0]
    } else {
        notification.data.args[1]
    };
    ensure!(
        address > 0,
        IdentityStateSnafu {
            reason: "exec notification has no executable path pointer",
        }
    );
    let mut bytes = vec![0_u8; MAXIMUM_EXECUTABLE_PATH_BYTES + 1];
    let mut local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let read = unsafe {
        libc::process_vm_readv(
            notification.pid as libc::pid_t,
            &raw mut local,
            1,
            &raw mut remote,
            1,
            0,
        )
    };
    ensure!(
        read > 0,
        IdentityStateSnafu {
            reason: "exec notification executable path is unreadable",
        }
    );
    bytes.truncate(read as usize);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context(IdentityStateSnafu {
            reason: "exec notification executable path is not terminated within its limit",
        })?;
    bytes.truncate(end);
    ensure!(
        !bytes.is_empty(),
        IdentityStateSnafu {
            reason: "exec notification executable path is empty",
        }
    );
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(test)]
mod tests {
    use snafu::ResultExt as _;

    use super::{validate_notification, OciContainerProcessStateV1};

    fn process_state() -> crate::Result<OciContainerProcessStateV1> {
        serde_json::from_value(serde_json::json!({
            "ociVersion": "1.2.1",
            "fds": ["seccompFd"],
            "pid": 42,
            "metadata": crate::runtime_admission::SECCOMP_LISTENER_METADATA,
            "state": {
                "ociVersion": "1.2.1",
                "id": "a".repeat(64),
                "status": "creating",
                "pid": 42,
                "bundle": "/run/containerd/bundle",
                "annotations": {}
            }
        }))
        .context(crate::error::JsonSnafu {
            path: "test-runc-seccomp-process-state",
        })
    }

    #[test]
    fn runc_process_state_requires_the_owned_listener_contract() -> crate::Result<()> {
        let state = process_state()?;
        state.validate()?;
        assert_eq!(state.container_id(), "a".repeat(64));
        Ok(())
    }

    #[test]
    fn initial_notification_requires_the_exact_runc_pid_and_exec_syscall() -> crate::Result<()> {
        let state = process_state()?;
        let mut notification = libc::seccomp_notif {
            id: 7,
            pid: 42,
            flags: 0,
            data: libc::seccomp_data {
                nr: libc::SYS_execve as i32,
                arch: 0,
                instruction_pointer: 0,
                args: [0; 6],
            },
        };
        validate_notification(&state, &notification, true)?;

        notification.pid = 43;
        assert!(validate_notification(&state, &notification, true).is_err());
        notification.pid = 42;
        notification.data.nr = libc::SYS_mount as i32;
        assert!(validate_notification(&state, &notification, true).is_err());
        Ok(())
    }
}
