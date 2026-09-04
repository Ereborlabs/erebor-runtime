#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::ioctl::{opcode, Setter, Updater};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotificationListenerReadiness {
    Pending,
    Readable,
    Closed,
}

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
    pub executable_path: Option<PathBuf>,
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
    delivered: oneshot::Sender<bool>,
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

#[cfg(feature = "test-support")]
pub struct RuntimeSeccompTestServer {
    server: RuntimeSeccompServer,
}

#[cfg(feature = "test-support")]
pub struct RuntimeSeccompTestReceiver {
    receiver: RuntimeSeccompReceiver,
}

#[cfg(feature = "test-support")]
pub struct RuntimeSeccompTestNotification {
    envelope: RuntimeSeccompEnvelope,
}

impl OciContainerProcessStateV1 {
    pub(crate) fn container_id(&self) -> &str {
        &self.state.id
    }

    pub(crate) fn annotations(&self) -> &BTreeMap<String, String> {
        &self.state.annotations
    }

    fn requires_protected_admission(&self) -> bool {
        self.state
            .annotations
            .get(crate::runtime_admission::PROFILE_ID_ANNOTATION)
            .is_some_and(|profile| !profile.is_empty())
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

    pub(crate) async fn respond(self, allowed: bool) -> Result<bool> {
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
        let delivered = tokio::time::timeout_at(self.deadline, delivery)
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
        Ok(delivered)
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
        let first_noninitial_continued = process.status() == "running"
            && continue_first_noninitial_notification(&listener, timeout)?;
        let listener = AsyncFd::new(listener).context(IoSnafu { path: socket_path })?;
        let mut sequence = u64::from(first_noninitial_continued);
        loop {
            if sequence > 0 || process.status() == "running" {
                if !continue_noninitial_notification(&listener).await? {
                    return Ok(());
                }
                sequence = sequence.checked_add(1).context(IdentityStateSnafu {
                    reason: "runtime exec notification sequence overflowed",
                })?;
                continue;
            }
            let Some(notification) = receive_notification(&listener).await? else {
                return Ok(());
            };
            let initial_exec = sequence == 0 && process.status() == "creating";
            validate_notification(&process, &notification, initial_exec)?;
            if !notification_is_valid(&listener, notification.id)? {
                continue;
            }
            let executable_path = if initial_exec {
                match read_executable_path(&notification) {
                    Ok(path) => Some(path),
                    Err(_error) if !notification_is_valid(&listener, notification.id)? => continue,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let expected_executable_path = executable_path.clone();
            if !process.requires_protected_admission() {
                if respond_to_notification(
                    &listener,
                    &process,
                    notification,
                    initial_exec,
                    expected_executable_path.as_deref(),
                    true,
                    Instant::now() + timeout,
                )
                .await?
                {
                    sequence = sequence.checked_add(1).context(IdentityStateSnafu {
                        reason: "runtime exec notification sequence overflowed",
                    })?;
                }
                continue;
            }
            let pid = Pid::from_raw(notification.pid as i32).context(IdentityStateSnafu {
                reason: "runtime exec notification has an invalid PID",
            })?;
            let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
                Ok(pidfd) => pidfd,
                Err(_error) if !notification_is_valid(&listener, notification.id)? => continue,
                Err(error) => {
                    return Err(std::io::Error::from(error)).context(IoSnafu {
                        path: PathBuf::from(format!("/proc/{}", notification.pid)),
                    });
                }
            };
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
            let allowed = dispatched.allowed;
            let delivered = respond_to_notification(
                &listener,
                &process,
                notification,
                initial_exec,
                expected_executable_path.as_deref(),
                allowed,
                deadline,
            )
            .await?;
            let _result = dispatched.delivered.send(delivered);
            if delivered {
                sequence = sequence.checked_add(1).context(IdentityStateSnafu {
                    reason: "runtime exec notification sequence overflowed",
                })?;
            }
        }
    }
}

fn continue_first_noninitial_notification(listener: &OwnedFd, timeout: Duration) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout.min(Duration::from_millis(100));
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let remaining_ms = deadline
            .saturating_duration_since(now)
            .as_millis()
            .clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, remaining_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context(IoSnafu {
                path: Path::new("seccomp notification fd"),
            });
        }
        if ready == 0 {
            return Ok(false);
        }
        if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(false);
        }
        let mut notification = empty_notification();
        let received = unsafe {
            rustix::ioctl::ioctl(
                listener,
                Updater::<SECCOMP_IOCTL_NOTIF_RECV, libc::seccomp_notif>::new(&mut notification),
            )
        };
        if let Err(error) = received {
            if matches!(error, rustix::io::Errno::NOENT | rustix::io::Errno::INTR) {
                continue;
            }
            return Err(std::io::Error::from(error)).context(IoSnafu {
                path: Path::new("seccomp notification fd"),
            });
        }
        ensure!(
            notification_is_one_exec(&notification),
            IdentityStateSnafu {
                reason: "runtime seccomp notification is not one exact exec request",
            }
        );
        let response = libc::seccomp_notif_resp {
            id: notification.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };
        match unsafe {
            rustix::ioctl::ioctl(
                listener,
                Setter::<SECCOMP_IOCTL_NOTIF_SEND, libc::seccomp_notif_resp>::new(response),
            )
        } {
            Ok(()) => return Ok(true),
            Err(error) if notification_response_was_canceled(error) => {
                continue;
            }
            Err(error) => {
                return Err(std::io::Error::from(error)).context(IoSnafu {
                    path: Path::new("seccomp notification fd"),
                });
            }
        }
    }
}

async fn continue_noninitial_notification(listener: &AsyncFd<OwnedFd>) -> Result<bool> {
    loop {
        let mut ready = listener.readable().await.context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        })?;
        match notification_listener_readiness(listener.get_ref()).context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        })? {
            NotificationListenerReadiness::Closed => return Ok(false),
            NotificationListenerReadiness::Pending => {
                ready.clear_ready();
                continue;
            }
            NotificationListenerReadiness::Readable => ready.clear_ready(),
        }
        let mut notification = empty_notification();
        let received = unsafe {
            rustix::ioctl::ioctl(
                listener.get_ref(),
                Updater::<SECCOMP_IOCTL_NOTIF_RECV, libc::seccomp_notif>::new(&mut notification),
            )
        };
        if let Err(error) = received {
            let error = std::io::Error::from(error);
            if notification_receive_was_canceled(&error) {
                tokio::task::yield_now().await;
                continue;
            }
            return Err(error).context(IoSnafu {
                path: Path::new("seccomp notification fd"),
            });
        }
        ensure!(
            notification_is_one_exec(&notification),
            IdentityStateSnafu {
                reason: "runtime seccomp notification is not one exact exec request",
            }
        );
        let response = libc::seccomp_notif_resp {
            id: notification.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };
        match unsafe {
            rustix::ioctl::ioctl(
                listener.get_ref(),
                Setter::<SECCOMP_IOCTL_NOTIF_SEND, libc::seccomp_notif_resp>::new(response),
            )
        } {
            Ok(()) => return Ok(true),
            Err(error) if notification_response_was_canceled(error) => {
                tokio::task::yield_now().await;
            }
            Err(error) => {
                return Err(std::io::Error::from(error)).context(IoSnafu {
                    path: Path::new("seccomp notification fd"),
                });
            }
        }
    }
}

impl RuntimeSeccompReceiver {
    pub(crate) async fn receive(&mut self) -> Option<RuntimeSeccompEnvelope> {
        self.notifications.recv().await
    }
}

#[cfg(feature = "test-support")]
impl RuntimeSeccompTestServer {
    pub fn bind(
        socket_path: &Path,
        timeout: Duration,
    ) -> Result<(Self, RuntimeSeccompTestReceiver)> {
        let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("runtime seccomp test timeout is invalid: {error}"),
            }
            .build()
        })?;
        let config = RuntimeAdmissionConfig {
            socket_path: socket_path.to_owned(),
            trusted_start_hook_path: PathBuf::from("/mithril-test-hook"),
            maximum_request_bytes: MAXIMUM_PROCESS_STATE_BYTES,
            timeout_ms,
        };
        let (server, receiver) = RuntimeSeccompServer::bind(&config)?;
        Ok((Self { server }, RuntimeSeccompTestReceiver { receiver }))
    }

    #[must_use]
    pub fn listener_path(&self) -> &Path {
        &self.server.socket_path
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        self.server.serve(shutdown).await
    }

    #[must_use]
    pub const fn listener_metadata() -> &'static str {
        crate::runtime_admission::SECCOMP_LISTENER_METADATA
    }
}

#[cfg(feature = "test-support")]
impl RuntimeSeccompTestReceiver {
    pub async fn receive(&mut self) -> Option<RuntimeSeccompTestNotification> {
        self.receiver
            .receive()
            .await
            .map(|envelope| RuntimeSeccompTestNotification { envelope })
    }
}

#[cfg(feature = "test-support")]
impl RuntimeSeccompTestNotification {
    #[must_use]
    pub fn container_id(&self) -> &str {
        self.envelope.process.container_id()
    }

    #[must_use]
    pub fn process_pid(&self) -> i32 {
        self.envelope.process.process_pid()
    }

    #[must_use]
    pub fn state_pid(&self) -> i32 {
        self.envelope.process.state_pid()
    }

    #[must_use]
    pub fn status(&self) -> &str {
        self.envelope.process.status()
    }

    #[must_use]
    pub fn bundle(&self) -> &Path {
        self.envelope.process.bundle()
    }

    #[must_use]
    pub fn notification_id(&self) -> u64 {
        self.envelope.notification.id
    }

    #[must_use]
    pub fn notification_pid(&self) -> u32 {
        self.envelope.notification.pid
    }

    #[must_use]
    pub fn syscall(&self) -> i32 {
        self.envelope.notification.syscall
    }

    #[must_use]
    pub fn executable_path(&self) -> Option<&Path> {
        self.envelope.notification.executable_path.as_deref()
    }

    #[must_use]
    pub fn initial_exec(&self) -> bool {
        self.envelope.notification.initial_exec
    }

    pub async fn respond(self, allowed: bool) -> Result<bool> {
        self.envelope.respond(allowed).await
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

async fn receive_notification(listener: &AsyncFd<OwnedFd>) -> Result<Option<libc::seccomp_notif>> {
    loop {
        let mut ready = listener.readable().await.context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        })?;
        match notification_listener_readiness(listener.get_ref()).context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        })? {
            NotificationListenerReadiness::Closed => return Ok(None),
            NotificationListenerReadiness::Pending => {
                ready.clear_ready();
                continue;
            }
            NotificationListenerReadiness::Readable => ready.clear_ready(),
        }
        let mut request = empty_notification();
        match unsafe {
            rustix::ioctl::ioctl(
                listener.get_ref(),
                Updater::<SECCOMP_IOCTL_NOTIF_RECV, libc::seccomp_notif>::new(&mut request),
            )
        } {
            Ok(()) => return Ok(Some(request)),
            Err(error) => {
                let error = std::io::Error::from(error);
                if !notification_receive_was_canceled(&error) {
                    return Err(error).context(IoSnafu {
                        path: Path::new("seccomp notification fd"),
                    });
                }
                tokio::task::yield_now().await;
            }
        }
    }
}

fn notification_listener_readiness(
    listener: &OwnedFd,
) -> std::io::Result<NotificationListenerReadiness> {
    let mut descriptor = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ready == 0 {
        return Ok(NotificationListenerReadiness::Pending);
    }
    if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Ok(NotificationListenerReadiness::Closed);
    }
    if descriptor.revents & libc::POLLIN != 0 {
        return Ok(NotificationListenerReadiness::Readable);
    }
    Ok(NotificationListenerReadiness::Pending)
}

fn notification_receive_was_canceled(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINTR))
}

fn notification_response_was_canceled(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::NOENT | rustix::io::Errno::INPROGRESS
    )
}

const fn empty_notification() -> libc::seccomp_notif {
    libc::seccomp_notif {
        id: 0,
        pid: 0,
        flags: 0,
        data: libc::seccomp_data {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        },
    }
}

async fn respond_to_notification(
    listener: &AsyncFd<OwnedFd>,
    process: &OciContainerProcessStateV1,
    mut notification: libc::seccomp_notif,
    initial_exec: bool,
    expected_executable_path: Option<&Path>,
    allowed: bool,
    deadline: Instant,
) -> Result<bool> {
    let syscall = notification.data.nr;
    loop {
        let response = libc::seccomp_notif_resp {
            id: notification.id,
            val: 0,
            error: if allowed { 0 } else { -libc::EPERM },
            flags: if allowed {
                libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32
            } else {
                0
            },
        };
        match unsafe {
            rustix::ioctl::ioctl(
                listener,
                Setter::<SECCOMP_IOCTL_NOTIF_SEND, libc::seccomp_notif_resp>::new(response),
            )
        } {
            Ok(()) => return Ok(true),
            Err(error) if notification_response_was_canceled(error) => {}
            Err(error) => {
                return Err(std::io::Error::from(error)).context(IoSnafu {
                    path: Path::new("seccomp notification fd"),
                });
            }
        }
        notification = match tokio::time::timeout_at(deadline, receive_notification(listener)).await
        {
            Ok(notification) => match notification? {
                Some(notification) => notification,
                None => return Ok(false),
            },
            Err(_elapsed) => return Ok(false),
        };
        validate_notification(process, &notification, initial_exec)?;
        ensure!(
            notification.data.nr == syscall,
            IdentityStateSnafu {
                reason: "retried runtime seccomp notification changed syscall",
            }
        );
        if initial_exec {
            let executable_path = match read_executable_path(&notification) {
                Ok(path) => path,
                Err(_error) if !notification_is_valid(listener, notification.id)? => continue,
                Err(error) => return Err(error),
            };
            ensure!(
                expected_executable_path == Some(executable_path.as_path()),
                IdentityStateSnafu {
                    reason: "retried runtime seccomp notification changed executable",
                }
            );
        }
    }
}

fn notification_is_valid(listener: &AsyncFd<OwnedFd>, id: u64) -> Result<bool> {
    let valid = unsafe {
        rustix::ioctl::ioctl(
            listener,
            Setter::<SECCOMP_IOCTL_NOTIF_ID_VALID, u64>::new(id),
        )
    };
    if let Err(error) = valid {
        if error == rustix::io::Errno::NOENT {
            return Ok(false);
        }
        return Err(std::io::Error::from(error)).context(IoSnafu {
            path: Path::new("seccomp notification fd"),
        });
    }
    Ok(true)
}

fn validate_notification(
    process: &OciContainerProcessStateV1,
    notification: &libc::seccomp_notif,
    initial_exec: bool,
) -> Result<()> {
    ensure!(
        notification_is_one_exec(notification)
            && (!initial_exec || notification.pid == process.process_pid() as u32),
        IdentityStateSnafu {
            reason: "seccomp notification is not one exact exec request",
        }
    );
    Ok(())
}

fn notification_is_one_exec(notification: &libc::seccomp_notif) -> bool {
    notification.id > 0
        && notification.pid > 0
        && notification.flags == 0
        && matches!(
            notification.data.nr as libc::c_long,
            libc::SYS_execve | libc::SYS_execveat
        )
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
    if read <= 0 {
        return IdentityStateSnafu {
            reason: format!(
                "exec notification executable path is unreadable: {}",
                std::io::Error::last_os_error()
            ),
        }
        .fail();
    }
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
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    use snafu::ResultExt as _;

    use super::{
        empty_notification, notification_listener_readiness, notification_receive_was_canceled,
        notification_response_was_canceled, validate_notification, NotificationListenerReadiness,
        OciContainerProcessStateV1,
    };

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
        assert!(!state.requires_protected_admission());
        Ok(())
    }

    #[test]
    fn only_a_nonempty_profile_routes_exec_to_protected_admission() -> crate::Result<()> {
        let mut state = process_state()?;
        state.state.annotations.insert(
            crate::runtime_admission::PROFILE_ID_ANNOTATION.to_owned(),
            String::new(),
        );
        assert!(!state.requires_protected_admission());
        state.state.annotations.insert(
            crate::runtime_admission::PROFILE_ID_ANNOTATION.to_owned(),
            "11111111-1111-4111-8111-111111111111".to_owned(),
        );
        assert!(state.requires_protected_admission());
        Ok(())
    }

    #[test]
    fn notification_receive_buffer_starts_zeroed() {
        let notification = empty_notification();
        assert_eq!(notification.id, 0);
        assert_eq!(notification.pid, 0);
        assert_eq!(notification.flags, 0);
        assert_eq!(notification.data.nr, 0);
        assert_eq!(notification.data.arch, 0);
        assert_eq!(notification.data.instruction_pointer, 0);
        assert_eq!(notification.data.args, [0; 6]);
    }

    #[test]
    fn canceled_notification_receive_is_retryable() {
        for errno in [libc::ENOENT, libc::EINTR] {
            assert!(notification_receive_was_canceled(
                &std::io::Error::from_raw_os_error(errno)
            ));
        }
        assert!(!notification_receive_was_canceled(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
    }

    #[test]
    fn canceled_notification_response_is_retryable() {
        for errno in [rustix::io::Errno::NOENT, rustix::io::Errno::INPROGRESS] {
            assert!(notification_response_was_canceled(errno));
        }
        assert!(!notification_response_was_canceled(
            rustix::io::Errno::INVAL
        ));
    }

    #[test]
    fn closed_notification_listener_is_detected_before_receive() -> std::io::Result<()> {
        let mut descriptors = [-1; 2];
        let status = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
        assert_eq!(status, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        assert_eq!(
            notification_listener_readiness(&reader)?,
            NotificationListenerReadiness::Pending
        );
        let byte = [1_u8];
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), byte.as_ptr().cast(), byte.len()) },
            1
        );
        assert_eq!(
            notification_listener_readiness(&reader)?,
            NotificationListenerReadiness::Readable
        );
        drop(writer);
        assert_eq!(
            notification_listener_readiness(&reader)?,
            NotificationListenerReadiness::Closed
        );
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
