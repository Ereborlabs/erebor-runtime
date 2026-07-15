use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, PermissionsExt},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use erebor_runtime_core::CodexHookEvent;
use erebor_runtime_filesystem::LinuxReadOnlySessionProjection;
use erebor_runtime_ipc::{
    v1::{
        Envelope, HookEvent, HookEventKind, HookHello, HookHelloAck, HookRejection,
        HookRejectionCode, HookResult, KIND_HOOK_EVENT, KIND_HOOK_HELLO, KIND_HOOK_HELLO_ACK,
        KIND_HOOK_REJECTION, KIND_HOOK_RESULT, PROTOCOL_VERSION,
    },
    EreborIpcFrame,
};
use snafu::{ensure, ResultExt};

use super::{
    error::{HookBrokerIoSnafu, HookBrokerProtocolSnafu, InvalidHookEventSnafu},
    CodexManagedSession, CodexSessionError,
};

const BROKER_SOCKET: &str = "codex-hook.sock";
const HOST_BROKER_DIRECTORY_PREFIX: &str = "erebor-codex-hook-";
const SESSION_BROKER_DIRECTORY: &str = "/run/erebor";
const SESSION_BROKER_ENDPOINT: &str = "/run/erebor/codex-hook.sock";
const MAX_NATIVE_EVENT_BYTES: usize = 32 * 1024;

/// Stable local Unix endpoint for a single managed Codex session. Its socket
/// directory is projected read-only at `/run/erebor` inside that session.
pub(crate) struct CodexHookBroker {
    directory: PathBuf,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl CodexHookBroker {
    pub(crate) fn start(managed_session: CodexManagedSession) -> Result<Self, CodexSessionError> {
        let directory = Self::create_socket_directory()?;
        let socket = directory.join(BROKER_SOCKET);
        let _result = fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).context(HookBrokerIoSnafu)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .context(HookBrokerIoSnafu)?;
        listener.set_nonblocking(true).context(HookBrokerIoSnafu)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _address)) => {
                        let session = managed_session.clone();
                        thread::spawn(move || {
                            let _result = stream.set_read_timeout(Some(Duration::from_secs(10)));
                            let _result = stream.set_write_timeout(Some(Duration::from_secs(10)));
                            let _result = CodexHookBrokerProtocol::new(session).serve(&mut stream);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_error) => thread::sleep(Duration::from_millis(1)),
                }
            }
        });
        Ok(Self {
            directory,
            shutdown,
            worker: Mutex::new(Some(worker)),
        })
    }

    fn create_socket_directory() -> Result<PathBuf, CodexSessionError> {
        for _attempt in 0..16 {
            let mut random = [0_u8; 12];
            fs::File::open("/dev/urandom")
                .and_then(|mut file| file.read_exact(&mut random))
                .context(HookBrokerIoSnafu)?;
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let directory =
                Path::new("/tmp").join(format!("{HOST_BROKER_DIRECTORY_PREFIX}{suffix}"));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                        .context(HookBrokerIoSnafu)?;
                    return Ok(directory);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context(HookBrokerIoSnafu),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to allocate a unique Codex hook broker directory",
        ))
        .context(HookBrokerIoSnafu)
    }

    pub(crate) fn session_projection(
        &self,
    ) -> Result<LinuxReadOnlySessionProjection, CodexSessionError> {
        LinuxReadOnlySessionProjection::new(&self.directory, SESSION_BROKER_DIRECTORY).map_err(
            |source| CodexSessionError::FilesystemProjection {
                source: Box::new(source),
                location: snafu::Location::default(),
            },
        )
    }

    #[must_use]
    pub(crate) const fn session_endpoint() -> &'static str {
        SESSION_BROKER_ENDPOINT
    }
}

impl Drop for CodexHookBroker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _result = UnixStream::connect(self.directory.join(BROKER_SOCKET));
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                let _result = worker.join();
            }
        }
        let _result = fs::remove_file(self.directory.join(BROKER_SOCKET));
        let _result = fs::remove_dir(&self.directory);
    }
}

struct CodexHookBrokerProtocol {
    managed_session: CodexManagedSession,
}

impl CodexHookBrokerProtocol {
    const fn new(managed_session: CodexManagedSession) -> Self {
        Self { managed_session }
    }

    fn serve(&self, stream: &mut UnixStream) -> Result<(), CodexSessionError> {
        let hello_envelope = Self::read_envelope(stream)?;
        let hello: HookHello = hello_envelope
            .decode_typed_payload(KIND_HOOK_HELLO)
            .context(HookBrokerProtocolSnafu)?;
        let observed_peer = LinuxHookPeerInspector::inspect(stream, &hello.ticket_id)?;
        let tickets = self.managed_session.hook_tickets();
        let ticket = match if hello.ticket_id.is_empty() {
            tickets.consume_matching_peer(&hello, &observed_peer)
        } else {
            tickets.consume(&hello, &observed_peer)
        } {
            Ok(ticket) => ticket,
            Err(error) => {
                Self::write_hello_ack(stream, &hello_envelope, false, error.to_string())?;
                return Ok(());
            }
        };
        Self::write_hello_ack(stream, &hello_envelope, true, String::new())?;

        while let Ok(envelope) = Self::read_envelope(stream) {
            if envelope.message_kind != KIND_HOOK_EVENT {
                Self::write_rejection(
                    stream,
                    &envelope,
                    HookRejectionCode::InvalidSchema,
                    "expected a hook event after successful hello",
                )?;
                break;
            }
            let event: HookEvent = envelope
                .decode_typed_payload(KIND_HOOK_EVENT)
                .context(HookBrokerProtocolSnafu)?;
            match self.validate_event(&event) {
                Ok(event_kind) => {
                    let result = HookResult {
                        event: event_kind as i32,
                        accepted: true,
                        result_json: br#"{"continue":true}"#.to_vec(),
                    };
                    let response = Envelope::wrap_message(
                        envelope.message_id.saturating_add(1),
                        envelope.message_id,
                        KIND_HOOK_RESULT,
                        &result,
                    )
                    .context(HookBrokerProtocolSnafu)?;
                    Self::write_envelope(stream, &response)?;
                }
                Err(error) => {
                    let code = if event.native_event_json.len() > MAX_NATIVE_EVENT_BYTES {
                        HookRejectionCode::EventTooLarge
                    } else {
                        HookRejectionCode::InvalidSchema
                    };
                    Self::write_rejection(stream, &envelope, code, error.to_string())?;
                    break;
                }
            }
        }
        let _ticket = ticket;
        Ok(())
    }

    fn validate_event(&self, event: &HookEvent) -> Result<HookEventKind, CodexSessionError> {
        ensure!(
            event.native_event_json.len() <= MAX_NATIVE_EVENT_BYTES,
            InvalidHookEventSnafu {
                reason: format!("native event is larger than {MAX_NATIVE_EVENT_BYTES} bytes")
            }
        );
        serde_json::from_slice::<serde_json::Value>(&event.native_event_json).map_err(|error| {
            CodexSessionError::InvalidHookEvent {
                reason: format!("native event JSON is malformed: {error}"),
                location: snafu::Location::default(),
            }
        })?;
        let event_kind = HookEventKind::try_from(event.event).map_err(|_error| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from("unknown hook event kind"),
                location: snafu::Location::default(),
            }
        })?;
        let codex_event = match event_kind {
            HookEventKind::SessionStart => CodexHookEvent::SessionStart,
            HookEventKind::UserPromptSubmit => CodexHookEvent::UserPromptSubmit,
            HookEventKind::PreToolUse => CodexHookEvent::PreToolUse,
            HookEventKind::PermissionRequest => CodexHookEvent::PermissionRequest,
            HookEventKind::PostToolUse => CodexHookEvent::PostToolUse,
            HookEventKind::SubagentStart => CodexHookEvent::SubagentStart,
            HookEventKind::SubagentStop => CodexHookEvent::SubagentStop,
            HookEventKind::Stop => CodexHookEvent::Stop,
            HookEventKind::Unspecified => {
                return InvalidHookEventSnafu {
                    reason: String::from("hook event kind is unspecified"),
                }
                .fail();
            }
        };
        let expected_schema = self
            .managed_session
            .profile()
            .event_schemas
            .iter()
            .find(|schema| schema.event == codex_event)
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: format!(
                    "event `{}` is not enabled by the managed profile",
                    codex_event.as_str()
                ),
                location: snafu::Location::default(),
            })?;
        ensure!(
            event.schema_sha256.is_empty() || event.schema_sha256 == expected_schema.sha256,
            InvalidHookEventSnafu {
                reason: format!(
                    "event `{}` schema fingerprint does not match",
                    codex_event.as_str()
                )
            }
        );
        Ok(event_kind)
    }

    fn read_envelope(stream: &mut UnixStream) -> Result<Envelope, CodexSessionError> {
        let frame = read_frame(stream)?;
        frame.decode_payload().context(HookBrokerProtocolSnafu)
    }

    fn write_hello_ack(
        stream: &mut UnixStream,
        request: &Envelope,
        accepted: bool,
        reason: String,
    ) -> Result<(), CodexSessionError> {
        let ack = HookHelloAck {
            protocol_version: PROTOCOL_VERSION,
            accepted,
            reason,
        };
        let response = Envelope::wrap_message(
            request.message_id.saturating_add(1),
            request.message_id,
            KIND_HOOK_HELLO_ACK,
            &ack,
        )
        .context(HookBrokerProtocolSnafu)?;
        Self::write_envelope(stream, &response)
    }

    fn write_rejection(
        stream: &mut UnixStream,
        request: &Envelope,
        code: HookRejectionCode,
        reason: impl Into<String>,
    ) -> Result<(), CodexSessionError> {
        let rejection = HookRejection {
            code: code as i32,
            reason: reason.into(),
        };
        let response = Envelope::wrap_message(
            request.message_id.saturating_add(1),
            request.message_id,
            KIND_HOOK_REJECTION,
            &rejection,
        )
        .context(HookBrokerProtocolSnafu)?;
        Self::write_envelope(stream, &response)
    }

    fn write_envelope(
        stream: &mut UnixStream,
        envelope: &Envelope,
    ) -> Result<(), CodexSessionError> {
        let frame = envelope.into_frame().context(HookBrokerProtocolSnafu)?;
        write_frame(stream, &frame)
    }
}

pub(super) struct LinuxHookPeerInspector;

impl LinuxHookPeerInspector {
    fn inspect(
        stream: &UnixStream,
        ticket_id: &str,
    ) -> Result<erebor_runtime_ipc::v1::HookPeerEvidence, CodexSessionError> {
        let credentials = rustix::net::sockopt::socket_peercred(stream.as_fd())
            .map_err(std::io::Error::from)
            .context(HookBrokerIoSnafu)?;
        let pid = credentials.pid.as_raw_pid();
        let process = LinuxHookProcess::inspect(pid)?;
        Ok(erebor_runtime_ipc::v1::HookPeerEvidence {
            ticket_id: ticket_id.to_owned(),
            observed_pid: i64::from(pid),
            process_start_time_ticks: process.start_time_ticks,
            executable: process.executable,
            argv: process.argv,
            cgroup_inode: process.cgroup_namespace_inode,
            mount_namespace_inode: process.mount_namespace_inode,
            stdin: Some(process.stdin),
            stdout: Some(process.stdout),
            pidfd_identity: process.start_time_ticks,
            exec_chain: process.exec_chain,
            observed_uid: credentials.uid.as_raw(),
            observed_gid: credentials.gid.as_raw(),
        })
    }

    pub(super) fn inspect_pid(
        pid: i32,
        ticket_id: &str,
    ) -> Result<erebor_runtime_ipc::v1::HookPeerEvidence, CodexSessionError> {
        let process = LinuxHookProcess::inspect(pid)?;
        let metadata = fs::metadata(format!("/proc/{pid}")).context(HookBrokerIoSnafu)?;
        Ok(erebor_runtime_ipc::v1::HookPeerEvidence {
            ticket_id: ticket_id.to_owned(),
            observed_pid: i64::from(pid),
            process_start_time_ticks: process.start_time_ticks,
            executable: process.executable,
            argv: process.argv,
            cgroup_inode: process.cgroup_namespace_inode,
            mount_namespace_inode: process.mount_namespace_inode,
            stdin: Some(process.stdin),
            stdout: Some(process.stdout),
            pidfd_identity: process.start_time_ticks,
            exec_chain: process.exec_chain,
            observed_uid: metadata.uid(),
            observed_gid: metadata.gid(),
        })
    }
}

struct LinuxHookProcess {
    start_time_ticks: u64,
    executable: String,
    argv: Vec<String>,
    cgroup_namespace_inode: u64,
    mount_namespace_inode: u64,
    stdin: erebor_runtime_ipc::v1::PipeIdentity,
    stdout: erebor_runtime_ipc::v1::PipeIdentity,
    exec_chain: Vec<String>,
}

impl LinuxHookProcess {
    fn inspect(pid: i32) -> Result<Self, CodexSessionError> {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let stat = fs::read_to_string(process.join("stat")).context(HookBrokerIoSnafu)?;
        let (parent_pid, start_time_ticks) = Self::stat_identities(&stat)?;
        let executable = fs::read_link(process.join("exe"))
            .context(HookBrokerIoSnafu)?
            .display()
            .to_string();
        let argv = fs::read(process.join("cmdline"))
            .context(HookBrokerIoSnafu)?
            .split(|byte| *byte == 0)
            .filter(|segment| !segment.is_empty())
            .map(|segment| String::from_utf8_lossy(segment).to_string())
            .collect();
        let parent_executable = fs::read_link(format!("/proc/{parent_pid}/exe"))
            .context(HookBrokerIoSnafu)?
            .display()
            .to_string();
        Ok(Self {
            start_time_ticks,
            executable: executable.clone(),
            argv,
            cgroup_namespace_inode: Self::inode(&process.join("ns/cgroup"))?,
            mount_namespace_inode: Self::inode(&process.join("ns/mnt"))?,
            stdin: Self::pipe_identity(&process.join("fd/0"))?,
            stdout: Self::pipe_identity(&process.join("fd/1"))?,
            exec_chain: vec![parent_executable, executable],
        })
    }

    fn stat_identities(stat: &str) -> Result<(i32, u64), CodexSessionError> {
        let (_name, fields) =
            stat.rsplit_once(") ")
                .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                    reason: String::from("unable to parse hook process stat record"),
                    location: snafu::Location::default(),
                })?;
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        let parent_pid = fields
            .get(1)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("hook process parent pid is invalid"),
                location: snafu::Location::default(),
            })?;
        let start_time_ticks = fields
            .get(19)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("hook process start identity is invalid"),
                location: snafu::Location::default(),
            })?;
        Ok((parent_pid, start_time_ticks))
    }

    fn inode(path: &Path) -> Result<u64, CodexSessionError> {
        fs::metadata(path)
            .context(HookBrokerIoSnafu)
            .map(|metadata| metadata.ino())
    }

    fn pipe_identity(
        path: &Path,
    ) -> Result<erebor_runtime_ipc::v1::PipeIdentity, CodexSessionError> {
        fs::metadata(path)
            .context(HookBrokerIoSnafu)
            .map(|metadata| erebor_runtime_ipc::v1::PipeIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<EreborIpcFrame, CodexSessionError> {
    let mut header = [0_u8; 12];
    stream.read_exact(&mut header).context(HookBrokerIoSnafu)?;
    let payload_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let mut source = header.to_vec();
    source.resize(12 + payload_len, 0);
    stream
        .read_exact(&mut source[12..])
        .context(HookBrokerIoSnafu)?;
    EreborIpcFrame::decode(&source).context(HookBrokerProtocolSnafu)
}

fn write_frame(stream: &mut UnixStream, frame: &EreborIpcFrame) -> Result<(), CodexSessionError> {
    let encoded = frame.encode().context(HookBrokerProtocolSnafu)?;
    stream.write_all(&encoded).context(HookBrokerIoSnafu)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use erebor_runtime_core::{
        CodexDeploymentMode, CodexHookEvent, CodexHookEventSchemaLayerConfig,
        CodexProfileLayerConfig, SessionRunnerKind,
    };
    use erebor_runtime_ipc::v1::HookEvent;

    use super::{CodexHookBrokerProtocol, HookEventKind, LinuxHookPeerInspector};
    use crate::{
        agents::codex::{CodexHookClient, CodexManagedSession},
        CodexSessionError,
    };

    #[test]
    fn inspector_observes_kernel_bound_unix_peer_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let (first, second) = UnixStream::pair()?;
        let peer = match LinuxHookPeerInspector::inspect(&first, "ticket") {
            Ok(peer) => peer,
            Err(CodexSessionError::HookBrokerIo { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        assert_eq!(peer.ticket_id, "ticket");
        assert_eq!(peer.observed_pid, i64::from(std::process::id()));
        assert!(!peer.executable.is_empty());
        assert!(!peer.exec_chain.is_empty());
        drop(second);
        Ok(())
    }

    #[test]
    fn broker_accepts_only_profile_pinned_event_schemas() -> Result<(), Box<dyn std::error::Error>>
    {
        let session = CodexManagedSession::for_test(profile());
        let broker = CodexHookBrokerProtocol::new(session);
        let valid = HookEvent {
            event: HookEventKind::SessionStart as i32,
            schema_sha256: "b".repeat(64),
            native_event_json: br#"{"session_id":"native"}"#.to_vec(),
        };
        assert_eq!(broker.validate_event(&valid)?, HookEventKind::SessionStart);

        let invalid = HookEvent {
            schema_sha256: "c".repeat(64),
            ..valid
        };
        assert!(matches!(
            broker.validate_event(&invalid),
            Err(CodexSessionError::InvalidHookEvent { .. })
        ));
        Ok(())
    }

    #[test]
    fn managed_hook_client_requires_a_guard_issued_kernel_peer_ticket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut broker_stream, mut hook_stream) = UnixStream::pair()?;
        let observed_peer = match LinuxHookPeerInspector::inspect(&broker_stream, "") {
            Ok(peer) => peer,
            Err(CodexSessionError::HookBrokerIo { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let session = CodexManagedSession::for_test(profile());
        let _ticket = session.issue_guarded_hook_ticket(observed_peer)?;
        let broker_session = session.clone();
        let worker = std::thread::spawn(move || {
            CodexHookBrokerProtocol::new(broker_session).serve(&mut broker_stream)
        });

        let result = CodexHookClient::submit_on_stream(
            &mut hook_stream,
            HookEvent {
                event: HookEventKind::SessionStart as i32,
                schema_sha256: "b".repeat(64),
                native_event_json: br#"{"session_id":"native"}"#.to_vec(),
            },
        )?;
        assert!(result.accepted);
        assert_eq!(result.result_json, br#"{"continue":true}"#);
        drop(hook_stream);
        let worker_result = worker
            .join()
            .map_err(|_panic| std::io::Error::other("broker worker panicked"))?;
        worker_result?;
        Ok(())
    }

    fn profile() -> CodexProfileLayerConfig {
        CodexProfileLayerConfig {
            id: String::from("test-profile"),
            runner: SessionRunnerKind::LinuxHost,
            executable: "/opt/codex/codex".into(),
            deployment: CodexDeploymentMode::LocalCooperative,
            profile_sha256: "a".repeat(64),
            trust_root: "/var/lib/erebor/codex".into(),
            requirements_source: "/var/lib/erebor/codex/requirements.toml".into(),
            requirements_sha256: "a".repeat(64),
            managed_hook_source: "/var/lib/erebor/codex/hooks/erebor-codex-hook".into(),
            managed_hook_sha256: "a".repeat(64),
            managed_hook_path: "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            shell_startup_source: "/var/lib/erebor/codex/hooks/shell-startup".into(),
            shell_startup_sha256: "a".repeat(64),
            shell_startup_path: "/usr/lib/erebor/codex-hooks/shell-startup".into(),
            hook_exec_history: vec![
                "/opt/codex/codex".into(),
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            ],
            event_schemas: vec![CodexHookEventSchemaLayerConfig {
                event: CodexHookEvent::SessionStart,
                sha256: "b".repeat(64),
            }],
        }
    }
}
