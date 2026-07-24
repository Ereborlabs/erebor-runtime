use std::{
    collections::HashMap,
    fs,
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

use erebor_runtime_core::SessionSpec;
use erebor_runtime_ipc::{
    v1::{
        Envelope, EnvelopeServiceFamily, HookEvent, HookEventKind, HookHello, HookHelloAck,
        HookRejection, HookRejectionCode, HookResult, KIND_HOOK_EVENT, KIND_HOOK_HELLO,
        KIND_HOOK_HELLO_ACK, KIND_HOOK_REJECTION, KIND_HOOK_RESULT, PROTOCOL_VERSION,
    },
    SyncFrameCodec,
};
use erebor_runtime_packages::{CodexHookEventName, CodexPackageDefinition};
use snafu::{ensure, ResultExt};

use crate::ChildSessionAdmissionHandler;

use super::{
    error::{HookBrokerIoSnafu, HookBrokerProtocolSnafu, InvalidHookEventSnafu},
    CodexAppServerRegistration, CodexCommandDispatch, CodexGuardLifecycleHandler,
    CodexInvocationLeaseOwner, CodexInvocationLeaseProfile, CodexInvocationLeaseTrust,
    CodexLeaseRuntimeEvidence, CodexManagedSession, CodexNativeHookEvent,
    CodexPromptReconciliation, CodexSessionError,
};

const BROKER_SOCKET: &str = "codex-hook.sock";
const SESSION_BROKER_ENDPOINT: &str = "/run/erebor/codex-hook.sock";
const MAX_NATIVE_EVENT_BYTES: usize = 32 * 1024;
const MAX_PROFILE_ANCESTOR_DEPTH: usize = 16;
const INVOCATION_LEASE_AUDIT_FILE: &str = "codex-invocation-leases.jsonl";

/// One daemon-owned hook listener shared by registered Codex sessions.
///
/// Registrations retain all session-local authorization state. The listener
/// only selects a registration after the managed hook identifies its session;
/// the selected registration still performs one-use ticket and kernel-peer
/// validation before processing any native event.
pub struct CodexHookService {
    endpoint: PathBuf,
    registrations: Arc<Mutex<HashMap<String, CodexHookRegistration>>>,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
struct CodexHookRegistration {
    managed_session: CodexManagedSession,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
}

/// Session-local Codex authorities retained by the shared listener's
/// registration table. It can extend only the already-created runtime-guard
/// router; it cannot access daemon control traffic.
pub struct CodexSessionHookRegistration {
    managed_session: CodexManagedSession,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    context_dag: Arc<super::CodexContextDag>,
}

impl CodexSessionHookRegistration {
    fn from_spec(
        spec: &SessionSpec,
        guard_executable: &Path,
        definition: &CodexPackageDefinition,
        context_repository: Arc<erebor_runtime_context::ContextRepository>,
    ) -> Result<Self, CodexSessionError> {
        let managed_session = CodexManagedSession::from_package(
            spec.session_id().as_str(),
            guard_executable.to_path_buf(),
            definition,
        )?;
        let dispatch = definition
            .hook_contract()
            .command_dispatch()
            .map(|dispatch| {
                CodexCommandDispatch::new(
                    dispatch.program().to_owned(),
                    dispatch.shell().display().to_string(),
                )
            });
        let trust = dispatch
            .map(CodexInvocationLeaseTrust::with_command_dispatch)
            .unwrap_or_default();
        let mut lease_profile = CodexInvocationLeaseProfile::new(
            managed_session.profile().id().to_owned(),
            managed_session.profile().executable().display().to_string(),
            managed_session
                .profile()
                .hook_exec_history()
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        );
        lease_profile.set_delegation_bridge(
            managed_session
                .profile()
                .delegation_bridge_path()
                .map(|path| path.display().to_string()),
        );
        let lease_owner = Arc::new(CodexInvocationLeaseOwner::new(
            spec.session_id().as_str(),
            erebor_runtime_events::ActorIdentity {
                id: String::from("agent"),
                kind: erebor_runtime_events::ActorKind::Agent,
            },
            lease_profile,
            trust,
            Some(
                spec.output()
                    .root()
                    .join("evidence")
                    .join(INVOCATION_LEASE_AUDIT_FILE),
            ),
        ));
        let context_dag = Arc::new(super::CodexContextDag::new(
            context_repository,
            spec.session_id().as_str(),
        ));
        lease_owner.set_context_dag(Arc::clone(&context_dag))?;
        Ok(Self {
            managed_session,
            reconciliation: Arc::new(CodexPromptReconciliation::default()),
            lease_owner,
            context_dag,
        })
    }

    #[must_use]
    pub fn with_interception_router(
        &self,
        router: crate::SessionInterceptionRouter,
        child_admissions: Arc<dyn ChildSessionAdmissionHandler>,
    ) -> crate::SessionInterceptionRouter {
        router
            .with_codex_invocation_lease_owner(Arc::clone(&self.lease_owner))
            .with_guard_lifecycle_handler(CodexGuardLifecycleHandler::new(
                self.managed_session.clone(),
                Arc::clone(&self.lease_owner),
                child_admissions,
            ))
    }

    #[must_use]
    pub fn app_server_registration(&self) -> CodexAppServerRegistration {
        CodexAppServerRegistration::new(
            self.managed_session.session_id(),
            Arc::clone(&self.context_dag),
            Arc::clone(&self.reconciliation),
            Arc::clone(&self.lease_owner),
        )
    }
}

impl CodexHookService {
    pub fn start(runtime_root: impl Into<PathBuf>) -> Result<Self, CodexSessionError> {
        let directory = runtime_root.into();
        fs::create_dir_all(&directory).context(HookBrokerIoSnafu)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .context(HookBrokerIoSnafu)?;
        let endpoint = directory.join(BROKER_SOCKET);
        match fs::remove_file(&endpoint) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context(HookBrokerIoSnafu),
        }
        let listener = UnixListener::bind(&endpoint).context(HookBrokerIoSnafu)?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o666))
            .context(HookBrokerIoSnafu)?;
        listener.set_nonblocking(true).context(HookBrokerIoSnafu)?;

        let registrations = Arc::new(Mutex::new(HashMap::<String, CodexHookRegistration>::new()));
        let worker_registrations = Arc::clone(&registrations);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _address)) => {
                        let registrations = Arc::clone(&worker_registrations);
                        thread::spawn(move || {
                            let _result = stream.set_read_timeout(Some(Duration::from_secs(10)));
                            let _result = stream.set_write_timeout(Some(Duration::from_secs(10)));
                            let hello_envelope =
                                CodexHookBrokerProtocol::read_envelope(&mut stream);
                            let Ok(hello_envelope) = hello_envelope else {
                                return;
                            };
                            let hello: Result<HookHello, _> = hello_envelope
                                .decode_typed_payload(KIND_HOOK_HELLO)
                                .context(HookBrokerProtocolSnafu);
                            let Ok(hello) = hello else {
                                return;
                            };
                            let registration = registrations
                                .lock()
                                .ok()
                                .and_then(|table| table.get(&hello.session_id).cloned());
                            let Some(registration) = registration else {
                                let _result = CodexHookBrokerProtocol::write_hello_ack(
                                    &mut stream,
                                    &hello_envelope,
                                    false,
                                    String::from(
                                        "no active Codex hook registration for this session",
                                    ),
                                );
                                return;
                            };
                            let _result = CodexHookBrokerProtocol::new(
                                registration.managed_session,
                                registration.reconciliation,
                                registration.lease_owner,
                            )
                            .serve_after_hello(
                                &mut stream,
                                hello_envelope,
                                hello,
                            );
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
            endpoint,
            registrations,
            shutdown,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub(crate) fn register(
        &self,
        managed_session: CodexManagedSession,
        reconciliation: Arc<CodexPromptReconciliation>,
        lease_owner: Arc<CodexInvocationLeaseOwner>,
    ) -> Result<(), CodexSessionError> {
        let session_id = managed_session.session_id().to_owned();
        let mut registrations = self
            .registrations
            .lock()
            .map_err(|_error| super::error::TicketRegistryLockSnafu.build())?;
        if registrations.contains_key(&session_id) {
            return Err(CodexSessionError::InvalidHookEvent {
                reason: format!("Codex hook session `{session_id}` is already registered"),
                location: snafu::Location::default(),
            });
        }
        registrations.insert(
            session_id,
            CodexHookRegistration {
                managed_session,
                reconciliation,
                lease_owner,
            },
        );
        Ok(())
    }

    pub fn register_session(
        &self,
        spec: &SessionSpec,
        guard_executable: &Path,
        definition: &CodexPackageDefinition,
        context_repository: Arc<erebor_runtime_context::ContextRepository>,
    ) -> Result<CodexSessionHookRegistration, CodexSessionError> {
        let registration = CodexSessionHookRegistration::from_spec(
            spec,
            guard_executable,
            definition,
            context_repository,
        )?;
        self.register(
            registration.managed_session.clone(),
            Arc::clone(&registration.reconciliation),
            Arc::clone(&registration.lease_owner),
        )?;
        Ok(registration)
    }

    pub fn unregister(&self, session_id: &str) -> Result<(), CodexSessionError> {
        self.registrations
            .lock()
            .map_err(|_error| super::error::TicketRegistryLockSnafu.build())?
            .remove(session_id);
        Ok(())
    }

    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    #[must_use]
    pub const fn session_endpoint() -> &'static str {
        SESSION_BROKER_ENDPOINT
    }
}

impl Drop for CodexHookService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _result = UnixStream::connect(&self.endpoint);
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                let _result = worker.join();
            }
        }
        let _result = fs::remove_file(&self.endpoint);
    }
}

struct CodexHookBrokerProtocol {
    managed_session: CodexManagedSession,
    reconciliation: std::sync::Arc<CodexPromptReconciliation>,
    lease_owner: std::sync::Arc<CodexInvocationLeaseOwner>,
}

impl CodexHookBrokerProtocol {
    const fn new(
        managed_session: CodexManagedSession,
        reconciliation: std::sync::Arc<CodexPromptReconciliation>,
        lease_owner: std::sync::Arc<CodexInvocationLeaseOwner>,
    ) -> Self {
        Self {
            managed_session,
            reconciliation,
            lease_owner,
        }
    }

    #[cfg(test)]
    fn serve(&self, stream: &mut UnixStream) -> Result<(), CodexSessionError> {
        let hello_envelope = Self::read_envelope(stream)?;
        let hello: HookHello = hello_envelope
            .decode_typed_payload(KIND_HOOK_HELLO)
            .context(HookBrokerProtocolSnafu)?;
        self.serve_after_hello(stream, hello_envelope, hello)
    }

    fn serve_after_hello(
        &self,
        stream: &mut UnixStream,
        hello_envelope: Envelope,
        hello: HookHello,
    ) -> Result<(), CodexSessionError> {
        if hello.session_id != self.managed_session.session_id() {
            Self::write_hello_ack(
                stream,
                &hello_envelope,
                false,
                String::from("Codex hook hello session does not match its registration"),
            )?;
            return Ok(());
        }
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
        let Some(runtime) = ticket.runtime_evidence() else {
            Self::write_hello_ack(
                stream,
                &hello_envelope,
                false,
                String::from("guard-issued hook ticket is missing profile runtime evidence"),
            )?;
            return Ok(());
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
            let event: HookEvent = match envelope
                .decode_typed_payload(KIND_HOOK_EVENT)
                .context(HookBrokerProtocolSnafu)
            {
                Ok(event) => event,
                Err(error) => {
                    Self::write_rejection(
                        stream,
                        &envelope,
                        HookRejectionCode::InvalidSchema,
                        error.to_string(),
                    )?;
                    break;
                }
            };
            match self.validate_event(&event) {
                Ok(event_kind) => {
                    let recording = (|| {
                        self.reconciliation
                            .record_authenticated_hook(event_kind, &event.native_event_json)?;
                        self.lease_owner.record_authenticated_hook(
                            event_kind,
                            &event.native_event_json,
                            runtime.clone(),
                            observed_peer.observed_pid,
                        )
                    })();
                    if let Err(error) = recording {
                        Self::write_rejection(
                            stream,
                            &envelope,
                            HookRejectionCode::BrokerUnavailable,
                            error.to_string(),
                        )?;
                        break;
                    }
                    let result = HookResult {
                        event: event_kind as i32,
                        accepted: true,
                        result_json: br#"{\"continue\":true}"#.to_vec(),
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
        let native_event =
            CodexNativeHookEvent::parse(&event.native_event_json).map_err(|reason| {
                CodexSessionError::InvalidHookEvent {
                    reason,
                    location: snafu::Location::default(),
                }
            })?;
        let event_kind = HookEventKind::try_from(event.event).map_err(|_error| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from("unknown hook event kind"),
                location: snafu::Location::default(),
            }
        })?;
        ensure!(
            event_kind == native_event.kind(),
            InvalidHookEventSnafu {
                reason: String::from("hook event kind does not match native hook_event_name")
            }
        );
        if event_kind == HookEventKind::Unspecified {
            return InvalidHookEventSnafu {
                reason: String::from("hook event kind is unspecified"),
            }
            .fail();
        }
        let package_event = package_event(event_kind);
        let expected_schema = self
            .managed_session
            .profile()
            .event_schema(&package_event)
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: format!(
                    "event `{}` is not enabled by the managed package",
                    event_kind.as_str_name()
                ),
                location: snafu::Location::default(),
            })?;
        ensure!(
            event.schema_sha256 == native_event.schema_sha256()
                && native_event.schema_sha256() == expected_schema.sha256(),
            InvalidHookEventSnafu {
                reason: format!(
                    "event `{}` schema fingerprint does not match its native shape or managed profile",
                    event_kind.as_str_name(),
                )
            }
        );
        Ok(event_kind)
    }

    fn read_envelope(stream: &mut UnixStream) -> Result<Envelope, CodexSessionError> {
        let frame = SyncFrameCodec::read_frame(stream).context(HookBrokerProtocolSnafu)?;
        let envelope: Envelope = frame.decode_payload().context(HookBrokerProtocolSnafu)?;
        envelope
            .validate_headers(EnvelopeServiceFamily::Hook)
            .context(HookBrokerProtocolSnafu)?;
        Ok(envelope)
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
        SyncFrameCodec::write_frame(stream, &frame).context(HookBrokerProtocolSnafu)
    }
}

fn package_event(event: erebor_runtime_ipc::v1::HookEventKind) -> CodexHookEventName {
    match event {
        erebor_runtime_ipc::v1::HookEventKind::SessionStart => CodexHookEventName::SessionStart,
        erebor_runtime_ipc::v1::HookEventKind::UserPromptSubmit => {
            CodexHookEventName::UserPromptSubmit
        }
        erebor_runtime_ipc::v1::HookEventKind::PreToolUse => CodexHookEventName::PreToolUse,
        erebor_runtime_ipc::v1::HookEventKind::PermissionRequest => {
            CodexHookEventName::PermissionRequest
        }
        erebor_runtime_ipc::v1::HookEventKind::PostToolUse => CodexHookEventName::PostToolUse,
        erebor_runtime_ipc::v1::HookEventKind::SubagentStart => CodexHookEventName::SubagentStart,
        erebor_runtime_ipc::v1::HookEventKind::SubagentStop => CodexHookEventName::SubagentStop,
        erebor_runtime_ipc::v1::HookEventKind::Stop => CodexHookEventName::Stop,
        erebor_runtime_ipc::v1::HookEventKind::Unspecified => CodexHookEventName::Stop,
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

    pub(super) fn runtime_evidence(
        peer: &erebor_runtime_ipc::v1::HookPeerEvidence,
        profile_executable: &Path,
    ) -> Result<CodexLeaseRuntimeEvidence, CodexSessionError> {
        let hook_pid = i32::try_from(peer.observed_pid).map_err(|_error| {
            CodexSessionError::InvalidHookEvent {
                reason: String::from("managed hook peer pid is outside the Linux pid range"),
                location: snafu::Location::default(),
            }
        })?;
        let process = LinuxHookProcess::inspect(hook_pid)?;
        process.profile_runtime(profile_executable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxProcessIdentity {
    pid: i32,
    parent_pid: i32,
    start_time_ticks: u64,
    executable: String,
}

impl LinuxProcessIdentity {
    fn inspect(pid: i32) -> Result<Self, CodexSessionError> {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let stat = fs::read_to_string(process.join("stat")).context(HookBrokerIoSnafu)?;
        let (parent_pid, start_time_ticks) = LinuxHookProcess::stat_identities(&stat)?;
        let executable = fs::read_link(process.join("exe"))
            .context(HookBrokerIoSnafu)?
            .display()
            .to_string();
        Ok(Self {
            pid,
            parent_pid,
            start_time_ticks,
            executable,
        })
    }
}

struct LinuxHookProcess {
    parent_pid: i32,
    parent_parent_pid: i32,
    parent_start_time_ticks: u64,
    parent_executable: String,
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
        let identity = LinuxProcessIdentity::inspect(pid)?;
        let argv = fs::read(process.join("cmdline"))
            .context(HookBrokerIoSnafu)?
            .split(|byte| *byte == 0)
            .filter(|segment| !segment.is_empty())
            .map(|segment| String::from_utf8_lossy(segment).to_string())
            .collect();
        let parent = LinuxProcessIdentity::inspect(identity.parent_pid)?;
        Ok(Self {
            parent_pid: parent.pid,
            parent_parent_pid: parent.parent_pid,
            parent_start_time_ticks: parent.start_time_ticks,
            parent_executable: parent.executable.clone(),
            start_time_ticks: identity.start_time_ticks,
            executable: identity.executable.clone(),
            argv,
            cgroup_namespace_inode: Self::inode(&process.join("ns/cgroup"))?,
            mount_namespace_inode: Self::inode(&process.join("ns/mnt"))?,
            stdin: Self::pipe_identity(&process.join("fd/0"))?,
            stdout: Self::pipe_identity(&process.join("fd/1"))?,
            exec_chain: vec![parent.executable, identity.executable],
        })
    }

    fn profile_runtime(
        &self,
        profile_executable: &Path,
    ) -> Result<CodexLeaseRuntimeEvidence, CodexSessionError> {
        let profile_executable = profile_executable.display().to_string();
        let mut ancestry = vec![LinuxProcessIdentity {
            pid: self.parent_pid,
            parent_pid: self.parent_parent_pid,
            start_time_ticks: self.parent_start_time_ticks,
            executable: self.parent_executable.clone(),
        }];
        if let Some(runtime) = Self::profile_runtime_from_ancestry(&profile_executable, &ancestry) {
            return Ok(Self::runtime_evidence_from(runtime));
        }
        while ancestry.len() < MAX_PROFILE_ANCESTOR_DEPTH {
            let Some(parent_pid) = ancestry
                .last()
                .map(|identity| identity.parent_pid)
                .filter(|parent_pid| *parent_pid > 1)
            else {
                break;
            };
            let parent = LinuxProcessIdentity::inspect(parent_pid)?;
            ancestry.push(parent);
            if let Some(runtime) =
                Self::profile_runtime_from_ancestry(&profile_executable, &ancestry)
            {
                return Ok(Self::runtime_evidence_from(runtime));
            }
        }
        Err(CodexSessionError::InvalidHookEvent {
            reason: format!(
                "managed hook process has no configured Codex executable ancestor `{profile_executable}`"
            ),
            location: snafu::Location::default(),
        })
    }

    fn runtime_evidence_from(identity: &LinuxProcessIdentity) -> CodexLeaseRuntimeEvidence {
        CodexLeaseRuntimeEvidence::new(
            i64::from(identity.pid),
            identity.start_time_ticks,
            identity.executable.clone(),
        )
    }

    fn profile_runtime_from_ancestry<'a>(
        profile_executable: &str,
        ancestry: &'a [LinuxProcessIdentity],
    ) -> Option<&'a LinuxProcessIdentity> {
        ancestry
            .iter()
            .find(|identity| identity.executable == profile_executable)
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

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream, path::PathBuf, sync::Arc};

    use erebor_runtime_events::{ActorIdentity, ActorKind};
    use erebor_runtime_ipc::v1::HookEvent;
    use erebor_runtime_packages::{
        CodexArtifact, CodexEntrypoint, CodexHookContract, CodexHookEventName,
        CodexHookEventSchema, CodexHookExec, CodexHookShell, CodexManagedArtifacts,
        CodexPackageDefinition, CodexSupportedPlatform, ContentDigest,
    };

    use super::{
        CodexHookBrokerProtocol, CodexInvocationLeaseOwner, CodexPromptReconciliation,
        HookEventKind, LinuxHookPeerInspector, LinuxHookProcess, LinuxProcessIdentity,
    };
    use crate::{
        agents::codex::{
            CodexHookClient, CodexInvocationLeaseProfile, CodexManagedSession, CodexNativeHookEvent,
        },
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
        let native_event_json = br#"{"hook_event_name":"SessionStart"}"#.to_vec();
        let native_event = CodexNativeHookEvent::parse(&native_event_json)?;
        let session = session("/opt/codex/codex", native_event.schema_sha256())?;
        let broker = CodexHookBrokerProtocol::new(
            session,
            Arc::new(CodexPromptReconciliation::default()),
            test_lease_owner(),
        );
        let valid = HookEvent {
            event: HookEventKind::SessionStart as i32,
            schema_sha256: native_event.schema_sha256().to_owned(),
            native_event_json,
        };
        assert_eq!(broker.validate_event(&valid)?, HookEventKind::SessionStart);

        let invalid = HookEvent {
            schema_sha256: "c".repeat(64),
            ..valid.clone()
        };
        assert!(matches!(
            broker.validate_event(&invalid),
            Err(CodexSessionError::InvalidHookEvent { .. })
        ));

        let omitted_schema = HookEvent {
            schema_sha256: String::new(),
            ..valid.clone()
        };
        assert!(matches!(
            broker.validate_event(&omitted_schema),
            Err(CodexSessionError::InvalidHookEvent { .. })
        ));

        let mismatched_kind = HookEvent {
            event: HookEventKind::PreToolUse as i32,
            ..valid
        };
        assert!(matches!(
            broker.validate_event(&mismatched_kind),
            Err(CodexSessionError::InvalidHookEvent { .. })
        ));
        Ok(())
    }

    #[test]
    fn profile_runtime_identity_skips_shell_ancestors() -> Result<(), Box<dyn std::error::Error>> {
        let ancestry = vec![
            LinuxProcessIdentity {
                pid: 300,
                parent_pid: 200,
                start_time_ticks: 30,
                executable: String::from("/usr/bin/zsh"),
            },
            LinuxProcessIdentity {
                pid: 200,
                parent_pid: 100,
                start_time_ticks: 20,
                executable: String::from("/usr/bin/sh"),
            },
            LinuxProcessIdentity {
                pid: 100,
                parent_pid: 1,
                start_time_ticks: 10,
                executable: String::from("/opt/codex/codex"),
            },
        ];

        let runtime =
            LinuxHookProcess::profile_runtime_from_ancestry("/opt/codex/codex", &ancestry)
                .ok_or_else(|| {
                    std::io::Error::other("configured Codex executable is not an ancestor")
                })?;

        assert_eq!(runtime.pid, 100);
        assert_eq!(runtime.start_time_ticks, 10);
        assert_eq!(runtime.executable, "/opt/codex/codex");
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
        let native_event_json = br#"{"hook_event_name":"SessionStart"}"#.to_vec();
        let native_event = CodexNativeHookEvent::parse(&native_event_json)?;
        let executable = observed_peer
            .exec_chain
            .first()
            .ok_or("test peer omitted its parent executable")?
            .clone();
        let session = session(executable, native_event.schema_sha256())?;
        let _ticket = session.issue_guarded_hook_ticket(observed_peer)?;
        let broker_session = session.clone();
        let worker = std::thread::spawn(move || {
            CodexHookBrokerProtocol::new(
                broker_session,
                Arc::new(CodexPromptReconciliation::default()),
                test_lease_owner(),
            )
            .serve(&mut broker_stream)
        });

        let result = CodexHookClient::submit_on_stream_for_session(
            &mut hook_stream,
            "session-test",
            HookEvent {
                event: HookEventKind::SessionStart as i32,
                schema_sha256: native_event.schema_sha256().to_owned(),
                native_event_json,
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

    #[test]
    fn broker_rejects_a_ticket_without_guard_captured_runtime(
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
        let native_event_json = br#"{"hook_event_name":"SessionStart"}"#.to_vec();
        let native_event = CodexNativeHookEvent::parse(&native_event_json)?;
        let session = session("/opt/codex/codex", native_event.schema_sha256())?;
        let _ticket = session.issue_hook_ticket(observed_peer)?;
        let broker_session = session.clone();
        let worker = std::thread::spawn(move || {
            CodexHookBrokerProtocol::new(
                broker_session,
                Arc::new(CodexPromptReconciliation::default()),
                test_lease_owner(),
            )
            .serve(&mut broker_stream)
        });

        let error = match CodexHookClient::submit_on_stream_for_session(
            &mut hook_stream,
            "session-test",
            HookEvent {
                event: HookEventKind::SessionStart as i32,
                schema_sha256: native_event.schema_sha256().to_owned(),
                native_event_json,
            },
        ) {
            Ok(_result) => {
                return Err(std::io::Error::other(
                    "the broker accepted a ticket without guard-time runtime evidence",
                )
                .into());
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CodexSessionError::HookRejected { stage, .. } if stage == "hello"
        ));
        drop(hook_stream);
        let worker_result = worker
            .join()
            .map_err(|_panic| std::io::Error::other("broker worker panicked"))?;
        worker_result?;
        Ok(())
    }

    #[test]
    fn managed_profile_uses_staged_executable_and_private_hook_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let staged_executable = "/var/lib/erebor/sessions/session-test/staging/executable";
        let definition = package(&"a".repeat(64))?;
        let session = CodexManagedSession::from_package(
            "session-test",
            staged_executable.into(),
            &definition,
        )?;
        let profile = session.profile();

        assert_eq!(
            profile.executable(),
            std::path::Path::new(staged_executable)
        );
        assert_eq!(
            profile.managed_hook_path(),
            std::path::Path::new("/run/erebor/codex/hooks/erebor-codex-hook")
        );
        assert_eq!(
            profile.hook_exec_history(),
            [
                std::path::PathBuf::from(staged_executable),
                std::path::PathBuf::from("/run/erebor/codex/hooks/erebor-codex-hook"),
            ]
        );
        Ok(())
    }

    #[test]
    fn invocation_lease_audit_is_a_file_inside_the_evidence_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let evidence = temporary.path().join("evidence");
        std::fs::create_dir(&evidence)?;
        let audit = evidence.join(super::INVOCATION_LEASE_AUDIT_FILE);
        let owner = test_lease_owner_with_audit(Some(audit.clone()));

        owner.record_authenticated_hook(
            HookEventKind::SessionStart,
            br#"{"hook_event_name":"SessionStart"}"#,
            super::CodexLeaseRuntimeEvidence::new(1, 2, String::from("/opt/codex/codex")),
            3,
        )?;

        assert!(audit.is_file());
        assert!(std::fs::read_to_string(audit)?.contains("session-start"));
        Ok(())
    }

    fn session(
        executable: impl Into<std::path::PathBuf>,
        schema_sha256: &str,
    ) -> Result<CodexManagedSession, Box<dyn std::error::Error>> {
        Ok(CodexManagedSession::from_package(
            "session-test",
            executable.into(),
            &package(schema_sha256)?,
        )?)
    }

    fn package(schema_sha256: &str) -> Result<CodexPackageDefinition, Box<dyn std::error::Error>> {
        let artifact = |path: &str, digest: char| {
            CodexArtifact::new(
                path.into(),
                ContentDigest::new(digest.to_string().repeat(64))?,
            )
        };
        let artifacts = CodexManagedArtifacts::new(
            artifact("/var/lib/erebor/codex/requirements.toml", 'a')?,
            "/run/erebor/codex/requirements.toml".into(),
            artifact("/var/lib/erebor/codex/hooks/erebor-codex-hook", 'b')?,
            "/run/erebor/codex/hooks/erebor-codex-hook".into(),
            artifact("/var/lib/erebor/codex/hooks/shell-startup", 'c')?,
            "/run/erebor/codex/hooks/shell-startup".into(),
            None,
            None,
        )?;
        Ok(CodexPackageDefinition::new(
            "codex-v1-test",
            ContentDigest::new("d".repeat(64))?,
            CodexSupportedPlatform::LinuxX86_64,
            vec![CodexEntrypoint::new(
                "codex-app-server",
                vec![String::from("app-server"), String::from("--stdio")],
                true,
            )?],
            artifacts,
            CodexHookContract::new(
                CodexHookShell::Direct,
                vec![
                    CodexHookExec::InstalledExecutable,
                    CodexHookExec::ManagedHook,
                ],
                vec![CodexHookEventSchema::new(
                    CodexHookEventName::SessionStart,
                    ContentDigest::new(schema_sha256.to_owned())?,
                )?],
                None,
            )?,
            None,
        )?)
    }

    fn test_lease_owner() -> Arc<CodexInvocationLeaseOwner> {
        test_lease_owner_with_audit(None)
    }

    fn test_lease_owner_with_audit(audit_path: Option<PathBuf>) -> Arc<CodexInvocationLeaseOwner> {
        Arc::new(CodexInvocationLeaseOwner::new(
            "session-test",
            ActorIdentity {
                id: String::from("agent-test"),
                kind: ActorKind::Agent,
            },
            CodexInvocationLeaseProfile::new(
                String::from("profile-test"),
                String::from("/opt/codex/codex"),
                vec![String::from(
                    "/usr/lib/erebor/codex-hooks/erebor-codex-hook",
                )],
            ),
            super::super::CodexInvocationLeaseTrust::default(),
            audit_path,
        ))
    }
}
