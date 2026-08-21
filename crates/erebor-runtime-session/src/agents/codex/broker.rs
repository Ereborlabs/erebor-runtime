use std::{
    collections::HashMap,
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
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
    transport::{UnixIncoming, UnixPeerIdentity, MAX_GRPC_MESSAGE_BYTES},
    v1::{
        hook_client_message, hook_server_message,
        hook_service_server::{HookService, HookServiceServer},
        HookClientMessage, HookEvent, HookEventKind, HookHello, HookHelloAck, HookRejection,
        HookRejectionCode, HookResult, HookServerMessage,
    },
};
use erebor_runtime_packages::{CodexHookEventName, CodexPackageDefinition};
use erebor_runtime_telemetry::warn;
use serde::Deserialize;
use serde_json::json;
use snafu::{ensure, ResultExt};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    ChildContextDelivery, ChildContextDeliveryHandler, ContextAgentControlHandler,
    ContextAgentControlResult, ContextOperationAdmissionHandler,
};

use super::{
    error::{HookBrokerIoSnafu, InvalidHookEventSnafu},
    CodexAppServerRegistration, CodexInvocationLeaseOwner, CodexInvocationLeaseProfile,
    CodexLeaseRuntimeEvidence, CodexManagedSession, CodexNativeHookEvent,
    CodexPromptReconciliation, CodexSessionError,
};

const BROKER_SOCKET: &str = "codex-hook.sock";
const SESSION_BROKER_ENDPOINT: &str = "/run/erebor/codex-hook.sock";
const MAX_NATIVE_EVENT_BYTES: usize = 32 * 1024;
const MAX_PROFILE_ANCESTOR_DEPTH: usize = 16;
const INVOCATION_LEASE_AUDIT_FILE: &str = "codex-invocation-leases.jsonl";

/// One Codex-adapter-owned hook listener shared by registered Codex sessions.
///
/// The daemon owns its process lifetime and supplies registrations. Those
/// registrations retain all session-local authorization state. The listener
/// selects a registration only after the managed hook identifies its session;
/// the selected registration still performs one-use ticket and kernel-peer
/// validation before processing any native event.
pub struct CodexHookService {
    endpoint: PathBuf,
    registrations: Arc<Mutex<HashMap<String, CodexHookRegistration>>>,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// The daemon-owned callbacks available to one registered Codex session.
/// They remain in-process extensions of the existing guarded hook listener;
/// none is a workload-facing channel.
pub struct CodexHookSessionHandlers {
    child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
    operation_admissions: Arc<dyn ContextOperationAdmissionHandler>,
    agent_controls: Arc<dyn ContextAgentControlHandler>,
}

impl CodexHookSessionHandlers {
    #[must_use]
    pub fn new(
        child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
        operation_admissions: Arc<dyn ContextOperationAdmissionHandler>,
        agent_controls: Arc<dyn ContextAgentControlHandler>,
    ) -> Self {
        Self {
            child_deliveries,
            operation_admissions,
            agent_controls,
        }
    }
}

#[derive(Clone)]
struct CodexHookRegistration {
    managed_session: CodexManagedSession,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    session_start_context: Option<String>,
    child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
    agent_controls: Arc<dyn ContextAgentControlHandler>,
}

/// Session-local Codex authorities retained by the shared listener's
/// registration table. It can extend only the already-created runtime-guard
/// router; it cannot access daemon control traffic.
pub struct CodexSessionHookRegistration {
    managed_session: CodexManagedSession,
    reconciliation: Arc<CodexPromptReconciliation>,
    lease_owner: Arc<CodexInvocationLeaseOwner>,
    context_dag: Arc<super::CodexContextDag>,
    session_start_context: Option<String>,
}

impl CodexSessionHookRegistration {
    fn from_spec(
        spec: &SessionSpec,
        runtime_executable: &Path,
        definition: &CodexPackageDefinition,
        context_repository: Arc<erebor_runtime_context::ContextRepository>,
    ) -> Result<Self, CodexSessionError> {
        let managed_session = CodexManagedSession::from_package(
            spec.session_id().as_str(),
            runtime_executable.to_path_buf(),
            definition,
        )?;
        let mut lease_profile =
            CodexInvocationLeaseProfile::new(managed_session.profile().id().to_owned());
        lease_profile.set_terminal_root_context(spec.tty());
        let lease_owner = Arc::new(CodexInvocationLeaseOwner::new(
            spec.session_id().as_str(),
            erebor_runtime_events::ActorIdentity {
                id: String::from("agent"),
                kind: erebor_runtime_events::ActorKind::Agent,
            },
            lease_profile,
            Some(
                spec.output()
                    .root()
                    .join("evidence")
                    .join(INVOCATION_LEASE_AUDIT_FILE),
            ),
        ));
        let context_dag = Arc::new(super::CodexContextDag::new(
            Arc::clone(&context_repository),
            spec.session_id().as_str(),
        ));
        lease_owner.set_context_dag(Arc::clone(&context_dag))?;
        let session_start_context = spec
            .parent_context()
            .map(|projection| {
                super::CodexContextDag::render_frozen_prompt_context(
                    context_repository.as_ref(),
                    projection,
                )
            })
            .transpose()?
            .flatten();
        Ok(Self {
            managed_session,
            reconciliation: Arc::new(CodexPromptReconciliation::default()),
            lease_owner,
            context_dag,
            session_start_context,
        })
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
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let listener = {
                let _runtime_guard = runtime.enter();
                tokio::net::UnixListener::from_std(listener)
            };
            let Ok(listener) = listener else {
                return;
            };
            let service = HookGrpc {
                registrations: worker_registrations,
            };
            let shutdown = async move {
                while !worker_shutdown.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let _result = runtime.block_on(
                tonic::transport::Server::builder()
                    .add_service(
                        HookServiceServer::new(service)
                            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
                    )
                    .serve_with_incoming_shutdown(UnixIncoming::new(listener), shutdown),
            );
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
        session_start_context: Option<String>,
        child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
        agent_controls: Arc<dyn ContextAgentControlHandler>,
    ) -> Result<(), CodexSessionError> {
        let session_id = managed_session.session_id().to_owned();
        let mut registrations = self
            .registrations
            .lock()
            .map_err(|_error| super::error::HookRegistryLockSnafu.build())?;
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
                session_start_context,
                child_deliveries,
                agent_controls,
            },
        );
        Ok(())
    }

    pub fn register_session(
        &self,
        spec: &SessionSpec,
        runtime_executable: &Path,
        definition: &CodexPackageDefinition,
        context_repository: Arc<erebor_runtime_context::ContextRepository>,
        handlers: CodexHookSessionHandlers,
    ) -> Result<CodexSessionHookRegistration, CodexSessionError> {
        let registration = CodexSessionHookRegistration::from_spec(
            spec,
            runtime_executable,
            definition,
            context_repository,
        )?;
        registration
            .lease_owner
            .set_operation_admission_handler(Arc::clone(&handlers.operation_admissions))?;
        registration
            .context_dag
            .set_operation_admission_handler(handlers.operation_admissions)?;
        self.register(
            registration.managed_session.clone(),
            Arc::clone(&registration.reconciliation),
            Arc::clone(&registration.lease_owner),
            registration.session_start_context.clone(),
            handlers.child_deliveries,
            handlers.agent_controls,
        )?;
        Ok(registration)
    }

    pub fn unregister(&self, session_id: &str) -> Result<(), CodexSessionError> {
        self.registrations
            .lock()
            .map_err(|_error| super::error::HookRegistryLockSnafu.build())?
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
    session_start_context: Option<String>,
    child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
    agent_controls: Arc<dyn ContextAgentControlHandler>,
}

#[derive(Clone)]
struct HookGrpc {
    registrations: Arc<Mutex<HashMap<String, CodexHookRegistration>>>,
}

#[tonic::async_trait]
impl HookService for HookGrpc {
    type OpenStream = ReceiverStream<Result<HookServerMessage, Status>>;

    async fn open(
        &self,
        request: Request<Streaming<HookClientMessage>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let peer = request
            .extensions()
            .get::<UnixPeerIdentity>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("Unix peer credentials are unavailable"))?;
        let registrations = Arc::clone(&self.registrations);
        let mut input = request.into_inner();
        let (output, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let first = tokio::time::timeout(Duration::from_secs(10), input.message()).await;
            let hello = match first {
                Ok(Ok(Some(HookClientMessage {
                    item: Some(hook_client_message::Item::Hello(hello)),
                }))) => hello,
                Ok(Ok(_)) => {
                    send_hook_ack(&output, false, "the first hook message must be a hello").await;
                    return;
                }
                Ok(Err(_status)) => return,
                Err(_elapsed) => {
                    send_hook_ack(&output, false, "the hook hello deadline expired").await;
                    return;
                }
            };
            let registration = registrations
                .lock()
                .ok()
                .and_then(|table| table.get(&hello.session_id).cloned());
            let Some(registration) = registration else {
                send_hook_ack(
                    &output,
                    false,
                    "no active Codex hook registration exists for this session",
                )
                .await;
                return;
            };
            let protocol = CodexHookBrokerProtocol::new(
                registration.managed_session,
                registration.reconciliation,
                registration.lease_owner,
                registration.session_start_context,
                registration.child_deliveries,
                registration.agent_controls,
            );
            let (runtime, observed_peer) = match protocol.authenticate(&peer, &hello) {
                Ok(authenticated) => authenticated,
                Err(error) => {
                    send_hook_ack(&output, false, &error.to_string()).await;
                    return;
                }
            };
            send_hook_ack(&output, true, "").await;

            loop {
                let message = match input.message().await {
                    Ok(Some(message)) => message,
                    Ok(None) | Err(_) => return,
                };
                let Some(hook_client_message::Item::Event(event)) = message.item else {
                    send_hook_rejection(
                        &output,
                        HookRejectionCode::InvalidSchema,
                        "expected a hook event after the hello",
                    )
                    .await;
                    return;
                };
                match protocol.process_event(&event, &runtime, observed_peer.observed_pid) {
                    Ok(result) => {
                        if output
                            .send(Ok(HookServerMessage {
                                item: Some(hook_server_message::Item::Result(result)),
                            }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) => {
                        let code = if event.native_event_json.len() > MAX_NATIVE_EVENT_BYTES {
                            HookRejectionCode::EventTooLarge
                        } else {
                            HookRejectionCode::InvalidSchema
                        };
                        send_hook_rejection(&output, code, &error.to_string()).await;
                        return;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

async fn send_hook_ack(
    output: &tokio::sync::mpsc::Sender<Result<HookServerMessage, Status>>,
    accepted: bool,
    reason: &str,
) {
    let _result = output
        .send(Ok(HookServerMessage {
            item: Some(hook_server_message::Item::HelloAck(HookHelloAck {
                accepted,
                reason: reason.to_owned(),
            })),
        }))
        .await;
}

async fn send_hook_rejection(
    output: &tokio::sync::mpsc::Sender<Result<HookServerMessage, Status>>,
    code: HookRejectionCode,
    reason: &str,
) {
    let _result = output
        .send(Ok(HookServerMessage {
            item: Some(hook_server_message::Item::Rejection(HookRejection {
                code: code as i32,
                reason: reason.to_owned(),
            })),
        }))
        .await;
}

impl CodexHookBrokerProtocol {
    const fn new(
        managed_session: CodexManagedSession,
        reconciliation: std::sync::Arc<CodexPromptReconciliation>,
        lease_owner: std::sync::Arc<CodexInvocationLeaseOwner>,
        session_start_context: Option<String>,
        child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
        agent_controls: Arc<dyn ContextAgentControlHandler>,
    ) -> Self {
        Self {
            managed_session,
            reconciliation,
            lease_owner,
            session_start_context,
            child_deliveries,
            agent_controls,
        }
    }

    fn authenticate(
        &self,
        peer: &UnixPeerIdentity,
        hello: &HookHello,
    ) -> Result<
        (
            CodexLeaseRuntimeEvidence,
            erebor_runtime_ipc::v1::HookPeerEvidence,
        ),
        CodexSessionError,
    > {
        if hello.session_id != self.managed_session.session_id() {
            return InvalidHookEventSnafu {
                reason: String::from("Codex hook hello session does not match its registration"),
            }
            .fail();
        }
        let pid = peer
            .pid
            .ok_or_else(|| CodexSessionError::InvalidHookEvent {
                reason: String::from("Unix peer pid is unavailable"),
                location: snafu::Location::default(),
            })?;
        let observed_peer = LinuxHookPeerInspector::inspect_pid(pid)?;
        ensure!(
            observed_peer.observed_uid == peer.uid && observed_peer.observed_gid == peer.gid,
            InvalidHookEventSnafu {
                reason: String::from("Unix peer credentials changed during hook authentication")
            }
        );
        ensure!(
            self.managed_session
                .profile()
                .allows_hook_executable(&observed_peer.executable),
            InvalidHookEventSnafu {
                reason: String::from(
                    "managed hook executable is not allowed by the registered profile"
                )
            }
        );
        let runtime = LinuxHookPeerInspector::runtime_evidence(
            &observed_peer,
            self.managed_session.profile().executable(),
        )?;
        self.managed_session
            .hook_peers()
            .authenticate_peer(observed_peer.clone())?;
        Ok((runtime, observed_peer))
    }

    fn process_event(
        &self,
        event: &HookEvent,
        runtime: &CodexLeaseRuntimeEvidence,
        observed_pid: i64,
    ) -> Result<HookResult, CodexSessionError> {
        let event_kind = self.validate_event(event)?;
        let control = (|| {
            self.reconciliation
                .record_authenticated_hook(event_kind, &event.native_event_json)?;
            self.lease_owner.record_authenticated_hook(
                event_kind,
                &event.native_event_json,
                runtime.clone(),
                observed_pid,
            )?;
            let control = self.execute_agent_control(event_kind, &event.native_event_json)?;
            self.publish_child_delivery(event_kind, &event.native_event_json, runtime)
                .map(|()| control)
        })()
        .inspect_err(|error| {
            warn!(
                error;
                "rejected authenticated Codex hook event",
                session_id = %self.managed_session.session_id(),
                hook_event = %event_kind.as_str_name()
            );
        })?;
        Ok(HookResult {
            event: event_kind as i32,
            accepted: true,
            result_json: self.hook_result(event_kind, control)?,
        })
    }

    fn hook_result(
        &self,
        event: HookEventKind,
        control: Option<ContextAgentControlResult>,
    ) -> Result<Vec<u8>, CodexSessionError> {
        if let Some(control) = control {
            return serde_json::to_vec(&json!({
                "continue": true,
                "erebor_context_control": {
                    "action": control.action().as_str(),
                    "agents": control.agents().iter().map(|agent| json!({
                        "thread_id": agent.thread_id(),
                        "turn_id": agent.turn_id(),
                    })).collect::<Vec<_>>(),
                },
            }))
            .map_err(|error| CodexSessionError::IncompatibleProfile {
                reason: format!("could not encode Codex context control result: {error}"),
                location: snafu::Location::default(),
            });
        }
        if event != HookEventKind::SessionStart {
            return Ok(br#"{"continue":true}"#.to_vec());
        }
        self.session_start_context.as_ref().map_or_else(
            || Ok(br#"{"continue":true}"#.to_vec()),
            |context| {
                serde_json::to_vec(&json!({
                    "continue": true,
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": context,
                    },
                }))
                .map_err(|error| CodexSessionError::IncompatibleProfile {
                    reason: format!("could not encode Codex SessionStart context: {error}"),
                    location: snafu::Location::default(),
                })
            },
        )
    }

    fn execute_agent_control(
        &self,
        event: HookEventKind,
        native_event: &[u8],
    ) -> Result<Option<ContextAgentControlResult>, CodexSessionError> {
        if event != HookEventKind::PreToolUse {
            return Ok(None);
        }
        let payload = payload_value(native_event)?;
        let Some(context_dag) = self.lease_owner.context_dag()? else {
            return Ok(None);
        };
        let Some(control) = context_dag.agent_control(&payload)? else {
            return Ok(None);
        };
        let requester_scope = control.requester().scope().clone();
        let result = self
            .agent_controls
            .handle_agent_control(control)
            .map_err(|reason| CodexSessionError::InvalidHookEvent {
                reason: format!("daemon rejected authenticated Codex context control: {reason}"),
                location: snafu::Location::default(),
            })?;
        context_dag.refresh_scope(&requester_scope)?;
        Ok(Some(result))
    }

    fn publish_child_delivery(
        &self,
        event: HookEventKind,
        native_event: &[u8],
        runtime: &CodexLeaseRuntimeEvidence,
    ) -> Result<(), CodexSessionError> {
        if event != HookEventKind::PostToolUse {
            return Ok(());
        }
        let payload: HookDeliveryEvent = serde_json::from_slice(native_event).map_err(|error| {
            CodexSessionError::InvalidHookEvent {
                reason: format!("PostToolUse delivery event is not valid JSON: {error}"),
                location: snafu::Location::default(),
            }
        })?;
        let Some(delivery) = payload.delivery()? else {
            return Ok(());
        };
        if !delivery.emit {
            return Ok(());
        }
        let operation_key = delivery.operation_key.filter(|key| !key.is_empty());
        let delivery = ChildContextDelivery::new(
            self.managed_session.session_id(),
            delivery.sequence,
            delivery.kind,
            delivery.mode,
            delivery.selected_text.into_bytes(),
        );
        let delivery = delivery.with_source_scope(self.lease_owner.delivery_scope(
            &payload_value(native_event)?,
            runtime,
            operation_key.as_deref(),
        )?);
        self.child_deliveries
            .publish_delivery(delivery)
            .map_err(|reason| CodexSessionError::InvalidHookEvent {
                reason: format!("daemon rejected authenticated child delivery: {reason}"),
                location: snafu::Location::default(),
            })
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
        ensure!(
            self.managed_session.profile().allows_event(&package_event),
            InvalidHookEventSnafu {
                reason: format!(
                    "event `{}` is not enabled by the managed package",
                    event_kind.as_str_name(),
                )
            }
        );
        Ok(event_kind)
    }
}

#[derive(Deserialize)]
struct HookDeliveryEvent {
    #[serde(default)]
    tool_response: serde_json::Value,
}

impl HookDeliveryEvent {
    fn delivery(&self) -> Result<Option<HookDeliveryPayload>, CodexSessionError> {
        let Some(delivery) = self.tool_response.get("erebor_delivery") else {
            return Ok(None);
        };
        serde_json::from_value(delivery.clone())
            .map(Some)
            .map_err(|error| CodexSessionError::InvalidHookEvent {
                reason: format!("PostToolUse Erebor delivery is invalid: {error}"),
                location: snafu::Location::default(),
            })
    }
}

#[derive(Deserialize)]
struct HookDeliveryPayload {
    #[serde(default = "default_delivery_emit")]
    emit: bool,
    sequence: u64,
    kind: String,
    mode: String,
    selected_text: String,
    #[serde(default)]
    operation_key: Option<String>,
}

const fn default_delivery_emit() -> bool {
    true
}

fn payload_value(native_event: &[u8]) -> Result<serde_json::Value, CodexSessionError> {
    serde_json::from_slice(native_event).map_err(|error| CodexSessionError::InvalidHookEvent {
        reason: format!("PostToolUse delivery event is not valid JSON: {error}"),
        location: snafu::Location::default(),
    })
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
    pub(super) fn inspect_pid(
        pid: i32,
    ) -> Result<erebor_runtime_ipc::v1::HookPeerEvidence, CodexSessionError> {
        let process = LinuxHookProcess::inspect(pid)?;
        let metadata = fs::metadata(format!("/proc/{pid}")).context(HookBrokerIoSnafu)?;
        Ok(erebor_runtime_ipc::v1::HookPeerEvidence {
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
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use erebor_runtime_context::{
        CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature,
        CommitTime, Snapshot, TreeEdit,
    };
    use erebor_runtime_events::{ActorIdentity, ActorKind};
    use erebor_runtime_ipc::v1::HookEvent;
    use erebor_runtime_packages::{
        CodexArtifact, CodexEntrypoint, CodexHookContract, CodexHookEventName, CodexHookExec,
        CodexHookShell, CodexManagedArtifacts, CodexPackageDefinition, CodexSupportedPlatform,
        ContentDigest,
    };

    use super::{
        CodexHookBrokerProtocol, CodexInvocationLeaseOwner, CodexLeaseRuntimeEvidence,
        CodexPromptReconciliation, HookEventKind, LinuxHookPeerInspector, LinuxHookProcess,
        LinuxProcessIdentity,
    };
    use crate::{
        agents::codex::{
            CodexInvocationLeaseProfile, CodexManagedSession, CodexScopeContextBinding,
        },
        ChildContextDelivery, ChildContextDeliveryHandler, CodexSessionError, ContextAgentControl,
        ContextAgentControlHandler, ContextAgentControlResult,
    };

    struct FixedMetadataSource;

    const SESSION_START_EVENT: &[u8] = br#"{"cwd":"/workspace","hook_event_name":"SessionStart","model":"gpt-5","permission_mode":"default","session_id":"session","source":"startup","transcript_path":null}"#;

    impl CommitMetadataSource for FixedMetadataSource {
        fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
            let time = CommitTime::new(1_700_000_000, 0)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            let signature = CommitSignature::new("Erebor Test", "test@erebor.invalid", time)
                .map_err(|source| Box::new(source) as CommitMetadataSourceError)?;
            Ok(CommitMetadata::new(signature.clone(), signature))
        }
    }

    struct AcceptChildDelivery;

    impl ChildContextDeliveryHandler for AcceptChildDelivery {
        fn publish_delivery(
            &self,
            _delivery: ChildContextDelivery,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    fn child_deliveries() -> Arc<dyn ChildContextDeliveryHandler> {
        Arc::new(AcceptChildDelivery)
    }

    struct AcceptAgentControl;

    impl ContextAgentControlHandler for AcceptAgentControl {
        fn handle_agent_control(
            &self,
            control: ContextAgentControl,
        ) -> std::result::Result<ContextAgentControlResult, String> {
            Ok(ContextAgentControlResult::allowed(
                control.action(),
                Vec::new(),
            ))
        }
    }

    fn agent_controls() -> Arc<dyn ContextAgentControlHandler> {
        Arc::new(AcceptAgentControl)
    }

    struct AdvancingAgentControl {
        repository: Arc<erebor_runtime_context::ContextRepository>,
        received: Arc<Mutex<Vec<ContextAgentControl>>>,
    }

    impl ContextAgentControlHandler for AdvancingAgentControl {
        fn handle_agent_control(
            &self,
            control: ContextAgentControl,
        ) -> std::result::Result<ContextAgentControlResult, String> {
            let scope = control.requester().scope().clone();
            let head = self
                .repository
                .scope_head(&scope)
                .map_err(|error| error.to_string())?;
            self.repository
                .append_snapshot(
                    scope,
                    head,
                    Snapshot::new(vec![TreeEdit::blob(
                        "erebor/context-dag/controls/test.json",
                        br#"{"kind":"agent-control"}"#.to_vec(),
                    )
                    .map_err(|error| error.to_string())?])
                    .map_err(|error| error.to_string())?,
                    "Record test context control",
                )
                .map_err(|error| error.to_string())?;
            self.received
                .lock()
                .map_err(|_error| String::from("recording control lock poisoned"))?
                .push(control.clone());
            Ok(ContextAgentControlResult::allowed(
                control.action(),
                Vec::new(),
            ))
        }
    }

    struct RecordingChildDelivery(Arc<Mutex<Vec<ChildContextDelivery>>>);

    impl ChildContextDeliveryHandler for RecordingChildDelivery {
        fn publish_delivery(
            &self,
            delivery: ChildContextDelivery,
        ) -> std::result::Result<(), String> {
            self.0
                .lock()
                .map_err(|_error| String::from("recording delivery lock poisoned"))?
                .push(delivery);
            Ok(())
        }
    }

    #[test]
    fn inspector_observes_kernel_bound_unix_peer_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let peer = match LinuxHookPeerInspector::inspect_pid(i32::try_from(std::process::id())?) {
            Ok(peer) => peer,
            Err(CodexSessionError::HookBrokerIo { source, .. })
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        assert_eq!(peer.observed_pid, i64::from(std::process::id()));
        assert!(!peer.executable.is_empty());
        assert!(!peer.exec_chain.is_empty());
        Ok(())
    }

    #[test]
    fn broker_accepts_only_profile_enabled_current_schema_events(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let native_event_json = SESSION_START_EVENT.to_vec();
        let session = session("/opt/codex/codex")?;
        let broker = CodexHookBrokerProtocol::new(
            session,
            Arc::new(CodexPromptReconciliation::default()),
            test_lease_owner(),
            None,
            child_deliveries(),
            agent_controls(),
        );
        let valid = HookEvent {
            event: HookEventKind::SessionStart as i32,
            native_event_json,
        };
        assert_eq!(broker.validate_event(&valid)?, HookEventKind::SessionStart);

        let invalid = HookEvent {
            event: HookEventKind::SessionStart as i32,
            native_event_json: br#"{"cwd":"/workspace","hook_event_name":"SessionStart","model":"gpt-5","permission_mode":"default","session_id":"session","source":"startup","transcript_path":null,"unexpected":true}"#.to_vec(),
        };
        assert!(matches!(
            broker.validate_event(&invalid),
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
    fn default_session_start_result_is_valid_json() -> Result<(), Box<dyn std::error::Error>> {
        let broker = CodexHookBrokerProtocol::new(
            session("/opt/codex/codex")?,
            Arc::new(CodexPromptReconciliation::default()),
            test_lease_owner(),
            None,
            child_deliveries(),
            agent_controls(),
        );

        let result: serde_json::Value =
            serde_json::from_slice(&broker.hook_result(HookEventKind::SessionStart, None)?)?;

        assert_eq!(
            result
                .pointer("/continue")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(result.pointer("/hookSpecificOutput").is_none());
        Ok(())
    }

    #[test]
    fn authenticated_context_control_refreshes_its_source_scope_after_daemon_write(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = Arc::new(erebor_runtime_context::ContextRepository::init(
            temporary.path().join("context"),
            FixedMetadataSource,
        )?);
        repository.initialize_root("session-test", Default::default(), "Initialize")?;
        let context_dag = Arc::new(super::super::CodexContextDag::new(
            Arc::clone(&repository),
            "session-test",
        ));
        context_dag
            .bind_terminal_turn(&serde_json::json!({
                "session_id": "parent-thread",
                "turn_id": "parent-turn",
            }))?
            .ok_or("control source turn did not bind")?;
        let owner = test_lease_owner();
        owner.set_context_dag(Arc::clone(&context_dag))?;
        let received = Arc::new(Mutex::new(Vec::new()));
        let broker = CodexHookBrokerProtocol::new(
            session("/opt/codex/codex")?,
            Arc::new(CodexPromptReconciliation::default()),
            owner,
            None,
            child_deliveries(),
            Arc::new(AdvancingAgentControl {
                repository: Arc::clone(&repository),
                received: Arc::clone(&received),
            }),
        );
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "parent-thread",
            "turn_id": "parent-turn",
            "tool_use_id": "control-1",
            "tool_name": "erebor_context_control",
            "tool_input": {
                "erebor_context_action": "list_agents",
                "target_thread_id": "",
                "target_turn_id": "",
                "follow_up_text": "",
            },
        });

        context_dag.record_authenticated_hook(
            HookEventKind::PreToolUse,
            &payload,
            serde_json::json!({"hook_pid": 7}),
        )?;
        let control = broker
            .execute_agent_control(HookEventKind::PreToolUse, &serde_json::to_vec(&payload)?)?
            .ok_or("broker did not recognize the authenticated context control")?;
        assert_eq!(control.action().as_str(), "list_agents");
        assert_eq!(
            received
                .lock()
                .map_err(|_error| "recording control lock poisoned")?
                .len(),
            1
        );

        // The handler advanced the daemon-owned ref. This second append would
        // fail with a stale expected head if the broker had not refreshed the
        // adapter's cached scope cursor before accepting another hook.
        context_dag.record_authenticated_hook(
            HookEventKind::UserPromptSubmit,
            &serde_json::json!({
                "session_id": "parent-thread",
                "turn_id": "parent-turn",
            }),
            serde_json::json!({"hook_pid": 7}),
        )?;
        Ok(())
    }

    #[test]
    fn post_tool_use_delivery_is_forwarded_only_through_the_authenticated_hook_route(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let owner = test_lease_owner();
        let root_scope = erebor_runtime_context::ScopeRef::root("session-test")?;
        owner.record_scope_context(CodexScopeContextBinding::new(
            String::from("fixture-thread"),
            String::from("fixture-turn"),
            root_scope.as_str().to_owned(),
            String::from("fixture-item-stream"),
            String::from("fixture-head"),
        ))?;
        let broker = CodexHookBrokerProtocol::new(
            session("/opt/codex/codex")?,
            Arc::new(CodexPromptReconciliation::default()),
            owner,
            None,
            Arc::new(RecordingChildDelivery(Arc::clone(&delivered))),
            agent_controls(),
        );
        broker.publish_child_delivery(
            HookEventKind::PostToolUse,
            br#"{"cwd":"/workspace","hook_event_name":"PostToolUse","model":"gpt-5","permission_mode":"default","session_id":"fixture-thread","tool_input":{},"tool_name":"Bash","tool_response":{"erebor_delivery":{"sequence":1,"kind":"result","mode":"queue","selected_text":"child result"}},"tool_use_id":"tool","transcript_path":null,"turn_id":"fixture-turn"}"#,
            &CodexLeaseRuntimeEvidence::new(1, 1, String::from("/opt/codex/codex")),
        )?;
        let deliveries = delivered
            .lock()
            .map_err(|_error| "recording delivery lock poisoned")?;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].source_session_id(), "session-test");
        assert_eq!(deliveries[0].sequence(), 1);
        assert_eq!(deliveries[0].kind(), "result");
        assert_eq!(deliveries[0].mode(), "queue");
        assert_eq!(deliveries[0].selected_bytes(), b"child result");
        assert_eq!(deliveries[0].source_scope(), Some(&root_scope));
        Ok(())
    }

    #[test]
    fn post_tool_use_with_an_ordinary_codex_tool_response_needs_no_delivery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let broker = CodexHookBrokerProtocol::new(
            session("/opt/codex/codex")?,
            Arc::new(CodexPromptReconciliation::default()),
            test_lease_owner(),
            None,
            child_deliveries(),
            agent_controls(),
        );

        // Codex represents the normal Bash tool response as a JSON string.
        // `erebor_delivery` is optional and exists only on object responses
        // emitted by Erebor-aware child-context operations.
        broker.publish_child_delivery(
            HookEventKind::PostToolUse,
            br#"{"cwd":"/workspace","hook_event_name":"PostToolUse","model":"gpt-5","permission_mode":"default","session_id":"fixture-thread","tool_input":{"command":"printf blocked > .erebor-denied"},"tool_name":"Bash","tool_response":"","tool_use_id":"tool","transcript_path":null,"turn_id":"fixture-turn"}"#,
            &CodexLeaseRuntimeEvidence::new(1, 1, String::from("/opt/codex/codex")),
        )?;

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
    fn managed_profile_uses_workload_executable_and_allowed_hook_history(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let workload_executable = "/run/erebor/admitted-executable";
        let definition = package()?;
        let session = CodexManagedSession::from_package(
            "session-test",
            workload_executable.into(),
            &definition,
        )?;
        let profile = session.profile();

        assert_eq!(
            profile.executable(),
            std::path::Path::new(workload_executable)
        );
        assert!(profile.allows_hook_executable(workload_executable));
        assert!(profile.allows_hook_executable("/run/erebor/codex/hooks/erebor-codex-hook"));
        assert!(!profile.allows_hook_executable("/tmp/unregistered-hook"));
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
    ) -> Result<CodexManagedSession, Box<dyn std::error::Error>> {
        Ok(CodexManagedSession::from_package(
            "session-test",
            executable.into(),
            &package()?,
        )?)
    }

    fn package() -> Result<CodexPackageDefinition, Box<dyn std::error::Error>> {
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
                vec![CodexHookEventName::SessionStart],
                None,
            )?,
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
            CodexInvocationLeaseProfile::new(String::from("profile-test")),
            audit_path,
        ))
    }
}
