use std::{
    collections::BTreeMap,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener as StdUnixListener,
    },
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_approvals::{ApprovalRecord, ApprovalRepository};
use erebor_runtime_ipc::v1::{
    ApprovalRecord as ApprovalRecordMessage, DaemonCommandResult, PolicyTestRequest,
    PolicyTestResponse, RunnerCapabilityRecord,
};
use erebor_runtime_telemetry::{error, info, JsonlTelemetry};
use prost::Message;
use rustix::{
    fs::chown,
    process::{geteuid, Gid, Uid},
};
use snafu::ResultExt;
use tokio::{net::UnixListener, sync::watch};

use crate::{
    approvals::DaemonApprovalRepository,
    config::DaemonConfig,
    error::{InvalidRequestSnafu, IoSnafu, StateLockSnafu, TelemetrySnafu, UnauthorizedSnafu},
    idempotency::{DaemonIdempotencyStore, MutationIntent, MutationResponseType},
    paths::{DaemonLock, DaemonSecurity},
    session_api::DaemonSessionApi,
    DaemonError, DaemonPaths, Result,
};
use erebor_runtime_core::ActiveSessionSignal;
use erebor_runtime_policy::{LocalPolicy, PolicyEvaluator};
use erebor_runtime_session::{
    ChildContextDelivery, ChildContextDeliveryHandler, ContextAgentControl,
    ContextAgentControlHandler, ContextAgentControlResult, ContextOperationAdmission,
    ContextOperationAdmissionHandler,
};

mod grpc;

const CONNECTION_LIMIT: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonControlService {
    listener: Option<UnixListener>,
    state: Arc<DaemonControlState>,
    socket: DaemonSocket,
    _lock: DaemonLock,
    shutdown: watch::Receiver<bool>,
}

struct DaemonControlState {
    paths: DaemonPaths,
    security: DaemonSecurity,
    configuration: RwLock<DaemonConfiguration>,
    idempotency: Mutex<DaemonIdempotencyStore>,
    telemetry: JsonlTelemetry,
    sessions: DaemonSessionApi,
    approvals: DaemonApprovalRepository,
    shutdown: watch::Sender<bool>,
    active_streams: Arc<PerUidStreamLimiter>,
}

struct DaemonConfiguration {
    value: DaemonConfig,
    generation: u64,
}

impl ChildContextDeliveryHandler for DaemonControlState {
    fn publish_delivery(&self, delivery: ChildContextDelivery) -> std::result::Result<(), String> {
        self.sessions
            .publish_child_delivery(delivery)
            .map_err(|error| error.to_string())
    }
}

impl ContextOperationAdmissionHandler for DaemonControlState {
    fn admit_operation(
        &self,
        admission: ContextOperationAdmission,
    ) -> std::result::Result<erebor_runtime_context::ScopeRef, String> {
        self.sessions
            .admit_context_operation(admission)
            .map_err(|error| error.to_string())
    }
}

impl ContextAgentControlHandler for DaemonControlState {
    fn handle_agent_control(
        &self,
        control: ContextAgentControl,
    ) -> std::result::Result<ContextAgentControlResult, String> {
        self.sessions
            .handle_agent_control(control)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy)]
struct PeerIdentity {
    uid: u32,
    gid: u32,
}

struct PerUidStreamPermit {
    limiter: Arc<PerUidStreamLimiter>,
    uid: u32,
}

struct PerUidStreamLimiter {
    active: Mutex<BTreeMap<u32, u32>>,
}

impl PerUidStreamLimiter {
    fn new() -> Self {
        Self {
            active: Mutex::new(BTreeMap::new()),
        }
    }

    fn acquire(self: &Arc<Self>, uid: u32, maximum: u32) -> Result<PerUidStreamPermit> {
        let mut active = self
            .active
            .lock()
            .map_err(|_error| StateLockSnafu.build())?;
        let count = active.entry(uid).or_default();
        if *count >= maximum {
            return InvalidRequestSnafu {
                reason: format!(
                    "owner UID {uid} has reached the {maximum} active daemon-stream limit"
                ),
            }
            .fail();
        }
        *count = count.saturating_add(1);
        Ok(PerUidStreamPermit {
            limiter: Arc::clone(self),
            uid,
        })
    }
}

struct DaemonSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
    cleanup_attempted: bool,
}

impl DaemonControlService {
    /// Starts one root-owned daemon using explicitly supplied local paths.
    pub async fn start_with_paths(paths: DaemonPaths) -> Result<Self> {
        Self::require_root_process()?;
        Self::start(paths, 0).await
    }

    fn require_root_process() -> Result<()> {
        if geteuid().as_raw() == 0 {
            Ok(())
        } else {
            InvalidRequestSnafu {
                reason: String::from("erebord must run as root"),
            }
            .fail()
        }
    }

    pub(crate) async fn start(paths: DaemonPaths, owner_uid: u32) -> Result<Self> {
        let bootstrap_security = DaemonSecurity {
            owner_uid,
            socket_gid: 0,
        };
        paths.prepare(bootstrap_security)?;
        let config = DaemonConfig::load(&paths, bootstrap_security)?;
        let security = DaemonSecurity {
            owner_uid,
            socket_gid: config.socket_group_gid,
        };
        paths.set_runtime_group(security)?;
        let lock = paths.acquire_lock(security)?;
        paths.remove_stale_socket(&lock, security).await?;

        let socket_path = paths.socket_path();
        let listener = Self::bind_listener(&socket_path, security)?;
        let socket = DaemonSocket::from_bound_path(socket_path)?;
        let telemetry =
            JsonlTelemetry::open(paths.log_path(), config.max_log_bytes).context(TelemetrySnafu)?;
        let sessions = DaemonSessionApi::installed(&paths, &config)?;
        let approvals = DaemonApprovalRepository::installed(&paths)?;
        let reconciled = sessions.reconcile()?;
        telemetry
            .emit(|| info!("erebord daemon control service started"))
            .context(TelemetrySnafu)?;
        if !reconciled.is_empty() {
            telemetry
                .emit(|| info!("reconciled durable sessions", count = %reconciled.len()))
                .context(TelemetrySnafu)?;
        }
        let (shutdown_sender, shutdown) = watch::channel(false);
        let state = Arc::new(DaemonControlState {
            idempotency: Mutex::new(DaemonIdempotencyStore::new(
                paths.idempotency_path(),
                paths.session_state_path(),
                config.max_idempotency_records as usize,
                Duration::from_secs(config.session_retry_horizon_seconds),
            )),
            paths,
            security,
            configuration: RwLock::new(DaemonConfiguration {
                value: config,
                generation: 1,
            }),
            telemetry,
            sessions,
            approvals,
            shutdown: shutdown_sender,
            active_streams: Arc::new(PerUidStreamLimiter::new()),
        });
        let child_deliveries: Arc<dyn ChildContextDeliveryHandler> = state.clone();
        state
            .sessions
            .bind_child_delivery_handler(child_deliveries)?;
        let operation_admissions: Arc<dyn ContextOperationAdmissionHandler> = state.clone();
        state
            .sessions
            .bind_operation_admission_handler(operation_admissions)?;
        let agent_controls: Arc<dyn ContextAgentControlHandler> = state.clone();
        state.sessions.bind_agent_control_handler(agent_controls)?;
        Ok(Self {
            listener: Some(listener),
            state,
            socket,
            _lock: lock,
            shutdown,
        })
    }

    pub async fn serve(mut self) -> Result<()> {
        let listener = self.listener.take().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("daemon gRPC listener is unavailable"),
            }
            .build()
        })?;
        let result = grpc::serve(listener, Arc::clone(&self.state), self.shutdown.clone())
            .await
            .map_err(|source| DaemonError::Grpc {
                source,
                location: snafu::Location::default(),
            });
        if result.is_err() {
            let _result = self
                .state
                .telemetry
                .emit(|| error!("daemon control service terminated unexpectedly"));
        }
        result
    }

    fn bind_listener(path: &PathBuf, security: DaemonSecurity) -> Result<UnixListener> {
        let listener = StdUnixListener::bind(path).context(IoSnafu {
            action: "binding daemon socket",
            path,
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).context(
            IoSnafu {
                action: "setting daemon socket permissions",
                path,
            },
        )?;
        chown(
            path,
            Some(Uid::from_raw(security.owner_uid)),
            Some(Gid::from_raw(security.socket_gid)),
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "setting daemon socket ownership",
            path,
        })?;
        listener.set_nonblocking(true).context(IoSnafu {
            action: "configuring daemon socket",
            path,
        })?;
        UnixListener::from_std(listener).context(IoSnafu {
            action: "starting daemon socket listener",
            path,
        })
    }
}

impl DaemonControlState {
    fn approval_owner(&self, peer: PeerIdentity, requested_owner_uid: u32) -> Result<u32> {
        let owner_uid = if requested_owner_uid == 0 {
            peer.uid
        } else {
            requested_owner_uid
        };
        if owner_uid == peer.uid || peer.uid == 0 {
            Ok(owner_uid)
        } else {
            UnauthorizedSnafu { uid: peer.uid }.fail()
        }
    }

    fn approval_record(record: &ApprovalRecord) -> ApprovalRecordMessage {
        ApprovalRecordMessage {
            approval_id: record.id().to_owned(),
            state: match record.state() {
                erebor_runtime_approvals::ApprovalState::Pending => String::from("pending"),
                erebor_runtime_approvals::ApprovalState::Approved => String::from("approved"),
                erebor_runtime_approvals::ApprovalState::Denied => String::from("denied"),
                erebor_runtime_approvals::ApprovalState::Expired => String::from("expired"),
                erebor_runtime_approvals::ApprovalState::Cancelled => String::from("cancelled"),
                erebor_runtime_approvals::ApprovalState::Consumed => String::from("consumed"),
            },
            owner_uid: record.binding().owner_uid(),
            session_id: record.binding().session_id().to_owned(),
            session_generation: record.binding().session_generation(),
            effect_digest: record.binding().effect_digest().to_owned(),
            process_identity: record.binding().process_identity().to_owned(),
            policy_set_digest: record.binding().policy_set_digest().to_owned(),
            policy_rule_id: record.binding().policy_rule_id().to_owned(),
            expires_at_unix_ms: record.expires_at_unix_ms(),
        }
    }

    fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_millis() as u64)
    }

    fn apply_mutation(
        &self,
        intent: &MutationIntent,
        resume_pending: bool,
    ) -> Result<crate::idempotency::MutationResponse> {
        match intent {
            MutationIntent::Reload {
                configuration,
                generation,
            } => {
                let message = self.publish_configuration(configuration.clone(), *generation)?;
                encode_mutation_response(
                    MutationResponseType::DaemonCommandResult,
                    &DaemonCommandResult { message },
                )
            }
            MutationIntent::Stop => encode_mutation_response(
                MutationResponseType::DaemonCommandResult,
                &DaemonCommandResult {
                    message: String::from("daemon stop accepted"),
                },
            ),
            MutationIntent::AgentInstall {
                uid,
                agent_name,
                package_digest,
                installed_at_unix_ms,
                artifact,
            } => {
                let response = self.sessions.install_verified_codex(
                    *uid,
                    agent_name,
                    package_digest,
                    artifact.clone(),
                    *installed_at_unix_ms,
                )?;
                encode_mutation_response(MutationResponseType::AgentInstallResponse, &response)
            }
            MutationIntent::SessionStart { uid, session_id } => {
                let active = self
                    .configuration
                    .read()
                    .map_err(|_error| StateLockSnafu.build())?;
                let constraints = self.sessions.validate_start(
                    *uid,
                    session_id,
                    active.generation,
                    &active.value,
                )?;
                drop(active);
                self.sessions
                    .start(*uid, session_id, &constraints, resume_pending)
            }
            MutationIntent::ApprovalApprove {
                owner_uid,
                approval_id,
            } => {
                let mut record = self.approval_record_for_transition(*owner_uid, approval_id)?;
                if record.state() == erebor_runtime_approvals::ApprovalState::Pending {
                    record.approve(Self::unix_time_ms()).map_err(|source| {
                        DaemonError::Approval {
                            source,
                            location: snafu::Location::default(),
                        }
                    })?;
                    record =
                        self.approvals
                            .replace(record)
                            .map_err(|source| DaemonError::Approval {
                                source,
                                location: snafu::Location::default(),
                            })?;
                }
                if record.state() != erebor_runtime_approvals::ApprovalState::Approved {
                    return InvalidRequestSnafu {
                        reason: String::from("approval is no longer pending or approved"),
                    }
                    .fail();
                }
                encode_mutation_response(
                    MutationResponseType::ApprovalRecord,
                    &Self::approval_record(&record),
                )
            }
            MutationIntent::ApprovalDeny {
                owner_uid,
                approval_id,
                reason,
            } => {
                let mut record = self.approval_record_for_transition(*owner_uid, approval_id)?;
                if record.state() == erebor_runtime_approvals::ApprovalState::Pending {
                    record
                        .deny(Self::unix_time_ms(), reason)
                        .map_err(|source| DaemonError::Approval {
                            source,
                            location: snafu::Location::default(),
                        })?;
                    record =
                        self.approvals
                            .replace(record)
                            .map_err(|source| DaemonError::Approval {
                                source,
                                location: snafu::Location::default(),
                            })?;
                }
                if record.state() != erebor_runtime_approvals::ApprovalState::Denied {
                    return InvalidRequestSnafu {
                        reason: String::from("approval is no longer pending or denied"),
                    }
                    .fail();
                }
                encode_mutation_response(
                    MutationResponseType::ApprovalRecord,
                    &Self::approval_record(&record),
                )
            }
            session => self.sessions.apply(session),
        }
    }

    fn approval_record_for_transition(
        &self,
        owner_uid: u32,
        approval_id: &str,
    ) -> Result<ApprovalRecord> {
        self.approvals
            .inspect(owner_uid, approval_id)
            .map_err(|source| DaemonError::Approval {
                source,
                location: snafu::Location::default(),
            })
    }

    fn next_configuration_generation(&self) -> Result<u64> {
        Ok(self
            .configuration
            .read()
            .map_err(|_error| StateLockSnafu.build())?
            .generation
            .saturating_add(1))
    }

    fn publish_configuration(
        &self,
        configuration: DaemonConfig,
        generation: u64,
    ) -> Result<String> {
        self.sessions.seed_root_curated(&configuration)?;
        let mut active = self
            .configuration
            .write()
            .map_err(|_error| StateLockSnafu.build())?;
        if active.value != configuration {
            active.value = configuration;
            active.generation = active.generation.saturating_add(1).max(generation);
        } else {
            active.generation = active.generation.max(generation);
        }
        Ok(format!(
            "configuration reloaded at generation {}",
            active.generation
        ))
    }

    fn require_root(&self, peer: PeerIdentity) -> Result<()> {
        if peer.uid == 0 {
            Ok(())
        } else {
            UnauthorizedSnafu { uid: peer.uid }.fail()
        }
    }

    fn acquire_stream_permit(self: &Arc<Self>, uid: u32) -> Result<PerUidStreamPermit> {
        let maximum = self
            .configuration
            .read()
            .map_err(|_error| StateLockSnafu.build())?
            .value
            .max_concurrent_streams_per_uid();
        self.active_streams.acquire(uid, maximum)
    }
}

impl Drop for DaemonSocket {
    fn drop(&mut self) {
        self.unlink_if_owned();
    }
}

impl Drop for PerUidStreamPermit {
    fn drop(&mut self) {
        if let Ok(mut active_streams) = self.limiter.active.lock() {
            match active_streams.get_mut(&self.uid) {
                Some(active) if *active > 1 => *active -= 1,
                Some(_) => {
                    active_streams.remove(&self.uid);
                }
                None => {}
            }
        }
    }
}

fn evaluate_policy_test(request: PolicyTestRequest, maximum: u64) -> Result<PolicyTestResponse> {
    let total = request
        .policy_json
        .len()
        .saturating_add(request.event_json.len());
    if total > maximum as usize {
        return InvalidRequestSnafu {
            reason: format!(
                "policy test upload is {total} bytes, exceeding the configured {maximum}-byte limit"
            ),
        }
        .fail();
    }
    let policy_source = std::str::from_utf8(&request.policy_json).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("policy test input is not UTF-8: {error}"),
        }
        .build()
    })?;
    let policy = LocalPolicy::from_json_str(policy_source).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("policy test input is invalid: {error}"),
        }
        .build()
    })?;
    let event = serde_json::from_slice(&request.event_json).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("policy test event is invalid: {error}"),
        }
        .build()
    })?;
    let decision = policy.evaluate(&event).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("policy test evaluation failed: {error}"),
        }
        .build()
    })?;
    let decision_json = serde_json::to_vec(&decision).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("policy test result cannot be encoded: {error}"),
        }
        .build()
    })?;
    Ok(PolicyTestResponse { decision_json })
}

fn runner_capability_record(
    report: &erebor_runtime_session::RunnerCapabilityReport,
) -> Result<RunnerCapabilityRecord> {
    let document_json = serde_json::to_vec(report.document()).map_err(|error| {
        InvalidRequestSnafu {
            reason: format!("runner capability document cannot be encoded: {error}"),
        }
        .build()
    })?;
    Ok(RunnerCapabilityRecord {
        document_json,
        available: report.available(),
        unavailable_reason: report.unavailable_reason().unwrap_or_default().to_owned(),
    })
}

fn parse_signal(value: &str) -> Result<ActiveSessionSignal> {
    match value {
        "terminate" | "TERM" | "SIGTERM" => Ok(ActiveSessionSignal::Terminate),
        "kill" | "KILL" | "SIGKILL" => Ok(ActiveSessionSignal::Kill),
        "interrupt" | "INT" | "SIGINT" => Ok(ActiveSessionSignal::Interrupt),
        _ => InvalidRequestSnafu {
            reason: format!("unsupported session signal `{value}`"),
        }
        .fail(),
    }
}

fn encode_mutation_response(
    response_type: MutationResponseType,
    message: &impl Message,
) -> Result<crate::idempotency::MutationResponse> {
    Ok(crate::idempotency::MutationResponse::new(
        response_type,
        message.encode_to_vec(),
    ))
}

impl DaemonSocket {
    fn from_bound_path(path: PathBuf) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(&path).context(IoSnafu {
            action: "inspecting bound daemon socket",
            path: &path,
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return crate::error::UnsafePathSnafu {
                path,
                reason: String::from("bound daemon socket path is not a socket"),
            }
            .fail();
        }
        Ok(Self {
            cleanup_attempted: false,
            device: metadata.dev(),
            inode: metadata.ino(),
            path,
        })
    }

    fn unlink_if_owned(&mut self) {
        if self.cleanup_attempted {
            return;
        }
        self.cleanup_attempted = true;
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if !metadata.file_type().is_symlink()
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _result = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for DaemonControlService {
    fn drop(&mut self) {
        self.socket.unlink_if_owned();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
        path::Path,
        sync::{Arc, Mutex, RwLock},
        time::Duration,
    };

    use erebor_runtime_client::DaemonClient;
    use erebor_runtime_ipc::{
        transport::{connect_unix, MAX_GRPC_MESSAGE_BYTES},
        v1::{
            hook_client_message, hook_service_client::HookServiceClient,
            policy_service_client::PolicyServiceClient, HookClientMessage, HookHello,
            PolicyTestRequest,
        },
    };
    use erebor_runtime_packages::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, InstallationRecord,
        PolicyPackageRevision, PolicySetRevision,
    };
    use erebor_runtime_telemetry::JsonlTelemetry;
    use rustix::process::geteuid;
    use tempfile::TempDir;
    use tokio::{io::AsyncWriteExt as _, net::UnixListener};
    use tonic::{Code, Request};

    use super::{
        evaluate_policy_test, DaemonApprovalRepository, DaemonConfiguration, DaemonControlState,
        DaemonSecurity, DaemonSocket,
    };
    use crate::{
        config::DaemonConfig, idempotency::DaemonIdempotencyStore, session_api::DaemonSessionApi,
        DaemonPaths,
    };

    #[test]
    fn policy_test_is_bounded_and_evaluated_by_the_daemon_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = evaluate_policy_test(
            PolicyTestRequest {
                policy_json: br#"{"rules":[{"id":"deny-terminal","match":{"surface":"terminal"},"decision":"deny"}]}"#.to_vec(),
                event_json: br#"{"id":"event-1","session_id":"session-1","actor":{"id":"agent","kind":"agent"},"surface":"terminal","action":"process_exec","target":null,"payload":{},"risk":{"level":"low","reasons":[]},"timestamp":"now"}"#.to_vec(),
            },
            1024,
        )?;
        let decision = String::from_utf8(response.decision_json)?;
        assert!(decision.contains("deny-terminal"));
        assert!(evaluate_policy_test(
            PolicyTestRequest {
                policy_json: vec![b'x'; 1024],
                event_json: vec![b'y'],
            },
            1024,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn root_only_operations_reject_non_root_observed_uids() -> Result<(), Box<dyn std::error::Error>>
    {
        let test_state = state()?;
        assert!(test_state
            .state
            .require_root(super::PeerIdentity {
                uid: 1000,
                gid: 1000,
            })
            .is_err());
        assert!(test_state
            .state
            .require_root(super::PeerIdentity { uid: 0, gid: 0 })
            .is_ok());
        Ok(())
    }

    #[test]
    fn daemon_stream_limit_is_scoped_to_the_observed_uid() -> Result<(), Box<dyn std::error::Error>>
    {
        let limiter = Arc::new(super::PerUidStreamLimiter::new());
        let first = limiter.acquire(1000, 1)?;
        assert!(limiter.acquire(1000, 1).is_err());
        let other_owner = limiter.acquire(1001, 1)?;
        drop(first);
        assert!(limiter.acquire(1000, 1).is_ok());
        drop(other_owner);
        Ok(())
    }

    #[test]
    fn reload_publishes_configuration_and_generation_as_one_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let mut replacement = test_state
            .state
            .configuration
            .read()
            .map_err(|_error| "configuration lock poisoned")?
            .value
            .clone();
        replacement.max_log_records = 3;

        assert_eq!(
            test_state
                .state
                .publish_configuration(replacement.clone(), 2)?,
            "configuration reloaded at generation 2"
        );
        assert_eq!(
            test_state
                .state
                .publish_configuration(replacement.clone(), 2)?,
            "configuration reloaded at generation 2"
        );
        let active = test_state
            .state
            .configuration
            .read()
            .map_err(|_error| "configuration lock poisoned")?;
        assert_eq!(active.value, replacement);
        assert_eq!(active.generation, 2);
        Ok(())
    }

    #[tokio::test]
    async fn typed_client_records_a_static_surface_session_without_a_runtime(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let owner_uid = geteuid().as_raw();
        seed_static_session_resources(&test_state, owner_uid)?;
        let socket_path = test_state._root.path().join("static-session.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(super::grpc::serve(
            listener,
            Arc::clone(&test_state.state),
            receiver,
        ));
        let client = DaemonClient::at(socket_path);

        let surface = client
            .surface_create("engineering-browser", "browser_cdp", "surface-create-1")
            .await?;
        assert_eq!(surface.name, "engineering-browser");
        assert_eq!(surface.surface_type, "browser_cdp");
        assert_eq!(
            client.surface_inspect("engineering-browser").await?,
            surface
        );
        assert_eq!(client.surface_list().await?.surfaces, vec![surface]);

        let created = client
            .session_create(
                erebor_runtime_ipc::v1::SessionCreateRequest {
                    runner_id: String::new(),
                    command: Vec::new(),
                    workspace: String::new(),
                    daemon_failure_mode: String::new(),
                    requested_loss_grace_seconds: 0,
                    environment: Vec::new(),
                    secret_references: Vec::new(),
                    tty: false,
                    detached: false,
                    terminal_rows: 0,
                    terminal_columns: 0,
                    agent_name: String::from("local-agent"),
                    policy_set_name: String::from("browser-policyset"),
                    surface_names: vec![String::from("engineering-browser")],
                    caller_home_sources: Vec::new(),
                },
                "static-session-create-1",
            )
            .await?;
        assert_eq!(created.state, "admitted");

        let session = client.session_inspect(&created.session_id).await?;
        assert_eq!(session.api_version, "erebor.dev/v1");
        assert_eq!(session.kind, "Session");
        assert_eq!(session.agent_name, "local-agent");
        assert_eq!(session.policy_set_name, "browser-policyset");
        assert_eq!(session.surface_names, ["engineering-browser"]);
        assert_eq!(client.session_list().await?.sessions, vec![session.clone()]);
        let start_error = match client
            .session_start(&created.session_id, "static-session-start-1")
            .await
        {
            Ok(_record) => {
                return Err("Phase 5.2 static Session must not activate a runtime".into())
            }
            Err(error) => error,
        };
        assert!(start_error.to_string().contains("static admission only"));
        assert!(!test_state
            .state
            .paths
            .session_state_path()
            .join(format!("users/{owner_uid}/sessions/{}", created.session_id))
            .exists());
        assert!(!test_state
            .state
            .paths
            .session_runtime_path()
            .join(&created.session_id)
            .exists());

        shutdown.send(true)?;
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn grpc_endpoint_rejects_wrong_service_oversize_and_stale_frame_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_state = state()?;
        let socket_path = test_state._root.path().join("transport-boundaries.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(super::grpc::serve(
            listener,
            Arc::clone(&test_state.state),
            receiver,
        ));
        let channel = connect_unix(&socket_path).await?;

        let wrong_service = HookServiceClient::new(channel.clone())
            .open(Request::new(futures_util::stream::iter([
                HookClientMessage {
                    item: Some(hook_client_message::Item::Hello(HookHello {
                        session_id: String::from("not-a-daemon-hook"),
                    })),
                },
            ])))
            .await
            .err()
            .ok_or("the daemon accepted an unregistered service")?;
        assert_eq!(wrong_service.code(), Code::Unimplemented);

        let oversized = PolicyServiceClient::new(channel)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES * 2)
            .test(Request::new(PolicyTestRequest {
                policy_json: vec![b'x'; MAX_GRPC_MESSAGE_BYTES + 1],
                event_json: Vec::new(),
            }))
            .await
            .err()
            .ok_or("the daemon accepted an oversized gRPC request")?;
        assert_eq!(oversized.code(), Code::OutOfRange);

        let mut stale = tokio::net::UnixStream::connect(&socket_path).await?;
        stale.write_all(b"ERBR\0\0\0\x01stale-frame").await?;
        stale.shutdown().await?;
        drop(stale);
        assert_eq!(
            DaemonClient::at(socket_path).status().await?.service_state,
            "running"
        );

        shutdown.send(true)?;
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        Ok(())
    }

    #[test]
    #[ignore = "requires host Unix-domain socket I/O"]
    fn daemon_socket_cleanup_preserves_a_replacement_socket(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("daemon.sock");
        let listener = StdUnixListener::bind(&path)?;
        let socket = DaemonSocket::from_bound_path(path.clone())?;
        fs::remove_file(&path)?;
        let replacement = StdUnixListener::bind(&path)?;

        drop(socket);
        assert!(path.exists());
        drop(replacement);
        drop(listener);
        Ok(())
    }

    fn state() -> Result<TestState, Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let paths = DaemonPaths::for_testing(root.path());
        let parent = match paths.config_path().parent() {
            Some(parent) => parent,
            None => return Err("test daemon config path has no parent".into()),
        };
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
        let security = DaemonSecurity::current_process();
        fs::write(
            paths.config_path(),
            format!(
                "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":4,\"max_idempotency_records\":4}}",
                security.socket_gid
            ),
        )?;
        fs::set_permissions(paths.config_path(), fs::Permissions::from_mode(0o600))?;
        paths.prepare(security)?;
        let configuration = DaemonConfig::load(&paths, security)?;
        let telemetry = JsonlTelemetry::open(paths.log_path(), configuration.max_log_bytes)?;
        let sessions = DaemonSessionApi::installed(&paths, &configuration)?;
        let approvals = DaemonApprovalRepository::installed(&paths)?;
        let (shutdown, _receiver) = tokio::sync::watch::channel(false);
        let state = Arc::new(DaemonControlState {
            idempotency: Mutex::new(DaemonIdempotencyStore::new(
                paths.idempotency_path(),
                paths.session_state_path(),
                configuration.max_idempotency_records as usize,
                Duration::from_secs(configuration.session_retry_horizon_seconds),
            )),
            paths,
            security,
            configuration: RwLock::new(DaemonConfiguration {
                value: configuration,
                generation: 1,
            }),
            telemetry,
            sessions,
            approvals,
            shutdown,
            active_streams: Arc::new(super::PerUidStreamLimiter::new()),
        });
        let child_deliveries: Arc<dyn erebor_runtime_session::ChildContextDeliveryHandler> =
            state.clone();
        state
            .sessions
            .bind_child_delivery_handler(child_deliveries)?;
        let operation_admissions: Arc<
            dyn erebor_runtime_session::ContextOperationAdmissionHandler,
        > = state.clone();
        state
            .sessions
            .bind_operation_admission_handler(operation_admissions)?;
        let agent_controls: Arc<dyn erebor_runtime_session::ContextAgentControlHandler> =
            state.clone();
        state.sessions.bind_agent_control_handler(agent_controls)?;
        Ok(TestState { state, _root: root })
    }

    struct TestState {
        state: Arc<DaemonControlState>,
        _root: TempDir,
    }

    fn seed_static_session_resources(
        test_state: &TestState,
        owner_uid: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const ADAPTER_DIGEST: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let package = AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            env!("CARGO_PKG_VERSION"),
            vec![String::from("<argv>")],
            ContentDigest::new(ADAPTER_DIGEST)?,
            Vec::new(),
        )?;
        let package_digest = package.canonical_digest()?;
        write_fixture_record(
            &test_state
                .state
                .paths
                .packages_state_path()
                .join(package_digest.as_str())
                .join("manifest.json"),
            &package.canonical_bytes()?,
        )?;
        let installation = InstallationRecord::new(owner_uid, package_digest, 1);
        let installation_digest = installation.canonical_digest()?;
        let user_root = test_state
            .state
            .paths
            .users_state_path()
            .join(owner_uid.to_string());
        write_fixture_record(
            &user_root
                .join("installations")
                .join(format!("{}.json", installation_digest.as_str())),
            &installation.canonical_bytes()?,
        )?;
        write_fixture_json(
            &user_root.join("agents/local-agent.json"),
            serde_json::json!({
                "apiVersion": "erebor.dev/v1",
                "kind": "Agent",
                "metadata": { "name": "local-agent" },
                "spec": { "adapter": "generic-process-v1" },
                "integrity_digest": installation_digest.as_str(),
            }),
        )?;

        let rule_document = br#"{"rules":[{"id":"mediate-managed-browser-launch","match":{"surface":"terminal","action":"process_exec","command_contains":"--remote-debugging-port"},"decision":"mediate","reason":"replace raw browser debug launches","mediation":{"kind":"managed_browser_cdp","replacement_surface":"browser_cdp","return_endpoint":"requested_port"}},{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#;
        let policy = PolicyPackageRevision::new(
            "browser-policy",
            b"name = \"browser-policy\"\n".to_vec(),
            BTreeMap::from([(String::from("terminal.json"), rule_document.to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Browser policy\n".to_vec(),
        )?;
        let policy_digest = policy.canonical_digest()?;
        write_fixture_record(
            &user_root
                .join("policy-packages")
                .join(format!("{}.json", policy_digest.as_str())),
            &policy.canonical_bytes()?,
        )?;
        write_fixture_json(
            &user_root.join("policy-package-names/browser-policy.json"),
            serde_json::json!({
                "apiVersion": "erebor.dev/v1",
                "kind": "PolicyPackage",
                "metadata": { "name": "browser-policy" },
                "spec": { "rules": serde_json::from_slice::<serde_json::Value>(rule_document)?["rules"] },
                "integrity_digest": policy_digest.as_str(),
            }),
        )?;
        let policy_set = PolicySetRevision::new(vec![policy_digest])?;
        let policy_set_digest = policy_set.canonical_digest()?;
        write_fixture_record(
            &user_root
                .join("policy-sets")
                .join(format!("{}.json", policy_set_digest.as_str())),
            &policy_set.canonical_bytes()?,
        )?;
        write_fixture_json(
            &user_root.join("policy-set-names/browser-policyset.json"),
            serde_json::json!({
                "apiVersion": "erebor.dev/v1",
                "kind": "PolicySet",
                "metadata": { "name": "browser-policyset" },
                "spec": { "packages": ["browser-policy"] },
                "integrity_digest": policy_set_digest.as_str(),
            }),
        )
    }

    fn write_fixture_json(
        path: &Path,
        value: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        write_fixture_record(path, &serde_json::to_vec(&value)?)
    }

    fn write_fixture_record(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let parent = path
            .parent()
            .ok_or("fixture record has no parent directory")?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}
