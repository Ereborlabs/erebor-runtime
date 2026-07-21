mod admission;
mod policy_fixture;
mod response;

use std::{path::PathBuf, sync::Arc, time::Duration};

use erebor_runtime_core::{
    ActiveSessionSignal, ImmutableIdentity, SessionLifecycleState, SessionOwner, SessionSpec,
};
use erebor_runtime_ipc::v1::{
    SessionAttachResponse, SessionCreateRequest, SessionCreateResponse, SessionInputLeaseResponse,
    SessionListResponse, SessionPruneResponse, SessionRecord, KIND_SESSION_ATTACH_RESPONSE,
    KIND_SESSION_CREATE_RESPONSE, KIND_SESSION_INPUT_LEASE_RESPONSE, KIND_SESSION_PRUNE_RESPONSE,
    KIND_SESSION_RECORD,
};
use erebor_runtime_session::{
    DurableSessionRecord, RunnerAdmissionRequest, RunnerInstallConfig, RunnerRegistry,
    SessionManager, SessionManagerError, SessionRepository, SessionRepositoryError,
    SessionRuntimeResources, StreamKind, ValidatedStartConstraints,
};
use prost::Message;
use snafu::ResultExt;
use uuid::Uuid;

use crate::{
    config::DaemonConfig,
    error::SessionSnafu,
    idempotency::{MutationIntent, MutationResponse},
    local_store::DaemonLocalStore,
    path_broker::DescriptorBroker,
    DaemonPaths, Result,
};

use self::{
    admission::{admit, parse_request, AdmissionContext},
    policy_fixture::PhaseTwoInterceptionRouterFactory,
    response::session_record,
};

pub(crate) struct DaemonSessionApi {
    manager: Arc<SessionManager>,
    state_root: PathBuf,
    runtime_root: PathBuf,
    retry_horizon: Duration,
    descriptor_broker: Arc<DescriptorBroker>,
    local_store: DaemonLocalStore,
}

impl DaemonSessionApi {
    pub(crate) fn installed(paths: &DaemonPaths, config: &DaemonConfig) -> Result<Self> {
        Self::new(
            paths,
            config,
            RunnerRegistry::compiled(RunnerInstallConfig::default()).context(SessionSnafu)?,
        )
    }

    pub(crate) fn new(
        paths: &DaemonPaths,
        config: &DaemonConfig,
        runners: RunnerRegistry,
    ) -> Result<Self> {
        let state_root = paths.session_state_path();
        let runtime_root = paths.session_runtime_path();
        let descriptor_broker = Arc::new(DescriptorBroker::installed());
        let local_store = DaemonLocalStore::installed(paths)?;
        let runtime = SessionRuntimeResources::new(
            state_root.clone(),
            runtime_root.clone(),
            Arc::clone(&descriptor_broker) as Arc<dyn erebor_runtime_session::SessionPathResolver>,
            Arc::new(PhaseTwoInterceptionRouterFactory),
        )
        .context(SessionSnafu)?;
        Ok(Self {
            manager: Arc::new(SessionManager::new(
                SessionRepository::new(&state_root),
                runners,
                runtime,
            )),
            state_root,
            runtime_root,
            retry_horizon: Duration::from_secs(config.session_retry_horizon_seconds),
            descriptor_broker,
            local_store,
        })
    }

    pub(crate) fn admit_request(
        &self,
        request: SessionCreateRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<SessionSpec> {
        let session_id = format!("session-{}", Uuid::new_v4());
        let request = parse_request(request)?;
        let runner = request.runner().clone();
        let capability = self.manager.inspect_runner(&runner).context(SessionSnafu)?;
        let owner = SessionOwner::new(owner_uid, owner_gid);
        let runner_admission = self
            .manager
            .admit_runner(
                &runner,
                RunnerAdmissionRequest::new(
                    &session_id,
                    &owner,
                    request.command(),
                    request.workspace(),
                    request.container_image_sha256(),
                    &self.runtime_root.join("runtime-interception.sock"),
                ),
                self.descriptor_broker.as_ref(),
            )
            .context(SessionSnafu)?;
        let spec = admit(
            request,
            AdmissionContext {
                owner,
                session_id: &session_id,
                root_configuration_generation: configuration_generation,
                state_root: &self.state_root,
                capability,
                runner_admission,
                config,
            },
        )?;
        self.manager
            .validate_admission(&spec)
            .context(SessionSnafu)?;
        Ok(spec)
    }

    pub(crate) fn apply(&self, intent: &MutationIntent) -> Result<MutationResponse> {
        match intent {
            MutationIntent::SessionCreate { spec } => self.create((**spec).clone()),
            MutationIntent::SessionStart { .. } => {
                unreachable!("session start requires validated root constraints")
            }
            MutationIntent::SessionStop {
                uid,
                session_id,
                grace_period_seconds,
            } => self.stop(*uid, session_id, *grace_period_seconds),
            MutationIntent::SessionKill {
                uid,
                session_id,
                signal,
            } => self.kill(*uid, session_id, *signal),
            MutationIntent::SessionRemove {
                uid,
                session_id,
                force,
            } => self.remove(*uid, session_id, *force),
            MutationIntent::SessionAttach {
                uid,
                session_id,
                request_input_lease,
                client_instance_id,
            } => self.attach(*uid, session_id, *request_input_lease, client_instance_id),
            MutationIntent::SessionInputLeaseRenew {
                uid,
                session_id,
                lease_id,
                client_instance_id,
            } => self.renew_lease(*uid, session_id, lease_id, client_instance_id),
            MutationIntent::SessionInputLeaseRelease {
                uid,
                session_id,
                lease_id,
                client_instance_id,
            } => self.release_lease(*uid, session_id, lease_id, client_instance_id),
            MutationIntent::SessionPrune {
                uid,
                terminal_before_unix_ms,
                maximum_sessions,
            } => self.prune(*uid, *terminal_before_unix_ms, *maximum_sessions),
            MutationIntent::SessionSetRetentionHold {
                uid,
                session_id,
                retention_hold,
            } => self.set_retention_hold(*uid, session_id, *retention_hold),
            MutationIntent::Reload { .. }
            | MutationIntent::Stop
            | MutationIntent::ApprovalApprove { .. }
            | MutationIntent::ApprovalDeny { .. } => {
                unreachable!("daemon-only mutation reached session service")
            }
        }
    }

    pub(crate) fn inspect(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let record = self
            .manager
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn list(&self, uid: u32) -> Result<SessionListResponse> {
        let sessions = self
            .manager
            .list(uid)
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn list_all(&self) -> Result<SessionListResponse> {
        let sessions = self
            .manager
            .list_all()
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn wait(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let record = self.manager.wait(uid, session_id).context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn stream(
        &self,
        uid: u32,
        session_id: &str,
        kind: StreamKind,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<erebor_runtime_session::DurableStreamCursor> {
        self.manager
            .stream(uid, session_id, kind, after_sequence, maximum_records)
            .context(SessionSnafu)
    }

    pub(crate) fn has_unresolved_sessions(&self) -> Result<bool> {
        self.manager.has_unresolved_sessions().context(SessionSnafu)
    }

    pub(crate) fn validate_start(
        &self,
        uid: u32,
        session_id: &str,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<ValidatedStartConstraints> {
        let record = self
            .manager
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if record.state() != SessionLifecycleState::Created {
            return Ok(ValidatedStartConstraints::new(
                uid,
                session_id,
                configuration_generation,
            ));
        }
        self.manager
            .validate_admission(record.spec())
            .context(SessionSnafu)?;
        let output = record.spec().output();
        let fixture_is_current = config
            .phase_two_fixture(
                record.spec().package().map(ImmutableIdentity::sha256),
                record.spec().installation().map(ImmutableIdentity::sha256),
                record.spec().adapter().map(ImmutableIdentity::sha256),
                record.spec().policy_set().sha256(),
            )
            .is_some_and(|fixture| {
                fixture
                    .policy_input_digests()
                    .iter()
                    .map(String::as_str)
                    .eq(record
                        .spec()
                        .policy_inputs()
                        .iter()
                        .map(ImmutableIdentity::sha256))
            });
        if record.spec().loss_grace_seconds() > config.max_daemon_loss_grace_seconds
            || output.maximum_bytes() > config.max_session_output_bytes
            || output.rotation_bytes() > config.session_output_rotation_bytes
            || !fixture_is_current
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "session no longer satisfies the active root start constraints",
                ),
            }
            .fail();
        }
        Ok(ValidatedStartConstraints::new(
            uid,
            session_id,
            configuration_generation,
        ))
    }

    pub(crate) fn reconcile(&self) -> Result<Vec<DurableSessionRecord>> {
        self.manager.reconcile().context(SessionSnafu)
    }

    fn create(&self, spec: SessionSpec) -> Result<MutationResponse> {
        let record = match self.manager.create(spec.clone()) {
            Ok(record) => record,
            Err(SessionManagerError::Repository {
                source: SessionRepositoryError::AlreadyExists { .. },
                ..
            }) => self
                .manager
                .inspect(spec.owner().uid(), spec.session_id().as_str())
                .context(SessionSnafu)?,
            Err(source) => return Err(source).context(SessionSnafu),
        };
        self.local_store.record_session_lease(record.spec())?;
        message(
            KIND_SESSION_CREATE_RESPONSE,
            &SessionCreateResponse {
                session_id: record.spec().session_id().as_str().to_owned(),
                state: record.state().as_str().to_owned(),
                generation: record.generation(),
                retry_guarantee_expires_unix_ms: self.retry_expiration(&record),
            },
        )
    }

    pub(crate) fn start(
        &self,
        uid: u32,
        session_id: &str,
        constraints: &ValidatedStartConstraints,
        resume_pending: bool,
    ) -> Result<MutationResponse> {
        let record = self
            .manager
            .start(uid, session_id, constraints, resume_pending)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn stop(
        &self,
        uid: u32,
        session_id: &str,
        grace_period_seconds: u64,
    ) -> Result<MutationResponse> {
        let record = self
            .manager
            .stop(
                uid,
                session_id,
                Duration::from_secs(grace_period_seconds.max(1)),
            )
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn kill(
        &self,
        uid: u32,
        session_id: &str,
        signal: ActiveSessionSignal,
    ) -> Result<MutationResponse> {
        let record = self
            .manager
            .kill(uid, session_id, signal)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn remove(&self, uid: u32, session_id: &str, force: bool) -> Result<MutationResponse> {
        let record = self
            .manager
            .remove(uid, session_id, force)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn attach(
        &self,
        uid: u32,
        session_id: &str,
        request_input_lease: bool,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let outcome = self
            .manager
            .attach(uid, session_id, request_input_lease, client_instance_id)
            .context(SessionSnafu)?;
        let lease = outcome.lease();
        message(
            KIND_SESSION_ATTACH_RESPONSE,
            &SessionAttachResponse {
                session_id: session_id.to_owned(),
                read_only: lease.is_none(),
                input_lease_id: lease
                    .as_ref()
                    .map_or_else(String::new, |value| value.lease_id().to_owned()),
                input_lease_expires_unix_ms: lease
                    .as_ref()
                    .map_or(0, |value| value.expires_unix_ms()),
            },
        )
    }

    fn renew_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let lease = self
            .manager
            .renew_input_lease(uid, session_id, lease_id, client_instance_id)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            &SessionInputLeaseResponse {
                session_id: session_id.to_owned(),
                input_lease_id: lease.lease_id().to_owned(),
                expires_unix_ms: lease.expires_unix_ms(),
                released: false,
            },
        )
    }

    fn release_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        self.manager
            .release_input_lease(uid, session_id, lease_id, client_instance_id)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            &SessionInputLeaseResponse {
                session_id: session_id.to_owned(),
                input_lease_id: lease_id.to_owned(),
                expires_unix_ms: 0,
                released: true,
            },
        )
    }

    fn prune(
        &self,
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: u32,
    ) -> Result<MutationResponse> {
        let result = self
            .manager
            .prune(
                uid,
                terminal_before_unix_ms,
                maximum_sessions.max(1) as usize,
            )
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_PRUNE_RESPONSE,
            &SessionPruneResponse {
                pruned_sessions: result.pruned as u32,
                retained_session_ids: result.retained_session_ids,
            },
        )
    }

    fn set_retention_hold(
        &self,
        uid: u32,
        session_id: &str,
        retention_hold: bool,
    ) -> Result<MutationResponse> {
        let record = self
            .manager
            .set_retention_hold(uid, session_id, retention_hold)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn record(&self, record: &DurableSessionRecord) -> SessionRecord {
        session_record(record, self.retry_expiration(record))
    }

    fn retry_expiration(&self, record: &DurableSessionRecord) -> u64 {
        if record.state() == erebor_runtime_core::SessionLifecycleState::Removed {
            record
                .updated_at_unix_ms()
                .saturating_add(self.retry_horizon.as_millis() as u64)
        } else {
            u64::MAX
        }
    }
}

fn message(kind: &str, value: &impl Message) -> Result<MutationResponse> {
    let mut payload = Vec::with_capacity(value.encoded_len());
    value
        .encode(&mut payload)
        .map_err(|source| crate::DaemonError::Ipc {
            source: erebor_runtime_ipc::IpcProtocolError::EncodePayload {
                source,
                location: snafu::Location::default(),
            },
            location: snafu::Location::default(),
        })?;
    Ok(MutationResponse {
        message_kind: kind.to_owned(),
        payload,
    })
}
