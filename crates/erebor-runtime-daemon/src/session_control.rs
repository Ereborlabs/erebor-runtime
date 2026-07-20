mod admission;
mod policy_fixture;
mod response;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use erebor_runtime_core::{
    ActiveSessionSignal, ImmutableIdentity, SessionHelperLaunchConfig, SessionLifecycleState,
    SessionRunnerKind, SessionSpec,
};
use erebor_runtime_ipc::v1::{
    SessionAttachResponse, SessionCreateRequest, SessionCreateResponse, SessionInputLeaseResponse,
    SessionListResponse, SessionPruneResponse, SessionRecord, KIND_SESSION_ATTACH_RESPONSE,
    KIND_SESSION_CREATE_RESPONSE, KIND_SESSION_INPUT_LEASE_RESPONSE, KIND_SESSION_PRUNE_RESPONSE,
    KIND_SESSION_RECORD,
};
use erebor_runtime_session::{
    output_endpoints, DurableSessionRecord, InputLeaseManager, RunnerRegistry, RuntimeGuardService,
    SessionInterceptionRouter, SessionOutputStores, SessionRepository, SessionRepositoryError,
    SessionSupervisor, SessionSupervisorError, StreamKind,
};
use prost::Message;
use rustix::fs::{makedev, open, statx, AtFlags, FileType, Mode, OFlags, StatxFlags};
use rustix::mount::{mount_bind, mount_remount, unmount, MountFlags, UnmountFlags};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use uuid::Uuid;

use crate::{
    config::DaemonConfig,
    error::{IoSnafu, RuntimeGuardSnafu, SessionOutputSnafu, SessionSnafu, StateLockSnafu},
    idempotency::{MutationIntent, MutationResponse},
    path_broker::DescriptorBroker,
    DaemonPaths, Result,
};

use self::{
    admission::{admit, AdmissionContext},
    policy_fixture::PhaseTwoProcessExecPolicy,
    response::session_record,
};

const INPUT_LEASE_DURATION: Duration = Duration::from_secs(30);
const GUARD_CREDENTIAL_FILE: &str = "runtime-guard.json";

pub(crate) struct DaemonSessionService {
    supervisor: Arc<SessionSupervisor>,
    guard: RuntimeGuardService,
    state_root: PathBuf,
    runtime_root: PathBuf,
    retry_horizon: Duration,
    leases: Mutex<BTreeMap<(u32, String), Arc<InputLeaseManager>>>,
    descriptor_broker: DescriptorBroker,
}

#[derive(Deserialize, Serialize)]
struct GuardCredential {
    schema_version: u32,
    token: String,
}

impl DaemonSessionService {
    pub(crate) fn installed(paths: &DaemonPaths, config: &DaemonConfig) -> Result<Self> {
        Self::new(
            paths,
            config,
            RunnerRegistry::compiled(SessionHelperLaunchConfig::default()),
        )
    }

    pub(crate) fn new(
        paths: &DaemonPaths,
        config: &DaemonConfig,
        runners: RunnerRegistry,
    ) -> Result<Self> {
        let state_root = paths.session_state_path();
        let runtime_root = paths.session_runtime_path();
        Ok(Self {
            supervisor: Arc::new(SessionSupervisor::new(
                SessionRepository::new(&state_root),
                runners,
            )),
            guard: RuntimeGuardService::new(&runtime_root).context(RuntimeGuardSnafu)?,
            state_root,
            runtime_root,
            retry_horizon: Duration::from_secs(config.session_retry_horizon_seconds),
            leases: Mutex::new(BTreeMap::new()),
            descriptor_broker: DescriptorBroker::installed(),
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
        let runner = parse_runner(&request.runner_id)?;
        let capability = self
            .supervisor
            .inspect_runner(runner)
            .context(SessionSnafu)?;
        let spec = admit(
            request,
            AdmissionContext {
                owner_uid,
                owner_gid,
                session_id: &session_id,
                root_configuration_generation: configuration_generation,
                state_root: &self.state_root,
                runtime_root: &self.runtime_root,
                capability,
                config,
                descriptor_broker: &self.descriptor_broker,
            },
        )?;
        self.supervisor
            .validate_admission(&spec)
            .context(SessionSnafu)?;
        Ok(spec)
    }

    pub(crate) fn apply(
        &self,
        intent: &MutationIntent,
        resume_pending: bool,
    ) -> Result<MutationResponse> {
        match intent {
            MutationIntent::SessionCreate { spec } => self.create((**spec).clone()),
            MutationIntent::SessionStart { uid, session_id } => {
                self.start(*uid, session_id, resume_pending)
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
            MutationIntent::Reload { .. } | MutationIntent::Stop => {
                unreachable!("daemon-only mutation reached session service")
            }
        }
    }

    pub(crate) fn inspect(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let record = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn list(&self, uid: u32) -> Result<SessionListResponse> {
        let sessions = self
            .supervisor
            .list(uid)
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn list_all(&self) -> Result<SessionListResponse> {
        let sessions = self
            .supervisor
            .list_all()
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn wait(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let current = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let record = if current.state().is_terminal() {
            current
        } else {
            self.supervisor
                .wait(uid, session_id)
                .context(SessionSnafu)?
        };
        self.finalize_runtime_resources(&record)?;
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
        let record = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let stores = self.output_stores(record.spec())?;
        stores
            .stream(kind)
            .read_after(after_sequence, maximum_records)
            .context(SessionOutputSnafu)
    }

    pub(crate) fn has_unresolved_sessions(&self) -> Result<bool> {
        Ok(self
            .supervisor
            .list_all()
            .context(SessionSnafu)?
            .iter()
            .any(|record| !record.state().is_terminal()))
    }

    pub(crate) fn validate_start(
        &self,
        uid: u32,
        session_id: &str,
        config: &DaemonConfig,
    ) -> Result<()> {
        let record = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if record.state() != SessionLifecycleState::Created {
            return Ok(());
        }
        self.supervisor
            .validate_admission(record.spec())
            .context(SessionSnafu)?;
        self.revalidate_path_identities(record.spec())?;
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
        Ok(())
    }

    fn revalidate_path_identities(&self, spec: &SessionSpec) -> Result<()> {
        let workspace = self.descriptor_broker.resolve(
            spec.owner().uid(),
            spec.owner().gid(),
            spec.workspace().requested_path(),
            erebor_runtime_core::SafePathKind::Directory,
        )?;
        if workspace.binding() != spec.workspace() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("workspace identity changed after session admission"),
            }
            .fail();
        }
        if let Some(binding) = spec.executable() {
            let executable = self.descriptor_broker.resolve(
                spec.owner().uid(),
                spec.owner().gid(),
                binding.requested_path(),
                erebor_runtime_core::SafePathKind::Executable,
            )?;
            if executable.binding() != binding {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from("executable identity changed after session admission"),
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(crate) fn reconcile(&self) -> Result<Vec<DurableSessionRecord>> {
        let candidates = self.supervisor.list_all().context(SessionSnafu)?;
        let mut reconciled = Vec::new();
        for record in candidates {
            if !matches!(
                record.state(),
                SessionLifecycleState::Starting
                    | SessionLifecycleState::Running
                    | SessionLifecycleState::Stopping
                    | SessionLifecycleState::ControlLost
            ) {
                continue;
            }
            let output = self.prepare_runtime(record.spec(), true)?;
            let reduced = self
                .supervisor
                .reconcile_session(
                    record.spec().owner().uid(),
                    record.spec().session_id().as_str(),
                    &output,
                )
                .context(SessionSnafu)?;
            if reduced.state().is_terminal() {
                self.finalize_runtime_resources(&reduced)?;
            }
            reconciled.push(reduced);
        }
        Ok(reconciled)
    }

    fn create(&self, spec: SessionSpec) -> Result<MutationResponse> {
        let record = match self.supervisor.create(spec.clone()) {
            Ok(record) => record,
            Err(SessionSupervisorError::Repository {
                source: SessionRepositoryError::AlreadyExists { .. },
                ..
            }) => self
                .supervisor
                .inspect(spec.owner().uid(), spec.session_id().as_str())
                .context(SessionSnafu)?,
            Err(source) => return Err(source).context(SessionSnafu),
        };
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

    fn start(&self, uid: u32, session_id: &str, resume_pending: bool) -> Result<MutationResponse> {
        let current = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let record = if current.state() == SessionLifecycleState::Created {
            let starting = self
                .supervisor
                .begin_start(uid, session_id)
                .context(SessionSnafu)?;
            let output = match self.prepare_runtime(starting.spec(), false) {
                Ok(output) => output,
                Err(error) => {
                    let _failed = self
                        .supervisor
                        .fail_start(uid, session_id, error.to_string());
                    let _guard = self.guard.stop_session(uid, session_id);
                    let _staging = self.cleanup_staging(starting.spec());
                    return Err(error);
                }
            };
            match self.supervisor.launch_start(starting, &output) {
                Ok(record) => record,
                Err(source) => {
                    let _cleanup = self.guard.stop_session(uid, session_id);
                    let _staging = self.cleanup_staging(current.spec());
                    return Err(source).context(SessionSnafu);
                }
            }
        } else if resume_pending {
            current
        } else {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "session `{session_id}` cannot start from state `{}`",
                    current.state().as_str()
                ),
            }
            .fail();
        };
        if record.state().is_terminal() {
            self.finalize_runtime_resources(&record)?;
        }
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn stop(
        &self,
        uid: u32,
        session_id: &str,
        grace_period_seconds: u64,
    ) -> Result<MutationResponse> {
        let current = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let record = if current.state().is_terminal() {
            current
        } else {
            self.supervisor
                .stop(
                    uid,
                    session_id,
                    Duration::from_secs(grace_period_seconds.max(1)),
                )
                .context(SessionSnafu)?
        };
        self.finalize_runtime_resources(&record)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn kill(
        &self,
        uid: u32,
        session_id: &str,
        signal: ActiveSessionSignal,
    ) -> Result<MutationResponse> {
        let current = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let record = if current.state().is_terminal() {
            current
        } else {
            self.supervisor
                .kill(uid, session_id, signal)
                .context(SessionSnafu)?
        };
        self.finalize_runtime_resources(&record)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn remove(&self, uid: u32, session_id: &str, force: bool) -> Result<MutationResponse> {
        let current = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        let record = if current.state() == SessionLifecycleState::Removed {
            current
        } else {
            self.supervisor
                .remove(uid, session_id, force)
                .context(SessionSnafu)?
        };
        self.finalize_runtime_resources(&record)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn attach(
        &self,
        uid: u32,
        session_id: &str,
        request_input_lease: bool,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let record = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if !record.spec().runner_capability().attach_supported() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("the admitted runner does not support attach"),
            }
            .fail();
        }
        if request_input_lease && !record.spec().tty() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("input leases require an interactive TTY session"),
            }
            .fail();
        }
        let lease = if request_input_lease {
            Some(
                self.lease(uid, session_id)?
                    .acquire(client_instance_id, INPUT_LEASE_DURATION)
                    .context(SessionOutputSnafu)?,
            )
        } else {
            None
        };
        message(
            KIND_SESSION_ATTACH_RESPONSE,
            &SessionAttachResponse {
                session_id: record.spec().session_id().as_str().to_owned(),
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
        self.require_input_lease_session(uid, session_id)?;
        let lease = self
            .lease(uid, session_id)?
            .renew(lease_id, client_instance_id, INPUT_LEASE_DURATION)
            .context(SessionOutputSnafu)?;
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
        self.require_input_lease_session(uid, session_id)?;
        self.lease(uid, session_id)?
            .release(lease_id, client_instance_id)
            .context(SessionOutputSnafu)?;
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
            .supervisor
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
            .supervisor
            .set_retention_hold(uid, session_id, retention_hold)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn prepare_runtime(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<erebor_runtime_core::OutputEndpoints> {
        let _stores = self.output_stores(spec)?;
        let (workspace, executable) = self.prepare_staging(spec, recovering)?;
        let mut output = output_endpoints(spec).with_prepared_execution(workspace, executable);
        if spec.runner_capability().physical_interception() {
            let credential = self.guard_credential(spec, recovering)?;
            let endpoint = self
                .guard
                .start_session_with_token(
                    spec.owner().uid(),
                    spec.owner().gid(),
                    spec.session_id().as_str(),
                    "agent",
                    SessionInterceptionRouter::new().with_process_exec_handler(
                        PhaseTwoProcessExecPolicy::new(spec.policy_set().clone()),
                    ),
                    Some(credential.token),
                )
                .context(RuntimeGuardSnafu)?;
            output = output.with_runtime_environment(endpoint.environment());
        }
        Ok(output)
    }

    fn prepare_staging(
        &self,
        spec: &SessionSpec,
        recovering: bool,
    ) -> Result<(PathBuf, Option<PathBuf>)> {
        let staging = self
            .runtime_root
            .join(spec.owner().uid().to_string())
            .join(spec.session_id().as_str())
            .join("staging");
        let workspace = staging.join("workspace");
        let executable = spec.executable().map(|_| staging.join("executable"));
        if recovering {
            self.verify_staging(&workspace, spec.workspace())?;
            if let (Some(path), Some(binding)) = (&executable, spec.executable()) {
                self.verify_staging(path, binding)?;
            }
            return Ok((workspace, executable));
        }
        fs::create_dir_all(&staging).context(IoSnafu {
            action: "creating daemon-owned session staging directory",
            path: &staging,
        })?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).context(IoSnafu {
            action: "protecting daemon-owned session staging directory",
            path: &staging,
        })?;
        let workspace_source = self.descriptor_broker.resolve(
            spec.owner().uid(),
            spec.owner().gid(),
            spec.workspace().requested_path(),
            erebor_runtime_core::SafePathKind::Directory,
        )?;
        if workspace_source.binding() != spec.workspace() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("workspace identity changed after session admission"),
            }
            .fail();
        }
        fs::create_dir(&workspace).context(IoSnafu {
            action: "creating workspace staging mountpoint",
            path: &workspace,
        })?;
        bind_descriptor(workspace_source.descriptor(), &workspace, false)?;
        if let (Some(target), Some(binding)) = (&executable, spec.executable()) {
            let source = self.descriptor_broker.resolve(
                spec.owner().uid(),
                spec.owner().gid(),
                binding.requested_path(),
                erebor_runtime_core::SafePathKind::Executable,
            )?;
            if source.binding() != binding {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from("executable identity changed after session admission"),
                }
                .fail();
            }
            File::create(target).context(IoSnafu {
                action: "creating executable staging mountpoint",
                path: target,
            })?;
            bind_descriptor(source.descriptor(), target, true)?;
        }
        Ok((workspace, executable))
    }

    fn verify_staging(
        &self,
        path: &Path,
        binding: &erebor_runtime_core::SafePathBinding,
    ) -> Result<()> {
        let descriptor = open(path, OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "opening persistent session staging mount",
                path,
            })?;
        let status = statx(
            &descriptor,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "verifying persistent session staging mount",
            path,
        })?;
        let parent = path.parent().ok_or_else(|| {
            crate::error::InvalidRequestSnafu {
                reason: format!("staging mount `{}` has no parent", path.display()),
            }
            .build()
        })?;
        let parent_descriptor = open(parent, OFlags::PATH | OFlags::NOFOLLOW, Mode::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "opening persistent session staging parent",
                path: parent,
            })?;
        let parent_status = statx(
            &parent_descriptor,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "verifying persistent session staging parent",
            path: parent,
        })?;
        let file_type = FileType::from_raw_mode(status.stx_mode.into());
        let valid_kind = match binding.kind() {
            erebor_runtime_core::SafePathKind::Directory => file_type.is_dir(),
            erebor_runtime_core::SafePathKind::Executable => {
                file_type.is_file() && status.stx_mode & 0o111 != 0
            }
            erebor_runtime_core::SafePathKind::File => file_type.is_file(),
        };
        if makedev(status.stx_dev_major, status.stx_dev_minor) != binding.device()
            || status.stx_ino != binding.inode()
            || status.stx_uid != binding.owner_uid()
            || status.stx_gid != binding.owner_gid()
            || !valid_kind
            || status.stx_mnt_id == parent_status.stx_mnt_id
        {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "staging mount `{}` no longer matches its admitted identity",
                    path.display()
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn output_stores(&self, spec: &SessionSpec) -> Result<SessionOutputStores> {
        SessionOutputStores::open(spec.output()).context(SessionOutputSnafu)
    }

    fn guard_credential(&self, spec: &SessionSpec, recovering: bool) -> Result<GuardCredential> {
        let path = self.guard_credential_path(spec);
        if recovering || path.exists() {
            let encoded = fs::read(&path).context(IoSnafu {
                action: "reading runtime guard credential",
                path: &path,
            })?;
            return serde_json::from_slice(&encoded).map_err(|source| {
                crate::DaemonError::InvalidConfig {
                    path,
                    source,
                    location: snafu::Location::default(),
                }
            });
        }
        let credential = GuardCredential {
            schema_version: 1,
            token: Uuid::new_v4().simple().to_string(),
        };
        write_secure_json(&path, &credential)?;
        Ok(credential)
    }

    fn finalize_runtime_resources(&self, record: &DurableSessionRecord) -> Result<()> {
        if !record.state().is_terminal() {
            return Ok(());
        }
        let uid = record.spec().owner().uid();
        let session_id = record.spec().session_id().as_str();
        self.guard
            .stop_session(uid, session_id)
            .context(RuntimeGuardSnafu)?;
        self.leases
            .lock()
            .map_err(|_error| StateLockSnafu.build())?
            .remove(&(uid, session_id.to_owned()));
        let credential = self.guard_credential_path(record.spec());
        match fs::remove_file(&credential) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "removing terminal runtime guard credential",
                    path: credential,
                });
            }
        }
        self.cleanup_staging(record.spec())?;
        Ok(())
    }

    fn cleanup_staging(&self, spec: &SessionSpec) -> Result<()> {
        let staging = self
            .runtime_root
            .join(spec.owner().uid().to_string())
            .join(spec.session_id().as_str())
            .join("staging");
        for target in [staging.join("executable"), staging.join("workspace")] {
            match unmount(&target, UnmountFlags::NOFOLLOW) {
                Ok(()) => {}
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOENT) => {}
                Err(error) => {
                    return Err(std::io::Error::from(error)).context(IoSnafu {
                        action: "unmounting terminal session staging",
                        path: target,
                    });
                }
            }
        }
        match fs::remove_dir_all(&staging) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "removing terminal session staging",
                    path: staging,
                });
            }
        }
        let session_runtime = self
            .runtime_root
            .join(spec.owner().uid().to_string())
            .join(spec.session_id().as_str());
        match fs::remove_dir(&session_runtime) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(source) => {
                return Err(source).context(IoSnafu {
                    action: "removing terminal session runtime directory",
                    path: session_runtime,
                });
            }
        }
        Ok(())
    }

    fn guard_credential_path(&self, spec: &SessionSpec) -> PathBuf {
        self.state_root
            .join("users")
            .join(spec.owner().uid().to_string())
            .join("sessions")
            .join(spec.session_id().as_str())
            .join(GUARD_CREDENTIAL_FILE)
    }

    fn lease(&self, uid: u32, session_id: &str) -> Result<Arc<InputLeaseManager>> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_error| StateLockSnafu.build())?;
        Ok(Arc::clone(
            leases
                .entry((uid, session_id.to_owned()))
                .or_insert_with(|| Arc::new(InputLeaseManager::new(session_id))),
        ))
    }

    fn require_input_lease_session(&self, uid: u32, session_id: &str) -> Result<()> {
        let record = self
            .supervisor
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if record.state() == SessionLifecycleState::Running
            && record.spec().tty()
            && record.spec().runner_capability().attach_supported()
        {
            Ok(())
        } else {
            crate::error::InvalidRequestSnafu {
                reason: String::from("input leases require an attachable interactive TTY session"),
            }
            .fail()
        }
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

fn parse_runner(value: &str) -> Result<SessionRunnerKind> {
    match value {
        "linux-host" | "linux_host" => Ok(SessionRunnerKind::LinuxHost),
        "docker" => Ok(SessionRunnerKind::Docker),
        _ => crate::error::InvalidRequestSnafu {
            reason: format!("unknown runner `{value}`"),
        }
        .fail(),
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

fn write_secure_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        crate::error::UnsafePathSnafu {
            path: path.to_path_buf(),
            reason: String::from("credential path has no parent"),
        }
        .build()
    })?;
    fs::create_dir_all(parent).context(IoSnafu {
        action: "creating runtime guard credential directory",
        path: parent,
    })?;
    let temporary = path.with_extension("tmp");
    let encoded =
        serde_json::to_vec(value).map_err(|source| crate::DaemonError::InvalidConfig {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context(IoSnafu {
            action: "writing runtime guard credential",
            path: &temporary,
        })?;
    file.write_all(&encoded).context(IoSnafu {
        action: "writing runtime guard credential",
        path: &temporary,
    })?;
    file.sync_all().context(IoSnafu {
        action: "syncing runtime guard credential",
        path: &temporary,
    })?;
    fs::rename(&temporary, path).context(IoSnafu {
        action: "publishing runtime guard credential",
        path,
    })?;
    File::open(parent)
        .context(IoSnafu {
            action: "opening runtime guard credential directory",
            path: parent,
        })?
        .sync_all()
        .context(IoSnafu {
            action: "syncing runtime guard credential directory",
            path: parent,
        })
}

fn bind_descriptor(descriptor: &File, target: &Path, read_only: bool) -> Result<()> {
    let source = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
    mount_bind(&source, target)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "bind-mounting a held descriptor into session staging",
            path: target,
        })?;
    let mut flags = MountFlags::BIND | MountFlags::NOSUID | MountFlags::NODEV;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    mount_remount(target, flags, "")
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "locking session staging mount flags",
            path: target,
        })
}
