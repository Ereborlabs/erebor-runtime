use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal, DaemonFailureMode,
    DockerSessionRunner, LinuxHostSessionRunner, OutputEndpoints, RunnerBinding,
    SessionHelperLaunchConfig, SessionLifecycleState, SessionRunner, SessionRunnerKind,
    SessionSpec,
};
use snafu::{OptionExt, ResultExt};

mod resources;

pub use resources::{
    ResolvedSessionPath, SessionInterceptionRouterFactory, SessionPathResolver,
    SessionPathResolverError, SessionRuntimeResources,
};

use crate::{
    error::session_manager::{
        ActiveHandleLockSnafu, ActiveHandleMissingSnafu, CapabilityChangedSnafu, OutputSnafu,
        RepositorySnafu, RunnerSnafu, RunnerUnavailableSnafu, StateLockSnafu,
    },
    DurableSessionRecord, DurableStreamCursor, InputLease, InputLeaseManager, SessionManagerError,
    SessionPruneResult, SessionRepository, SessionRepositoryError, StreamKind,
};

use self::resources::SessionRuntime;

type ActiveHandle = Arc<Mutex<Box<dyn ActiveSession>>>;
type ActiveHandles = BTreeMap<(u32, String), ActiveHandle>;
type InputLeases = BTreeMap<(u32, String), Arc<InputLeaseManager>>;

const INPUT_LEASE_DURATION: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct SessionAttachOutcome {
    lease: Option<InputLease>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStartConstraints {
    owner_uid: u32,
    session_id: String,
    root_configuration_generation: u64,
}

impl ValidatedStartConstraints {
    #[must_use]
    pub fn new(
        owner_uid: u32,
        session_id: impl Into<String>,
        root_configuration_generation: u64,
    ) -> Self {
        Self {
            owner_uid,
            session_id: session_id.into(),
            root_configuration_generation,
        }
    }

    fn authorizes(&self, record: &DurableSessionRecord) -> bool {
        self.owner_uid == record.spec().owner().uid()
            && self.session_id == record.spec().session_id().as_str()
            && self.root_configuration_generation >= record.spec().root_configuration_generation()
    }
}

impl SessionAttachOutcome {
    #[must_use]
    pub const fn lease(&self) -> Option<&InputLease> {
        self.lease.as_ref()
    }
}

pub struct RunnerRegistry {
    runners: BTreeMap<SessionRunnerKind, Arc<dyn SessionRunner>>,
}

impl RunnerRegistry {
    #[must_use]
    pub fn new(runners: impl IntoIterator<Item = Arc<dyn SessionRunner>>) -> Self {
        Self {
            runners: runners
                .into_iter()
                .map(|runner| (runner.kind(), runner))
                .collect(),
        }
    }

    pub fn get(
        &self,
        kind: SessionRunnerKind,
    ) -> Result<&Arc<dyn SessionRunner>, SessionManagerError> {
        self.runners
            .get(&kind)
            .context(RunnerUnavailableSnafu { runner: kind })
    }

    #[must_use]
    pub fn compiled(helper: SessionHelperLaunchConfig) -> Self {
        Self::new([
            Arc::new(LinuxHostSessionRunner::new(helper.clone())) as Arc<dyn SessionRunner>,
            Arc::new(DockerSessionRunner::new(helper)) as Arc<dyn SessionRunner>,
        ])
    }

    pub fn inspect(
        &self,
        kind: SessionRunnerKind,
    ) -> Result<erebor_runtime_core::RunnerCapabilityDocument, SessionManagerError> {
        self.get(kind)?.inspect().context(RunnerSnafu)
    }
}

pub struct SessionManager {
    repository: SessionRepository,
    runners: RunnerRegistry,
    runtime: Arc<dyn SessionRuntime>,
    active: Mutex<ActiveHandles>,
    leases: Mutex<InputLeases>,
}

impl SessionManager {
    #[must_use]
    pub fn new(
        repository: SessionRepository,
        runners: RunnerRegistry,
        runtime: SessionRuntimeResources,
    ) -> Self {
        Self::new_with_runtime(repository, runners, Arc::new(runtime))
    }

    fn new_with_runtime(
        repository: SessionRepository,
        runners: RunnerRegistry,
        runtime: Arc<dyn SessionRuntime>,
    ) -> Self {
        Self {
            repository,
            runners,
            runtime,
            active: Mutex::new(BTreeMap::new()),
            leases: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn create(&self, spec: SessionSpec) -> Result<DurableSessionRecord, SessionManagerError> {
        self.repository.create(spec).context(RepositorySnafu)
    }

    pub fn inspect(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        self.repository
            .load(uid, session_id)
            .context(RepositorySnafu)
    }

    pub fn list(&self, uid: u32) -> Result<Vec<DurableSessionRecord>, SessionManagerError> {
        self.repository.list(uid).context(RepositorySnafu)
    }

    pub fn list_all(&self) -> Result<Vec<DurableSessionRecord>, SessionManagerError> {
        let mut records = Vec::new();
        for uid in self.repository.user_ids().context(RepositorySnafu)? {
            records.extend(self.list(uid)?);
        }
        Ok(records)
    }

    pub fn stream(
        &self,
        uid: u32,
        session_id: &str,
        kind: StreamKind,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<DurableStreamCursor, SessionManagerError> {
        let record = self.inspect(uid, session_id)?;
        self.runtime
            .stream(record.spec(), kind, after_sequence, maximum_records)
    }

    pub fn has_unresolved_sessions(&self) -> Result<bool, SessionManagerError> {
        Ok(self
            .list_all()?
            .iter()
            .any(|record| !record.state().is_terminal()))
    }

    pub fn attach(
        &self,
        uid: u32,
        session_id: &str,
        request_input_lease: bool,
        client_instance_id: &str,
    ) -> Result<SessionAttachOutcome, SessionManagerError> {
        let record = self.inspect(uid, session_id)?;
        if !record.spec().runner_capability().attach_supported() {
            return Err(SessionManagerError::InvalidOperation {
                session_id: session_id.to_owned(),
                reason: String::from("the admitted runner does not support attach"),
                location: snafu::Location::default(),
            });
        }
        if request_input_lease && !record.spec().tty() {
            return Err(SessionManagerError::InvalidOperation {
                session_id: session_id.to_owned(),
                reason: String::from("input leases require an interactive TTY session"),
                location: snafu::Location::default(),
            });
        }
        let lease = if request_input_lease {
            Some(
                self.lease(uid, session_id)?
                    .acquire(client_instance_id, INPUT_LEASE_DURATION)
                    .context(OutputSnafu)?,
            )
        } else {
            None
        };
        Ok(SessionAttachOutcome { lease })
    }

    pub fn renew_input_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<InputLease, SessionManagerError> {
        self.require_input_lease_session(uid, session_id)?;
        self.lease(uid, session_id)?
            .renew(lease_id, client_instance_id, INPUT_LEASE_DURATION)
            .context(OutputSnafu)
    }

    pub fn release_input_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<(), SessionManagerError> {
        self.require_input_lease_session(uid, session_id)?;
        self.lease(uid, session_id)?
            .release(lease_id, client_instance_id)
            .context(OutputSnafu)
    }

    pub fn inspect_runner(
        &self,
        kind: SessionRunnerKind,
    ) -> Result<erebor_runtime_core::RunnerCapabilityDocument, SessionManagerError> {
        self.runners.inspect(kind)
    }

    pub fn validate_admission(&self, spec: &SessionSpec) -> Result<(), SessionManagerError> {
        self.runners
            .get(spec.runner_capability().runner())?
            .validate_admission(spec)
            .context(RunnerSnafu)
    }

    pub fn start(
        &self,
        uid: u32,
        session_id: &str,
        constraints: &ValidatedStartConstraints,
        resume_pending: bool,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let current = self.inspect(uid, session_id)?;
        if !constraints.authorizes(&current) {
            return Err(SessionManagerError::InvalidOperation {
                session_id: session_id.to_owned(),
                reason: String::from(
                    "validated root constraints do not authorize this session start",
                ),
                location: snafu::Location::default(),
            });
        }
        if current.state() != SessionLifecycleState::Created {
            if resume_pending {
                self.finalize_runtime(&current)?;
                return Ok(current);
            }
            return Err(SessionManagerError::InvalidState {
                session_id: session_id.to_owned(),
                operation: "start",
                state: current.state().as_str().to_owned(),
                location: snafu::Location::default(),
            });
        }

        let starting = self.begin_start(current)?;
        let output = match self.runtime.prepare(starting.spec(), false) {
            Ok(output) => output,
            Err(source) => {
                let failed = self.fail_start(&starting, source.to_string())?;
                self.cleanup_runtime(&failed)?;
                return Err(source);
            }
        };
        let record = match self.launch_start(starting, &output) {
            Ok(record) => record,
            Err(source) => {
                let current = self.inspect(uid, session_id)?;
                let failed = if matches!(
                    current.state(),
                    SessionLifecycleState::Starting | SessionLifecycleState::Running
                ) {
                    self.fail_record(&current, source.to_string())?
                } else {
                    current
                };
                self.cleanup_runtime(&failed)?;
                return Err(source);
            }
        };
        self.finalize_runtime(&record)?;
        Ok(record)
    }

    fn begin_start(
        &self,
        created: DurableSessionRecord,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let uid = created.spec().owner().uid();
        let session_id = created.spec().session_id().as_str();
        let runner = self
            .runners
            .get(created.spec().runner_capability().runner())?;
        let current_capability = runner.inspect().context(RunnerSnafu)?;
        if &current_capability != created.spec().runner_capability() {
            return CapabilityChangedSnafu {
                session_id: session_id.to_owned(),
            }
            .fail();
        }
        self.repository
            .transition(
                uid,
                session_id,
                created.generation(),
                SessionLifecycleState::Starting,
                None,
                None,
            )
            .context(RepositorySnafu)
    }

    fn launch_start(
        &self,
        starting: DurableSessionRecord,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let uid = starting.spec().owner().uid();
        let session_id = starting.spec().session_id().as_str().to_owned();
        let runner = self
            .runners
            .get(starting.spec().runner_capability().runner())?;
        let current_capability = runner.inspect().context(RunnerSnafu)?;
        if &current_capability != starting.spec().runner_capability() {
            return CapabilityChangedSnafu {
                session_id: session_id.clone(),
            }
            .fail();
        }
        let mut active = match runner.start(starting.spec(), output) {
            Ok(active) => active,
            Err(source) => {
                let _failed = self.repository.transition(
                    uid,
                    &session_id,
                    starting.generation(),
                    SessionLifecycleState::Failed,
                    None,
                    Some(source.to_string()),
                );
                return Err(source).context(RunnerSnafu);
            }
        };
        let binding = RunnerBinding::new(
            runner.kind(),
            current_capability.implementation_id(),
            active.stable_identity(),
            unix_time_ms(),
        )
        .map_err(|source| SessionRepositoryError::Spec {
            source,
            location: snafu::Location::default(),
        })
        .context(RepositorySnafu)?;
        if active.health().context(RunnerSnafu)? == ActiveSessionHealth::Exited {
            let exit = active.wait().context(RunnerSnafu)?;
            return self.finish_starting(starting, binding, exit);
        }
        let running = self
            .repository
            .transition(
                uid,
                &session_id,
                starting.generation(),
                SessionLifecycleState::Running,
                Some(binding),
                None,
            )
            .context(RepositorySnafu)?;
        self.active_handles(&session_id)?
            .insert((uid, session_id.clone()), Arc::new(Mutex::new(active)));
        Ok(running)
    }

    fn fail_start(
        &self,
        starting: &DurableSessionRecord,
        reason: String,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        self.fail_record(starting, reason)
    }

    fn fail_record(
        &self,
        record: &DurableSessionRecord,
        reason: String,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        self.repository
            .transition(
                record.spec().owner().uid(),
                record.spec().session_id().as_str(),
                record.generation(),
                SessionLifecycleState::Failed,
                None,
                Some(reason),
            )
            .context(RepositorySnafu)
    }

    pub fn wait(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let current = self.inspect(uid, session_id)?;
        if current.state().is_terminal() {
            self.finalize_runtime(&current)?;
            return Ok(current);
        }
        let handle = self.handle(uid, session_id)?;
        let exit = loop {
            let health = handle
                .lock()
                .map_err(|_error| {
                    ActiveHandleLockSnafu {
                        session_id: session_id.to_owned(),
                    }
                    .build()
                })?
                .health()
                .context(RunnerSnafu)?;
            if health == ActiveSessionHealth::Exited {
                break handle
                    .lock()
                    .map_err(|_error| {
                        ActiveHandleLockSnafu {
                            session_id: session_id.to_owned(),
                        }
                        .build()
                    })?
                    .wait()
                    .context(RunnerSnafu)?;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let record = self.inspect(uid, session_id)?;
        self.finish(record, exit)
    }

    pub fn stop(
        &self,
        uid: u32,
        session_id: &str,
        grace_period: Duration,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let current = self.inspect(uid, session_id)?;
        if current.state().is_terminal() {
            self.finalize_runtime(&current)?;
            return Ok(current);
        }
        let stopping = self.begin_stopping(uid, session_id)?;
        let handle = self.handle(uid, session_id)?;
        let exit = handle
            .lock()
            .map_err(|_error| {
                ActiveHandleLockSnafu {
                    session_id: session_id.to_owned(),
                }
                .build()
            })?
            .stop(grace_period)
            .context(RunnerSnafu)?;
        self.finish(stopping, exit)
    }

    pub fn kill(
        &self,
        uid: u32,
        session_id: &str,
        signal: ActiveSessionSignal,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let current = self.inspect(uid, session_id)?;
        if current.state().is_terminal() {
            self.finalize_runtime(&current)?;
            return Ok(current);
        }
        let stopping = self.begin_stopping(uid, session_id)?;
        let handle = self.handle(uid, session_id)?;
        let exit = handle
            .lock()
            .map_err(|_error| {
                ActiveHandleLockSnafu {
                    session_id: session_id.to_owned(),
                }
                .build()
            })?
            .kill(signal)
            .context(RunnerSnafu)?;
        self.finish(stopping, exit)
    }

    pub fn remove(
        &self,
        uid: u32,
        session_id: &str,
        force: bool,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let mut record = self.inspect(uid, session_id)?;
        if record.state() == SessionLifecycleState::Removed {
            self.finalize_runtime(&record)?;
            return Ok(record);
        }
        if !record.state().is_terminal() {
            if !force {
                return self
                    .repository
                    .remove(uid, session_id, record.generation())
                    .context(RepositorySnafu);
            }
            record = self.kill(uid, session_id, ActiveSessionSignal::Kill)?;
        }
        self.cleanup_runtime(&record)?;
        self.runners
            .get(record.spec().runner_capability().runner())?
            .remove(record.spec(), record.runner_binding())
            .context(RunnerSnafu)?;
        let removed = self
            .repository
            .remove(uid, session_id, record.generation())
            .context(RepositorySnafu)?;
        self.remove_lease(uid, session_id)?;
        Ok(removed)
    }

    pub fn set_retention_hold(
        &self,
        uid: u32,
        session_id: &str,
        retention_hold: bool,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        self.repository
            .set_retention_hold(uid, session_id, retention_hold)
            .context(RepositorySnafu)
    }

    pub fn reconcile(&self) -> Result<Vec<DurableSessionRecord>, SessionManagerError> {
        let mut reconciled = Vec::new();
        for record in self.list_all()? {
            let state = record.state();
            if !matches!(
                state,
                SessionLifecycleState::Starting
                    | SessionLifecycleState::Running
                    | SessionLifecycleState::Stopping
                    | SessionLifecycleState::ControlLost
            ) {
                continue;
            }
            let output = match self.runtime.prepare(record.spec(), true) {
                Ok(output) => output,
                Err(source) => {
                    let interrupted = if matches!(
                        record.state(),
                        SessionLifecycleState::Running | SessionLifecycleState::Stopping
                    ) {
                        let control_lost = self
                            .repository
                            .transition(
                                record.spec().owner().uid(),
                                record.spec().session_id().as_str(),
                                record.generation(),
                                SessionLifecycleState::ControlLost,
                                None,
                                Some(String::from(
                                    "daemon restart requires runtime resource recovery",
                                )),
                            )
                            .context(RepositorySnafu)?;
                        self.interrupt(control_lost, source.to_string())?
                    } else {
                        self.interrupt(record, source.to_string())?
                    };
                    reconciled.push(interrupted);
                    continue;
                }
            };
            reconciled.push(self.reconcile_record(record, &output)?);
        }
        Ok(reconciled)
    }

    pub fn prune(
        &self,
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: usize,
    ) -> Result<SessionPruneResult, SessionManagerError> {
        for record in self.list(uid)? {
            self.finalize_runtime(&record)?;
        }
        self.repository
            .prune(uid, terminal_before_unix_ms, maximum_sessions)
            .context(RepositorySnafu)
    }

    fn begin_stopping(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let running = self.inspect(uid, session_id)?;
        if running.state() == SessionLifecycleState::Stopping {
            return Ok(running);
        }
        self.repository
            .transition(
                uid,
                session_id,
                running.generation(),
                SessionLifecycleState::Stopping,
                None,
                None,
            )
            .context(RepositorySnafu)
    }

    fn finish(
        &self,
        record: DurableSessionRecord,
        exit: ActiveSessionExit,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let uid = record.spec().owner().uid();
        let session_id = record.spec().session_id().as_str().to_owned();
        let next = match (exit.exit_code(), exit.signal()) {
            (Some(0), _) => SessionLifecycleState::Succeeded,
            (Some(_), _) | (_, Some(_)) => SessionLifecycleState::Failed,
            (None, None) => SessionLifecycleState::Interrupted,
        };
        let failure = (next == SessionLifecycleState::Failed).then(|| {
            exit.failure().map_or_else(
                || {
                    format!(
                        "runner exited with code {:?} signal {:?}",
                        exit.exit_code(),
                        exit.signal()
                    )
                },
                str::to_owned,
            )
        });
        let finished = self
            .repository
            .transition(uid, &session_id, record.generation(), next, None, failure)
            .context(RepositorySnafu)?;
        self.active_handles(&session_id)?
            .remove(&(uid, session_id.clone()));
        self.finalize_runtime(&finished)?;
        Ok(finished)
    }

    fn finish_starting(
        &self,
        record: DurableSessionRecord,
        binding: RunnerBinding,
        exit: ActiveSessionExit,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let next = if exit.exit_code() == Some(0) {
            SessionLifecycleState::Succeeded
        } else if exit.exit_code().is_none() && exit.signal().is_none() {
            SessionLifecycleState::Interrupted
        } else {
            SessionLifecycleState::Failed
        };
        let finished = self
            .repository
            .transition(
                record.spec().owner().uid(),
                record.spec().session_id().as_str(),
                record.generation(),
                next,
                Some(binding),
                (next != SessionLifecycleState::Succeeded).then(|| {
                    exit.failure()
                        .map_or_else(|| String::from("runner exited during start"), str::to_owned)
                }),
            )
            .context(RepositorySnafu)?;
        Ok(finished)
    }

    fn reconcile_record(
        &self,
        record: DurableSessionRecord,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let uid = record.spec().owner().uid();
        let session_id = record.spec().session_id().as_str().to_owned();
        let resume_stopping = record.state() == SessionLifecycleState::Stopping;
        let Some(binding) = record.runner_binding().cloned() else {
            return self.interrupt(
                record,
                "daemon restarted before a stable runner identity was persisted",
            );
        };
        let control_lost = if record.state() == SessionLifecycleState::ControlLost {
            record
        } else {
            self.repository
                .transition(
                    uid,
                    &session_id,
                    record.generation(),
                    SessionLifecycleState::ControlLost,
                    None,
                    Some(String::from(
                        "daemon restart requires stable-identity recovery",
                    )),
                )
                .context(RepositorySnafu)?
        };
        let runner = self
            .runners
            .get(control_lost.spec().runner_capability().runner())?;
        let current = runner.inspect().context(RunnerSnafu)?;
        if &current != control_lost.spec().runner_capability() {
            return self.interrupt(
                control_lost,
                "runner capability changed before recovery could be proven",
            );
        }
        match runner.recover(control_lost.spec(), &binding, output) {
            Ok(mut active) => {
                if active.health().context(RunnerSnafu)? == ActiveSessionHealth::Exited {
                    let exit = active.wait().context(RunnerSnafu)?;
                    return self.finish(control_lost, exit);
                }
                if control_lost.spec().daemon_failure_mode() == DaemonFailureMode::Terminate {
                    let exit = active
                        .stop(Duration::from_secs(
                            control_lost.spec().loss_grace_seconds(),
                        ))
                        .context(RunnerSnafu)?;
                    return self.finish(control_lost, exit);
                }
                self.active_handles(&session_id)?
                    .insert((uid, session_id.clone()), Arc::new(Mutex::new(active)));
                let running = self
                    .repository
                    .transition(
                        uid,
                        &session_id,
                        control_lost.generation(),
                        if resume_stopping {
                            SessionLifecycleState::Stopping
                        } else {
                            SessionLifecycleState::Running
                        },
                        None,
                        None,
                    )
                    .context(RepositorySnafu)?;
                if resume_stopping {
                    let handle = self.handle(uid, &session_id)?;
                    let exit = handle
                        .lock()
                        .map_err(|_error| {
                            ActiveHandleLockSnafu {
                                session_id: session_id.clone(),
                            }
                            .build()
                        })?
                        .stop(Duration::from_secs(running.spec().loss_grace_seconds()))
                        .context(RunnerSnafu)?;
                    self.finish(running, exit)
                } else {
                    Ok(running)
                }
            }
            Err(source) => self.interrupt(control_lost, source.to_string()),
        }
    }

    fn interrupt(
        &self,
        record: DurableSessionRecord,
        reason: impl Into<String>,
    ) -> Result<DurableSessionRecord, SessionManagerError> {
        let interrupted = self
            .repository
            .transition(
                record.spec().owner().uid(),
                record.spec().session_id().as_str(),
                record.generation(),
                SessionLifecycleState::Interrupted,
                None,
                Some(reason.into()),
            )
            .context(RepositorySnafu)?;
        self.finalize_runtime(&interrupted)?;
        Ok(interrupted)
    }

    fn finalize_runtime(&self, record: &DurableSessionRecord) -> Result<(), SessionManagerError> {
        if record.state().is_terminal() {
            self.cleanup_runtime(record)?;
        }
        Ok(())
    }

    fn cleanup_runtime(&self, record: &DurableSessionRecord) -> Result<(), SessionManagerError> {
        self.runtime.cleanup(record.spec())?;
        self.remove_lease(
            record.spec().owner().uid(),
            record.spec().session_id().as_str(),
        )
    }

    fn lease(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<Arc<InputLeaseManager>, SessionManagerError> {
        let mut leases = self.leases.lock().map_err(|_error| {
            StateLockSnafu {
                resource: "input lease",
            }
            .build()
        })?;
        Ok(Arc::clone(
            leases
                .entry((uid, session_id.to_owned()))
                .or_insert_with(|| Arc::new(InputLeaseManager::new(session_id))),
        ))
    }

    fn remove_lease(&self, uid: u32, session_id: &str) -> Result<(), SessionManagerError> {
        self.leases
            .lock()
            .map_err(|_error| {
                StateLockSnafu {
                    resource: "input lease",
                }
                .build()
            })?
            .remove(&(uid, session_id.to_owned()));
        Ok(())
    }

    fn require_input_lease_session(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<(), SessionManagerError> {
        let record = self.inspect(uid, session_id)?;
        if record.state() == SessionLifecycleState::Running
            && record.spec().tty()
            && record.spec().runner_capability().attach_supported()
        {
            return Ok(());
        }
        Err(SessionManagerError::InvalidOperation {
            session_id: session_id.to_owned(),
            reason: String::from("input leases require an attachable interactive TTY session"),
            location: snafu::Location::default(),
        })
    }

    fn handle(&self, uid: u32, session_id: &str) -> Result<ActiveHandle, SessionManagerError> {
        self.active_handles(session_id)?
            .get(&(uid, session_id.to_owned()))
            .cloned()
            .context(ActiveHandleMissingSnafu {
                session_id: session_id.to_owned(),
            })
    }

    fn active_handles(
        &self,
        session_id: &str,
    ) -> Result<std::sync::MutexGuard<'_, ActiveHandles>, SessionManagerError> {
        self.active.lock().map_err(|_error| {
            ActiveHandleLockSnafu {
                session_id: session_id.to_owned(),
            }
            .build()
        })
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

#[must_use]
pub fn output_endpoints(spec: &SessionSpec) -> OutputEndpoints {
    let root = spec.output().root();
    OutputEndpoints::new(
        root.join("stdout"),
        root.join("stderr"),
        root.join("events"),
        root.join("evidence"),
        root.join("continuity"),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use erebor_runtime_core::{
        ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal,
        ActiveSessionSignalKind, DaemonFailureMode, EvidenceRequirement, ImmutableIdentity,
        OutputEndpoints, OutputPlan, OutputStreamRequirements, RunnerBinding,
        RunnerCapabilityDocument, SafePathBinding, SafePathKind, SessionAdmission, SessionOwner,
        SessionRunner, SessionRunnerKind, SessionSpec, WorkloadPrivilegePlan,
    };
    use erebor_runtime_events::SessionId;
    use tempfile::TempDir;

    use crate::SessionOutputStores;

    use super::{
        output_endpoints, resources::SessionRuntime, DurableStreamCursor, RunnerRegistry,
        SessionManager, SessionManagerError, SessionRepository, StreamKind,
        ValidatedStartConstraints,
    };

    type TestError = Box<dyn std::error::Error>;
    type ManagerFixture = (
        SessionManager,
        Arc<FakeRunnerState>,
        Arc<FakeRuntimeState>,
        SessionSpec,
    );

    fn start_constraints() -> ValidatedStartConstraints {
        ValidatedStartConstraints::new(1000, "session-manager-test", 1)
    }

    struct FakeRunnerState {
        capability: Mutex<RunnerCapabilityDocument>,
        running: Arc<AtomicBool>,
        starts: AtomicUsize,
        fail_start: AtomicBool,
        recoveries: AtomicUsize,
        removals: AtomicUsize,
    }

    struct FakeRunner {
        state: Arc<FakeRunnerState>,
    }

    #[derive(Default)]
    struct FakeRuntimeState {
        preparations: AtomicUsize,
        cleanups: AtomicUsize,
        fail_prepare: AtomicBool,
    }

    struct FakeRuntime {
        state: Arc<FakeRuntimeState>,
    }

    impl SessionRuntime for FakeRuntime {
        fn prepare(
            &self,
            spec: &SessionSpec,
            _recovering: bool,
        ) -> Result<OutputEndpoints, SessionManagerError> {
            self.state.preparations.fetch_add(1, Ordering::SeqCst);
            if self.state.fail_prepare.load(Ordering::SeqCst) {
                return Err(SessionManagerError::InvalidRuntime {
                    session_id: spec.session_id().as_str().to_owned(),
                    reason: String::from("injected runtime preparation failure"),
                    location: snafu::Location::default(),
                });
            }
            Ok(output_endpoints(spec))
        }

        fn cleanup(&self, _spec: &SessionSpec) -> Result<(), SessionManagerError> {
            self.state.cleanups.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn stream(
            &self,
            spec: &SessionSpec,
            kind: StreamKind,
            after_sequence: u64,
            maximum_records: usize,
        ) -> Result<DurableStreamCursor, SessionManagerError> {
            SessionOutputStores::open(spec.output())
                .map_err(|source| SessionManagerError::Output {
                    source,
                    location: snafu::Location::default(),
                })?
                .stream(kind)
                .read_after(after_sequence, maximum_records)
                .map_err(|source| SessionManagerError::Output {
                    source,
                    location: snafu::Location::default(),
                })
        }
    }

    struct FakeActiveSession {
        capability: RunnerCapabilityDocument,
        running: Arc<AtomicBool>,
    }

    impl ActiveSession for FakeActiveSession {
        fn stable_identity(&self) -> &str {
            "fake-stable-identity"
        }

        fn capability_snapshot(&self) -> &RunnerCapabilityDocument {
            &self.capability
        }

        fn wait(&mut self) -> Result<ActiveSessionExit, erebor_runtime_core::RuntimeError> {
            self.running.store(false, Ordering::SeqCst);
            Ok(ActiveSessionExit::new(Some(0), None))
        }

        fn stop(
            &mut self,
            _grace_period: Duration,
        ) -> Result<ActiveSessionExit, erebor_runtime_core::RuntimeError> {
            self.running.store(false, Ordering::SeqCst);
            Ok(ActiveSessionExit::new(None, Some(15)))
        }

        fn kill(
            &mut self,
            _signal: ActiveSessionSignal,
        ) -> Result<ActiveSessionExit, erebor_runtime_core::RuntimeError> {
            self.running.store(false, Ordering::SeqCst);
            Ok(ActiveSessionExit::new(None, Some(9)))
        }

        fn health(&mut self) -> Result<ActiveSessionHealth, erebor_runtime_core::RuntimeError> {
            Ok(if self.running.load(Ordering::SeqCst) {
                ActiveSessionHealth::Running
            } else {
                ActiveSessionHealth::Exited
            })
        }
    }

    impl SessionRunner for FakeRunner {
        fn kind(&self) -> SessionRunnerKind {
            SessionRunnerKind::LinuxHost
        }

        fn inspect(&self) -> Result<RunnerCapabilityDocument, erebor_runtime_core::RuntimeError> {
            self.state
                .capability
                .lock()
                .map(|capability| capability.clone())
                .map_err(
                    |_error| erebor_runtime_core::RuntimeError::SessionRunnerProtocol {
                        runner: String::from("linux-host"),
                        reason: String::from("fake capability lock is poisoned"),
                        location: snafu::Location::default(),
                    },
                )
        }

        fn validate_admission(
            &self,
            _spec: &SessionSpec,
        ) -> Result<(), erebor_runtime_core::RuntimeError> {
            Ok(())
        }

        fn start(
            &self,
            _spec: &SessionSpec,
            _output: &OutputEndpoints,
        ) -> Result<Box<dyn ActiveSession>, erebor_runtime_core::RuntimeError> {
            self.state.starts.fetch_add(1, Ordering::SeqCst);
            if self.state.fail_start.load(Ordering::SeqCst) {
                return Err(erebor_runtime_core::RuntimeError::SessionRunnerProtocol {
                    runner: String::from("linux-host"),
                    reason: String::from("injected runner start failure"),
                    location: snafu::Location::default(),
                });
            }
            self.state.running.store(true, Ordering::SeqCst);
            Ok(Box::new(FakeActiveSession {
                capability: self.inspect()?,
                running: Arc::clone(&self.state.running),
            }))
        }

        fn recover(
            &self,
            _spec: &SessionSpec,
            _binding: &RunnerBinding,
            _output: &OutputEndpoints,
        ) -> Result<Box<dyn ActiveSession>, erebor_runtime_core::RuntimeError> {
            self.state.recoveries.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeActiveSession {
                capability: self.inspect()?,
                running: Arc::clone(&self.state.running),
            }))
        }

        fn remove(
            &self,
            _spec: &SessionSpec,
            _binding: Option<&RunnerBinding>,
        ) -> Result<(), erebor_runtime_core::RuntimeError> {
            self.state.removals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn capability(version: &str) -> Result<RunnerCapabilityDocument, Box<dyn std::error::Error>> {
        RunnerCapabilityDocument::new(
            SessionRunnerKind::LinuxHost,
            "fake-linux-runner",
            version,
            "linux",
            "x86_64",
            true,
            true,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
            ]),
            false,
            true,
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue]),
            BTreeMap::new(),
        )
        .map_err(Into::into)
    }

    fn fixture_with_mode(
        root: &TempDir,
        daemon_failure_mode: DaemonFailureMode,
    ) -> Result<ManagerFixture, TestError> {
        let state = Arc::new(FakeRunnerState {
            capability: Mutex::new(capability("1")?),
            running: Arc::new(AtomicBool::new(false)),
            starts: AtomicUsize::new(0),
            fail_start: AtomicBool::new(false),
            recoveries: AtomicUsize::new(0),
            removals: AtomicUsize::new(0),
        });
        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let runtime_state = Arc::new(FakeRuntimeState::default());
        let runtime = Arc::new(FakeRuntime {
            state: Arc::clone(&runtime_state),
        }) as Arc<dyn SessionRuntime>;
        let manager = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            runtime,
        );
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let output_root = root.path().join("output");
        let spec = SessionSpec::new(SessionAdmission {
            session_id: SessionId::new("session-manager-test"),
            owner: SessionOwner::new(1000, 1000),
            workload_privileges: WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 512, 0)?,
            command: vec![String::from("/usr/bin/agent")],
            package: None,
            installation: None,
            adapter: None,
            policy_inputs: vec![ImmutableIdentity::new("root-policy", digest)?],
            policy_set: ImmutableIdentity::new("policy-set", digest)?,
            runner_capability: capability("1")?,
            workspace: SafePathBinding::new(
                PathBuf::from("/workspace"),
                1,
                2,
                3,
                1000,
                1000,
                SafePathKind::Directory,
            )?,
            executable: Some(SafePathBinding::new(
                PathBuf::from("/usr/bin/agent"),
                1,
                4,
                3,
                1000,
                1000,
                SafePathKind::Executable,
            )?),
            container_image: None,
            environment: Vec::new(),
            secret_references: Vec::new(),
            filesystem_projections: Vec::new(),
            endpoint_projections: Vec::new(),
            output: OutputPlan::new(
                output_root,
                4096,
                512,
                64,
                OutputStreamRequirements::required(),
            )?,
            evidence_requirements: vec![EvidenceRequirement::new("audit", true)?],
            tty: false,
            detached: true,
            daemon_failure_mode,
            loss_grace_seconds: 1,
            root_configuration_generation: 1,
            created_at_unix_ms: 1,
        })?;
        Ok((manager, state, runtime_state, spec))
    }

    fn fixture(root: &TempDir) -> Result<ManagerFixture, TestError> {
        fixture_with_mode(root, DaemonFailureMode::Continue)
    }

    #[test]
    fn manager_creates_without_starting_and_starts_exactly_once(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime, spec) = fixture(&root)?;
        let created = manager.create(spec)?;
        assert_eq!(
            created.state(),
            erebor_runtime_core::SessionLifecycleState::Created
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);

        let running = manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        assert_eq!(
            running.state(),
            erebor_runtime_core::SessionLifecycleState::Running
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        assert!(manager
            .start(1000, "session-manager-test", &start_constraints(), false)
            .is_err());
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.preparations.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.cleanups.load(Ordering::SeqCst), 0);
        let replayed = manager.start(1000, "session-manager-test", &start_constraints(), true)?;
        assert_eq!(
            replayed.state(),
            erebor_runtime_core::SessionLifecycleState::Running
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.preparations.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_marks_runtime_preparation_failure_and_cleans_once(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime, spec) = fixture(&root)?;
        runtime.fail_prepare.store(true, Ordering::SeqCst);
        manager.create(spec)?;

        assert!(manager
            .start(1000, "session-manager-test", &start_constraints(), false)
            .is_err());
        assert_eq!(
            manager.inspect(1000, "session-manager-test")?.state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.preparations.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.cleanups.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_marks_runner_start_failure_and_cleans_once() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = TempDir::new()?;
        let (manager, state, runtime, spec) = fixture(&root)?;
        state.fail_start.store(true, Ordering::SeqCst);
        manager.create(spec)?;

        assert!(manager
            .start(1000, "session-manager-test", &start_constraints(), false)
            .is_err());
        assert_eq!(
            manager.inspect(1000, "session-manager-test")?.state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.preparations.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.cleanups.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_rejects_capability_drift_before_launch() -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, _runtime, spec) = fixture(&root)?;
        manager.create(spec)?;
        let Ok(mut current) = state.capability.lock() else {
            return Err("fake capability lock is poisoned".into());
        };
        *current = capability("2")?;
        drop(current);

        assert!(manager
            .start(1000, "session-manager-test", &start_constraints(), false)
            .is_err());
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn manager_requires_current_root_constraint_validation_before_start(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime, spec) = fixture(&root)?;
        manager.create(spec)?;
        let stale = ValidatedStartConstraints::new(1000, "session-manager-test", 0);

        assert!(manager
            .start(1000, "session-manager-test", &stale, false)
            .is_err());
        assert_eq!(
            manager.inspect(1000, "session-manager-test")?.state(),
            erebor_runtime_core::SessionLifecycleState::Created
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.preparations.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn manager_recovers_by_stable_binding_and_runner_then_removes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime_state, spec) = fixture(&root)?;
        manager.create(spec)?;
        let running = manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        drop(manager);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            Arc::new(FakeRuntime {
                state: Arc::clone(&runtime_state),
            }),
        );
        let records = recovered.reconcile()?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Running
        );
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 1);

        let terminal = recovered.kill(1000, "session-manager-test", ActiveSessionSignal::Kill)?;
        assert_eq!(
            terminal.state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert_eq!(runtime_state.cleanups.load(Ordering::SeqCst), 1);
        let removed = recovered.remove(1000, "session-manager-test", false)?;
        assert_eq!(
            removed.state(),
            erebor_runtime_core::SessionLifecycleState::Removed
        );
        assert_eq!(state.removals.load(Ordering::SeqCst), 1);
        assert_eq!(
            running.runner_binding().map(RunnerBinding::stable_identity),
            Some("fake-stable-identity")
        );
        Ok(())
    }

    #[test]
    fn manager_recovery_preparation_failure_interrupts_without_recovering_runner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime_state, spec) = fixture(&root)?;
        manager.create(spec)?;
        manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        drop(manager);

        runtime_state.fail_prepare.store(true, Ordering::SeqCst);
        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            Arc::new(FakeRuntime {
                state: Arc::clone(&runtime_state),
            }),
        );
        let records = recovered.reconcile()?;

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Interrupted
        );
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 0);
        assert_eq!(runtime_state.cleanups.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_wait_and_stop_use_terminal_cleanup_owner() -> Result<(), Box<dyn std::error::Error>>
    {
        let wait_root = TempDir::new()?;
        let (wait_manager, wait_state, wait_runtime, wait_spec) = fixture(&wait_root)?;
        wait_manager.create(wait_spec)?;
        wait_manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        wait_state.running.store(false, Ordering::SeqCst);
        let waited = wait_manager.wait(1000, "session-manager-test")?;
        assert_eq!(
            waited.state(),
            erebor_runtime_core::SessionLifecycleState::Succeeded
        );
        assert_eq!(wait_runtime.cleanups.load(Ordering::SeqCst), 1);

        let stop_root = TempDir::new()?;
        let (stop_manager, _stop_state, stop_runtime, stop_spec) = fixture(&stop_root)?;
        stop_manager.create(stop_spec)?;
        stop_manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        let stopped = stop_manager.stop(1000, "session-manager-test", Duration::from_secs(1))?;
        assert_eq!(
            stopped.state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert_eq!(stop_runtime.cleanups.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_recovery_enforces_terminate_mode_before_returning_control(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime_state, spec) =
            fixture_with_mode(&root, DaemonFailureMode::Terminate)?;
        manager.create(spec)?;
        manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        drop(manager);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            Arc::new(FakeRuntime {
                state: Arc::clone(&runtime_state),
            }),
        );
        let records = recovered.reconcile()?;

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert!(!state.running.load(Ordering::SeqCst));
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn manager_recovery_marks_starting_without_a_binding_interrupted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (manager, state, runtime_state, spec) = fixture(&root)?;
        let created = manager.create(spec)?;
        manager.begin_start(created)?;
        drop(manager);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            Arc::new(FakeRuntime {
                state: Arc::clone(&runtime_state),
            }),
        );
        let records = recovered.reconcile()?;

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Interrupted
        );
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn manager_recovery_resumes_a_persisted_stop_intent() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = TempDir::new()?;
        let (manager, state, runtime_state, spec) = fixture(&root)?;
        manager.create(spec)?;
        manager.start(1000, "session-manager-test", &start_constraints(), false)?;
        manager.begin_stopping(1000, "session-manager-test")?;
        drop(manager);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionManager::new_with_runtime(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
            Arc::new(FakeRuntime {
                state: Arc::clone(&runtime_state),
            }),
        );
        let records = recovered.reconcile()?;

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        assert!(!state.running.load(Ordering::SeqCst));
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
