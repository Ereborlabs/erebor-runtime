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

use crate::{
    error::session_supervisor::{
        ActiveHandleLockSnafu, ActiveHandleMissingSnafu, CapabilityChangedSnafu, RepositorySnafu,
        RunnerSnafu, RunnerUnavailableSnafu,
    },
    DurableSessionRecord, SessionPruneResult, SessionRepository, SessionRepositoryError,
    SessionSupervisorError,
};

type ActiveHandle = Arc<Mutex<Box<dyn ActiveSession>>>;
type ActiveHandles = BTreeMap<(u32, String), ActiveHandle>;

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
    ) -> Result<&Arc<dyn SessionRunner>, SessionSupervisorError> {
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
    ) -> Result<erebor_runtime_core::RunnerCapabilityDocument, SessionSupervisorError> {
        self.get(kind)?.inspect().context(RunnerSnafu)
    }
}

pub struct SessionSupervisor {
    repository: SessionRepository,
    runners: RunnerRegistry,
    active: Mutex<ActiveHandles>,
}

impl SessionSupervisor {
    #[must_use]
    pub fn new(repository: SessionRepository, runners: RunnerRegistry) -> Self {
        Self {
            repository,
            runners,
            active: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn create(
        &self,
        spec: SessionSpec,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        self.repository.create(spec).context(RepositorySnafu)
    }

    pub fn inspect(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        self.repository
            .load(uid, session_id)
            .context(RepositorySnafu)
    }

    pub fn list(&self, uid: u32) -> Result<Vec<DurableSessionRecord>, SessionSupervisorError> {
        self.repository.list(uid).context(RepositorySnafu)
    }

    pub fn list_all(&self) -> Result<Vec<DurableSessionRecord>, SessionSupervisorError> {
        let mut records = Vec::new();
        for uid in self.repository.user_ids().context(RepositorySnafu)? {
            records.extend(self.list(uid)?);
        }
        Ok(records)
    }

    pub fn inspect_runner(
        &self,
        kind: SessionRunnerKind,
    ) -> Result<erebor_runtime_core::RunnerCapabilityDocument, SessionSupervisorError> {
        self.runners.inspect(kind)
    }

    pub fn validate_admission(&self, spec: &SessionSpec) -> Result<(), SessionSupervisorError> {
        self.runners
            .get(spec.runner_capability().runner())?
            .validate_admission(spec)
            .context(RunnerSnafu)
    }

    pub fn start(
        &self,
        uid: u32,
        session_id: &str,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let starting = self.begin_start(uid, session_id)?;
        self.launch_start(starting, output)
    }

    pub fn begin_start(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let created = self.inspect(uid, session_id)?;
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

    pub fn launch_start(
        &self,
        starting: DurableSessionRecord,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
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

    pub fn fail_start(
        &self,
        uid: u32,
        session_id: &str,
        reason: String,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let starting = self.inspect(uid, session_id)?;
        self.repository
            .transition(
                uid,
                session_id,
                starting.generation(),
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
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
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
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
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
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
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
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let mut record = self.inspect(uid, session_id)?;
        if !record.state().is_terminal() {
            if !force {
                return self
                    .repository
                    .remove(uid, session_id, record.generation())
                    .context(RepositorySnafu);
            }
            record = self.kill(uid, session_id, ActiveSessionSignal::Kill)?;
        }
        self.runners
            .get(record.spec().runner_capability().runner())?
            .remove(record.spec(), record.runner_binding())
            .context(RunnerSnafu)?;
        self.repository
            .remove(uid, session_id, record.generation())
            .context(RepositorySnafu)
    }

    pub fn reconcile(&self) -> Result<Vec<DurableSessionRecord>, SessionSupervisorError> {
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
            let output = output_endpoints(record.spec());
            reconciled.push(self.reconcile_record(record, &output)?);
        }
        Ok(reconciled)
    }

    pub fn reconcile_session(
        &self,
        uid: u32,
        session_id: &str,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let record = self.inspect(uid, session_id)?;
        self.reconcile_record(record, output)
    }

    pub fn prune(
        &self,
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: usize,
    ) -> Result<SessionPruneResult, SessionSupervisorError> {
        self.repository
            .prune(uid, terminal_before_unix_ms, maximum_sessions)
            .context(RepositorySnafu)
    }

    fn begin_stopping(
        &self,
        uid: u32,
        session_id: &str,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
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
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let uid = record.spec().owner().uid();
        let session_id = record.spec().session_id().as_str().to_owned();
        let next = match (exit.exit_code(), exit.signal()) {
            (Some(0), _) => SessionLifecycleState::Succeeded,
            (Some(_), _) | (_, Some(_)) => SessionLifecycleState::Failed,
            (None, None) => SessionLifecycleState::Interrupted,
        };
        let failure = (next == SessionLifecycleState::Failed).then(|| {
            format!(
                "runner exited with code {:?} signal {:?}",
                exit.exit_code(),
                exit.signal()
            )
        });
        let finished = self
            .repository
            .transition(uid, &session_id, record.generation(), next, None, failure)
            .context(RepositorySnafu)?;
        self.active_handles(&session_id)?
            .remove(&(uid, session_id.clone()));
        Ok(finished)
    }

    fn finish_starting(
        &self,
        record: DurableSessionRecord,
        binding: RunnerBinding,
        exit: ActiveSessionExit,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let next = if exit.exit_code() == Some(0) {
            SessionLifecycleState::Succeeded
        } else if exit.exit_code().is_none() && exit.signal().is_none() {
            SessionLifecycleState::Interrupted
        } else {
            SessionLifecycleState::Failed
        };
        self.repository
            .transition(
                record.spec().owner().uid(),
                record.spec().session_id().as_str(),
                record.generation(),
                next,
                Some(binding),
                (next != SessionLifecycleState::Succeeded)
                    .then(|| String::from("runner exited during start")),
            )
            .context(RepositorySnafu)
    }

    fn reconcile_record(
        &self,
        record: DurableSessionRecord,
        output: &OutputEndpoints,
    ) -> Result<DurableSessionRecord, SessionSupervisorError> {
        let uid = record.spec().owner().uid();
        let session_id = record.spec().session_id().as_str().to_owned();
        let resume_stopping = record.state() == SessionLifecycleState::Stopping;
        let Some(binding) = record.runner_binding().cloned() else {
            return self
                .repository
                .transition(
                    uid,
                    &session_id,
                    record.generation(),
                    SessionLifecycleState::Interrupted,
                    None,
                    Some(String::from(
                        "daemon restarted before a stable runner identity was persisted",
                    )),
                )
                .context(RepositorySnafu);
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
            return self
                .repository
                .transition(
                    uid,
                    &session_id,
                    control_lost.generation(),
                    SessionLifecycleState::Interrupted,
                    None,
                    Some(String::from(
                        "runner capability changed before recovery could be proven",
                    )),
                )
                .context(RepositorySnafu);
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
            Err(source) => self
                .repository
                .transition(
                    uid,
                    &session_id,
                    control_lost.generation(),
                    SessionLifecycleState::Interrupted,
                    None,
                    Some(source.to_string()),
                )
                .context(RepositorySnafu),
        }
    }

    fn handle(&self, uid: u32, session_id: &str) -> Result<ActiveHandle, SessionSupervisorError> {
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
    ) -> Result<std::sync::MutexGuard<'_, ActiveHandles>, SessionSupervisorError> {
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
        OutputEndpoints, OutputPlan, RunnerBinding, RunnerCapabilityDocument, SafePathBinding,
        SafePathKind, SessionAdmission, SessionOwner, SessionRunner, SessionRunnerKind,
        SessionSpec, WorkloadPrivilegePlan,
    };
    use erebor_runtime_events::SessionId;
    use tempfile::TempDir;

    use super::{output_endpoints, RunnerRegistry, SessionRepository, SessionSupervisor};

    struct FakeRunnerState {
        capability: Mutex<RunnerCapabilityDocument>,
        running: Arc<AtomicBool>,
        starts: AtomicUsize,
        recoveries: AtomicUsize,
        removals: AtomicUsize,
    }

    struct FakeRunner {
        state: Arc<FakeRunnerState>,
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
    ) -> Result<(SessionSupervisor, Arc<FakeRunnerState>, SessionSpec), Box<dyn std::error::Error>>
    {
        let state = Arc::new(FakeRunnerState {
            capability: Mutex::new(capability("1")?),
            running: Arc::new(AtomicBool::new(false)),
            starts: AtomicUsize::new(0),
            recoveries: AtomicUsize::new(0),
            removals: AtomicUsize::new(0),
        });
        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let supervisor = SessionSupervisor::new(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
        );
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let output_root = root.path().join("output");
        let spec = SessionSpec::new(SessionAdmission {
            session_id: SessionId::new("session-supervisor-test"),
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
            output: OutputPlan::new(output_root, 4096, 512, 64)?,
            evidence_requirements: vec![EvidenceRequirement::new("audit", true)?],
            tty: false,
            detached: true,
            daemon_failure_mode,
            loss_grace_seconds: 1,
            root_configuration_generation: 1,
            created_at_unix_ms: 1,
        })?;
        Ok((supervisor, state, spec))
    }

    fn fixture(
        root: &TempDir,
    ) -> Result<(SessionSupervisor, Arc<FakeRunnerState>, SessionSpec), Box<dyn std::error::Error>>
    {
        fixture_with_mode(root, DaemonFailureMode::Continue)
    }

    #[test]
    fn supervisor_creates_without_starting_and_starts_exactly_once(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture(&root)?;
        let created = supervisor.create(spec)?;
        assert_eq!(
            created.state(),
            erebor_runtime_core::SessionLifecycleState::Created
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);

        let running = supervisor.start(
            1000,
            "session-supervisor-test",
            &output_endpoints(created.spec()),
        )?;
        assert_eq!(
            running.state(),
            erebor_runtime_core::SessionLifecycleState::Running
        );
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        assert!(supervisor
            .start(
                1000,
                "session-supervisor-test",
                &output_endpoints(running.spec())
            )
            .is_err());
        assert_eq!(state.starts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn supervisor_rejects_capability_drift_before_launch() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture(&root)?;
        supervisor.create(spec)?;
        let Ok(mut current) = state.capability.lock() else {
            return Err("fake capability lock is poisoned".into());
        };
        *current = capability("2")?;
        drop(current);

        assert!(supervisor
            .begin_start(1000, "session-supervisor-test")
            .is_err());
        assert_eq!(state.starts.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn supervisor_recovers_by_stable_binding_and_runner_then_removes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture(&root)?;
        let created = supervisor.create(spec)?;
        let running = supervisor.start(
            1000,
            "session-supervisor-test",
            &output_endpoints(created.spec()),
        )?;
        drop(supervisor);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionSupervisor::new(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
        );
        let records = recovered.reconcile()?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].state(),
            erebor_runtime_core::SessionLifecycleState::Running
        );
        assert_eq!(state.recoveries.load(Ordering::SeqCst), 1);

        let terminal =
            recovered.kill(1000, "session-supervisor-test", ActiveSessionSignal::Kill)?;
        assert_eq!(
            terminal.state(),
            erebor_runtime_core::SessionLifecycleState::Failed
        );
        let removed = recovered.remove(1000, "session-supervisor-test", false)?;
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
    fn supervisor_recovery_enforces_terminate_mode_before_returning_control(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture_with_mode(&root, DaemonFailureMode::Terminate)?;
        let created = supervisor.create(spec)?;
        supervisor.start(
            1000,
            "session-supervisor-test",
            &output_endpoints(created.spec()),
        )?;
        drop(supervisor);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionSupervisor::new(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
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
    fn supervisor_recovery_marks_starting_without_a_binding_interrupted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture(&root)?;
        supervisor.create(spec)?;
        supervisor.begin_start(1000, "session-supervisor-test")?;
        drop(supervisor);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionSupervisor::new(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
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
    fn supervisor_recovery_resumes_a_persisted_stop_intent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let (supervisor, state, spec) = fixture(&root)?;
        let created = supervisor.create(spec)?;
        supervisor.start(
            1000,
            "session-supervisor-test",
            &output_endpoints(created.spec()),
        )?;
        supervisor.begin_stopping(1000, "session-supervisor-test")?;
        drop(supervisor);

        let runner = Arc::new(FakeRunner {
            state: Arc::clone(&state),
        }) as Arc<dyn SessionRunner>;
        let recovered = SessionSupervisor::new(
            SessionRepository::new(root.path()),
            RunnerRegistry::new([runner]),
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
