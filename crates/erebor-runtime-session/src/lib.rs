use std::{
    fs::{self, File},
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

mod adoption;
mod control_broker;

use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    AuditCommandLogLevel, DockerSessionCommandOptions, DockerSessionMount,
    LinuxHostSessionCommandOptions, ProcessInterceptionDecision, ProcessInterceptionHandlerConfig,
    ProcessInterceptionHandlerKind, ProcessMediationPrivateEndpointConfig,
    ProcessMediationReplacementSurface, RuntimeAuditConfig, RuntimeConfig, RuntimeConfigError,
    RuntimeError, SessionActorLayerConfig, SessionAdoptPlan, SessionInterceptionBackendKind,
    SessionInterceptionOperation, SessionRegistry, SessionRegistryError, SessionRegistryFinish,
    SessionRunOutcome, SessionRunPlan, SessionRunnerKind, SessionRunnerLauncher,
    SessionSurfaceDefinition, SessionSurfaceKind, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
    SessionSurfaceSupervisor, TerminalProcessInterceptionMode, TerminalSurfaceConfig,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicyError, PolicySet};
use erebor_runtime_terminal::{
    compile_terminal_process_guard_rules, TerminalProcessGuardDecision, TerminalProcessGuardRule,
    TerminalSurfaceError,
};
use snafu::Location;
use thiserror::Error;

pub use adoption::adopt_session_target;
pub use control_broker::{
    BrowserCdpMediationHandler, GuardBrokerClient, SessionControlBroker,
    SessionControlBrokerEndpoint, SessionControlBrokerError, SessionControlRegistration,
    SessionInterceptionHandler, SessionMediationIntent, SessionMediationRegistry,
    SurfaceMediationHandler, SurfaceMediationOutcome,
};

const LINUX_PROCESS_GUARD: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erebor-linux-process-guard"));
const DOCKER_GUARD_DIR: &str = "/erebor/guard";
const DOCKER_CONTROL_DIR: &str = "/erebor/control";
const LINUX_PROCESS_GUARD_PATH: &str = "/erebor/guard/erebor-linux-process-guard";
const DOCKER_AUDIT_DIR: &str = "/erebor/audit";
const LAZY_BROWSER_CDP_CONTROL_TIMEOUT_MS: u64 = 15_000;
static SESSION_GUARD_BUNDLE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionDiagnosticOutcome {
    stdout: String,
    stderr: String,
}

impl SessionDiagnosticOutcome {
    #[must_use]
    pub fn new(stdout: String, stderr: String) -> Self {
        Self { stdout, stderr }
    }

    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub fn run_session_plan(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<SessionRunOutcome, SessionExecutionError> {
    let prepared_session = prepare_registry_session(config, plan)?;
    let result = run_session_plan_inner(config, plan, prepared_session.as_ref());
    finish_registry_session(prepared_session.as_ref(), plan.session_id(), &result)?;
    result
}

fn run_session_plan_inner(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionRunOutcome, SessionExecutionError> {
    let side_resources = start_session_side_resources(config, plan, prepared_session)?;

    match plan.runner().kind() {
        SessionRunnerKind::Docker => SessionRunnerLauncher::run_with_docker_options(
            plan,
            side_resources.environment(),
            side_resources.docker_options(),
        ),
        SessionRunnerKind::LinuxHost => SessionRunnerLauncher::run_with_linux_host_options(
            plan,
            side_resources.environment(),
            side_resources.linux_host_options(),
        ),
    }
    .map_err(SessionExecutionError::runtime)
}

pub fn run_session_diagnostic(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
    let prepared_session = prepare_registry_session(config, plan)?;
    let result = run_session_diagnostic_inner(config, plan, prepared_session.as_ref());
    finish_registry_diagnostic(prepared_session.as_ref(), plan, &result)?;
    result
}

fn run_session_diagnostic_inner(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
    let side_resources = start_session_side_resources(config, plan, prepared_session)?;
    let outcome = match plan.runner().kind() {
        SessionRunnerKind::Docker => SessionRunnerLauncher::run_capture_with_docker_options(
            plan,
            side_resources.environment(),
            side_resources.docker_options(),
        ),
        SessionRunnerKind::LinuxHost => SessionRunnerLauncher::run_capture_with_linux_host_options(
            plan,
            side_resources.environment(),
            side_resources.linux_host_options(),
        ),
    }
    .map_err(SessionExecutionError::runtime)?;

    if outcome.run().exit_code() == Some(0) {
        Ok(SessionDiagnosticOutcome::new(
            outcome.stdout().to_owned(),
            outcome.stderr().to_owned(),
        ))
    } else {
        Err(SessionExecutionError::diagnostic_failed(format!(
            "guarded {} diagnostic exited with code {:?}: {}",
            plan.runner().kind().as_str(),
            outcome.run().exit_code(),
            outcome.stderr().trim()
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionStorage {
    audit_path: PathBuf,
}

impl SessionStorage {
    fn new(audit_path: PathBuf) -> Self {
        Self { audit_path }
    }

    fn audit_path(&self) -> &Path {
        &self.audit_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedSession {
    registry: SessionRegistry,
    storage: SessionStorage,
}

fn prepare_registry_session(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<Option<PreparedSession>, SessionExecutionError> {
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry
        .start_session(config, plan)
        .map_err(SessionExecutionError::session_registry)?;
    let storage = SessionStorage::new(started.audit_path().to_path_buf());
    Ok(Some(PreparedSession { registry, storage }))
}

fn finish_registry_session(
    prepared_session: Option<&PreparedSession>,
    session_id: &SessionId,
    result: &Result<SessionRunOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let update = match result {
        Ok(outcome) => SessionRegistryFinish::succeeded(outcome),
        Err(error) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(session_id, update)
        .map_err(SessionExecutionError::session_registry)?;
    Ok(())
}

fn finish_registry_diagnostic(
    prepared_session: Option<&PreparedSession>,
    plan: &SessionRunPlan,
    result: &Result<SessionDiagnosticOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let update = match result {
        Ok(_outcome) => {
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(plan.runner().kind(), Some(0)))
        }
        Err(error) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(plan.session_id(), update)
        .map_err(SessionExecutionError::session_registry)?;
    Ok(())
}

fn session_exit_code_from_error(error: &SessionExecutionError) -> Option<i32> {
    match error {
        SessionExecutionError::Runtime {
            source: RuntimeError::SessionRunnerExit { code, .. },
            ..
        } => *code,
        SessionExecutionError::DiagnosticFailed { .. } => None,
        _ => None,
    }
}

pub fn adopt_session_plan(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionRunOutcome, SessionExecutionError> {
    match plan.runner().kind() {
        SessionRunnerKind::Docker => Err(SessionExecutionError::runtime(
            RuntimeError::unsupported_session_runner_operation("docker", "adopt"),
        )),
        SessionRunnerKind::LinuxHost => {
            let side_resources = start_adopt_session_side_resources(config, plan)?;
            let linux_host_options = side_resources.linux_host_adopt_options(plan.pid())?;
            SessionRunnerLauncher::adopt_with_linux_host_options(
                plan,
                side_resources.environment(),
                &linux_host_options,
            )
            .map_err(SessionExecutionError::runtime)
        }
    }
}

pub fn adopt_session_plan_capture(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
    let outcome = match plan.runner().kind() {
        SessionRunnerKind::Docker => {
            return Err(SessionExecutionError::runtime(
                RuntimeError::unsupported_session_runner_operation("docker", "adopt"),
            ));
        }
        SessionRunnerKind::LinuxHost => {
            let side_resources = start_adopt_session_side_resources(config, plan)?;
            let linux_host_options = side_resources.linux_host_adopt_options(plan.pid())?;
            SessionRunnerLauncher::adopt_capture_with_linux_host_options(
                plan,
                side_resources.environment(),
                &linux_host_options,
            )
        }
    }
    .map_err(SessionExecutionError::runtime)?;

    if outcome.run().exit_code() == Some(0) {
        Ok(SessionDiagnosticOutcome::new(
            outcome.stdout().to_owned(),
            outcome.stderr().to_owned(),
        ))
    } else {
        Err(SessionExecutionError::diagnostic_failed(format!(
            "guarded {} adoption exited with code {:?}: {}",
            plan.runner().kind().as_str(),
            outcome.run().exit_code(),
            outcome.stderr().trim()
        )))
    }
}

pub fn start_surface_launch_plan(
    launch_plan: SessionSurfaceLaunchPlan,
) -> Result<(), SessionExecutionError> {
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                let surface = BrowserCdpSurface::new(
                    config.clone(),
                    policy_set,
                    runtime_context("browser-cdp"),
                )
                .with_audit_config(launch_plan.audit().clone());
                launcher.add_surface(surface);
            }
            SessionSurfaceDefinition::Terminal(_) => {
                tracing::info!(
                    surface = SessionSurfaceKind::Terminal.as_str(),
                    "terminal/process surface is enforced by session runners and has no standalone service"
                );
            }
        }
    }

    if launcher.is_empty() {
        tracing::info!(
            control = %launch_plan.control_listen(),
            surfaces = %format_surfaces(launch_plan.surfaces().into_iter()),
            "no long-lived session surface services to start"
        );
        return Ok(());
    }

    let supervisor = launcher.start().map_err(SessionExecutionError::runtime)?;
    tracing::info!(
        control = %supervisor.control_listen(),
        surfaces = %format_surfaces(supervisor.running().iter().map(erebor_runtime_core::RunningSessionSurface::surface)),
        endpoints = %format_endpoints(supervisor.running()),
        "session surfaces started"
    );

    supervisor.wait().map_err(SessionExecutionError::runtime)?;
    Ok(())
}

fn start_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    let start_plan = config
        .surface_start_plan_for_session(plan)
        .map_err(SessionExecutionError::invalid_config)?;
    start_session_side_resources_from_start_plan(config, plan, start_plan, prepared_session)
}

fn start_adopt_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionSideResources, SessionExecutionError> {
    let process_exec_interception = config
        .session_interception_capabilities()
        .operations()
        .iter()
        .any(|operation| {
            operation.operation() == SessionInterceptionOperation::ProcessExec
                && operation.effective()
        });
    if plan.runner().kind() == SessionRunnerKind::LinuxHost && !process_exec_interception {
        return Err(SessionExecutionError::guard_config(
            "linux-host adoption requires session.interception process_exec support",
        ));
    }

    let start_plan = config
        .surface_start_plan_for_runner_kind(plan.runner().kind())
        .map_err(SessionExecutionError::invalid_config)?;
    start_session_side_resources_from_start_plan(config, plan, start_plan, None)
}

fn start_session_side_resources_from_start_plan(
    _config: &RuntimeConfig,
    plan: &impl SessionPlanContext,
    start_plan: erebor_runtime_core::SessionSurfaceStartPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    if start_plan.surfaces().is_empty() {
        return Ok(SessionSideResources::default());
    }

    let launch_plan = SessionSurfaceLaunchPlan::from_start_plan(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &start_plan,
    )
    .map_err(SessionExecutionError::runtime)?;
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());
    let mut environment = Vec::new();
    let interception_backend = SessionInterceptionBackendBundle::prepare(
        &start_plan,
        plan,
        prepared_session.map(|session| &session.storage),
    )?;
    let mut lazy_browser_cdp = None;
    let uses_lazy_browser_cdp = start_plan
        .terminal()
        .is_some_and(terminal_uses_managed_browser_cdp_mediation);

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                if uses_lazy_browser_cdp {
                    lazy_browser_cdp = Some(LazyBrowserCdpMediationConfig {
                        config: config.clone(),
                        policy_set,
                        context: session_cdp_context(plan),
                        audit_jsonl: prepared_session
                            .map(|session| session.storage.audit_path().to_path_buf()),
                        audit: plan.audit().clone(),
                    });
                } else {
                    let mut surface = BrowserCdpSurface::new(
                        config.clone(),
                        policy_set,
                        session_cdp_context(plan),
                    )
                    .with_audit_config(plan.audit().clone());
                    if let Some(audit_jsonl) =
                        prepared_session.map(|session| session.storage.audit_path())
                    {
                        surface = surface.with_audit_jsonl(audit_jsonl.to_path_buf());
                    }
                    launcher.add_surface(surface);
                }
            }
            SessionSurfaceDefinition::Terminal(_) => {
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("terminal"),
                ));
                environment.push((String::from("EREBOR_TERMINAL_TTY"), plan.tty().to_string()));

                if let Some(interception_backend) = interception_backend.as_ref() {
                    environment.push((
                        String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
                        interception_backend.terminal_process_guard().to_owned(),
                    ));
                } else {
                    environment.push((
                        String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
                        String::from("disabled"),
                    ));
                }
            }
        }
    }

    if launcher.is_empty() {
        let control_registration = register_session_control_channel(
            interception_backend.as_ref(),
            plan,
            None,
            lazy_browser_cdp,
        )?;
        let (docker_options, linux_host_options) = side_resource_command_options(
            interception_backend.as_ref(),
            None,
            control_registration.as_ref(),
        )?;
        return Ok(SessionSideResources {
            environment,
            docker_options,
            linux_host_options,
            browser_cdp_endpoint: None,
            _control_registration: control_registration,
            _interception_backend: interception_backend,
            _supervisor: None,
        });
    }

    let supervisor = launcher.start().map_err(SessionExecutionError::runtime)?;
    let mut browser_cdp_endpoint = None;
    for runtime in supervisor.running() {
        match runtime.surface() {
            SessionSurfaceKind::BrowserCdp => {
                browser_cdp_endpoint = Some(runtime.endpoint().to_owned());
                environment.push((
                    String::from("EREBOR_BROWSER_CDP_URL"),
                    runtime.endpoint().to_owned(),
                ));
                environment.push((
                    String::from("EREBOR_OPENCLAW_BROWSER_PROFILE"),
                    String::from("erebor"),
                ));
            }
            SessionSurfaceKind::Terminal => {}
            SessionSurfaceKind::Mcp
            | SessionSurfaceKind::Network
            | SessionSurfaceKind::Saas
            | SessionSurfaceKind::Desktop
            | SessionSurfaceKind::InternalSystem => {}
        }
    }

    let control_registration = register_session_control_channel(
        interception_backend.as_ref(),
        plan,
        browser_cdp_endpoint.as_deref(),
        lazy_browser_cdp,
    )?;
    let (docker_options, linux_host_options) = side_resource_command_options(
        interception_backend.as_ref(),
        browser_cdp_endpoint.as_deref(),
        control_registration.as_ref(),
    )?;

    Ok(SessionSideResources {
        environment,
        docker_options,
        linux_host_options,
        browser_cdp_endpoint,
        _control_registration: control_registration,
        _interception_backend: interception_backend,
        _supervisor: Some(supervisor),
    })
}

trait SessionPlanContext {
    fn audit(&self) -> &RuntimeAuditConfig;
    fn session_id(&self) -> &SessionId;
    fn actor(&self) -> &SessionActorLayerConfig;
    fn terminal(&self) -> &TerminalSurfaceConfig;
    fn runner_kind(&self) -> SessionRunnerKind;

    fn tty(&self) -> bool {
        self.terminal().tty()
    }
}

impl SessionPlanContext for SessionRunPlan {
    fn audit(&self) -> &RuntimeAuditConfig {
        self.audit()
    }

    fn session_id(&self) -> &SessionId {
        self.session_id()
    }

    fn actor(&self) -> &SessionActorLayerConfig {
        self.actor()
    }

    fn terminal(&self) -> &TerminalSurfaceConfig {
        self.terminal()
    }

    fn runner_kind(&self) -> SessionRunnerKind {
        self.runner().kind()
    }
}

impl SessionPlanContext for SessionAdoptPlan {
    fn audit(&self) -> &RuntimeAuditConfig {
        self.audit()
    }

    fn session_id(&self) -> &SessionId {
        self.session_id()
    }

    fn actor(&self) -> &SessionActorLayerConfig {
        self.actor()
    }

    fn terminal(&self) -> &TerminalSurfaceConfig {
        self.terminal()
    }

    fn runner_kind(&self) -> SessionRunnerKind {
        self.runner().kind()
    }
}

fn read_policy(path: &Path) -> Result<LocalPolicy, SessionExecutionError> {
    tracing::debug!(path = %path.display(), "reading session policy");
    let source = fs::read_to_string(path).map_err(|error| SessionExecutionError::ReadPolicy {
        path: path.to_path_buf(),
        source: error,
        location: Location::default(),
    })?;

    LocalPolicy::from_json_str(&source).map_err(SessionExecutionError::invalid_policy)
}

fn read_policy_set(paths: &[PathBuf]) -> Result<PolicySet, SessionExecutionError> {
    let policies = paths
        .iter()
        .map(|path| read_policy(path))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PolicySet::from_policies(policies))
}

enum SessionInterceptionBackendBundle {
    LinuxPtrace(LinuxPtraceInterceptionBackendBundle),
}

impl SessionInterceptionBackendBundle {
    fn prepare(
        start_plan: &erebor_runtime_core::SessionSurfaceStartPlan,
        plan: &impl SessionPlanContext,
        storage: Option<&SessionStorage>,
    ) -> Result<Option<Self>, SessionExecutionError> {
        if !start_plan
            .interception()
            .operation_supported(SessionInterceptionOperation::ProcessExec)
        {
            return Ok(None);
        }

        let Some(terminal) = start_plan.terminal() else {
            return Ok(None);
        };

        if terminal.process_interception().enabled()
            && plan.runner_kind() != SessionRunnerKind::LinuxHost
        {
            return Err(SessionExecutionError::guard_config(
                "terminal process interception currently supports linux-host sessions only",
            ));
        }

        match start_plan.interception().backend() {
            SessionInterceptionBackendKind::LinuxPtrace => {
                LinuxPtraceInterceptionBackendBundle::prepare(terminal, plan, storage)
                    .map(Self::LinuxPtrace)
                    .map(Some)
            }
        }
    }

    fn terminal_process_guard(&self) -> &'static str {
        match self {
            Self::LinuxPtrace(_) => SessionInterceptionBackendKind::LinuxPtrace.as_str(),
        }
    }

    fn docker_options(&self) -> DockerSessionCommandOptions {
        match self {
            Self::LinuxPtrace(bundle) => bundle.docker_options(),
        }
    }

    fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match self {
            Self::LinuxPtrace(bundle) => bundle.linux_host_options(browser_cdp_endpoint),
        }
    }

    fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match self {
            Self::LinuxPtrace(bundle) => bundle.linux_host_adopt_options(pid, browser_cdp_endpoint),
        }
    }

    fn control_handlers(&self) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        match self {
            Self::LinuxPtrace(bundle) => bundle.control_handlers(),
        }
    }
}

struct LinuxPtraceInterceptionBackendBundle {
    host_dir: PathBuf,
    guard_path: PathBuf,
    session_id: String,
    guard_rules: String,
    audit_path: Option<PathBuf>,
    audit_filename: Option<String>,
    audit_terminal_level: AuditCommandLogLevel,
    audit_terminal_debug_commands: Vec<String>,
    terminal_tty: bool,
    interception: Option<LinuxProcessInterceptionBundle>,
}

impl LinuxPtraceInterceptionBackendBundle {
    fn prepare(
        config: &TerminalSurfaceConfig,
        plan: &impl SessionPlanContext,
        storage: Option<&SessionStorage>,
    ) -> Result<Self, SessionExecutionError> {
        let instance_id = SESSION_GUARD_BUNDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let host_dir = std::env::temp_dir().join(format!(
            "erebor-linux-process-guard-{}-{}-{}",
            plan.session_id().as_str(),
            std::process::id(),
            instance_id
        ));
        fs::create_dir_all(&host_dir).map_err(SessionExecutionError::guard_io)?;
        let guard_path = host_dir.join("erebor-linux-process-guard");
        write_executable_file(&guard_path, LINUX_PROCESS_GUARD, instance_id)
            .map_err(SessionExecutionError::guard_io)?;

        let interception = LinuxProcessInterceptionBundle::prepare(&guard_path, &host_dir, config)?;
        let mut rules = compile_terminal_process_guard_rules(config)
            .map_err(SessionExecutionError::terminal_surface)?;
        if let Some(interception) = interception.as_ref() {
            rules.prepend(interception.allow_rules());
        }
        let guard_rules = rules.to_env_value();
        let mut audit_jsonl_path = None;
        let mut audit_filename = None;

        if let Some(audit_path) = storage.map(SessionStorage::audit_path) {
            let audit_parent = audit_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::create_dir_all(audit_parent).map_err(SessionExecutionError::guard_io)?;
            audit_filename = Some(
                audit_path
                    .file_name()
                    .ok_or_else(|| {
                        SessionExecutionError::guard_config(
                            "audit JSONL path must include a file name",
                        )
                    })?
                    .to_string_lossy()
                    .to_string(),
            );
            audit_jsonl_path = Some(audit_path.to_path_buf());
        }

        Ok(Self {
            host_dir,
            guard_path,
            session_id: plan.session_id().as_str().to_owned(),
            guard_rules,
            audit_path: audit_jsonl_path,
            audit_filename,
            audit_terminal_level: plan.audit().surfaces().terminal().level(),
            audit_terminal_debug_commands: plan
                .audit()
                .surfaces()
                .terminal()
                .debug_commands()
                .to_vec(),
            terminal_tty: plan.terminal().tty(),
            interception,
        })
    }

    fn docker_options(&self) -> DockerSessionCommandOptions {
        let mut options = DockerSessionCommandOptions::new()
            .with_mount(DockerSessionMount::new(&self.host_dir, DOCKER_GUARD_DIR).read_only())
            .with_entrypoint(LINUX_PROCESS_GUARD_PATH)
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace")
            .with_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string())
            .with_environment("EREBOR_GUARD_RULES", self.guard_rules.clone());

        if let Some(audit_path) = self.audit_path.as_ref() {
            let audit_parent = audit_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let Some(audit_filename) = self.audit_filename.as_ref() else {
                return options;
            };
            let container_audit_path = format!("{DOCKER_AUDIT_DIR}/{audit_filename}");
            options = options
                .with_mount(DockerSessionMount::new(audit_parent, DOCKER_AUDIT_DIR))
                .with_environment("EREBOR_GUARD_AUDIT_JSONL", container_audit_path)
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_LEVEL",
                    audit_command_level_env(self.audit_terminal_level),
                )
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS",
                    self.audit_terminal_debug_commands.join("\n"),
                );
        }

        options
    }

    fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        let mut options = LinuxHostSessionCommandOptions::new()
            .with_wrapper_program(&self.guard_path)
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace")
            .with_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string())
            .with_environment("EREBOR_GUARD_RULES", self.guard_rules.clone())
            .with_environment(
                "EREBOR_GUARD_CGROUP_DIR",
                format!(
                    "/sys/fs/cgroup/erebor/{}",
                    linux_cgroup_component(&self.session_id)
                ),
            );

        if let Some(audit_path) = self.audit_path.as_ref() {
            options = options
                .with_environment("EREBOR_GUARD_AUDIT_JSONL", audit_path.display().to_string())
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_LEVEL",
                    audit_command_level_env(self.audit_terminal_level),
                )
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS",
                    self.audit_terminal_debug_commands.join("\n"),
                );
        }

        if let Some(interception) = self.interception.as_ref() {
            for (key, value) in interception.environment(browser_cdp_endpoint)? {
                options = options.with_environment(key, value);
            }
        }

        Ok(options)
    }

    fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        Ok(self
            .linux_host_options(browser_cdp_endpoint)?
            .with_adopt_pid(pid))
    }

    fn control_handlers(&self) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        self.interception.as_ref().map_or_else(
            || Ok(Vec::new()),
            LinuxProcessInterceptionBundle::control_handlers,
        )
    }
}

fn write_executable_file(path: &Path, contents: &[u8], instance_id: u64) -> Result<(), io::Error> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable path must include a file name",
        )
    })?;
    let temp_path = path.with_file_name(format!(
        ".{}.tmp-{instance_id}",
        file_name.to_string_lossy()
    ));

    let mut file = File::create(&temp_path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);

    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755))?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct LinuxProcessInterceptionBundle {
    shim_dir: PathBuf,
    handlers: Vec<LinuxProcessInterceptionHandler>,
}

impl LinuxProcessInterceptionBundle {
    fn prepare(
        guard_path: &Path,
        host_dir: &Path,
        config: &TerminalSurfaceConfig,
    ) -> Result<Option<Self>, SessionExecutionError> {
        let interception = config.process_interception();
        if !interception.enabled() {
            return Ok(None);
        }

        match interception.mode() {
            TerminalProcessInterceptionMode::Shim => {}
        }

        let shim_dir = host_dir.join("shims");
        fs::create_dir_all(&shim_dir).map_err(SessionExecutionError::guard_io)?;

        let handlers = interception
            .handlers()
            .iter()
            .map(|handler| LinuxProcessInterceptionHandler::prepare(handler, guard_path, &shim_dir))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(Self { shim_dir, handlers }))
    }

    fn allow_rules(&self) -> Vec<TerminalProcessGuardRule> {
        self.handlers
            .iter()
            .flat_map(LinuxProcessInterceptionHandler::allow_rules)
            .collect()
    }

    fn environment(
        &self,
        _browser_cdp_endpoint: Option<&str>,
    ) -> Result<Vec<(String, String)>, SessionExecutionError> {
        let mut environment = vec![
            (
                String::from("EREBOR_PROCESS_INTERCEPTION"),
                String::from("linux-ptrace"),
            ),
            (
                String::from("EREBOR_PROCESS_INTERCEPTION_HANDLERS"),
                self.handlers_env(),
            ),
            (
                String::from("EREBOR_PROCESS_INTERCEPTION_SHIM_DIR"),
                self.shim_dir.display().to_string(),
            ),
        ];

        if self.handlers.iter().any(|handler| handler.prepend_path) {
            let path = std::env::var("PATH").unwrap_or_default();
            let shim_path = self.shim_dir.display().to_string();
            let value = if path.is_empty() {
                shim_path
            } else {
                format!("{shim_path}:{path}")
            };
            environment.push((String::from("PATH"), value));
        }

        for handler in &self.handlers {
            let Some(primary_shim) = handler.primary_shim_path() else {
                continue;
            };
            for variable in handler.executable_env_vars() {
                environment.push((variable, primary_shim.display().to_string()));
            }
        }

        Ok(environment)
    }

    fn handlers_env(&self) -> String {
        self.handlers
            .iter()
            .map(LinuxProcessInterceptionHandler::to_env_line)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn control_handlers(&self) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        self.handlers
            .iter()
            .map(LinuxProcessInterceptionHandler::to_control_handler)
            .collect()
    }
}

#[derive(Clone, Debug)]
struct LinuxProcessInterceptionHandler {
    id: String,
    decision: ProcessInterceptionDecision,
    kind: ProcessInterceptionHandlerKind,
    replacement_surface: ProcessMediationReplacementSurface,
    private_endpoint: ProcessMediationPrivateEndpointConfig,
    executables: Vec<String>,
    allowed_ports: Vec<u16>,
    executable_env: Vec<String>,
    print_devtools_listening_line: bool,
    keepalive: bool,
    prepend_path: bool,
    shim_paths: Vec<PathBuf>,
}

impl LinuxProcessInterceptionHandler {
    fn prepare(
        handler: &ProcessInterceptionHandlerConfig,
        guard_path: &Path,
        shim_dir: &Path,
    ) -> Result<Self, SessionExecutionError> {
        let mut shim_paths = Vec::new();
        let mut executables = Vec::new();

        for executable in handler.matcher().executables() {
            let shim_name = executable_basename(executable).ok_or_else(|| {
                SessionExecutionError::guard_config(format!(
                    "process interception handler `{}` executable `{}` is not a valid executable name",
                    handler.id(),
                    executable
                ))
            })?;
            let shim_path = shim_dir.join(&shim_name);
            std::os::unix::fs::symlink(guard_path, &shim_path)
                .map_err(SessionExecutionError::guard_io)?;
            executables.push(shim_name);
            shim_paths.push(shim_path);
        }

        Ok(Self {
            id: handler.id().to_owned(),
            decision: handler.decision(),
            kind: handler.kind(),
            replacement_surface: handler.replacement().surface(),
            private_endpoint: *handler.replacement().private_endpoint(),
            executables,
            allowed_ports: handler.requested_endpoint().allowed_ports().to_vec(),
            executable_env: process_interception_executable_env(handler),
            print_devtools_listening_line: handler.compatibility().print_devtools_listening_line(),
            keepalive: handler.compatibility().keepalive(),
            prepend_path: handler.environment().prepend_path(),
            shim_paths,
        })
    }

    fn allow_rules(&self) -> Vec<TerminalProcessGuardRule> {
        self.shim_paths
            .iter()
            .map(|path| {
                TerminalProcessGuardRule::new(
                    path.display().to_string(),
                    "process launch is routed through an Erebor process interception shim",
                    format!("erebor-process-interception-{}-shim", self.id),
                    TerminalProcessGuardDecision::Allow,
                )
            })
            .collect()
    }

    fn primary_shim_path(&self) -> Option<&Path> {
        self.shim_paths.first().map(PathBuf::as_path)
    }

    fn executable_env_vars(&self) -> Vec<String> {
        self.executable_env.clone()
    }

    fn to_env_line(&self) -> String {
        [
            interception_env_field(&self.id),
            interception_env_field(self.executables.join(",")),
        ]
        .join("\t")
    }

    fn to_control_handler(&self) -> Result<SessionInterceptionHandler, SessionExecutionError> {
        let reason = match self.decision {
            ProcessInterceptionDecision::Allow => "process launch allowed by Erebor broker",
            ProcessInterceptionDecision::Deny => "process launch denied by Erebor broker",
            ProcessInterceptionDecision::RequireApproval => {
                "process launch requires approval from Erebor broker"
            }
            ProcessInterceptionDecision::Mediate => "process launch mediated by Erebor broker",
        };

        let handler = match self.decision {
            ProcessInterceptionDecision::Allow => {
                SessionInterceptionHandler::allow(&self.id, reason)
            }
            ProcessInterceptionDecision::Deny => SessionInterceptionHandler::deny(&self.id, reason),
            ProcessInterceptionDecision::RequireApproval => {
                SessionInterceptionHandler::require_approval(&self.id, reason)
            }
            ProcessInterceptionDecision::Mediate => SessionInterceptionHandler::mediate(
                &self.id,
                reason,
                SessionMediationIntent::new(
                    self.kind.as_str(),
                    replacement_surface_name(self.replacement_surface),
                )
                .with_lease_id(format!("{}-lease", self.id))
                .with_allowed_ports(self.allowed_ports.clone())
                .with_private_endpoint(self.private_endpoint)
                .with_compatibility_line(self.print_devtools_listening_line)
                .with_keepalive(self.keepalive),
            ),
        };

        Ok(handler)
    }
}

#[derive(Clone)]
struct LazyBrowserCdpMediationConfig {
    config: erebor_runtime_core::BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
}

impl Drop for LinuxPtraceInterceptionBackendBundle {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.host_dir);
    }
}

fn terminal_uses_managed_browser_cdp_mediation(config: &TerminalSurfaceConfig) -> bool {
    config.process_interception().enabled()
        && config
            .process_interception()
            .handlers()
            .iter()
            .any(|handler| handler.kind() == ProcessInterceptionHandlerKind::ManagedBrowserCdp)
}

fn session_cdp_context(plan: &impl SessionPlanContext) -> CdpSessionContext {
    CdpSessionContext {
        session_id: plan.session_id().clone(),
        actor: ActorIdentity {
            id: plan.actor().id.clone(),
            kind: plan.actor().kind.clone(),
        },
        timestamp: runtime_timestamp(),
    }
}

fn linux_cgroup_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn audit_command_level_env(level: AuditCommandLogLevel) -> &'static str {
    match level {
        AuditCommandLogLevel::All => "all",
        AuditCommandLogLevel::Signal => "signal",
        AuditCommandLogLevel::NonAllow => "non_allow",
    }
}

fn side_resource_command_options(
    interception_backend: Option<&SessionInterceptionBackendBundle>,
    browser_cdp_endpoint: Option<&str>,
    control_registration: Option<&SessionControlRegistration>,
) -> Result<(DockerSessionCommandOptions, LinuxHostSessionCommandOptions), SessionExecutionError> {
    match interception_backend {
        Some(backend) => {
            let mut docker_options = backend.docker_options();
            let mut linux_host_options = backend.linux_host_options(browser_cdp_endpoint)?;
            if let Some(control_registration) = control_registration {
                docker_options = with_environment(
                    docker_options.with_mount(
                        DockerSessionMount::new(
                            control_registration.endpoint().directory(),
                            DOCKER_CONTROL_DIR,
                        )
                        .read_only(),
                    ),
                    control_registration
                        .docker_endpoint(Path::new(DOCKER_CONTROL_DIR))
                        .environment(),
                );
                linux_host_options = with_linux_host_environment(
                    linux_host_options,
                    control_registration.endpoint().environment(),
                );
            }

            Ok((docker_options, linux_host_options))
        }
        None => Ok((
            DockerSessionCommandOptions::default(),
            LinuxHostSessionCommandOptions::default(),
        )),
    }
}

fn register_session_control_channel(
    interception_backend: Option<&SessionInterceptionBackendBundle>,
    plan: &impl SessionPlanContext,
    browser_cdp_endpoint: Option<&str>,
    lazy_browser_cdp: Option<LazyBrowserCdpMediationConfig>,
) -> Result<Option<SessionControlRegistration>, SessionExecutionError> {
    let uses_lazy_browser_cdp = lazy_browser_cdp.is_some();
    interception_backend
        .map(|backend| {
            let handlers = backend.control_handlers()?;
            let registration = SessionControlBroker::register_session_with_mediators(
                plan.session_id().as_str(),
                &plan.actor().id,
                handlers,
                session_mediation_registry(browser_cdp_endpoint, lazy_browser_cdp)?,
            )
            .map_err(SessionExecutionError::control_broker)?;
            let registration = if uses_lazy_browser_cdp {
                registration.with_timeout_ms(LAZY_BROWSER_CDP_CONTROL_TIMEOUT_MS)
            } else {
                registration
            };
            Ok(registration)
        })
        .transpose()
}

fn with_environment(
    mut options: DockerSessionCommandOptions,
    environment: Vec<(String, String)>,
) -> DockerSessionCommandOptions {
    for (key, value) in environment {
        options = options.with_environment(key, value);
    }
    options
}

fn with_linux_host_environment(
    mut options: LinuxHostSessionCommandOptions,
    environment: Vec<(String, String)>,
) -> LinuxHostSessionCommandOptions {
    for (key, value) in environment {
        options = options.with_environment(key, value);
    }
    options
}

fn process_interception_executable_env(handler: &ProcessInterceptionHandlerConfig) -> Vec<String> {
    if !handler.environment().executable_env().is_empty() {
        return handler.environment().executable_env().to_vec();
    }

    match handler.kind() {
        ProcessInterceptionHandlerKind::ManagedBrowserCdp => [
            "CHROME_PATH",
            "BROWSER",
            "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
            "PUPPETEER_EXECUTABLE_PATH",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

fn session_mediation_registry(
    browser_cdp_endpoint: Option<&str>,
    lazy_browser_cdp: Option<LazyBrowserCdpMediationConfig>,
) -> Result<SessionMediationRegistry, SessionExecutionError> {
    let mut registry = SessionMediationRegistry::new();
    if let Some(lazy) = lazy_browser_cdp {
        registry.register_handler(
            BrowserCdpMediationHandler::lazy(
                lazy.config,
                lazy.policy_set,
                lazy.context,
                lazy.audit_jsonl,
                lazy.audit,
            )
            .map_err(SessionExecutionError::guard_io)?,
        );
    } else if let Some(endpoint) = browser_cdp_endpoint {
        registry.register_handler(BrowserCdpMediationHandler::new(endpoint));
    }
    Ok(registry)
}

fn replacement_surface_name(surface: ProcessMediationReplacementSurface) -> &'static str {
    match surface {
        ProcessMediationReplacementSurface::BrowserCdp => "browser_cdp",
    }
}

fn executable_basename(value: &str) -> Option<String> {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}

fn interception_env_field(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}

fn runtime_context(session_prefix: &str) -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new(format!("{session_prefix}-{}", std::process::id())),
        actor: ActorIdentity {
            id: String::from("erebor-runtime-session"),
            kind: ActorKind::System,
        },
        timestamp: runtime_timestamp(),
    }
}

fn runtime_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    format!("unix:{seconds}")
}

fn format_surfaces(surfaces: impl Iterator<Item = SessionSurfaceKind>) -> String {
    surfaces
        .map(SessionSurfaceKind::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_endpoints(runtimes: &[erebor_runtime_core::RunningSessionSurface]) -> String {
    runtimes
        .iter()
        .map(|runtime| format!("{}={}", runtime.surface().as_str(), runtime.endpoint()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Default)]
struct SessionSideResources {
    environment: Vec<(String, String)>,
    docker_options: DockerSessionCommandOptions,
    linux_host_options: LinuxHostSessionCommandOptions,
    browser_cdp_endpoint: Option<String>,
    _control_registration: Option<SessionControlRegistration>,
    _interception_backend: Option<SessionInterceptionBackendBundle>,
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionSideResources {
    fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    fn docker_options(&self) -> &DockerSessionCommandOptions {
        &self.docker_options
    }

    fn linux_host_options(&self) -> &LinuxHostSessionCommandOptions {
        &self.linux_host_options
    }

    fn linux_host_adopt_options(
        &self,
        pid: i32,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        self._interception_backend.as_ref().map_or_else(
            || Ok(LinuxHostSessionCommandOptions::default()),
            |backend| {
                let options =
                    backend.linux_host_adopt_options(pid, self.browser_cdp_endpoint.as_deref())?;
                if let Some(control_registration) = self._control_registration.as_ref() {
                    Ok(with_linux_host_environment(
                        options,
                        control_registration.endpoint().environment(),
                    ))
                } else {
                    Ok(options)
                }
            },
        )
    }
}

#[derive(Debug, Error)]
pub enum SessionExecutionError {
    #[error("{source}")]
    InvalidConfig {
        source: RuntimeConfigError,
        location: Location,
    },
    #[error("failed to read policy `{}`: {source}", path.display())]
    ReadPolicy {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("{source}")]
    InvalidPolicy {
        source: PolicyError,
        location: Location,
    },
    #[error("{source}")]
    Runtime {
        source: RuntimeError,
        location: Location,
    },
    #[error("{source}")]
    TerminalSurface {
        source: TerminalSurfaceError,
        location: Location,
    },
    #[error("guarded session diagnostic failed: {reason}")]
    DiagnosticFailed { reason: String, location: Location },
    #[error("Linux process guard I/O failed: {source}")]
    GuardIo {
        source: io::Error,
        location: Location,
    },
    #[error("Linux process guard config is invalid: {reason}")]
    GuardConfig { reason: String, location: Location },
    #[error("{source}")]
    SessionRegistry {
        source: SessionRegistryError,
        location: Location,
    },
    #[error("{source}")]
    ControlBroker {
        source: SessionControlBrokerError,
        location: Location,
    },
    #[error("failed to read process table `{}`: {source}", path.display())]
    ReadProcessTable {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("invalid session adoption target: {reason}")]
    InvalidAdoptTarget { reason: String, location: Location },
    #[error("no running process matched session adoption pattern `{pattern}`")]
    AdoptMatchNotFound { pattern: String, location: Location },
    #[error("session adoption pattern `{pattern}` matched multiple processes: {}", matches.join(", "))]
    AdoptMatchAmbiguous {
        pattern: String,
        matches: Vec<String>,
        location: Location,
    },
}

impl SessionExecutionError {
    #[track_caller]
    fn invalid_config(source: RuntimeConfigError) -> Self {
        Self::InvalidConfig {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn invalid_policy(source: PolicyError) -> Self {
        Self::InvalidPolicy {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn runtime(source: RuntimeError) -> Self {
        Self::Runtime {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn terminal_surface(source: TerminalSurfaceError) -> Self {
        Self::TerminalSurface {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn diagnostic_failed(reason: impl Into<String>) -> Self {
        Self::DiagnosticFailed {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn guard_io(source: io::Error) -> Self {
        Self::GuardIo {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn guard_config(reason: impl Into<String>) -> Self {
        Self::GuardConfig {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn session_registry(source: SessionRegistryError) -> Self {
        Self::SessionRegistry {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn control_broker(source: SessionControlBrokerError) -> Self {
        Self::ControlBroker {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn invalid_adopt_target(reason: impl Into<String>) -> Self {
        Self::InvalidAdoptTarget {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn adopt_match_not_found(pattern: impl Into<String>) -> Self {
        Self::AdoptMatchNotFound {
            pattern: pattern.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn adopt_match_ambiguous(pattern: impl Into<String>, matches: Vec<String>) -> Self {
        Self::AdoptMatchAmbiguous {
            pattern: pattern.into(),
            matches,
            location: Location::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use erebor_runtime_core::{
        DockerSessionCommandPlan, LinuxHostSessionCommandPlan, RuntimeConfig, SessionRunPlan,
        SessionRunnerKind,
    };
    use erebor_runtime_events::SessionId;

    use super::{process_interception_executable_env, start_session_side_resources};

    #[test]
    fn managed_browser_interception_defaults_browser_executable_env_vars(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:9222"
                }
              }
            }
            "#,
        )?;
        let terminal = config
            .surface_start_plan()?
            .terminal()
            .ok_or_else(|| std::io::Error::other("missing terminal surface"))?
            .clone();
        let handler = terminal
            .process_interception()
            .handlers()
            .first()
            .ok_or_else(|| std::io::Error::other("missing process interception handler"))?;

        let variables = process_interception_executable_env(handler);

        assert!(variables.contains(&String::from("CHROME_PATH")));
        assert!(variables.contains(&String::from("BROWSER")));
        assert!(variables.contains(&String::from("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")));
        assert!(variables.contains(&String::from("PUPPETEER_EXECUTABLE_PATH")));
        Ok(())
    }

    #[test]
    fn managed_browser_example_uses_lazy_requested_browser_endpoint(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("missing repo root"))?;
        let config_path = repo_root.join("examples/governed-openclaw-pilot/session-config.json");
        let config = RuntimeConfig::from_json_str(&fs::read_to_string(config_path)?)?;
        let browser_cdp = config
            .surface_start_plan()?
            .browser_cdp()
            .ok_or_else(|| std::io::Error::other("missing browser CDP surface"))?
            .clone();
        let terminal = config
            .surface_start_plan()?
            .terminal()
            .ok_or_else(|| std::io::Error::other("missing terminal surface"))?
            .clone();
        let handler = terminal
            .process_interception()
            .handlers()
            .first()
            .ok_or_else(|| std::io::Error::other("missing process interception handler"))?;

        assert_eq!(handler.id(), "managed-browser-cdp");
        assert_eq!(browser_cdp.listen().port(), 0);
        assert_eq!(browser_cdp.browser_url(), None);
        assert!(browser_cdp.owns_browser());
        assert!(handler.requested_endpoint().allowed_ports().is_empty());
        assert_eq!(
            handler.replacement().private_endpoint().port_strategy(),
            erebor_runtime_core::ProcessMediationPrivatePortStrategy::RequestedPlusOffset
        );
        assert_eq!(handler.replacement().private_endpoint().port_offset(), 1);
        assert_eq!(
            handler.replacement().surface(),
            erebor_runtime_core::ProcessMediationReplacementSurface::BrowserCdp
        );
        Ok(())
    }

    #[test]
    fn session_side_resources_inject_control_broker_environment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = test_dir("control-env")?;
        let policy_path = write_policy(&test_dir)?;
        let config = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "session": {{
                "enabled": true,
                "actor": {{ "id": "openclaw" }},
                "runner": {{ "kind": "linux_host" }},
                "interception": {{ "enabled": true }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}
            "#,
            policy_path.display()
        ))?;
        let linux_plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-control-env"),
            vec![String::from("true")],
        )?;
        let linux_resources = start_session_side_resources(&config, &linux_plan, None)?;
        let linux_launch =
            LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
                &linux_plan,
                linux_resources.environment(),
                linux_resources.linux_host_options(),
            );
        let linux_control_path =
            environment_value(linux_launch.environment(), "EREBOR_SESSION_CONTROL_PATH")
                .ok_or_else(|| std::io::Error::other("missing Linux host control path"))?;

        assert!(linux_launch.environment().contains(&(
            String::from("EREBOR_SESSION_CONTROL_PROTOCOL"),
            String::from("erebor_ipc_v1")
        )));
        assert!(linux_launch.environment().contains(&(
            String::from("EREBOR_SESSION_CONTROL_TRANSPORT"),
            String::from("unix")
        )));
        assert!(linux_launch.environment().contains(&(
            String::from("EREBOR_SESSION_CONTROL_TIMEOUT_MS"),
            String::from("25")
        )));
        assert!(linux_control_path.ends_with("session-control.sock"));

        let docker_plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-control-env-docker"),
            vec![String::from("true")],
        )?;
        let docker_resources = start_session_side_resources(&config, &docker_plan, None)?;
        let docker_launch =
            DockerSessionCommandPlan::from_session_run_plan_with_environment_and_options(
                &docker_plan,
                docker_resources.environment(),
                docker_resources.docker_options(),
            );
        let docker_args = docker_launch.args().join("\n");

        assert!(docker_args.contains("EREBOR_SESSION_CONTROL_PROTOCOL=erebor_ipc_v1"));
        assert!(docker_args.contains("EREBOR_SESSION_CONTROL_TRANSPORT=unix"));
        assert!(docker_args.contains("EREBOR_SESSION_CONTROL_TIMEOUT_MS=25"));
        assert!(docker_args
            .contains("EREBOR_SESSION_CONTROL_PATH=/erebor/control/session-control.sock"));
        assert!(docker_args.contains("/erebor/control:ro"));
        fs::remove_dir_all(test_dir)?;
        Ok(())
    }

    fn environment_value(environment: &[(String, String)], key: &str) -> Option<String> {
        environment
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then(|| value.clone()))
    }

    fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "erebor-session-resources-{name}-{}",
            std::process::id()
        ));
        let _result = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn write_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
        let policy_path = test_dir.join("policy.json");
        fs::write(
            &policy_path,
            r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP process launch is denied"
                }
              ]
            }
            "#,
        )?;
        Ok(policy_path)
    }
}
