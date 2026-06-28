use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

mod adoption;
mod control_broker;
mod interception_backend;

use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    DockerSessionCommandOptions, DockerSessionMount, LinuxHostSessionCommandOptions,
    ProcessInterceptionHandlerKind, RuntimeAuditConfig, RuntimeConfig, RuntimeConfigError,
    RuntimeError, SessionActorLayerConfig, SessionAdoptPlan, SessionInterceptionOperation,
    SessionRegistry, SessionRegistryError, SessionRegistryFinish, SessionRunOutcome,
    SessionRunPlan, SessionRunnerKind, SessionRunnerLauncher, SessionSurfaceDefinition,
    SessionSurfaceKind, SessionSurfaceLaunchPlan, SessionSurfaceLauncher, SessionSurfaceSupervisor,
    TerminalProcessInterceptionMode, TerminalSurfaceConfig,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicyError, PolicySet};
use erebor_runtime_terminal::{TerminalProcessExecValidator, TerminalSurfaceError};
use snafu::Location;
use thiserror::Error;

use crate::interception_backend::{
    ProcessExecInterceptionInput, ProcessExecMediationInput, ProcessExecMediationMode,
    SessionInterceptionBackendBundle, SessionInterceptionBackendSurfaceRegistry,
};

pub use adoption::adopt_session_target;
pub use control_broker::{
    BrowserCdpMediationHandler, GuardBrokerClient, SessionControlBroker,
    SessionControlBrokerEndpoint, SessionControlBrokerError, SessionControlRegistration,
    SessionInterceptionHandler, SessionInterceptionRouter, SessionMediationIntent,
    SessionMediationRegistry, SurfaceMediationHandler, SurfaceMediationOutcome,
};
pub use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};

const DOCKER_CONTROL_DIR: &str = "/erebor/control";
const LAZY_BROWSER_CDP_CONTROL_TIMEOUT_MS: u64 = 15_000;

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
    let mut interception_surfaces = SessionInterceptionBackendSurfaceRegistry::new();
    let mut terminal_surface_present = false;
    let process_exec_supported = start_plan
        .interception()
        .operation_supported(SessionInterceptionOperation::ProcessExec);
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
            SessionSurfaceDefinition::Terminal(config) => {
                terminal_surface_present = true;
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("terminal"),
                ));
                environment.push((
                    String::from("EREBOR_TERMINAL_TTY"),
                    config.tty().to_string(),
                ));

                if process_exec_supported {
                    interception_surfaces.register_process_exec(
                        terminal_process_exec_input(config, plan)?,
                        TerminalProcessExecValidator::from_config(config)
                            .map_err(SessionExecutionError::terminal_surface)?,
                    );
                }
            }
        }
    }

    let (process_exec_interception, interception_router) = interception_surfaces.into_parts();
    let interception_backend = SessionInterceptionBackendBundle::prepare(
        start_plan.interception(),
        process_exec_interception,
        plan,
        prepared_session.map(|session| &session.storage),
    )?;
    if terminal_surface_present {
        if let Some(interception_backend) = interception_backend.as_ref() {
            environment.push((
                String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
                interception_backend.backend_kind().to_owned(),
            ));
        } else {
            environment.push((
                String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
                String::from("disabled"),
            ));
        }
    }

    if launcher.is_empty() {
        let control_registration = register_session_control_channel(
            interception_backend.as_ref(),
            interception_router.clone(),
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
        interception_router,
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
    fn runner_kind(&self) -> SessionRunnerKind;
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

#[derive(Clone)]
struct LazyBrowserCdpMediationConfig {
    config: erebor_runtime_core::BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
}

fn terminal_uses_managed_browser_cdp_mediation(config: &TerminalSurfaceConfig) -> bool {
    config.process_interception().enabled()
        && config
            .process_interception()
            .handlers()
            .iter()
            .any(|handler| handler.kind() == ProcessInterceptionHandlerKind::ManagedBrowserCdp)
}

fn terminal_process_exec_input<'a>(
    config: &'a TerminalSurfaceConfig,
    plan: &impl SessionPlanContext,
) -> Result<ProcessExecInterceptionInput<'a>, SessionExecutionError> {
    let mediation = config.process_interception();
    if mediation.enabled() && plan.runner_kind() != SessionRunnerKind::LinuxHost {
        return Err(SessionExecutionError::guard_config(
            "terminal process interception currently supports linux-host sessions only",
        ));
    }

    Ok(ProcessExecInterceptionInput::new(
        ProcessExecMediationInput::new(
            mediation.enabled(),
            process_exec_mediation_mode(mediation.mode()),
            mediation.handlers(),
        ),
        plan.audit().surfaces().terminal().level(),
        plan.audit().surfaces().terminal().debug_commands().to_vec(),
        config.tty(),
    ))
}

fn process_exec_mediation_mode(mode: TerminalProcessInterceptionMode) -> ProcessExecMediationMode {
    match mode {
        TerminalProcessInterceptionMode::Shim => ProcessExecMediationMode::Shim,
    }
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
    interception_router: SessionInterceptionRouter,
    plan: &impl SessionPlanContext,
    browser_cdp_endpoint: Option<&str>,
    lazy_browser_cdp: Option<LazyBrowserCdpMediationConfig>,
) -> Result<Option<SessionControlRegistration>, SessionExecutionError> {
    let uses_lazy_browser_cdp = lazy_browser_cdp.is_some();
    interception_backend
        .map(|backend| {
            let handlers = backend.control_handlers()?;
            let registration = SessionControlBroker::register_session_with_router_and_mediators(
                plan.session_id().as_str(),
                &plan.actor().id,
                handlers,
                interception_router,
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

    use super::{
        interception_backend::process_interception_executable_env, start_session_side_resources,
    };

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
