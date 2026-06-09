use std::{
    fs, io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    DockerSessionCommandOptions, DockerSessionMount, RuntimeConfig, RuntimeConfigError,
    RuntimeError, SessionRunOutcome, SessionRunPlan, SessionRunnerLauncher,
    SessionSurfaceDefinition, SessionSurfaceKind, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
    SessionSurfaceSupervisor, TerminalSurfaceConfig,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicyError, PolicySet};
use erebor_runtime_terminal::{compile_terminal_process_guard_rules, TerminalSurfaceError};
use snafu::Location;
use thiserror::Error;

const LINUX_PROCESS_GUARD: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erebor-linux-process-guard"));
const DOCKER_GUARD_DIR: &str = "/erebor/guard";
const LINUX_PROCESS_GUARD_PATH: &str = "/erebor/guard/erebor-linux-process-guard";
const DOCKER_AUDIT_DIR: &str = "/erebor/audit";

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
    let side_resources = start_session_side_resources(config, plan)?;

    SessionRunnerLauncher::run_with_docker_options(
        plan,
        side_resources.environment(),
        side_resources.docker_options(),
    )
    .map_err(SessionExecutionError::runtime)
}

pub fn run_session_diagnostic(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
    let side_resources = start_session_side_resources(config, plan)?;
    let outcome = SessionRunnerLauncher::run_capture_with_docker_options(
        plan,
        side_resources.environment(),
        side_resources.docker_options(),
    )
    .map_err(SessionExecutionError::runtime)?;

    if outcome.run().exit_code() == Some(0) {
        Ok(SessionDiagnosticOutcome::new(
            outcome.stdout().to_owned(),
            outcome.stderr().to_owned(),
        ))
    } else {
        Err(SessionExecutionError::diagnostic_failed(format!(
            "guarded Docker diagnostic exited with code {:?}: {}",
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
                launcher.add_surface(BrowserCdpSurface::new(
                    config.clone(),
                    policy_set,
                    runtime_context("browser-cdp"),
                ));
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
) -> Result<SessionSideResources, SessionExecutionError> {
    let start_plan = config
        .surface_start_plan_for_session(plan)
        .map_err(SessionExecutionError::invalid_config)?;
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
    let mut docker_options = DockerSessionCommandOptions::default();
    let mut guard_bundle = None;

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                launcher.add_surface(BrowserCdpSurface::new(
                    config.clone(),
                    policy_set,
                    session_cdp_context(plan),
                ));
            }
            SessionSurfaceDefinition::Terminal(config) => {
                let bundle = LinuxProcessGuardBundle::prepare(config, plan)?;
                docker_options = bundle.docker_options().clone();
                guard_bundle = Some(bundle);
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("process_guard"),
                ));
                environment.push((
                    String::from("EREBOR_TERMINAL_TTY"),
                    plan.terminal().tty().to_string(),
                ));
            }
        }
    }

    if launcher.is_empty() {
        return Ok(SessionSideResources {
            environment,
            docker_options,
            _guard_bundle: guard_bundle,
            _supervisor: None,
        });
    }

    let supervisor = launcher.start().map_err(SessionExecutionError::runtime)?;
    for runtime in supervisor.running() {
        match runtime.surface() {
            SessionSurfaceKind::BrowserCdp => {
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

    Ok(SessionSideResources {
        environment,
        docker_options,
        _guard_bundle: guard_bundle,
        _supervisor: Some(supervisor),
    })
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

struct LinuxProcessGuardBundle {
    host_dir: PathBuf,
    docker_options: DockerSessionCommandOptions,
}

impl LinuxProcessGuardBundle {
    fn prepare(
        config: &TerminalSurfaceConfig,
        plan: &SessionRunPlan,
    ) -> Result<Self, SessionExecutionError> {
        let host_dir = std::env::temp_dir().join(format!(
            "erebor-linux-process-guard-{}-{}",
            plan.session_id().as_str(),
            std::process::id()
        ));
        fs::create_dir_all(&host_dir).map_err(SessionExecutionError::guard_io)?;
        let guard_path = host_dir.join("erebor-linux-process-guard");
        fs::write(&guard_path, LINUX_PROCESS_GUARD).map_err(SessionExecutionError::guard_io)?;
        fs::set_permissions(&guard_path, fs::Permissions::from_mode(0o755))
            .map_err(SessionExecutionError::guard_io)?;

        let mut options = DockerSessionCommandOptions::new()
            .with_mount(DockerSessionMount::new(&host_dir, DOCKER_GUARD_DIR).read_only())
            .with_entrypoint(LINUX_PROCESS_GUARD_PATH)
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace")
            .with_environment("EREBOR_TERMINAL_TTY", plan.terminal().tty().to_string())
            .with_environment(
                "EREBOR_GUARD_DENY_RULES",
                compile_terminal_process_guard_rules(config)
                    .map_err(SessionExecutionError::terminal_surface)?
                    .to_docker_env_value(),
            );

        if let Some(audit_path) = plan.audit().jsonl() {
            let audit_parent = audit_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::create_dir_all(audit_parent).map_err(SessionExecutionError::guard_io)?;
            let audit_filename = audit_path
                .file_name()
                .ok_or_else(|| {
                    SessionExecutionError::guard_config("audit JSONL path must include a file name")
                })?
                .to_string_lossy()
                .to_string();
            let container_audit_path = format!("{DOCKER_AUDIT_DIR}/{audit_filename}");
            options = options
                .with_mount(DockerSessionMount::new(audit_parent, DOCKER_AUDIT_DIR))
                .with_environment("EREBOR_GUARD_AUDIT_JSONL", container_audit_path);
        }

        Ok(Self {
            host_dir,
            docker_options: options,
        })
    }

    fn docker_options(&self) -> &DockerSessionCommandOptions {
        &self.docker_options
    }
}

impl Drop for LinuxProcessGuardBundle {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.host_dir);
    }
}

fn session_cdp_context(plan: &SessionRunPlan) -> CdpSessionContext {
    CdpSessionContext {
        session_id: plan.session_id().clone(),
        actor: ActorIdentity {
            id: plan.actor().id.clone(),
            kind: plan.actor().kind.clone(),
        },
        timestamp: runtime_timestamp(),
    }
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
    _guard_bundle: Option<LinuxProcessGuardBundle>,
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionSideResources {
    fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    fn docker_options(&self) -> &DockerSessionCommandOptions {
        &self.docker_options
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
}
