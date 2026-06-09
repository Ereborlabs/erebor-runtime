use std::{
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use erebor_runtime_audit::{read_audit_records, AuditLogError, JsonlAuditSink};
use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    AuditError, AuditRecord, AuditSink, BrowserCdpSurfaceLayerConfig, DenyApprovalProvider,
    LocalEnforcementEngine, NoopAuditSink, RunningSessionSurface, RuntimeAuditConfig,
    RuntimeConfig, RuntimeConfigError, RuntimeError, SessionRunPlan, SessionRunnerKind,
    SessionRunnerLauncher, SessionSurfaceDefinition, SessionSurfaceLaunchPlan,
    SessionSurfaceLauncher, SessionSurfaceLayers, SessionSurfaceStartPlan,
    SessionSurfaceSupervisor,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, ExecutionSurface, RiskLevel, RiskMetadata, RuntimeEvent,
    SessionId, TargetRef,
};
use erebor_runtime_policy::{Decision, LocalPolicy, PolicyError, PolicyEvaluator, PolicySet};
use snafu::Location;
use thiserror::Error;

use crate::logging::{init_tracing, LoggingArgs};

#[derive(Debug, Parser)]
#[command(
    name = "erebor-runtime",
    version,
    about = "Zero-trust action governance runtime for AI agents",
    next_line_help = true
)]
pub(crate) struct Cli {
    #[command(flatten)]
    logging: LoggingArgs,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub(crate) fn execute(&self) -> Result<(), CliError> {
        init_tracing(&self.logging);
        tracing::debug!(command = %self.command, "executing command");

        match &self.command {
            Command::Start(args) => start_runtime(args)?,
            Command::Session(args) => execute_session(args)?,
            Command::Dev(args) => execute_dev(args)?,
            Command::Policy(args) => execute_policy(args)?,
            Command::Audit(args) => execute_audit(args)?,
        }

        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the configured session surfaces.
    Start(StartArgs),
    /// Start or manage governed agent sessions.
    Session(SessionArgs),
    /// Development and surface-specific utilities.
    Dev(DevArgs),
    /// Policy development and validation commands.
    Policy(PolicyArgs),
    /// Audit log commands.
    Audit(AuditArgs),
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(args) => write!(
                formatter,
                "start config={} listen={}",
                args.config.display(),
                args.listen
            ),
            Self::Session(SessionArgs {
                command: SessionCommand::Run(args),
            }) => write!(
                formatter,
                "session run runner={} config={} command={}",
                args.runner.as_str(),
                args.config.display(),
                args.command.join(" ")
            ),
            Self::Session(SessionArgs {
                command: SessionCommand::Diagnose(args),
            }) => write!(
                formatter,
                "session diagnose runner={} config={} name={}",
                args.runner.as_str(),
                args.config.display(),
                args.name
            ),
            Self::Dev(DevArgs {
                command: DevCommand::ProxyCdp(args),
            }) => {
                write!(
                    formatter,
                    "dev proxy-cdp policy={} listen={} upstream=configured",
                    args.policy.display(),
                    args.listen
                )
            }
            Self::Policy(PolicyArgs {
                command: PolicyCommand::Test(args),
            }) => write!(
                formatter,
                "policy test policy={} event={}",
                args.policy.display(),
                args.event.display()
            ),
            Self::Audit(AuditArgs {
                command: AuditCommand::Tail(args),
            }) => write!(formatter, "audit tail file={}", args.file.display()),
        }
    }
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Runtime config describing enabled session surfaces and policies.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Local address for runtime control/status APIs.
    #[arg(long, default_value = "127.0.0.1:3737")]
    listen: SocketAddr,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Run an agent or command inside a governed session runner.
    Run(SessionRunArgs),
    /// Run a named bounded diagnostic from the session config.
    Diagnose(SessionDiagnoseArgs),
}

#[derive(Debug, Args)]
struct SessionRunArgs {
    /// Session config describing policies, audit, surfaces, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    runner: SessionRunnerArg,
    /// Command to execute inside the governed session runner.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct SessionDiagnoseArgs {
    /// Session config describing policies, audit, diagnostics, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    runner: SessionRunnerArg,
    /// Named diagnostic from the session config.
    name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SessionRunnerArg {
    Docker,
}

impl SessionRunnerArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
        }
    }
}

impl From<SessionRunnerArg> for SessionRunnerKind {
    fn from(value: SessionRunnerArg) -> Self {
        match value {
            SessionRunnerArg::Docker => Self::Docker,
        }
    }
}

#[derive(Debug, Args)]
struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Proxy an existing Chromium CDP endpoint with an explicit policy.
    ProxyCdp(ProxyCdpArgs),
}

#[derive(Debug, Args)]
struct ProxyCdpArgs {
    /// Existing local Chromium browser websocket URL.
    #[arg(long, value_parser = parse_ws_url)]
    browser_url: WebSocketUrl,
    /// Policy file or package entrypoint to apply.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Local address for the governed CDP endpoint.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate a single event fixture against a policy.
    Test(PolicyTestArgs),
}

#[derive(Debug, Args)]
struct PolicyTestArgs {
    /// Policy file or package entrypoint to test.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Runtime event JSON fixture.
    #[arg(long, value_parser = parse_non_empty_path)]
    event: PathBuf,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Follow a JSONL audit log.
    Tail(AuditTailArgs),
}

#[derive(Debug, Args)]
struct AuditTailArgs {
    /// JSONL audit log path.
    #[arg(long, value_parser = parse_non_empty_path)]
    file: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WebSocketUrl(String);

impl WebSocketUrl {
    fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_ws_url(value: &str) -> Result<WebSocketUrl, String> {
    if value.starts_with("ws://") {
        Ok(WebSocketUrl(value.to_owned()))
    } else {
        Err(String::from("must start with ws://"))
    }
}

fn parse_non_empty_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() {
        Err(String::from("path cannot be empty"))
    } else {
        Ok(path.to_path_buf())
    }
}

fn read_runtime_config(path: &Path) -> Result<RuntimeConfig, CliError> {
    tracing::debug!(path = %path.display(), "reading runtime config");
    let source = fs::read_to_string(path).map_err(|error| CliError::ReadConfig {
        path: path.to_path_buf(),
        source: error,
        location: Location::default(),
    })?;
    let mut config: RuntimeConfig =
        RuntimeConfig::from_json_str(&source).map_err(CliError::invalid_config)?;
    resolve_config_paths(path, &mut config);

    Ok(config)
}

fn build_start_plan(path: &Path) -> Result<SessionSurfaceStartPlan, CliError> {
    read_runtime_config(path)?
        .surface_start_plan()
        .map_err(CliError::invalid_config)
}

fn build_runtime_launch_plan(args: &StartArgs) -> Result<SessionSurfaceLaunchPlan, CliError> {
    let plan = build_start_plan(&args.config)?;
    tracing::debug!(
        control_listen = %args.listen,
        surfaces = ?plan.surfaces(),
        policy_count = plan.policies().len(),
        "building session surface launch plan"
    );
    SessionSurfaceLaunchPlan::from_start_plan(args.listen, &plan).map_err(CliError::runtime)
}

fn build_dev_proxy_launch_plan(args: &ProxyCdpArgs) -> Result<SessionSurfaceLaunchPlan, CliError> {
    let config = RuntimeConfig {
        policies: vec![args.policy.clone()],
        audit: RuntimeAuditConfig::default(),
        session: Default::default(),
        surfaces: SessionSurfaceLayers {
            browser_cdp: BrowserCdpSurfaceLayerConfig {
                enabled: true,
                browser_url: Some(args.browser_url.as_str().to_owned()),
                listen: args.listen,
                browser: Default::default(),
            },
            ..SessionSurfaceLayers::default()
        },
    };
    let plan = config
        .surface_start_plan()
        .map_err(CliError::invalid_config)?;

    SessionSurfaceLaunchPlan::from_start_plan(args.listen, &plan).map_err(CliError::runtime)
}

fn resolve_config_paths(config_path: &Path, config: &mut RuntimeConfig) {
    let base_dir = config_base_dir(config_path);
    let base_dir = base_dir.as_deref();
    for policy in &mut config.policies {
        resolve_config_path(base_dir, policy);
    }
    resolve_optional_config_path(base_dir, &mut config.audit.jsonl);
    resolve_optional_config_path(base_dir, &mut config.session.workspace);
    resolve_optional_config_path(
        base_dir,
        &mut config.surfaces.browser_cdp.browser.executable,
    );
    resolve_optional_config_path(
        base_dir,
        &mut config.surfaces.browser_cdp.browser.user_data_dir,
    );
}

fn config_base_dir(config_path: &Path) -> Option<PathBuf> {
    config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map(|current_dir| current_dir.join(path))
                    .unwrap_or_else(|_| path.to_path_buf())
            }
        })
}

fn resolve_optional_config_path(base_dir: Option<&Path>, path: &mut Option<PathBuf>) {
    if let Some(path) = path {
        resolve_config_path(base_dir, path);
    }
}

fn resolve_config_path(base_dir: Option<&Path>, path: &mut PathBuf) {
    if path.is_absolute() {
        return;
    }
    let Some(base_dir) = base_dir else {
        return;
    };

    *path = base_dir.join(&path);
}

fn read_policy(path: &Path) -> Result<LocalPolicy, CliError> {
    tracing::debug!(path = %path.display(), "reading policy");
    let source = fs::read_to_string(path).map_err(|error| CliError::ReadPolicy {
        path: path.to_path_buf(),
        source: error,
        location: Location::default(),
    })?;

    LocalPolicy::from_json_str(&source).map_err(CliError::invalid_policy)
}

fn read_policy_set(paths: &[PathBuf]) -> Result<PolicySet, CliError> {
    let policies = paths
        .iter()
        .map(|path| read_policy(path))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PolicySet::from_policies(policies))
}

fn read_event(path: &Path) -> Result<RuntimeEvent, CliError> {
    tracing::debug!(path = %path.display(), "reading runtime event fixture");
    let source = fs::read_to_string(path).map_err(|error| CliError::ReadEvent {
        path: path.to_path_buf(),
        source: error,
        location: Location::default(),
    })?;

    serde_json::from_str(&source).map_err(CliError::invalid_event)
}

fn start_runtime(args: &StartArgs) -> Result<(), CliError> {
    let launch_plan = build_runtime_launch_plan(args)?;
    start_runtime_from_launch_plan(launch_plan)
}

fn execute_session(args: &SessionArgs) -> Result<(), CliError> {
    match &args.command {
        SessionCommand::Run(args) => session_run(args),
        SessionCommand::Diagnose(args) => session_diagnose(args),
    }
}

fn session_run(args: &SessionRunArgs) -> Result<(), CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    let plan = SessionRunPlan::from_config(
        &config,
        args.runner.into(),
        session_id,
        args.command.clone(),
    )
    .map_err(CliError::invalid_config)?;
    execute_session_run_plan(&config, &plan)
}

fn session_diagnose(args: &SessionDiagnoseArgs) -> Result<(), CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    let plan = SessionRunPlan::from_diagnostic(&config, args.runner.into(), session_id, &args.name)
        .map_err(CliError::invalid_config)?;
    execute_session_run_plan(&config, &plan)
}

fn execute_session_run_plan(config: &RuntimeConfig, plan: &SessionRunPlan) -> Result<(), CliError> {
    let policy_set = read_policy_set(plan.policies())?;
    let engine = LocalEnforcementEngine::with_hooks(
        policy_set,
        DenyApprovalProvider,
        ConfiguredAuditSink::from_config(plan.audit()),
    );
    let event = session_process_event(plan);
    let outcome = engine.enforce(&event).map_err(CliError::runtime)?;

    match outcome.final_decision {
        Decision::Allow { .. } => {
            let side_resources = start_session_side_resources(config, plan)?;
            SessionRunnerLauncher::run(plan, side_resources.environment())
                .map_err(CliError::runtime)?;
            Ok(())
        }
        Decision::Deny { reason, .. } => Err(CliError::session_denied(reason)),
        Decision::RequireApproval { reason, .. } => Err(CliError::session_denied(reason)),
    }
}

#[cfg(test)]
fn build_session_run_plan(args: &SessionRunArgs) -> Result<SessionRunPlan, CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    SessionRunPlan::from_config(
        &config,
        args.runner.into(),
        session_id,
        args.command.clone(),
    )
    .map_err(CliError::invalid_config)
}

#[cfg(test)]
fn build_session_diagnose_plan(args: &SessionDiagnoseArgs) -> Result<SessionRunPlan, CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    SessionRunPlan::from_diagnostic(&config, args.runner.into(), session_id, &args.name)
        .map_err(CliError::invalid_config)
}

fn start_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<SessionSideResources, CliError> {
    let start_plan = config
        .surface_start_plan_for_session(plan)
        .map_err(CliError::invalid_config)?;
    if start_plan.surfaces().is_empty() {
        return Ok(SessionSideResources::default());
    }

    let policy_set = read_policy_set(start_plan.policies())?;
    let launch_plan = SessionSurfaceLaunchPlan::from_start_plan(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &start_plan,
    )
    .map_err(CliError::runtime)?;
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                launcher.add_surface(BrowserCdpSurface::new(
                    config.clone(),
                    policy_set.clone(),
                    session_cdp_context(plan),
                ));
            }
        }
    }

    let supervisor = launcher.start().map_err(CliError::runtime)?;
    let mut environment = Vec::new();
    for runtime in supervisor.running() {
        if runtime.surface() == erebor_runtime_core::SessionSurfaceKind::BrowserCdp {
            environment.push((
                String::from("EREBOR_BROWSER_CDP_URL"),
                runtime.endpoint().to_owned(),
            ));
            environment.push((
                String::from("EREBOR_OPENCLAW_BROWSER_PROFILE"),
                String::from("erebor"),
            ));
        }
    }

    Ok(SessionSideResources {
        environment,
        _supervisor: Some(supervisor),
    })
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

#[derive(Default)]
struct SessionSideResources {
    environment: Vec<(String, String)>,
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionSideResources {
    fn environment(&self) -> &[(String, String)] {
        &self.environment
    }
}

fn session_process_event(plan: &SessionRunPlan) -> RuntimeEvent {
    let command = plan.command();
    let command_name = command.first().cloned().unwrap_or_default();

    RuntimeEvent {
        id: erebor_runtime_events::EventId::new(format!(
            "{}-root-process-exec",
            plan.session_id().as_str()
        )),
        session_id: plan.session_id().clone(),
        actor: ActorIdentity {
            id: plan.actor().id.clone(),
            kind: plan.actor().kind.clone(),
        },
        surface: ExecutionSurface::Terminal,
        action: ActionKind::ProcessExec,
        target: Some(TargetRef {
            label: Some(command_name),
            uri: None,
        }),
        payload: serde_json::json!({
            "kind": "session_process_exec",
            "session_runner": plan.runner().kind().as_str(),
            "docker": {
                "image": plan.runner().docker().image(),
                "network": plan.runner().docker().network(),
                "workdir": plan.runner().docker().workdir(),
            },
            "workspace": plan.workspace(),
            "diagnostic": plan.diagnostic(),
            "command": command,
        }),
        risk: RiskMetadata {
            level: RiskLevel::Medium,
            reasons: vec![String::from(
                "root command for Docker/OCI governed session runner",
            )],
        },
        timestamp: runtime_timestamp(),
    }
}

fn execute_dev(args: &DevArgs) -> Result<(), CliError> {
    match &args.command {
        DevCommand::ProxyCdp(args) => {
            let launch_plan = build_dev_proxy_launch_plan(args)?;
            start_runtime_from_launch_plan(launch_plan)
        }
    }
}

fn start_runtime_from_launch_plan(launch_plan: SessionSurfaceLaunchPlan) -> Result<(), CliError> {
    let policy_set = read_policy_set(launch_plan.policy_paths())?;
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                launcher.add_surface(BrowserCdpSurface::new(
                    config.clone(),
                    policy_set.clone(),
                    runtime_context("browser-cdp"),
                ));
            }
        }
    }

    let supervisor = launcher.start().map_err(CliError::runtime)?;
    tracing::info!(
        control = %supervisor.control_listen(),
        surfaces = %format_surfaces(supervisor.running().iter().map(RunningSessionSurface::surface)),
        endpoints = %format_endpoints(supervisor.running()),
        "session surfaces started"
    );

    supervisor.wait().map_err(CliError::runtime)?;
    Ok(())
}

fn execute_policy(args: &PolicyArgs) -> Result<(), CliError> {
    match &args.command {
        PolicyCommand::Test(args) => {
            tracing::debug!(
                policy = %args.policy.display(),
                event = %args.event.display(),
                "testing policy"
            );
            let policy_set = read_policy_set(std::slice::from_ref(&args.policy))?;
            let event = read_event(&args.event)?;
            let decision = policy_set
                .evaluate(&event)
                .map_err(CliError::policy_evaluation)?;
            println!(
                "{}",
                serde_json::to_string(&decision).map_err(CliError::encode_json)?
            );
        }
    }

    Ok(())
}

fn execute_audit(args: &AuditArgs) -> Result<(), CliError> {
    match &args.command {
        AuditCommand::Tail(args) => {
            tracing::debug!(file = %args.file.display(), "reading audit records");
            for record in read_audit_records(&args.file).map_err(CliError::audit_log)? {
                println!(
                    "{}",
                    serde_json::to_string(&record).map_err(CliError::encode_json)?
                );
            }
        }
    }

    Ok(())
}

fn runtime_context(session_prefix: &str) -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new(format!("{session_prefix}-{}", std::process::id())),
        actor: ActorIdentity {
            id: String::from("erebor-runtime-cli"),
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

fn format_surfaces(
    surfaces: impl Iterator<Item = erebor_runtime_core::SessionSurfaceKind>,
) -> String {
    surfaces
        .map(erebor_runtime_core::SessionSurfaceKind::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_endpoints(runtimes: &[RunningSessionSurface]) -> String {
    runtimes
        .iter()
        .map(|runtime| format!("{}={}", runtime.surface().as_str(), runtime.endpoint()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfiguredAuditSink {
    Runtime(NoopAuditSink),
    Jsonl(JsonlAuditSink),
}

impl ConfiguredAuditSink {
    fn from_config(config: &RuntimeAuditConfig) -> Self {
        config.jsonl().map_or_else(
            || Self::Runtime(NoopAuditSink),
            |path| Self::Jsonl(JsonlAuditSink::new(path.to_path_buf())),
        )
    }
}

impl AuditSink for ConfiguredAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        match self {
            Self::Runtime(sink) => sink.record(record),
            Self::Jsonl(sink) => sink.record(record),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error("failed to read runtime config `{}`: {source}", path.display())]
    ReadConfig {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
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
    #[error("policy evaluation failed: {source}")]
    PolicyEvaluation {
        source: PolicyError,
        location: Location,
    },
    #[error("failed to read event `{}`: {source}", path.display())]
    ReadEvent {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("event fixture JSON is invalid: {source}")]
    InvalidEvent {
        source: serde_json::Error,
        location: Location,
    },
    #[error("{source}")]
    Runtime {
        source: RuntimeError,
        location: Location,
    },
    #[error("session command denied: {reason}")]
    SessionDenied { reason: String, location: Location },
    #[error("{source}")]
    AuditLog {
        source: AuditLogError,
        location: Location,
    },
    #[error("failed to encode JSON output: {source}")]
    EncodeJson {
        source: serde_json::Error,
        location: Location,
    },
}

impl CliError {
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
    fn policy_evaluation(source: PolicyError) -> Self {
        Self::PolicyEvaluation {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn invalid_event(source: serde_json::Error) -> Self {
        Self::InvalidEvent {
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
    fn session_denied(reason: impl Into<String>) -> Self {
        Self::SessionDenied {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn audit_log(source: AuditLogError) -> Self {
        Self::AuditLog {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn encode_json(source: serde_json::Error) -> Self {
        Self::EncodeJson {
            source,
            location: Location::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::{CommandFactory, Parser};
    use erebor_runtime_core::{RuntimeError, SessionSurfaceDefinition, SessionSurfaceKind};

    use super::{
        build_dev_proxy_launch_plan, build_runtime_launch_plan, build_session_diagnose_plan,
        build_session_run_plan, resolve_config_paths, Cli, CliError, ProxyCdpArgs,
        SessionDiagnoseArgs, SessionRunArgs, SessionRunnerArg, StartArgs, WebSocketUrl,
    };

    #[test]
    fn rejects_unknown_arguments() {
        let error = Cli::try_parse_from(["erebor-runtime", "start", "--unknown"]);

        assert!(error.is_err());
    }

    #[test]
    fn requires_config_for_runtime_start() {
        let error = Cli::try_parse_from(["erebor-runtime", "start"]);

        assert!(error.is_err());
    }

    #[test]
    fn accepts_single_runtime_command_with_config() {
        let cli = Cli::try_parse_from(["erebor-runtime", "start", "--config", "erebor.json"]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_run_with_runtime_config_and_command() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "run",
            "--runner",
            "docker",
            "--config",
            "pilot-session.json",
            "openclaw",
            "--help",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_diagnose_with_runtime_config_and_name() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "diagnose",
            "--runner",
            "docker",
            "--config",
            "pilot-session.json",
            "list-workspace",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_restrictive_global_log_level() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "--log-level",
            "debug",
            "start",
            "--config",
            "erebor.json",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn rejects_unknown_log_level() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "--log-level",
            "verbose",
            "start",
            "--config",
            "erebor.json",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn start_builds_surface_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
                  "listen": "127.0.0.1:3738"
                }
              }
            }
            "#,
        )?;
        let args = StartArgs {
            config: config_path.clone(),
            listen: "127.0.0.1:3737".parse()?,
        };

        let plan = build_runtime_launch_plan(&args)?;

        assert_eq!(plan.control_listen(), "127.0.0.1:3737".parse()?);
        assert_eq!(
            plan.policy_paths(),
            vec![config_path
                .parent()
                .ok_or_else(|| std::io::Error::other("missing config parent"))?
                .join("policies/browser.json")]
        );
        assert_eq!(plan.surfaces(), vec![SessionSurfaceKind::BrowserCdp]);
        let SessionSurfaceDefinition::BrowserCdp(browser_cdp) = &plan.definitions()[0];
        assert_eq!(browser_cdp.listen(), "127.0.0.1:3738".parse()?);
        assert_eq!(
            browser_cdp.browser_url(),
            Some("ws://127.0.0.1:9222/devtools/browser/demo")
        );

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn start_preserves_absolute_policy_paths() -> Result<(), Box<dyn std::error::Error>> {
        let absolute_policy_path =
            std::env::temp_dir().join(format!("erebor-runtime-policy-{}.json", std::process::id()));
        let config_path = write_temp_file(&format!(
            r#"
            {{
              "policies": ["{}"],
              "surfaces": {{
                "browser_cdp": {{
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }}
              }}
            }}
            "#,
            absolute_policy_path.display()
        ))?;
        let args = StartArgs {
            config: config_path.clone(),
            listen: "127.0.0.1:3737".parse()?,
        };

        let plan = build_runtime_launch_plan(&args)?;

        assert_eq!(plan.policy_paths(), vec![absolute_policy_path]);

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn session_run_builds_docker_session_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "audit": { "jsonl": "audit/pilot.jsonl" },
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "workspace": "workspace",
                "runner": {
                  "kind": "docker",
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              }
            }
            "#,
        )?;
        let args = SessionRunArgs {
            config: config_path.clone(),
            runner: SessionRunnerArg::Docker,
            command: vec![String::from("openclaw"), String::from("--help")],
        };

        let plan = build_session_run_plan(&args)?;
        let base_dir = config_path
            .parent()
            .ok_or_else(|| std::io::Error::other("missing config parent"))?;

        assert_eq!(plan.actor().id, "openclaw");
        assert_eq!(
            plan.policies(),
            vec![base_dir.join("policies/browser.json")].as_slice()
        );
        assert_eq!(
            plan.audit().jsonl(),
            Some(base_dir.join("audit/pilot.jsonl").as_path())
        );
        assert_eq!(plan.workspace(), Some(base_dir.join("workspace").as_path()));
        assert_eq!(
            plan.runner().docker().image(),
            "erebor/openclaw-pilot:local"
        );
        assert_eq!(plan.runner().docker().network(), "none");
        assert_eq!(plan.command(), ["openclaw", "--help"]);

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn relative_config_paths_resolve_from_absolute_config_base(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = erebor_runtime_core::RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policy.json"],
              "audit": { "jsonl": "pilot-audit.jsonl" },
              "session": {
                "enabled": true,
                "workspace": "../.."
              }
            }
            "#,
        )?;

        resolve_config_paths(
            std::path::Path::new("examples/governed-openclaw-pilot/session-config.json"),
            &mut config,
        );

        let current_dir = std::env::current_dir()?;
        assert_eq!(
            config.policies,
            vec![current_dir.join("examples/governed-openclaw-pilot/policy.json")]
        );
        assert_eq!(
            config.audit.jsonl,
            Some(current_dir.join("examples/governed-openclaw-pilot/pilot-audit.jsonl"))
        );
        assert_eq!(
            config.session.workspace,
            Some(current_dir.join("examples/governed-openclaw-pilot/../.."))
        );
        Ok(())
    }

    #[test]
    fn session_diagnose_builds_named_diagnostic_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "diagnostics": [
                  {
                    "name": "list-workspace",
                    "command": ["sh", "-lc", "ls -la /workspace | head"]
                  }
                ],
                "runner": {
                  "kind": "docker",
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "none",
                    "workdir": "/workspace"
                  }
                }
              }
            }
            "#,
        )?;
        let args = SessionDiagnoseArgs {
            config: config_path.clone(),
            runner: SessionRunnerArg::Docker,
            name: String::from("list-workspace"),
        };

        let plan = build_session_diagnose_plan(&args)?;

        assert_eq!(plan.actor().id, "openclaw");
        assert_eq!(plan.diagnostic(), Some("list-workspace"));
        assert_eq!(plan.command(), ["sh", "-lc", "ls -la /workspace | head"]);

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn dev_proxy_builds_the_same_surface_launch_plan_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let args = ProxyCdpArgs {
            browser_url: WebSocketUrl(String::from("ws://127.0.0.1:9222/devtools/browser/demo")),
            policy: PathBuf::from("policies/browser.json"),
            listen: "127.0.0.1:3738".parse()?,
        };

        let plan = build_dev_proxy_launch_plan(&args)?;

        assert_eq!(
            plan.policy_paths(),
            vec![PathBuf::from("policies/browser.json")]
        );
        assert_eq!(plan.surfaces(), vec![SessionSurfaceKind::BrowserCdp]);
        assert_eq!(plan.definitions().len(), 1);
        let SessionSurfaceDefinition::BrowserCdp(browser_cdp) = &plan.definitions()[0];
        assert_eq!(browser_cdp.listen(), "127.0.0.1:3738".parse()?);
        assert_eq!(
            browser_cdp.browser_url(),
            Some("ws://127.0.0.1:9222/devtools/browser/demo")
        );
        Ok(())
    }

    #[test]
    fn start_rejects_invalid_runtime_config() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": [],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        )?;
        let args = StartArgs {
            config: config_path.clone(),
            listen: "127.0.0.1:3737".parse()?,
        };

        assert!(build_runtime_launch_plan(&args).is_err());

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn start_rejects_unsupported_enabled_surfaces() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let args = StartArgs {
            config: config_path.clone(),
            listen: "127.0.0.1:3737".parse()?,
        };

        let error = build_runtime_launch_plan(&args);

        assert!(matches!(
            error,
            Err(CliError::Runtime {
                source: RuntimeError::UnsupportedSessionSurface { surface, .. },
                ..
            })
                if surface == "terminal"
        ));

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn rejects_non_websocket_cdp_url() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "dev",
            "proxy-cdp",
            "--browser-url",
            "http://localhost:9222",
            "--policy",
            "policy.json",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn rejects_non_local_cdp_websocket_url() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "dev",
            "proxy-cdp",
            "--browser-url",
            "wss://browser.example/ws",
            "--policy",
            "policy.json",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn accepts_policy_test_with_policy_and_event() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "policy",
            "test",
            "--policy",
            "policy.json",
            "--event",
            "event.json",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn audit_tail_rejects_invalid_jsonl() -> Result<(), Box<dyn std::error::Error>> {
        let audit_path = write_temp_file("{not-json}\n")?;
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "audit",
            "tail",
            "--file",
            audit_path.to_string_lossy().as_ref(),
        ])?;

        assert!(cli.execute().is_err());
        let _result = fs::remove_file(audit_path);
        Ok(())
    }

    #[test]
    fn clap_debug_assertions_pass() {
        Cli::command().debug_assert();
    }

    fn write_temp_file(source: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-cli-{nanos}-{}.json",
            std::process::id()
        ));

        fs::write(&path, source)?;

        Ok(path)
    }
}
