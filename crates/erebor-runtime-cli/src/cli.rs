use std::{
    fmt, fs, io,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use erebor_runtime_audit::{
    read_audit_records, render_session_describe_from_source, render_session_list_from_source,
    render_session_show_from_source, AuditLogError, EvidenceTraceError, EvidenceTracePaths,
    EvidenceTraceSink, FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer, SessionReviewError,
    SessionReviewOutputFormat, SessionReviewSourcePaths,
};
use erebor_runtime_core::{
    BrowserCdpSurfaceLayerConfig, RuntimeAuditConfig, RuntimeConfig, RuntimeConfigError,
    RuntimeError, SessionAdoptTarget, SessionRunPlan, SessionRunnerKind, SessionSurfaceLaunchPlan,
    SessionSurfaceLayers, SessionSurfaceStartPlan,
};
use erebor_runtime_events::{RuntimeEvent, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicyError, PolicyEvaluator, PolicySet};
use erebor_runtime_session::{
    adopt_session_target, run_session_diagnostic, run_session_plan, start_surface_launch_plan,
    SessionDiagnosticOutcome, SessionExecutionError,
};
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
            Self::Session(SessionArgs {
                command: SessionCommand::Adopt(args),
            }) => write!(
                formatter,
                "session adopt runner={} config={} target={}",
                args.runner.as_str(),
                args.config.display(),
                args.target_display()
            ),
            Self::Session(SessionArgs {
                command: SessionCommand::Ls(args),
            }) => write!(
                formatter,
                "session ls source={}",
                review_source_display(args.audit.as_ref(), &args.registry)
            ),
            Self::Session(SessionArgs {
                command: SessionCommand::Show(args),
            }) => write!(
                formatter,
                "session show session_id={} source={}",
                args.session_id,
                review_source_display(args.audit.as_ref(), &args.registry)
            ),
            Self::Session(SessionArgs {
                command: SessionCommand::Describe(args),
            }) => write!(
                formatter,
                "session describe session_id={} source={}",
                args.session_id,
                review_source_display(args.audit.as_ref(), &args.registry)
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
            Self::Audit(AuditArgs {
                command: AuditCommand::EvidenceTrace(args),
            }) => write!(
                formatter,
                "audit evidence-trace audit={} out={}",
                args.audit.display(),
                args.out
                    .as_ref()
                    .map_or_else(|| String::from("stdout"), |path| path.display().to_string())
            ),
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
    /// Start an agent inside a governed session runner.
    Run(SessionRunArgs),
    /// Run a named bounded diagnostic from the session config.
    Diagnose(SessionDiagnoseArgs),
    /// Adopt an already-running agent process into a governed session.
    Adopt(SessionAdoptArgs),
    /// List sessions present in an audit log.
    Ls(SessionLsArgs),
    /// Show a buyer-readable summary for one governed session.
    Show(SessionShowArgs),
    /// Describe governed session decisions with proof details.
    Describe(SessionDescribeArgs),
}

#[derive(Debug, Args)]
struct SessionRunArgs {
    /// Session config describing policies, audit, surfaces, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    runner: SessionRunnerArg,
    /// Agent entrypoint to launch inside the governed session runner.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct SessionLsArgs {
    /// JSONL audit log path. Omit to read the local session registry.
    #[arg(long, value_parser = parse_non_empty_path)]
    audit: Option<PathBuf>,
    /// Session registry root used when --audit is omitted.
    #[arg(long, value_parser = parse_non_empty_path, default_value = ".erebor/sessions")]
    registry: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct SessionShowArgs {
    /// Session id to show.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
    /// JSONL audit log path. Provide with --policy and --config for explicit artifact review.
    #[arg(long, value_parser = parse_non_empty_path)]
    audit: Option<PathBuf>,
    /// Policy file used by the governed session.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: Option<PathBuf>,
    /// Runtime/session config used by the governed session.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: Option<PathBuf>,
    /// Session registry root used when explicit artifacts are omitted.
    #[arg(long, value_parser = parse_non_empty_path, default_value = ".erebor/sessions")]
    registry: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct SessionDescribeArgs {
    /// Session id to describe.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
    /// JSONL audit log path. Provide with --policy and --config for explicit artifact review.
    #[arg(long, value_parser = parse_non_empty_path)]
    audit: Option<PathBuf>,
    /// Policy file used by the governed session.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: Option<PathBuf>,
    /// Runtime/session config used by the governed session.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: Option<PathBuf>,
    /// Session registry root used when explicit artifacts are omitted.
    #[arg(long, value_parser = parse_non_empty_path, default_value = ".erebor/sessions")]
    registry: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
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

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("adopt_target")
        .required(true)
        .args(["pid", "match_pattern"])
))]
struct SessionAdoptArgs {
    /// Session config describing policies, audit, surfaces, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    runner: SessionRunnerArg,
    /// Already-running process id to attach to.
    #[arg(long, value_parser = parse_positive_pid)]
    pid: Option<i32>,
    /// Find one already-running process whose executable or command line contains this text.
    #[arg(long = "match", value_name = "TEXT", value_parser = parse_non_empty_string)]
    match_pattern: Option<String>,
}

impl SessionAdoptArgs {
    fn target_display(&self) -> String {
        self.target().display_target()
    }

    fn target(&self) -> SessionAdoptTarget {
        match (self.pid, self.match_pattern.as_deref()) {
            (Some(pid), None) => SessionAdoptTarget::pid(pid),
            (None, Some(pattern)) => SessionAdoptTarget::process_match(pattern),
            _ => unreachable!("clap enforces exactly one session adoption target"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SessionRunnerArg {
    Docker,
    LinuxHost,
}

impl SessionRunnerArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::LinuxHost => "linux-host",
        }
    }
}

impl From<SessionRunnerArg> for SessionRunnerKind {
    fn from(value: SessionRunnerArg) -> Self {
        match value {
            SessionRunnerArg::Docker => Self::Docker,
            SessionRunnerArg::LinuxHost => Self::LinuxHost,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

impl From<OutputFormat> for SessionReviewOutputFormat {
    fn from(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Text => Self::Text,
            OutputFormat::Json => Self::Json,
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
    /// Render a DPO-readable evidence trace from a governed session audit.
    EvidenceTrace(AuditEvidenceTraceArgs),
}

#[derive(Debug, Args)]
struct AuditTailArgs {
    /// JSONL audit log path.
    #[arg(long, value_parser = parse_non_empty_path)]
    file: PathBuf,
}

#[derive(Debug, Args)]
struct AuditEvidenceTraceArgs {
    /// JSONL audit log path.
    #[arg(long, value_parser = parse_non_empty_path)]
    audit: PathBuf,
    /// Policy file used by the governed run.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Session/runtime config used by the governed run.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Prompt artifact used by the governed run.
    #[arg(long, value_parser = parse_non_empty_path)]
    prompt: Option<PathBuf>,
    /// Markdown report output path. Omit to print to stdout.
    #[arg(long, value_parser = parse_non_empty_path)]
    out: Option<PathBuf>,
    /// Session id to render. Defaults to the latest session with browser and denied evidence.
    #[arg(long, value_parser = parse_non_empty_string)]
    session_id: Option<String>,
    /// Plain-language purpose for this governed session.
    #[arg(
        long,
        default_value = "OpenClaw support investigation of a local OAuth callback reproduction under Erebor governance."
    )]
    purpose: String,
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

fn parse_non_empty_string(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(String::from("value cannot be empty"))
    } else {
        Ok(value.to_owned())
    }
}

fn parse_positive_pid(value: &str) -> Result<i32, String> {
    let pid = value
        .parse::<i32>()
        .map_err(|_| String::from("pid must be a positive process id"))?;
    if pid <= 0 {
        Err(String::from("pid must be a positive process id"))
    } else {
        Ok(pid)
    }
}

fn review_source_display(audit: Option<&PathBuf>, registry: &Path) -> String {
    audit.map_or_else(
        || format!("registry:{}", registry.display()),
        |path| format!("audit:{}", path.display()),
    )
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
                policies: Vec::new(),
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
    for policy in &mut config.surfaces.browser_cdp.policies {
        resolve_config_path(base_dir, policy);
    }
    for policy in &mut config.surfaces.terminal.policies {
        resolve_config_path(base_dir, policy);
    }
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
        SessionCommand::Adopt(args) => session_adopt(args),
        SessionCommand::Ls(args) => session_ls(args),
        SessionCommand::Show(args) => session_show(args),
        SessionCommand::Describe(args) => session_describe(args),
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
    .map_err(CliError::invalid_config)?
    .with_config_path(args.config.clone());
    execute_session_run_plan(&config, &plan)
}

fn session_diagnose(args: &SessionDiagnoseArgs) -> Result<(), CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    let plan = SessionRunPlan::from_diagnostic(&config, args.runner.into(), session_id, &args.name)
        .map_err(CliError::invalid_config)?
        .with_config_path(args.config.clone());
    execute_session_diagnostic_plan(&config, &plan)
}

fn session_adopt(args: &SessionAdoptArgs) -> Result<(), CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    adopt_session_target(&config, args.runner.into(), session_id, args.target())
        .map_err(CliError::session_execution)?;
    Ok(())
}

fn session_ls(args: &SessionLsArgs) -> Result<(), CliError> {
    let source = SessionReviewSourcePaths {
        audit: args.audit.clone(),
        registry: args.registry.clone(),
        ..SessionReviewSourcePaths::default()
    };
    let output = render_session_list_from_source(&source, args.format.into())
        .map_err(CliError::session_review)?;
    print!("{output}");
    Ok(())
}

fn session_show(args: &SessionShowArgs) -> Result<(), CliError> {
    let source = SessionReviewSourcePaths {
        audit: args.audit.clone(),
        policy: args.policy.clone(),
        config: args.config.clone(),
        registry: args.registry.clone(),
    };
    let output = render_session_show_from_source(&source, &args.session_id, args.format.into())
        .map_err(CliError::session_review)?;
    print!("{output}");
    Ok(())
}

fn session_describe(args: &SessionDescribeArgs) -> Result<(), CliError> {
    let source = SessionReviewSourcePaths {
        audit: args.audit.clone(),
        policy: args.policy.clone(),
        config: args.config.clone(),
        registry: args.registry.clone(),
    };
    let output = render_session_describe_from_source(&source, &args.session_id, args.format.into())
        .map_err(CliError::session_review)?;
    print!("{output}");
    Ok(())
}

fn execute_session_run_plan(config: &RuntimeConfig, plan: &SessionRunPlan) -> Result<(), CliError> {
    run_session_plan(config, plan).map_err(CliError::session_execution)?;
    Ok(())
}

fn execute_session_diagnostic_plan(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<(), CliError> {
    let outcome = run_session_diagnostic(config, plan).map_err(CliError::session_execution)?;
    write_session_diagnostic_outcome(&outcome)
}

fn write_session_diagnostic_outcome(outcome: &SessionDiagnosticOutcome) -> Result<(), CliError> {
    if !outcome.stdout().is_empty() {
        io::stdout()
            .write_all(outcome.stdout().as_bytes())
            .map_err(CliError::write_session_output)?;
    }
    if !outcome.stderr().is_empty() {
        io::stderr()
            .write_all(outcome.stderr().as_bytes())
            .map_err(CliError::write_session_output)?;
    }

    Ok(())
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
    .map(|plan| plan.with_config_path(args.config.clone()))
    .map_err(CliError::invalid_config)
}

#[cfg(test)]
fn build_session_diagnose_plan(args: &SessionDiagnoseArgs) -> Result<SessionRunPlan, CliError> {
    let config = read_runtime_config(&args.config)?;
    let session_id = SessionId::new(format!("session-{}", std::process::id()));
    SessionRunPlan::from_diagnostic(&config, args.runner.into(), session_id, &args.name)
        .map(|plan| plan.with_config_path(args.config.clone()))
        .map_err(CliError::invalid_config)
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
    start_surface_launch_plan(launch_plan).map_err(CliError::session_execution)
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
        AuditCommand::EvidenceTrace(args) => {
            tracing::debug!(
                audit = %args.audit.display(),
                policy = %args.policy.display(),
                config = %args.config.display(),
                "rendering evidence trace"
            );
            let request =
                erebor_runtime_audit::EvidenceTraceRequest::from_paths(EvidenceTracePaths {
                    audit: args.audit.clone(),
                    policy: args.policy.clone(),
                    config: args.config.clone(),
                    prompt: args.prompt.clone(),
                    session_id: args.session_id.clone(),
                    purpose: args.purpose.clone(),
                })
                .map_err(CliError::evidence_trace)?;
            let report = MarkdownEvidenceTraceRenderer
                .render(&request)
                .map_err(CliError::evidence_trace)?;

            if let Some(out) = args.out.as_ref() {
                let sink = FileEvidenceTraceSink::new(out);
                let receipt = sink.send(&report).map_err(CliError::evidence_trace)?;
                println!(
                    "evidence_trace={} sha256={}",
                    receipt.destination(),
                    receipt.report_sha256()
                );
            } else {
                print!("{}", report.markdown());
            }
        }
    }

    Ok(())
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
    #[error("{source}")]
    SessionExecution {
        source: Box<SessionExecutionError>,
        location: Location,
    },
    #[error("failed to write session diagnostic output: {source}")]
    WriteSessionOutput {
        source: io::Error,
        location: Location,
    },
    #[error("{source}")]
    AuditLog {
        source: AuditLogError,
        location: Location,
    },
    #[error("{source}")]
    EvidenceTrace {
        source: EvidenceTraceError,
        location: Location,
    },
    #[error("{source}")]
    SessionReview {
        source: Box<SessionReviewError>,
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
    fn session_execution(source: SessionExecutionError) -> Self {
        Self::SessionExecution {
            source: Box::new(source),
            location: Location::default(),
        }
    }

    #[track_caller]
    fn write_session_output(source: io::Error) -> Self {
        Self::WriteSessionOutput {
            source,
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
    fn evidence_trace(source: EvidenceTraceError) -> Self {
        Self::EvidenceTrace {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    fn session_review(source: SessionReviewError) -> Self {
        Self::SessionReview {
            source: Box::new(source),
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
    use erebor_runtime_core::{SessionAdoptTarget, SessionSurfaceDefinition, SessionSurfaceKind};

    use super::{
        build_dev_proxy_launch_plan, build_runtime_launch_plan, build_session_diagnose_plan,
        build_session_run_plan, resolve_config_paths, Cli, ProxyCdpArgs, SessionAdoptArgs,
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
    fn accepts_session_run_with_linux_host_runner() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "run",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
            "openclaw",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn rejects_session_run_tty_flag() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "run",
            "--runner",
            "docker",
            "--tty",
            "--config",
            "pilot-session.json",
            "openclaw",
        ]);

        assert!(error.is_err());
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
    fn accepts_session_adopt_with_linux_host_runner_and_pid() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "adopt",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
            "--pid",
            "1234",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_adopt_with_linux_host_runner_and_match() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "adopt",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
            "--match",
            "openclaw",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_ls_with_audit() {
        let cli =
            Cli::try_parse_from(["erebor-runtime", "session", "ls", "--audit", "audit.jsonl"]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_ls_without_audit_for_registry_mode() {
        let cli = Cli::try_parse_from(["erebor-runtime", "session", "ls"]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_show_with_audit_policy_config() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "show",
            "session-1",
            "--audit",
            "audit.jsonl",
            "--policy",
            "policy.json",
            "--config",
            "session-config.json",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_show_without_artifacts_for_registry_mode() {
        let cli = Cli::try_parse_from(["erebor-runtime", "session", "show", "session-1"]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_describe_with_audit_policy_config() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "describe",
            "session-1",
            "--audit",
            "audit.jsonl",
            "--policy",
            "policy.json",
            "--config",
            "session-config.json",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_describe_without_artifacts_for_registry_mode() {
        let cli = Cli::try_parse_from(["erebor-runtime", "session", "describe", "session-1"]);

        assert!(cli.is_ok());
    }

    #[test]
    fn accepts_session_review_json_format() {
        let ls = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "ls",
            "--audit",
            "audit.jsonl",
            "--format",
            "json",
        ]);
        let show = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "show",
            "session-1",
            "--audit",
            "audit.jsonl",
            "--policy",
            "policy.json",
            "--config",
            "session-config.json",
            "--format",
            "json",
        ]);
        let describe = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "describe",
            "session-1",
            "--audit",
            "audit.jsonl",
            "--policy",
            "policy.json",
            "--config",
            "session-config.json",
            "--format",
            "json",
        ]);

        assert!(ls.is_ok());
        assert!(show.is_ok());
        assert!(describe.is_ok());
    }

    #[test]
    fn accepts_incomplete_explicit_session_review_flags_for_domain_validation() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "show",
            "session-1",
            "--audit",
            "audit.jsonl",
        ]);

        assert!(cli.is_ok());
    }

    #[test]
    fn rejects_session_adopt_with_multiple_targets() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "adopt",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
            "--pid",
            "1234",
            "--match",
            "openclaw",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn rejects_session_adopt_without_target() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "adopt",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn rejects_session_adopt_with_invalid_pid() {
        let error = Cli::try_parse_from([
            "erebor-runtime",
            "session",
            "adopt",
            "--runner",
            "linux-host",
            "--config",
            "pilot-session.json",
            "--pid",
            "0",
        ]);

        assert!(error.is_err());
    }

    #[test]
    fn session_adopt_args_translate_to_service_target() {
        let args = SessionAdoptArgs {
            config: PathBuf::from("pilot-session.json"),
            runner: SessionRunnerArg::LinuxHost,
            pid: None,
            match_pattern: Some(String::from("openclaw")),
        };

        assert_eq!(args.target(), SessionAdoptTarget::process_match("openclaw"));
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
        let browser_cdp = match &plan.definitions()[0] {
            SessionSurfaceDefinition::BrowserCdp(browser_cdp) => browser_cdp,
            SessionSurfaceDefinition::Terminal(_) => {
                return Err(std::io::Error::other("expected browser CDP surface").into());
            }
        };
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
              },
              "surfaces": {
                "terminal": { "enabled": true, "tty": true }
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
        assert!(plan.terminal().tty());
        assert_eq!(plan.command(), ["openclaw", "--help"]);

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn session_run_builds_linux_host_session_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "workspace": "workspace",
                "runner": {
                  "kind": "linux_host"
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let args = SessionRunArgs {
            config: config_path.clone(),
            runner: SessionRunnerArg::LinuxHost,
            command: vec![String::from("openclaw")],
        };

        let plan = build_session_run_plan(&args)?;
        let base_dir = config_path
            .parent()
            .ok_or_else(|| std::io::Error::other("missing config parent"))?;

        assert_eq!(plan.actor().id, "openclaw");
        assert_eq!(
            plan.runner().kind(),
            erebor_runtime_core::SessionRunnerKind::LinuxHost
        );
        assert_eq!(plan.workspace(), Some(base_dir.join("workspace").as_path()));
        assert_eq!(plan.command(), ["openclaw"]);

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
              },
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "policies": ["browser-policy.json"]
                },
                "terminal": {
                  "enabled": true,
                  "policies": ["terminal-policy.json"]
                }
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
        assert_eq!(
            config.session.registry_path,
            PathBuf::from(".erebor/sessions")
        );
        assert_eq!(
            config.surfaces.browser_cdp.policies,
            vec![current_dir.join("examples/governed-openclaw-pilot/browser-policy.json")]
        );
        assert_eq!(
            config.surfaces.terminal.policies,
            vec![current_dir.join("examples/governed-openclaw-pilot/terminal-policy.json")]
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
              },
              "surfaces": {
                "terminal": { "enabled": true }
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
        let browser_cdp = match &plan.definitions()[0] {
            SessionSurfaceDefinition::BrowserCdp(browser_cdp) => browser_cdp,
            SessionSurfaceDefinition::Terminal(_) => {
                return Err(std::io::Error::other("expected browser CDP surface").into());
            }
        };
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
    fn start_builds_terminal_surface_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
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

        let plan = build_runtime_launch_plan(&args)?;

        assert_eq!(
            plan.surfaces(),
            vec![SessionSurfaceKind::BrowserCdp, SessionSurfaceKind::Terminal]
        );
        assert_eq!(plan.definitions().len(), 2);
        assert!(matches!(
            plan.definitions()[1],
            SessionSurfaceDefinition::Terminal(_)
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
    fn accepts_audit_evidence_trace_command() {
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "audit",
            "evidence-trace",
            "--audit",
            "audit.jsonl",
            "--policy",
            "policy.json",
            "--config",
            "session-config.json",
            "--prompt",
            "prompt.txt",
            "--out",
            "evidence-trace.md",
        ]);

        assert!(cli.is_ok());
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
