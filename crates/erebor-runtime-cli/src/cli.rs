use std::{
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Args, Parser, Subcommand};
use erebor_runtime_audit::{read_audit_records, AuditLogError};
use erebor_runtime_cdp::{BrowserCdpRuntime, CdpSessionContext};
use erebor_runtime_core::{
    BrowserCdpLayerConfig, GovernanceLayers, RunningRuntime, RuntimeConfig, RuntimeConfigError,
    RuntimeDefinition, RuntimeError, RuntimeLaunchPlan, RuntimeLauncher, RuntimeStartPlan,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, RuntimeEvent, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicyError, PolicyEvaluator, PolicySet};
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
            Command::Dev(args) => execute_dev(args)?,
            Command::Policy(args) => execute_policy(args)?,
            Command::Audit(args) => execute_audit(args)?,
        }

        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the configured governance runtime.
    Start(StartArgs),
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
    /// Runtime config describing enabled governance layers and policies.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Local address for runtime control/status APIs.
    #[arg(long, default_value = "127.0.0.1:3737")]
    listen: SocketAddr,
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

    RuntimeConfig::from_json_str(&source).map_err(CliError::invalid_config)
}

fn build_start_plan(path: &Path) -> Result<RuntimeStartPlan, CliError> {
    read_runtime_config(path)?
        .start_plan()
        .map_err(CliError::invalid_config)
}

fn build_runtime_launch_plan(args: &StartArgs) -> Result<RuntimeLaunchPlan, CliError> {
    let plan = build_start_plan(&args.config)?;
    tracing::debug!(
        control_listen = %args.listen,
        layers = ?plan.layers(),
        policy_count = plan.policies().len(),
        "building runtime launch plan"
    );
    RuntimeLaunchPlan::from_start_plan(args.listen, &plan).map_err(CliError::runtime)
}

fn build_dev_proxy_launch_plan(args: &ProxyCdpArgs) -> Result<RuntimeLaunchPlan, CliError> {
    let config = RuntimeConfig {
        policies: vec![args.policy.clone()],
        governance: GovernanceLayers {
            browser_cdp: BrowserCdpLayerConfig {
                enabled: true,
                browser_url: Some(args.browser_url.as_str().to_owned()),
                listen: args.listen,
                browser: Default::default(),
            },
            ..GovernanceLayers::default()
        },
    };
    let plan = config.start_plan().map_err(CliError::invalid_config)?;

    RuntimeLaunchPlan::from_start_plan(args.listen, &plan).map_err(CliError::runtime)
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

fn execute_dev(args: &DevArgs) -> Result<(), CliError> {
    match &args.command {
        DevCommand::ProxyCdp(args) => {
            let launch_plan = build_dev_proxy_launch_plan(args)?;
            start_runtime_from_launch_plan(launch_plan)
        }
    }
}

fn start_runtime_from_launch_plan(launch_plan: RuntimeLaunchPlan) -> Result<(), CliError> {
    let policy_set = read_policy_set(launch_plan.policy_paths())?;
    let mut launcher = RuntimeLauncher::new(launch_plan.control_listen());

    for definition in launch_plan.definitions() {
        match definition {
            RuntimeDefinition::BrowserCdp(config) => {
                launcher.add_runtime(BrowserCdpRuntime::new(
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
        governance = %format_layers(supervisor.running().iter().map(RunningRuntime::layer)),
        endpoints = %format_endpoints(supervisor.running()),
        "governance runtime started"
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

fn format_layers(layers: impl Iterator<Item = erebor_runtime_core::GovernanceLayer>) -> String {
    layers
        .map(erebor_runtime_core::GovernanceLayer::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_endpoints(runtimes: &[RunningRuntime]) -> String {
    runtimes
        .iter()
        .map(|runtime| format!("{}={}", runtime.layer().as_str(), runtime.endpoint()))
        .collect::<Vec<_>>()
        .join(" ")
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
    use erebor_runtime_core::{GovernanceLayer, RuntimeDefinition, RuntimeError};

    use super::{
        build_dev_proxy_launch_plan, build_runtime_launch_plan, Cli, CliError, ProxyCdpArgs,
        StartArgs, WebSocketUrl,
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
    fn start_builds_runtime_launch_plan() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
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
            vec![PathBuf::from("policies/browser.json")]
        );
        assert_eq!(plan.layers(), vec![GovernanceLayer::BrowserCdp]);
        let RuntimeDefinition::BrowserCdp(browser_cdp) = &plan.definitions()[0];
        assert_eq!(browser_cdp.listen(), "127.0.0.1:3738".parse()?);
        assert_eq!(
            browser_cdp.browser_url(),
            Some("ws://127.0.0.1:9222/devtools/browser/demo")
        );

        let _result = fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn dev_proxy_builds_the_same_runtime_launch_plan_shape(
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
        assert_eq!(plan.layers(), vec![GovernanceLayer::BrowserCdp]);
        assert_eq!(plan.definitions().len(), 1);
        let RuntimeDefinition::BrowserCdp(browser_cdp) = &plan.definitions()[0];
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
              "governance": {
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
    fn start_rejects_unsupported_enabled_layers() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_file(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
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
                source: RuntimeError::UnsupportedGovernanceLayer { layer, .. },
                ..
            })
                if layer == "terminal"
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
