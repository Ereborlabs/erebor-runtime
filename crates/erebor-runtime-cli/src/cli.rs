use std::{
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand};
use erebor_runtime_core::{GovernanceLayer, RuntimeConfig, RuntimeConfigError};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "erebor-runtime",
    version,
    about = "Zero-trust action governance runtime for AI agents",
    next_line_help = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub(crate) fn execute(&self) -> Result<(), CliError> {
        match &self.command {
            Command::Start(args) => {
                let config = read_runtime_config(&args.config)?;
                println!(
                    "start config={} listen={} governance={}",
                    args.config.display(),
                    args.listen,
                    format_layers(&config.enabled_layers())
                );
            }
            _ => println!("{}", self.command),
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
                    "dev proxy-cdp policy={} browser-url={}",
                    args.policy.display(),
                    args.browser_url.as_str()
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
    /// Existing Chromium browser websocket URL.
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
    if value.starts_with("ws://") || value.starts_with("wss://") {
        Ok(WebSocketUrl(value.to_owned()))
    } else {
        Err(String::from("must start with ws:// or wss://"))
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
    let source = fs::read_to_string(path).map_err(|error| CliError::ReadConfig {
        path: path.to_path_buf(),
        source: error,
    })?;

    RuntimeConfig::from_json_str(&source).map_err(CliError::InvalidConfig)
}

fn format_layers(layers: &[GovernanceLayer]) -> String {
    layers
        .iter()
        .map(|layer| layer.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error("failed to read runtime config `{}`: {source}", path.display())]
    ReadConfig { path: PathBuf, source: io::Error },
    #[error("{0}")]
    InvalidConfig(#[from] RuntimeConfigError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::{CommandFactory, Parser};

    use super::Cli;

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
    fn start_loads_runtime_config() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_config(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": { "enabled": true },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "start",
            "--config",
            config_path.to_string_lossy().as_ref(),
        ])?;

        cli.execute()?;

        Ok(())
    }

    #[test]
    fn start_rejects_invalid_runtime_config() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = write_temp_config(
            r#"
            {
              "policies": [],
              "governance": {
                "browser_cdp": { "enabled": true }
              }
            }
            "#,
        )?;
        let cli = Cli::try_parse_from([
            "erebor-runtime",
            "start",
            "--config",
            config_path.to_string_lossy().as_ref(),
        ])?;

        assert!(cli.execute().is_err());

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
    fn clap_debug_assertions_pass() {
        Cli::command().debug_assert();
    }

    fn write_temp_config(source: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-cli-{nanos}-{}.json",
            std::process::id()
        ));

        fs::write(&path, source)?;

        Ok(path)
    }
}
