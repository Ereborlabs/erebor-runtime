use std::fmt;

use clap::{Parser, Subcommand};

use crate::{
    error::CliError,
    logging::{init_tracing, LoggingArgs},
};

mod agent;
mod approval;
mod audit;
pub(super) mod config_paths;
mod daemon;
mod filesystem;
mod parsers;
mod policy;
mod runner;
mod session;
mod start;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(super) use config_paths::ConfigPathResolver;
pub(super) use parsers::{parse_non_empty_path, parse_non_empty_string, OutputFormat};

#[derive(Debug, Parser)]
#[command(
    name = "erebor",
    version,
    about = "Zero-trust action governance runtime for AI agents",
    next_line_help = true
)]
pub struct Cli {
    #[command(flatten)]
    logging: LoggingArgs,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn execute(&self) -> Result<(), CliError> {
        init_tracing(&self.logging);
        tracing::debug!(command = %self.command, "executing command");

        match &self.command {
            Command::Start(args) => start::StartCommand::new(args).execute(),
            Command::Agent(args) => agent::AgentCommandOwner::new(args).execute(),
            Command::Run(args) => session::SessionCommandOwner::execute_codex_run(args),
            Command::Session(args) => session::SessionCommandOwner::new(args).execute(),
            Command::Policy(args) => policy::PolicyCommandOwner::new(args).execute(),
            Command::Runner(args) => runner::RunnerCommandOwner::new(args).execute(),
            Command::Audit(args) => audit::AuditCommandOwner::new(args).execute(),
            Command::Approval(args) => approval::ApprovalCommandOwner::new(args).execute(),
            Command::Filesystem(args) => filesystem::execute(args),
            Command::Daemon(args) => daemon::DaemonCommandOwner::new(args).execute(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the configured session surfaces.
    Start(start::StartArgs),
    /// Load a locally verified agent executable into the daemon-owned inventory.
    Agent(agent::AgentArgs),
    /// Create, start, and attach to one daemon-owned Codex session by local alias.
    Run(session::CodexRunArgs),
    /// Start or manage governed agent sessions.
    Session(session::SessionArgs),
    /// Policy development and validation commands.
    Policy(policy::PolicyArgs),
    /// Inspect the daemon's installed runner capability documents.
    Runner(runner::RunnerArgs),
    /// Audit log commands.
    Audit(audit::AuditArgs),
    /// Inspect or resolve durable effect approvals.
    Approval(approval::ApprovalArgs),
    /// Filesystem revert transaction commands.
    Filesystem(filesystem::FilesystemArgs),
    /// Inspect or administer the local Erebor daemon.
    Daemon(daemon::DaemonArgs),
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(args) => formatter.write_str(&args.display()),
            Self::Agent(args) => formatter.write_str(&args.display()),
            Self::Run(args) => formatter.write_str(&format!("run {}", args.alias)),
            Self::Session(args) => formatter.write_str(&args.display()),
            Self::Policy(args) => formatter.write_str(&args.display()),
            Self::Runner(args) => formatter.write_str(&args.display()),
            Self::Audit(args) => formatter.write_str(&args.display()),
            Self::Approval(args) => formatter.write_str(&args.display()),
            Self::Filesystem(args) => formatter.write_str(&args.display()),
            Self::Daemon(_) => formatter.write_str("daemon"),
        }
    }
}
