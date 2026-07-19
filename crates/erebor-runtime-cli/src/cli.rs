use std::fmt;

use clap::{Parser, Subcommand};

use crate::{
    error::CliError,
    logging::{init_tracing, LoggingArgs},
};

mod audit;
pub(super) mod config_paths;
mod daemon;
mod dev;
mod filesystem;
mod parsers;
mod policy;
mod session;
mod start;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub(super) use config_paths::ConfigPathResolver;
pub(super) use parsers::{
    parse_non_empty_path, parse_non_empty_string, parse_positive_pid, parse_ws_url, OutputFormat,
    WebSocketUrl,
};

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
            Command::Session(args) => session::SessionCommandOwner::new(args).execute(),
            Command::Dev(args) => dev::DevCommandOwner::new(args).execute(),
            Command::Policy(args) => policy::PolicyCommandOwner::new(args).execute(),
            Command::Audit(args) => audit::AuditCommandOwner::new(args).execute(),
            Command::Filesystem(args) => filesystem::execute(args),
            Command::Daemon(args) => daemon::DaemonCommandOwner::new(args).execute(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the configured session surfaces.
    Start(start::StartArgs),
    /// Start or manage governed agent sessions.
    Session(session::SessionArgs),
    /// Development and surface-specific utilities.
    Dev(dev::DevArgs),
    /// Policy development and validation commands.
    Policy(policy::PolicyArgs),
    /// Audit log commands.
    Audit(audit::AuditArgs),
    /// Filesystem revert transaction commands.
    Filesystem(filesystem::FilesystemArgs),
    /// Inspect or administer the local Erebor daemon.
    Daemon(daemon::DaemonArgs),
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(args) => formatter.write_str(&args.display()),
            Self::Session(args) => formatter.write_str(&args.display()),
            Self::Dev(args) => formatter.write_str(&args.display()),
            Self::Policy(args) => formatter.write_str(&args.display()),
            Self::Audit(args) => formatter.write_str(&args.display()),
            Self::Filesystem(args) => formatter.write_str(&args.display()),
            Self::Daemon(_) => formatter.write_str("daemon"),
        }
    }
}
