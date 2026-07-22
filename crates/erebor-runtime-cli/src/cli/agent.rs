use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use snafu::ResultExt;
use uuid::Uuid;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu};

use super::{parse_non_empty_path, parse_non_empty_string};

#[derive(Debug, Args)]
pub(super) struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

impl AgentArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            AgentCommand::Install(args) => format!(
                "agent install {} --from {}",
                args.package_reference,
                args.from.display()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Enroll a caller-provided Codex executable against a root-curated release.
    Install(AgentInstallArgs),
}

#[derive(Debug, Args)]
struct AgentInstallArgs {
    /// Exact root-curated package reference: NAME@sha256:LOWERCASE_DIGEST.
    #[arg(value_parser = parse_non_empty_string)]
    package_reference: String,
    /// Absolute path to the vendor-provided executable to enroll.
    #[arg(long, value_parser = parse_non_empty_path)]
    from: PathBuf,
}

pub(super) struct AgentCommandOwner<'a> {
    args: &'a AgentArgs,
}

impl<'a> AgentCommandOwner<'a> {
    pub(super) const fn new(args: &'a AgentArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            AgentCommand::Install(args) => {
                let response = runtime
                    .block_on(DaemonClient::local().agent_install_codex(
                        &args.package_reference,
                        args.from.display().to_string(),
                        &format!("agent-install-{}", Uuid::new_v4()),
                    ))
                    .context(DaemonClientSnafu)?;
                println!("package_digest={}", response.package_digest);
                println!("installation_digest={}", response.installation_digest);
                for alias in response.aliases {
                    println!("alias={alias}");
                }
                Ok(())
            }
        }
    }
}
