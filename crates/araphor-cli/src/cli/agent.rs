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
            AgentCommand::Load(args) => format!(
                "agent load {} --from {} --adapter {} --name {}",
                args.package_name,
                args.from.display(),
                args.adapter,
                args.name,
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Load a caller-provided Codex executable into the verified local agent inventory.
    Load(AgentLoadArgs),
}

#[derive(Debug, Args)]
struct AgentLoadArgs {
    /// Name of the root-curated AgentPackage to enroll.
    #[arg(value_parser = parse_non_empty_string)]
    package_name: String,
    /// Absolute path to the vendor-provided executable to enroll.
    #[arg(long, value_parser = parse_non_empty_path)]
    from: PathBuf,
    /// Adapter selected by the AgentPackage. It is required so enrollment never guesses.
    #[arg(long, value_parser = parse_non_empty_string)]
    adapter: String,
    /// Immutable owner-scoped name for the enrolled Agent.
    #[arg(long, value_parser = parse_non_empty_string)]
    name: String,
}

pub(super) struct AgentCommandOwner<'a> {
    args: &'a AgentArgs,
    client: &'a DaemonClient,
}

impl<'a> AgentCommandOwner<'a> {
    pub(super) const fn new(args: &'a AgentArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            AgentCommand::Load(args) => {
                let response = runtime
                    .block_on(self.client.agent_load_codex(
                        &args.package_name,
                        args.from.display().to_string(),
                        &args.name,
                        &args.adapter,
                        &format!("agent-load-{}", Uuid::new_v4()),
                    ))
                    .context(DaemonClientSnafu)?;
                println!("agent={}", response.name);
                Ok(())
            }
        }
    }
}
