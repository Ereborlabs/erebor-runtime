use clap::{Args, Subcommand};
use erebor_runtime_client::{DaemonClient, RunnerCapability};
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu, EncodeJsonSnafu};

use super::parse_non_empty_string;

#[derive(Debug, Args)]
pub(super) struct RunnerArgs {
    #[command(subcommand)]
    command: RunnerCommand,
}

impl RunnerArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            RunnerCommand::Ls => String::from("runner ls"),
            RunnerCommand::Inspect(args) => format!("runner inspect {}", args.runner_id),
        }
    }
}

#[derive(Debug, Subcommand)]
enum RunnerCommand {
    /// List compiled daemon runners and their current availability.
    Ls,
    /// Render one exact versioned capability document.
    Inspect(RunnerInspectArgs),
}

#[derive(Debug, Args)]
struct RunnerInspectArgs {
    #[arg(value_parser = parse_non_empty_string)]
    runner_id: String,
}

pub(super) struct RunnerCommandOwner<'a> {
    args: &'a RunnerArgs,
    client: &'a DaemonClient,
}

impl<'a> RunnerCommandOwner<'a> {
    pub(super) const fn new(args: &'a RunnerArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            RunnerCommand::Ls => runtime
                .block_on(self.client.runner_list())
                .context(DaemonClientSnafu)?
                .iter()
                .try_for_each(Self::write),
            RunnerCommand::Inspect(args) => {
                let report = runtime
                    .block_on(self.client.runner_inspect(&args.runner_id))
                    .context(DaemonClientSnafu)?;
                Self::write(&report)
            }
        }
    }

    fn write(report: &RunnerCapability) -> Result<(), CliError> {
        println!(
            "available={} unavailable_reason={} capability={}",
            report.available,
            report.unavailable_reason.as_deref().unwrap_or_default(),
            serde_json::to_string(&report.document).context(EncodeJsonSnafu)?,
        );
        Ok(())
    }
}
