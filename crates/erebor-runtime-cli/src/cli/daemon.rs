use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu};

#[derive(Debug, Args)]
pub(super) struct DaemonArgs {
    #[command(subcommand)]
    command: DaemonCommand,
}

pub(super) struct DaemonCommandOwner<'a> {
    args: &'a DaemonArgs,
}

impl<'a> DaemonCommandOwner<'a> {
    pub(super) fn new(args: &'a DaemonArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        runtime.block_on(self.execute_async())
    }

    async fn execute_async(&self) -> Result<(), CliError> {
        let client = DaemonClient::local();
        match &self.args.command {
            DaemonCommand::Status => {
                let status = client.status().await.context(DaemonClientSnafu)?;
                println!(
                    "daemon_pid={} configuration_generation={} state={}",
                    status.daemon_pid, status.configuration_generation, status.service_state
                );
            }
            DaemonCommand::Logs(args) => {
                let records = client
                    .logs(args.after_sequence, args.maximum_records)
                    .await
                    .context(DaemonClientSnafu)?;
                for record in records {
                    println!(
                        "sequence={} timestamp={} level={} message={}",
                        record.sequence, record.timestamp, record.level, record.message
                    );
                }
            }
            DaemonCommand::Reload(args) => {
                let message = client
                    .reload(&args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?;
                println!("{message}");
            }
            DaemonCommand::Stop(args) => {
                let message = client
                    .stop(&args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?;
                println!("{message}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Report the daemon's sanitized control-plane status.
    Status,
    /// Read a bounded stream of daemon operational records (root only).
    Logs(LogsArgs),
    /// Transactionally reload root-owned daemon configuration (root only).
    Reload(MutationArgs),
    /// Gracefully stop the daemon (root only).
    Stop(MutationArgs),
}

#[derive(Debug, Args)]
struct LogsArgs {
    /// Return records strictly after this sequence number.
    #[arg(long, default_value_t = 0)]
    after_sequence: u64,
    /// Maximum records to return before the daemon ends the stream.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
    maximum_records: u32,
}

#[derive(Debug, Args)]
struct MutationArgs {
    /// Stable key reused only when retrying the same operation after an uncertain result.
    #[arg(long, value_parser = non_empty_idempotency_key)]
    idempotency_key: String,
}

fn non_empty_idempotency_key(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(String::from("idempotency key must not be empty"));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn daemon_commands_share_the_erebor_root_command_tree() {
        assert!(Cli::try_parse_from(["erebor", "daemon", "status"]).is_ok());
        assert!(Cli::try_parse_from([
            "erebor",
            "daemon",
            "--socket",
            "/tmp/daemon.sock",
            "status"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["erebor", "status"]).is_err());
        assert!(Cli::try_parse_from([
            "erebor",
            "daemon",
            "reload",
            "--idempotency-key",
            "retry-1",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["erebor", "session", "run"]).is_err());
    }
}
