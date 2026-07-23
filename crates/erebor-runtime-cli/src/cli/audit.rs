use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu};

use super::parse_non_empty_string;

#[derive(Debug, Args)]
pub(super) struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

impl AuditArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            AuditCommand::Tail(args) => format!("audit tail session_id={}", args.session_id),
            AuditCommand::EvidenceTrace(args) => {
                format!("audit evidence-trace session_id={}", args.session_id)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Print raw audit records for a governed session.
    Tail(AuditTailArgs),
    /// Print durable daemon-owned evidence records for a governed session.
    EvidenceTrace(AuditEvidenceTraceArgs),
}

#[derive(Debug, Args)]
struct AuditTailArgs {
    /// Session id, local alias, or unique prefix in the caller's daemon namespace.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
    /// Return records strictly after this durable cursor.
    #[arg(long, default_value_t = 0)]
    after_sequence: u64,
    /// Bound the result page before it leaves the daemon.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    maximum_records: u32,
}

#[derive(Debug, Args)]
struct AuditEvidenceTraceArgs {
    /// Session id, local alias, or unique prefix in the caller's daemon namespace.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
    /// Return records strictly after this durable cursor.
    #[arg(long, default_value_t = 0)]
    after_sequence: u64,
    /// Bound the result page before it leaves the daemon.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    maximum_records: u32,
}

pub(super) struct AuditCommandOwner<'a> {
    args: &'a AuditArgs,
    client: &'a DaemonClient,
}

impl<'a> AuditCommandOwner<'a> {
    pub(super) const fn new(args: &'a AuditArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            AuditCommand::Tail(args) => AuditTailCommand::new(args, self.client).execute(),
            AuditCommand::EvidenceTrace(args) => {
                AuditEvidenceTraceCommand::new(args, self.client).execute()
            }
        }
    }
}

struct AuditTailCommand<'a> {
    args: &'a AuditTailArgs,
    client: &'a DaemonClient,
}

impl<'a> AuditTailCommand<'a> {
    const fn new(args: &'a AuditTailArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let page = runtime
            .block_on(self.client.session_events(
                &self.args.session_id,
                self.args.after_sequence,
                self.args.maximum_records,
            ))
            .context(DaemonClientSnafu)?;
        for record in page.records {
            println!(
                "session_id={} sequence={} timestamp_unix_ms={} kind={} payload={}",
                record.session_id,
                record.sequence,
                record.timestamp_unix_ms,
                record.event_kind,
                String::from_utf8_lossy(&record.payload),
            );
        }
        println!(
            "durable_cursor={} truncated_before_cursor={}",
            page.end.durable_cursor, page.end.truncated_before_cursor
        );
        Ok(())
    }
}

struct AuditEvidenceTraceCommand<'a> {
    args: &'a AuditEvidenceTraceArgs,
    client: &'a DaemonClient,
}

impl<'a> AuditEvidenceTraceCommand<'a> {
    const fn new(args: &'a AuditEvidenceTraceArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let page = runtime
            .block_on(self.client.session_evidence(
                &self.args.session_id,
                self.args.after_sequence,
                self.args.maximum_records,
            ))
            .context(DaemonClientSnafu)?;
        for record in page.records {
            println!(
                "session_id={} sequence={} timestamp_unix_ms={} source={} payload={}",
                record.session_id,
                record.sequence,
                record.timestamp_unix_ms,
                record.source,
                String::from_utf8_lossy(&record.payload),
            );
        }
        println!(
            "durable_cursor={} truncated_before_cursor={}",
            page.end.durable_cursor, page.end.truncated_before_cursor
        );
        Ok(())
    }
}
