use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_audit::{
    EvidenceTraceRequest, EvidenceTraceSink, EvidenceTraceSource, FileEvidenceTraceSink,
    MarkdownEvidenceTraceRenderer,
};
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu, EvidenceTraceSnafu};

use super::{parse_non_empty_path, parse_non_empty_string};

#[derive(Debug, Args)]
pub(super) struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

impl AuditArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            AuditCommand::Tail(args) => format!("audit tail session_id={}", args.session_id),
            AuditCommand::EvidenceTrace(args) => format!(
                "audit evidence-trace session_id={} out={}",
                args.session_id,
                args.out
                    .as_ref()
                    .map_or_else(|| String::from("stdout"), |path| path.display().to_string())
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Print raw audit records for a governed session.
    Tail(AuditTailArgs),
    /// Render a DPO-readable evidence trace from a governed session audit.
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
    /// Session id whose registry artifacts should be rendered.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
    /// Prompt artifact used by the governed run.
    #[arg(long, value_parser = parse_non_empty_path)]
    prompt: Option<PathBuf>,
    /// Markdown report output path. Omit to print to stdout.
    #[arg(long, value_parser = parse_non_empty_path)]
    out: Option<PathBuf>,
    /// Plain-language purpose for this governed session.
    #[arg(
        long,
        default_value = "OpenClaw support investigation of a local OAuth callback reproduction under Erebor governance."
    )]
    purpose: String,
}

pub(super) struct AuditCommandOwner<'a> {
    args: &'a AuditArgs,
}

impl<'a> AuditCommandOwner<'a> {
    pub(super) const fn new(args: &'a AuditArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            AuditCommand::Tail(args) => AuditTailCommand::new(args).execute(),
            AuditCommand::EvidenceTrace(args) => AuditEvidenceTraceCommand::new(args).execute(),
        }
    }
}

struct AuditTailCommand<'a> {
    args: &'a AuditTailArgs,
}

impl<'a> AuditTailCommand<'a> {
    const fn new(args: &'a AuditTailArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let page = runtime
            .block_on(erebor_runtime_client::DaemonClient::local().session_events(
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
}

impl<'a> AuditEvidenceTraceCommand<'a> {
    const fn new(args: &'a AuditEvidenceTraceArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        tracing::debug!(
            session = %self.args.session_id,
            "rendering evidence trace"
        );
        let request = EvidenceTraceRequest::from_paths(
            EvidenceTraceSource::default()
                .paths(
                    &self.args.session_id,
                    self.args.prompt.clone(),
                    self.args.purpose.clone(),
                )
                .context(EvidenceTraceSnafu)?,
        )
        .context(EvidenceTraceSnafu)?;
        let report = MarkdownEvidenceTraceRenderer
            .render(&request)
            .context(EvidenceTraceSnafu)?;

        if let Some(out) = self.args.out.as_ref() {
            let sink = FileEvidenceTraceSink::new(out);
            let receipt = sink.send(&report).context(EvidenceTraceSnafu)?;
            println!(
                "evidence_trace={} sha256={}",
                receipt.destination(),
                receipt.report_sha256()
            );
        } else {
            print!("{}", report.markdown());
        }
        Ok(())
    }
}
