use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_audit::{
    read_audit_records, EvidenceTraceRequest, EvidenceTraceSink, EvidenceTraceSource,
    FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer,
};
use snafu::ResultExt;

use crate::error::{AuditLogSnafu, CliError, EncodeJsonSnafu, EvidenceTraceSnafu};

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
    /// Session id whose registry-owned audit records should be printed.
    #[arg(value_parser = parse_non_empty_string)]
    session_id: String,
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
        let audit_path = EvidenceTraceSource::default()
            .audit_path(&self.args.session_id)
            .context(EvidenceTraceSnafu)?;
        tracing::debug!(
            session = %self.args.session_id,
            audit = %audit_path.display(),
            "reading session audit records"
        );
        for record in read_audit_records(&audit_path).context(AuditLogSnafu)? {
            println!(
                "{}",
                serde_json::to_string(&record).context(EncodeJsonSnafu)?
            );
        }
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
