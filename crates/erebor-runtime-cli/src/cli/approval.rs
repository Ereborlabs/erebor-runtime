use clap::{Args, Subcommand};
use erebor_runtime_client::{ApprovalPage, ApprovalRecord, DaemonClient};
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu};

use super::parse_non_empty_string;

#[derive(Debug, Args)]
pub(super) struct ApprovalArgs {
    #[command(subcommand)]
    command: ApprovalCommand,
}

impl ApprovalArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            ApprovalCommand::Ls => String::from("approval ls"),
            ApprovalCommand::Inspect(args) => format!("approval inspect {}", args.approval_id),
            ApprovalCommand::Approve(args) => format!("approval approve {}", args.approval_id),
            ApprovalCommand::Deny(args) => format!("approval deny {}", args.approval_id),
        }
    }
}

pub(super) struct ApprovalCommandOwner<'a> {
    args: &'a ApprovalArgs,
}

impl<'a> ApprovalCommandOwner<'a> {
    pub(super) const fn new(args: &'a ApprovalArgs) -> Self {
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
            ApprovalCommand::Ls => {
                Self::render_page(client.approval_list().await.context(DaemonClientSnafu)?)
            }
            ApprovalCommand::Inspect(args) => Self::render_record(
                client
                    .approval_inspect(&args.approval_id, args.owner_uid)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            ApprovalCommand::Approve(args) => Self::render_record(
                client
                    .approval_approve(&args.approval_id, args.owner_uid, &args.idempotency_key)
                    .await
                    .context(DaemonClientSnafu)?,
            ),
            ApprovalCommand::Deny(args) => Self::render_record(
                client
                    .approval_deny(
                        &args.approval_id,
                        args.owner_uid,
                        &args.reason,
                        &args.idempotency_key,
                    )
                    .await
                    .context(DaemonClientSnafu)?,
            ),
        }
        Ok(())
    }

    fn render_page(page: ApprovalPage) {
        for record in page.records {
            Self::render_record(record);
        }
    }

    fn render_record(record: ApprovalRecord) {
        println!(
            "approval_id={} state={} owner_uid={} session_id={} generation={} effect_digest={} expires_at_unix_ms={}",
            record.approval_id,
            record.state,
            record.owner_uid,
            record.session_id,
            record.session_generation,
            record.effect_digest,
            record.expires_at_unix_ms,
        );
    }
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List your pending approvals.
    Ls,
    /// Inspect an approval. Root may select another UID explicitly.
    Inspect(ApprovalInspectArgs),
    /// Approve an exact pending effect (root approvers only).
    Approve(ApprovalMutationArgs),
    /// Deny an exact pending effect (root approvers only).
    Deny(ApprovalDenyArgs),
}

#[derive(Debug, Args)]
struct ApprovalInspectArgs {
    #[arg(value_parser = parse_non_empty_string)]
    approval_id: String,
    /// Owner UID. Omit for your own record.
    #[arg(long, default_value_t = 0)]
    owner_uid: u32,
}

#[derive(Debug, Args)]
struct ApprovalMutationArgs {
    #[arg(value_parser = parse_non_empty_string)]
    approval_id: String,
    /// UID that owns the effect being approved.
    #[arg(long)]
    owner_uid: u32,
    /// Stable key reused only when retrying the same uncertain request.
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct ApprovalDenyArgs {
    #[arg(value_parser = parse_non_empty_string)]
    approval_id: String,
    /// UID that owns the effect being denied.
    #[arg(long)]
    owner_uid: u32,
    #[arg(long, value_parser = parse_non_empty_string)]
    reason: String,
    /// Stable key reused only when retrying the same uncertain request.
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn approval_commands_require_exact_mutation_bindings() {
        assert!(Cli::try_parse_from(["erebor", "approval", "ls"]).is_ok());
        assert!(Cli::try_parse_from(["erebor", "approval", "approve", "approval-1"]).is_err());
        assert!(Cli::try_parse_from([
            "erebor",
            "approval",
            "deny",
            "approval-1",
            "--owner-uid",
            "1000",
            "--reason",
            "denied",
            "--idempotency-key",
            "retry-1",
        ])
        .is_ok());
    }
}
