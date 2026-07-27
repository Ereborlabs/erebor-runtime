use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::v1::{
    FilesystemMutationRequest, FilesystemOperationKind, FilesystemQueryRequest,
};
use snafu::ResultExt;

use crate::error::{CliError, DaemonClientSnafu, DaemonRuntimeSnafu};

use super::{parse_non_empty_string, OutputFormat};

#[derive(Debug, Args)]
pub(crate) struct FilesystemArgs {
    #[command(subcommand)]
    command: FilesystemCommand,
}

impl FilesystemArgs {
    pub(crate) fn display(&self) -> String {
        match &self.command {
            FilesystemCommand::Transactions(args) => args.display(),
            FilesystemCommand::Retention(args) => args.display(),
        }
    }
}

pub(crate) fn execute(args: &FilesystemArgs, client: &DaemonClient) -> Result<(), CliError> {
    FilesystemCommandOwner::new(args, client).execute()
}

#[derive(Debug, Subcommand)]
enum FilesystemCommand {
    /// Inspect and roll back daemon-owned filesystem transactions.
    Transactions(TransactionArgs),
    /// Inspect and prune daemon-owned filesystem retention artifacts.
    Retention(RetentionArgs),
}

#[derive(Debug, Args)]
struct TransactionArgs {
    #[command(subcommand)]
    command: TransactionCommand,
}

impl TransactionArgs {
    fn display(&self) -> String {
        match &self.command {
            TransactionCommand::List(args) => {
                format!(
                    "filesystem transactions list session={} format={}",
                    args.session.session,
                    args.format.as_str()
                )
            }
            TransactionCommand::Commit(args) => {
                format!(
                    "filesystem transactions commit session={} format={}",
                    args.session.session,
                    args.format.as_str()
                )
            }
            TransactionCommand::Show(args) => format!(
                "filesystem transactions show session={} target={} format={}",
                args.session.session,
                args.target,
                args.format.as_str()
            ),
            TransactionCommand::Rename(args) => format!(
                "filesystem transactions rename session={} target={}",
                args.session.session, args.target
            ),
            TransactionCommand::Rollback(args) => format!(
                "filesystem transactions rollback session={} target={} format={}",
                args.session.session,
                args.target,
                args.format.as_str()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum TransactionCommand {
    /// List transaction and subtransaction handles for a Session.
    List(TransactionListArgs),
    /// Commit current Session work without host promotion.
    Commit(TransactionCommitArgs),
    /// Show changed paths for a transaction or subtransaction.
    Show(TransactionShowArgs),
    /// Rename a transaction or subtransaction handle.
    Rename(TransactionRenameArgs),
    /// Roll back a transaction or subtransaction.
    Rollback(TransactionRollbackArgs),
}

#[derive(Debug, Args)]
struct TransactionListArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct TransactionCommitArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(long, value_parser = parse_non_empty_string)]
    name: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct TransactionShowArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(value_parser = parse_non_empty_string)]
    target: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct TransactionRenameArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(value_parser = parse_non_empty_string)]
    target: String,
    #[arg(value_parser = parse_non_empty_string)]
    name: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct TransactionRollbackArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(value_parser = parse_non_empty_string)]
    target: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct TransactionSessionArgs {
    /// Daemon-owned Session or its user-facing alias.
    #[arg(long, value_parser = parse_non_empty_string)]
    session: String,
}

#[derive(Debug, Args)]
struct RetentionArgs {
    #[command(subcommand)]
    command: RetentionCommand,
}

impl RetentionArgs {
    fn display(&self) -> String {
        match &self.command {
            RetentionCommand::List(args) => {
                format!(
                    "filesystem retention list session={} format={}",
                    args.session.session,
                    args.format.as_str()
                )
            }
            RetentionCommand::Prune(args) => format!(
                "filesystem retention prune session={} target={} format={}",
                args.session.session,
                args.target,
                args.format.as_str()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum RetentionCommand {
    /// List retained refs and local artifacts for a Session.
    List(RetentionListArgs),
    /// Explicitly prune a restored transaction, subtransaction, or unprotected ref.
    Prune(RetentionPruneArgs),
}

#[derive(Debug, Args)]
struct RetentionListArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct RetentionPruneArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(value_parser = parse_non_empty_string)]
    target: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, value_parser = parse_non_empty_string)]
    idempotency_key: String,
}

struct FilesystemCommandOwner<'a> {
    args: &'a FilesystemArgs,
    client: &'a DaemonClient,
}

impl<'a> FilesystemCommandOwner<'a> {
    const fn new(args: &'a FilesystemArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            FilesystemCommand::Transactions(args) => self.transactions(args),
            FilesystemCommand::Retention(args) => self.retention(args),
        }
    }

    fn transactions(&self, args: &TransactionArgs) -> Result<(), CliError> {
        match &args.command {
            TransactionCommand::List(args) => self.query(
                &args.session.session,
                FilesystemOperationKind::TransactionsList,
                "",
                args.format,
            ),
            TransactionCommand::Show(args) => self.query(
                &args.session.session,
                FilesystemOperationKind::TransactionsShow,
                &args.target,
                args.format,
            ),
            TransactionCommand::Commit(args) => self.mutation(
                &args.session.session,
                FilesystemOperationKind::TransactionsCommit,
                "",
                args.name.as_deref().unwrap_or_default(),
                args.format,
                &args.idempotency_key,
            ),
            TransactionCommand::Rename(args) => self.mutation(
                &args.session.session,
                FilesystemOperationKind::TransactionsRename,
                &args.target,
                &args.name,
                OutputFormat::Text,
                &args.idempotency_key,
            ),
            TransactionCommand::Rollback(args) => self.mutation(
                &args.session.session,
                FilesystemOperationKind::TransactionsRollback,
                &args.target,
                "",
                args.format,
                &args.idempotency_key,
            ),
        }
    }

    fn retention(&self, args: &RetentionArgs) -> Result<(), CliError> {
        match &args.command {
            RetentionCommand::List(args) => self.query(
                &args.session.session,
                FilesystemOperationKind::RetentionList,
                "",
                args.format,
            ),
            RetentionCommand::Prune(args) => self.mutation(
                &args.session.session,
                FilesystemOperationKind::RetentionPrune,
                &args.target,
                "",
                args.format,
                &args.idempotency_key,
            ),
        }
    }

    fn query(
        &self,
        session_id: &str,
        operation: FilesystemOperationKind,
        target: &str,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        let runtime = Self::runtime()?;
        let response = runtime
            .block_on(self.client.filesystem_query(FilesystemQueryRequest {
                session_id: session_id.to_owned(),
                operation: operation as i32,
                target: target.to_owned(),
                output_format: format.as_str().to_owned(),
            }))
            .context(DaemonClientSnafu)?;
        println!("{}", response.output);
        Ok(())
    }

    fn mutation(
        &self,
        session_id: &str,
        operation: FilesystemOperationKind,
        target: &str,
        name: &str,
        format: OutputFormat,
        idempotency_key: &str,
    ) -> Result<(), CliError> {
        let runtime = Self::runtime()?;
        let response = runtime
            .block_on(self.client.filesystem_mutation(
                FilesystemMutationRequest {
                    session_id: session_id.to_owned(),
                    operation: operation as i32,
                    target: target.to_owned(),
                    name: name.to_owned(),
                    output_format: format.as_str().to_owned(),
                },
                idempotency_key,
            ))
            .context(DaemonClientSnafu)?;
        println!("{}", response.output);
        Ok(())
    }

    fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::FilesystemArgs;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(clap::Subcommand)]
    enum TestCommand {
        Filesystem(FilesystemArgs),
    }

    #[test]
    fn filesystem_commands_name_a_daemon_session_not_a_registry_path() {
        assert!(TestCli::try_parse_from([
            "erebor",
            "filesystem",
            "transactions",
            "list",
            "--session",
            "review-1",
        ])
        .is_ok());
        assert!(TestCli::try_parse_from([
            "erebor",
            "filesystem",
            "transactions",
            "list",
            "--registry",
            "/tmp/registry",
            "--session",
            "review-1",
        ])
        .is_err());
    }
}
