use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_filesystem::{
    list_transaction_catalog, rename_transaction_target, rollback_transaction_target,
    show_transaction_target,
};
use snafu::ResultExt;

use crate::error::{CliError, FilesystemSnafu};

use super::{parse_non_empty_path, parse_non_empty_string, OutputFormat};

mod render;
mod storage;

use render::{print_catalog, print_rollback, print_target};
use storage::open_storage;

#[derive(Debug, Args)]
pub(crate) struct FilesystemArgs {
    #[command(subcommand)]
    command: FilesystemCommand,
}

impl FilesystemArgs {
    pub(crate) fn display(&self) -> String {
        match &self.command {
            FilesystemCommand::Transactions(args) => args.display(),
        }
    }
}

pub(crate) fn execute(args: &FilesystemArgs) -> Result<(), CliError> {
    match &args.command {
        FilesystemCommand::Transactions(args) => execute_transactions(args),
    }
}

#[derive(Debug, Subcommand)]
enum FilesystemCommand {
    /// Inspect and roll back filesystem revert transactions.
    Transactions(TransactionArgs),
}

#[derive(Debug, Args)]
struct TransactionArgs {
    #[command(subcommand)]
    command: TransactionCommand,
}

impl TransactionArgs {
    fn display(&self) -> String {
        match &self.command {
            TransactionCommand::List(args) => format!(
                "filesystem transactions list registry={} session={} format={}",
                args.session.registry.display(),
                args.session.session,
                args.format.as_str()
            ),
            TransactionCommand::Show(args) => format!(
                "filesystem transactions show registry={} session={} target={} format={}",
                args.session.registry.display(),
                args.session.session,
                args.target,
                args.format.as_str()
            ),
            TransactionCommand::Rename(args) => format!(
                "filesystem transactions rename registry={} session={} target={}",
                args.session.registry.display(),
                args.session.session,
                args.target
            ),
            TransactionCommand::Rollback(args) => format!(
                "filesystem transactions rollback registry={} session={} target={} format={}",
                args.session.registry.display(),
                args.session.session,
                args.target,
                args.format.as_str()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum TransactionCommand {
    /// List transaction and subtransaction handles for a session.
    List(TransactionListArgs),
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
}

#[derive(Debug, Args)]
struct TransactionRollbackArgs {
    #[command(flatten)]
    session: TransactionSessionArgs,
    #[arg(value_parser = parse_non_empty_string)]
    target: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct TransactionSessionArgs {
    #[arg(long, value_parser = parse_non_empty_path)]
    registry: PathBuf,
    #[arg(long, value_parser = parse_non_empty_string)]
    session: String,
}

fn execute_transactions(args: &TransactionArgs) -> Result<(), CliError> {
    match &args.command {
        TransactionCommand::List(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let catalog = list_transaction_catalog(&storage).context(FilesystemSnafu)?;
            print_catalog(&catalog, args.format)
        }
        TransactionCommand::Show(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let target =
                show_transaction_target(&storage, &args.target).context(FilesystemSnafu)?;
            print_target(&target, args.format)
        }
        TransactionCommand::Rename(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let rename = rename_transaction_target(&storage, &args.target, &args.name)
                .context(FilesystemSnafu)?;
            println!("renamed {} {}", rename.handle(), rename.name());
            Ok(())
        }
        TransactionCommand::Rollback(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let rollback =
                rollback_transaction_target(&storage, &args.target).context(FilesystemSnafu)?;
            print_rollback(&rollback, args.format)
        }
    }
}
