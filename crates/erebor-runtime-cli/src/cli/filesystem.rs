use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_filesystem::{
    FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemTransactionCatalog,
    FilesystemTransactionRename, FilesystemTransactionRollback, FilesystemTransactionTarget,
};
use snafu::ResultExt;

use crate::error::{CliError, FilesystemSnafu};

use super::{parse_non_empty_path, parse_non_empty_string, OutputFormat};

mod render;
mod storage;

use render::{
    print_catalog, print_retention_inventory, print_retention_prune, print_rollback, print_target,
};
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
            FilesystemCommand::Retention(args) => args.display(),
        }
    }
}

pub(crate) fn execute(args: &FilesystemArgs) -> Result<(), CliError> {
    match &args.command {
        FilesystemCommand::Transactions(args) => execute_transactions(args),
        FilesystemCommand::Retention(args) => execute_retention(args),
    }
}

#[derive(Debug, Subcommand)]
enum FilesystemCommand {
    /// Inspect and roll back filesystem revert transactions.
    Transactions(TransactionArgs),
    /// Inspect and prune retained filesystem revert artifacts.
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

#[derive(Debug, Args)]
struct RetentionArgs {
    #[command(subcommand)]
    command: RetentionCommand,
}

impl RetentionArgs {
    fn display(&self) -> String {
        match &self.command {
            RetentionCommand::List(args) => format!(
                "filesystem retention list registry={} session={} format={}",
                args.session.registry.display(),
                args.session.session,
                args.format.as_str()
            ),
            RetentionCommand::Prune(args) => format!(
                "filesystem retention prune registry={} session={} target={} format={}",
                args.session.registry.display(),
                args.session.session,
                args.target,
                args.format.as_str()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
enum RetentionCommand {
    /// List retained refs and local artifacts for a session.
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
}

fn execute_transactions(args: &TransactionArgs) -> Result<(), CliError> {
    match &args.command {
        TransactionCommand::List(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let catalog = FilesystemTransactionCatalog::load(&storage).context(FilesystemSnafu)?;
            print_catalog(&catalog, args.format)
        }
        TransactionCommand::Show(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let target = FilesystemTransactionTarget::show(&storage, &args.target)
                .context(FilesystemSnafu)?;
            print_target(&target, args.format)
        }
        TransactionCommand::Rename(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let rename = FilesystemTransactionRename::rename(&storage, &args.target, &args.name)
                .context(FilesystemSnafu)?;
            println!("renamed {} {}", rename.handle(), rename.name());
            Ok(())
        }
        TransactionCommand::Rollback(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let rollback = FilesystemTransactionRollback::rollback(&storage, &args.target)
                .context(FilesystemSnafu)?;
            print_rollback(&rollback, args.format)
        }
    }
}

fn execute_retention(args: &RetentionArgs) -> Result<(), CliError> {
    match &args.command {
        RetentionCommand::List(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let inventory =
                FilesystemRetentionInventory::load(&storage).context(FilesystemSnafu)?;
            print_retention_inventory(&inventory, args.format)
        }
        RetentionCommand::Prune(args) => {
            let storage = open_storage(&args.session.registry, &args.session.session)?;
            let prune =
                FilesystemRetentionPrune::prune(&storage, &args.target).context(FilesystemSnafu)?;
            print_retention_prune(&prune, args.format)
        }
    }
}
