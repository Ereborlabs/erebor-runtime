use std::path::PathBuf;

use clap::{Args, Subcommand};
use erebor_runtime_filesystem::{
    FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemSessionWorkCatalog,
    FilesystemSessionWorkCommitRequest, FilesystemSessionWorkRename, FilesystemSessionWorkRollback,
    FilesystemSessionWorkTarget, FilesystemTransactionCatalog, FilesystemTransactionRename,
    FilesystemTransactionRollback, FilesystemTransactionTarget,
};
use snafu::ResultExt;

use crate::error::{CliError, FilesystemSnafu};

use super::{parse_non_empty_path, parse_non_empty_string, OutputFormat};

mod render;
mod storage;

use render::{RetentionRenderer, SessionWorkRenderer, TransactionRenderer};
use storage::FilesystemStorageOpener;

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
    FilesystemCommandOwner::new(args).execute()
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
            TransactionCommand::Commit(args) => format!(
                "filesystem transactions commit registry={} session={} format={}",
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
    /// Commit current session work without host promotion.
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

struct FilesystemCommandOwner<'a> {
    args: &'a FilesystemArgs,
}

impl<'a> FilesystemCommandOwner<'a> {
    const fn new(args: &'a FilesystemArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            FilesystemCommand::Transactions(args) => TransactionCommandOwner::new(args).execute(),
            FilesystemCommand::Retention(args) => RetentionCommandOwner::new(args).execute(),
        }
    }
}

struct TransactionCommandOwner<'a> {
    args: &'a TransactionArgs,
}

impl<'a> TransactionCommandOwner<'a> {
    const fn new(args: &'a TransactionArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            TransactionCommand::List(args) => self.list(args),
            TransactionCommand::Commit(args) => self.commit(args),
            TransactionCommand::Show(args) => self.show(args),
            TransactionCommand::Rename(args) => self.rename(args),
            TransactionCommand::Rollback(args) => self.rollback(args),
        }
    }

    fn list(&self, args: &TransactionListArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        let catalog = FilesystemTransactionCatalog::load(&storage).context(FilesystemSnafu)?;
        TransactionRenderer::print_catalog(&catalog, args.format).and_then(|()| {
            let work = FilesystemSessionWorkCatalog::load(&storage, &args.session.session)
                .context(FilesystemSnafu)?;
            SessionWorkRenderer::print_catalog(&work, args.format)
        })
    }

    fn commit(&self, args: &TransactionCommitArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        let mut request = FilesystemSessionWorkCommitRequest::user(&args.session.session)
            .context(FilesystemSnafu)?;
        if let Some(name) = args.name.as_deref() {
            request.set_name(name).context(FilesystemSnafu)?;
        }
        let commit = storage
            .commit_session_work(request)
            .context(FilesystemSnafu)?;
        SessionWorkRenderer::print_commit(&commit, args.format)
    }

    fn show(&self, args: &TransactionShowArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        match FilesystemTransactionTarget::show(&storage, &args.target) {
            Ok(target) => TransactionRenderer::print_target(&target, args.format),
            Err(_) => {
                let target = FilesystemSessionWorkTarget::show(
                    &storage,
                    &args.session.session,
                    &args.target,
                )
                .context(FilesystemSnafu)?;
                SessionWorkRenderer::print_target(&target, args.format)
            }
        }
    }

    fn rename(&self, args: &TransactionRenameArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        match FilesystemTransactionRename::rename(&storage, &args.target, &args.name) {
            Ok(rename) => println!("renamed {} {}", rename.handle(), rename.name()),
            Err(_) => {
                let rename = FilesystemSessionWorkRename::rename(
                    &storage,
                    &args.session.session,
                    &args.target,
                    &args.name,
                )
                .context(FilesystemSnafu)?;
                println!("renamed {} {}", rename.handle(), rename.name());
            }
        }
        Ok(())
    }

    fn rollback(&self, args: &TransactionRollbackArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        match FilesystemTransactionRollback::rollback(&storage, &args.target) {
            Ok(rollback) => TransactionRenderer::print_rollback(&rollback, args.format),
            Err(_) => {
                let rollback = FilesystemSessionWorkRollback::rollback(
                    &storage,
                    &args.session.session,
                    &args.target,
                )
                .context(FilesystemSnafu)?;
                SessionWorkRenderer::print_rollback(&rollback, args.format)
            }
        }
    }
}

struct RetentionCommandOwner<'a> {
    args: &'a RetentionArgs,
}

impl<'a> RetentionCommandOwner<'a> {
    const fn new(args: &'a RetentionArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            RetentionCommand::List(args) => self.list(args),
            RetentionCommand::Prune(args) => self.prune(args),
        }
    }

    fn list(&self, args: &RetentionListArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        let inventory = FilesystemRetentionInventory::load(&storage).context(FilesystemSnafu)?;
        RetentionRenderer::print_inventory(&inventory, args.format)
    }

    fn prune(&self, args: &RetentionPruneArgs) -> Result<(), CliError> {
        let storage =
            FilesystemStorageOpener::new(&args.session.registry, &args.session.session).open()?;
        let prune =
            FilesystemRetentionPrune::prune(&storage, &args.target).context(FilesystemSnafu)?;
        RetentionRenderer::print_prune(&prune, args.format)
    }
}
