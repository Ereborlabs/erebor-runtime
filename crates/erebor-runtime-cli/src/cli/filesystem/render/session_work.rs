use comfy_table::Table;
use erebor_runtime_filesystem::{
    FilesystemSessionWorkCatalog, FilesystemSessionWorkChange, FilesystemSessionWorkCommit,
    FilesystemSessionWorkRollback, FilesystemSessionWorkTarget, FilesystemSessionWorkTransaction,
    FilesystemSessionWorkTransactionState,
};
use snafu::ResultExt;

use crate::error::{CliError, EncodeJsonSnafu};

use super::super::super::OutputFormat;
use super::RenderSupport;

pub(in crate::cli::filesystem) struct SessionWorkRenderer;

impl SessionWorkRenderer {
    pub(in crate::cli::filesystem) fn print_commit(
        commit: &FilesystemSessionWorkCommit,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => RenderSupport::print_json(commit),
            OutputFormat::Text => {
                let mut table = RenderSupport::standard_table();
                table.set_header(["STATUS", "HANDLE", "TRANSACTION", "CHECKPOINT"]);
                table.add_row([
                    String::from("committed"),
                    commit.handle().to_owned(),
                    commit.transaction_id().to_owned(),
                    commit.checkpoint_ref().to_owned(),
                ]);
                println!("{table}");
                Ok(())
            }
        }
    }

    pub(in crate::cli::filesystem) fn print_catalog(
        catalog: &FilesystemSessionWorkCatalog,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => RenderSupport::print_json(catalog),
            OutputFormat::Text => {
                if !catalog.is_empty() {
                    println!("{}", Self::transaction_table(catalog.transactions()));
                }
                Ok(())
            }
        }
    }

    pub(in crate::cli::filesystem) fn print_target(
        target: &FilesystemSessionWorkTarget,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => RenderSupport::print_json(target),
            OutputFormat::Text => {
                match target {
                    FilesystemSessionWorkTarget::Transaction(transaction) => {
                        println!(
                            "{}",
                            Self::transaction_table(std::slice::from_ref(transaction))
                        );
                        println!(
                            "{}",
                            Self::changes_table(Self::transaction_changes(transaction))
                        );
                    }
                    FilesystemSessionWorkTarget::Subtransaction(subtransaction) => {
                        let mut table = RenderSupport::standard_table();
                        table.set_header([
                            "HANDLE",
                            "TYPE",
                            "NAME",
                            "TRANSACTION",
                            "VOLUME",
                            "CHANGES",
                        ]);
                        table.add_row([
                            subtransaction.handle().to_owned(),
                            String::from("work_subtransaction"),
                            RenderSupport::optional_name(subtransaction.name()),
                            subtransaction.transaction_id().to_owned(),
                            subtransaction.volume_id().to_owned(),
                            subtransaction.changes().len().to_string(),
                        ]);
                        println!("{table}");
                        println!(
                            "{}",
                            Self::changes_table(
                                subtransaction
                                    .changes()
                                    .iter()
                                    .map(|change| (subtransaction.handle(), change))
                                    .collect(),
                            )
                        );
                    }
                }
                Ok(())
            }
        }
    }

    pub(in crate::cli::filesystem) fn print_rollback(
        rollback: &FilesystemSessionWorkRollback,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string(rollback).context(EncodeJsonSnafu)?
                );
                Ok(())
            }
            OutputFormat::Text => {
                let mut table = RenderSupport::standard_table();
                table.set_header(["STATUS", "HANDLE", "TRANSACTION", "RESTORED_VOLUMES"]);
                table.add_row([
                    String::from("overlay_restored"),
                    rollback.handle().to_owned(),
                    rollback.transaction_id().to_owned(),
                    Self::restored_volumes(rollback),
                ]);
                println!("{table}");
                Ok(())
            }
        }
    }

    fn transaction_table(transactions: &[FilesystemSessionWorkTransaction]) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header([
            "HANDLE",
            "TYPE",
            "STATE",
            "NAME",
            "TRANSACTION",
            "SOURCE",
            "SUBTX",
            "CHANGES",
        ]);
        for transaction in transactions {
            table.add_row([
                transaction.handle().to_owned(),
                String::from("work_transaction"),
                Self::state(transaction.state()).to_owned(),
                RenderSupport::optional_name(transaction.name()),
                transaction.transaction_id().to_owned(),
                transaction.source().to_owned(),
                transaction.subtransactions().len().to_string(),
                transaction.change_count().to_string(),
            ]);
            for subtransaction in transaction.subtransactions() {
                table.add_row([
                    subtransaction.handle().to_owned(),
                    String::from("work_subtransaction"),
                    String::from("-"),
                    RenderSupport::optional_name(subtransaction.name()),
                    subtransaction.transaction_id().to_owned(),
                    subtransaction.volume_id().to_owned(),
                    String::from("-"),
                    subtransaction.changes().len().to_string(),
                ]);
            }
        }
        table
    }

    fn transaction_changes(
        transaction: &FilesystemSessionWorkTransaction,
    ) -> Vec<(&str, &FilesystemSessionWorkChange)> {
        transaction
            .subtransactions()
            .iter()
            .flat_map(|subtransaction| {
                subtransaction
                    .changes()
                    .iter()
                    .map(|change| (subtransaction.handle(), change))
            })
            .collect()
    }

    fn changes_table(changes: Vec<(&str, &FilesystemSessionWorkChange)>) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header(["HANDLE", "OP", "PATH"]);
        for (handle, change) in changes {
            table.add_row([
                handle.to_owned(),
                change.operation().to_owned(),
                change.path().to_owned(),
            ]);
        }
        table
    }

    fn restored_volumes(rollback: &FilesystemSessionWorkRollback) -> String {
        if rollback.restored_volumes().is_empty() {
            String::from("-")
        } else {
            rollback.restored_volumes().join(",")
        }
    }

    const fn state(state: FilesystemSessionWorkTransactionState) -> &'static str {
        match state {
            FilesystemSessionWorkTransactionState::Current => "current",
            FilesystemSessionWorkTransactionState::Available => "available",
        }
    }
}
