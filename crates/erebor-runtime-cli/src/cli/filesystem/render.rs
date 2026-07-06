use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use erebor_runtime_filesystem::{
    FilesystemSubtransactionState, FilesystemTransaction, FilesystemTransactionCatalog,
    FilesystemTransactionChange, FilesystemTransactionRollback, FilesystemTransactionState,
    FilesystemTransactionTarget,
};
use serde::Serialize;
use snafu::ResultExt;

use crate::error::{CliError, EncodeJsonSnafu};

use super::super::OutputFormat;

mod retention;

pub(super) use retention::{print_retention_inventory, print_retention_prune};

pub(super) fn print_catalog(
    catalog: &FilesystemTransactionCatalog,
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => print_json(catalog),
        OutputFormat::Text => {
            println!("{}", transaction_table(catalog.transactions()));
            Ok(())
        }
    }
}

pub(super) fn print_target(
    target: &FilesystemTransactionTarget,
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => print_json(target),
        OutputFormat::Text => {
            match target {
                FilesystemTransactionTarget::Transaction(transaction) => {
                    println!("{}", transaction_table(std::slice::from_ref(transaction)));
                    println!("{}", changes_table(transaction_changes(transaction)));
                }
                FilesystemTransactionTarget::Subtransaction(subtransaction) => {
                    println!(
                        "{}",
                        subtransaction_table(std::slice::from_ref(subtransaction))
                    );
                    println!("{}", changes_table(subtransaction_changes(subtransaction)));
                }
            }
            Ok(())
        }
    }
}

pub(super) fn print_rollback(
    rollback: &FilesystemTransactionRollback,
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => print_json(rollback),
        OutputFormat::Text => {
            println!("{}", rollback_table(rollback));
            Ok(())
        }
    }
}

fn transaction_table(transactions: &[FilesystemTransaction]) -> Table {
    let mut table = standard_table();
    table.set_header([
        "HANDLE", "TYPE", "STATE", "NAME", "SESSION", "VOLUME", "SUBTX", "CHANGES",
    ]);
    for transaction in transactions {
        table.add_row([
            transaction.handle().to_owned(),
            String::from("transaction"),
            transaction_state(transaction.state()).to_owned(),
            optional_name(transaction.name()),
            transaction.promotion_id().to_owned(),
            String::from("-"),
            transaction.subtransactions().len().to_string(),
            transaction.change_count().to_string(),
        ]);
        add_subtransaction_rows(&mut table, transaction.subtransactions());
    }
    table
}

fn subtransaction_table(
    subtransactions: &[erebor_runtime_filesystem::FilesystemSubtransaction],
) -> Table {
    let mut table = standard_table();
    table.set_header([
        "HANDLE", "TYPE", "STATE", "NAME", "SESSION", "VOLUME", "SUBTX", "CHANGES",
    ]);
    add_subtransaction_rows(&mut table, subtransactions);
    table
}

fn add_subtransaction_rows(
    table: &mut Table,
    subtransactions: &[erebor_runtime_filesystem::FilesystemSubtransaction],
) {
    for subtransaction in subtransactions {
        table.add_row([
            subtransaction.handle().to_owned(),
            String::from("subtransaction"),
            subtransaction_state(subtransaction.state()).to_owned(),
            optional_name(subtransaction.name()),
            subtransaction.promotion_id().to_owned(),
            subtransaction.volume_id().to_owned(),
            String::from("-"),
            subtransaction.changes().len().to_string(),
        ]);
    }
}

fn changes_table(changes: Vec<(&str, &FilesystemTransactionChange)>) -> Table {
    let mut table = standard_table();
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

fn rollback_table(rollback: &FilesystemTransactionRollback) -> Table {
    let mut table = standard_table();
    table.set_header(["STATUS", "HANDLE", "PROMOTION", "RESTORED_VOLUMES"]);
    table.add_row([
        if rollback.restored_volumes().is_empty() {
            String::from("already_restored")
        } else {
            String::from("rolled_back")
        },
        rollback.handle().to_owned(),
        rollback.promotion_id().to_owned(),
        restored_volumes(rollback),
    ]);
    table
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string(value).context(EncodeJsonSnafu)?);
    Ok(())
}

fn transaction_changes(
    transaction: &FilesystemTransaction,
) -> Vec<(&str, &FilesystemTransactionChange)> {
    transaction
        .subtransactions()
        .iter()
        .flat_map(subtransaction_changes)
        .collect()
}

fn subtransaction_changes(
    subtransaction: &erebor_runtime_filesystem::FilesystemSubtransaction,
) -> Vec<(&str, &FilesystemTransactionChange)> {
    subtransaction
        .changes()
        .iter()
        .map(|change| (subtransaction.handle(), change))
        .collect()
}

fn standard_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn optional_name(name: Option<&str>) -> String {
    name.unwrap_or("-").to_owned()
}

fn restored_volumes(rollback: &FilesystemTransactionRollback) -> String {
    if rollback.restored_volumes().is_empty() {
        String::from("-")
    } else {
        rollback.restored_volumes().join(",")
    }
}

fn transaction_state(state: FilesystemTransactionState) -> &'static str {
    match state {
        FilesystemTransactionState::Applied => "applied",
        FilesystemTransactionState::PartiallyRestored => "partially_restored",
        FilesystemTransactionState::Restored => "restored",
    }
}

fn subtransaction_state(state: FilesystemSubtransactionState) -> &'static str {
    match state {
        FilesystemSubtransactionState::Applied => "applied",
        FilesystemSubtransactionState::Restored => "restored",
    }
}
