use comfy_table::Table;
use erebor_runtime_filesystem::{
    FilesystemRetainedArtifactStatus, FilesystemRetainedLocalArtifact, FilesystemRetainedLocalKind,
    FilesystemRetainedRef, FilesystemRetainedRefKind, FilesystemRetentionInventory,
    FilesystemRetentionPrune, FilesystemRetentionState, FilesystemRetentionTransaction,
};

use crate::error::CliError;

use super::super::super::OutputFormat;
use super::RenderSupport;

pub(in crate::cli::filesystem) struct RetentionRenderer;

impl RetentionRenderer {
    pub(in crate::cli::filesystem) fn print_inventory(
        inventory: &FilesystemRetentionInventory,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => RenderSupport::print_json(inventory),
            OutputFormat::Text => {
                println!("{}", Self::transaction_table(inventory.transactions()));
                println!("{}", Self::ref_table(inventory));
                println!("{}", Self::local_table(inventory));
                Ok(())
            }
        }
    }

    pub(in crate::cli::filesystem) fn print_prune(
        prune: &FilesystemRetentionPrune,
        format: OutputFormat,
    ) -> Result<(), CliError> {
        match format {
            OutputFormat::Json => RenderSupport::print_json(prune),
            OutputFormat::Text => {
                println!("{}", Self::prune_table(prune));
                Ok(())
            }
        }
    }

    fn transaction_table(transactions: &[FilesystemRetentionTransaction]) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header([
            "HANDLE", "TYPE", "STATE", "NAME", "SESSION", "VOLUME", "REFS",
        ]);
        for transaction in transactions {
            table.add_row([
                transaction.handle().to_owned(),
                String::from("transaction"),
                Self::retention_state(transaction.state()).to_owned(),
                RenderSupport::optional_name(transaction.name()),
                transaction.promotion_id().to_owned(),
                String::from("-"),
                Self::transaction_ref_count(transaction).to_string(),
            ]);
            for subtransaction in transaction.subtransactions() {
                table.add_row([
                    subtransaction.handle().to_owned(),
                    String::from("subtransaction"),
                    Self::retention_state(subtransaction.state()).to_owned(),
                    RenderSupport::optional_name(subtransaction.name()),
                    subtransaction.promotion_id().to_owned(),
                    subtransaction.volume_id().to_owned(),
                    subtransaction.refs().len().to_string(),
                ]);
            }
        }
        table
    }

    fn ref_table(inventory: &FilesystemRetentionInventory) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header([
            "OWNER",
            "KIND",
            "STATUS",
            "PROTECTED",
            "ROLLBACK",
            "SESSION",
            "VOLUME",
            "REF",
        ]);
        for transaction in inventory.transactions() {
            Self::add_ref_rows(&mut table, transaction.handle(), transaction.refs());
            for subtransaction in transaction.subtransactions() {
                Self::add_ref_rows(&mut table, subtransaction.handle(), subtransaction.refs());
            }
        }
        Self::add_ref_rows(&mut table, "loose", inventory.loose_refs());
        table
    }

    fn add_ref_rows(table: &mut Table, owner: &str, refs: &[FilesystemRetainedRef]) {
        for reference in refs {
            table.add_row([
                owner.to_owned(),
                Self::retained_ref_kind(reference.kind()).to_owned(),
                Self::artifact_status(reference.status()).to_owned(),
                Self::bool_text(reference.protected()).to_owned(),
                Self::bool_text(reference.required_for_rollback()).to_owned(),
                reference.promotion_id().to_owned(),
                RenderSupport::optional_name(reference.volume_id()),
                reference.reference().to_owned(),
            ]);
        }
    }

    fn local_table(inventory: &FilesystemRetentionInventory) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header(["OWNER", "KIND", "STATUS", "PROTECTED", "ROLLBACK", "PATH"]);
        Self::add_local_rows(&mut table, "session", inventory.local_artifacts());
        for transaction in inventory.transactions() {
            Self::add_local_rows(
                &mut table,
                transaction.handle(),
                transaction.local_artifacts(),
            );
            for subtransaction in transaction.subtransactions() {
                Self::add_local_rows(
                    &mut table,
                    subtransaction.handle(),
                    subtransaction.local_artifacts(),
                );
            }
        }
        table
    }

    fn add_local_rows(
        table: &mut Table,
        owner: &str,
        artifacts: &[FilesystemRetainedLocalArtifact],
    ) {
        for artifact in artifacts {
            table.add_row([
                owner.to_owned(),
                Self::retained_local_kind(artifact.kind()).to_owned(),
                Self::artifact_status(artifact.status()).to_owned(),
                Self::bool_text(artifact.protected()).to_owned(),
                Self::bool_text(artifact.required_for_rollback()).to_owned(),
                artifact.path().display().to_string(),
            ]);
        }
    }

    fn prune_table(prune: &FilesystemRetentionPrune) -> Table {
        let mut table = RenderSupport::standard_table();
        table.set_header([
            "STATUS",
            "TARGET",
            "PRUNED_REFS",
            "SKIPPED_REFS",
            "PRUNED_LOCAL",
            "SKIPPED_LOCAL",
            "OSTREE_PRUNED",
        ]);
        table.add_row([
            String::from("pruned"),
            prune.selector().to_owned(),
            prune.pruned_refs().len().to_string(),
            prune.skipped_refs().len().to_string(),
            prune.pruned_local_artifacts().len().to_string(),
            prune.skipped_local_artifacts().len().to_string(),
            prune.ostree_prune().objects_pruned().to_string(),
        ]);
        table
    }

    fn retention_state(state: FilesystemRetentionState) -> &'static str {
        match state {
            FilesystemRetentionState::Applied => "applied",
            FilesystemRetentionState::PartiallyRestored => "partially_restored",
            FilesystemRetentionState::Restored => "restored",
            FilesystemRetentionState::Corrupt => "corrupt",
        }
    }

    fn artifact_status(status: FilesystemRetainedArtifactStatus) -> &'static str {
        match status {
            FilesystemRetainedArtifactStatus::Present => "present",
            FilesystemRetainedArtifactStatus::Missing => "missing",
            FilesystemRetainedArtifactStatus::Corrupt => "corrupt",
        }
    }

    fn retained_ref_kind(kind: FilesystemRetainedRefKind) -> &'static str {
        match kind {
            FilesystemRetainedRefKind::CheckpointManifest => "checkpoint_manifest",
            FilesystemRetainedRefKind::CheckpointLayer => "checkpoint_layer",
            FilesystemRetainedRefKind::PromotionManifest => "promotion_manifest",
            FilesystemRetainedRefKind::PromotionPreimage => "promotion_preimage",
        }
    }

    fn retained_local_kind(kind: FilesystemRetainedLocalKind) -> &'static str {
        match kind {
            FilesystemRetainedLocalKind::PromotionWorkdir => "promotion_workdir",
            FilesystemRetainedLocalKind::RollbackCheckout => "rollback_checkout",
            FilesystemRetainedLocalKind::CowPreimageArtifact => "cow_preimage_artifact",
            FilesystemRetainedLocalKind::PromotionLock => "promotion_lock",
            FilesystemRetainedLocalKind::TransactionCatalogJournal => "transaction_catalog_journal",
            FilesystemRetainedLocalKind::RetentionJournal => "retention_journal",
        }
    }

    fn transaction_ref_count(transaction: &FilesystemRetentionTransaction) -> usize {
        transaction.refs().len()
            + transaction
                .subtransactions()
                .iter()
                .map(|subtransaction| subtransaction.refs().len())
                .sum::<usize>()
    }

    fn bool_text(value: bool) -> &'static str {
        if value {
            "yes"
        } else {
            "no"
        }
    }
}
