use duckdb::{params, Transaction};
use snafu::ResultExt as _;

use super::{PackageActivationV1, PackageCommitV1, PackageKeyV1};
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStore, Result};

impl AnalysisStore {
    pub fn activate_package(
        &self,
        input: &PackageActivationV1,
        expected: Option<u64>,
        prepared: Option<&PackageCommitV1>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<PackageActivationV1> {
        if !input.key.valid()
            || input.revision.is_empty()
            || input.revision.len() > 4096
            || input.grant_id.is_empty()
            || input.grant_id.len() > 256
            || input.metadata.len() > super::MAX_PACKAGE_METADATA_BYTES
        {
            return self.reject("the package activation is invalid");
        }
        if let Some(prepared) = prepared {
            self.validate_package_commit(prepared)?;
            if prepared.activation != *input || !input.active {
                return self.reject("the prepared result uses another or inactive activation");
            }
        }
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package activation",
            })?;
        let current = Self::activation_from(&transaction, &input.key)?;
        if let Some(prepared) = prepared {
            if let Some(receipt) = self.package_retry(&transaction, prepared)? {
                check()?;
                let mut committed = input.clone();
                committed.generation = receipt.commit_revision;
                committed.checkpoint_revision = receipt.commit_revision;
                committed.result_id = Some(receipt.result_id);
                return Ok(committed);
            }
        }
        if current.as_ref().map(|value| value.generation) != expected {
            return AnalysisConflictSnafu.fail();
        }
        let artifact = Self::package_from(
            &transaction,
            input.key.tenant_id,
            &input.key.package_id,
            &input.revision,
        )?
        .ok_or_else(|| crate::PackageErrorCodeV1::Missing.error("activation artifact"))?;
        if let Some(current) = &current {
            if prepared.is_none()
                && current.active == input.active
                && current.revision == input.revision
                && current.grant_id == input.grant_id
                && current.metadata == input.metadata
            {
                let installed: bool = transaction
                    .query_row(
                        "SELECT installed FROM package_activations
                     WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                        params![
                            input.key.tenant_id.as_slice(),
                            input.key.scope_id,
                            input.key.package_id,
                            input.key.export
                        ],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "check package installation retry",
                    })?;
                if installed {
                    check()?;
                    return Ok(current.clone());
                }
            }
            if current.active && current.revision != input.revision && prepared.is_none() {
                let artifact = artifact.decode_artifact()?;
                if !input.active || !artifact.prepared(&input.key.export) {
                    return self
                        .reject("a package upgrade requires a prepared result and checkpoint");
                }
            }
        }
        if prepared.is_some_and(|value| {
            current
                .as_ref()
                .map_or(0, |active| active.checkpoint_revision)
                != value.expected_checkpoint_revision
        }) {
            return AnalysisConflictSnafu.fail();
        }
        let before = Self::package_bytes(&transaction, input.key.tenant_id)?;
        let revision = self.package_next(&transaction)?;
        let mut active = input.clone();
        active.generation = revision;
        active.checkpoint_revision = 0;
        active.result_id = None;
        Self::write_activation(&transaction, &active)?;
        if current.is_some() {
            Self::stale_package_heads(&transaction, &input.key)?;
        }
        if let Some(current) = &current {
            if current.revision != input.revision {
                self.collect_package_rows(
                    &transaction,
                    input.key.tenant_id,
                    &input.key.package_id,
                    &current.revision,
                )?;
            }
        }
        if let Some(prepared) = prepared {
            self.package_commit_rows(&transaction, prepared, revision, before)?;
            active.result_id = Some(prepared.result_id.clone());
            active.checkpoint_revision = revision;
        } else {
            self.package_charge(&transaction, input.key.tenant_id, before, 0, 0)?;
            Self::record_revision(
                &transaction,
                revision,
                &["package_activations", "package_results"],
            )?;
        }
        if current
            .as_ref()
            .is_some_and(|prior| prior.revision != input.revision)
        {
            Self::record_revision(&transaction, revision, &["package_revisions"])?;
        }
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(super::super::AnalysisCommitStage::BeforeResultCommit)?;
        #[cfg(test)]
        self.crash_at("package.before");
        self.commit_metadata(transaction, "commit package activation")?;
        #[cfg(test)]
        self.crash_at("package.after");
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        Ok(active)
    }

    pub(super) fn write_activation(
        transaction: &Transaction<'_>,
        active: &PackageActivationV1,
    ) -> Result<()> {
        let key = &active.key;
        transaction.execute("INSERT INTO package_activations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true)
            ON CONFLICT (tenant_id, scope_id, package_id, export_name) DO UPDATE SET
                revision = excluded.revision, generation = excluded.generation, checkpoint_revision = excluded.checkpoint_revision,
                result_id = excluded.result_id, grant_id = excluded.grant_id, metadata = excluded.metadata, active = excluded.active, installed = true",
            params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export, active.revision, active.generation,
                active.checkpoint_revision, active.result_id, active.grant_id, active.metadata, active.active],
        ).context(AnalysisDatabaseSnafu { operation: "write package activation" })?;
        Self::check_package_scope(transaction, key)?;
        Ok(())
    }

    pub(super) fn check_package_scope(
        transaction: &Transaction<'_>,
        key: &PackageKeyV1,
    ) -> Result<()> {
        let count: u64 = transaction
            .query_row(
                "SELECT count(*)
             FROM package_activations WHERE tenant_id = ? AND scope_id = ? AND installed",
                params![key.tenant_id.as_slice(), key.scope_id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bound package scope",
            })?;
        if count > super::MAX_PACKAGE_ROWS as u64 {
            return Err(crate::PackageErrorCodeV1::Limit.error("package scope activations"));
        }
        Ok(())
    }

    pub fn remove_package(
        &self,
        key: &PackageKeyV1,
        generation: u64,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.stop_package(key, generation, true, check)
    }

    pub fn suspend_package(
        &self,
        key: &PackageKeyV1,
        generation: u64,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.stop_package(key, generation, false, check)
    }

    fn stop_package(
        &self,
        key: &PackageKeyV1,
        generation: u64,
        removed: bool,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package removal",
            })?;
        let Some(mut active) = Self::activation_from(&transaction, key)? else {
            return AnalysisConflictSnafu.fail();
        };
        if active.generation != generation {
            return AnalysisConflictSnafu.fail();
        }
        let installed: bool = transaction
            .query_row(
                "SELECT installed FROM package_activations
            WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                params![
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read package removal status",
            })?;
        if !installed || (!removed && !active.active) {
            check()?;
            return Ok(());
        }
        let before = Self::package_bytes(&transaction, key.tenant_id)?;
        let revision = self.package_next(&transaction)?;
        active.active = false;
        active.generation = revision;
        Self::write_activation(&transaction, &active)?;
        transaction
            .execute(
                "UPDATE package_activations SET installed = ?
            WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                params![
                    !removed,
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "remove package installation",
            })?;
        Self::stale_package_heads(&transaction, key)?;
        self.collect_package_rows(
            &transaction,
            key.tenant_id,
            &key.package_id,
            &active.revision,
        )?;
        self.package_charge(&transaction, key.tenant_id, before, 0, 0)?;
        Self::record_revision(
            &transaction,
            revision,
            &[
                "package_activations",
                "package_results",
                "package_revisions",
            ],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit package removal")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        Ok(())
    }

    pub(super) fn stale_package_heads(
        transaction: &Transaction<'_>,
        key: &PackageKeyV1,
    ) -> Result<bool> {
        let mut statement = transaction.prepare("SELECT h.result_id FROM package_heads h JOIN package_results r USING (result_id)
            WHERE h.tenant_id = ? AND h.scope_id = ? AND h.package_id = ? AND h.export_name = ? AND NOT r.stale")
            .context(AnalysisDatabaseSnafu { operation: "prepare stale package heads" })?;
        let ids = statement
            .query_map(
                params![
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export
                ],
                |row| row.get::<_, String>(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read stale package heads",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode stale package heads",
            })?;
        let changed = !ids.is_empty();
        for id in ids {
            Self::stale_package_tree(transaction, key.tenant_id, &id)?;
        }
        Ok(changed)
    }
}
