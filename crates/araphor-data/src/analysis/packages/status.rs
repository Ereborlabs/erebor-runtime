use duckdb::params;
use snafu::ResultExt as _;

use super::{PackageActivationV1, PackageKeyV1};
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStore, Result};

impl AnalysisStore {
    pub fn mark_package_stale(&self, expected: &PackageActivationV1) -> Result<()> {
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package input notice",
            })?;
        let current = Self::activation_from(&transaction, &expected.key)?;
        if current.as_ref() != Some(expected) {
            return Ok(());
        }
        if !expected.active {
            return AnalysisConflictSnafu.fail();
        }
        if !Self::stale_package_heads(&transaction, &expected.key)? {
            return Ok(());
        }
        let revision = self.package_next(&transaction)?;
        Self::record_revision(&transaction, revision, &["package_results"])?;
        self.commit_metadata(transaction, "commit package input notice")?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub fn update_package_metadata(
        &self,
        key: &PackageKeyV1,
        generation: u64,
        metadata: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.write_package_status(key, generation, None, metadata, check)
    }

    pub fn fail_package(
        &self,
        expected: &PackageActivationV1,
        metadata: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.write_package_status(
            &expected.key,
            expected.generation,
            Some(expected),
            metadata,
            check,
        )
    }

    fn write_package_status(
        &self,
        key: &PackageKeyV1,
        generation: u64,
        expected: Option<&PackageActivationV1>,
        metadata: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if metadata.len() > super::MAX_PACKAGE_METADATA_BYTES {
            return self.reject("the package status exceeds its byte limit");
        }
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package status",
            })?;
        let current = Self::activation_from(&transaction, key)?;
        if expected.is_some() && current.as_ref() != expected {
            check()?;
            return Ok(());
        }
        if current
            .as_ref()
            .is_none_or(|active| active.generation != generation || !active.active)
        {
            return AnalysisConflictSnafu.fail();
        }
        let stale = expected.is_some() && Self::stale_package_heads(&transaction, key)?;
        let activation_changed = current
            .as_ref()
            .is_some_and(|active| active.metadata != metadata);
        if !stale
            && current
                .as_ref()
                .is_some_and(|active| active.metadata == metadata)
        {
            check()?;
            return Ok(());
        }
        let before = Self::package_bytes(&transaction, key.tenant_id)?;
        transaction
            .execute(
                "UPDATE package_activations SET metadata = ?
            WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                params![
                    metadata,
                    key.tenant_id.as_slice(),
                    key.scope_id,
                    key.package_id,
                    key.export
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "write package status",
            })?;
        Self::check_package_scope(&transaction, key)?;
        self.package_charge(&transaction, key.tenant_id, before, 0, 0)?;
        let revision = self.package_next(&transaction)?;
        Self::record_revision(
            &transaction,
            revision,
            &["package_activations", "package_results"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit package status")?;
        self.revision.send_replace(revision);
        if activation_changed {
            self.activations.send_replace(revision);
        }
        Ok(())
    }

    pub fn renew_package(
        &self,
        expected: &PackageActivationV1,
        metadata: &[u8],
        grant_id: &str,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<PackageActivationV1> {
        if metadata.len() > super::MAX_PACKAGE_METADATA_BYTES
            || grant_id.is_empty()
            || grant_id.len() > 256
        {
            return self.reject("the renewed package authority is invalid");
        }
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package authority renewal",
            })?;
        let current = Self::activation_from(&transaction, &expected.key)?;
        let installed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_activations
             WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ? AND installed)",
            params![expected.key.tenant_id.as_slice(), expected.key.scope_id,
                expected.key.package_id, expected.key.export], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "check package renewal status" })?;
        if current.as_ref() != Some(expected) || !installed {
            return AnalysisConflictSnafu.fail();
        }
        if expected.grant_id == grant_id && expected.metadata == metadata {
            check()?;
            return Ok(expected.clone());
        }
        let before = Self::package_bytes(&transaction, expected.key.tenant_id)?;
        let revision = self.package_next(&transaction)?;
        let mut renewed = expected.clone();
        renewed.generation = revision;
        renewed.metadata = metadata.into();
        renewed.grant_id = grant_id.into();
        Self::write_activation(&transaction, &renewed)?;
        self.package_charge(&transaction, expected.key.tenant_id, before, 0, 0)?;
        Self::record_revision(&transaction, revision, &["package_activations"])?;
        check()?;
        self.commit_metadata(transaction, "commit package authority renewal")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        Ok(renewed)
    }
}
