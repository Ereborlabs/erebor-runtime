use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::{PackageRevisionV1, MAX_PACKAGE_ROWS};
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub(crate) fn install_package(
        &self,
        revisions: &[PackageRevisionV1],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if revisions.is_empty() || revisions.len() > 64 {
            return self.reject("the package closure is empty or exceeds its limit");
        }
        let tenant = revisions[0].tenant_id;
        let mut keys = std::collections::BTreeSet::new();
        for package in revisions {
            if package.tenant_id != tenant
                || package.package_id.is_empty()
                || package.package_id.len() > 256
                || package.revision.is_empty()
                || package.revision.len() > 4096
                || package.descriptor.is_empty()
                || package.artifact.is_empty()
                || package.encoded_bytes == 0
                || crate::package::storage::StoredArtifact::frame_size(&package.artifact)?
                    != package.encoded_bytes
                || package.dependencies.len() > 64
                || !keys.insert((&package.package_id, &package.revision))
            {
                return self.reject("the package closure is invalid");
            }
        }
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package installation",
            })?;
        let before = Self::package_bytes(&transaction, tenant)?;
        let revision = self.package_next(&transaction)?;
        let mut changed = false;
        for package in revisions {
            if let Some(existing) =
                Self::package_from(&transaction, tenant, &package.package_id, &package.revision)?
            {
                if existing != *package {
                    return AnalysisConflictSnafu.fail();
                }
                continue;
            }
            let dependencies = serde_json::to_string(&package.dependencies).context(JsonSnafu {
                path: "<package-dependencies>",
            })?;
            transaction
                .execute(
                    "INSERT INTO package_revisions (tenant_id, package_id, revision, descriptor, artifact, dependencies, commit_revision, encoded_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        tenant.as_slice(),
                        package.package_id,
                        package.revision,
                        package.descriptor,
                        package.artifact,
                        dependencies,
                        revision,
                        package.encoded_bytes as u64
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert package revision",
                })?;
            changed = true;
        }
        for package in revisions {
            for dependency in &package.dependencies {
                if Self::package_from(
                    &transaction,
                    tenant,
                    &dependency.package_id,
                    &dependency.revision,
                )?
                .is_none()
                {
                    return self.reject("the locked package dependency is absent");
                }
            }
        }
        let count: u64 = transaction
            .query_row(
                "SELECT count(*) FROM package_revisions WHERE tenant_id = ?",
                params![tenant.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count package revisions",
            })?;
        if count > MAX_PACKAGE_ROWS as u64 {
            return self.reject("the package revisions exceed their count limit");
        }
        if !changed {
            check()?;
            return Ok(());
        }
        self.package_charge(&transaction, tenant, before, 0, 0)?;
        Self::record_revision(&transaction, revision, &["package_revisions"])?;
        check()?;
        self.commit_metadata(transaction, "commit package installation")?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub(super) fn package_next(&self, reader: &Connection) -> Result<u64> {
        Self::read_meta_from(reader, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the package commit revision is exhausted"))
    }

    pub(super) fn package_bytes(reader: &Connection, tenant: [u8; 16]) -> Result<i64> {
        reader
            .query_row(
                &format!(
                    "SELECT COALESCE(SUM(bytes), 0)::BIGINT FROM ({}) WHERE tenant_id = ?",
                    Self::PACKAGE_CHARGES
                ),
                params![tenant.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count package charges",
            })
    }

    pub(super) fn package_charge(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        before: i64,
        extra: i64,
        results: i64,
    ) -> Result<()> {
        let bytes = Self::package_bytes(transaction, tenant)? - before + extra;
        if bytes == 0 && results == 0 {
            return self.check_logical(transaction, tenant, false);
        }
        super::super::quota::UsageChange {
            bytes,
            results,
            ..Default::default()
        }
        .apply(transaction, &tenant)?;
        self.check_logical(transaction, tenant, false)
    }
}
