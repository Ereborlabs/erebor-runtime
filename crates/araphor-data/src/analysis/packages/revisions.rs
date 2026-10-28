use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::PackageRevisionV1;
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub fn install_package(
        &self,
        revisions: &[PackageRevisionV1],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if revisions.is_empty() {
            return self.reject("the package closure is empty");
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
                || !keys.insert((&package.package_id, &package.revision))
            {
                return self.reject("the package closure is invalid");
            }
        }
        for package in revisions {
            package.decode_artifact()?;
        }
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package installation",
            })?;
        let revision = self.package_next(&transaction)?;
        let changed = self.insert_package_revisions(&transaction, revisions, revision)?;
        if !changed {
            check()?;
            return Ok(());
        }
        self.check_revision_limits(&transaction, tenant)?;
        Self::record_revision(&transaction, revision, &["package_revisions"])?;
        check()?;
        self.commit_metadata(transaction, "commit package installation")?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub fn package_revision(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<PackageRevisionV1>> {
        self.read_snapshot(|reader| Self::package_from(reader, tenant, package, revision))
    }

    pub fn package_revision_until(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        control: &crate::AnalysisReadControl,
    ) -> Result<Option<PackageRevisionV1>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::package_from(reader, tenant, package, revision)
        })
    }

    pub(in crate::analysis) fn package_from(
        reader: &Connection,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<PackageRevisionV1>> {
        let row = reader
            .query_row(
                "SELECT descriptor, artifact, dependencies FROM package_revisions
             WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![tenant.as_slice(), package, revision],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read package revision",
            })?;
        row.map(|(descriptor, artifact, dependencies)| {
            Ok(PackageRevisionV1 {
                tenant_id: tenant,
                package_id: package.into(),
                revision: revision.into(),
                descriptor,
                artifact,
                dependencies: serde_json::from_str(&dependencies).context(JsonSnafu {
                    path: "<package-dependencies>",
                })?,
            })
        })
        .transpose()
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn package_revisions(&self, tenant: [u8; 16]) -> Result<Vec<PackageRevisionV1>> {
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare(
                    "SELECT package_id, revision FROM package_revisions WHERE tenant_id = ?
                 ORDER BY package_id, revision",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare package list",
                })?;
            let keys = statement
                .query_map(params![tenant.as_slice()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "list package revisions",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode package list",
                })?;
            keys.into_iter()
                .map(|(package, revision)| {
                    Self::package_from(reader, tenant, &package, &revision)?
                        .ok_or_else(|| self.state_error("the selected package revision is absent"))
                })
                .collect()
        })
    }

    pub(super) fn insert_package_revisions(
        &self,
        transaction: &Connection,
        revisions: &[PackageRevisionV1],
        revision: u64,
    ) -> Result<bool> {
        let mut changed = false;
        for package in revisions {
            if let Some(existing) = Self::package_from(
                transaction,
                package.tenant_id,
                &package.package_id,
                &package.revision,
            )? {
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
                    "INSERT INTO package_revisions (tenant_id, package_id, revision, descriptor, artifact, dependencies, commit_revision)
                    VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        package.tenant_id.as_slice(),
                        package.package_id,
                        package.revision,
                        package.descriptor,
                        package.artifact,
                        dependencies,
                        revision
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
                    transaction,
                    package.tenant_id,
                    &dependency.package_id,
                    &dependency.revision,
                )?
                .is_none()
                {
                    return self.reject("the locked package dependency is absent");
                }
            }
        }
        Ok(changed)
    }

    pub(in crate::analysis) fn package_next(&self, reader: &Connection) -> Result<u64> {
        Self::read_meta_from(reader, &self.root)?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the package commit revision is exhausted"))
    }
}
