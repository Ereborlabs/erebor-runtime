use std::collections::BTreeSet;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::PackageRevisionV1;
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore,
    PackageBundleV1, PackageErrorCodeV1 as Code, PackageRefV1, Result,
};

impl AnalysisStore {
    pub fn install_package_image(
        &self,
        tenant: [u8; 16],
        bundle: &PackageBundleV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        let revisions = PackageRevisionV1::from_bundle(bundle, tenant)?;
        let digest = bundle.digest()?;
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin package image installation",
            })?;
        let existing = Self::package_image_record(
            &transaction,
            tenant,
            &bundle.root.package_id,
            Some(&bundle.root.revision),
        )?;
        if existing
            .as_ref()
            .is_some_and(|(_, saved, _)| *saved != digest)
        {
            return AnalysisConflictSnafu.fail();
        }
        let revision = self.package_next(&transaction)?;
        let changed = self.insert_package_revisions(&transaction, &revisions, revision)?;
        if let Some((_, _, installed)) = existing {
            if changed {
                return self.reject("the installed image closure is absent");
            }
            check()?;
            return Ok(installed);
        }
        transaction
            .execute(
                "INSERT INTO package_images (tenant_id, package_id, revision, digest, commit_revision)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    tenant.as_slice(),
                    bundle.root.package_id,
                    bundle.root.revision,
                    digest,
                    revision,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert package image",
            })?;
        self.check_logical(&transaction, tenant, false)?;
        Self::record_revision(
            &transaction,
            revision,
            if changed {
                &["package_revisions", "package_images"]
            } else {
                &["package_images"]
            },
        )?;
        check()?;
        self.commit_metadata(transaction, "commit package image installation")?;
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn package_image(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundleV1>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::package_image_from(reader, tenant, package, revision, control)
        })
    }

    fn package_image_record(
        reader: &Connection,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
    ) -> Result<Option<(String, String, u64)>> {
        reader
            .query_row(
                "SELECT revision, digest, commit_revision FROM package_images
                 WHERE tenant_id = ? AND package_id = ? AND (? OR revision = ?)
                 ORDER BY commit_revision DESC, revision DESC LIMIT 1",
                params![
                    tenant.as_slice(),
                    package,
                    revision.is_none(),
                    revision.unwrap_or_default(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read package image",
            })
    }

    pub(in crate::analysis) fn package_image_from(
        reader: &Connection,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundleV1>> {
        let Some((revision, digest, _)) =
            Self::package_image_record(reader, tenant, package, revision)?
        else {
            return Ok(None);
        };
        let root = PackageRefV1 {
            package_id: package.into(),
            revision,
        };
        let mut pending = vec![root.clone()];
        let mut seen = BTreeSet::new();
        let mut artifacts = Vec::new();
        while let Some(reference) = pending.pop() {
            control.check()?;
            if !seen.insert(reference.clone()) {
                continue;
            }
            let retained =
                Self::package_from(reader, tenant, &reference.package_id, &reference.revision)?
                    .ok_or_else(|| Code::Missing.error("installed image artifact"))?;
            artifacts.push(retained.decode_artifact()?);
            pending.extend(
                retained
                    .dependencies
                    .into_iter()
                    .map(|dependency| PackageRefV1 {
                        package_id: dependency.package_id,
                        revision: dependency.revision,
                    }),
            );
        }
        artifacts.sort_by_key(crate::PackageArtifactV1::reference);
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root,
            artifacts,
        };
        bundle.validate()?;
        if bundle.digest()? != digest {
            return Err(Code::Invalid.error("retained image digest"));
        }
        control.check()?;
        Ok(Some(bundle))
    }
}
