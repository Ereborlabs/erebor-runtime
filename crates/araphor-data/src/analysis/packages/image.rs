use std::collections::BTreeSet;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::PackageRevisionV1;
use crate::{
    AnalysisConflictSnafu, AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore,
    PackageBundle, PackageBundleV1, PackageErrorCodeV1 as Code, PackageRefV1, Result,
};

impl AnalysisStore {
    pub fn install_package_image(
        &self,
        tenant: [u8; 16],
        bundle: &PackageBundle,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        let revisions = PackageRevisionV1::from_bundle(bundle, tenant)?;
        let digest = bundle.digest();
        let bundle = bundle.bundle();
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
            false,
        )?;
        if existing
            .as_ref()
            .is_some_and(|(_, saved, _, _)| saved.as_str() != digest)
        {
            return AnalysisConflictSnafu.fail();
        }
        let revision = self.package_next(&transaction)?;
        let changed = self.insert_package_revisions(&transaction, &revisions, revision)?;
        if let Some((_, _, installed, true)) = existing {
            if changed {
                return self.reject("the installed image closure is absent");
            }
            check()?;
            return Ok(installed);
        }
        transaction
            .execute(
                "INSERT INTO package_images (tenant_id, package_id, revision, digest, commit_revision, installed)
                 VALUES (?, ?, ?, ?, ?, true) ON CONFLICT (tenant_id, package_id, revision)
                 DO UPDATE SET installed = true, commit_revision = excluded.commit_revision",
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
        self.check_revision_limits(&transaction, tenant)?;
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
    ) -> Result<Option<PackageBundle>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::package_image_from(reader, tenant, package, revision, control)
        })
    }

    pub fn uninstall_package_image(
        &self,
        tenant: [u8; 16],
        expected: &araphor_discovery_definition::ImagePin,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        expected.validate()?;
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("image uninstall tenant"));
        }
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin image uninstall",
            })?;
        let image = &expected.image;
        let existing = Self::package_image_record(
            &transaction,
            tenant,
            &image.package_id,
            Some(&image.revision),
            false,
        )?;
        if existing
            .as_ref()
            .is_some_and(|(_, digest, _, _)| digest != &expected.digest)
        {
            return Err(Code::Conflict.error("image uninstall pin"));
        }
        if existing.is_none_or(|(_, _, _, installed)| !installed) {
            check()?;
            return Ok(false);
        }
        let revision = self.package_next(&transaction)?;
        transaction.execute(
            "UPDATE package_images SET installed = false, commit_revision = ? WHERE tenant_id = ? AND package_id = ? AND revision = ? AND digest = ?",
            params![revision, tenant.as_slice(), image.package_id, image.revision, expected.digest],
        ).context(AnalysisDatabaseSnafu { operation: "uninstall exact image" })?;
        self.collect_package_rows(&transaction, tenant, &image.package_id, &image.revision)?;
        self.check_revision_limits(&transaction, tenant)?;
        Self::record_revision(
            &transaction,
            revision,
            &["package_images", "package_revisions"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit image uninstall")?;
        self.revision.send_replace(revision);
        Ok(true)
    }

    pub fn retained_package_image(
        &self,
        tenant: [u8; 16],
        pin: &araphor_discovery_definition::ImagePin,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::retained_package_image_from(reader, tenant, pin, control)
        })
    }

    pub(in crate::analysis) fn retained_package_image_from(
        reader: &Connection,
        tenant: [u8; 16],
        pin: &araphor_discovery_definition::ImagePin,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        pin.validate()?;
        let Some((_, digest, _, _)) = Self::package_image_record(
            reader,
            tenant,
            &pin.image.package_id,
            Some(&pin.image.revision),
            false,
        )?
        else {
            return Ok(None);
        };
        if digest != pin.digest {
            return Err(Code::Conflict.error("retained image pin"));
        }
        Self::package_image_bundle(reader, tenant, pin.image.clone(), &digest, control).map(Some)
    }

    fn package_image_record(
        reader: &Connection,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
        installed: bool,
    ) -> Result<Option<(String, String, u64, bool)>> {
        reader
            .query_row(
                "SELECT revision, digest, commit_revision, installed FROM package_images
                 WHERE tenant_id = ? AND package_id = ? AND (? OR revision = ?) AND (NOT ? OR installed)
                 ORDER BY commit_revision DESC, revision DESC LIMIT 1",
                params![
                    tenant.as_slice(),
                    package,
                    revision.is_none(),
                    revision.unwrap_or_default(),
                    installed,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
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
    ) -> Result<Option<PackageBundle>> {
        let Some((revision, digest, _, true)) =
            Self::package_image_record(reader, tenant, package, revision, true)?
        else {
            return Ok(None);
        };
        let root = PackageRefV1 {
            package_id: package.into(),
            revision,
        };
        Self::package_image_bundle(reader, tenant, root, &digest, control).map(Some)
    }

    fn package_image_bundle(
        reader: &Connection,
        tenant: [u8; 16],
        root: PackageRefV1,
        digest: &str,
        control: &AnalysisReadControl,
    ) -> Result<PackageBundle> {
        let artifacts = Self::package_artifacts_from(reader, tenant, &root, control)
            .map_err(crate::Error::stored_artifact)?;
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root,
            artifacts,
        };
        let bundle = PackageBundle::checked(bundle, digest)
            .map_err(crate::Error::from)
            .map_err(crate::Error::stored_artifact)?
            .ok_or_else(|| {
                Code::Invalid
                    .error("retained image digest")
                    .stored_artifact()
            })?;
        control.check()?;
        Ok(bundle)
    }

    pub(in crate::analysis) fn package_artifacts_from(
        reader: &Connection,
        tenant: [u8; 16],
        root: &PackageRefV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<crate::PackageArtifactV1>> {
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
            artifacts.push(
                retained
                    .decode_artifact()
                    .map_err(crate::Error::stored_artifact)?,
            );
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
        control.check()?;
        Ok(artifacts)
    }
}
