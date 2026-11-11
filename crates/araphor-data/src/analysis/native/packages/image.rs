use araphor_discovery_definition::ImagePin;
use serde::Deserialize;

use super::{PackageRecord, PackageRevisionV1, Records};
use crate::{
    analysis::native::{DataView, DataWrite, NativeStore},
    AnalysisConflictSnafu, AnalysisReadControl, NativeStateSnafu, PackageBundle, PackageBundleV1,
    PackageErrorCodeV1 as Code, PackageRefV1, Result,
};

#[derive(Deserialize)]
pub(super) struct ImageRecord {
    pub(super) tenant: [u8; 16],
    pub(super) root: PackageRefV1,
    pub(super) digest: String,
    pub(super) revision: u64,
    pub(super) installed: bool,
}

impl ImageRecord {
    pub(super) fn read(
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<Self>> {
        let identity = PackageRecord::identity(tenant, package, Some(revision))?;
        let Some(id) = Records::find(&identity, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::payload(&Records::key(b'I', id), get)? else {
            return Ok(None);
        };
        let record: Self = Records::decode(&bytes)?;
        if record.tenant != tenant
            || record.root.package_id != package
            || record.root.revision != revision
            || record.revision == 0
        {
            return NativeStateSnafu {
                field: "image record identity",
            }
            .fail();
        }
        Ok(Some(record))
    }

    pub(super) fn matches(&self, pin: &ImagePin, installed: bool) -> bool {
        self.root == pin.image && self.digest == pin.digest && (!installed || self.installed)
    }
}

impl NativeStore {
    pub fn install_package_image(
        &self,
        tenant: [u8; 16],
        bundle: &PackageBundle,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        let revisions = PackageRevisionV1::from_bundle(bundle, tenant)?;
        let root = &bundle.bundle().root;
        let mut tx = self.write()?;
        let existing = ImageRecord::read(tenant, &root.package_id, &root.revision, |key| {
            Records::staged(key, &tx.transaction)
        })?;
        if existing
            .as_ref()
            .is_some_and(|row| row.digest != bundle.digest())
        {
            return AnalysisConflictSnafu.fail();
        }
        tx.stage_packages(&revisions)?;
        if let Some(row) = existing.filter(|row| row.installed) {
            if tx.dirty {
                return crate::Error::reject_path(
                    &self.root,
                    "the installed image closure is absent",
                );
            }
            check()?;
            return Ok(row.revision);
        }
        let identity = PackageRecord::identity(tenant, &root.package_id, Some(&root.revision))?;
        let id = Records::intern(&mut tx.transaction, &identity)?;
        let bytes = Records::encode(&(tenant, root, bundle.digest(), tx.revision, true))?;
        Records::stage(&mut tx.transaction, Records::key(b'I', id), bytes);
        let name = PackageRecord::identity(tenant, &root.package_id, None)?;
        let name = Records::intern(&mut tx.transaction, &name)?;
        tx.transaction
            .insert(Records::key(b'A', name), id.to_be_bytes());
        tx.dirty = true;
        let revision = tx.revision;
        check()?;
        tx.commit([])?;
        Ok(revision)
    }
}

impl NativeStore {
    pub fn package_image(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        control.check()?;
        let _permit = self.reserve_reader()?;
        self.view()?
            .package_image(tenant, package, revision, control)
    }

    pub fn retained_package_image(
        &self,
        tenant: [u8; 16],
        pin: &ImagePin,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        control.check()?;
        let _permit = self.reserve_reader()?;
        self.view()?.retained_package_image(tenant, pin, control)
    }
}

impl DataView {
    pub fn package_image(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        control.check()?;
        let row = if let Some(revision) = revision {
            ImageRecord::read(tenant, package, revision, |key| {
                Records::read(key, &self.snapshot)
            })?
        } else {
            let identity = PackageRecord::identity(tenant, package, None)?;
            let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))?
            else {
                return Ok(None);
            };
            let Some(id) = Records::read(&Records::key(b'A', id), &self.snapshot)? else {
                return Ok(None);
            };
            let id = NativeStore::number(&id)?;
            let bytes = Records::payload(&Records::key(b'I', id), |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "image head record",
                }
                .build()
            })?;
            let row: ImageRecord = Records::decode(&bytes)?;
            if row.tenant != tenant || row.root.package_id != package {
                return NativeStateSnafu {
                    field: "image head identity",
                }
                .fail();
            }
            Some(row)
        };
        row.filter(|row| row.installed)
            .map(|row| self.image_bundle(row, control))
            .transpose()
    }

    pub fn retained_package_image(
        &self,
        tenant: [u8; 16],
        pin: &ImagePin,
        control: &AnalysisReadControl,
    ) -> Result<Option<PackageBundle>> {
        control.check()?;
        pin.validate()?;
        let Some(row) =
            ImageRecord::read(tenant, &pin.image.package_id, &pin.image.revision, |key| {
                Records::read(key, &self.snapshot)
            })?
        else {
            return Ok(None);
        };
        if !row.matches(pin, false) {
            return Err(Code::Conflict.error("retained image pin"));
        }
        self.image_bundle(row, control).map(Some)
    }

    pub(super) fn image_bundle(
        &self,
        row: ImageRecord,
        control: &AnalysisReadControl,
    ) -> Result<PackageBundle> {
        row.check_revision(self.metadata_revision)?;
        let artifacts = self.package_closure(row.tenant, &row.root, control)?;
        let bundle = row.bundle(artifacts)?;
        control.check()?;
        Ok(bundle)
    }

    fn package_closure(
        &self,
        tenant: [u8; 16],
        root: &PackageRefV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<crate::PackageArtifactV1>> {
        PackageRevisionV1::closure(tenant, root, control, |tenant, package, revision| {
            self.package_revision(tenant, package, revision, control)
        })
        .map(|(_, artifacts)| artifacts)
    }
}

impl ImageRecord {
    fn check_revision(&self, head: u64) -> Result<()> {
        if self.revision == 0 || self.revision > head {
            return NativeStateSnafu {
                field: "image record revision",
            }
            .fail();
        }
        Ok(())
    }

    fn bundle(self, artifacts: Vec<crate::PackageArtifactV1>) -> Result<PackageBundle> {
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: self.root,
            artifacts,
        };
        PackageBundle::checked(bundle, &self.digest)
            .map_err(crate::Error::from)
            .map_err(crate::Error::stored_artifact)?
            .ok_or_else(|| {
                Code::Invalid
                    .error("retained image digest")
                    .stored_artifact()
            })
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn retained_package_image(
        &self,
        tenant: [u8; 16],
        pin: &ImagePin,
    ) -> Result<Option<PackageBundle>> {
        pin.validate()?;
        let Some(row) =
            ImageRecord::read(tenant, &pin.image.package_id, &pin.image.revision, |key| {
                Records::staged(key, &self.transaction)
            })?
        else {
            return Ok(None);
        };
        if !row.matches(pin, false) {
            return Err(Code::Conflict.error("retained image pin"));
        }
        row.check_revision(self.metadata_revision)?;
        let (_, artifacts) = PackageRevisionV1::closure(
            tenant,
            &row.root,
            &AnalysisReadControl::default(),
            |tenant, package, revision| self.package_revision(tenant, package, revision),
        )?;
        row.bundle(artifacts).map(Some)
    }

    pub(in crate::analysis::native) fn installed_image(
        &self,
        tenant: [u8; 16],
        pin: &ImagePin,
    ) -> Result<bool> {
        let row = ImageRecord::read(tenant, &pin.image.package_id, &pin.image.revision, |key| {
            Records::staged(key, &self.transaction)
        })?;
        Ok(row.is_some_and(|row| row.matches(pin, true)))
    }
}
