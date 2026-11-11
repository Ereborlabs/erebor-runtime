use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{records::Records, DataView, DataWrite, NativeStore};
use crate::{AnalysisConflictSnafu, ManagedEncodingSnafu, NativeStateSnafu, Result};

use crate::analysis::PackageRevisionV1;

mod catalogue;
mod collection;
mod definitions;
mod image;
mod recovery;

#[derive(Deserialize, Serialize)]
struct PackageRecord {
    value: PackageRevisionV1,
    revision: u64,
    body_bytes: u64,
}

impl PackageRecord {
    const BODY: &'static [u8] = b"\0data/@package-body/";

    fn body_key(id: u64) -> Vec<u8> {
        [Self::BODY, &id.to_be_bytes()].concat()
    }

    fn body_keys(&self, id: u64) -> impl Iterator<Item = Vec<u8>> {
        let key = Self::body_key(id);
        let fragments = if self.body_bytes >= u64::from(u32::MAX) {
            self.body_bytes.div_ceil(u64::from(u32::MAX))
        } else {
            0
        };
        std::iter::once(key.clone()).chain(
            (0..fragments).map(move |slot| [key.as_slice(), &slot.to_be_bytes()[..]].concat()),
        )
    }

    fn check(&self) -> Result<()> {
        if self.revision == 0 || self.body_bytes == 0 || !self.value.artifact.is_empty() {
            return NativeStateSnafu {
                field: "package metadata header",
            }
            .fail();
        }
        Ok(())
    }

    fn body(
        &self,
        id: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let body =
            Records::charged_payload(&Self::body_key(id), get, charge)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "package artifact body",
                }
                .build()
            })?;
        if body.len() as u64 != self.body_bytes {
            return NativeStateSnafu {
                field: "package artifact length",
            }
            .fail();
        }
        Ok(body)
    }
    fn identity(tenant: [u8; 16], package: &str, revision: Option<&str>) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'P', tenant, package, revision)).context(ManagedEncodingSnafu)
    }

    fn read(
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<Self>> {
        Self::read_charged(tenant, package, revision, get, &mut |_| Ok(()))
    }

    fn read_charged(
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        let Some((id, mut record)) =
            Self::read_header(tenant, package, revision, &mut get, charge)?
        else {
            return Ok(None);
        };
        record.value.artifact = record.body(id, get, charge)?;
        Ok(Some(record))
    }

    fn read_header(
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let identity = Self::identity(tenant, package, Some(revision))?;
        let Some(id) = Records::find(&identity, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(&Records::key(b'P', id), get, charge)? else {
            return Ok(None);
        };
        let record: Self = Records::decode(&bytes)?;
        record.check()?;
        if record.value.tenant_id != tenant
            || record.value.package_id != package
            || record.value.revision != revision
            || record.revision == 0
        {
            return NativeStateSnafu {
                field: "package record identity",
            }
            .fail();
        }
        Ok(Some((id, record)))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn package_descriptor_charged(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        let row = PackageRecord::read_header(
            tenant,
            package,
            revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?;
        if row
            .as_ref()
            .is_some_and(|(_, row)| row.revision > self.metadata_revision)
        {
            return NativeStateSnafu {
                field: "package record revision",
            }
            .fail();
        }
        Ok(row.map(|(_, row)| row.value.descriptor))
    }

    pub fn package_revision(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        control: &crate::AnalysisReadControl,
    ) -> Result<Option<PackageRevisionV1>> {
        self.package_revision_charged(tenant, package, revision, control, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn package_revision_charged(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
        control: &crate::AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<PackageRevisionV1>> {
        control.check()?;
        let record = PackageRecord::read_charged(
            tenant,
            package,
            revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?;
        if record
            .as_ref()
            .is_some_and(|row| row.revision > self.metadata_revision)
        {
            return NativeStateSnafu {
                field: "package record revision",
            }
            .fail();
        }
        control.check()?;
        Ok(record.map(|record| record.value))
    }
}

impl NativeStore {
    pub fn install_package(
        &self,
        revisions: &[PackageRevisionV1],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        PackageRevisionV1::validate_installation(revisions, &self.root)?;
        let mut tx = self.write()?;
        tx.stage_packages(revisions)?;
        check()?;
        tx.commit([])?;
        Ok(())
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn package_descriptor(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<Vec<u8>>> {
        let row = PackageRecord::read_header(
            tenant,
            package,
            revision,
            |key| Records::staged(key, &self.transaction),
            &mut |_| Ok(()),
        )?;
        if row
            .as_ref()
            .is_some_and(|(_, row)| row.revision > self.metadata_revision)
        {
            return NativeStateSnafu {
                field: "package record revision",
            }
            .fail();
        }
        Ok(row.map(|(_, row)| row.value.descriptor))
    }

    pub(super) fn package_revision(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<PackageRevisionV1>> {
        let row = PackageRecord::read(tenant, package, revision, |key| {
            Records::staged(key, &self.transaction)
        })?;
        if row
            .as_ref()
            .is_some_and(|row| row.revision > self.metadata_revision)
        {
            return NativeStateSnafu {
                field: "package record revision",
            }
            .fail();
        }
        Ok(row.map(|row| row.value))
    }

    fn stage_packages(&mut self, revisions: &[PackageRevisionV1]) -> Result<()> {
        for package in revisions {
            match PackageRecord::read(
                package.tenant_id,
                &package.package_id,
                &package.revision,
                |key| Records::staged(key, &self.transaction),
            )? {
                Some(record) if record.value != *package => return AnalysisConflictSnafu.fail(),
                Some(record) => {
                    catalogue::PackageHeader::check(&record.value, record.revision, |key| {
                        Records::staged(key, &self.transaction)
                    })?;
                    continue;
                }
                None => {}
            }
            let identity = PackageRecord::identity(
                package.tenant_id,
                &package.package_id,
                Some(&package.revision),
            )?;
            let id = Records::intern(&mut self.transaction, &identity)?;
            let record = PackageRecord {
                value: PackageRevisionV1 {
                    tenant_id: package.tenant_id,
                    package_id: package.package_id.clone(),
                    revision: package.revision.clone(),
                    descriptor: package.descriptor.clone(),
                    artifact: Vec::new(),
                    dependencies: package.dependencies.clone(),
                },
                revision: self.revision,
                body_bytes: package.artifact.len() as u64,
            };
            let bytes = Records::encode(&record)?;
            Records::stage(&mut self.transaction, Records::key(b'P', id), bytes);
            let mut body = Vec::with_capacity(package.artifact.len() + 1);
            body.push(0);
            body.extend_from_slice(&package.artifact);
            Records::stage(&mut self.transaction, PackageRecord::body_key(id), body);
            let header =
                catalogue::PackageHeader::from_package(package, self.revision, |dependency| {
                    Records::intern(&mut self.transaction, dependency)
                })?;
            Records::stage(
                &mut self.transaction,
                catalogue::PackageHeader::key(id),
                Records::encode(&header)?,
            );
            self.dirty = true;
        }
        for package in revisions {
            for dependency in &package.dependencies {
                if PackageRecord::read(
                    package.tenant_id,
                    &dependency.package_id,
                    &dependency.revision,
                    |key| Records::staged(key, &self.transaction),
                )?
                .is_none()
                {
                    return crate::Error::reject_path(
                        &self.store.root,
                        "the locked package dependency is absent",
                    );
                }
            }
        }
        Ok(())
    }
}
