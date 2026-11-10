use std::collections::{BTreeMap, BTreeSet, VecDeque};

use araphor_discovery_definition::ImagePin;
use snafu::ResultExt as _;

use super::{
    catalogue::PackageHeader, definitions::DefinitionRecord, image::ImageRecord, PackageRecord,
    Records,
};
use crate::analysis::native::{
    context::ContextRecord, managed::VersionRecord, DataWrite, NativeStore,
};
use crate::{
    NativeStateSnafu, NativeStorageSnafu, PackageErrorCodeV1 as Code, PackageRefV1, Result,
};

impl NativeStore {
    pub fn uninstall_package_image(
        &self,
        tenant: [u8; 16],
        expected: &ImagePin,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        expected.validate()?;
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("image uninstall tenant"));
        }
        let mut tx = self.write()?;
        let image = &expected.image;
        let existing = ImageRecord::read(tenant, &image.package_id, &image.revision, |key| {
            Records::staged(key, &tx.transaction)
        })?;
        if existing
            .as_ref()
            .is_some_and(|row| row.digest != expected.digest)
        {
            return Err(Code::Conflict.error("image uninstall pin"));
        }
        let Some(row) = existing.filter(|row| row.installed) else {
            check()?;
            return Ok(false);
        };
        let id = tx.package_id(tenant, &row.root)?;
        Records::stage(
            &mut tx.transaction,
            Records::key(b'I', id),
            Records::encode(&(row.tenant, &row.root, &row.digest, tx.revision, false))?,
        );
        tx.dirty = true;
        tx.image_head(tenant, &image.package_id)?;
        tx.collect_packages(Some(id))?;
        check()?;
        tx.commit([])?;
        Ok(true)
    }

    pub fn collect_package_admissions(&self) -> Result<()> {
        let mut tx = self.write()?;
        tx.collect_packages(None)?;
        tx.commit([])?;
        Ok(())
    }

    pub fn collect_package(&self, tenant: [u8; 16], package: &str, revision: &str) -> Result<()> {
        let mut tx = self.write()?;
        let identity = PackageRecord::identity(tenant, package, Some(revision))?;
        let Some(id) = Records::find(&identity, |key| Records::staged(key, &tx.transaction))?
        else {
            return Ok(());
        };
        tx.collect_packages(Some(id))?;
        tx.commit([])?;
        Ok(())
    }
}

impl DataWrite<'_> {
    fn package_id(&self, tenant: [u8; 16], package: &PackageRefV1) -> Result<u64> {
        let identity =
            PackageRecord::identity(tenant, &package.package_id, Some(&package.revision))?;
        Records::find(&identity, |key| Records::staged(key, &self.transaction))?
            .ok_or_else(|| Code::Missing.error("retained package identity"))
    }

    fn image_head(&mut self, tenant: [u8; 16], package: &str) -> Result<()> {
        let mut winner = None;
        for entry in self.transaction.prefix(b"\0data/I") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "select installed image head",
            })?;
            if key.len() != 15 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("retained image"))?;
            let row: ImageRecord = Records::decode(&bytes)?;
            if row.installed && row.tenant == tenant && row.root.package_id == package {
                let candidate = (
                    row.revision,
                    row.root.revision,
                    NativeStore::number(&key[7..])?,
                );
                if winner.as_ref().is_none_or(|current| candidate > *current) {
                    winner = Some(candidate);
                }
            }
        }
        let identity = PackageRecord::identity(tenant, package, None)?;
        let name = Records::find(&identity, |key| Records::staged(key, &self.transaction))?
            .ok_or_else(|| Code::Missing.error("image head identity"))?;
        if let Some((_, _, id)) = winner {
            self.transaction
                .insert(Records::key(b'A', name), id.to_be_bytes());
        } else {
            self.transaction.remove(Records::key(b'A', name));
        }
        Ok(())
    }

    fn package_roots(&self) -> Result<BTreeSet<u64>> {
        let mut roots = BTreeSet::new();
        for entry in self.transaction.prefix(b"\0data/I") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read installed package roots",
            })?;
            if key.len() != 15 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("retained image"))?;
            let row: ImageRecord = Records::decode(&bytes)?;
            if row.installed {
                roots.insert(NativeStore::number(&key[7..])?);
            }
        }
        for id in self.context_owner_ids("native-package-v1")? {
            let key = Records::key(b'C', id);
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("retained context"))?;
            let row: ContextRecord = Records::decode(&bytes)?;
            if row.version.key.owner_id == "native-package-v1" {
                let provenance = row
                    .version
                    .package_provenance()?
                    .ok_or_else(|| Code::Missing.error("native package context"))?;
                roots.insert(self.package_id(row.version.key.tenant_id, &provenance.root)?);
            }
        }
        for entry in self.transaction.prefix(b"\0data/D") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read definition package roots",
            })?;
            if key.len() != 23 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("retained definition"))?;
            let row: DefinitionRecord = Records::decode(&bytes)?;
            for pin in row.definition(self.metadata_revision)?.images {
                roots.insert(self.package_id(row.tenant, &pin.image)?);
            }
        }
        for entry in self.transaction.prefix(b"\0data/Z") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read managed package roots",
            })?;
            if key.len() != 23 {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("retained managed version"))?;
            let row: VersionRecord = Records::decode(&bytes)?;
            for pin in &row.spec.definition.images {
                roots.insert(self.package_id(row.spec.tenant, &pin.image)?);
            }
        }
        Ok(roots)
    }

    fn collect_packages(&mut self, target: Option<u64>) -> Result<()> {
        let roots = self.package_roots()?;
        let mut packages = BTreeMap::new();
        for entry in self.transaction.prefix(PackageHeader::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read package collection headers",
            })?;
            if key.len() != PackageHeader::PREFIX.len() + 8 {
                continue;
            }
            let id = NativeStore::number(&key[PackageHeader::PREFIX.len()..])?;
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("package collection header"))?;
            let header: PackageHeader = Records::decode(&bytes)?;
            if self.package_id(header.tenant, &header.root)? != id
                || header.revision == 0
                || header.revision > self.revision
            {
                return NativeStateSnafu {
                    field: "package collection identity",
                }
                .fail();
            }
            packages.insert(id, header);
        }
        let mut incoming = packages
            .keys()
            .map(|id| (*id, 0usize))
            .collect::<BTreeMap<_, _>>();
        for header in packages.values() {
            for dependency in &header.dependencies {
                let count = incoming
                    .get_mut(dependency)
                    .ok_or_else(|| Code::Missing.error("package collection dependency"))?;
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| Code::Invalid.error("package reference count"))?;
            }
        }
        if roots.iter().any(|id| !packages.contains_key(id)) {
            return Err(Code::Missing.error("package collection root"));
        }
        let mut pending = match target {
            Some(id) => VecDeque::from([id]),
            None => packages.keys().copied().collect(),
        };
        while let Some(id) = pending.pop_front() {
            if roots.contains(&id) || incoming.get(&id).is_none_or(|count| *count != 0) {
                continue;
            }
            let Some(header) = packages.remove(&id) else {
                continue;
            };
            Records::remove(&mut self.transaction, Records::key(b'P', id))?;
            Records::remove(&mut self.transaction, PackageRecord::body_key(id))?;
            Records::remove(&mut self.transaction, Records::key(b'I', id))?;
            Records::remove(&mut self.transaction, PackageHeader::key(id))?;
            self.dirty = true;
            for dependency in header.dependencies {
                let count = incoming
                    .get_mut(&dependency)
                    .ok_or_else(|| Code::Missing.error("package collection dependency"))?;
                *count = count
                    .checked_sub(1)
                    .ok_or_else(|| Code::Invalid.error("package reference count"))?;
                if *count == 0 {
                    pending.push_back(dependency);
                }
            }
        }
        Ok(())
    }
}
