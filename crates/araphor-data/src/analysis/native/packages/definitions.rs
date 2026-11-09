use araphor_discovery_definition::ResolvedDefinition;
use serde::Deserialize;
use snafu::ResultExt as _;

use super::{image::ImageRecord, Records};
use crate::{
    analysis::native::{DataView, DataWrite, NativeStore},
    AnalysisReadControl, ManagedEncodingSnafu, NativeStorageSnafu, PackageErrorCodeV1 as Code,
    Result,
};

#[derive(Deserialize)]
pub(super) struct DefinitionRecord {
    pub(super) tenant: [u8; 16],
    pub(super) bytes: Vec<u8>,
    pub(super) revision: u64,
}

impl DefinitionRecord {
    pub(super) fn identity(tenant: [u8; 16], name: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'D', tenant, name)).context(ManagedEncodingSnafu)
    }

    pub(super) fn key(id: u64, revision: u64) -> Vec<u8> {
        [Records::key(b'D', id), revision.to_be_bytes().to_vec()].concat()
    }

    pub(super) fn definition(&self, head: u64) -> Result<ResolvedDefinition> {
        let definition = ResolvedDefinition::from_bytes(&self.bytes)?;
        if self.tenant == [0; 16]
            || self.revision == 0
            || self.revision > head
            || definition.encode()? != self.bytes
        {
            return Err(Code::Invalid.error("retained definition identity"));
        }
        Ok(definition)
    }

    fn matches(&self, tenant: [u8; 16], bytes: &[u8], revision: u64, head: u64) -> Result<bool> {
        if self.bytes != bytes {
            return Ok(false);
        }
        if self.tenant != tenant
            || self.revision == 0
            || self.revision > head
            || self.revision != revision
        {
            return Err(Code::Invalid.error("retained definition identity"));
        }
        Ok(true)
    }

    fn find(
        id: u64,
        tenant: [u8; 16],
        bytes: &[u8],
        head: u64,
        entries: fjall::BranchIterator,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        control: &AnalysisReadControl,
    ) -> Result<Option<u64>> {
        let latest = get(&Records::key(b'F', id))?
            .ok_or_else(|| Code::Invalid.error("retained definition head"))?;
        let latest = NativeStore::number(&latest)?;
        if latest == 0 || latest > head {
            return Err(Code::Invalid.error("retained definition head"));
        }
        let payload = Records::payload(&Self::key(id, latest), &mut get)?
            .ok_or_else(|| Code::Invalid.error("retained definition head"))?;
        let row: Self = Records::decode(&payload)?;
        if row.matches(tenant, bytes, latest, head)? {
            control.check()?;
            return Ok(Some(latest));
        }
        let prefix = Records::key(b'D', id);
        let mut selected = None;
        for entry in entries {
            control.check()?;
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "find definition",
            })?;
            if key.len() != prefix.len() + 8 {
                continue;
            }
            let revision = NativeStore::number(&key[prefix.len()..])?;
            if revision == latest {
                continue;
            }
            let payload = Records::payload(&key, &mut get)?
                .ok_or_else(|| Code::Invalid.error("retained definition identity"))?;
            let row: Self = Records::decode(&payload)?;
            if row.matches(tenant, bytes, revision, head)?
                && selected.replace(row.revision).is_some()
            {
                return Err(Code::Invalid.error("retained definition identity"));
            }
        }
        control.check()?;
        Ok(selected)
    }
}

impl NativeStore {
    pub fn admit_definition(
        &self,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("definition tenant"));
        }
        definition.validate()?;
        let bytes = definition.encode()?;
        let mut tx = self.write()?;
        for pin in &definition.images {
            let image =
                ImageRecord::read(tenant, &pin.image.package_id, &pin.image.revision, |key| {
                    Records::staged(key, &tx.transaction)
                })?;
            if image.is_none_or(|image| !image.matches(pin, true)) {
                return Err(Code::Missing.error("definition image"));
            }
        }
        let identity = DefinitionRecord::identity(tenant, &definition.definition.name)?;
        if let Some(id) = Records::find(&identity, |key| Records::staged(key, &tx.transaction))? {
            let prefix = Records::key(b'D', id);
            if let Some(revision) = DefinitionRecord::find(
                id,
                tenant,
                &bytes,
                tx.metadata_revision,
                tx.transaction.prefix(&prefix),
                |key| Records::staged(key, &tx.transaction),
                &AnalysisReadControl::default(),
            )? {
                check()?;
                return Ok(revision);
            }
        }
        let id = Records::intern(&mut tx.transaction, &identity)?;
        let revision = tx.revision;
        let payload = Records::encode(&(tenant, &bytes, revision))?;
        Records::stage(
            &mut tx.transaction,
            DefinitionRecord::key(id, revision),
            payload,
        );
        tx.transaction
            .insert(Records::key(b'F', id), revision.to_be_bytes());
        tx.dirty = true;
        check()?;
        tx.commit([])?;
        Ok(revision)
    }
}

impl DataView {
    pub fn definition(
        &self,
        tenant: [u8; 16],
        name: &str,
        revision: Option<u64>,
        control: &AnalysisReadControl,
    ) -> Result<Option<(ResolvedDefinition, u64)>> {
        control.check()?;
        if tenant == [0; 16] || revision == Some(0) {
            return Err(Code::Invalid.error("definition reference"));
        }
        let identity = DefinitionRecord::identity(tenant, name)?;
        let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))? else {
            return Ok(None);
        };
        let revision = if let Some(revision) = revision {
            revision
        } else {
            let Some(bytes) = Records::read(&Records::key(b'F', id), &self.snapshot)? else {
                return Ok(None);
            };
            NativeStore::number(&bytes)?
        };
        let Some(definition) =
            DefinitionRecord::read(id, tenant, name, revision, self.metadata_revision, |key| {
                Records::read(key, &self.snapshot)
            })?
        else {
            return Ok(None);
        };
        self.definition_images(tenant, &definition)?;
        control.check()?;
        Ok(Some((definition, revision)))
    }

    pub fn definition_revision(
        &self,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Option<u64>> {
        control.check()?;
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("definition tenant"));
        }
        let bytes = definition.encode()?;
        let identity = DefinitionRecord::identity(tenant, &definition.definition.name)?;
        let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))? else {
            return Ok(None);
        };
        let prefix = Records::key(b'D', id);
        let found = DefinitionRecord::find(
            id,
            tenant,
            &bytes,
            self.metadata_revision,
            self.snapshot.prefix(&prefix),
            |key| Records::read(key, &self.snapshot),
            control,
        )?;
        if found.is_some() {
            self.definition_images(tenant, definition)?;
        }
        control.check()?;
        Ok(found)
    }

    pub(super) fn definition_images(
        &self,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
    ) -> Result<()> {
        for pin in &definition.images {
            let image =
                ImageRecord::read(tenant, &pin.image.package_id, &pin.image.revision, |key| {
                    Records::read(key, &self.snapshot)
                })?;
            if image.is_none_or(|image| !image.matches(pin, false)) {
                return Err(Code::Missing.error("definition image"));
            }
        }
        Ok(())
    }
}

impl DefinitionRecord {
    fn read(
        id: u64,
        tenant: [u8; 16],
        name: &str,
        revision: u64,
        head: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<ResolvedDefinition>> {
        let Some(bytes) = Records::payload(&Self::key(id, revision), get)? else {
            return Ok(None);
        };
        let row: Self = Records::decode(&bytes)?;
        let definition = row.definition(head)?;
        if row.tenant != tenant || row.revision != revision || definition.definition.name != name {
            return Err(Code::Invalid.error("retained definition identity"));
        }
        Ok(Some(definition))
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn definition(
        &self,
        tenant: [u8; 16],
        name: &str,
        revision: u64,
    ) -> Result<Option<ResolvedDefinition>> {
        let identity = DefinitionRecord::identity(tenant, name)?;
        let Some(id) = Records::find(&identity, |key| Records::staged(key, &self.transaction))?
        else {
            return Ok(None);
        };
        DefinitionRecord::read(id, tenant, name, revision, self.metadata_revision, |key| {
            Records::staged(key, &self.transaction)
        })
    }
}
