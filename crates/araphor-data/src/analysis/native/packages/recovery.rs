use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super::{definitions::DefinitionRecord, image::ImageRecord, PackageRecord, Records};
use crate::{
    analysis::native::{DataView, NativeStore},
    AnalysisReadControl, NativeStateSnafu, NativeStorageSnafu, Result,
};

impl DataView {
    pub(in crate::analysis::native) fn validate_catalogue(&self) -> Result<()> {
        let control = AnalysisReadControl::default();
        let mut images = BTreeMap::new();
        let mut definitions = BTreeMap::<Vec<u8>, u64>::new();
        let mut values = BTreeSet::new();
        for entry in self.snapshot.prefix(b"\0data/P") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate package catalogue",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "package record key",
                }
                .fail();
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "package record",
                    }
                    .build()
                })?;
            let row: PackageRecord = Records::decode(&bytes)?;
            let identity = PackageRecord::identity(
                row.value.tenant_id,
                &row.value.package_id,
                Some(&row.value.revision),
            )?;
            let id = Records::find(&identity, |key| Records::read(key, &self.snapshot))?;
            if row.revision == 0
                || row.revision > self.metadata_revision
                || id != Some(NativeStore::number(&key[7..])?)
            {
                return NativeStateSnafu {
                    field: "package record identity",
                }
                .fail();
            }
            row.value
                .decode_artifact()
                .map_err(crate::Error::stored_artifact)?;
            for dependency in &row.value.dependencies {
                if self
                    .package_revision(
                        row.value.tenant_id,
                        &dependency.package_id,
                        &dependency.revision,
                        &control,
                    )?
                    .is_none()
                {
                    return NativeStateSnafu {
                        field: "package dependency",
                    }
                    .fail();
                }
            }
        }
        for entry in self.snapshot.prefix(b"\0data/I") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate image catalogue",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "image record key",
                }
                .fail();
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "image record",
                    }
                    .build()
                })?;
            let row: ImageRecord = Records::decode(&bytes)?;
            let pin = araphor_discovery_definition::ImagePin {
                image: row.root.clone(),
                digest: row.digest.clone(),
            };
            pin.validate()?;
            let identity = PackageRecord::identity(
                row.tenant,
                &row.root.package_id,
                Some(&row.root.revision),
            )?;
            let id = Records::find(&identity, |key| Records::read(key, &self.snapshot))?;
            let package = PackageRecord::read(
                row.tenant,
                &row.root.package_id,
                &row.root.revision,
                |key| Records::read(key, &self.snapshot),
            )?;
            if row.tenant == [0; 16]
                || row.revision == 0
                || row.revision > self.metadata_revision
                || id != Some(NativeStore::number(&key[7..])?)
                || package.is_none_or(|package| package.revision > row.revision)
            {
                return NativeStateSnafu {
                    field: "image record identity",
                }
                .fail();
            }
            if row.installed {
                let name = PackageRecord::identity(row.tenant, &row.root.package_id, None)?;
                let name = Records::find(&name, |key| Records::read(key, &self.snapshot))?
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "image head identity",
                        }
                        .build()
                    })?;
                let candidate = (
                    row.revision,
                    row.root.revision.clone(),
                    NativeStore::number(&key[7..])?,
                );
                let entry = images
                    .entry(Records::key(b'A', name))
                    .or_insert_with(|| candidate.clone());
                if candidate > *entry {
                    *entry = candidate;
                }
            }
            self.image_bundle(row, &control)?;
        }
        for entry in self.snapshot.prefix(b"\0data/D") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate definition catalogue",
            })?;
            if key.len() == 31 {
                continue;
            }
            if key.len() != 23 {
                return NativeStateSnafu {
                    field: "definition record key",
                }
                .fail();
            }
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "definition record",
                    }
                    .build()
                })?;
            let row: DefinitionRecord = Records::decode(&bytes)?;
            let definition = row.definition(self.metadata_revision)?;
            let identity = DefinitionRecord::identity(row.tenant, &definition.definition.name)?;
            let id = Records::find(&identity, |key| Records::read(key, &self.snapshot))?;
            if row.revision != NativeStore::number(&key[15..])?
                || id != Some(NativeStore::number(&key[7..15])?)
            {
                return NativeStateSnafu {
                    field: "definition record identity",
                }
                .fail();
            }
            let head = definitions
                .entry(Records::key(b'F', NativeStore::number(&key[7..15])?))
                .or_default();
            *head = (*head).max(row.revision);
            self.definition_images(row.tenant, &definition)?;
            if !values.insert((NativeStore::number(&key[7..15])?, row.bytes)) {
                return NativeStateSnafu {
                    field: "duplicate definition",
                }
                .fail();
            }
        }
        self.validate_heads(
            b"\0data/A",
            images
                .into_iter()
                .map(|(key, (_, _, id))| (key, id))
                .collect(),
        )?;
        self.validate_heads(b"\0data/F", definitions)?;
        Ok(())
    }

    pub(in crate::analysis::native) fn validate_heads(
        &self,
        prefix: &[u8],
        mut expected: BTreeMap<Vec<u8>, u64>,
    ) -> Result<()> {
        for entry in self.snapshot.prefix(prefix) {
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "validate catalogue head",
            })?;
            if expected.remove(key.as_ref()) != Some(NativeStore::number(&value)?) {
                return NativeStateSnafu {
                    field: "catalogue head",
                }
                .fail();
            }
        }
        if !expected.is_empty() {
            return NativeStateSnafu {
                field: "catalogue head",
            }
            .fail();
        }
        Ok(())
    }
}
