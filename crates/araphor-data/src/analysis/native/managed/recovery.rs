use std::collections::{BTreeMap, BTreeSet};

use araphor_graph::native::Graph;
use snafu::ResultExt as _;

use super::{CallHead, InstanceRecord, ManagedGraph, Records, VersionRecord};
use crate::{
    analysis::native::{DataView, NativeStore},
    AnalysisReadControl, NativeStateSnafu, NativeStorageSnafu, Result,
};

impl DataView {
    pub(in crate::analysis::native) fn validate_managed(&self) -> Result<()> {
        let control = AnalysisReadControl::default();
        let mut owners = BTreeSet::new();
        let mut graphs = BTreeMap::new();
        for entry in self.snapshot.prefix(b"\0data/Z") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed versions",
            })?;
            if key.len() == 31 {
                continue;
            }
            if key.len() != 23 {
                return NativeStateSnafu {
                    field: "managed version key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..15])?;
            let generation = NativeStore::number(&key[15..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "managed version record",
                    }
                    .build()
                })?;
            let row: VersionRecord = Records::decode(&bytes)?;
            let tenant = row.spec.tenant;
            let name = row.spec.id.clone();
            let row = row.check(tenant, &name, generation, self.metadata_revision)?;
            if Records::find(
                &InstanceRecord::identity(row.spec.tenant, &row.spec.id)?,
                |key| Records::read(key, &self.snapshot),
            )? != Some(id)
            {
                return NativeStateSnafu {
                    field: "managed version identity",
                }
                .fail();
            }
            let definition = self
                .definition(
                    row.spec.tenant,
                    &row.spec.definition.definition.name,
                    Some(row.spec.manifest.definition),
                    &control,
                )?
                .map(|(definition, _)| definition.encode())
                .transpose()?;
            row.spec.check_images(definition.as_deref(), |pin| {
                self.retained_package_image(row.spec.tenant, pin, &control)
            })?;
            owners.insert(id);
            let admission = row
                .spec
                .graph_declarations(|call| self.managed_contract(&row.spec, call))?;
            if !admission.calls.is_empty() {
                let graph = graphs.entry(id).or_insert_with(|| ManagedGraph {
                    graph: id,
                    writers: BTreeMap::new(),
                    relations: BTreeMap::new(),
                });
                graph.extend(admission.relations, admission.calls, |identity| {
                    Records::find(identity, |key| Records::read(key, &self.snapshot))?.ok_or_else(
                        || {
                            NativeStateSnafu {
                                field: "managed Graph identity",
                            }
                            .build()
                        },
                    )
                })?;
            }
        }
        let mut active = BTreeMap::new();
        let mut calls = BTreeMap::new();
        for entry in self.snapshot.prefix(b"\0data/J") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed instances",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "managed instance key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "managed instance record",
                    }
                    .build()
                })?;
            let row: InstanceRecord = Records::decode(&bytes)?;
            if !owners.remove(&id)
                || Records::find(&InstanceRecord::identity(row.tenant, &row.id)?, |key| {
                    Records::read(key, &self.snapshot)
                })? != Some(id)
            {
                return NativeStateSnafu {
                    field: "managed instance identity",
                }
                .fail();
            }
            let instance = self
                .managed_instance(row.tenant, &row.id, &control)?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "managed current version",
                    }
                    .build()
                })?;
            if instance.progress != 0 {
                self.managed_source_at(&instance, &control)?
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Missing.error("managed completed attempt")
                    })?;
            }
            if instance.running && !instance.removed {
                active.insert(Records::key(b'B', id), instance.lifecycle);
            }
            for call in instance.spec.manifest.calls.keys() {
                calls.insert(
                    InstanceRecord::call_key(id, *call),
                    (instance.clone(), *call),
                );
            }
        }
        if !owners.is_empty() {
            return NativeStateSnafu {
                field: "managed version owner",
            }
            .fail();
        }
        self.validate_heads(b"\0data/B", active)?;
        for entry in self.snapshot.prefix(b"\0data/Q") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed call heads",
            })?;
            if key.len() == 31 {
                continue;
            }
            let Some((instance, call)) = calls.remove(key.as_ref()) else {
                return NativeStateSnafu {
                    field: "managed call manifest",
                }
                .fail();
            };
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "managed call head",
                    }
                    .build()
                })?;
            let row: CallHead = Records::decode(&bytes)?;
            match row.result {
                Some(result) if row.revision != 0 && row.revision <= instance.progress => {
                    let (_, stored, owner) = self.result_owner(
                        instance.spec.tenant,
                        &result,
                        &control,
                        &mut |_| Ok(()),
                    )?;
                    let super::results::ResultBody::Call(record) = stored.body else {
                        return Err(
                            crate::PackageErrorCodeV1::Invalid.error("managed call head kind")
                        );
                    };
                    if stored.revision != row.revision
                        || record.call != call
                        || record.instance != instance.spec.id
                        || !instance.spec.same_call(&owner.1.spec, call)
                    {
                        return Err(
                            crate::PackageErrorCodeV1::Invalid.error("managed call head receipt")
                        );
                    }
                }
                None if row.revision == 0 => {}
                _ => return Err(crate::PackageErrorCodeV1::Invalid.error("managed call receipt")),
            }
        }
        if !calls.is_empty() {
            return NativeStateSnafu {
                field: "managed call manifest",
            }
            .fail();
        }
        for entry in self.snapshot.prefix(b"\0data/G") {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate managed Graph mappings",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "managed Graph key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..])?;
            let saved = ManagedGraph::read(id, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "managed Graph mapping",
                    }
                    .build()
                })?;
            if graphs.remove(&id).as_ref() != Some(&saved) {
                return NativeStateSnafu {
                    field: "managed Graph manifest",
                }
                .fail();
            }
            Graph::new(id)?.check_installation(
                &self.snapshot,
                &saved.writers.values().copied().collect::<Vec<_>>(),
                &saved.declarations()?,
            )?;
        }
        if !graphs.is_empty() {
            return NativeStateSnafu {
                field: "managed Graph mapping",
            }
            .fail();
        }
        Ok(())
    }
}
