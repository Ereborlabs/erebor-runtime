use std::{
    collections::BTreeSet,
    ops::Bound::{Excluded, Included},
};

use snafu::ResultExt as _;

use super::{DataView, DataWrite, NativeStore, Records};
use crate::{
    AnalysisContextRefV1, AnalysisExtractionV1, AnalysisReadControl, AnalysisSelectionV1,
    NativeStateSnafu, NativeStorageSnafu, Result, Selection,
};

struct ContextIndex;

impl ContextIndex {
    const TENANT: &'static [u8] = b"\0data/context/tenant/";
    const OWNER: &'static [u8] = b"\0data/context/owner/";

    fn owner(tenant: [u8; 16], owner: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'O', tenant, owner)).context(crate::ManagedEncodingSnafu)
    }

    fn key(prefix: &[u8], revision: u64, id: u64) -> Vec<u8> {
        [prefix, &revision.to_be_bytes(), &id.to_be_bytes()].concat()
    }

    fn tenant(tenant: &[u8; 16]) -> Vec<u8> {
        [Self::TENANT, tenant].concat()
    }
    fn owned(owner: u64) -> Vec<u8> {
        [Self::OWNER, &owner.to_be_bytes()].concat()
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn context_owner_ids(
        &self,
        tenant: Option<[u8; 16]>,
        owner: &str,
    ) -> Result<Vec<u64>> {
        let mut ids = Vec::new();
        let prefix = if let Some(tenant) = tenant {
            let Some(id) = Records::find(&ContextIndex::owner(tenant, owner)?, |key| {
                Records::staged(key, &self.transaction)
            })?
            else {
                return Ok(ids);
            };
            ContextIndex::owned(id)
        } else {
            ContextIndex::TENANT.to_vec()
        };
        let width = if tenant.is_some() { 16 } else { 32 };
        for entry in self.transaction.prefix(&prefix) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read retained context headers",
            })?;
            if key.len() != prefix.len() + width {
                continue;
            }
            let bytes = Records::payload(&key, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "retained context header",
                    }
                    .build()
                })?;
            let reference: AnalysisContextRefV1 = Records::decode(&bytes)?;
            if tenant.is_some_and(|tenant| {
                reference.key.tenant_id != tenant || reference.key.owner_id != owner
            }) {
                return NativeStateSnafu {
                    field: "retained context owner",
                }
                .fail();
            }
            if reference.key.owner_id == owner {
                ids.push(NativeStore::number(&key[key.len() - 8..])?);
            }
        }
        Ok(ids)
    }

    pub(super) fn index_context(
        &mut self,
        id: u64,
        reference: &AnalysisContextRefV1,
    ) -> Result<()> {
        let owner = Records::intern(
            &mut self.transaction,
            &ContextIndex::owner(reference.key.tenant_id, &reference.key.owner_id)?,
        )?;
        let bytes = Records::encode(reference)?;
        for prefix in [
            ContextIndex::tenant(&reference.key.tenant_id),
            ContextIndex::owned(owner),
        ] {
            Records::stage(
                &mut self.transaction,
                ContextIndex::key(&prefix, reference.commit_revision, id),
                bytes.clone(),
            );
        }
        Ok(())
    }
}

impl DataView {
    pub(in crate::analysis::native) fn context_bound(&self, mut bound: u64) -> Result<u64> {
        if bound == 0 {
            return Ok(0);
        }
        let prefix = ContextIndex::TENANT;
        for row in self.snapshot.prefix(prefix) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "read retained context history",
            })?;
            if key.len() == prefix.len() + 40 {
                continue;
            }
            if key.len() != prefix.len() + 32 {
                return NativeStateSnafu {
                    field: "context history key",
                }
                .fail();
            }
            let revision = NativeStore::number(&key[prefix.len() + 16..prefix.len() + 24])?;
            if revision == 0 || revision > self.metadata_revision {
                return NativeStateSnafu {
                    field: "context history revision",
                }
                .fail();
            }
            bound = bound.min(revision);
        }
        Ok(bound)
    }

    pub(in crate::analysis::native) fn context_reference(
        &self,
        tenant: [u8; 16],
        id: u64,
        revision: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<AnalysisContextRefV1> {
        charge(0)?;
        let key = ContextIndex::key(&ContextIndex::tenant(&tenant), revision, id);
        let bytes =
            Records::charged_payload(&key, |key| Records::read(key, &self.snapshot), charge)?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "context reference header",
                    }
                    .build()
                })?;
        let reference: AnalysisContextRefV1 = Records::decode(&bytes)?;
        if !reference.key.valid()
            || reference.key.tenant_id != tenant
            || reference.commit_revision != revision
            || revision == 0
            || revision > self.metadata_revision
            || super::ContextRecord::id(&reference.key, |key| Records::read(key, &self.snapshot))?
                != Some(id)
            || Records::read(&Records::key(b'C', id), &self.snapshot)?.is_none()
        {
            return NativeStateSnafu {
                field: "context reference identity",
            }
            .fail();
        }
        Ok(reference)
    }

    pub(in crate::analysis::native) fn input_context_key(key: &[u8]) -> bool {
        key.starts_with(ContextIndex::TENANT) && key.len() == ContextIndex::TENANT.len() + 32
    }

    pub(in crate::analysis::native) fn input_context(
        &self,
        key: &[u8],
    ) -> Result<Option<AnalysisContextRefV1>> {
        if !Self::input_context_key(key) {
            return Ok(None);
        }
        let bytes =
            Records::payload(key, |key| Records::read(key, &self.snapshot))?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "input context header",
                }
                .build()
            })?;
        let reference: AnalysisContextRefV1 = Records::decode(&bytes)?;
        let id = NativeStore::number(&key[key.len() - 8..])?;
        if !reference.key.valid()
            || reference.commit_revision != self.metadata_revision
            || ContextIndex::key(
                &ContextIndex::tenant(&reference.key.tenant_id),
                reference.commit_revision,
                id,
            ) != key
        {
            return NativeStateSnafu {
                field: "input context header identity",
            }
            .fail();
        }
        Ok(Some(reference))
    }

    pub(super) fn check_context_index(
        &self,
        id: u64,
        reference: &AnalysisContextRefV1,
    ) -> Result<()> {
        let owner = Records::find(
            &ContextIndex::owner(reference.key.tenant_id, &reference.key.owner_id)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| {
            NativeStateSnafu {
                field: "context owner index",
            }
            .build()
        })?;
        for prefix in [
            ContextIndex::tenant(&reference.key.tenant_id),
            ContextIndex::owned(owner),
        ] {
            let bytes = Records::payload(
                &ContextIndex::key(&prefix, reference.commit_revision, id),
                |key| Records::read(key, &self.snapshot),
            )?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "context header index",
                }
                .build()
            })?;
            let saved: AnalysisContextRefV1 = Records::decode(&bytes)?;
            if saved != *reference {
                return NativeStateSnafu {
                    field: "context header index",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(super) fn check_context_indexes(&self, count: usize) -> Result<()> {
        for (prefix, width) in [(ContextIndex::TENANT, 32), (ContextIndex::OWNER, 24)] {
            let mut found = 0;
            for entry in self.snapshot.prefix(prefix) {
                let (key, _) = entry.context(NativeStorageSnafu {
                    operation: "validate context header indexes",
                })?;
                if key.len() == prefix.len() + width + 8 {
                    continue;
                }
                if key.len() != prefix.len() + width {
                    return NativeStateSnafu {
                        field: "context header key",
                    }
                    .fail();
                }
                found += 1;
            }
            if found != count {
                return NativeStateSnafu {
                    field: "context header set",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(in crate::analysis::native) fn context_headers(
        &self,
        selection: &AnalysisSelectionV1,
        owners: Option<&BTreeSet<String>>,
        after: Option<u64>,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        let mut headers = Vec::new();
        if selection.contexts.is_empty() || owners.is_some_and(BTreeSet::is_empty) {
            return Ok(headers);
        }
        let mut prefixes = Vec::new();
        if let Some(owners) = owners {
            for owner in owners {
                control.check()?;
                if let Some(id) =
                    Records::find(&ContextIndex::owner(selection.tenant_id, owner)?, |key| {
                        Records::read(key, &self.snapshot)
                    })?
                {
                    let added = AnalysisExtractionV1::grow(
                        &mut prefixes,
                        output.input_bytes,
                        output.limits.input_bytes,
                    )?;
                    output.charge(added)?;
                    output.charge(ContextIndex::OWNER.len() + 8)?;
                    prefixes.push(ContextIndex::owned(id));
                }
            }
        } else {
            output.charge(AnalysisExtractionV1::grow(
                &mut prefixes,
                output.input_bytes,
                output.limits.input_bytes,
            )?)?;
            output.charge(ContextIndex::TENANT.len() + 16)?;
            prefixes.push(ContextIndex::tenant(&selection.tenant_id));
        }
        let prefix_bytes = prefixes.capacity() * std::mem::size_of::<Vec<u8>>()
            + prefixes.iter().map(Vec::capacity).sum::<usize>();
        let mut count = selection
            .key_count()
            .saturating_sub(selection.contexts.as_slice().len());
        for prefix in &prefixes {
            let first = ContextIndex::key(prefix, after.unwrap_or(0), u64::MAX);
            let last = [
                ContextIndex::key(prefix, self.revision, u64::MAX),
                vec![u8::MAX; 8],
            ]
            .concat();
            let lower = if after.is_some() {
                Excluded(first)
            } else {
                Included(ContextIndex::key(prefix, 0, 0))
            };
            for entry in self.snapshot.range::<Vec<u8>, _>((lower, Included(last))) {
                control.check()?;
                let (key, _) = entry.context(NativeStorageSnafu {
                    operation: "read context headers",
                })?;
                if key.len() == prefix.len() + 24 {
                    continue;
                }
                if key.len() != prefix.len() + 16 {
                    return NativeStateSnafu {
                        field: "context header key",
                    }
                    .fail();
                }
                let saved = output.input_bytes;
                let bytes = Records::charged_payload(
                    &key,
                    |key| Records::read(key, &self.snapshot),
                    &mut |bytes| output.charge(bytes),
                )?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "context header value",
                    }
                    .build()
                })?;
                let header: AnalysisContextRefV1 = Records::decode(&bytes)?;
                drop(bytes);
                output.input_bytes = saved;
                if header.key.tenant_id != selection.tenant_id
                    || !header.key.valid()
                    || header.commit_revision == 0
                    || header.commit_revision > self.metadata_revision
                    || NativeStore::number(&key[prefix.len()..prefix.len() + 8])?
                        != header.commit_revision
                {
                    return NativeStateSnafu {
                        field: "context header identity",
                    }
                    .fail();
                }
                if selection.targets_only && header.key.owner_id != "mithril-control/target"
                    || owners.is_some_and(|owners| !owners.contains(&header.key.owner_id))
                    || matches!(&selection.contexts, Selection::Exact(keys) if !keys.contains(&header.key))
                {
                    continue;
                }
                if output.limits.keys.is_some_and(|limit| count >= limit) {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "selected input keys",
                    }
                    .fail();
                }
                output.charge(AnalysisExtractionV1::grow(
                    &mut headers,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?)?;
                output.charge(header.key.allocated_bytes())?;
                headers.push(header);
                count += 1;
            }
        }
        drop(prefixes);
        output.input_bytes -= prefix_bytes;
        headers.sort_by(|left, right| {
            if after.is_some() {
                (left.commit_revision, &left.key).cmp(&(right.commit_revision, &right.key))
            } else {
                left.key.cmp(&right.key)
            }
        });
        Ok(headers)
    }
}
