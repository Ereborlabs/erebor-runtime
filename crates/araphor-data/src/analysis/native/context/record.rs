use serde::Deserialize;
use snafu::ResultExt as _;

use super::super::{records::Records, DataView, DataWrite, NativeStore};
use crate::{
    AnalysisConflictSnafu, AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
    ManagedEncodingSnafu, NativeStateSnafu, Result,
};

#[derive(Deserialize)]
pub(super) struct ContextRecord {
    pub(super) version: AnalysisContextVersionV1,
    pub(super) revision: u64,
}

impl ContextRecord {
    pub(super) fn identity(key: &AnalysisContextKeyV1, version: bool) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(
            key.tenant_id,
            &key.owner_id,
            &key.entity_key,
            &key.lifetime_key,
            version.then_some(key.owner_revision),
        ))
        .context(ManagedEncodingSnafu)
    }

    pub(super) fn check(record: &ContextRecord, key: &AnalysisContextKeyV1) -> Result<()> {
        if !record.version.valid() || record.version.key != *key || record.revision == 0 {
            return NativeStateSnafu {
                field: "context record identity",
            }
            .fail();
        }
        Ok(())
    }
}

impl DataView {
    pub(super) fn context_row(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        self.context_charged(key, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn context_charged(
        &self,
        key: &AnalysisContextKeyV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let identity = ContextRecord::identity(key, true)?;
        let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(
            &Records::key(b'C', id),
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        else {
            return Ok(None);
        };
        let record: ContextRecord = Records::decode(&bytes)?;
        ContextRecord::check(&record, key)?;
        if record.revision > self.metadata_revision {
            return NativeStateSnafu {
                field: "context record revision",
            }
            .fail();
        }
        Ok(Some((record.version, record.revision)))
    }

    pub fn context_head(&self, key: &AnalysisContextKeyV1) -> Result<Option<AnalysisContextRefV1>> {
        let identity = ContextRecord::identity(key, false)?;
        let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))? else {
            return Ok(None);
        };
        let Some(bytes) = Records::read(&Records::key(b'H', id), &self.snapshot)? else {
            return Ok(None);
        };
        let id = NativeStore::number(&bytes)?;
        let bytes = Records::payload(&Records::key(b'C', id), |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| {
            NativeStateSnafu {
                field: "context head record",
            }
            .build()
        })?;
        let record: ContextRecord = Records::decode(&bytes)?;
        if ContextRecord::identity(&record.version.key, false)? != identity
            || !record.version.valid()
            || record.revision == 0
            || record.revision > self.metadata_revision
            || ContextRecord::id(&record.version.key, |key| {
                Records::read(key, &self.snapshot)
            })? != Some(id)
        {
            return NativeStateSnafu {
                field: "context head identity",
            }
            .fail();
        }
        self.verify_context(&record.version)?;
        Ok(Some(AnalysisContextRefV1 {
            key: record.version.key,
            commit_revision: record.revision,
        }))
    }
}

impl DataWrite<'_> {
    pub(super) fn record(
        &mut self,
        input: &AnalysisContextVersionV1,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
        let identity = ContextRecord::identity(&input.key, true)?;
        let base = ContextRecord::identity(&input.key, false)?;
        let found = Records::find(&base, |key| Records::staged(key, &self.transaction))?;
        let previous = found
            .map(|id| Records::staged(&Records::key(b'H', id), &self.transaction))
            .transpose()?
            .flatten()
            .map(|bytes| -> Result<ContextRecord> {
                let id = NativeStore::number(&bytes)?;
                let bytes = Records::payload(&Records::key(b'C', id), |key| {
                    Records::staged(key, &self.transaction)
                })?
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "context head record",
                    }
                    .build()
                })?;
                let record: ContextRecord = Records::decode(&bytes)?;
                if ContextRecord::identity(&record.version.key, false)?
                    != ContextRecord::identity(&input.key, false)?
                    || !record.version.valid()
                    || record.revision == 0
                    || record.revision > self.revision
                {
                    return NativeStateSnafu {
                        field: "context head identity",
                    }
                    .fail();
                }
                Ok(record)
            })
            .transpose()?;
        if expected.is_some_and(|expected| {
            previous
                .as_ref()
                .map_or(0, |record| record.version.key.owner_revision)
                != expected
                || expected.checked_add(1) != Some(input.key.owner_revision)
        }) {
            return AnalysisConflictSnafu.fail();
        }
        let base = match found {
            Some(id) => id,
            None => Records::intern(&mut self.transaction, &base)?,
        };
        let head = Records::key(b'H', base);
        let id = Records::intern(&mut self.transaction, &identity)?;
        let encoded = Records::encode(&(input, self.revision))?;
        Records::stage(&mut self.transaction, Records::key(b'C', id), encoded);
        let reference = AnalysisContextRefV1 {
            key: input.key.clone(),
            commit_revision: self.revision,
        };
        self.index_context(id, &reference)?;
        self.note_relation("context_versions", self.revision)?;
        if previous
            .as_ref()
            .is_none_or(|prior| prior.version.key.owner_revision < input.key.owner_revision)
        {
            self.transaction.insert(head, id.to_be_bytes());
        }
        self.dirty = true;
        Ok(reference)
    }
}
