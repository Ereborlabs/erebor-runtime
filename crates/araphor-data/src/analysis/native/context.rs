use fjall::{BranchSnapshot, BranchWriteTransaction};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{DataView, DataWrite, NativeStore};
use crate::{
    AnalysisConflictSnafu, AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
    ManagedDecodingSnafu, ManagedEncodingSnafu, NativeStateSnafu, NativeStorageSnafu, Result,
};

#[derive(Deserialize)]
struct ContextRecord {
    version: AnalysisContextVersionV1,
    revision: u64,
}

pub(super) struct Records;

impl Records {
    const DICTIONARY: &'static [u8] = b"\0data/key/";
    const WIDTH: usize = u16::MAX as usize - Self::DICTIONARY.len() - 8;

    fn key(kind: u8, id: u64) -> Vec<u8> {
        [b"\0data/".as_slice(), &[kind], &id.to_be_bytes()].concat()
    }

    fn identity(key: &AnalysisContextKeyV1, version: bool) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(
            key.tenant_id,
            &key.owner_id,
            &key.entity_key,
            &key.lifetime_key,
            version.then_some(key.owner_revision),
        ))
        .context(ManagedEncodingSnafu)
    }

    fn lookup(parent: u64, bytes: &[u8]) -> Vec<u8> {
        [Self::DICTIONARY, &parent.to_be_bytes(), bytes].concat()
    }

    fn find(
        key: &[u8],
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<u64>> {
        let mut parent = 0;
        for bytes in key.chunks(Self::WIDTH) {
            let Some(value) = get(&Self::lookup(parent, bytes))? else {
                return Ok(None);
            };
            let id = NativeStore::number(&value)?;
            if id <= parent {
                return NativeStateSnafu {
                    field: "context dictionary link",
                }
                .fail();
            }
            parent = id;
        }
        Ok(Some(parent))
    }

    fn intern(tx: &mut BranchWriteTransaction<'_>, key: &[u8]) -> Result<u64> {
        let mut parent = 0;
        for bytes in key.chunks(Self::WIDTH) {
            let lookup = Self::lookup(parent, bytes);
            let id = match tx.get(&lookup).context(NativeStorageSnafu {
                operation: "find context identity",
            })? {
                Some(value) => NativeStore::number(&value)?,
                None => {
                    let next = tx
                        .get(b"\0data/next")
                        .context(NativeStorageSnafu {
                            operation: "read context allocator",
                        })?
                        .map(|bytes| NativeStore::number(&bytes))
                        .transpose()?
                        .unwrap_or(1);
                    let after = next.checked_add(1).filter(|_| next != 0).ok_or_else(|| {
                        NativeStateSnafu {
                            field: "context identity exhausted",
                        }
                        .build()
                    })?;
                    tx.insert(b"\0data/next", after.to_be_bytes());
                    tx.insert(lookup, next.to_be_bytes());
                    next
                }
            };
            if id <= parent {
                return NativeStateSnafu {
                    field: "context dictionary link",
                }
                .fail();
            }
            parent = id;
        }
        Ok(parent)
    }

    fn read(key: &[u8], view: &BranchSnapshot) -> Result<Option<fjall::Slice>> {
        view.get(key).context(NativeStorageSnafu {
            operation: "read context record",
        })
    }

    fn staged(key: &[u8], tx: &BranchWriteTransaction<'_>) -> Result<Option<fjall::Slice>> {
        tx.get(key).context(NativeStorageSnafu {
            operation: "read staged context record",
        })
    }

    fn fragment(key: &[u8], slot: usize) -> Vec<u8> {
        [key, &(slot as u64).to_be_bytes()].concat()
    }

    pub(super) fn payload(
        key: &[u8],
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(value) = get(key)? else {
            return Ok(None);
        };
        match value.first() {
            Some(0) => Ok(Some(value[1..].to_vec())),
            Some(1) => {
                let len = usize::try_from(NativeStore::number(&value[1..])?).map_err(|_| {
                    NativeStateSnafu {
                        field: "context payload size",
                    }
                    .build()
                })?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(len).map_err(|_| {
                    crate::AnalysisInputTooLargeSnafu {
                        resource: "context payload",
                    }
                    .build()
                })?;
                for slot in 0..len.div_ceil(u32::MAX as usize) {
                    let fragment = get(&Self::fragment(key, slot))?.ok_or_else(|| {
                        NativeStateSnafu {
                            field: "context payload fragment",
                        }
                        .build()
                    })?;
                    if fragment.len() != (len - bytes.len()).min(u32::MAX as usize) {
                        return NativeStateSnafu {
                            field: "context payload length",
                        }
                        .fail();
                    }
                    bytes.extend_from_slice(&fragment);
                }
                Ok(Some(bytes))
            }
            _ => NativeStateSnafu {
                field: "context payload tag",
            }
            .fail(),
        }
    }

    pub(super) fn stage(tx: &mut BranchWriteTransaction<'_>, key: Vec<u8>, bytes: Vec<u8>) {
        if bytes.len() <= u32::MAX as usize {
            tx.insert(key, bytes);
        } else {
            let mut manifest = vec![1];
            manifest.extend_from_slice(&((bytes.len() - 1) as u64).to_be_bytes());
            tx.insert(key.clone(), manifest);
            for (slot, fragment) in bytes[1..].chunks(u32::MAX as usize).enumerate() {
                tx.insert(Self::fragment(&key, slot), fragment);
            }
        }
    }

    pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = vec![0];
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes))
            .context(ManagedEncodingSnafu)?;
        Ok(bytes)
    }

    pub(super) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = T::deserialize(&mut decoder).context(ManagedDecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return NativeStateSnafu {
                field: "context record trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }

    fn check(record: &ContextRecord, key: &AnalysisContextKeyV1) -> Result<()> {
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
    pub fn context(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let identity = Records::identity(key, true)?;
        let Some(id) = Records::find(&identity, |key| Records::read(key, &self.snapshot))? else {
            return Ok(None);
        };
        let Some(bytes) = Records::payload(&Records::key(b'C', id), |key| {
            Records::read(key, &self.snapshot)
        })?
        else {
            return Ok(None);
        };
        let record: ContextRecord = Records::decode(&bytes)?;
        Records::check(&record, key)?;
        if record.revision > self.revision {
            return NativeStateSnafu {
                field: "context record revision",
            }
            .fail();
        }
        Ok(Some((record.version, record.revision)))
    }

    pub fn context_head(&self, key: &AnalysisContextKeyV1) -> Result<Option<AnalysisContextRefV1>> {
        let identity = Records::identity(key, false)?;
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
        if Records::identity(&record.version.key, false)? != identity
            || !record.version.valid()
            || record.revision == 0
            || record.revision > self.revision
        {
            return NativeStateSnafu {
                field: "context head identity",
            }
            .fail();
        }
        Ok(Some(AnalysisContextRefV1 {
            key: record.version.key,
            commit_revision: record.revision,
        }))
    }
}

impl DataWrite<'_> {
    // This method stores admitted rows. Qualified owner checks stay with Data's domain owner.
    pub fn context(
        &mut self,
        input: &AnalysisContextVersionV1,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
        if !input.valid() {
            return NativeStateSnafu {
                field: "context input",
            }
            .fail();
        }
        let identity = Records::identity(&input.key, true)?;
        if let Some(id) = Records::find(&identity, |key| Records::staged(key, &self.transaction))? {
            if let Some(bytes) = Records::payload(&Records::key(b'C', id), |key| {
                Records::staged(key, &self.transaction)
            })? {
                let stored: ContextRecord = Records::decode(&bytes)?;
                Records::check(&stored, &input.key)?;
                if stored.version != *input {
                    return AnalysisConflictSnafu.fail();
                }
                return Ok(AnalysisContextRefV1 {
                    key: input.key.clone(),
                    commit_revision: stored.revision,
                });
            }
        }
        let base = Records::identity(&input.key, false)?;
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
                if Records::identity(&record.version.key, false)?
                    != Records::identity(&input.key, false)?
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
