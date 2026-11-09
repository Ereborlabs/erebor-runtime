use super::NativeStore;
use crate::{
    ManagedDecodingSnafu, ManagedEncodingSnafu, NativeStateSnafu, NativeStorageSnafu, Result,
};
use fjall::{BranchSnapshot, BranchWriteTransaction};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

pub(super) struct Records;

impl Records {
    const DICTIONARY: &'static [u8] = b"\0data/key/";
    const WIDTH: usize = u16::MAX as usize - Self::DICTIONARY.len() - 8;

    pub(super) fn key(kind: u8, id: u64) -> Vec<u8> {
        [b"\0data/".as_slice(), &[kind], &id.to_be_bytes()].concat()
    }

    fn lookup(parent: u64, bytes: &[u8]) -> Vec<u8> {
        [Self::DICTIONARY, &parent.to_be_bytes(), bytes].concat()
    }

    pub(super) fn find(
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

    pub(super) fn intern(tx: &mut BranchWriteTransaction<'_>, key: &[u8]) -> Result<u64> {
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

    pub(super) fn read(key: &[u8], view: &BranchSnapshot) -> Result<Option<fjall::Slice>> {
        view.get(key).context(NativeStorageSnafu {
            operation: "read context record",
        })
    }

    pub(super) fn staged(
        key: &[u8],
        tx: &BranchWriteTransaction<'_>,
    ) -> Result<Option<fjall::Slice>> {
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
            .serialize(
                &mut rmp_serde::Serializer::new(&mut bytes)
                    .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
            )
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
}
