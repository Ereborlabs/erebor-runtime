use fjall::{BranchSnapshot, BranchWriteTransaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::scratch::Scratch as Memory;
use crate::{
    error::{DecodeSnafu, EncodeSnafu, InvalidSnafu, NativeSnafu},
    Result,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct StoredRelation {
    pub(super) graph: u64,
    pub(super) kind: u8,
    pub(super) endpoints: Option<(u64, u64)>,
    pub(super) schema: Vec<u8>,
}

impl StoredRelation {
    pub(super) fn new(graph: u64, declaration: &super::Declaration) -> Result<Self> {
        let batch = arrow_array::RecordBatch::new_empty(std::sync::Arc::new(
            declaration.shape.properties.clone(),
        ));
        Ok(Self {
            graph,
            kind: declaration.shape.kind as u8,
            endpoints: declaration.endpoints,
            schema: Properties::encode(&batch)?,
        })
    }

    pub(super) fn shape(&self) -> Result<crate::Relation> {
        let batch = Properties::decode(&self.schema)?;
        let kind = match (self.kind, self.endpoints) {
            (0, None) => crate::EntityKind::Node,
            (1, Some((1.., 1..))) => crate::EntityKind::Edge,
            _ => {
                return InvalidSnafu {
                    field: "native Graph stored declaration",
                }
                .fail()
            }
        };
        Ok(crate::Relation {
            kind,
            properties: batch.schema().as_ref().clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct Head {
    pub(super) layer: u64,
    pub(super) parent: Option<u64>,
    pub(super) revision: u64,
}

pub(super) struct Properties;

impl Properties {
    pub(super) fn encode(batch: &arrow_array::RecordBatch) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut stream = arrow_ipc::writer::StreamWriter::try_new(&mut bytes, &batch.schema())?;
            stream.write(batch)?;
            stream.finish()?;
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<arrow_array::RecordBatch> {
        let mut stream =
            arrow_ipc::reader::StreamReader::try_new(std::io::Cursor::new(bytes), None)?;
        let batch = stream.next().transpose()?.ok_or_else(|| {
            InvalidSnafu {
                field: "native Graph property chunk",
            }
            .build()
        })?;
        if stream.next().is_some() {
            return InvalidSnafu {
                field: "native Graph property stream",
            }
            .fail();
        }
        Ok(batch)
    }

    pub(super) fn stage(tx: &mut BranchWriteTransaction<'_>, id: u64, bytes: &[u8]) {
        tx.insert(Key::record(b'P', &[id]), (bytes.len() as u64).to_be_bytes());
        for (slot, fragment) in bytes.chunks(u32::MAX as usize).enumerate() {
            tx.insert(Key::record(b'P', &[id, slot as u64]), fragment);
        }
    }

    pub(super) fn load(
        view: &BranchSnapshot,
        id: u64,
        writer: u64,
        memory: &mut Memory<'_>,
    ) -> Result<arrow_array::RecordBatch> {
        let value = view
            .get(Key::record(b'P', &[id]))
            .context(NativeSnafu {
                operation: "read Graph property size",
            })?
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph property reference",
                }
                .build()
            })?;
        let len = usize::try_from(Key::number(&value)?).map_err(|_| {
            InvalidSnafu {
                field: "native Graph property size",
            }
            .build()
        })?;
        memory.charge(writer, len)?;
        let mut bytes = Vec::with_capacity(len);
        for slot in 0..len.div_ceil(u32::MAX as usize) {
            memory.check(writer)?;
            let fragment = view
                .get(Key::record(b'P', &[id, slot as u64]))
                .context(NativeSnafu {
                    operation: "read Graph property fragment",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph property fragment",
                    }
                    .build()
                })?;
            if fragment.len() != (len - bytes.len()).min(u32::MAX as usize) {
                return InvalidSnafu {
                    field: "native Graph property length",
                }
                .fail();
            }
            bytes.extend_from_slice(&fragment);
        }
        let batch = Self::decode(&bytes)?;
        memory.charge(writer, batch.get_array_memory_size())?;
        Ok(batch)
    }
}

pub(super) struct Key;

impl Key {
    pub(super) fn record(kind: u8, fields: &[u64]) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + fields.len() * 8);
        key.extend_from_slice(b"\0graph/");
        key.push(kind);
        for value in fields {
            key.extend_from_slice(&value.to_be_bytes());
        }
        key
    }

    pub(super) fn number(bytes: &[u8]) -> Result<u64> {
        bytes.try_into().map(u64::from_be_bytes).map_err(|_| {
            InvalidSnafu {
                field: "native Graph integer",
            }
            .build()
        })
    }

    pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        rmp_serde::to_vec(value).context(EncodeSnafu)
    }

    pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = T::deserialize(&mut decoder).context(DecodeSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return InvalidSnafu {
                field: "native Graph trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }

    pub(super) fn allocate(tx: &mut BranchWriteTransaction<'_>) -> Result<u64> {
        let next = tx
            .get(b"\0graph/next")
            .context(NativeSnafu {
                operation: "read Graph allocator",
            })?
            .map(|bytes| Self::number(&bytes))
            .transpose()?
            .unwrap_or(1);
        let after = next.checked_add(1).filter(|_| next != 0).ok_or_else(|| {
            InvalidSnafu {
                field: "native Graph identity",
            }
            .build()
        })?;
        tx.insert(b"\0graph/next", after.to_be_bytes());
        Ok(next)
    }
}

#[derive(PartialEq, Serialize, Deserialize)]
struct Fragment {
    kind: u8,
    scope: u64,
    parent: u64,
    bytes: Vec<u8>,
}

impl Fragment {
    fn check(&self, kind: u8, scope: u64, parent: u64, bytes: &[u8]) -> Result<()> {
        if self.kind != kind || self.scope != scope || self.parent != parent || self.bytes != bytes
        {
            return InvalidSnafu {
                field: "Graph dictionary index",
            }
            .fail();
        }
        Ok(())
    }
}

pub(super) struct Dictionary;

impl Dictionary {
    const WIDTH: usize = u16::MAX as usize - 25;

    fn key(kind: u8, scope: u64, parent: u64, bytes: &[u8]) -> Vec<u8> {
        let mut key = b"\0graph/D".to_vec();
        key.push(kind);
        key.extend_from_slice(&scope.to_be_bytes());
        key.extend_from_slice(&parent.to_be_bytes());
        key.extend_from_slice(bytes);
        key
    }

    fn fragments(key: &[u8]) -> impl Iterator<Item = &[u8]> {
        key.chunks(Self::WIDTH).chain(key.is_empty().then_some(key))
    }

    pub(super) fn find(
        view: &BranchSnapshot,
        kind: u8,
        scope: u64,
        key: &[u8],
    ) -> Result<Option<u64>> {
        let mut parent = 0;
        for bytes in Self::fragments(key) {
            let Some(value) =
                view.get(Self::key(kind, scope, parent, bytes))
                    .context(NativeSnafu {
                        operation: "find Graph identity",
                    })?
            else {
                return Ok(None);
            };
            let id = Key::number(&value)?;
            if id <= parent {
                return InvalidSnafu {
                    field: "Graph dictionary link",
                }
                .fail();
            }
            let reverse = view
                .get(Key::record(b'V', &[id]))
                .context(NativeSnafu {
                    operation: "check Graph identity reference",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph dictionary reference",
                    }
                    .build()
                })?;
            Key::decode::<Fragment>(&reverse)?.check(kind, scope, parent, bytes)?;
            parent = id;
        }
        Ok(Some(parent))
    }

    pub(super) fn intern(
        tx: &mut BranchWriteTransaction<'_>,
        kind: u8,
        scope: u64,
        key: &[u8],
        writer: u64,
        memory: &mut Memory<'_>,
    ) -> Result<u64> {
        let mut parent = 0;
        for bytes in Self::fragments(key) {
            memory.check(writer)?;
            memory.charge(writer, 2 * bytes.len() + 128)?;
            let lookup = Self::key(kind, scope, parent, bytes);
            let id = if let Some(value) = tx.get(&lookup).context(NativeSnafu {
                operation: "find staged Graph identity",
            })? {
                let id = Key::number(&value)?;
                let reverse = tx
                    .get(Key::record(b'V', &[id]))
                    .context(NativeSnafu {
                        operation: "check staged Graph identity",
                    })?
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "Graph dictionary reference",
                        }
                        .build()
                    })?;
                Key::decode::<Fragment>(&reverse)?.check(kind, scope, parent, bytes)?;
                id
            } else {
                let id = Key::allocate(tx)?;
                let fragment = Fragment {
                    kind,
                    scope,
                    parent,
                    bytes: bytes.to_vec(),
                };
                tx.insert(lookup, id.to_be_bytes());
                tx.insert(Key::record(b'V', &[id]), Key::encode(&fragment)?);
                id
            };
            if id <= parent {
                return InvalidSnafu {
                    field: "Graph dictionary link",
                }
                .fail();
            }
            parent = id;
        }
        Ok(parent)
    }

    pub(super) fn resolve(
        view: &BranchSnapshot,
        kind: u8,
        scope: u64,
        mut id: u64,
        writer: u64,
        memory: &mut Memory<'_>,
    ) -> Result<Vec<u8>> {
        let mut parts = Vec::new();
        let mut len = 0usize;
        while id != 0 {
            memory.check(writer)?;
            let value = view
                .get(Key::record(b'V', &[id]))
                .context(NativeSnafu {
                    operation: "read Graph identity",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph dictionary reference",
                    }
                    .build()
                })?;
            memory.charge(writer, value.len().saturating_mul(3) + 128)?;
            let fragment: Fragment = Key::decode(&value)?;
            if fragment.kind != kind
                || fragment.scope != scope
                || fragment.parent >= id
                || fragment.bytes.len() > Self::WIDTH
            {
                return InvalidSnafu {
                    field: "Graph dictionary chain",
                }
                .fail();
            }
            let lookup = Self::key(kind, scope, fragment.parent, &fragment.bytes);
            if view
                .get(lookup)
                .context(NativeSnafu {
                    operation: "check Graph identity",
                })?
                .as_deref()
                != Some(id.to_be_bytes().as_slice())
            {
                return InvalidSnafu {
                    field: "Graph dictionary index",
                }
                .fail();
            }
            len = len.checked_add(fragment.bytes.len()).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph dictionary bytes",
                }
                .build()
            })?;
            parts.push(fragment.bytes);
            id = fragment.parent;
        }
        if parts.is_empty() {
            return InvalidSnafu {
                field: "Graph dictionary zero identity",
            }
            .fail();
        }
        memory.charge(writer, len)?;
        let mut key = Vec::with_capacity(len);
        for bytes in parts.into_iter().rev() {
            key.extend_from_slice(&bytes);
        }
        Ok(key)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct StoredMember {
    pub(super) writer: u64,
    pub(super) owner: u64,
    pub(super) relation: u64,
    pub(super) entity: u64,
    pub(super) revision: u64,
    pub(super) property: u64,
    pub(super) chunk: u64,
    pub(super) row: usize,
    pub(super) endpoints: Option<[u64; 3]>,
}

impl StoredMember {
    pub(super) fn key(&self) -> Vec<u8> {
        Key::record(b'M', &[self.writer, self.owner, self.relation, self.entity])
    }
    pub(super) fn indexes(&self, graph: u64, ends: Option<(u64, u64)>) -> Vec<Vec<u8>> {
        let mut keys = vec![
            Key::record(b'R', &[self.relation, self.writer, self.owner, self.entity]),
            Key::record(b'K', &[self.relation, self.entity, self.writer, self.owner]),
        ];
        if let (Some([from, to, _label]), Some((source, target))) = (self.endpoints, ends) {
            for (kind, endpoint) in [(b'O', from), (b'I', to)] {
                keys.push(Key::record(
                    kind,
                    &[
                        self.relation,
                        endpoint,
                        self.writer,
                        self.owner,
                        self.entity,
                    ],
                ));
            }
            for (relation, endpoint) in [(source, from), (target, to)] {
                keys.push(Key::record(
                    b'E',
                    &[
                        graph,
                        relation,
                        endpoint,
                        self.writer,
                        self.relation,
                        self.owner,
                        self.entity,
                    ],
                ));
            }
        }
        keys
    }
}
