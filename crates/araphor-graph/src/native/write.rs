use std::collections::BTreeSet;

use fjall::BranchWriteTransaction;
use snafu::ResultExt as _;

use super::{
    record::{Dictionary, Head, Key, Properties, StoredMember, StoredRelation},
    Graph, Lease, Prepared, Reserve,
};
use crate::{
    error::{ConflictSnafu, InvalidSnafu, NativeSnafu},
    scratch::Scratch,
    Result,
};

pub struct LayerRequest {
    pub writer: u64,
    pub layer: u64,
    pub parent: Option<u64>,
}

pub struct Pending {
    pub stamps: Vec<Vec<u8>>,
    pub added: usize,
    pub removed: usize,
    pub encoded_bytes: usize,
    _leases: Vec<Lease>,
}

impl Graph {
    // Discard the caller's transaction if staging returns an error.
    pub fn stage(
        &self,
        tx: &mut BranchWriteTransaction<'_>,
        revision: u64,
        requests: &[LayerRequest],
        prepared: Prepared,
        reserve: &Reserve<'_>,
    ) -> Result<Pending> {
        if revision == 0 || prepared.graph != self.id || requests.len() != prepared.parents.len() {
            return InvalidSnafu {
                field: "native Graph prepared scope",
            }
            .fail();
        }
        let mut memory = Scratch::new(reserve);
        let mut writers = BTreeSet::new();
        let mut layers = BTreeSet::new();
        for request in requests {
            memory.check(request.writer)?;
            let parent = prepared.parents.get(&request.writer).ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph prepared writer",
                }
                .build()
            })?;
            let current = tx
                .get(Key::record(b'h', &[request.writer]))
                .context(NativeSnafu {
                    operation: "check Graph current head",
                })?
                .map(|bytes| Key::decode::<Head>(&bytes))
                .transpose()?;
            if current != *parent || request.parent != parent.as_ref().map(|head| head.layer) {
                return ConflictSnafu {
                    resource: "native Graph parent",
                }
                .fail();
            }
            if request.layer == 0
                || !writers.insert(request.writer)
                || !layers.insert(request.layer)
                || tx
                    .get(Key::record(b'l', &[request.layer]))
                    .context(NativeSnafu {
                        operation: "check Graph layer identity",
                    })?
                    .is_some()
            {
                return InvalidSnafu {
                    field: "native Graph layer identity",
                }
                .fail();
            }
            if current
                .as_ref()
                .is_some_and(|head| head.revision >= revision)
            {
                return InvalidSnafu {
                    field: "native Graph layer order",
                }
                .fail();
            }
            if tx
                .get(Key::record(b'w', &[request.writer]))
                .context(NativeSnafu {
                    operation: "check Graph staged writer",
                })?
                .as_deref()
                != Some(self.id.to_be_bytes().as_slice())
            {
                return InvalidSnafu {
                    field: "native Graph staged writer",
                }
                .fail();
            }
        }
        for (relation, declaration) in &prepared.declarations {
            let stored = tx
                .get(Key::record(b'f', &[*relation]))
                .context(NativeSnafu {
                    operation: "check Graph prepared relation",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph prepared relation",
                    }
                    .build()
                })?;
            if Key::decode::<StoredRelation>(&stored)? != *declaration {
                return ConflictSnafu {
                    resource: "native Graph declaration",
                }
                .fail();
            }
        }
        let mut pending = Pending {
            stamps: Vec::new(),
            added: 0,
            removed: 0,
            encoded_bytes: 0,
            _leases: Vec::new(),
        };
        let mut nodes = BTreeSet::new();
        let mut edges = BTreeSet::new();
        for (key, member) in &prepared.closed {
            memory.check(member.writer)?;
            let current = tx
                .get(key)
                .context(NativeSnafu {
                    operation: "check Graph base member",
                })?
                .ok_or_else(|| {
                    ConflictSnafu {
                        resource: "native Graph base member",
                    }
                    .build()
                })?;
            if Key::decode::<StoredMember>(&current)? != *member {
                return ConflictSnafu {
                    resource: "native Graph base member",
                }
                .fail();
            }
            tx.remove(key.as_slice());
            for index in member.indexes(self.id, prepared.declarations[&member.relation].endpoints)
            {
                tx.remove(index);
            }
            if member.endpoints.is_none() {
                memory.charge(member.writer, 64)?;
                nodes.insert((member.relation, member.entity));
            }
            pending.removed += 1;
        }
        for rows in prepared.rows {
            let writer = rows.writer;
            memory.check(writer)?;
            let chunk = Key::allocate(tx)?;
            Properties::stage(tx, chunk, &rows.encoded);
            pending.encoded_bytes += rows.encoded.len();
            for row in 0..rows.keys.len() {
                memory.check(writer)?;
                let owner =
                    Dictionary::intern(tx, 0, writer, &rows.owners[row], writer, &mut memory)?;
                let entity =
                    Dictionary::intern(tx, 1, rows.relation, &rows.keys[row], writer, &mut memory)?;
                let declaration = &prepared.declarations[&rows.relation];
                let endpoints = if let (Some((from, to)), Some(values)) =
                    (declaration.endpoints, &rows.endpoints)
                {
                    Some([
                        Dictionary::intern(tx, 1, from, &values[0][row], writer, &mut memory)?,
                        Dictionary::intern(tx, 1, to, &values[1][row], writer, &mut memory)?,
                        Dictionary::intern(tx, 2, self.id, &values[2][row], writer, &mut memory)?,
                    ])
                } else {
                    None
                };
                let member = StoredMember {
                    writer,
                    owner,
                    relation: rows.relation,
                    entity,
                    revision,
                    property: Key::allocate(tx)?,
                    chunk,
                    row,
                    endpoints,
                };
                let key = member.key();
                if tx
                    .get(&key)
                    .context(NativeSnafu {
                        operation: "check Graph final member",
                    })?
                    .is_some()
                {
                    return ConflictSnafu {
                        resource: "native Graph final member",
                    }
                    .fail();
                }
                memory.charge(writer, 512)?;
                if endpoints.is_some() {
                    edges.insert(key.clone());
                } else {
                    nodes.insert((rows.relation, entity));
                }
                for index in member.indexes(self.id, declaration.endpoints) {
                    tx.insert(index, key.as_slice());
                }
                tx.insert(
                    Key::record(b'L', &[rows.relation, writer, member.property]),
                    Key::encode(&(chunk, row, revision))?,
                );
                tx.insert(key, Key::encode(&member)?);
                pending.added += 1;
            }
        }
        for (relation, entity) in nodes {
            for item in tx.prefix(Key::record(b'E', &[self.id, relation, entity])) {
                let (_, member) = item.context(NativeSnafu {
                    operation: "read affected Graph edges",
                })?;
                let bytes = tx
                    .get(&member)
                    .context(NativeSnafu {
                        operation: "read affected Graph edge",
                    })?
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "native Graph affected edge reference",
                        }
                        .build()
                    })?;
                let member: StoredMember = Key::decode(&bytes)?;
                memory.check(member.writer)?;
                memory.charge(member.writer, 128)?;
                edges.insert(member.key());
            }
        }
        for key in edges {
            let value = tx
                .get(key)
                .context(NativeSnafu {
                    operation: "read staged Graph edge",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph edge reference",
                    }
                    .build()
                })?;
            let member: StoredMember = Key::decode(&value)?;
            memory.check(member.writer)?;
            let declaration = tx
                .get(Key::record(b'f', &[member.relation]))
                .context(NativeSnafu {
                    operation: "read staged Graph edge relation",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph edge relation",
                    }
                    .build()
                })?;
            let declaration: StoredRelation = Key::decode(&declaration)?;
            let (Some((from, to)), Some([source, target, _])) =
                (declaration.endpoints, member.endpoints)
            else {
                return InvalidSnafu {
                    field: "native Graph edge declaration",
                }
                .fail();
            };
            for (relation, entity) in [(from, source), (to, target)] {
                if tx
                    .prefix(Key::record(b'K', &[relation, entity]))
                    .next()
                    .transpose()
                    .context(NativeSnafu {
                        operation: "check Graph endpoint presence",
                    })?
                    .is_none()
                {
                    return InvalidSnafu {
                        field: "native Graph missing endpoint",
                    }
                    .fail();
                }
            }
        }
        for request in requests {
            let head = Head {
                layer: request.layer,
                parent: request.parent,
                revision,
            };
            let encoded = Key::encode(&head)?;
            tx.insert(Key::record(b'h', &[request.writer]), encoded.as_slice());
            tx.insert(
                Key::record(b'l', &[request.layer]),
                Key::encode(&(request.writer, head))?,
            );
            pending.stamps.push(Key::record(b'q', &[request.layer]));
        }
        pending._leases = prepared
            ._leases
            .into_iter()
            .chain(memory.into_leases())
            .collect();
        Ok(pending)
    }
}
