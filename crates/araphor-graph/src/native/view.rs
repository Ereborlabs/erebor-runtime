use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array};
use fjall::BranchSnapshot;
use snafu::ResultExt as _;

use super::{
    record::{Dictionary, Head, Key, Properties, StoredMember, StoredRelation},
    Graph, Lease, Reserve,
};
use crate::{
    error::{InvalidSnafu, NativeSnafu},
    scratch::Scratch,
    EntityKind, Read, ReadOrigin, Relation, Result,
};

pub(super) struct Chunk {
    pub(super) batch: Arc<RecordBatch>,
    pub(super) _leases: Arc<Vec<Lease>>,
}

pub struct Member {
    pub writer: u64,
    pub relation: u64,
    pub owner: Vec<u8>,
    pub key: Vec<u8>,
    pub endpoints: Option<[Vec<u8>; 3]>,
    pub property: u64,
    pub revision: u64,
    properties: Arc<RecordBatch>,
    pub row: usize,
    _chunk: Arc<Chunk>,
    _leases: Vec<Lease>,
}

impl Member {
    pub fn properties(&self) -> &RecordBatch {
        &self.properties
    }
}

pub struct ReadBatch {
    batch: RecordBatch,
    origins: Vec<ReadOrigin>,
    _leases: Vec<Lease>,
}

impl ReadBatch {
    pub fn batch(&self) -> &RecordBatch {
        &self.batch
    }
    pub fn origins(&self) -> &[ReadOrigin] {
        &self.origins
    }
}

pub struct View {
    pub(super) graph: Graph,
    pub(super) snapshots: BTreeMap<u64, BranchSnapshot>,
    pub(super) heads: BTreeMap<u64, Option<Head>>,
    pub(super) relations: BTreeMap<u64, (StoredRelation, Relation)>,
    pub(super) chunks: Mutex<BTreeMap<(u64, u64), Arc<Chunk>>>,
    _leases: Vec<Lease>,
}

impl View {
    pub(super) fn new(
        graph: Graph,
        snapshot: BranchSnapshot,
        mut selected: BTreeMap<u64, BranchSnapshot>,
        reserve: &Reserve<'_>,
    ) -> Result<Self> {
        let mut memory = Scratch::new(reserve);
        let mut relations = BTreeMap::new();
        for item in snapshot.prefix(Key::record(b'g', &[graph.id])) {
            memory.check(0)?;
            let (_, value) = item.context(NativeSnafu {
                operation: "read Graph relations",
            })?;
            let relation = Key::number(&value)?;
            let record = snapshot
                .get(Key::record(b'f', &[relation]))
                .context(NativeSnafu {
                    operation: "read Graph relation",
                })?
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "native Graph relation reference",
                    }
                    .build()
                })?;
            memory.charge(0, record.len().saturating_mul(4) + 256)?;
            let stored: StoredRelation = Key::decode(&record)?;
            if stored.graph != graph.id {
                return InvalidSnafu {
                    field: "native Graph relation scope",
                }
                .fail();
            }
            let shape = stored.shape()?;
            relations.insert(relation, (stored, shape));
        }
        let mut snapshots = BTreeMap::new();
        let mut heads = BTreeMap::new();
        for item in snapshot.prefix(Key::record(b'v', &[graph.id])) {
            let (_, value) = item.context(NativeSnafu {
                operation: "read Graph writers",
            })?;
            let writer = Key::number(&value)?;
            memory.check(writer)?;
            memory.charge(writer, 256)?;
            let view = selected.remove(&writer).unwrap_or_else(|| snapshot.clone());
            if view
                .get(Key::record(b'w', &[writer]))
                .context(NativeSnafu {
                    operation: "check Graph view writer",
                })?
                .as_deref()
                != Some(graph.id.to_be_bytes().as_slice())
            {
                return InvalidSnafu {
                    field: "native Graph view writer",
                }
                .fail();
            }
            let head = view
                .get(Key::record(b'h', &[writer]))
                .context(NativeSnafu {
                    operation: "read Graph head",
                })?
                .map(|value| Key::decode(&value))
                .transpose()?;
            heads.insert(writer, head);
            snapshots.insert(writer, view);
        }
        if !selected.is_empty() {
            return InvalidSnafu {
                field: "native Graph selected writer",
            }
            .fail();
        }
        Ok(Self {
            graph,
            snapshots,
            heads,
            relations,
            chunks: Mutex::new(BTreeMap::new()),
            _leases: memory.into_leases(),
        })
    }

    pub fn writers(&self) -> impl Iterator<Item = u64> + '_ {
        self.snapshots.keys().copied()
    }

    pub fn head(&self, writer: u64) -> Result<Option<u64>> {
        self.heads
            .get(&writer)
            .map(|head| head.as_ref().map(|head| head.layer))
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph writer",
                }
                .build()
            })
    }

    pub(super) fn snapshot(&self, writer: u64) -> Result<&BranchSnapshot> {
        self.snapshots.get(&writer).ok_or_else(|| {
            InvalidSnafu {
                field: "native Graph writer",
            }
            .build()
        })
    }

    pub(super) fn relation(&self, relation: u64) -> Result<&(StoredRelation, Relation)> {
        self.relations.get(&relation).ok_or_else(|| {
            InvalidSnafu {
                field: "native Graph relation",
            }
            .build()
        })
    }

    pub fn member_key(
        &self,
        writer: u64,
        relation: u64,
        owner: &[u8],
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.relation(relation)?;
        if writer == 0 {
            return InvalidSnafu {
                field: "native Graph member writer",
            }
            .fail();
        }
        let Some(snapshot) = self.snapshots.get(&writer) else {
            return Ok(None);
        };
        let (Some(owner), Some(entity)) = (
            Dictionary::find(snapshot, 0, writer, owner)?,
            Dictionary::find(snapshot, 1, relation, key)?,
        ) else {
            return Ok(None);
        };
        Ok(Some(Key::record(b'M', &[writer, owner, relation, entity])))
    }

    pub fn presence(
        &self,
        writer: u64,
        relation: u64,
        batch: &RecordBatch,
        reserve: &Reserve<'_>,
    ) -> Result<Vec<bool>> {
        if writer == 0 {
            return InvalidSnafu {
                field: "native Graph presence writer",
            }
            .fail();
        }
        self.relation(relation)?;
        let owners = Self::binary(batch, "owner")?;
        let keys = Self::binary(batch, "key")?;
        if !self.snapshots.contains_key(&writer) {
            return Ok(vec![false; batch.num_rows()]);
        }
        let mut memory = Scratch::new(reserve);
        memory.charge(writer, batch.num_rows())?;
        let mut present = Vec::with_capacity(batch.num_rows());
        for row in 0..batch.num_rows() {
            memory.check(writer)?;
            let key = self.member_key(writer, relation, owners.value(row), keys.value(row))?;
            present.push(match key {
                Some(key) => self
                    .snapshot(writer)?
                    .get(key)
                    .context(NativeSnafu {
                        operation: "read Graph presence",
                    })?
                    .is_some(),
                None => false,
            });
        }
        Ok(present)
    }

    pub fn visit(
        &self,
        relation: u64,
        read: Read,
        keys: &RecordBatch,
        reserve: &Reserve<'_>,
        mut visit: impl FnMut(Member) -> Result<()>,
    ) -> Result<()> {
        let (declaration, shape) = self.relation(relation)?;
        if keys.schema().as_ref()
            != &if matches!(read, Read::Owned(_)) {
                arrow_schema::Schema::empty()
            } else {
                Relation::key_schema()
            }
            || !matches!(
                (shape.kind, read),
                (_, Read::Owned(1..))
                    | (EntityKind::Node, Read::Nodes)
                    | (
                        EntityKind::Edge,
                        Read::Outgoing | Read::Incoming | Read::Neighbors
                    )
            )
            || matches!(read, Read::Owned(_)) && keys.num_rows() != 0
        {
            return InvalidSnafu {
                field: "native Graph read declaration",
            }
            .fail();
        }
        let mut memory = Scratch::new(reserve);
        let mut seen = BTreeSet::new();
        for (writer, snapshot) in &self.snapshots {
            memory.check(*writer)?;
            if let Read::Owned(wanted) = read {
                if *writer != wanted {
                    continue;
                }
                for item in snapshot.prefix(Key::record(b'R', &[relation, *writer])) {
                    memory.check(*writer)?;
                    let (_, key) = item.context(NativeSnafu {
                        operation: "scan Graph owned members",
                    })?;
                    visit(self.read_member(*writer, &key, reserve)?)?;
                }
                continue;
            }
            for key in Self::binary(keys, "key")?.iter().flatten() {
                let scopes = declaration.endpoints.unwrap_or((relation, relation));
                let indexes: &[(u8, u64)] = match read {
                    Read::Nodes => &[(b'K', relation)],
                    Read::Outgoing => &[(b'O', scopes.0)],
                    Read::Incoming => &[(b'I', scopes.1)],
                    Read::Neighbors => &[(b'O', scopes.0), (b'I', scopes.1)],
                    Read::Owned(_) => unreachable!(),
                };
                for (kind, scope) in indexes {
                    let Some(entity) = Dictionary::find(snapshot, 1, *scope, key)? else {
                        continue;
                    };
                    for item in snapshot.prefix(Key::record(*kind, &[relation, entity, *writer])) {
                        memory.check(*writer)?;
                        let (_, member) = item.context(NativeSnafu {
                            operation: "scan Graph adjacency",
                        })?;
                        if seen.contains(member.as_ref()) {
                            continue;
                        }
                        memory.charge(*writer, member.len() + 128)?;
                        seen.insert(member.to_vec());
                        visit(self.read_member(*writer, &member, reserve)?)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn member(
        &self,
        writer: u64,
        relation: u64,
        owner: &[u8],
        key: &[u8],
        reserve: &Reserve<'_>,
    ) -> Result<Option<Member>> {
        let Some(key) = self.member_key(writer, relation, owner, key)? else {
            return Ok(None);
        };
        let Some(bytes) = self.snapshot(writer)?.get(&key).context(NativeSnafu {
            operation: "read Graph point member",
        })?
        else {
            return Ok(None);
        };
        self.decode_member(writer, &key, &bytes, reserve).map(Some)
    }

    fn read_member(&self, writer: u64, key: &[u8], reserve: &Reserve<'_>) -> Result<Member> {
        let snapshot = self.snapshot(writer)?;
        let bytes = snapshot
            .get(key)
            .context(NativeSnafu {
                operation: "read Graph member",
            })?
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph member reference",
                }
                .build()
            })?;
        self.decode_member(writer, key, &bytes, reserve)
    }

    fn decode_member(
        &self,
        writer: u64,
        key: &[u8],
        bytes: &[u8],
        reserve: &Reserve<'_>,
    ) -> Result<Member> {
        let snapshot = self.snapshot(writer)?;
        let mut memory = Scratch::new(reserve);
        memory.charge(writer, bytes.len() + 256)?;
        let stored: StoredMember = Key::decode(bytes)?;
        if stored.writer != writer || stored.key() != key {
            return InvalidSnafu {
                field: "native Graph member identity",
            }
            .fail();
        }
        let (declaration, shape) = self.relation(stored.relation)?;
        let owner = Dictionary::resolve(snapshot, 0, writer, stored.owner, writer, &mut memory)?;
        let key = Dictionary::resolve(
            snapshot,
            1,
            stored.relation,
            stored.entity,
            writer,
            &mut memory,
        )?;
        let endpoints = match (declaration.endpoints, stored.endpoints) {
            (Some((from, to)), Some([source, target, label])) => Some([
                Dictionary::resolve(snapshot, 1, from, source, writer, &mut memory)?,
                Dictionary::resolve(snapshot, 1, to, target, writer, &mut memory)?,
                Dictionary::resolve(snapshot, 2, self.graph.id, label, writer, &mut memory)?,
            ]),
            (None, None) => None,
            _ => {
                return InvalidSnafu {
                    field: "native Graph member kind",
                }
                .fail()
            }
        };
        let chunk = self.chunk(writer, stored.chunk, reserve)?;
        if chunk.batch.schema().as_ref() != &shape.properties
            || stored.row >= chunk.batch.num_rows()
        {
            return InvalidSnafu {
                field: "native Graph property row",
            }
            .fail();
        }
        Ok(Member {
            writer,
            relation: stored.relation,
            owner,
            key,
            endpoints,
            property: stored.property,
            revision: stored.revision,
            properties: Arc::clone(&chunk.batch),
            row: stored.row,
            _chunk: chunk,
            _leases: memory.into_leases(),
        })
    }

    fn chunk(&self, writer: u64, id: u64, reserve: &Reserve<'_>) -> Result<Arc<Chunk>> {
        let snapshot = self.snapshot(writer)?;
        let cached = self
            .chunks
            .lock()
            .map_err(|_| {
                InvalidSnafu {
                    field: "native Graph property lock",
                }
                .build()
            })?
            .get(&(writer, id))
            .cloned();
        Ok(if let Some(chunk) = cached {
            chunk
        } else {
            let mut memory = Scratch::new(reserve);
            let batch = Properties::load(snapshot, id, writer, &mut memory)?;
            let chunk = Arc::new(Chunk {
                batch: Arc::new(batch),
                _leases: Arc::new(memory.into_leases()),
            });
            self.chunks
                .lock()
                .map_err(|_| {
                    InvalidSnafu {
                        field: "native Graph property lock",
                    }
                    .build()
                })?
                .entry((writer, id))
                .or_insert(chunk)
                .clone()
        })
    }

    pub fn visit_properties(
        &self,
        relation: u64,
        reserve: &Reserve<'_>,
        mut visit: impl FnMut(ReadBatch) -> Result<()>,
    ) -> Result<()> {
        let (_, shape) = self.relation(relation)?;
        for (writer, snapshot) in &self.snapshots {
            let mut memory = Scratch::new(reserve);
            let mut selected = Vec::new();
            let mut current = None;
            let prefix = Key::record(b'L', &[relation, *writer]);
            for item in snapshot.prefix(&prefix) {
                memory.check(*writer)?;
                let (key, value) = item.context(NativeSnafu {
                    operation: "scan Graph property references",
                })?;
                let reference = Key::number(&key[prefix.len()..])?;
                let (chunk, row, revision): (u64, usize, u64) = Key::decode(&value)?;
                if let Some(id) = current.filter(|id| *id != chunk) {
                    self.emit_properties(*writer, id, shape, &selected, reserve, &mut visit)?;
                    selected.clear();
                }
                memory.charge(*writer, 64)?;
                selected.push((reference, row, revision));
                current = Some(chunk);
            }
            if let Some(chunk) = current {
                self.emit_properties(*writer, chunk, shape, &selected, reserve, &mut visit)?;
            }
        }
        Ok(())
    }

    fn emit_properties(
        &self,
        writer: u64,
        id: u64,
        shape: &Relation,
        selected: &[(u64, usize, u64)],
        reserve: &Reserve<'_>,
        visit: &mut impl FnMut(ReadBatch) -> Result<()>,
    ) -> Result<()> {
        let chunk = self.chunk(writer, id, reserve)?;
        if chunk.batch.schema().as_ref() != &shape.properties
            || selected
                .iter()
                .any(|(_, row, _)| *row >= chunk.batch.num_rows())
        {
            return InvalidSnafu {
                field: "native Graph property reference",
            }
            .fail();
        }
        let indices = UInt64Array::from_iter_values(selected.iter().map(|(_, row, _)| *row as u64));
        let properties = arrow_select::take::take_record_batch(&chunk.batch, &indices)?;
        let batch = RecordBatch::try_new(
            Arc::new(arrow_schema::Schema::new(vec![
                arrow_schema::Field::new("property_ref", arrow_schema::DataType::UInt64, false),
                arrow_schema::Field::new(
                    "properties",
                    arrow_schema::DataType::Struct(shape.properties.fields().clone()),
                    false,
                ),
            ])),
            vec![
                Arc::new(UInt64Array::from_iter_values(
                    selected.iter().map(|(id, _, _)| *id),
                )),
                Arc::new(StructArray::from(properties)),
            ],
        )?;
        let mut output = Scratch::new(reserve);
        output.charge(
            writer,
            batch.get_array_memory_size() + selected.len().saturating_mul(32),
        )?;
        visit(ReadBatch {
            batch,
            origins: selected
                .iter()
                .map(|(_, _, revision)| ReadOrigin {
                    writer,
                    revision: *revision,
                })
                .collect(),
            _leases: output.into_leases(),
        })
    }

    pub fn read(
        &self,
        relation: u64,
        read: Read,
        keys: &RecordBatch,
        reserve: &Reserve<'_>,
        mut visit: impl FnMut(ReadBatch) -> Result<()>,
    ) -> Result<()> {
        let (_, shape) = self.relation(relation)?;
        let mut rows = Vec::new();
        self.visit(relation, read, keys, reserve, |member| {
            rows.push(member);
            Ok(())
        })?;
        rows.sort_by(|left, right| {
            (left.writer, &left.owner, &left.key).cmp(&(right.writer, &right.owner, &right.key))
        });
        if rows.is_empty() {
            return visit(ReadBatch {
                batch: RecordBatch::new_empty(Arc::new(shape.read_schema())),
                origins: Vec::new(),
                _leases: Vec::new(),
            });
        }
        let mut start = 0;
        while start < rows.len() {
            let mut end = start + 1;
            while end < rows.len() && Arc::ptr_eq(&rows[start].properties, &rows[end].properties) {
                end += 1;
            }
            Self::emit(shape, &rows[start..end], reserve, &mut visit)?;
            start = end;
        }
        Ok(())
    }

    fn emit(
        shape: &Relation,
        rows: &[Member],
        reserve: &Reserve<'_>,
        visit: &mut impl FnMut(ReadBatch) -> Result<()>,
    ) -> Result<()> {
        let mut memory = Scratch::new(reserve);
        for row in rows {
            memory.check(row.writer)?;
            let endpoints = row
                .endpoints
                .as_ref()
                .map_or(0, |keys| keys.iter().map(Vec::len).sum());
            memory.charge(
                row.writer,
                row.owner.len() + row.key.len() + endpoints + 256,
            )?;
        }
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|row| row.writer),
            )),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|row| row.owner.as_slice()),
            )),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|row| row.key.as_slice()),
            )),
        ];
        if shape.kind == EntityKind::Edge {
            for field in 0..3 {
                columns.push(Arc::new(BinaryArray::from_iter(rows.iter().map(|row| {
                    row.endpoints.as_ref().map(|ends| ends[field].as_slice())
                }))));
            }
        }
        let selected = UInt64Array::from_iter_values(rows.iter().map(|row| row.row as u64));
        let properties = arrow_select::take::take_record_batch(&rows[0].properties, &selected)?;
        columns.push(Arc::new(StructArray::from(properties)));
        let batch = RecordBatch::try_new(Arc::new(shape.read_schema()), columns)?;
        memory.charge(rows[0].writer, batch.get_array_memory_size())?;
        visit(ReadBatch {
            batch,
            origins: rows
                .iter()
                .map(|row| ReadOrigin {
                    writer: row.writer,
                    revision: row.revision,
                })
                .collect(),
            _leases: memory.into_leases(),
        })
    }

    pub(super) fn binary<'a>(
        batch: &'a RecordBatch,
        name: &'static str,
    ) -> Result<&'a BinaryArray> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph binary key",
                }
                .build()
            })
    }
}
