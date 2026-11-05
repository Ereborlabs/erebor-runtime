use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;

use arrow_array::{Array, BinaryArray, RecordBatch, UInt64Array, UInt8Array};

use crate::{
    error::{ConflictSnafu, InvalidSnafu},
    transaction::Commands,
    EntityKind, Relation, Result, Write,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Identity {
    relation: u64,
    owner: Vec<u8>,
    key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Edit {
    sequence: u64,
    action: Write,
    base_present: Option<bool>,
    batch: Arc<RecordBatch>,
    row: usize,
}

#[derive(Clone, Debug)]
pub enum Staged {
    Edits {
        relation: u64,
        sequence: u64,
        batch: Arc<RecordBatch>,
    },
    Clear {
        sequence: u64,
        batch: Arc<RecordBatch>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Read {
    Owned(u64),
    Nodes,
    Outgoing,
    Incoming,
    Neighbors,
}

type Lookup = BTreeMap<(u64, Vec<u8>), BTreeSet<Identity>>;

#[derive(Debug)]
pub struct Journal {
    identity: Arc<()>,
    writer: u64,
    sequence: u64,
    cleared: u64,
    owners: BTreeMap<Vec<u8>, u64>,
    edits: BTreeMap<Identity, Edit>,
    keys: Lookup,
    outgoing: Lookup,
    incoming: Lookup,
    batches: Vec<Staged>,
}

pub struct PreparedStage {
    identity: Arc<()>,
    expected: u64,
    last: u64,
    edits: BTreeMap<Identity, Edit>,
    endpoints: Vec<(Identity, Vec<u8>, Vec<u8>)>,
    clears: Vec<(Option<Vec<u8>>, u64)>,
    batch: Staged,
    retained: usize,
    scratch: usize,
}

impl PreparedStage {
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }
    pub fn scratch_bytes(&self) -> usize {
        self.scratch
    }
}

impl Journal {
    pub fn stage_budget(batch: &RecordBatch) -> Result<(usize, usize)> {
        let retained = Self::stage_bytes(batch, 4)?;
        let scratch = retained.checked_mul(2).ok_or_else(|| {
            InvalidSnafu {
                field: "Graph stage memory",
            }
            .build()
        })?;
        Ok((retained, scratch))
    }

    pub fn new(writer: u64) -> Result<Self> {
        if writer == 0 {
            return InvalidSnafu {
                field: "writer identity",
            }
            .fail();
        }
        Ok(Self {
            identity: Arc::new(()),
            writer,
            sequence: 0,
            cleared: 0,
            owners: BTreeMap::new(),
            edits: BTreeMap::new(),
            keys: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            batches: Vec::new(),
        })
    }

    pub fn prepare(
        &self,
        relation: u64,
        shape: &Relation,
        batch: RecordBatch,
        base: &[bool],
    ) -> Result<PreparedStage> {
        if relation == 0
            || batch.schema().as_ref() != &shape.command_schema()
            || base.len() != batch.num_rows()
        {
            return InvalidSnafu {
                field: "edit schema",
            }
            .fail();
        }
        Commands::check(&batch, shape.kind == EntityKind::Edge)?;
        let batch = Arc::new(batch);
        let owners = Self::binary(&batch, "owner")?;
        let keys = Self::binary(&batch, "key")?;
        let operations = batch
            .column_by_name("operation")
            .and_then(|array| array.as_any().downcast_ref::<UInt8Array>())
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "edit operation",
                }
                .build()
            })?;
        let first = self.sequence.checked_add(1).ok_or_else(|| {
            InvalidSnafu {
                field: "edit sequence",
            }
            .build()
        })?;
        let last = self
            .sequence
            .checked_add(batch.num_rows() as u64)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "edit sequence",
                }
                .build()
            })?;
        let mut pending = BTreeMap::<Identity, Edit>::new();
        for (row, present) in base.iter().copied().enumerate() {
            let identity = Identity {
                relation,
                owner: owners.value(row).to_vec(),
                key: keys.value(row).to_vec(),
            };
            let prior = pending.get(&identity).or_else(|| self.edits.get(&identity));
            let barrier = self.barrier(&identity.owner);
            let base_present = prior.map_or_else(
                || (barrier == 0).then_some(present),
                |edit| edit.base_present,
            );
            let present = match prior.filter(|edit| edit.sequence > barrier) {
                Some(edit) => edit.action != Write::Remove,
                None => barrier == 0 && present,
            };
            let action = match operations.value(row) {
                0 if !present => Write::Add,
                1 if present => Write::Update,
                2 if present => Write::Remove,
                _ => {
                    return InvalidSnafu {
                        field: "edit state",
                    }
                    .fail()
                }
            };
            pending.insert(
                identity,
                Edit {
                    sequence: first + row as u64,
                    action,
                    base_present,
                    batch: Arc::clone(&batch),
                    row,
                },
            );
        }
        let mut endpoints = Vec::new();
        for (identity, edit) in &pending {
            if shape.kind == EntityKind::Edge && edit.action != Write::Remove {
                endpoints.push((
                    identity.clone(),
                    Self::binary(&edit.batch, "from")?.value(edit.row).to_vec(),
                    Self::binary(&edit.batch, "to")?.value(edit.row).to_vec(),
                ));
            }
        }
        let retained = Self::stage_bytes(&batch, 4)?;
        Ok(PreparedStage {
            identity: Arc::clone(&self.identity),
            expected: self.sequence,
            last,
            edits: pending,
            endpoints,
            clears: Vec::new(),
            batch: Staged::Edits {
                relation,
                sequence: first,
                batch,
            },
            retained,
            scratch: retained.checked_mul(2).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph stage memory",
                }
                .build()
            })?,
        })
    }

    pub fn prepare_clear(&self, batch: RecordBatch) -> Result<PreparedStage> {
        if batch.schema().as_ref() != &Relation::clear_schema() {
            return InvalidSnafu {
                field: "owner clear schema",
            }
            .fail();
        }
        let owners = Self::binary(&batch, "owner")?;
        let first = self.sequence.checked_add(1).ok_or_else(|| {
            InvalidSnafu {
                field: "edit sequence",
            }
            .build()
        })?;
        let last = self
            .sequence
            .checked_add(batch.num_rows() as u64)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "edit sequence",
                }
                .build()
            })?;
        let clears = (0..batch.num_rows())
            .map(|row| {
                (
                    (!owners.is_null(row)).then(|| owners.value(row).to_vec()),
                    first + row as u64,
                )
            })
            .collect();
        let retained = Self::stage_bytes(&batch, 1)?;
        Ok(PreparedStage {
            identity: Arc::clone(&self.identity),
            expected: self.sequence,
            last,
            edits: BTreeMap::new(),
            endpoints: Vec::new(),
            clears,
            batch: Staged::Clear {
                sequence: first,
                batch: Arc::new(batch),
            },
            retained,
            scratch: retained.checked_mul(2).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph stage memory",
                }
                .build()
            })?,
        })
    }

    pub fn publish(&mut self, stage: PreparedStage) -> Result<()> {
        if !Arc::ptr_eq(&self.identity, &stage.identity) || self.sequence != stage.expected {
            return ConflictSnafu {
                resource: "stage basis",
            }
            .fail();
        }
        for (owner, sequence) in stage.clears {
            if let Some(owner) = owner {
                self.owners.insert(owner, sequence);
            } else {
                self.cleared = sequence;
            }
        }
        for (identity, from, to) in stage.endpoints {
            Self::index(&mut self.outgoing, (identity.relation, from), &identity);
            Self::index(&mut self.incoming, (identity.relation, to), &identity);
        }
        for (identity, edit) in stage.edits {
            Self::index(
                &mut self.keys,
                (identity.relation, identity.key.clone()),
                &identity,
            );
            self.edits.insert(identity, edit);
        }
        self.sequence = stage.last;
        self.batches.push(stage.batch);
        Ok(())
    }

    pub fn overlay(
        &self,
        relation: u64,
        shape: &Relation,
        read: Read,
        keys: &[Vec<u8>],
        base: Vec<RecordBatch>,
    ) -> Result<Vec<RecordBatch>> {
        if !matches!(read, Read::Owned(1..))
            && (shape.kind == EntityKind::Node) != (read == Read::Nodes)
        {
            return InvalidSnafu {
                field: "read operation",
            }
            .fail();
        }
        if matches!(read,Read::Owned(writer) if writer!=self.writer) {
            return Ok(base);
        }
        let schema = Arc::new(shape.read_schema());
        let requested = keys.iter().map(Vec::as_slice).collect::<BTreeSet<_>>();
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for batch in base {
            if batch.schema() != schema {
                return InvalidSnafu {
                    field: "read schema",
                }
                .fail();
            }
            let writers = batch
                .column_by_name("writer")
                .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
                .filter(|array| {
                    array.null_count() == 0 && array.values().iter().all(|writer| *writer != 0)
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "read writer",
                    }
                    .build()
                })?;
            let owners = Self::binary(&batch, "owner")?;
            let names = Self::binary(&batch, "key")?;
            if owners.null_count() != 0 || names.null_count() != 0 {
                return InvalidSnafu {
                    field: "read identity",
                }
                .fail();
            }
            let mut selected = Vec::new();
            for row in 0..batch.num_rows() {
                let identity = Identity {
                    relation,
                    owner: owners.value(row).to_vec(),
                    key: names.value(row).to_vec(),
                };
                if !seen.insert((writers.value(row), identity.clone())) {
                    return InvalidSnafu {
                        field: "duplicate read identity",
                    }
                    .fail();
                }
                if writers.value(row) != self.writer
                    || (self.barrier(&identity.owner) == 0 && !self.edits.contains_key(&identity))
                {
                    selected.push(row as u64);
                }
            }
            if selected.len() == batch.num_rows() {
                result.push(batch);
            } else if !selected.is_empty() {
                result.push(arrow_select::take::take_record_batch(
                    &batch,
                    &UInt64Array::from(selected),
                )?);
            }
        }
        let mut candidates = BTreeSet::new();
        if matches!(read, Read::Owned(_)) {
            let first = Identity {
                relation,
                owner: Vec::new(),
                key: Vec::new(),
            };
            candidates.extend(
                self.edits
                    .range(first..)
                    .take_while(|(identity, _)| identity.relation == relation)
                    .map(|(identity, _)| identity),
            );
        }
        for key in keys {
            let lookup = (relation, key.clone());
            for index in match read {
                Read::Owned(_) => Vec::new(),
                Read::Nodes => vec![&self.keys],
                Read::Outgoing => vec![&self.outgoing],
                Read::Incoming => vec![&self.incoming],
                Read::Neighbors => vec![&self.outgoing, &self.incoming],
            } {
                if let Some(found) = index.get(&lookup) {
                    candidates.extend(found.iter());
                }
            }
        }
        let mut batches = BTreeMap::<usize, (Arc<RecordBatch>, Vec<u64>)>::new();
        for identity in candidates {
            let edit = &self.edits[identity];
            if edit.action == Write::Remove
                || edit.sequence <= self.barrier(&identity.owner)
                || !Self::matches(edit, read, &requested)?
            {
                continue;
            }
            let (_, selected) = batches
                .entry(Arc::as_ptr(&edit.batch) as usize)
                .or_insert_with(|| (Arc::clone(&edit.batch), Vec::new()));
            selected.push(edit.row as u64);
        }
        for (_, (batch, indices)) in batches {
            let selected =
                arrow_select::take::take_record_batch(&batch, &UInt64Array::from(indices))?;
            let mut columns: Vec<Arc<dyn Array>> = vec![Arc::new(UInt64Array::from(vec![
                    self.writer;
                    selected.num_rows()
                ]))];
            for field in schema.fields().iter().skip(1) {
                columns.push(Arc::clone(
                    selected.column_by_name(field.name()).ok_or_else(|| {
                        InvalidSnafu {
                            field: "read column",
                        }
                        .build()
                    })?,
                ));
            }
            result.push(RecordBatch::try_new(Arc::clone(&schema), columns)?);
        }
        if result.is_empty() {
            result.push(RecordBatch::new_empty(schema));
        }
        Ok(result)
    }

    pub fn batches(&self) -> &[Staged] {
        &self.batches
    }

    pub fn writer(&self) -> u64 {
        self.writer
    }

    #[cfg(feature = "store")]
    pub(crate) fn touched_keys(&self) -> impl Iterator<Item = (u64, &[u8], &[u8], Option<bool>)> {
        self.edits.iter().map(|(identity, edit)| {
            (
                identity.relation,
                identity.owner.as_slice(),
                identity.key.as_slice(),
                edit.base_present,
            )
        })
    }

    #[cfg(feature = "store")]
    pub(crate) fn final_rows(&self) -> impl Iterator<Item = (u64, &Arc<RecordBatch>, usize)> {
        self.edits.iter().filter_map(|(identity, edit)| {
            (edit.sequence > self.barrier(&identity.owner) && edit.action != Write::Remove)
                .then_some((identity.relation, &edit.batch, edit.row))
        })
    }

    #[cfg(feature = "store")]
    pub(crate) fn clear_owners(&self) -> impl Iterator<Item = Option<&[u8]>> {
        (self.cleared != 0).then_some(None).into_iter().chain(
            self.owners
                .iter()
                .filter(|(_, sequence)| **sequence > self.cleared)
                .map(|(owner, _)| Some(owner.as_slice())),
        )
    }

    pub fn contains(&self, relation: u64, owner: &[u8], key: &[u8]) -> bool {
        self.edits.contains_key(&Identity {
            relation,
            owner: owner.to_vec(),
            key: key.to_vec(),
        })
    }

    fn barrier(&self, owner: &[u8]) -> u64 {
        self.cleared
            .max(self.owners.get(owner).copied().unwrap_or_default())
    }

    fn binary<'a>(batch: &'a RecordBatch, name: &str) -> Result<&'a BinaryArray> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "binary Graph column",
                }
                .build()
            })
    }

    fn index(index: &mut Lookup, key: (u64, Vec<u8>), identity: &Identity) {
        index.entry(key).or_default().insert(identity.clone());
    }

    fn matches(edit: &Edit, read: Read, keys: &BTreeSet<&[u8]>) -> Result<bool> {
        if matches!(read, Read::Owned(_)) {
            return Ok(true);
        }
        let names: &[&str] = match read {
            Read::Owned(_) => &[],
            Read::Nodes => &["key"],
            Read::Outgoing => &["from"],
            Read::Incoming => &["to"],
            Read::Neighbors => &["from", "to"],
        };
        for name in names {
            let array = Self::binary(&edit.batch, name)?;
            if keys.contains(array.value(edit.row)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn stage_bytes(batch: &RecordBatch, copies: usize) -> Result<usize> {
        let entry = size_of::<Identity>() + size_of::<Edit>() + 16 * size_of::<usize>();
        // Allow four index entries and spare B-tree nodes for each row.
        let metadata = batch
            .num_rows()
            .checked_mul(entry)
            .and_then(|bytes| bytes.checked_add(batch.get_array_memory_size()))
            .and_then(|bytes| bytes.checked_add(Self::schema_bytes(batch.schema_ref())))
            .and_then(|bytes| bytes.checked_mul(copies))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(size_of::<Staged>() + size_of::<Arc<()>>()));
        metadata.ok_or_else(|| {
            InvalidSnafu {
                field: "Graph stage memory",
            }
            .build()
        })
    }

    fn schema_bytes(schema: &arrow_schema::Schema) -> usize {
        let mut bytes = schema
            .fields()
            .size()
            .saturating_mul(2)
            .saturating_add(size_of::<[usize; 2]>());
        let capacity = schema.metadata().capacity();
        if capacity != 0 {
            bytes = bytes
                .saturating_add(
                    capacity
                        .saturating_mul(2)
                        .saturating_mul(size_of::<(String, String)>() + 1),
                )
                .saturating_add(size_of::<(String, String)>());
        }
        for (key, value) in schema.metadata() {
            bytes = bytes
                .saturating_add(key.capacity())
                .saturating_add(value.capacity());
        }
        bytes
    }
}
