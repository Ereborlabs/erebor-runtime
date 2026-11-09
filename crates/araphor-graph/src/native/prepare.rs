use std::{collections::BTreeMap, sync::Arc};

use arrow_array::{RecordBatch, RecordBatchOptions, StructArray, UInt64Array};
use snafu::ResultExt as _;

use super::{
    record::{Head, Key, Properties, StoredMember, StoredRelation},
    Lease, Reserve, View,
};
use crate::{
    error::{InvalidSnafu, NativeSnafu},
    scratch::Scratch,
    Journal, Relation, Result, Staged,
};

pub struct Prepared {
    pub(super) graph: u64,
    pub(super) parents: BTreeMap<u64, Option<Head>>,
    pub(super) declarations: BTreeMap<u64, StoredRelation>,
    pub(super) closed: BTreeMap<Vec<u8>, StoredMember>,
    pub(super) rows: Vec<Rows>,
    pub(super) _leases: Vec<Lease>,
}

pub(super) struct Rows {
    pub(super) writer: u64,
    pub(super) relation: u64,
    pub(super) encoded: Vec<u8>,
    pub(super) owners: Vec<Vec<u8>>,
    pub(super) keys: Vec<Vec<u8>>,
    pub(super) endpoints: Option<[Vec<Vec<u8>>; 3]>,
}

impl View {
    pub fn prepare(&self, journals: &[&Journal], reserve: &Reserve<'_>) -> Result<Prepared> {
        let mut memory = Scratch::new(reserve);
        let mut prepared = Prepared {
            graph: self.graph.id,
            parents: BTreeMap::new(),
            declarations: BTreeMap::new(),
            closed: BTreeMap::new(),
            rows: Vec::new(),
            _leases: Vec::new(),
        };
        for journal in journals {
            let writer = journal.writer();
            memory.check(writer)?;
            let snapshot = self.snapshot(writer)?;
            if prepared
                .parents
                .insert(writer, self.heads[&writer].clone())
                .is_some()
            {
                return InvalidSnafu {
                    field: "native Graph duplicate journal",
                }
                .fail();
            }
            memory.charge(writer, 256)?;
            for stage in journal.batches() {
                if let Staged::Edits {
                    relation, batch, ..
                } = stage
                {
                    let (declaration, shape) = self.relation(*relation)?;
                    if batch.schema().as_ref() != &shape.command_schema() {
                        return InvalidSnafu {
                            field: "native Graph journal schema",
                        }
                        .fail();
                    }
                    memory.charge(writer, declaration.schema.len() + 256)?;
                    prepared
                        .declarations
                        .entry(*relation)
                        .or_insert_with(|| declaration.clone());
                }
            }
            for (relation, owner, key, expected) in journal.touched_keys() {
                memory.check(writer)?;
                let identity = self.member_key(writer, relation, owner, key)?;
                let stored = identity
                    .as_ref()
                    .map(|key| {
                        snapshot.get(key).context(NativeSnafu {
                            operation: "read Graph journal base",
                        })
                    })
                    .transpose()?
                    .flatten();
                if expected.is_some_and(|expected| expected != stored.is_some()) {
                    return InvalidSnafu {
                        field: "native Graph journal base presence",
                    }
                    .fail();
                }
                if let (Some(key), Some(value)) = (identity, stored) {
                    prepared.close(key, &value, writer, &mut memory)?;
                }
            }
            for owner in journal.clear_owners() {
                let prefix = if let Some(owner) = owner {
                    let Some(owner) = super::record::Dictionary::find(snapshot, 0, writer, owner)?
                    else {
                        continue;
                    };
                    Key::record(b'M', &[writer, owner])
                } else {
                    Key::record(b'M', &[writer])
                };
                for item in snapshot.prefix(prefix) {
                    memory.check(writer)?;
                    let (key, value) = item.context(NativeSnafu {
                        operation: "read Graph clear base",
                    })?;
                    prepared.close(key.to_vec(), &value, writer, &mut memory)?;
                }
            }
            let mut groups = BTreeMap::<(u64, usize), (&RecordBatch, Vec<u64>)>::new();
            for (relation, batch, row) in journal.final_rows() {
                memory.check(writer)?;
                memory.charge(writer, 64)?;
                groups
                    .entry((relation, Arc::as_ptr(batch) as usize))
                    .or_insert_with(|| (batch, Vec::new()))
                    .1
                    .push(row as u64);
            }
            for ((relation, _), (batch, rows)) in groups {
                memory.charge(
                    writer,
                    batch.get_array_memory_size().saturating_mul(4)
                        + batch.num_rows().saturating_mul(128),
                )?;
                let batch = arrow_select::take::take_record_batch(batch, &UInt64Array::from(rows))?;
                let (_, shape) = self.relation(relation)?;
                prepared
                    .rows
                    .push(Rows::new(writer, relation, shape, batch)?);
            }
        }
        for member in prepared.closed.values() {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                prepared.declarations.entry(member.relation)
            {
                let declaration = &self.relation(member.relation)?.0;
                memory.charge(member.writer, declaration.schema.len() + 256)?;
                entry.insert(declaration.clone());
            }
        }
        prepared._leases = memory.into_leases();
        Ok(prepared)
    }
}

impl Prepared {
    fn close(
        &mut self,
        key: Vec<u8>,
        value: &[u8],
        writer: u64,
        memory: &mut Scratch<'_>,
    ) -> Result<()> {
        if self.closed.contains_key(&key) {
            return Ok(());
        }
        memory.charge(writer, key.len() + value.len() + 256)?;
        let member: StoredMember = Key::decode(value)?;
        if member.writer != writer || member.key() != key {
            return InvalidSnafu {
                field: "native Graph base identity",
            }
            .fail();
        }
        self.closed.insert(key, member);
        Ok(())
    }
}

impl Rows {
    fn new(writer: u64, relation: u64, shape: &Relation, batch: RecordBatch) -> Result<Self> {
        use arrow_array::Array;
        let values = batch
            .column_by_name("properties")
            .and_then(|array| array.as_any().downcast_ref::<StructArray>())
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "native Graph final properties",
                }
                .build()
            })?;
        let properties = RecordBatch::try_new_with_options(
            Arc::new(shape.properties.clone()),
            values.columns().to_vec(),
            &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
        )?;
        let keys = |name| -> Result<Vec<Vec<u8>>> {
            Ok(View::binary(&batch, name)?
                .iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect())
        };
        Ok(Self {
            writer,
            relation,
            encoded: Properties::encode(&properties)?,
            owners: keys("owner")?,
            keys: keys("key")?,
            endpoints: (shape.kind == crate::EntityKind::Edge)
                .then(|| -> Result<_> { Ok([keys("from")?, keys("to")?, keys("label")?]) })
                .transpose()?,
        })
    }
}
