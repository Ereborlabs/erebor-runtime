use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use araphor_analysis_types::arrow::views::{ContextKeyRow, RecordIdRow};
use araphor_graph::{EntityKind, Journal, Relation};
use arrow_array::{
    Array, ArrayRef, BinaryArray, BooleanArray, FixedSizeBinaryArray, FixedSizeListArray,
    Float32Array, Float64Array, Int8Array, Int16Array, Int32Array, Int64Array, ListArray,
    RecordBatch, StringArray, StructArray, UInt8Array, UInt16Array, UInt32Array, UInt64Array,
};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Schema};
use serde::{Deserialize, Serialize};

use super::Result;

#[derive(Deserialize)]
struct LinkShape {
    #[allow(dead_code)]
    record: RecordIdRow,
    #[allow(dead_code)]
    context: ContextKeyRow,
    #[allow(dead_code)]
    revision: u64,
    #[allow(dead_code)]
    restricted: bool,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub writer: u64,
    pub relation: u64,
    pub owner: Vec<u8>,
    pub key: Vec<u8>,
    pub endpoints: Option<[Vec<u8>; 3]>,
    pub properties: Arc<RecordBatch>,
    pub row: usize,
    pub opened: u64,
}

impl Row {
    pub fn identity(&self) -> (u64, u64, Vec<u8>, Vec<u8>) {
        (
            self.writer,
            self.relation,
            self.owner.clone(),
            self.key.clone(),
        )
    }

    pub fn value(&self) -> Result<RecordBatch> {
        Ok(arrow_select::take::take_record_batch(
            &self.properties,
            &UInt64Array::from(vec![self.row as u64]),
        )?)
    }

    pub fn assert_equal(&self, other: &Self) -> Result<()> {
        assert_eq!(self.identity(), other.identity());
        assert_eq!(self.endpoints, other.endpoints);
        assert_eq!(self.opened, other.opened);
        assert_eq!(self.value()?, other.value()?);
        Ok(())
    }
}

pub struct Group {
    pub writer: u64,
    pub relation: u64,
    pub rows: Vec<Row>,
    pub commands: RecordBatch,
}

pub struct Step {
    pub revision: u64,
    pub captured: u64,
    pub previous: u64,
    pub groups: Vec<Group>,
    pub closed: usize,
}

impl Step {
    pub fn added(&self) -> usize {
        self.groups.iter().map(|g| g.rows.len()).sum()
    }

    pub fn state(&self, writer: u64) -> Vec<u8> {
        [
            writer.to_be_bytes().as_slice(),
            self.captured.to_be_bytes().as_slice(),
            &[0x7f; 64],
        ]
        .concat()
    }

    pub fn is_update(&self, row: &Row) -> bool {
        row.relation == 1 && row.row < self.closed
    }
}

pub struct Fixture {
    pub shapes: BTreeMap<u64, Relation>,
    pub steps: Vec<Step>,
    pub probes: Vec<Vec<u8>>,
}

impl Fixture {
    pub fn new() -> Result<Self> {
        let slot = OnceLock::new();
        let link = araphor_analysis_types::arrow::port::<LinkShape>("causal_link", &slot);
        let shapes = BTreeMap::from([
            (
                1,
                Relation {
                    kind: EntityKind::Node,
                    properties: araphor_analysis_types::FindingMember::port().schema,
                },
            ),
            (
                2,
                Relation {
                    kind: EntityKind::Node,
                    properties: Schema::new(vec![Field::new("kind", DataType::Utf8, false)]),
                },
            ),
            (
                3,
                Relation {
                    kind: EntityKind::Edge,
                    properties: link.schema,
                },
            ),
        ]);
        let counts = [
            (26, 24, 28, 22, 0, 0),
            (29, 27, 6, 5, 1, 0),
            (44, 36, 0, 0, 1, 1),
            (46, 44, 0, 0, 1, 1),
            (62, 48, 0, 0, 1, 1),
            (64, 62, 34, 27, 2, 1),
            (85, 71, 0, 0, 2, 2),
            (87, 85, 34, 27, 3, 2),
        ];
        let mut steps = Vec::new();
        let (mut nodes, mut edges, mut previous) = (0, 0, 1);
        for (revision, captured, node_count, edge_count, findings, closed) in counts {
            let mut groups = Vec::new();
            for (relation, count) in [(2, node_count), (3, edge_count), (1, findings)] {
                if count == 0 {
                    continue;
                }
                let properties = Arc::new(Self::properties(
                    &shapes[&relation].properties,
                    count,
                    revision,
                )?);
                let mut rows = Vec::new();
                let mut operations = Vec::new();
                for index in 0..count {
                    let ordinal = match relation {
                        2 => nodes + index,
                        3 => edges + index,
                        _ => index,
                    };
                    let endpoints = (relation == 3).then(|| {
                        [
                            Self::key(b'n', ordinal % 14),
                            Self::key(b'n', (ordinal + 1) % 14),
                            b"caused_by".to_vec(),
                        ]
                    });
                    let key = if let Some([from, to, label]) = &endpoints {
                        [
                            from.as_slice(),
                            to.as_slice(),
                            label.as_slice(),
                            &(ordinal as u64).to_be_bytes(),
                        ]
                        .concat()
                    } else {
                        Self::key(
                            if relation == 1 { b'f' } else { b'n' },
                            if relation == 2 { ordinal % 14 } else { ordinal },
                        )
                    };
                    rows.push(Row {
                        writer: if relation == 1 { 2 } else { 1 },
                        relation,
                        owner: Self::key(b'o', if relation == 1 { index } else { ordinal + 16 }),
                        key,
                        endpoints,
                        properties: Arc::clone(&properties),
                        row: index,
                        opened: revision,
                    });
                    operations.push(if relation == 1 && index < closed {
                        1
                    } else {
                        0
                    });
                }
                let commands = Self::commands(&shapes[&relation], &rows, operations)?;
                groups.push(Group {
                    writer: if relation == 1 { 2 } else { 1 },
                    relation,
                    rows,
                    commands,
                });
            }
            nodes += node_count;
            edges += edge_count;
            steps.push(Step {
                revision,
                captured,
                previous,
                groups,
                closed,
            });
            previous = revision;
        }
        Ok(Self {
            shapes,
            steps,
            probes: (0..14).map(|i| Self::key(b'n', i)).collect(),
        })
    }

    fn key(kind: u8, id: usize) -> Vec<u8> {
        [
            vec![kind, 0, 255],
            vec![7; 16],
            (id as u64).to_be_bytes().to_vec(),
            vec![kind; 24],
        ]
        .concat()
    }

    fn commands(shape: &Relation, rows: &[Row], ops: Vec<u8>) -> Result<RecordBatch> {
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|r| r.owner.as_slice()),
            )),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|r| r.key.as_slice()),
            )),
            Arc::new(UInt8Array::from(ops)),
        ];
        if shape.kind == EntityKind::Edge {
            for index in 0..3 {
                columns.push(Arc::new(BinaryArray::from_iter_values(
                    rows.iter()
                        .map(|r| r.endpoints.as_ref().unwrap()[index].as_slice()),
                )));
            }
        }
        columns.push(Arc::new(StructArray::from(
            rows[0].properties.as_ref().clone(),
        )));
        Ok(RecordBatch::try_new(
            Arc::new(shape.command_schema()),
            columns,
        )?)
    }

    fn properties(schema: &Schema, count: usize, seed: u64) -> Result<RecordBatch> {
        RecordBatch::try_new(
            Arc::new(schema.clone()),
            schema
                .fields()
                .iter()
                .map(|f| Self::array(f, count, seed))
                .collect::<Result<Vec<_>>>()?,
        )
        .map_err(Into::into)
    }

    fn array(field: &Field, count: usize, seed: u64) -> Result<ArrayRef> {
        macro_rules! number {
            ($array:ty,$ty:ty) => {
                Arc::new(<$array>::from_iter_values(
                    (0..count).map(|i| (seed + i as u64) as $ty),
                )) as ArrayRef
            };
        }
        Ok(match field.data_type() {
            DataType::Boolean => Arc::new(BooleanArray::from(
                (0..count).map(|i| i % 2 == 0).collect::<Vec<_>>(),
            )),
            DataType::UInt8 => number!(UInt8Array, u8),
            DataType::UInt16 => number!(UInt16Array, u16),
            DataType::UInt32 => number!(UInt32Array, u32),
            DataType::UInt64 => number!(UInt64Array, u64),
            DataType::Int8 => number!(Int8Array, i8),
            DataType::Int16 => number!(Int16Array, i16),
            DataType::Int32 => number!(Int32Array, i32),
            DataType::Int64 => number!(Int64Array, i64),
            DataType::Float32 => number!(Float32Array, f32),
            DataType::Float64 => number!(Float64Array, f64),
            DataType::Utf8 => Arc::new(StringArray::from_iter_values(
                (0..count).map(|i| format!("{}-{seed}-{i}", field.name())),
            )),
            DataType::Binary => Arc::new(BinaryArray::from_iter_values(
                (0..count).map(|i| Self::key(b'v', seed as usize + i)),
            )),
            DataType::FixedSizeBinary(size) => Arc::new(FixedSizeBinaryArray::try_from_iter(
                (0..count).map(|i| vec![(seed as usize + i) as u8; *size as usize]),
            )?),
            DataType::Struct(fields) => Arc::new(StructArray::try_new(
                fields.clone(),
                fields
                    .iter()
                    .map(|f| Self::array(f, count, seed))
                    .collect::<Result<Vec<_>>>()?,
                None,
            )?),
            DataType::List(child) => {
                let n = if field.name() == "evidence" { 6 } else { 1 };
                Arc::new(ListArray::try_new(
                    Arc::clone(child),
                    OffsetBuffer::new(
                        (0..=count)
                            .map(|i| (i * n) as i32)
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    Self::array(child, count * n, seed)?,
                    None,
                )?)
            }
            DataType::FixedSizeList(child, n) => Arc::new(FixedSizeListArray::try_new(
                Arc::clone(child),
                *n,
                Self::array(child, count * (*n as usize), seed)?,
                None,
            )?),
            other => return Err(format!("unsupported fixture type {other:?}").into()),
        })
    }

    pub fn expected(&self, revision: u64) -> Vec<Row> {
        let mut rows = BTreeMap::new();
        for step in self.steps.iter().filter(|s| s.revision <= revision) {
            for row in step.groups.iter().flat_map(|g| &g.rows) {
                rows.insert(row.identity(), row.clone());
            }
        }
        rows.into_values().collect()
    }

    pub fn assert_rows(expected: &[Row], actual: &mut [Row]) -> Result<()> {
        actual.sort_by_key(Row::identity);
        assert_eq!(expected.len(), actual.len());
        for (a, b) in expected.iter().zip(actual) {
            a.assert_equal(b)?;
        }
        Ok(())
    }

    pub fn keys(&self) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Arc::new(Relation::key_schema()),
            vec![Arc::new(BinaryArray::from_iter_values(
                self.probes.iter().map(Vec::as_slice),
            ))],
        )?)
    }

    pub fn journals(&self, step: &Step) -> Result<BTreeMap<u64, Journal>> {
        let mut journals = BTreeMap::from([(1, Journal::new(1)?), (2, Journal::new(2)?)]);
        for group in &step.groups {
            let operations = group
                .commands
                .column_by_name("operation")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt8Array>()
                .unwrap();
            let base = operations
                .values()
                .iter()
                .map(|v| *v == 1)
                .collect::<Vec<_>>();
            let journal = journals.get_mut(&group.writer).unwrap();
            let prepared = journal.prepare(
                group.relation,
                &self.shapes[&group.relation],
                group.commands.clone(),
                &base,
            )?;
            journal.publish(prepared)?;
        }
        Ok(journals)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub writer: u64,
    pub owner: u64,
    pub relation: u64,
    pub entity: u64,
    pub opened: u64,
    pub closed: Option<u64>,
    pub property: u64,
    pub endpoints: Option<[u64; 3]>,
}
