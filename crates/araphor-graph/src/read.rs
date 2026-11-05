use std::sync::Arc;

use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::DataType;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{EntityKind, GraphStore, Read, Relation, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadOrigin {
    pub writer: u64,
    pub revision: u64,
}

impl GraphStore {
    pub fn read(
        &self,
        connection: &Connection,
        graph: u64,
        relation: u64,
        shape: &Relation,
        revision: u64,
        read: Read,
        keys: &RecordBatch,
        mut check: impl FnMut() -> Result<()>,
        mut reserve: impl FnMut(&RecordBatch) -> Result<()>,
        mut visit: impl FnMut(RecordBatch, Vec<ReadOrigin>) -> Result<()>,
    ) -> Result<()> {
        if graph == 0
            || relation == 0
            || revision == 0
            || keys.schema().as_ref()
                != &if matches!(read, Read::Owned(_)) {
                    arrow_schema::Schema::empty()
                } else {
                    Relation::key_schema()
                }
            || matches!(read, Read::Owned(0))
            || matches!(read, Read::Owned(_)) && keys.num_rows() != 0
            || !matches!(
                (shape.kind, read),
                (_, Read::Owned(1..))
                    | (EntityKind::Node, Read::Nodes)
                    | (
                        EntityKind::Edge,
                        Read::Outgoing | Read::Incoming | Read::Neighbors
                    )
            )
        {
            return InvalidSnafu {
                field: "Graph read declaration",
            }
            .fail();
        }
        let declared: Option<(u8,Option<u64>,Option<u64>)> = connection.query_row(
            "SELECT entity_kind,from_relation,to_relation FROM graph_relations WHERE graph_id=? AND relation_id=?",
            params![graph,relation],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().context(DatabaseSnafu { operation: "check Graph read relation" })?;
        if !declared.is_some_and(|(kind, from, to)| {
            kind == shape.kind as u8
                && matches!(
                    (shape.kind, from, to),
                    (EntityKind::Node, None, None) | (EntityKind::Edge, Some(1..), Some(1..))
                )
        }) {
            return InvalidSnafu {
                field: "Graph stored relation",
            }
            .fail();
        }
        let keys = if matches!(read, Read::Owned(_)) {
            None
        } else {
            Some(
                keys.column(0)
                    .as_any()
                    .downcast_ref::<BinaryArray>()
                    .filter(|array| array.null_count() == 0)
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "Graph read keys",
                        }
                        .build()
                    })?
                    .iter()
                    .flatten()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>(),
            )
        };
        let heads = Self::writer_heads(connection, graph, revision)?;
        let rows = self.select(relation, &heads, read, keys.as_deref(), &mut check)?;
        if rows.is_empty() {
            let batch = RecordBatch::new_empty(Arc::new(shape.read_schema()));
            reserve(&batch)?;
            return visit(batch, Vec::new());
        }
        let mut start = 0;
        while start < rows.len() {
            check()?;
            let mut end = start + 1;
            while end < rows.len() && Arc::ptr_eq(&rows[start].properties, &rows[end].properties) {
                check()?;
                end += 1;
            }
            let selected = &rows[start..end];
            let mut columns: Vec<ArrayRef> = vec![
                Arc::new(UInt64Array::from_iter_values(
                    selected.iter().map(|row| row.writer),
                )),
                Arc::new(BinaryArray::from_iter_values(
                    selected.iter().map(|row| row.owner_key.as_ref()),
                )),
                Arc::new(BinaryArray::from_iter_values(
                    selected.iter().map(|row| row.key.as_ref()),
                )),
            ];
            if shape.kind == EntityKind::Edge {
                for field in 0..3 {
                    columns.push(Arc::new(BinaryArray::from_iter_values(
                        selected
                            .iter()
                            .map(|row| row.endpoints.as_ref().unwrap()[field].as_ref()),
                    )));
                }
            }
            let indices = UInt64Array::from_iter_values(selected.iter().map(|row| row.row as u64));
            let properties =
                arrow_select::take::take_record_batch(&rows[start].properties, &indices)?;
            columns.push(Arc::new(StructArray::from(properties)));
            let fields = shape
                .read_schema()
                .fields()
                .iter()
                .zip(&columns)
                .map(|(field, column)| {
                    arrow_schema::Field::new(field.name(), column.data_type().clone(), false)
                })
                .collect::<Vec<_>>();
            let batch = Self::read_batch(
                shape,
                RecordBatch::try_new(Arc::new(arrow_schema::Schema::new(fields)), columns)?,
            )?;
            reserve(&batch)?;
            let origins = selected
                .iter()
                .map(|row| ReadOrigin {
                    writer: row.writer,
                    revision: row.revision,
                })
                .collect();
            visit(batch, origins)?;
            start = end;
        }
        Ok(())
    }

    fn read_batch(shape: &Relation, batch: RecordBatch) -> Result<RecordBatch> {
        let schema = Arc::new(shape.read_schema());
        if batch.num_columns() != schema.fields().len() {
            return InvalidSnafu {
                field: "Graph stored property shape",
            }
            .fail();
        }
        let actual = batch.schema();
        let columns = batch
            .columns()
            .iter()
            .zip(actual.fields())
            .zip(schema.fields())
            .map(|((column, actual), field)| {
                if actual.name() != field.name()
                    || !Self::storage_compatible(actual.data_type(), field.data_type())
                    || !field.is_nullable() && column.null_count() != 0
                {
                    return InvalidSnafu {
                        field: "Graph stored property null",
                    }
                    .fail();
                }
                arrow_cast::cast(column.as_ref(), field.data_type()).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        RecordBatch::try_new(schema, columns).map_err(Into::into)
    }

    pub(crate) fn storage_compatible(actual: &DataType, expected: &DataType) -> bool {
        use DataType::*;
        match (actual, expected) {
            (Binary, FixedSizeBinary(_)) | (Utf8View, Utf8) | (BinaryView, Binary) => true,
            (List(left), List(right)) => {
                Self::storage_compatible(left.data_type(), right.data_type())
            }
            (FixedSizeList(left, a), FixedSizeList(right, b)) => {
                a == b && Self::storage_compatible(left.data_type(), right.data_type())
            }
            (Struct(left), Struct(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(left, right)| {
                        left.name() == right.name()
                            && Self::storage_compatible(left.data_type(), right.data_type())
                    })
            }
            _ => actual == expected,
        }
    }
}
