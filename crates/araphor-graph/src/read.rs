use std::sync::Arc;

use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array};
use arrow_schema::DataType;
use duckdb::{Connection, params};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{EntityKind, GraphStore, Read, Relation, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadOrigin {
    pub writer: u64,
    pub revision: u64,
}

mod view;
pub use view::GraphReadView;

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
        reserve: impl FnMut(&RecordBatch) -> Result<()>,
        visit: impl FnMut(RecordBatch, Vec<ReadOrigin>) -> Result<()>,
    ) -> Result<()> {
        if graph == 0 || revision == 0 {
            return InvalidSnafu {
                field: "Graph read declaration",
            }
            .fail();
        }
        GraphReadView::check_read(relation, shape, read, keys)?;
        self.read_view(connection, graph, revision, &[relation], &mut check, |_| {
            Ok(())
        })?
        .read(relation, shape, read, keys, check, reserve, visit)
    }
}

impl GraphReadView {
    pub fn read(
        &self,
        relation: u64,
        shape: &Relation,
        read: Read,
        keys: &RecordBatch,
        mut check: impl FnMut() -> Result<()>,
        mut reserve: impl FnMut(&RecordBatch) -> Result<()>,
        mut visit: impl FnMut(RecordBatch, Vec<ReadOrigin>) -> Result<()>,
    ) -> Result<()> {
        check()?;
        Self::check_read(relation, shape, read, keys)?;
        if !self
            .relations
            .get(&relation)
            .is_some_and(|(kind, from, to)| {
                *kind == shape.kind as u8
                    && matches!(
                        (shape.kind, from, to),
                        (EntityKind::Node, None, None) | (EntityKind::Edge, Some(1..), Some(1..))
                    )
            })
        {
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
        let rows = self
            .store
            .select(relation, &self.heads, read, keys.as_deref(), &mut check)?;
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
            let batch = GraphStore::read_batch(
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
    fn check_read(relation: u64, shape: &Relation, read: Read, keys: &RecordBatch) -> Result<()> {
        if relation == 0
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
        Ok(())
    }
}

impl GraphStore {
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
