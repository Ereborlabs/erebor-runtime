use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use duckdb::core::LogicalTypeId::{self, *};
use duckdb::types::Value;
use sdk::arrow_array::{
    ArrayRef, BinaryArray, BooleanArray, StringArray, UInt32Array, UInt64Array,
};
use snafu::ResultExt as _;

use super::super::input::InputRow;
use super::schema::GraphTable;
use crate::{AnalysisReadControl, Result};

pub(super) struct ArrowRows<'a> {
    schemas: [Arc<sdk::Schema>; 3],
    held: usize,
    limit: usize,
    control: &'a AnalysisReadControl,
}

impl<'a> ArrowRows<'a> {
    pub(super) fn new(held: usize, limit: usize, control: &'a AnalysisReadControl) -> Result<Self> {
        let schemas = [
            GraphTable::Subjects.schema()?,
            GraphTable::Relationships.schema()?,
            GraphTable::Manifest.schema()?,
        ];
        let schema_bytes = schemas
            .iter()
            .map(|schema| {
                size_of::<sdk::Schema>()
                    + schema
                        .fields()
                        .iter()
                        .map(|field| field.size())
                        .sum::<usize>()
            })
            .sum::<usize>();
        let encoder = Self {
            schemas,
            held: held.saturating_add(schema_bytes),
            limit,
            control,
        };
        encoder.check(0)?;
        Ok(encoder)
    }

    fn check(&self, bytes: usize) -> Result<()> {
        self.control.check()?;
        if self
            .held
            .checked_add(bytes)
            .is_none_or(|total| total > self.limit)
        {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "graph SDK input buffers",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn batch(
        &mut self,
        table: GraphTable,
        rows: &[InputRow],
    ) -> Result<sdk::RecordBatch> {
        let schema = self.schemas[table.index()].clone();
        let row_bytes = rows.iter().try_fold(0usize, |bytes, row| {
            Ok::<_, crate::Error>(bytes.saturating_add(row.allocation_bytes()?))
        })?;
        Self::check_offsets(row_bytes)?;
        let reserved = row_bytes
            .saturating_mul(2)
            .saturating_add(schema.fields().len().saturating_mul(512));
        self.check(reserved)?;
        if rows.iter().any(|row| row.0.len() != schema.fields().len()) {
            return crate::QueryInvalidSnafu {
                field: "graph input row width",
            }
            .fail();
        }
        let columns = table
            .fields()
            .enumerate()
            .map(|(index, field)| self.column(rows, index, field.1))
            .collect::<Result<Vec<_>>>()?;
        let batch = sdk::RecordBatch::try_new(schema, columns)
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)?;
        let bytes = batch
            .get_array_memory_size()
            .saturating_add(size_of::<sdk::RecordBatch>());
        self.check(bytes)?;
        self.held = self.held.saturating_add(bytes);
        Ok(batch)
    }

    pub(super) fn check_offsets(bytes: usize) -> Result<()> {
        if bytes > i32::MAX as usize {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "graph SDK Arrow offsets",
            }
            .fail();
        }
        Ok(())
    }

    fn column(&self, rows: &[InputRow], index: usize, kind: LogicalTypeId) -> Result<ArrayRef> {
        self.control.check()?;
        let invalid = || {
            crate::QueryInvalidSnafu {
                field: "graph input value type",
            }
            .build()
        };
        macro_rules! primitive {
            ($variant:ident, $array:ident) => {{
                let values = rows
                    .iter()
                    .map(|row| match &row.0[index] {
                        Value::$variant(value) => Ok(Some(*value)),
                        Value::Null => Ok(None),
                        _ => Err(invalid()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Arc::new($array::from(values)) as ArrayRef
            }};
        }
        Ok(match kind {
            UBigint => primitive!(UBigInt, UInt64Array),
            UInteger => primitive!(UInt, UInt32Array),
            Boolean => primitive!(Boolean, BooleanArray),
            Blob => {
                let values = rows
                    .iter()
                    .map(|row| match &row.0[index] {
                        Value::Blob(value) => Ok(Some(value.as_slice())),
                        Value::Null => Ok(None),
                        _ => Err(invalid()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Arc::new(BinaryArray::from(values))
            }
            Varchar => {
                let values = rows
                    .iter()
                    .map(|row| match &row.0[index] {
                        Value::Text(value) => Ok(Some(value.as_str())),
                        Value::Null => Ok(None),
                        _ => Err(invalid()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Arc::new(StringArray::from(values))
            }
            _ => return Err(invalid()),
        })
    }
}
