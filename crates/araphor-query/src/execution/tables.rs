use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::Arc;

use datafusion::arrow::array::{ArrayRef, RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::common::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use snafu::ResultExt as _;

use super::Session;
use crate::{InvalidSnafu, Result, SqlSnafu};

impl Session {
    pub fn indexed_schema(schema: &Schema) -> Result<SchemaRef> {
        let mut names = BTreeSet::new();
        if schema
            .fields()
            .iter()
            .any(|field| field.name() == "__row_index" || !names.insert(field.name()))
        {
            return InvalidSnafu {
                field: "indexed table schema",
            }
            .fail();
        }
        let mut fields = schema.fields().to_vec();
        fields.push(Arc::new(Field::new("__row_index", DataType::UInt64, false)));
        Ok(Arc::new(Schema::new_with_metadata(
            fields,
            schema.metadata().clone(),
        )))
    }

    pub fn check_input<'a>(&self, batches: impl Iterator<Item = &'a RecordBatch>) -> Result<usize> {
        self.control.check()?;
        let bytes = batches.fold(0usize, |total, batch| {
            total
                .saturating_add(batch.get_array_memory_size())
                .saturating_add(size_of::<RecordBatch>())
                .saturating_add(batch.num_columns().saturating_mul(size_of::<ArrayRef>()))
                .saturating_add(batch.num_rows().saturating_mul(size_of::<u64>()))
        });
        if bytes > self.engine.limits.input_bytes {
            return Err(crate::Error::Sql {
                source: DataFusionError::ResourcesExhausted("local input bytes".into()),
            });
        }
        Ok(bytes)
    }

    pub fn index_batches(
        &self,
        schema: SchemaRef,
        batches: &[RecordBatch],
        memory: &MemoryReservation,
        metadata: usize,
    ) -> Result<Vec<RecordBatch>> {
        self.check_input(batches.iter())?;
        if schema.fields().last().is_none_or(|field| {
            field.as_ref() != &Field::new("__row_index", DataType::UInt64, false)
        }) || batches.iter().any(|batch| {
            batch.schema_ref().fields().as_ref() != &schema.fields()[..schema.fields().len() - 1]
                || batch.schema_ref().metadata() != schema.metadata()
        }) {
            return InvalidSnafu {
                field: "indexed batch schema",
            }
            .fail();
        }
        memory
            .try_resize(memory.size().max(metadata))
            .context(SqlSnafu)?;
        // Keep retained metadata separate while native claims consume prepaid bytes.
        let pending = memory.split(memory.size() - metadata);
        for batch in batches {
            self.control.check()?;
            self.memory
                .retain_input(batch, &pending)
                .context(SqlSnafu)?;
        }
        drop(pending);
        let overflow = || crate::Error::Sql {
            source: DataFusionError::ResourcesExhausted("indexed input allocation".into()),
        };
        let headers = size_of::<RecordBatch>()
            .checked_add(
                schema
                    .fields()
                    .len()
                    .checked_mul(size_of::<ArrayRef>())
                    .ok_or_else(overflow)?,
            )
            .and_then(|bytes| bytes.checked_add(size_of::<UInt64Array>()))
            .and_then(|bytes| bytes.checked_mul(batches.len()))
            .and_then(|bytes| metadata.checked_add(bytes))
            .ok_or_else(overflow)?;
        memory.try_resize(headers).context(SqlSnafu)?;
        let mut indexed = Vec::with_capacity(batches.len());
        let mut offset = 0u64;
        for batch in batches {
            self.control.check()?;
            let rows = u64::try_from(batch.num_rows()).map_err(|_| overflow())?;
            let end = offset.checked_add(rows).ok_or_else(overflow)?;
            let bytes = batch
                .num_rows()
                .checked_mul(size_of::<u64>())
                .and_then(|bytes| headers.checked_add(bytes))
                .ok_or_else(overflow)?;
            memory.try_resize(bytes).context(SqlSnafu)?;
            let mut indices = Vec::with_capacity(batch.num_rows());
            indices.extend(offset..end);
            let mut columns = Vec::with_capacity(schema.fields().len());
            columns.extend_from_slice(batch.columns());
            columns.push(Arc::new(UInt64Array::from(indices)));
            let batch = RecordBatch::try_new(Arc::clone(&schema), columns)
                .map_err(DataFusionError::from)
                .context(SqlSnafu)?;
            self.memory.retain_input(&batch, memory).context(SqlSnafu)?;
            indexed.push(batch);
            offset = end;
        }
        memory.try_resize(headers).context(SqlSnafu)?;
        self.control.check()?;
        Ok(indexed)
    }
}

#[cfg(test)]
mod tests;
