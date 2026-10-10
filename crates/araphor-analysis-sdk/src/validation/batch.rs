use std::ops::Range;

use arrow_array::{Array, FixedSizeListArray, Float32Array, Float64Array, ListArray, StructArray};

use crate::{Error, ErrorCode, Limits, RecordBatch, Result, Schema};

pub(super) struct BatchBudget {
    bytes_left: u64,
    rows_left: u64,
    batches_left: u32,
}

impl BatchBudget {
    pub(super) fn new(bytes: u64, limits: &Limits) -> Self {
        Self {
            bytes_left: bytes,
            rows_left: limits.max_rows,
            batches_left: limits.max_batches,
        }
    }

    pub(super) fn bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes_left = self
            .bytes_left
            .checked_sub(bytes)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "batch bytes"))?;
        Ok(())
    }

    pub(super) fn batch(&mut self, batch: &RecordBatch, schema: &Schema) -> Result<()> {
        if batch.schema().as_ref() != schema {
            return Err(Error::contract(ErrorCode::Incompatible, "batch schema"));
        }
        self.batches_left = self
            .batches_left
            .checked_sub(1)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "batches"))?;
        self.rows_left = self
            .rows_left
            .checked_sub(batch.num_rows() as u64)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "rows"))?;
        self.bytes(batch.get_array_memory_size() as u64)?;
        for (field, array) in schema.fields().iter().zip(batch.columns()) {
            if !field.is_nullable() && array.null_count() > 0 {
                return Err(Error::contract(ErrorCode::Invalid, field.name()));
            }
            array.to_data().validate_full()?;
            Self::finite(array.as_ref(), 0..array.len())?;
        }
        Ok(())
    }

    fn finite(array: &dyn Array, range: Range<usize>) -> Result<()> {
        if let Some(nulls) = array.nulls() {
            let selected = nulls.slice(range.start, range.len());
            for (start, end) in selected.valid_slices() {
                Self::finite_values(array, range.start + start..range.start + end)?;
            }
        } else if !range.is_empty() {
            Self::finite_values(array, range)?;
        }
        Ok(())
    }

    fn finite_values(array: &dyn Array, range: Range<usize>) -> Result<()> {
        let values = array.as_any();
        let invalid = if let Some(values) = values.downcast_ref::<Float32Array>() {
            values.values()[range]
                .iter()
                .any(|value| !value.is_finite())
        } else if let Some(values) = values.downcast_ref::<Float64Array>() {
            values.values()[range]
                .iter()
                .any(|value| !value.is_finite())
        } else {
            if let Some(list) = values.downcast_ref::<ListArray>() {
                let offsets = list.value_offsets();
                Self::finite(
                    list.values().as_ref(),
                    offsets[range.start] as usize..offsets[range.end] as usize,
                )?;
            } else if let Some(list) = values.downcast_ref::<FixedSizeListArray>() {
                let size = list.value_length() as usize;
                Self::finite(list.values().as_ref(), range.start * size..range.end * size)?;
            } else if let Some(structure) = values.downcast_ref::<StructArray>() {
                for child in structure.columns() {
                    Self::finite(child.as_ref(), range.clone())?;
                }
            }
            false
        };
        if invalid {
            return Err(Error::contract(ErrorCode::Invalid, "nonfinite number"));
        }
        Ok(())
    }
}
