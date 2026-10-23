use std::ops::Range;

use arrow_array::{Array, FixedSizeListArray, Float32Array, Float64Array, ListArray, StructArray};

use crate::{Error, ErrorCode, RecordBatch, Result, Schema};

pub(super) fn validate(batch: &RecordBatch, schema: &Schema) -> Result<()> {
    if batch.schema().as_ref() != schema {
        return Err(Error::contract(ErrorCode::Incompatible, "batch schema"));
    }
    for (field, array) in schema.fields().iter().zip(batch.columns()) {
        if !field.is_nullable() && array.null_count() > 0 {
            return Err(Error::contract(ErrorCode::Invalid, field.name()));
        }
        array.to_data().validate_full()?;
        finite(array.as_ref(), 0..array.len())?;
    }
    Ok(())
}

fn finite(array: &dyn Array, range: Range<usize>) -> Result<()> {
    if let Some(nulls) = array.nulls() {
        let selected = nulls.slice(range.start, range.len());
        for (start, end) in selected.valid_slices() {
            finite_values(array, range.start + start..range.start + end)?;
        }
    } else if !range.is_empty() {
        finite_values(array, range)?;
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
            finite(
                list.values().as_ref(),
                offsets[range.start] as usize..offsets[range.end] as usize,
            )?;
        } else if let Some(list) = values.downcast_ref::<FixedSizeListArray>() {
            let size = list.value_length() as usize;
            finite(list.values().as_ref(), range.start * size..range.end * size)?;
        } else if let Some(structure) = values.downcast_ref::<StructArray>() {
            for child in structure.columns() {
                finite(child.as_ref(), range.clone())?;
            }
        }
        false
    };
    if invalid {
        return Err(Error::contract(ErrorCode::Invalid, "nonfinite number"));
    }
    Ok(())
}
