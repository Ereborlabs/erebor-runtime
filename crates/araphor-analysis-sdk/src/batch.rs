use std::ops::Range;
use std::sync::Arc;

use arrow_array::cast::AsArray as _;
use arrow_array::{
    make_array, new_null_array, Array, ArrayRef, FixedSizeListArray, ListArray, RecordBatchOptions,
    StructArray,
};
use arrow_cast::{can_cast_types, cast_with_options, CastOptions};
use arrow_data::ByteView;

use crate::{DataType, Dataset, Error, ErrorCode, RecordBatch, Result, Schema, TimeUnit};

impl Dataset {
    /// Return the buffer allocation bound before batch normalization.
    pub fn conversion_bytes(batch: &RecordBatch, schema: &Schema) -> Result<usize> {
        batch
            .columns()
            .iter()
            .zip(schema.fields())
            .try_fold(0usize, |bytes, (array, field)| {
                bytes
                    .checked_add(Self::array_bytes(array, field.data_type())?)
                    .ok_or_else(|| Error::contract(ErrorCode::Invalid, "conversion allocation"))
            })
    }

    /// Normalize a native batch to the declared dataset schema.
    pub fn normalize_batch(batch: RecordBatch, schema: Arc<Schema>) -> Result<RecordBatch> {
        if batch.num_columns() != schema.fields().len() {
            return Err(Error::contract(ErrorCode::Invalid, "batch width"));
        }
        let actual = batch.schema();
        let columns = batch
            .columns()
            .iter()
            .zip(actual.fields())
            .zip(schema.fields())
            .map(|((array, field), expected)| {
                if field.name() != expected.name()
                    || !Self::compatible(field.data_type(), expected.data_type())
                {
                    return Err(Error::contract(ErrorCode::Invalid, "batch schema"));
                }
                Self::cast_array(array, expected.data_type())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RecordBatch::try_new_with_options(
            schema,
            columns,
            &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
        )?)
    }

    fn compatible(actual: &DataType, expected: &DataType) -> bool {
        use DataType::*;
        match (actual, expected) {
            (_, Null) => true,
            (Binary, FixedSizeBinary(_)) | (Utf8View, Utf8) | (BinaryView, Binary) => true,
            (Timestamp(TimeUnit::Nanosecond, _), Timestamp(TimeUnit::Nanosecond, _)) => true,
            (List(left), List(right)) | (FixedSizeList(left, _), FixedSizeList(right, _)) => {
                Self::compatible(left.data_type(), right.data_type())
                    && !matches!((actual, expected), (FixedSizeList(_, a), FixedSizeList(_, b)) if a != b)
            }
            (Struct(left), Struct(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(a, b)| {
                        a.name() == b.name() && Self::compatible(a.data_type(), b.data_type())
                    })
            }
            _ => actual == expected,
        }
    }

    fn array_bytes(array: &ArrayRef, kind: &DataType) -> Result<usize> {
        if array.data_type() == kind || *kind == DataType::Null {
            return Ok(0);
        }
        let overflow = || Error::contract(ErrorCode::Invalid, "conversion allocation");
        let align = |bytes: usize| {
            bytes
                .checked_add(63)
                .map(|bytes| bytes / 64 * 64)
                .ok_or_else(overflow)
        };
        let variable = match (array.data_type(), kind) {
            (DataType::Utf8View, DataType::Utf8) => Some(
                array
                    .as_any()
                    .downcast_ref::<arrow_array::StringViewArray>()
                    .ok_or_else(overflow)?
                    .views()
                    .iter()
                    .try_fold(0usize, |bytes, view| {
                        bytes
                            .checked_add(ByteView::from(*view).length as usize)
                            .ok_or_else(overflow)
                    })?,
            ),
            (DataType::BinaryView, DataType::Binary) => Some(
                array
                    .as_any()
                    .downcast_ref::<arrow_array::BinaryViewArray>()
                    .ok_or_else(overflow)?
                    .views()
                    .iter()
                    .try_fold(0usize, |bytes, view| {
                        bytes
                            .checked_add(ByteView::from(*view).length as usize)
                            .ok_or_else(overflow)
                    })?,
            ),
            _ => None,
        };
        if let Some(data) = variable {
            let data = align(data)?;
            let offsets = align(
                array
                    .len()
                    .checked_add(1)
                    .and_then(|rows| rows.checked_mul(4))
                    .ok_or_else(overflow)?,
            )?;
            let validity = align(array.len().div_ceil(8))?;
            return data
                .checked_add(offsets)
                .and_then(|bytes| bytes.checked_add(validity))
                .ok_or_else(overflow);
        }
        if let (DataType::Binary, DataType::FixedSizeBinary(width)) = (array.data_type(), kind) {
            let width = usize::try_from(*width).map_err(|_| overflow())?;
            let values = align(array.len().checked_mul(width).ok_or_else(overflow)?)?;
            let validity = align(array.len().div_ceil(8))?;
            return values.checked_add(validity).ok_or_else(overflow);
        }
        let fields = match kind {
            DataType::List(field) | DataType::FixedSizeList(field, _) => {
                std::slice::from_ref(field)
            }
            DataType::Struct(fields) => fields.as_ref(),
            _ => return align(array.get_buffer_memory_size()),
        };
        let data = array.to_data();
        if data.child_data().len() != fields.len() {
            return Err(overflow());
        }
        data.child_data()
            .iter()
            .zip(fields)
            .try_fold(0usize, |bytes, (child, field)| {
                bytes
                    .checked_add(Self::array_bytes(
                        &make_array(child.clone()),
                        field.data_type(),
                    )?)
                    .ok_or_else(overflow)
            })
    }

    fn cast_array(array: &ArrayRef, kind: &DataType) -> Result<ArrayRef> {
        Self::validate_nulls(array.as_ref(), kind, 0..array.len())?;
        Self::convert_array(array, kind)
    }

    fn validate_nulls(array: &dyn Array, kind: &DataType, rows: Range<usize>) -> Result<()> {
        if array.data_type() == kind || rows.is_empty() {
            return Ok(());
        }
        match (array.data_type(), kind) {
            (_, DataType::Null) => {
                if array.logical_nulls().is_none_or(|nulls| {
                    nulls.slice(rows.start, rows.len()).null_count() != rows.len()
                }) {
                    return Err(Error::contract(ErrorCode::Invalid, "array type"));
                }
            }
            (DataType::List(_), DataType::List(field)) => {
                let array = array.as_list::<i32>();
                for row in rows {
                    if array.is_valid(row) {
                        let offsets = array.value_offsets();
                        Self::validate_nulls(
                            array.values().as_ref(),
                            field.data_type(),
                            offsets[row] as usize..offsets[row + 1] as usize,
                        )?;
                    }
                }
            }
            (DataType::FixedSizeList(_, _), DataType::FixedSizeList(field, _)) => {
                let array = array.as_fixed_size_list();
                let size = array.value_length() as usize;
                for row in rows {
                    if array.is_valid(row) {
                        Self::validate_nulls(
                            array.values().as_ref(),
                            field.data_type(),
                            row * size..(row + 1) * size,
                        )?;
                    }
                }
            }
            (DataType::Struct(_), DataType::Struct(fields)) => {
                let array = array.as_struct();
                let nulls = array
                    .nulls()
                    .map(|nulls| nulls.slice(rows.start, rows.len()));
                for (column, field) in array.columns().iter().zip(fields) {
                    if let Some(nulls) = &nulls {
                        for (start, end) in nulls.valid_slices() {
                            Self::validate_nulls(
                                column.as_ref(),
                                field.data_type(),
                                rows.start + start..rows.start + end,
                            )?;
                        }
                    } else {
                        Self::validate_nulls(column.as_ref(), field.data_type(), rows.clone())?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn convert_array(array: &ArrayRef, kind: &DataType) -> Result<ArrayRef> {
        if array.data_type() == kind {
            return Ok(Arc::clone(array));
        }
        if *kind == DataType::Null {
            return Ok(new_null_array(kind, array.len()));
        }
        let native = can_cast_types(array.data_type(), kind);
        let converted = match (array.data_type(), kind) {
            (DataType::List(_), DataType::List(field)) if !native => {
                let array = array.as_list::<i32>();
                ListArray::try_new(
                    Arc::clone(field),
                    array.offsets().clone(),
                    Self::convert_array(array.values(), field.data_type())?,
                    array.nulls().cloned(),
                )
                .map(|array| Arc::new(array) as ArrayRef)
            }
            (DataType::FixedSizeList(_, _), DataType::FixedSizeList(field, size)) if !native => {
                let array = array.as_fixed_size_list();
                FixedSizeListArray::try_new(
                    Arc::clone(field),
                    *size,
                    Self::convert_array(array.values(), field.data_type())?,
                    array.nulls().cloned(),
                )
                .map(|array| Arc::new(array) as ArrayRef)
            }
            (DataType::Struct(_), DataType::Struct(fields)) if !native => {
                let array = array.as_struct();
                let columns = array
                    .columns()
                    .iter()
                    .zip(fields)
                    .map(|(column, field)| Self::convert_array(column, field.data_type()))
                    .collect::<Result<Vec<_>>>()?;
                StructArray::try_new(fields.clone(), columns, array.nulls().cloned())
                    .map(|array| Arc::new(array) as ArrayRef)
            }
            _ => cast_with_options(
                array.as_ref(),
                kind,
                &CastOptions {
                    safe: false,
                    ..Default::default()
                },
            ),
        };
        Ok(converted?)
    }
}

#[cfg(test)]
mod tests;
