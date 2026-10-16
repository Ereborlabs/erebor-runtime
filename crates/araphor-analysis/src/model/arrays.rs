use araphor_analysis_sdk as sdk;
use araphor_query::datafusion::arrow::array::ByteView;
use arrow_cast::{can_cast_types, cast_with_options, CastOptions};
use sdk::arrow_array::cast::AsArray as _;
use sdk::arrow_array::{
    make_array, new_null_array, Array, ArrayRef, FixedSizeListArray, ListArray, StructArray,
};
use snafu::ResultExt as _;
use std::ops::Range;
use std::sync::Arc;

use crate::Result;

pub(super) struct ModelArrays;

impl ModelArrays {
    pub(super) fn conversion_bytes(array: &ArrayRef, kind: &sdk::DataType) -> Result<usize> {
        if array.data_type() == kind || *kind == sdk::DataType::Null {
            return Ok(0);
        }
        let overflow = || {
            crate::ModelInvalidSnafu {
                field: "model conversion allocation",
            }
            .build()
        };
        let align = |bytes: usize| {
            bytes
                .checked_add(63)
                .map(|bytes| bytes / 64 * 64)
                .ok_or_else(overflow)
        };
        let variable = match (array.data_type(), kind) {
            (sdk::DataType::Utf8View, sdk::DataType::Utf8) => Some(
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::StringViewArray>()
                    .ok_or_else(overflow)?
                    .views()
                    .iter()
                    .try_fold(0usize, |bytes, view| {
                        bytes
                            .checked_add(ByteView::from(*view).length as usize)
                            .ok_or_else(overflow)
                    })?,
            ),
            (sdk::DataType::BinaryView, sdk::DataType::Binary) => Some(
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::BinaryViewArray>()
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
        if let (sdk::DataType::Binary, sdk::DataType::FixedSizeBinary(width)) =
            (array.data_type(), kind)
        {
            let width = usize::try_from(*width).map_err(|_| overflow())?;
            let values = align(array.len().checked_mul(width).ok_or_else(overflow)?)?;
            let validity = align(array.len().div_ceil(8))?;
            return values.checked_add(validity).ok_or_else(overflow);
        }
        let fields = match kind {
            sdk::DataType::List(field) | sdk::DataType::FixedSizeList(field, _) => {
                std::slice::from_ref(field)
            }
            sdk::DataType::Struct(fields) => fields.as_ref(),
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
                    .checked_add(Self::conversion_bytes(
                        &make_array(child.clone()),
                        field.data_type(),
                    )?)
                    .ok_or_else(overflow)
            })
    }

    pub(super) fn cast(array: &ArrayRef, kind: &sdk::DataType) -> Result<ArrayRef> {
        Self::validate_nulls(array.as_ref(), kind, 0..array.len())?;
        Self::convert(array, kind)
    }

    fn validate_nulls(array: &dyn Array, kind: &sdk::DataType, rows: Range<usize>) -> Result<()> {
        if array.data_type() == kind || rows.is_empty() {
            return Ok(());
        }
        match (array.data_type(), kind) {
            (_, sdk::DataType::Null) => {
                if array.logical_nulls().is_none_or(|nulls| {
                    nulls.slice(rows.start, rows.len()).null_count() != rows.len()
                }) {
                    return crate::ModelInvalidSnafu {
                        field: "model array type",
                    }
                    .fail();
                }
            }
            (sdk::DataType::List(_), sdk::DataType::List(field)) => {
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
            (sdk::DataType::FixedSizeList(_, _), sdk::DataType::FixedSizeList(field, _)) => {
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
            (sdk::DataType::Struct(_), sdk::DataType::Struct(fields)) => {
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

    fn convert(array: &ArrayRef, kind: &sdk::DataType) -> Result<ArrayRef> {
        if array.data_type() == kind {
            return Ok(Arc::clone(array));
        }
        if *kind == sdk::DataType::Null {
            return Ok(new_null_array(kind, array.len()));
        }
        let native = can_cast_types(array.data_type(), kind);
        let converted = match (array.data_type(), kind) {
            (sdk::DataType::List(_), sdk::DataType::List(field)) if !native => {
                let array = array.as_list::<i32>();
                ListArray::try_new(
                    Arc::clone(field),
                    array.offsets().clone(),
                    Self::convert(array.values(), field.data_type())?,
                    array.nulls().cloned(),
                )
                .map(|array| Arc::new(array) as ArrayRef)
            }
            (sdk::DataType::FixedSizeList(_, _), sdk::DataType::FixedSizeList(field, size))
                if !native =>
            {
                let array = array.as_fixed_size_list();
                FixedSizeListArray::try_new(
                    Arc::clone(field),
                    *size,
                    Self::convert(array.values(), field.data_type())?,
                    array.nulls().cloned(),
                )
                .map(|array| Arc::new(array) as ArrayRef)
            }
            (sdk::DataType::Struct(_), sdk::DataType::Struct(fields)) if !native => {
                let array = array.as_struct();
                let columns = array
                    .columns()
                    .iter()
                    .zip(fields)
                    .map(|(column, field)| Self::convert(column, field.data_type()))
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
        converted
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use araphor_query::datafusion::arrow::buffer::NullBuffer;
    use sdk::arrow_array::StringViewArray;

    #[test]
    fn fixed_binary_cast_reservation() -> Result<()> {
        use sdk::arrow_array::cast::AsArray as _;
        use sdk::arrow_array::BinaryArray;

        let value = vec![7; 1024];
        let values: ArrayRef = Arc::new(BinaryArray::from(vec![
            Some(value.as_slice()),
            None,
            Some(value.as_slice()),
        ]));
        let nonnull: ArrayRef = Arc::new(BinaryArray::from(vec![Some(value.as_slice()); 3]));
        let nulls: ArrayRef = Arc::new(BinaryArray::from(vec![None::<&[u8]>; 3]));
        for array in [
            nonnull,
            Arc::clone(&nulls),
            values.slice(1, 2),
            nulls.slice(1, 2),
        ] {
            let kind = sdk::DataType::FixedSizeBinary(1024);
            let bytes = ModelArrays::conversion_bytes(&array, &kind)?;
            let converted = ModelArrays::cast(&array, &kind)?;
            assert!(bytes >= converted.get_buffer_memory_size());
            assert_eq!(converted.len(), array.len());
            assert_eq!(converted.null_count(), array.null_count());
            let actual = converted.as_fixed_size_binary();
            let expected = array.as_binary::<i32>();
            for row in 0..array.len() {
                assert_eq!(actual.is_null(row), expected.is_null(row));
                if array.is_valid(row) {
                    assert_eq!(actual.value(row), expected.value(row));
                }
            }
        }
        assert!(ModelArrays::cast(&values, &sdk::DataType::FixedSizeBinary(512)).is_err());
        Ok(())
    }

    #[test]
    fn null_view_cast_reservation() -> Result<()> {
        let original = StringViewArray::from(vec!["x".repeat(1024), "value".into()]);
        let (views, buffers, _) = original.into_parts();
        let array: ArrayRef = Arc::new(StringViewArray::new(
            views,
            buffers,
            Some(NullBuffer::from(vec![false, true])),
        ));
        let bytes = ModelArrays::conversion_bytes(&array, &sdk::DataType::Utf8)?;
        let cast = ModelArrays::cast(&array, &sdk::DataType::Utf8)?;
        assert!(bytes >= cast.get_buffer_memory_size());
        assert!(cast.is_null(0));
        assert_eq!(cast.len(), 2);
        Ok(())
    }
}
