use std::collections::HashMap;

use arrow_array::cast::AsArray as _;
use arrow_array::types::Int32Type;
use arrow_array::{
    BinaryArray, FixedSizeListArray, Int32Array, ListArray, StringViewArray, StructArray,
};
use arrow_buffer::{NullBuffer, OffsetBuffer};

use super::*;
use crate::Field;

#[test]
fn normalize_zero_columns() -> Result<()> {
    let schema = Arc::new(Schema::empty());
    for rows in [0, 3] {
        let batch = RecordBatch::try_new_with_options(
            Arc::clone(&schema),
            Vec::new(),
            &RecordBatchOptions::new().with_row_count(Some(rows)),
        )?;
        let normalized = Dataset::normalize_batch(batch, Arc::clone(&schema))?;
        assert_eq!(normalized.num_rows(), rows);
        assert_eq!(normalized.num_columns(), 0);
        assert_eq!(normalized.schema(), schema);
    }
    Ok(())
}

#[test]
fn fixed_binary_cast_reservation() -> Result<()> {
    let value = vec![7; 1024];
    let values: ArrayRef = Arc::new(BinaryArray::from(vec![
        Some(value.as_slice()),
        None,
        Some(value.as_slice()),
    ]));
    let nonnull: ArrayRef = Arc::new(BinaryArray::from(vec![Some(value.as_slice()); 3]));
    let nulls: ArrayRef = Arc::new(BinaryArray::from(vec![None::<&[u8]>; 3]));
    let schema = Arc::new(Schema::new(vec![Field::new(
        "values",
        DataType::FixedSizeBinary(1024),
        true,
    )]));
    for array in [
        nonnull,
        Arc::clone(&nulls),
        values.slice(1, 2),
        nulls.slice(1, 2),
    ] {
        let batch = RecordBatch::try_from_iter([("values", Arc::clone(&array))])?;
        let bytes = Dataset::conversion_bytes(&batch, &schema)?;
        let converted = Dataset::normalize_batch(batch, Arc::clone(&schema))?;
        assert!(bytes >= converted.column(0).get_buffer_memory_size());
        assert_eq!(converted.num_rows(), array.len());
        assert_eq!(converted.column(0).null_count(), array.null_count());
        let actual = converted.column(0).as_fixed_size_binary();
        let expected = array.as_binary::<i32>();
        for row in 0..array.len() {
            assert_eq!(actual.is_null(row), expected.is_null(row));
            if array.is_valid(row) {
                assert_eq!(actual.value(row), expected.value(row));
            }
        }
    }
    let batch = RecordBatch::try_from_iter([("values", values)])?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "values",
        DataType::FixedSizeBinary(512),
        true,
    )]));
    assert!(Dataset::normalize_batch(batch, schema).is_err());
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
    let batch = RecordBatch::try_from_iter([("values", array)])?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "values",
        DataType::Utf8,
        true,
    )]));
    let bytes = Dataset::conversion_bytes(&batch, &schema)?;
    let cast = Dataset::normalize_batch(batch, schema)?;
    assert!(bytes >= cast.column(0).get_buffer_memory_size());
    assert!(cast.column(0).is_null(0));
    assert_eq!(cast.num_rows(), 2);
    Ok(())
}

#[test]
fn normalize_sliced_metadata() -> Result<()> {
    let lists = ListArray::from_iter_primitive::<Int32Type, _, _>([
        Some(vec![None]),
        Some(vec![None, None]),
    ]);
    let actual = RecordBatch::try_from_iter([("values", Arc::new(lists) as ArrayRef)])?.slice(1, 1);
    let item = Arc::new(
        Field::new("item", DataType::Null, true)
            .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
    );
    let expected = Schema::new(vec![Field::new(
        "values",
        DataType::List(Arc::clone(&item)),
        false,
    )]);
    let schema = Arc::new(expected.clone());
    let batch = Dataset::normalize_batch(actual, schema.clone())?;
    assert!(Arc::ptr_eq(&batch.schema(), &schema));
    assert_eq!(batch.schema().as_ref(), &expected);
    let data = batch.column(0).to_data();
    assert_eq!(data.data_type(), &DataType::List(item));
    assert_eq!(data.len(), 1);
    assert_eq!(data.child_data()[0].data_type(), &DataType::Null);
    assert_eq!(
        make_array(data.child_data()[0].clone()).logical_null_count(),
        data.child_data()[0].len()
    );
    Ok(())
}

#[test]
fn normalize_sliced_nulls() -> Result<()> {
    let rows = [Some(vec![Some(1)]), Some(vec![None])];
    let item = Arc::new(
        Field::new("item", DataType::Null, true)
            .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
    );
    for (array, kind) in [
        (
            Arc::new(ListArray::from_iter_primitive::<Int32Type, _, _>(
                rows.clone(),
            )) as ArrayRef,
            DataType::List(Arc::clone(&item)),
        ),
        (
            Arc::new(FixedSizeListArray::from_iter_primitive::<Int32Type, _, _>(
                rows, 1,
            )) as ArrayRef,
            DataType::FixedSizeList(Arc::clone(&item), 1),
        ),
    ] {
        let schema = Arc::new(Schema::new(vec![Field::new("values", kind, true)]));
        let actual = RecordBatch::try_from_iter([("values", array.slice(1, 1))])?;
        assert_eq!(Dataset::conversion_bytes(&actual, &schema)?, 0);
        let normalized = Dataset::normalize_batch(actual, Arc::clone(&schema))?;
        assert_eq!(normalized.schema(), schema);
        assert_eq!(normalized.num_rows(), 1);
        match normalized.column(0).data_type() {
            DataType::List(_) => {
                let lists = normalized.column(0).as_list::<i32>();
                assert_eq!(lists.value_offsets(), &[1, 2]);
                assert_eq!(lists.value(0).logical_null_count(), 1);
                assert_eq!(lists.values().get_buffer_memory_size(), 0);
            }
            DataType::FixedSizeList(_, _) => {
                let lists = normalized.column(0).as_fixed_size_list();
                assert_eq!(lists.value(0).logical_null_count(), 1);
                assert_eq!(lists.values().get_buffer_memory_size(), 0);
            }
            _ => unreachable!(),
        }
        let visible = RecordBatch::try_from_iter([("values", array.slice(0, 1))])?;
        assert!(Dataset::normalize_batch(visible, schema).is_err());
    }
    Ok(())
}

#[test]
fn normalize_masked_nulls() -> Result<()> {
    let values = Arc::new(Int32Array::from(vec![Some(1), None])) as ArrayRef;
    let actual_item = Arc::new(Field::new("item", DataType::Int32, true));
    let expected_item = Arc::new(
        Field::new("item", DataType::Null, true)
            .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
    );
    let nulls = NullBuffer::from(vec![false, true]);
    let lists = ListArray::new(
        Arc::clone(&actual_item),
        OffsetBuffer::new(vec![0, 1, 2].into()),
        Arc::clone(&values),
        None,
    );
    for (array, kind) in [
        (
            Arc::new(ListArray::new(
                Arc::clone(&actual_item),
                lists.offsets().clone(),
                Arc::clone(&values),
                Some(nulls.clone()),
            )) as ArrayRef,
            DataType::List(Arc::clone(&expected_item)),
        ),
        (
            Arc::new(FixedSizeListArray::new(
                Arc::clone(&actual_item),
                1,
                Arc::clone(&values),
                Some(nulls.clone()),
            )) as ArrayRef,
            DataType::FixedSizeList(Arc::clone(&expected_item), 1),
        ),
        (
            Arc::new(StructArray::new(
                vec![Arc::clone(&actual_item)].into(),
                vec![values],
                Some(nulls.clone()),
            )) as ArrayRef,
            DataType::Struct(vec![Arc::clone(&expected_item)].into()),
        ),
        (
            Arc::new(StructArray::new(
                vec![Field::new("nested", lists.data_type().clone(), true)].into(),
                vec![Arc::new(lists)],
                Some(nulls),
            )) as ArrayRef,
            DataType::Struct(
                vec![Field::new("nested", DataType::List(expected_item), true)].into(),
            ),
        ),
    ] {
        let schema = Arc::new(Schema::new(vec![Field::new("values", kind, true)]));
        let actual = RecordBatch::try_from_iter([("values", Arc::clone(&array))])?;
        assert_eq!(Dataset::conversion_bytes(&actual, &schema)?, 0);
        let normalized = Dataset::normalize_batch(actual, Arc::clone(&schema))?;
        assert_eq!(normalized.schema(), schema);
        assert_eq!(normalized.column(0).nulls(), array.nulls());
        assert!(normalized.column(0).is_null(0));
        assert!(normalized.column(0).is_valid(1));

        let visible = array.to_data().into_builder().nulls(None).build()?;
        let visible = RecordBatch::try_from_iter([("values", make_array(visible))])?;
        assert!(Dataset::normalize_batch(visible, schema).is_err());
    }
    Ok(())
}

#[test]
fn normalize_rejects_schema_changes() -> Result<()> {
    let values = Arc::new(Int32Array::from(vec![1])) as ArrayRef;
    let batch = RecordBatch::try_from_iter([("value", Arc::clone(&values))])?;
    for fields in [
        vec![],
        vec![Field::new("renamed", DataType::Int32, false)],
        vec![Field::new("value", DataType::Int64, false)],
    ] {
        assert!(matches!(
            Dataset::normalize_batch(batch.clone(), Arc::new(Schema::new(fields))),
            Err(Error::Contract {
                code: ErrorCode::Invalid,
                ..
            })
        ));
    }
    let structure: ArrayRef = Arc::new(StructArray::new(
        vec![Field::new("child", DataType::Int32, false)].into(),
        vec![values],
        None,
    ));
    let batch = RecordBatch::try_from_iter([("value", structure)])?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Struct(vec![Field::new("renamed", DataType::Int32, false)].into()),
        false,
    )]));
    assert!(matches!(
        Dataset::normalize_batch(batch, schema),
        Err(Error::Contract {
            code: ErrorCode::Invalid,
            ..
        })
    ));
    Ok(())
}
