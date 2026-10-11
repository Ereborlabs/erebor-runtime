use arrow_buffer::NullBuffer;

use crate::arrow_array::{
    types::Int32Type, Array, BinaryArray, FixedSizeListArray, ListArray, NullArray,
    RecordBatchOptions, StructArray,
};

use super::*;

#[test]
fn ipc_owns_binary_buffers() -> TestResult {
    let payload = vec![7_u8; 1024 * 1024 + 1];
    let schema = Schema::new(vec![Field::new("value", DataType::Binary, true)]);
    let data = crate::Dataset {
        name: "values".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(BinaryArray::from(vec![
                Some(payload.as_slice()),
                None,
                Some(b"".as_slice()),
            ]))],
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let tight = Limits {
        max_bytes: encoded.arrow_ipc.len() as u64,
        ..Limits::default()
    };
    let decoded = encoded.decode(&schema, tight)?;
    assert_eq!(decoded.batches, data.batches);
    assert!(decoded.batches[0].get_array_memory_size() as u64 <= tight.max_bytes);
    assert_eq!(
        encoded
            .decode(
                &schema,
                Limits {
                    max_bytes: tight.max_bytes - 1,
                    ..tight
                },
            )
            .err()
            .ok_or("encoded bytes accepted")?
            .code(),
        ErrorCode::Limit
    );
    Ok(())
}

#[test]
fn ipc_owns_nested_buffers() -> TestResult {
    let lists = ListArray::from_iter_primitive::<Int32Type, _, _>([
        Some(vec![Some(1), None]),
        None,
        Some(Vec::new()),
    ]);
    let fields = vec![
        Field::new("list", lists.data_type().clone(), true),
        Field::new("binary", DataType::Binary, true),
        Field::new("missing", DataType::Null, true),
    ];
    let array = StructArray::try_new(
        fields.clone().into(),
        vec![
            Arc::new(lists),
            Arc::new(BinaryArray::from(vec![
                Some(b"a".as_slice()),
                None,
                Some(b""),
            ])),
            Arc::new(NullArray::new(3)),
        ],
        Some(NullBuffer::from(vec![true, false, true])),
    )?;
    let schema = Schema::new(vec![Field::new(
        "record",
        DataType::Struct(fields.into()),
        true,
    )]);
    let data = crate::Dataset {
        name: "records".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(array)],
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    assert_eq!(
        encoded.decode(&schema, Limits::default())?.batches,
        data.batches
    );
    Ok(())
}

#[test]
fn ipc_keeps_columnless_rows() -> TestResult {
    let schema = Schema::empty();
    let data = crate::Dataset {
        name: "rows".into(),
        batches: vec![RecordBatch::try_new_with_options(
            Arc::new(schema.clone()),
            Vec::new(),
            &RecordBatchOptions::new().with_row_count(Some(7)),
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let decoded = encoded.decode(&schema, Limits::default())?;
    assert_eq!(decoded.batches, data.batches);
    assert_eq!(decoded.batches[0].num_rows(), 7);
    Ok(())
}

#[test]
fn ipc_bounds_sparse_nulls() -> TestResult {
    let field = Arc::new(Field::new("item", DataType::Null, true));
    let array = FixedSizeListArray::try_new(
        Arc::clone(&field),
        65_536,
        Arc::new(NullArray::new(128 * 65_536)),
        Some(NullBuffer::new_null(128)),
    )?;
    let schema = Schema::new(vec![Field::new(
        "lists",
        DataType::FixedSizeList(field, 65_536),
        true,
    )]);
    let data = crate::Dataset {
        name: "lists".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(array)],
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let tight = Limits {
        max_bytes: 64 * 1024,
        ..Limits::default()
    };
    assert!(encoded.arrow_ipc.len() as u64 <= tight.max_bytes);
    assert!(data.batches[0].get_array_memory_size() as u64 <= tight.max_bytes);
    assert_eq!(
        encoded
            .decode(&schema, tight)
            .err()
            .ok_or("sparse child copy accepted")?
            .code(),
        ErrorCode::Limit
    );
    Ok(())
}
