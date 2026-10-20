use std::sync::Arc;

use arrow_array::NullArray;

use crate::{wire::Dataset, DataType, Field, Limits, RecordBatch, Schema};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn null_has_no_scratch() -> TestResult {
    let schema = Schema::new(vec![Field::new("missing", DataType::Null, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![Arc::new(NullArray::new(1_000_000))],
    )?;
    assert_eq!(Dataset::encoding_scratch(&batch)?, 0);
    let data = crate::Dataset {
        name: "nulls".into(),
        batches: vec![batch],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    assert!(encoded.arrow_ipc.len() < 1024);
    assert_eq!(
        encoded.decode(&schema, Limits::default())?.batches,
        data.batches
    );
    Ok(())
}

#[test]
fn decode_bound_covers_buffers() -> TestResult {
    use arrow_array::types::Int32Type;
    use arrow_array::{ArrayRef, Int32Array, ListArray, StringArray, StructArray};
    use arrow_buffer::NullBuffer;

    for rows in [0, 1, 15, 16, 17, 1000] {
        let child = Arc::new(Field::new("value", DataType::Int32, false));
        let structure = StructArray::new(
            vec![Arc::clone(&child)].into(),
            vec![Arc::new(Int32Array::from_iter_values(0..rows))],
            Some(NullBuffer::from(
                (0..rows).map(|row| row % 2 == 0).collect::<Vec<_>>(),
            )),
        );
        let lists = ListArray::from_iter_primitive::<Int32Type, _, _>(
            (0..rows).map(|row| (row % 2 == 0).then(|| vec![Some(row); 3])),
        );
        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from_iter_values((0..rows).map(|_| "value"))),
            Arc::new(structure),
            Arc::new(lists),
        ];
        let schema = Schema::new(vec![
            Field::new("text", DataType::Utf8, false),
            Field::new("nested", columns[1].data_type().clone(), true),
            Field::new("list", columns[2].data_type().clone(), true),
        ]);
        let batch = RecordBatch::try_new(Arc::new(schema.clone()), columns)?;
        let data = crate::Dataset {
            name: "values".into(),
            batches: vec![batch.clone(), batch],
        };
        let encoded = Dataset::encode(&data, &schema, Limits::default())?;
        let bound = Dataset::decoding_bytes(&encoded.arrow_ipc, Limits::default())?;
        let decoded = encoded.decode(&schema, Limits::default())?;
        let buffers = decoded
            .batches
            .iter()
            .flat_map(RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>();
        let ipc_copy = encoded.arrow_ipc.len().div_ceil(64) * 64;
        assert!(
            bound >= ipc_copy + buffers,
            "rows={rows}, bound={bound}, buffers={buffers}"
        );
        assert_eq!(decoded.batches, data.batches);
    }
    Ok(())
}

#[test]
fn decode_bound_covers_nulls() -> TestResult {
    let rows = 1_000_000;
    let schema = Schema::new(vec![Field::new("missing", DataType::Null, true)]);
    let data = crate::Dataset {
        name: "nulls".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(NullArray::new(rows))],
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let bound = Dataset::decoding_bytes(&encoded.arrow_ipc, Limits::default())?;
    assert!(encoded.arrow_ipc.len() < 1024);
    assert!(bound >= rows.div_ceil(8));
    let mut truncated = encoded.arrow_ipc;
    truncated.pop();
    assert!(Dataset::decoding_bytes(&truncated, Limits::default()).is_err());
    Ok(())
}
