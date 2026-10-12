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
