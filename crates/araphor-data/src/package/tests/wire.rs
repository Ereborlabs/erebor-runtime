use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::UInt64Array;

use super::TestResult;
use crate::package::PackageDatasetV1;

#[test]
fn package_ipc_limits() -> TestResult {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let data = sdk::Dataset {
        name: "values".into(),
        batches: vec![sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![1, u64::MAX]))],
        )?],
    };
    let limits = sdk::Limits::default();
    let encoded = PackageDatasetV1::encode(&data, &schema, limits)?;
    let decoded = encoded.decode(&schema, limits)?;
    assert_eq!(decoded.batches, data.batches);
    assert!(encoded
        .decode(
            &schema,
            sdk::Limits {
                max_rows: 1,
                ..limits
            }
        )
        .is_err());
    assert!(PackageDatasetV1::encode(
        &data,
        &schema,
        sdk::Limits {
            max_bytes: 8,
            ..limits
        }
    )
    .is_err());
    let malicious = PackageDatasetV1 {
        name: "values".into(),
        ipc: vec![255, 255, 255, 255, 255, 255, 255, 127],
    };
    assert!(malicious.decode(&schema, limits).is_err());
    let mut truncated = encoded;
    truncated.ipc.truncate(truncated.ipc.len() / 2);
    assert!(truncated.decode(&schema, limits).is_err());
    Ok(())
}
