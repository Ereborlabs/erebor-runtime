use sdk::arrow_array::{FixedSizeBinaryArray, TimestampNanosecondArray};

use super::*;

#[test]
fn sql_model_portable_precision() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits {
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let schema = sdk::Schema::new(vec![
        sdk::Field::new("value", sdk::DataType::UInt64, false),
        sdk::Field::new(
            "time",
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        sdk::Field::new("bytes", sdk::DataType::FixedSizeBinary(2), false),
    ]);
    let data = sdk::RecordBatch::try_new(
        Arc::new(schema.clone()),
        vec![
            Arc::new(UInt64Array::from(vec![u64::MAX])),
            Arc::new(TimestampNanosecondArray::from(vec![-1]).with_timezone("UTC")),
            Arc::new(FixedSizeBinaryArray::try_from_iter(
                [[0u8, 255]].into_iter(),
            )?),
        ],
    )?;
    let model = sdk::Model::new(
        "identity",
        vec![sdk::Port::new("data", schema.clone())],
        vec![sdk::Port::new("rows", schema)],
    );
    let evaluation = sdk::Evaluation {
        export: "identity".into(),
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "precise".into(),
            time_utc_ns: 100,
            seed: None,
            limits: model.limits,
        },
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "data".into(),
                batches: vec![data.clone()],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
    };
    let package = sdk::Package::new("precise", "1", vec![model]);
    let program = SqlModelV1 {
        outputs: BTreeMap::from([("rows".into(), "SELECT value, time, bytes FROM data".into())]),
        ..Default::default()
    };
    let output = owner.evaluate_model([1; 16], &package, &program, &evaluation, &control()?)?;
    assert_eq!(output.output.datasets[0].batches[0], data);
    drop(output);
    let mut wrong = program.clone();
    wrong.outputs.insert(
        "rows".into(),
        "SELECT CAST(value AS BIGINT) AS value, time, bytes FROM data".into(),
    );
    assert!(owner
        .evaluate_model([1; 16], &package, &wrong, &evaluation, &control()?)
        .is_err());
    let cancelled = control()?;
    cancelled.cancel()?;
    assert!(owner
        .evaluate_model([1; 16], &package, &program, &evaluation, &cancelled)
        .is_err());
    let mut bounded = evaluation;
    bounded.context.limits.max_bytes = 1;
    assert!(owner
        .evaluate_model([1; 16], &package, &program, &bounded, &control()?)
        .is_err());
    Ok(())
}

#[test]
fn sql_model_timestamp_parameters() -> TestResult {
    let schema = sdk::Schema::new(vec![
        sdk::Field::new(
            "time",
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        sdk::Field::new("bytes", sdk::DataType::FixedSizeBinary(2), false),
    ]);
    let input = serde_json::json!({"time":"1969-12-31T23:59:59.999999999Z", "bytes":"00ff"});
    let batch = QueryOwner::model_parameters(&schema, Some(&input))?.ok_or("parameters")?;
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampNanosecondArray>()
            .ok_or("timestamp")?
            .value(0),
        -1
    );
    assert_eq!(
        batch
            .column(1)
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .ok_or("bytes")?
            .value(0),
        &[0, 255]
    );
    Ok(())
}
