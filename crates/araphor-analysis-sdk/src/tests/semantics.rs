use arrow_array::{ArrayRef, BooleanArray, FixedSizeListArray, Float32Array, Int64Array};

use super::*;

#[test]
fn nested_vectors_preserve_precision() -> TestResult {
    let mut package = FilesCount::package();
    let vector = Arc::new(Field::new("item", DataType::Float32, false));
    let schema = Schema::new(vec![
        Field::new("counter", DataType::UInt64, false),
        Field::new(
            "time",
            DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        Field::new("vector", DataType::FixedSizeList(vector.clone(), 3), false),
    ]);
    package.exports[0]
        .inputs
        .push(Port::new("features", schema.clone()));
    let mut fixture = FilesCount::fixture()?;
    let features: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from(vec![u64::MAX])),
        Arc::new(arrow_array::TimestampNanosecondArray::from(vec![i64::MAX]).with_timezone("UTC")),
        Arc::new(FixedSizeListArray::try_new(
            vector,
            3,
            Arc::new(Float32Array::from(vec![0.25, 0.5, 0.75])),
            None,
        )?),
    ];
    fixture.evaluation.inputs.push(Input {
        data: Dataset {
            name: "features".into(),
            batches: vec![RecordBatch::try_new(Arc::new(schema), features)?],
        },
        revision: Revision {
            owner: "features".into(),
            id: "features.1".into(),
            window: None,
        },
        coverage: Coverage {
            state: CoverageState::Complete,
            limits: vec![],
        },
    });
    package.validate_evaluation(&fixture.evaluation)?;
    let descriptor: Package = serde_json::from_str(&package.inspect()?)?;
    assert_eq!(descriptor, package);
    let batch = &fixture.evaluation.inputs[1].data.batches[0];
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("counter")?
            .value(0),
        u64::MAX
    );
    Ok(())
}

#[test]
fn missing_and_null_are_distinct() -> TestResult {
    let mut package = FilesCount::package();
    let schema = Schema::new(vec![
        Field::new("present", DataType::Boolean, false),
        Field::new("value", DataType::Int64, true),
    ]);
    package.exports[0]
        .inputs
        .push(Port::new("fields", schema.clone()));
    let mut fixture = FilesCount::fixture()?;
    fixture.evaluation.inputs.push(Input {
        data: Dataset {
            name: "fields".into(),
            batches: vec![RecordBatch::try_new(
                Arc::new(schema),
                vec![
                    Arc::new(BooleanArray::from(vec![false, true, true])),
                    Arc::new(Int64Array::from(vec![None, None, Some(0)])),
                ],
            )?],
        },
        revision: Revision {
            owner: "fixture".into(),
            id: "fields.1".into(),
            window: None,
        },
        coverage: Coverage {
            state: CoverageState::Unknown,
            limits: vec!["SOURCE_GAP".into()],
        },
    });
    package.validate_evaluation(&fixture.evaluation)?;
    assert_eq!(
        fixture.evaluation.inputs[1].coverage.state,
        CoverageState::Unknown
    );
    Ok(())
}

#[test]
fn prior_result_supplies_retained_evidence() -> TestResult {
    let mut package = FilesCount::package();
    let mut prior = package.exports[0].outputs[0].clone();
    prior.name = "prior".into();
    prior.evidence_required = false;
    package.exports[0].inputs.push(prior);
    let mut fixture = FilesCount::fixture()?;
    let prior = FilesCount::evaluate(&fixture.evaluation)?
        .datasets
        .remove(0);
    fixture.evaluation.inputs.push(Input {
        data: Dataset {
            name: "prior".into(),
            batches: prior.batches,
        },
        revision: Revision {
            owner: "AnalysisStore".into(),
            id: "result.exact.1".into(),
            window: None,
        },
        coverage: Coverage {
            state: CoverageState::Complete,
            limits: vec![],
        },
    });
    let mut output = FilesCount::evaluate(&fixture.evaluation)?;
    output.evidence = vec![EvidenceLink {
        output: RowRef {
            dataset: "counts".into(),
            row: 0,
        },
        input: RowRef {
            dataset: "prior".into(),
            row: 0,
        },
    }];
    package.validate_output(&fixture.evaluation, &output)?;
    output.evidence[0].input.dataset = "checkpoint".into();
    assert!(package
        .validate_output(&fixture.evaluation, &output)
        .is_err());
    Ok(())
}

#[test]
fn rejects_nonfinite_parameters() -> TestResult {
    let mut package = FilesCount::package();
    let schema = Schema::new(vec![Field::new("threshold", DataType::Float32, false)]);
    package.exports[0].parameters = schema.clone();
    let mut fixture = FilesCount::fixture()?;
    fixture.evaluation.parameters = Some(RecordBatch::try_new(
        Arc::new(schema),
        vec![Arc::new(Float32Array::from(vec![f32::NAN]))],
    )?);
    assert_eq!(
        package
            .validate_evaluation(&fixture.evaluation)
            .err()
            .ok_or("nonfinite number accepted")?
            .code(),
        ErrorCode::Invalid
    );
    Ok(())
}

#[test]
fn invalid_output_never_returns_report() -> TestResult {
    let package = FilesCount::package();
    let fixture = FilesCount::fixture()?;
    let result = package.test(&fixture, |input| {
        let mut output = FilesCount::evaluate(input)?;
        output.datasets[0].name = "undeclared".into();
        Ok(output)
    });
    assert_eq!(
        result.err().ok_or("bad output produced report")?.code(),
        ErrorCode::Invalid
    );
    Ok(())
}
