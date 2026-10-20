use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{
    builder::{Float64Builder, ListBuilder},
    Array as _, Float64Array,
};

use crate::tests::TestResult;
use crate::PackageFixtureV1;

fn schema() -> sdk::Schema {
    sdk::Schema::new(vec![sdk::Field::new(
        "value",
        sdk::DataType::Float64,
        false,
    )])
}

fn batch(values: Vec<f64>) -> TestResult<sdk::RecordBatch> {
    Ok(sdk::RecordBatch::try_new(
        Arc::new(schema()),
        vec![Arc::new(Float64Array::from(values))],
    )?)
}

fn dataset(name: &str, values: Vec<f64>) -> TestResult<sdk::Dataset> {
    Ok(sdk::Dataset {
        name: name.into(),
        batches: vec![batch(values)?],
    })
}

fn model(outputs: Vec<sdk::Port>) -> sdk::Model {
    sdk::Model::new(
        "evaluate",
        vec![sdk::Port::new("source", schema())],
        outputs,
    )
}

fn fixture(
    model: sdk::Model,
    expected: &sdk::Output,
) -> TestResult<(PackageFixtureV1, sdk::Package, sdk::Evaluation)> {
    let saved = PackageFixtureV1 {
        name: "expected".into(),
        export: model.name.clone(),
        time_utc_ns: 123,
        seed: Some(u64::MAX),
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        expected: sdk::wire::Output::encode_model(expected, &model, model.limits)?,
    };
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: vec![sdk::Input {
            data: dataset("source", vec![1.0, 2.0])?,
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "source-1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: None,
        checkpoint: None,
        context: saved.evaluation_context(&model),
    };
    Ok((
        saved,
        sdk::Package::new("fixture", "r1", vec![model]),
        evaluation,
    ))
}

#[test]
fn fixture_batches_and_tolerance() -> TestResult {
    let mut model = model(vec![
        sdk::Port::new("rows", schema()),
        sdk::Port::new("other", schema()),
    ]);
    model.tolerance.absolute = 0.01;
    let expected = sdk::Output {
        datasets: vec![
            dataset("other", vec![1.005])?,
            sdk::Dataset {
                name: "rows".into(),
                batches: vec![batch(vec![1.005])?, batch(vec![2.005])?],
            },
        ],
        ..Default::default()
    };
    let (fixture, package, evaluation) = fixture(model, &expected)?;
    let mut actual = sdk::Output {
        datasets: vec![
            dataset("rows", vec![1.0, 2.0])?,
            dataset("other", vec![1.0])?,
        ],
        ..Default::default()
    };
    actual.datasets[0].batches.insert(0, batch(Vec::new())?);
    assert!(fixture.compare_output(&package, &evaluation, &actual)?);
    actual.datasets[0] = dataset("rows", vec![1.1, 2.0])?;
    assert!(!fixture.compare_output(&package, &evaluation, &actual)?);
    actual.datasets[0] = dataset("rows", vec![2.0, 1.0])?;
    assert!(!fixture.compare_output(&package, &evaluation, &actual)?);
    Ok(())
}

#[test]
fn fixture_references_and_state() -> TestResult {
    let mut model = model(vec![sdk::Port::new("rows", schema())]);
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", schema())],
    });
    model.reasons = ["fixture.FIRST", "fixture.SECOND"]
        .map(|code| sdk::Reason {
            code: code.into(),
            details: schema(),
        })
        .to_vec();
    let row = |name: &str, row| sdk::RowRef {
        dataset: name.into(),
        row,
    };
    let actual = sdk::Output {
        datasets: vec![dataset("rows", vec![1.0, 2.0])?],
        evidence: vec![
            sdk::EvidenceLink {
                output: row("rows", 0),
                input: row("source", 0),
            },
            sdk::EvidenceLink {
                output: row("rows", 1),
                input: row("source", 1),
            },
        ],
        reasons: vec![
            sdk::ReasonValue {
                output: row("rows", 0),
                code: "fixture.FIRST".into(),
                details: batch(vec![1.0])?,
            },
            sdk::ReasonValue {
                output: row("rows", 1),
                code: "fixture.SECOND".into(),
                details: batch(vec![2.0])?,
            },
        ],
        checkpoint: Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![dataset("state", vec![1.0, 2.0])?],
        }),
    };
    let mut expected = actual.clone();
    expected.evidence.reverse();
    expected.reasons.reverse();
    expected.checkpoint.as_mut().ok_or("checkpoint")?.datasets[0].batches =
        vec![batch(vec![1.0])?, batch(vec![2.0])?];
    let (fixture, package, evaluation) = fixture(model, &expected)?;
    assert!(fixture.compare_output(&package, &evaluation, &actual)?);
    let mut changed = actual.clone();
    changed.reasons[0].details = batch(vec![3.0])?;
    assert!(!fixture.compare_output(&package, &evaluation, &changed)?);
    changed = actual.clone();
    changed.evidence[1].input.row = 0;
    assert!(!fixture.compare_output(&package, &evaluation, &changed)?);
    changed = actual.clone();
    changed.checkpoint.as_mut().ok_or("checkpoint")?.datasets[0] =
        dataset("state", vec![1.0, 3.0])?;
    assert!(!fixture.compare_output(&package, &evaluation, &changed)?);
    changed = actual.clone();
    changed.checkpoint.as_mut().ok_or("checkpoint")?.version = 2;
    assert!(fixture
        .compare_output(&package, &evaluation, &changed)
        .is_err());
    Ok(())
}

#[test]
fn fixture_nested_floats() -> TestResult {
    let output = |value| -> TestResult<sdk::Output> {
        let mut values = ListBuilder::new(Float64Builder::new());
        values.values().append_value(value);
        values.values().append_null();
        values.append(true);
        values.values().append_value(value + 100.0);
        values.append(false);
        let values = values.finish();
        let schema = sdk::Schema::new(vec![sdk::Field::new(
            "values",
            values.data_type().clone(),
            true,
        )]);
        Ok(sdk::Output {
            datasets: vec![sdk::Dataset {
                name: "rows".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(schema),
                    vec![Arc::new(values)],
                )?],
            }],
            ..Default::default()
        })
    };
    let expected = output(1.0)?;
    let mut model = model(vec![sdk::Port::new(
        "rows",
        expected.datasets[0].batches[0].schema().as_ref().clone(),
    )]);
    model.tolerance.relative = 0.01;
    let (fixture, mut package, evaluation) = fixture(model, &expected)?;
    assert!(fixture.compare_output(&package, &evaluation, &output(1.005)?)?);
    assert!(!fixture.compare_output(&package, &evaluation, &output(1.1)?)?);
    package.exports[0].tolerance.relative = 0.0;
    assert!(!fixture.compare_output(&package, &evaluation, &output(1.005)?)?);
    Ok(())
}

#[test]
fn fixture_checks_expected_references() -> TestResult {
    let expected = sdk::Output {
        datasets: vec![dataset("rows", vec![1.0])?],
        evidence: vec![sdk::EvidenceLink {
            output: sdk::RowRef {
                dataset: "rows".into(),
                row: 0,
            },
            input: sdk::RowRef {
                dataset: "source".into(),
                row: 0,
            },
        }],
        ..Default::default()
    };
    let (mut fixture, package, evaluation) =
        fixture(model(vec![sdk::Port::new("rows", schema())]), &expected)?;
    fixture.expected.evidence[0].input.row = 2;
    assert!(matches!(
        fixture.compare_output(&package, &evaluation, &expected),
        Err(crate::Error::AnalysisContract { .. })
    ));
    fixture.export = "another".into();
    assert!(matches!(
        fixture.compare_output(&package, &evaluation, &expected),
        Err(crate::Error::Package {
            field: "fixture export",
            ..
        })
    ));
    Ok(())
}

#[test]
fn fixture_context_roundtrip() -> TestResult {
    let model = model(vec![sdk::Port::new("rows", schema())]);
    for (name, now, value) in [
        ("matching", 946684800000000000, 1.0),
        ("later", 946684801000000000, 0.0),
    ] {
        let expected = sdk::Output {
            datasets: vec![dataset("rows", vec![value])?],
            ..Default::default()
        };
        let (mut saved, _, _) = fixture(model.clone(), &expected)?;
        saved.name = name.into();
        saved.time_utc_ns = now;
        let restored: PackageFixtureV1 = serde_json::from_slice(&serde_json::to_vec(&saved)?)?;
        assert_eq!(restored, saved);
        let context = restored.evaluation_context(&model);
        assert_eq!(context.time_utc_ns, now);
        assert_eq!(context.seed, Some(u64::MAX));
        assert_eq!(context.limits, model.limits);
        let mut json = serde_json::to_value(&restored)?;
        let fields = json.as_object_mut().ok_or("fixture object")?;
        fields.remove("time_utc_ns");
        fields.remove("seed");
        let defaults: PackageFixtureV1 = serde_json::from_value(json)?;
        assert_eq!(defaults.evaluation_context(&model).time_utc_ns, 0);
        assert_eq!(defaults.evaluation_context(&model).seed, None);
    }
    Ok(())
}
