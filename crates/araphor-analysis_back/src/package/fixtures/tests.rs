use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{
    builder::{Float64Builder, ListBuilder},
    Array as _, Float64Array,
};

use super::comparison;
use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageFixtureV1, PackageImplementationV1, PackageRequestV1};

fn schema() -> sdk::Schema {
    sdk::Schema::new(vec![sdk::Field::new(
        "count",
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

#[tokio::test]
async fn package_fixture_row_tolerance() -> TestResult {
    let fixture = Fixture::new()?;
    let mut bundle = bundle(
        "1",
        "SELECT 1::DOUBLE AS count UNION ALL SELECT 2::DOUBLE AS count",
    );
    let artifact = &mut bundle.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.outputs[0].schema = schema();
    model.outputs.push(sdk::Port::new("other", schema()));
    model.tolerance.absolute = 0.01;
    let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] else {
        return Err("SQL".into());
    };
    program
        .outputs
        .insert("other".into(), "SELECT 1::DOUBLE AS count".into());
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
    artifact.fixtures.push(PackageFixtureV1 {
        name: "equal".into(),
        export: "count".into(),
        time_utc_ns: 0,
        seed: None,
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        expected: crate::AnalysisPackageOwner::encode_output(&expected, model)?,
    });
    let changed = sdk::Output {
        datasets: vec![
            dataset("other", vec![1.005])?,
            dataset("rows", vec![1.1, 2.0])?,
        ],
        ..Default::default()
    };
    let mut mismatch = artifact.fixtures[0].clone();
    mismatch.name = "different".into();
    mismatch.expected = crate::AnalysisPackageOwner::encode_output(&changed, model)?;
    artifact.fixtures.push(mismatch);
    fixture.install(bundle, None).await?;
    let response = fixture
        .execute(PackageRequestV1::Test {
            scope_id: "test".into(),
            package_id: "test.model".into(),
            fixture: None,
        })
        .await?;
    assert_eq!(response.tests.len(), 2);
    assert!(
        response
            .tests
            .iter()
            .find(|test| test.fixture == "equal")
            .ok_or("equal")?
            .passed
    );
    assert!(
        !response
            .tests
            .iter()
            .find(|test| test.fixture == "different")
            .ok_or("different")?
            .passed
    );
    Ok(())
}

mod clock;

#[test]
fn package_fixture_reference_comparison() -> TestResult {
    let model = sdk::Model::new("test", Vec::new(), vec![sdk::Port::new("rows", schema())]);
    let row = |index| sdk::RowRef {
        dataset: "rows".into(),
        row: index,
    };
    let mut actual = sdk::Output {
        datasets: vec![dataset("rows", vec![1.0, 2.0])?],
        evidence: vec![
            sdk::EvidenceLink {
                output: row(0),
                input: row(0),
            },
            sdk::EvidenceLink {
                output: row(1),
                input: row(1),
            },
        ],
        reasons: vec![
            sdk::ReasonValue {
                output: row(0),
                code: "first".into(),
                details: batch(vec![1.0])?,
            },
            sdk::ReasonValue {
                output: row(1),
                code: "second".into(),
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
    assert!(comparison::output(&actual, &expected, &model));
    actual.reasons[0].details = batch(vec![3.0])?;
    assert!(!comparison::output(&actual, &expected, &model));
    actual = expected.clone();
    actual.evidence[0].input.row = 0;
    assert!(!comparison::output(&actual, &expected, &model));
    actual = expected.clone();
    actual.checkpoint.as_mut().ok_or("checkpoint")?.version = 2;
    assert!(!comparison::output(&actual, &expected, &model));
    actual = expected.clone();
    actual.datasets[0] = dataset("rows", vec![2.0, 1.0])?;
    assert!(!comparison::output(&actual, &expected, &model));
    Ok(())
}

#[test]
fn package_fixture_nested_floats() -> TestResult {
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
    let mut model = sdk::Model::new("test", Vec::new(), Vec::new());
    model.tolerance.relative = 0.01;
    assert!(comparison::output(&output(1.0)?, &output(1.005)?, &model));
    assert!(!comparison::output(&output(1.0)?, &output(1.1)?, &model));
    model.tolerance.relative = 0.0;
    assert!(!comparison::output(&output(1.0)?, &output(1.005)?, &model));
    Ok(())
}
