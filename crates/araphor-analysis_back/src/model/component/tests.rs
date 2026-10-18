use std::collections::HashMap;
use std::sync::Arc;

use sdk::arrow_array::UInt64Array;

use super::*;
use crate::package::tests::Fixture;
use crate::Limits;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

mod nested;

fn input(schema: sdk::Schema) -> sdk::Result<(sdk::Package, sdk::Evaluation)> {
    let model = sdk::Model::new(
        "evaluate",
        vec![sdk::Port::new("input", schema.clone())],
        vec![sdk::Port::new("data", schema.clone())],
    );
    let evaluation = sdk::Evaluation {
        export: "evaluate".into(),
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: "input".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(schema),
                    vec![Arc::new(UInt64Array::from(vec![7]))],
                )?],
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
        parameters: None,
        context: sdk::EvaluationContext {
            id: "component".into(),
            time_utc_ns: 0,
            seed: None,
            limits: sdk::Limits {
                max_bytes: 1024 * 1024,
                ..model.limits
            },
        },
        checkpoint: None,
    };
    Ok((sdk::Package::new("fixture", "1", vec![model]), evaluation))
}

fn schema() -> sdk::Schema {
    sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)])
}

#[test]
fn exchange_preflight_tracks_checkpoint() -> TestResult {
    let fixture = Fixture::new()?;
    let (mut package, mut evaluation) = input(schema())?;
    package.exports[0].checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", schema())],
    });
    let initial = fixture.owner.exchange_preflight(&package, &evaluation)?;
    let scratch = evaluation.encoding_scratch_bytes()?;
    assert_eq!(
        initial,
        4 * (evaluation.allocated_bytes() + scratch) + 4 * package.allocated_bytes()
    );
    evaluation.checkpoint = Some(sdk::Checkpoint {
        version: 1,
        datasets: Vec::new(),
    });
    assert_eq!(
        fixture.owner.exchange_preflight(&package, &evaluation)?,
        initial
    );
    let retained = evaluation.allocated_bytes();
    evaluation
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .datasets
        .push(sdk::Dataset {
            name: "state".into(),
            batches: evaluation.inputs[0].data.batches.clone(),
        });
    package.validate_evaluation(&evaluation)?;
    assert_eq!(
        fixture.owner.exchange_preflight(&package, &evaluation)?,
        initial
            + 4 * (evaluation.allocated_bytes() - retained)
            + 4 * (evaluation.encoding_scratch_bytes()? - scratch)
    );
    Ok(())
}

#[test]
fn empty_input_reserves_schema() -> TestResult {
    let fixture = Fixture::new()?;
    let schema =
        schema().with_metadata(HashMap::from([("metadata".into(), "x".repeat(100 * 1024))]));
    let (package, mut evaluation) = input(schema.clone())?;
    evaluation.inputs[0].data.batches.clear();
    let preflight = fixture.owner.exchange_preflight(&package, &evaluation)?;
    assert!(preflight >= 4 * package.allocated_bytes());
    let memory = fixture.owner.query.memory();
    let capacity = fixture
        .owner
        .query
        .limits()
        .input_capacity
        .ok_or("configured input capacity")?;
    let pressure = memory.reserve_input(capacity - preflight + 1)?;
    assert!(memory.reserve_input(preflight).is_err());
    drop(pressure);
    let reservation = memory.reserve_input(preflight)?;
    let wire = package.check_evaluation(&evaluation)?.encode()?;
    let decoded = wire.decode(&package)?;
    assert_eq!(decoded.inputs[0].data.batches.len(), 1);
    assert_eq!(decoded.inputs[0].data.batches[0].num_rows(), 0);
    assert_eq!(decoded.inputs[0].data.batches[0].schema().as_ref(), &schema);
    drop((wire, decoded, reservation));
    evaluation.context.limits.max_bytes = 1024;
    assert!(package
        .check_evaluation(&evaluation)
        .and_then(|checked| checked.encode())
        .is_err());
    drop(memory.reserve_input(capacity)?);
    Ok(())
}

#[test]
fn wire_failure_releases_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let schema = schema().with_metadata(HashMap::from([("metadata".into(), "x".repeat(1024))]));
    let (package, mut evaluation) = input(schema)?;
    evaluation.context.limits.max_bytes = 256;
    let checked = package.check_evaluation(&evaluation)?;
    let reservation = fixture
        .owner
        .query
        .memory()
        .reserve_input(fixture.owner.exchange_preflight(&package, &evaluation)?)?;
    assert!(checked.encode().is_err());
    drop(reservation);
    drop(
        fixture.owner.query.memory().reserve_input(
            fixture
                .owner
                .query
                .limits()
                .input_capacity
                .ok_or("configured input capacity")?,
        )?,
    );
    Ok(())
}

#[test]
fn oversized_input_rejects_exchange() -> TestResult {
    let fixture = Fixture::new_limits(Limits {
        input_bytes: 1024,
        ..Default::default()
    })?;
    let schema = schema().with_metadata(HashMap::from([("metadata".into(), "x".repeat(4096))]));
    let (package, evaluation) = input(schema)?;
    assert!(matches!(
        fixture.owner.exchange_preflight(&package, &evaluation),
        Err(crate::Error::ModelLimit {
            resource: "analysis input memory",
            ..
        })
    ));
    drop(
        fixture.owner.query.memory().reserve_input(
            fixture
                .owner
                .query
                .limits()
                .input_capacity
                .ok_or("configured input capacity")?,
        )?,
    );
    Ok(())
}
