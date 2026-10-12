use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sdk::arrow_array::UInt64Array;
use snafu::ResultExt as _;

use crate::query::tests::QueryFixture;
use crate::QueryLimits;

use super::*;

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
fn default_ceiling_keeps_small_input() -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let (package, mut evaluation) = input(schema())?;
    evaluation.context.limits = package.exports[0].limits;
    let retained = evaluation.allocated_bytes();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let output =
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, wire| {
            let decoded = wire
                .decode(&package)
                .context(crate::AnalysisContractSnafu)?;
            assert_eq!(
                decoded.inputs[0].data.batches,
                evaluation.inputs[0].data.batches
            );
            assert_eq!(decoded.context.limits, package.exports[0].limits);
            let output = sdk::Output {
                datasets: vec![sdk::Dataset {
                    name: "data".into(),
                    batches: decoded.inputs[0].data.batches.clone(),
                }],
                ..Default::default()
            };
            let bytes = output.allocated_bytes();
            Ok((output, bytes))
        })?;
    assert_eq!(
        output.output.datasets[0].batches,
        evaluation.inputs[0].data.batches
    );
    let capacity = QueryLimits::default().input_capacity;
    let rest = query.retain_analysis_input(capacity - retained)?;
    assert!(query.retain_analysis_input(1).is_err());
    drop(rest);
    drop(output);
    drop(query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn component_leases_cover_wire() -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let (package, evaluation) = input(schema())?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let capacity = QueryLimits::default().input_capacity;
    let retained = evaluation.allocated_bytes();
    let failed =
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, wire| {
            let bytes = retained
                .checked_add(wire.allocated_bytes())
                .ok_or_else(|| {
                    crate::QueryInvalidSnafu {
                        field: "test component allocation",
                    }
                    .build()
                })?;
            let rest = query.retain_analysis_input(capacity - bytes)?;
            assert!(query.retain_analysis_input(1).is_err());
            drop(rest);
            crate::QueryInvalidSnafu {
                field: "test component failure",
            }
            .fail()
        });
    assert!(matches!(
        failed,
        Err(crate::Error::QueryInvalid {
            field: "test component failure",
            ..
        })
    ));
    drop(query.retain_analysis_input(capacity)?);
    let output =
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, wire| {
            let bytes = retained + wire.allocated_bytes();
            drop(query.retain_analysis_input(capacity - bytes)?);
            let output = sdk::Output {
                datasets: vec![sdk::Dataset {
                    name: "data".into(),
                    batches: evaluation.inputs[0].data.batches.clone(),
                }],
                ..Default::default()
            };
            let bytes = output.allocated_bytes();
            Ok((output, bytes))
        })?;
    assert_eq!(
        output.output.datasets[0].batches[0],
        evaluation.inputs[0].data.batches[0]
    );
    let rest = query.retain_analysis_input(capacity - retained)?;
    assert!(query.retain_analysis_input(1).is_err());
    drop(rest);
    drop(output);
    drop(query.retain_analysis_input(capacity)?);
    Ok(())
}

#[test]
fn component_encode_releases_lease() -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let enriched = schema().with_metadata(HashMap::from([("metadata".into(), "x".repeat(1024))]));
    let (package, mut evaluation) = input(enriched)?;
    evaluation.context.limits.max_bytes = 256;
    package.validate_evaluation(&evaluation)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let mut entered = false;
    assert!(matches!(
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, _| {
            entered = true;
            Ok((sdk::Output::default(), 0))
        }),
        Err(crate::Error::AnalysisContract { .. })
    ));
    assert!(!entered);
    drop(query.retain_analysis_input(QueryLimits::default().input_capacity)?);
    let (package, evaluation) = input(schema())?;
    control.cancel()?;
    assert!(matches!(
        query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, _| {
            entered = true;
            Ok((sdk::Output::default(), 0))
        }),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(!entered);
    drop(query.retain_analysis_input(QueryLimits::default().input_capacity)?);
    Ok(())
}

#[test]
fn component_preflight_keeps_limits() -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let (mut package, mut evaluation) = input(schema())?;
    package.exports[0].checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", schema())],
    });
    let initial = query.component_preflight(&package, &evaluation)?;
    let scratch = evaluation.encoding_scratch_bytes()?;
    assert_eq!(
        initial,
        4 * (evaluation.allocated_bytes() + scratch) + 4 * package.allocated_bytes()
    );
    evaluation.checkpoint = Some(sdk::Checkpoint {
        version: 1,
        datasets: Vec::new(),
    });
    assert_eq!(query.component_preflight(&package, &evaluation)?, initial);
    let retained = evaluation.allocated_bytes();
    evaluation
        .checkpoint
        .as_mut()
        .ok_or("checkpoint missing")?
        .datasets
        .push(sdk::Dataset {
            name: "state".into(),
            batches: evaluation.inputs[0].data.batches.clone(),
        });
    package.validate_evaluation(&evaluation)?;
    let expanded = query.component_preflight(&package, &evaluation)?;
    assert!(expanded > initial);
    assert_eq!(
        expanded,
        initial
            + 4 * (evaluation.allocated_bytes() - retained)
            + 4 * (evaluation.encoding_scratch_bytes()? - scratch)
    );
    evaluation.context.limits.max_bytes = QueryLimits::default().input_bytes as u64 + 1;
    assert!(matches!(
        query.component_preflight(&package, &evaluation),
        Err(crate::Error::QueryInvalid {
            field: "component input limits",
            ..
        })
    ));
    Ok(())
}

#[test]
fn empty_inputs_reserve_schema() -> TestResult {
    let fixture = QueryFixture::new()?;
    let query = fixture.owner(QueryLimits::default())?;
    let schema =
        schema().with_metadata(HashMap::from([("metadata".into(), "x".repeat(100 * 1024))]));
    let (package, mut evaluation) = input(schema.clone())?;
    evaluation.inputs[0].data.batches.clear();
    let retained = evaluation.allocated_bytes();
    let capacity = QueryLimits::default().input_capacity;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    for limit in [101 * 1024, 1024] {
        evaluation.context.limits.max_bytes = limit as u64;
        package.validate_evaluation(&evaluation)?;
        let previous = 4 * retained;
        assert_eq!(
            query.component_preflight(&package, &evaluation)?,
            previous + 4 * package.allocated_bytes()
        );
        let blocked = query.retain_analysis_input(capacity - previous)?;
        let mut entered = false;
        let result =
            query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, _| {
                entered = true;
                Ok((sdk::Output::default(), 0))
            });
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisBusy {
                resource: "query input capacity",
                ..
            })
        ));
        assert!(!entered);
        drop(blocked);
        drop(query.retain_analysis_input(capacity)?);
        let result =
            query.evaluate_component([1; 16], &package, &evaluation, &control, |_, _, wire| {
                entered = true;
                let decoded = wire
                    .decode(&package)
                    .context(crate::AnalysisContractSnafu)?;
                assert_eq!(decoded.inputs[0].data.batches.len(), 1);
                assert_eq!(decoded.inputs[0].data.batches[0].num_rows(), 0);
                assert_eq!(decoded.inputs[0].data.batches[0].schema().as_ref(), &schema);
                let output = sdk::Output {
                    datasets: vec![sdk::Dataset {
                        name: "data".into(),
                        batches: Vec::new(),
                    }],
                    ..Default::default()
                };
                let bytes = output.allocated_bytes();
                Ok((output, bytes))
            });
        if limit == 1024 {
            assert!(matches!(result, Err(crate::Error::AnalysisContract { .. })));
            assert!(!entered);
        } else {
            let output = result?;
            assert!(entered);
            assert!(output.output.datasets[0].batches.is_empty());
            let blocked = query.retain_analysis_input(capacity - retained)?;
            assert!(query.retain_analysis_input(1).is_err());
            drop(blocked);
            drop(output);
        }
        drop(query.retain_analysis_input(capacity)?);
    }
    Ok(())
}
