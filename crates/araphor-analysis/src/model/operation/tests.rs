use std::collections::BTreeMap;
use std::time::Duration;

use super::super::SqlModelV1;
use super::*;
use crate::analysis::{PackageActivationV1, PackageKeyV1};
use crate::package::PackageGrantV1;
use crate::testing::QueryFixture;
use crate::{AnalysisSelectionV1, Limits};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn port(name: &str) -> sdk::Port {
    sdk::Port::new(
        name,
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
    )
}

fn control() -> araphor_data::Result<AnalysisReadControl> {
    AnalysisReadControl::with_timeout(Duration::from_secs(30))
}

fn limits() -> Limits {
    Limits {
        tenant_evaluations: 1,
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    }
}

fn model(values: &[(&str, u64)]) -> sdk::Model {
    let mut model = sdk::Model::new("evaluate", Vec::new(), vec![port("result")]);
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = values
        .iter()
        .map(|(name, value)| sdk::InputPort {
            port: port(name),
            source: sdk::InputSource::Query(format!(
                "SELECT {value}::BIGINT UNSIGNED AS value FROM catalog LIMIT 1"
            )),
        })
        .collect();
    model
}

fn scope(selection: AnalysisSelectionV1) -> (PackageGrantV1, PackageActivationV1) {
    let active = PackageActivationV1 {
        key: PackageKeyV1 {
            tenant_id: selection.tenant_id,
            scope_id: "scope".into(),
            package_id: "fixture".into(),
            export: "evaluate".into(),
        },
        revision: "1".into(),
        generation: 0,
        checkpoint_revision: 0,
        result_id: None,
        grant_id: "fixture".into(),
        metadata: Vec::new(),
        active: true,
    };
    (
        PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection,
            expires_utc_ns: None,
            authorization_id: None,
        },
        active,
    )
}

fn request<'a>(
    model: &'a sdk::Model,
    grant: &'a PackageGrantV1,
    active: &'a PackageActivationV1,
) -> ModelInputRequest<'a> {
    ModelInputRequest {
        activation: active,
        model,
        grant,
        now: 1_000,
    }
}

fn evaluation(inputs: Vec<sdk::Input>, model: &sdk::Model) -> sdk::Evaluation {
    sdk::Evaluation {
        export: model.name.clone(),
        inputs,
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "operation".into(),
            time_utc_ns: 1_000,
            seed: None,
            limits: model.limits,
        },
    }
}

#[test]
fn operation_inputs_match() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let mut model = model(&[("catalog", 7), ("second", 9)]);
    model.outputs.push(port("other"));
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let mut program = SqlModelV1::default();
    program
        .outputs
        .insert("result".into(), "SELECT value FROM catalog".into());
    program
        .outputs
        .insert("other".into(), "SELECT value FROM second".into());
    let admitted = AdmittedExport::admit(&owner, &model, Some(&program))?;
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let mut baseline = ModelRun::new(&owner, [1; 16], &control()?)?;
    baseline.prepare_inputs(
        request(&model, &grant, &active),
        &AdmittedExport::admit(&owner, &model, None)?,
        || Ok(()),
    )?;
    let expected_inputs = baseline.take_inputs()?;
    drop(baseline);
    let expected = ModelRun::new(&owner, [1; 16], &control()?)?.evaluate_model(
        &package,
        &program,
        &evaluation(expected_inputs.inputs.clone(), &model),
    )?;
    let expected_bytes = serde_json::to_vec(&crate::AnalysisPackageOwner::encode_output(
        &expected.output,
        &model,
    )?)?;
    drop(expected);
    let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
    operation.prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))?;
    let actual = operation.take_inputs()?;
    for (expected, actual) in expected_inputs.inputs.iter().zip(&actual.inputs) {
        assert_eq!(expected.revision, actual.revision);
        assert_eq!(expected.coverage, actual.coverage);
        assert_eq!(expected.data.batches, actual.data.batches);
    }
    assert_eq!(expected_inputs.source_revisions, actual.source_revisions);
    assert_eq!(expected_inputs.contexts, actual.contexts);
    assert_eq!(expected_inputs.witnesses, actual.witnesses);
    assert_eq!(expected_inputs.dependencies, actual.dependencies);
    drop(owner.reserve_evaluation([1; 16])?);
    let output = operation.evaluate_admitted(
        &package,
        &admitted,
        &evaluation(actual.inputs.clone(), &model),
    )?;
    assert_eq!(
        expected_bytes,
        serde_json::to_vec(&crate::AnalysisPackageOwner::encode_output(
            &output.output,
            &model
        )?)?
    );
    assert!(output.output.evidence.is_empty());
    assert!(output.output.reasons.is_empty());
    assert!(output.output.checkpoint.is_none());
    drop(owner.reserve_evaluation([1; 16])?);
    Ok(())
}

#[test]
fn reused_session_narrows_deadline() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let state = owner.catalog(BTreeMap::new())?;
    let plan = Arc::new(owner.plan(
        &state,
        araphor_query::parser::Parser::parse("SELECT 7")?,
        Vec::new(),
    )?);
    let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
    operation.start(AnalysisSelectionV1::tenant([1; 16]), 1_000)?;
    operation.control = operation.control.within(Duration::from_millis(10))?;
    operation.start(AnalysisSelectionV1::tenant([1; 16]), 1_000)?;
    std::thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        operation.session()?.execute(plan, &Default::default()),
        Err(araphor_query::Error::Data {
            source: araphor_data::Error::AnalysisReadDeadline { .. }
        })
    ));
    drop(owner.reserve_evaluation([1; 16])?);
    Ok(())
}

#[test]
fn operation_source_cleanup() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let model = model(&[("source", 7)]);
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let admitted = AdmittedExport::admit(&owner, &model, None)?;
    let mut foreign = grant.clone();
    foreign.selection.tenant_id = [9; 16];
    let mut denied = ModelRun::new(&owner, [1; 16], &control()?)?;
    assert_eq!(
        denied
            .prepare_inputs(request(&model, &foreign, &active), &admitted, || Ok(()))
            .err()
            .ok_or("foreign tenant accepted")?
            .package_code(),
        crate::PackageErrorCodeV1::Denied
    );
    drop(denied);
    let permit = owner.reserve_evaluation([1; 16])?;
    let mut blocked = ModelRun::new(&owner, [1; 16], &control()?)?;
    assert!(blocked
        .prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))
        .err()
        .ok_or("busy execution accepted")?
        .is_busy());
    drop(blocked);
    drop(permit);
    let mut invalid = model.clone();
    invalid.inputs[0].source = sdk::InputSource::Query(
        "SELECT CAST(relation AS BIGINT) AS value FROM catalog LIMIT 1".into(),
    );
    let mut rejected = ModelRun::new(&owner, [1; 16], &control()?)?;
    assert!(rejected
        .prepare_inputs(
            request(&invalid, &grant, &active),
            &AdmittedExport::admit(&owner, &invalid, None)?,
            || Ok(())
        )
        .is_err());
    drop(rejected);
    drop(
        owner
            .memory()
            .reserve_input(owner.limits().input_capacity)?,
    );
    let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
    operation.prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))?;
    let retained = operation.take_inputs()?;
    let pressure = owner
        .memory()
        .reserve_input(owner.limits().input_capacity - owner.limits().input_bytes)?;
    let mut blocked = ModelRun::new(&owner, [1; 16], &control()?)?;
    assert!(blocked
        .prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))
        .err()
        .ok_or("input pressure accepted")?
        .is_busy());
    drop(blocked);
    drop(pressure);
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let program = SqlModelV1 {
        outputs: BTreeMap::from([("result".into(), "SELECT value FROM source".into())]),
        ..Default::default()
    };
    let output_pressure = owner
        .memory()
        .reserve_output(owner.limits().output_capacity)?;
    assert!(operation
        .evaluate_model(
            &package,
            &program,
            &evaluation(retained.inputs.clone(), &model)
        )
        .err()
        .ok_or("output pressure accepted")?
        .is_busy());
    drop(output_pressure);
    drop(retained);
    drop(
        owner
            .memory()
            .reserve_input(owner.limits().input_capacity)?,
    );
    drop(
        owner
            .memory()
            .reserve_output(owner.limits().output_capacity)?,
    );
    drop(owner.reserve_evaluation([1; 16])?);
    Ok(())
}

#[test]
fn pruned_source_evidence() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 9)?;
    fixture.event(2, 200, 7)?;
    let owner = fixture.owner(limits())?;
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let mut model = model(&[("source", 7)]);
    let mut revisions = Vec::new();
    let mut witnesses = Vec::new();
    for (sql, expected_rows) in [
        (
            "SELECT CAST(operation AS BIGINT UNSIGNED) AS value FROM events WHERE operation = 7",
            1,
        ),
        (
            "SELECT CAST(operation AS BIGINT UNSIGNED) AS value FROM events WHERE operation = 7 AND false",
            0,
        ),
        (
            "WITH unused AS (SELECT operation FROM events) SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
            1,
        ),
    ] {
        model.inputs[0].source = sdk::InputSource::Query(sql.into());
        let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
        operation.prepare_inputs(
            request(&model, &grant, &active),
            &AdmittedExport::admit(&owner, &model, None)?,
            || Ok(()),
        )?;
        let inputs = operation.take_inputs()?;
        assert_eq!(
            inputs
                .witnesses
                .iter()
                .map(|witness| witness.cursor)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            inputs.inputs[0]
                .data
                .batches
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>(),
            expected_rows
        );
        revisions.push(inputs.inputs[0].revision.clone());
        witnesses.push(inputs.witnesses.clone());
        drop(operation);
        drop(inputs);
    }
    assert_ne!(revisions[0], revisions[1]);
    assert_eq!(revisions[0], revisions[2]);
    assert_eq!(witnesses[0], witnesses[1]);
    assert_eq!(witnesses[0], witnesses[2]);
    Ok(())
}

#[test]
fn operation_source_denial() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let model = model(&[("source", 7)]);
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    for sql in [
        "SELECT 1::BIGINT UNSIGNED AS value FROM catalog",
        "SELECT 1::BIGINT UNSIGNED AS value FROM _query_catalog()",
        "SELECT value FROM \"araphor:port:0\"",
        "WITH unused AS (SELECT 1::BIGINT UNSIGNED AS value FROM catalog) SELECT value FROM source",
        "WITH unused AS (SELECT value FROM output_result) SELECT value FROM source",
    ] {
        let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
        operation.prepare_inputs(
            request(&model, &grant, &active),
            &AdmittedExport::admit(&owner, &model, None)?,
            || Ok(()),
        )?;
        let retained = operation.take_inputs()?;
        let mut program = SqlModelV1::default();
        program.outputs.insert("result".into(), sql.into());
        assert!(operation
            .evaluate_model(
                &package,
                &program,
                &evaluation(retained.inputs.clone(), &model),
            )
            .is_err());
        drop(retained);
        drop(owner.reserve_evaluation([1; 16])?);
    }
    Ok(())
}

#[test]
fn named_alias_revision() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 7)?;
    let owner = fixture.owner(limits())?;
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "source_cursor",
        sdk::DataType::UInt64,
        false,
    )]);
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("selected", schema.clone()),
            source: sdk::InputSource::Query(
                "SELECT source_cursor FROM \"activity-log\" WHERE false".into(),
            ),
        },
        sdk::InputPort {
            port: sdk::Port::new("activity-log", schema),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ];
    let (grant, active) = scope(AnalysisSelectionV1::new(
        fixture.source.tenant_id,
        vec![fixture.source.clone()],
    ));
    let mut program = SqlModelV1::default();
    program.outputs.insert(
        "result".into(),
        "SELECT source_cursor FROM \"activity-log\"".into(),
    );
    let package = sdk::Package::new("fixture", "1", vec![model.clone()]);
    let admitted = AdmittedExport::admit(&owner, &model, Some(&program))?;
    let mut previous = None;
    for cursor in 1..=2 {
        if cursor == 2 {
            fixture.event(2, 200, 7)?;
        }
        let mut operation = ModelRun::new(&owner, fixture.source.tenant_id, &control()?)?;
        operation.prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))?;
        let inputs = operation.take_inputs()?;
        assert_eq!(inputs.inputs[0].data.name, "selected");
        assert_eq!(inputs.inputs[0].data.batches[0].num_rows(), 0);
        assert!(!inputs.source_revisions.is_empty());
        assert_eq!(inputs.witnesses.len(), cursor);
        if let Some(previous) = previous {
            assert_ne!(inputs.inputs[0].revision, previous);
        }
        previous = Some(inputs.inputs[0].revision.clone());
        let result = operation.evaluate_admitted(
            &package,
            &admitted,
            &evaluation(inputs.inputs.clone(), &model),
        )?;
        assert_eq!(
            result.output.datasets[0]
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            cursor
        );
    }
    Ok(())
}

#[test]
fn declared_tables_override_canonical_names() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let mut model = model(&[]);
    model.inputs.push(sdk::InputPort {
        port: port("events"),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "1".into(),
            export: "evaluate".into(),
            output: "result".into(),
        })),
    });
    model.inputs.push(sdk::InputPort {
        port: port("selected"),
        source: sdk::InputSource::Query("SELECT value FROM events".into()),
    });
    let admitted = AdmittedExport::admit(&owner, &model, None)?;
    assert!(admitted.inputs.iter().any(|input| matches!(input, AdmittedInput::Query { reads, inputs, .. } if reads.is_empty() && inputs == &[0])));
    model.inputs[0].port.name = "EVENTS".into();
    assert!(AdmittedExport::admit(&owner, &model, None).is_err());
    model.inputs[1].source = sdk::InputSource::Query("SELECT value FROM \"EVENTS\"".into());
    assert!(AdmittedExport::admit(&owner, &model, None).is_ok());
    Ok(())
}

#[test]
fn operation_input_capacity() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(Limits {
        input_capacity: limits().input_bytes,
        ..limits()
    })?;
    let mut model = model(&[("source", 7)]);
    model.limits.max_bytes = owner.limits().input_bytes as u64 / 2;
    let admitted = AdmittedExport::admit(&owner, &model, None)?;
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let pressure = owner.memory().reserve_input(1)?;
    let mut blocked = ModelRun::new(&owner, [1; 16], &control()?)?;
    assert!(blocked
        .prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))
        .err()
        .ok_or("input pressure accepted")?
        .is_busy());
    drop(blocked);
    drop(pressure);
    let mut operation = ModelRun::new(&owner, [1; 16], &control()?)?;
    operation.prepare_inputs(request(&model, &grant, &active), &admitted, || Ok(()))?;
    let inputs = operation.take_inputs()?;
    drop(operation);
    drop(inputs);
    drop(
        owner
            .memory()
            .reserve_input(owner.limits().input_capacity)?,
    );
    Ok(())
}

#[test]
fn aggregate_output_rows_stop_before_reference_tables() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let mut model = model(&[]);
    model.outputs.push(port("other"));
    model.limits.max_rows = 1;
    let package = sdk::Package::new("output-limits", "1", vec![model.clone()]);
    let mut program = SqlModelV1::default();
    for name in ["result", "other"] {
        program
            .outputs
            .insert(name.into(), "SELECT 1::BIGINT UNSIGNED AS value".into());
    }
    assert!(matches!(
        ModelRun::new(&owner, [1; 16], &control()?)?.evaluate_model(
            &package,
            &program,
            &evaluation(Vec::new(), &model),
        ),
        Err(crate::Error::ModelLimit {
            resource: "model output rows",
            ..
        }),
    ));
    drop(owner.reserve_evaluation([1; 16])?);
    drop(
        owner
            .memory()
            .reserve_input(owner.limits().input_capacity)?,
    );
    Ok(())
}

#[test]
fn admitted_input_provenance() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 7)?;
    let owner = fixture.owner(limits())?;
    let (grant, active) = scope(AnalysisSelectionV1::new(
        fixture.source.tenant_id,
        vec![fixture.source.clone()],
    ));
    let mut model = model(&[]);
    let rows = sdk::Schema::new(vec![sdk::Field::new(
        "source_cursor",
        sdk::DataType::UInt64,
        false,
    )]);
    let ordinals = sdk::Schema::new(vec![sdk::Field::new(
        "ordinal",
        sdk::DataType::UInt32,
        false,
    )]);
    model.inputs = vec![
        sdk::InputPort {
            port: port("zrows"),
            source: sdk::InputSource::Query("SELECT source_cursor AS value FROM \"ZRows\"".into()),
        },
        sdk::InputPort {
            port: port("selected"),
            source: sdk::InputSource::Query("WITH unused AS (SELECT ordinal FROM \"arows\") SELECT source_cursor AS value FROM \"ZRows\"".into()),
        },
        sdk::InputPort {
            port: sdk::Port::new("arows", ordinals),
            source: sdk::InputSource::Table(sdk::TableRef::Named("catalog".into())),
        },
        sdk::InputPort {
            port: sdk::Port::new("ZRows", rows),
            source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
        },
    ];
    sdk::Package::new("binding-fixture", "1", vec![model.clone()]).validate()?;
    let mut expected: Option<BTreeMap<String, sdk::wire::Input>> = None;
    let mut expected_metadata = None;
    for indices in [&[0, 1, 2, 3][..], &[3, 0, 2, 1][..], &[3, 2, 1][..]] {
        let mut declared = model.clone();
        declared.inputs = indices
            .iter()
            .map(|index| model.inputs[*index].clone())
            .collect();
        let mut admitted = AdmittedExport::admit(&owner, &declared, None)?;
        let before = admitted.allocated_bytes();
        let capacity = admitted.inputs.capacity();
        admitted.inputs.reserve_exact(8);
        let growth = (admitted.inputs.capacity() - capacity)
            * std::mem::size_of::<super::super::AdmittedInput>();
        assert_eq!(admitted.allocated_bytes(), before + growth);
        let mut calls = 0;
        let mut operation = ModelRun::new(&owner, fixture.source.tenant_id, &control()?)?;
        operation.prepare_inputs(request(&declared, &grant, &active), &admitted, || {
            calls += 1;
            Ok(())
        })?;
        let inputs = operation.take_inputs()?;
        assert!(calls >= indices.len());
        assert_eq!(
            inputs
                .inputs
                .iter()
                .map(|input| &input.data.name)
                .collect::<Vec<_>>(),
            declared
                .inputs
                .iter()
                .map(|input| &input.port.name)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            inputs
                .inputs
                .iter()
                .find(|input| input.data.name == "selected")
                .ok_or("selected input")?
                .data
                .batches
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>(),
            1
        );
        let data = inputs
            .inputs
            .iter()
            .map(|input| {
                let port = declared
                    .inputs
                    .iter()
                    .find(|port| port.port.name == input.data.name)
                    .ok_or("declared input")?;
                Ok((
                    input.data.name.clone(),
                    sdk::wire::Input {
                        data: sdk::wire::Dataset::encode(
                            &input.data,
                            &port.port.schema,
                            declared.limits,
                        )?,
                        revision: input.revision.clone(),
                        coverage: input.coverage.clone(),
                    },
                ))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        assert_ne!(data["ZRows"].revision, data["arows"].revision);
        if let Some(expected) = &expected {
            if indices.contains(&0) {
                assert_eq!(expected, &data);
            } else {
                for (name, actual) in &data {
                    assert_eq!(expected[name].data, actual.data);
                    assert_eq!(expected[name].coverage, actual.coverage);
                    assert_eq!(expected[name].revision, actual.revision);
                }
            }
        } else {
            expected = Some(data);
        }
        let metadata = (
            inputs.source_revisions.clone(),
            inputs.dependencies.clone(),
            inputs.witnesses.clone(),
            inputs.contexts.clone(),
        );
        if let Some(expected) = &expected_metadata {
            assert_eq!(expected, &metadata);
        } else {
            expected_metadata = Some(metadata);
        }
        drop(operation);
        drop(inputs);
        drop(
            owner
                .memory()
                .reserve_input(owner.limits().input_capacity)?,
        );
        drop(owner.reserve_evaluation(fixture.source.tenant_id)?);
    }
    Ok(())
}
