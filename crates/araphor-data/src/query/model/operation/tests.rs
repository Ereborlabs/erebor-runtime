use std::time::Duration;

use super::*;
use crate::analysis::{PackageActivationV1, PackageKeyV1};
use crate::package::PackageGrantV1;
use crate::query::tests::QueryFixture;
use crate::{AnalysisSelectionV1, QueryLimits};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn port(name: &str) -> sdk::Port {
    sdk::Port::new(
        name,
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
    )
}

fn control() -> crate::Result<AnalysisReadControl> {
    AnalysisReadControl::with_timeout(Duration::from_secs(30))
}

fn limits() -> QueryLimits {
    QueryLimits {
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
                "SELECT {value}::UBIGINT AS value FROM catalog LIMIT 1"
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
    let admitted = AdmittedExport::admit(&model, Some(&program))?;
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let (baseline, expected_inputs) = owner.model_operation([1; 16]).inputs(
        request(&model, &grant, &active),
        &control()?,
        || Ok(()),
    )?;
    baseline.release_inputs()?;
    let expected = owner.evaluate_model(
        [1; 16],
        &package,
        &program,
        &evaluation(expected_inputs.inputs.clone(), &model),
        &control()?,
    )?;
    let expected_bytes = serde_json::to_vec(&crate::AnalysisPackageOwner::encode_output(
        &expected.output,
        &model,
    )?)?;
    drop(expected);
    let (operation, actual) = owner.model_operation([1; 16]).inputs_admitted(
        request(&model, &grant, &active),
        &admitted,
        &control()?,
        || Ok(()),
    )?;
    for (expected, actual) in expected_inputs.inputs.iter().zip(&actual.inputs) {
        assert_eq!(expected.revision, actual.revision);
        assert_eq!(expected.coverage, actual.coverage);
        assert_eq!(expected.data.batches, actual.data.batches);
    }
    assert_eq!(expected_inputs.source_revisions, actual.source_revisions);
    assert_eq!(expected_inputs.contexts, actual.contexts);
    assert_eq!(expected_inputs.witnesses, actual.witnesses);
    assert_eq!(expected_inputs.dependencies, actual.dependencies);
    assert!(matches!(
        owner.budget.component([1; 16], 0, 0),
        Err(crate::Error::AnalysisBusy {
            resource: "query evaluation capacity",
            ..
        })
    ));
    let output = operation.evaluate_admitted(
        &package,
        &program,
        &admitted,
        &evaluation(actual.inputs.clone(), &model),
        &control()?,
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
    drop(owner.budget.component([1; 16], 0, 0)?);
    Ok(())
}

#[test]
fn operation_source_cleanup() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(limits())?;
    let model = model(&[("source", 7)]);
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let mut foreign = grant.clone();
    foreign.selection.tenant_id = [9; 16];
    assert!(matches!(
        owner.model_operation([1; 16]).inputs(
            request(&model, &foreign, &active),
            &control()?,
            || Ok(())
        ),
        Err(crate::Error::QueryDenied { .. })
    ));
    let mut invalid = model.clone();
    invalid.inputs[0].source = sdk::InputSource::Query(
        "SELECT CAST(relation AS BIGINT) AS value FROM catalog LIMIT 1".into(),
    );
    assert!(owner
        .model_operation([1; 16])
        .inputs(request(&invalid, &grant, &active), &control()?, || Ok(()))
        .is_err());
    assert_eq!(owner.input_charge(), 0);
    drop(owner.budget.evaluate([1; 16])?);
    let (operation, retained) = owner.model_operation([1; 16]).inputs(
        request(&model, &grant, &active),
        &control()?,
        || Ok(()),
    )?;
    let state = &operation.engine.as_ref().ok_or("missing engine")?.0;
    assert!(operation.bound.is_empty());
    assert!(state.table_functions().is_empty());
    for name in state.catalog_list().catalog_names() {
        let catalog = state
            .catalog_list()
            .catalog(&name)
            .ok_or("missing catalog")?;
        for name in catalog.schema_names() {
            assert!(catalog
                .schema(&name)
                .ok_or("missing schema")?
                .table_names()
                .is_empty());
        }
    }
    let held = owner
        .budget
        .retained_input(owner.limits.input_capacity - owner.input_charge())?;
    assert!(matches!(
        owner.budget.retained_input(1),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    assert!(matches!(
        owner.model_operation([1; 16]).inputs(
            request(&model, &grant, &active),
            &control()?,
            || Ok(())
        ),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    drop(retained);
    operation.release_inputs()?;
    drop(owner.budget.evaluate([1; 16])?);
    drop(held);
    let (operation, retained) = owner.model_operation([1; 16]).inputs(
        request(&model, &grant, &active),
        &control()?,
        || Ok(()),
    )?;
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let mut program = SqlModelV1::default();
    program
        .outputs
        .insert("result".into(), "SELECT value FROM source".into());
    let full_output = owner.budget.output(owner.limits.output_capacity)?;
    assert!(matches!(
        operation.evaluate(
            &package,
            &program,
            &evaluation(retained.inputs.clone(), &model),
            &control()?
        ),
        Err(crate::Error::AnalysisBusy {
            resource: "query output capacity",
            ..
        })
    ));
    drop(retained);
    drop(owner.budget.retained_input(owner.limits.input_capacity)?);
    drop(owner.budget.model([1; 16], 0)?);
    drop(full_output);
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
            "SELECT CAST(operation AS UBIGINT) AS value FROM events WHERE operation = 7",
            1,
        ),
        (
            "SELECT CAST(operation AS UBIGINT) AS value FROM events WHERE operation = 7 AND false",
            0,
        ),
        (
            "WITH unused AS (SELECT operation FROM events) SELECT CAST(7 AS UBIGINT) AS value",
            1,
        ),
    ] {
        model.inputs[0].source = sdk::InputSource::Query(sql.into());
        let (operation, inputs) = owner.model_operation([1; 16]).inputs(
            request(&model, &grant, &active),
            &control()?,
            || Ok(()),
        )?;
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
        "SELECT 1::UBIGINT AS value FROM catalog",
        "SELECT 1::UBIGINT AS value FROM _query_catalog()",
        "SELECT value FROM \"araphor:port:0\"",
    ] {
        let (operation, retained) = owner.model_operation([1; 16]).inputs(
            request(&model, &grant, &active),
            &control()?,
            || Ok(()),
        )?;
        let mut program = SqlModelV1::default();
        program.outputs.insert("result".into(), sql.into());
        assert!(operation
            .evaluate(
                &package,
                &program,
                &evaluation(retained.inputs.clone(), &model),
                &control()?
            )
            .is_err());
        drop(retained);
        drop(owner.budget.evaluate([1; 16])?);
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
    let admitted = AdmittedExport::admit(&model, Some(&program))?;
    let mut previous = None;
    for cursor in 1..=2 {
        if cursor == 2 {
            fixture.event(2, 200, 7)?;
        }
        let operation = owner.model_operation(fixture.source.tenant_id);
        assert!(operation.engine.is_none());
        let (operation, inputs) = operation.inputs_admitted(
            request(&model, &grant, &active),
            &admitted,
            &control()?,
            || Ok(()),
        )?;
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
            &program,
            &admitted,
            &evaluation(inputs.inputs.clone(), &model),
            &control()?,
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
fn catalog_name_collision() {
    let mut model = model(&[]);
    model.inputs.push(sdk::InputPort {
        port: port("EVENTS"),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "1".into(),
            export: "evaluate".into(),
            output: "result".into(),
        })),
    });
    assert!(QueryOwner::admit_inputs(&model).is_err());
}

#[test]
fn operation_input_capacity() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits {
        input_capacity: limits().input_bytes,
        ..limits()
    })?;
    let model = model(&[("source", 7)]);
    let (grant, active) = scope(AnalysisSelectionV1::tenant([1; 16]));
    let pressure = owner.budget.retained_input(1)?;
    assert!(matches!(
        owner.model_operation([1; 16]).inputs(
            request(&model, &grant, &active),
            &control()?,
            || Ok(())
        ),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    drop(pressure);
    let (operation, inputs) = owner.model_operation([1; 16]).inputs(
        request(&model, &grant, &active),
        &control()?,
        || Ok(()),
    )?;
    operation.release_inputs()?;
    drop(inputs);
    drop(owner.budget.retained_input(owner.limits.input_capacity)?);
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
            .insert(name.into(), "SELECT 1::UBIGINT AS value".into());
    }
    assert!(matches!(
        owner.evaluate_model(
            [1; 16],
            &package,
            &program,
            &evaluation(Vec::new(), &model),
            &control()?,
        ),
        Err(crate::Error::QueryLimit { .. }),
    ));
    drop(owner.budget.evaluate([1; 16])?);
    assert_eq!(owner.input_charge(), 0);
    Ok(())
}
