use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::{AnalysisSelectionV1, AnalysisStore, QueryLimits, QuerySql};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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

fn request<'a>(port: &'a sdk::Port, value: u64) -> crate::Result<SqlModelInputRequestV1<'a>> {
    Ok(SqlModelInputRequestV1 {
        selection: AnalysisSelectionV1::tenant([1; 16]),
        sql: QuerySql::admit(
            &format!("SELECT {value}::UBIGINT AS value FROM catalog LIMIT 1"),
            Vec::new(),
            false,
        )?,
        port,
        limits: sdk::Limits::default(),
        now_ns: 1_000,
    })
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
fn sql_operation_matches_standalone_inputs_and_output() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let owner = QueryOwner::new(store, limits())?;
    let ports = [port("catalog"), port("second")];
    let model = sdk::Model::new(
        "evaluate",
        ports.to_vec(),
        vec![port("result"), port("other")],
    );
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let mut program = SqlModelV1::default();
    program
        .outputs
        .insert("result".into(), "SELECT value FROM catalog".into());
    program
        .outputs
        .insert("other".into(), "SELECT value FROM second".into());
    let baseline = [
        owner.model_input(request(&ports[0], 7)?, &control()?)?,
        owner.model_input(request(&ports[1], 9)?, &control()?)?,
    ];
    let expected = owner.evaluate_model(
        [1; 16],
        &package,
        &program,
        &evaluation(
            baseline.iter().map(|input| input.input.clone()).collect(),
            &model,
        ),
        &control()?,
    )?;
    let expected_bytes = serde_json::to_vec(&crate::package::PackageOutputV1::encode(
        &expected.output,
        &model,
    )?)?;
    drop(expected);
    let mut operation = owner.sql_operation([1; 16])?;
    let actual = [
        operation.model_input(request(&ports[0], 7)?, &control()?)?,
        operation.model_input(request(&ports[1], 9)?, &control()?)?,
    ];
    for (expected, actual) in baseline.iter().zip(&actual) {
        assert_eq!(expected.input.revision, actual.input.revision);
        assert_eq!(expected.input.coverage, actual.input.coverage);
        assert_eq!(expected.input.data.batches, actual.input.data.batches);
        assert_eq!(expected.source_revisions, actual.source_revisions);
        assert_eq!(expected.contexts, actual.contexts);
        assert_eq!(expected.witnesses, actual.witnesses);
    }
    assert!(matches!(
        owner.budget.component([1; 16], 0, 0),
        Err(crate::Error::AnalysisBusy {
            resource: "query evaluation capacity",
            ..
        })
    ));
    let output = operation.evaluate(
        &package,
        &program,
        &evaluation(
            actual.iter().map(|input| input.input.clone()).collect(),
            &model,
        ),
        &control()?,
    )?;
    assert_eq!(
        expected_bytes,
        serde_json::to_vec(&crate::package::PackageOutputV1::encode(
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
fn sql_operation_clears_sources_and_preserves_capacity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let owner = QueryOwner::new(
        Arc::new(AnalysisStore::open(directory.path().join("analysis"))?),
        limits(),
    )?;
    let input = port("source");
    let mut operation = owner.sql_operation([1; 16])?;
    let mut foreign = request(&input, 7)?;
    foreign.selection.tenant_id = [9; 16];
    assert!(matches!(
        operation.model_input(foreign, &control()?),
        Err(crate::Error::QueryDenied { .. })
    ));
    let mut invalid = request(&input, 7)?;
    invalid.sql = QuerySql::admit(
        "SELECT CAST(relation AS BIGINT) AS value FROM catalog LIMIT 1",
        Vec::new(),
        false,
    )?;
    assert!(operation.model_input(invalid, &control()?).is_err());
    assert!(operation
        .connection
        .prepare("SELECT * FROM catalog")
        .is_err());
    assert!(operation
        .connection
        .query_row("SELECT count(*) FROM _query_catalog()", [], |row| row
            .get::<_, u64>(0))
        .is_err());
    let retained = operation.model_input(request(&input, 7)?, &control()?)?;
    assert!(matches!(
        owner
            .budget
            .retained_input(owner.limits.input_capacity - owner.limits.input_bytes),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    drop(retained);
    let held = owner
        .budget
        .retained_input(owner.limits.input_capacity - owner.limits.input_bytes)?;
    assert!(matches!(
        owner.budget.retained_input(1),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    assert!(matches!(
        operation.model_input(request(&port("second"), 9)?, &control()?),
        Err(crate::Error::AnalysisBusy {
            resource: "query input capacity",
            ..
        })
    ));
    drop(operation);
    drop(owner.budget.evaluate([1; 16])?);
    drop(held);
    let model = sdk::Model::new("evaluate", vec![input.clone()], vec![port("result")]);
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    let mut program = SqlModelV1::default();
    program
        .outputs
        .insert("result".into(), "SELECT value FROM source".into());
    let mut operation = owner.sql_operation([1; 16])?;
    let retained = operation.model_input(request(&input, 7)?, &control()?)?;
    let full_output = owner.budget.output(owner.limits.output_capacity)?;
    assert!(matches!(
        operation.evaluate(
            &package,
            &program,
            &evaluation(vec![retained.input.clone()], &model),
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
fn sql_operation_rejects_hidden_source_access() -> TestResult {
    let directory = tempfile::tempdir()?;
    let owner = QueryOwner::new(
        Arc::new(AnalysisStore::open(directory.path().join("analysis"))?),
        limits(),
    )?;
    let input = port("source");
    let model = sdk::Model::new("evaluate", vec![input.clone()], vec![port("result")]);
    let package = sdk::Package::new("sql-operation", "1", vec![model.clone()]);
    for sql in [
        "SELECT 1::UBIGINT AS value FROM catalog",
        "SELECT 1::UBIGINT AS value FROM _query_catalog()",
        "SELECT value FROM \"araphor:port:0\"",
    ] {
        let mut operation = owner.sql_operation([1; 16])?;
        let retained = operation.model_input(request(&input, 7)?, &control()?)?;
        let mut program = SqlModelV1::default();
        program.outputs.insert("result".into(), sql.into());
        assert!(operation
            .evaluate(
                &package,
                &program,
                &evaluation(vec![retained.input.clone()], &model),
                &control()?
            )
            .is_err());
        drop(retained);
        drop(owner.budget.evaluate([1; 16])?);
    }
    Ok(())
}
