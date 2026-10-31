use super::*;

use araphor_data::AnalysisSelectionV1;
use datafusion::arrow::array::{Array as _, UInt64Array};
use datafusion::datasource::{provider_as_source, ViewTable};
use datafusion::logical_expr::{col, lit, LogicalPlanBuilder, TableScan};

use crate::definition::Invocation;

fn bundle(nested: bool) -> PackageBundleV1 {
    let mut bundle = Fixture::bundle();
    let artifact = &mut bundle.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0].source = sdk::InputSource::Query(
        "SELECT CAST(100 - key AS BIGINT UNSIGNED) AS value FROM (VALUES (3), (1), (2)) supplied(key) ORDER BY supplied.key DESC".into(),
    );
    let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] else {
        unreachable!();
    };
    program.outputs.insert(
        "result".into(),
        "SELECT value FROM source ORDER BY value DESC".into(),
    );
    program.checkpoint.insert(
        "state".into(),
        "SELECT value AS total FROM output_result ORDER BY total ASC".into(),
    );
    program.evidence = Some("SELECT 'result' AS output_dataset, result.__row_index AS output_row, 'source' AS input_dataset, source.__row_index AS input_row FROM output_result result JOIN source ON source.value = result.value".into());
    if nested {
        let mut inner = model.clone();
        inner.name = "inner".into();
        let program = program.clone();
        model.inputs[0].source = sdk::InputSource::Query(
            r#"SELECT value FROM "fixture"."r1".inner(increment => 2) ORDER BY value ASC"#.into(),
        );
        artifact.descriptor.exports.push(inner);
        artifact.implementations.push(PackageImplementationV1::Sql {
            export: "inner".into(),
            program,
        });
    }
    bundle
}

fn values(batches: &[sdk::RecordBatch], column: usize) -> TestResult<Vec<u64>> {
    let mut result = Vec::new();
    for batch in batches {
        let values = batch
            .column(column)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("unsigned values")?;
        assert_eq!(values.null_count(), 0);
        result.extend(values.values());
    }
    Ok(result)
}

#[tokio::test]
async fn native_program_order() -> TestResult {
    for (nested, name) in [(false, "count"), (true, "count"), (false, "Count.Mixed")] {
        let mut bundle = bundle(nested);
        bundle.artifacts[0].descriptor.exports[0].name = name.into();
        let PackageImplementationV1::Sql { export, .. } =
            &mut bundle.artifacts[0].implementations[0]
        else {
            return Err("SQL implementation".into());
        };
        *export = name.into();
        let fixture = Fixture::installed(&bundle)?;
        let prepared = fixture
            .prepare(&Fixture::sql(format!(
                r#"SELECT * FROM "fixture"."r1"."{name}"(increment => 2)"#,
            )))
            .await?;
        let session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            1,
        )?;
        let result = session
            .execute_definition(&prepared, Invocation::default())
            .await?;
        assert_eq!(values(&result.batches, 0)?, [99, 98, 97]);
        assert_eq!(result.calls.len(), if nested { 2 } else { 1 });
        for (&id, call) in &result.calls {
            assert_eq!(
                values(&call.evaluation().inputs[0].data.batches, 0)?,
                [97, 98, 99]
            );
            assert_eq!(values(&call.output().datasets[0].batches, 0)?, [99, 98, 97]);
            assert_eq!(
                values(
                    &call
                        .output()
                        .checkpoint
                        .as_ref()
                        .ok_or("saved state")?
                        .datasets[0]
                        .batches,
                    0
                )?,
                [97, 98, 99]
            );
            let replay = session
                .replay_call(&prepared, id, call.evaluation().clone())
                .await?;
            let actual = replay.calls.get(&id).ok_or("replayed call")?;
            assert_eq!(
                actual.evaluation().inputs[0].data.batches,
                call.evaluation().inputs[0].data.batches
            );
            assert_eq!(
                actual.output().datasets[0].batches,
                call.output().datasets[0].batches
            );
            let actual = actual
                .output()
                .checkpoint
                .as_ref()
                .ok_or("replayed state")?;
            let expected = call.output().checkpoint.as_ref().ok_or("original state")?;
            assert_eq!(actual.version, expected.version);
            assert_eq!(actual.datasets[0].batches, expected.datasets[0].batches);
        }
    }
    Ok(())
}

#[tokio::test]
async fn prepared_view_program_order() -> TestResult {
    let fixture = Fixture::installed(&bundle(false))?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#,
        ))
        .await?;
    let base = LogicalPlanBuilder::from(prepared.plan.clone())
        .project(vec![
            col("value"),
            (col("value") + lit(1_u64)).alias("next"),
        ])?
        .build()?;
    let source = provider_as_source(Arc::new(ViewTable::new(
        base,
        Some("prepared query".into()),
    )));
    let mut session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    for projection in [vec![1], vec![1, 0]] {
        let scan = TableScan::try_new(
            "saved",
            Arc::clone(&source),
            Some(projection.clone()),
            vec![col("saved.value").gt(lit(97_u64))],
            Some(1),
        )?;
        session.register_table(
            "selected",
            Arc::new(ViewTable::new(
                LogicalPlan::TableScan(scan),
                Some("selected query".into()),
            )),
        )?;
        let selected = session
            .prepare_definition(&Fixture::sql("SELECT * FROM selected"))
            .await?;
        let output = session
            .execute_definition(&selected, Invocation::default())
            .await?;
        assert_eq!(values(&output.batches, 0)?, [100]);
        assert_eq!(output.batches[0].num_columns(), projection.len());
        if projection.len() == 2 {
            assert_eq!(values(&output.batches, 1)?, [99]);
        }
        let call = output.calls.values().next().ok_or("view call")?;
        assert_eq!(
            values(&call.evaluation().inputs[0].data.batches, 0)?,
            [97, 98, 99]
        );
    }
    let scan = |name: &str| {
        TableScan::try_new(name, Arc::clone(&source), Some(vec![0]), vec![], None)
            .map(LogicalPlan::TableScan)
    };
    let shared = LogicalPlanBuilder::from(scan("left")?)
        .union(scan("right")?)?
        .build()?;
    session.register_table("shared", Arc::new(ViewTable::new(shared, None)))?;
    let shared = session
        .prepare_definition(&Fixture::sql("SELECT * FROM shared"))
        .await?;
    let output = session
        .execute_definition(&shared, Invocation::default())
        .await?;
    let mut actual = values(&output.batches, 0)?;
    actual.sort_unstable();
    assert_eq!(actual, [97, 97, 98, 98, 99, 99]);
    assert_eq!(output.calls.len(), 1);
    Ok(())
}
